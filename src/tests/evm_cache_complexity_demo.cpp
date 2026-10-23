// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Time buildBytecodeCache. Two modes:
//   1. Synthetic dyn-dispatch (algorithmic stress):
//        evmCacheComplexityDemo <n_jumpdests>
//      Builds CALLDATALOAD JUMP <N x JUMPDEST> STOP and times once.
//   2. Real-bytecode replay (corpus bench):
//        evmCacheComplexityDemo --bytecode <hex-or-bin-file> [--label <tag>]
//      Loads bytecode from file (hex or raw bytes), runs cache build,
//      emits CSV row.
//
// Optional --dump-r1-stats replaces the timing-only CSV with R1
// counters (unresolved JUMP/JUMPI after local + optional cross-block
// absinterp, JUMPDESTs stamped with ImplicitDynamicPredCount, and
// nonzero gas-chunk / meterGas sites before vs after SPP).
// --r1 on|off and --spp on|off select the 2×2 ablation.
//
// Output (default): CSV `<label>,<n_jumpdests>,<build_us>` on stdout.
// Output (--dump-r1-stats): one CSV data row; header is printed by
// tools/r1_baseline_stats.sh.
// With ZEN_EVM_CACHE_PROFILE=ON, per-phase rows also emit on stderr.

#include "evm/evm_cache.h"
#include "platform/platform.h"

#include <evmc/evmc.h>
#include <evmc/instructions.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {

constexpr uint8_t OP_STOP = static_cast<uint8_t>(evmc_opcode::OP_STOP);
constexpr uint8_t OP_CALLDATALOAD =
    static_cast<uint8_t>(evmc_opcode::OP_CALLDATALOAD);
constexpr uint8_t OP_JUMP = static_cast<uint8_t>(evmc_opcode::OP_JUMP);
constexpr uint8_t OP_JUMPI = static_cast<uint8_t>(evmc_opcode::OP_JUMPI);
constexpr uint8_t OP_JUMPDEST = static_cast<uint8_t>(evmc_opcode::OP_JUMPDEST);
constexpr uint8_t OP_PUSH0 = static_cast<uint8_t>(evmc_opcode::OP_PUSH0);
constexpr uint8_t OP_PUSH1 = static_cast<uint8_t>(evmc_opcode::OP_PUSH1);
constexpr uint8_t OP_PUSH32 = static_cast<uint8_t>(evmc_opcode::OP_PUSH32);
constexpr uint8_t OP_DUP1 = static_cast<uint8_t>(evmc_opcode::OP_DUP1);
constexpr uint8_t OP_DUP16 = static_cast<uint8_t>(evmc_opcode::OP_DUP16);
constexpr uint8_t OP_SWAP1 = static_cast<uint8_t>(evmc_opcode::OP_SWAP1);
constexpr uint8_t OP_SWAP16 = static_cast<uint8_t>(evmc_opcode::OP_SWAP16);
constexpr uint8_t OP_CODECOPY = static_cast<uint8_t>(evmc_opcode::OP_CODECOPY);
constexpr uint8_t OP_RETURN = static_cast<uint8_t>(evmc_opcode::OP_RETURN);

uint8_t opcodeLen(uint8_t Op) {
  if (Op >= OP_PUSH1 && Op <= OP_PUSH32)
    return static_cast<uint8_t>(Op - OP_PUSH1 + 2);
  return 1;
}

bool isPush1To32(uint8_t Op) { return Op >= OP_PUSH1 && Op <= OP_PUSH32; }

bool isJumpOp(uint8_t Op) { return Op == OP_JUMP || Op == OP_JUMPI; }

bool isStackManip(uint8_t Op) {
  return Op == OP_PUSH0 || (Op >= OP_DUP1 && Op <= OP_DUP16) ||
         (Op >= OP_SWAP1 && Op <= OP_SWAP16);
}

std::vector<uint8_t> makeDynDispatchContract(size_t NumJumpDests) {
  std::vector<uint8_t> Code;
  Code.reserve(NumJumpDests + 3);
  Code.push_back(OP_CALLDATALOAD);
  Code.push_back(OP_JUMP);
  for (size_t I = 0; I < NumJumpDests; ++I) {
    Code.push_back(OP_JUMPDEST);
  }
  Code.push_back(OP_STOP);
  return Code;
}

int hexNibble(char C) {
  if (C >= '0' && C <= '9')
    return C - '0';
  if (C >= 'a' && C <= 'f')
    return C - 'a' + 10;
  if (C >= 'A' && C <= 'F')
    return C - 'A' + 10;
  return -1;
}

bool tryDecodeHex(const std::string &Input, std::vector<uint8_t> &Out) {
  std::string Stripped;
  Stripped.reserve(Input.size());
  for (char C : Input) {
    if (std::isspace(static_cast<unsigned char>(C)))
      continue;
    Stripped.push_back(C);
  }
  if (Stripped.size() >= 2 && Stripped[0] == '0' &&
      (Stripped[1] == 'x' || Stripped[1] == 'X')) {
    Stripped.erase(0, 2);
  }
  if (Stripped.size() % 2 != 0)
    return false;
  Out.clear();
  Out.reserve(Stripped.size() / 2);
  for (size_t I = 0; I < Stripped.size(); I += 2) {
    int Hi = hexNibble(Stripped[I]);
    int Lo = hexNibble(Stripped[I + 1]);
    if (Hi < 0 || Lo < 0)
      return false;
    Out.push_back(static_cast<uint8_t>((Hi << 4) | Lo));
  }
  return true;
}

std::vector<uint8_t> loadBytecodeFile(const std::string &Path) {
  std::ifstream In(Path, std::ios::binary);
  if (!In) {
    std::fprintf(stderr, "error: cannot open %s\n", Path.c_str());
    std::exit(2);
  }
  std::ostringstream Buf;
  Buf << In.rdbuf();
  const std::string Content = Buf.str();
  std::vector<uint8_t> Bytes;
  if (tryDecodeHex(Content, Bytes))
    return Bytes;
  Bytes.assign(Content.begin(), Content.end());
  return Bytes;
}

size_t findSolidityMetadataStart(const std::vector<uint8_t> &Code) {
  // Solidity CBOR blob starts with a2 64 69 70 66 73 58 22 ("ipfs").
  static const uint8_t Marker[] = {0xa2, 0x64, 0x69, 0x70,
                                   0x66, 0x73, 0x58, 0x22};
  if (Code.size() < sizeof(Marker))
    return Code.size();
  for (size_t I = 0; I + sizeof(Marker) <= Code.size(); ++I) {
    if (std::memcmp(Code.data() + I, Marker, sizeof(Marker)) == 0)
      return I;
  }
  return Code.size();
}

bool decodePushU64(const std::vector<uint8_t> &Code, size_t Pc, uint8_t Op,
                   uint64_t &Out) {
  if (!isPush1To32(Op))
    return false;
  const size_t N = static_cast<size_t>(Op - OP_PUSH1 + 1);
  if (Pc + 1 + N > Code.size())
    return false;
  uint64_t Value = 0;
  for (size_t I = 0; I < N; ++I) {
    if (N > 8 && I < N - 8 && Code[Pc + 1 + I] != 0)
      return false;
    Value = (Value << 8) | Code[Pc + 1 + I];
  }
  Out = Value;
  return true;
}

// Best-effort: Solidity creation bytecode copies runtime via CODECOPY+RETURN
// in the constructor, then appends the runtime (+ optional CBOR metadata).
bool tryExtractSolidityRuntime(const std::vector<uint8_t> &Creation,
                               std::vector<uint8_t> &Runtime) {
  const size_t Meta = findSolidityMetadataStart(Creation);
  const size_t SearchEnd = std::min(Creation.size(), static_cast<size_t>(128));
  uint64_t LastPush = 0;
  uint64_t PrevPush = 0;
  bool HaveLast = false;
  bool HavePrev = false;

  for (size_t Pc = 0; Pc < SearchEnd;) {
    const uint8_t Op = Creation[Pc];
    if (isPush1To32(Op)) {
      uint64_t Imm = 0;
      if (decodePushU64(Creation, Pc, Op, Imm)) {
        PrevPush = LastPush;
        HavePrev = HaveLast;
        LastPush = Imm;
        HaveLast = true;
      }
    } else if (Op == OP_CODECOPY && HaveLast && HavePrev) {
      size_t Q = Pc + 1;
      while (Q < SearchEnd && isStackManip(Creation[Q]))
        Q += opcodeLen(Creation[Q]);
      if (Q < SearchEnd && Creation[Q] == OP_RETURN) {
        const uint64_t Candidates[2][2] = {{LastPush, PrevPush},
                                           {PrevPush, LastPush}};
        for (const auto &Pair : Candidates) {
          const uint64_t Offset = Pair[0];
          const uint64_t Size = Pair[1];
          if (Size == 0 || Offset == 0 || Offset >= Meta)
            continue;
          if (Offset + Size > Meta && Offset + Size > Creation.size())
            continue;
          const size_t UseEnd =
              static_cast<size_t>(std::min<uint64_t>(Offset + Size, Meta));
          if (UseEnd <= Offset)
            continue;
          Runtime.assign(Creation.begin() + static_cast<size_t>(Offset),
                         Creation.begin() + UseEnd);
          const size_t RuntimeMeta = findSolidityMetadataStart(Runtime);
          if (RuntimeMeta < Runtime.size())
            Runtime.resize(RuntimeMeta);
          if (Runtime.size() >= 2 && Runtime[0] == 0x60 && Runtime[1] == 0x80)
            return true;
          if (Runtime.size() >= 4)
            return true;
        }
      }
    }
    Pc += opcodeLen(Op);
  }

  if (Meta < Creation.size() && Meta >= 4) {
    Runtime.assign(Creation.begin(), Creation.begin() + Meta);
    return true;
  }
  return false;
}

size_t countJumpDests(const std::vector<uint8_t> &Code) {
  size_t Count = 0;
  for (size_t Pc = 0; Pc < Code.size();) {
    const uint8_t Op = Code[Pc];
    if (Op == OP_JUMPDEST)
      ++Count;
    Pc += opcodeLen(Op);
  }
  return Count;
}

struct JumpCensus {
  size_t NJump = 0;
  size_t NJumpi = 0;
  size_t NResolved = 0;
  size_t NUnresolved = 0;
};

// Match buildCFGEdges: a JUMP/JUMPI is resolved if the single-target map,
// the ConstSet multi-target map, or the adjacent PUSH1..PUSH32 fallback
// names a valid JUMPDEST. Everything else is HasUnresolvedDynamicSuccessor.
JumpCensus countJumps(const std::vector<uint8_t> &Code,
                      const zen::evm::EVMBytecodeCache &Cache) {
  JumpCensus Out;
  size_t PrevPc = SIZE_MAX;
  uint8_t PrevOp = 0;
  for (size_t Pc = 0; Pc < Code.size();) {
    const uint8_t Op = Code[Pc];
    if (isJumpOp(Op)) {
      if (Op == OP_JUMP)
        ++Out.NJump;
      else
        ++Out.NJumpi;

      const uint32_t PC32 = static_cast<uint32_t>(Pc);
      bool Resolved = Cache.ResolvedJumpTargets.count(PC32) != 0 ||
                      Cache.ResolvedJumpMultiTargets.count(PC32) != 0;
      if (!Resolved && PrevPc != SIZE_MAX && isPush1To32(PrevOp) &&
          PrevPc + opcodeLen(PrevOp) == Pc &&
          PrevPc < Cache.PushValueMap.size() && Pc < Cache.JumpDestMap.size()) {
        const intx::uint256 Value = Cache.PushValueMap[PrevPc];
        if ((Value >> 64) == 0) {
          const uint64_t Dest = static_cast<uint64_t>(Value);
          if (Dest < Cache.JumpDestMap.size() && Cache.JumpDestMap[Dest] != 0)
            Resolved = true;
        }
      }
      if (Resolved)
        ++Out.NResolved;
      else
        ++Out.NUnresolved;
    }
    PrevPc = Pc;
    PrevOp = Op;
    Pc += opcodeLen(Op);
  }
  return Out;
}

struct ChunkCensus {
  size_t NChunks = 0;
  size_t NMeterBefore = 0;
  size_t NMeterAfter = 0;
  size_t NShifted = 0;
};

ChunkCensus countChunks(const zen::evm::EVMBytecodeCache &Cache) {
  ChunkCensus Out;
  const size_t N = Cache.GasChunkEnd.size();
  for (size_t Pc = 0; Pc < N; ++Pc) {
    if (Cache.GasChunkEnd[Pc] <= Pc)
      continue;
    ++Out.NChunks;
    const uint64_t Before =
        Pc < Cache.GasChunkCost.size() ? Cache.GasChunkCost[Pc] : 0;
    const uint64_t After =
        Pc < Cache.GasChunkCostSPP.size() ? Cache.GasChunkCostSPP[Pc] : 0;
    if (Before != 0)
      ++Out.NMeterBefore;
    if (After != 0)
      ++Out.NMeterAfter;
    if (Before != After)
      ++Out.NShifted;
  }
  return Out;
}

struct TimedCache {
  zen::evm::EVMBytecodeCache Cache;
  double Us = 0;
};

TimedCache buildTimedCache(const std::vector<uint8_t> &Code, bool EnableSPP,
                           bool EnableR1) {
  TimedCache Out;
  using Clock = zen::common::SteadyClock;
  const auto Start = Clock::now();
  zen::evm::buildBytecodeCache(Out.Cache,
                               reinterpret_cast<const std::byte *>(Code.data()),
                               Code.size(), EVMC_CANCUN, EnableSPP, EnableR1);
  const auto End = Clock::now();
  Out.Us = std::chrono::duration<double, std::micro>(End - Start).count();
  return Out;
}

double timeCacheBuildUs(const std::vector<uint8_t> &Code) {
  return buildTimedCache(Code, /*EnableSPP=*/true, /*EnableR1=*/true).Us;
}

bool parseOnOff(const std::string &S, bool &Out) {
  if (S == "on" || S == "1" || S == "true") {
    Out = true;
    return true;
  }
  if (S == "off" || S == "0" || S == "false") {
    Out = false;
    return true;
  }
  return false;
}

[[noreturn]] void usage(const char *Argv0, int RC) {
  std::fprintf(stderr,
               "usage: %s <n_jumpdests>\n"
               "       %s --bytecode <hex-or-bin-file> [--label <tag>] "
               "[--dump-r1-stats] [--slice auto|runtime|full] "
               "[--r1 on|off] [--spp on|off]\n",
               Argv0, Argv0);
  std::exit(RC);
}

} // namespace

int main(int Argc, char **Argv) {
  if (Argc < 2)
    usage(Argv[0], 2);

  std::string Label;
  std::string BytecodePath;
  std::string Slice = "auto";
  size_t SyntheticN = 0;
  bool Synthetic = true;
  bool DumpR1 = false;
  bool EnableR1 = true;
  bool EnableSPP = true;

  for (int I = 1; I < Argc; ++I) {
    const std::string Arg = Argv[I];
    if (Arg == "--bytecode" && I + 1 < Argc) {
      BytecodePath = Argv[++I];
      Synthetic = false;
    } else if (Arg == "--label" && I + 1 < Argc) {
      Label = Argv[++I];
    } else if (Arg == "--dump-r1-stats") {
      DumpR1 = true;
    } else if (Arg == "--slice" && I + 1 < Argc) {
      Slice = Argv[++I];
    } else if (Arg == "--r1" && I + 1 < Argc) {
      if (!parseOnOff(Argv[++I], EnableR1))
        usage(Argv[0], 2);
    } else if (Arg == "--spp" && I + 1 < Argc) {
      if (!parseOnOff(Argv[++I], EnableSPP))
        usage(Argv[0], 2);
    } else if (Arg.size() > 0 &&
               std::isdigit(static_cast<unsigned char>(Arg[0]))) {
      SyntheticN = static_cast<size_t>(std::stoull(Arg));
      Synthetic = true;
    } else {
      usage(Argv[0], 2);
    }
  }

  std::vector<uint8_t> Code;
  std::string UsedSlice = "synthetic";
  size_t NumJumpDests = 0;
  if (Synthetic) {
    Code = makeDynDispatchContract(SyntheticN);
    NumJumpDests = SyntheticN;
    if (Label.empty())
      Label = "synthetic";
  } else {
    std::vector<uint8_t> Loaded = loadBytecodeFile(BytecodePath);
    if (Slice == "full") {
      Code = std::move(Loaded);
      UsedSlice = "full";
    } else if (Slice == "runtime") {
      if (!tryExtractSolidityRuntime(Loaded, Code)) {
        std::fprintf(stderr, "error: failed to extract Solidity runtime from %s\n",
                     BytecodePath.c_str());
        return 2;
      }
      UsedSlice = "runtime";
    } else if (Slice == "auto") {
      if (tryExtractSolidityRuntime(Loaded, Code)) {
        UsedSlice = "runtime";
      } else {
        Code = std::move(Loaded);
        UsedSlice = "full";
      }
    } else {
      usage(Argv[0], 2);
    }
    NumJumpDests = countJumpDests(Code);
    if (Label.empty()) {
      auto Slash = BytecodePath.find_last_of('/');
      const std::string Base = Slash == std::string::npos
                                   ? BytecodePath
                                   : BytecodePath.substr(Slash + 1);
      auto Dot = Base.find_last_of('.');
      Label = Dot == std::string::npos ? Base : Base.substr(0, Dot);
    }
  }

  if (!DumpR1) {
    const double Us = timeCacheBuildUs(Code);
    std::printf("%s,%zu,%.3f\n", Label.c_str(), NumJumpDests, Us);
    return 0;
  }

  const TimedCache Built = buildTimedCache(Code, EnableSPP, EnableR1);
  const JumpCensus J = countJumps(Code, Built.Cache);
  const ChunkCensus C = countChunks(Built.Cache);
  const size_t NJumpTotal = J.NJump + J.NJumpi;
  const size_t NJDBlocked = J.NUnresolved > 0 ? NumJumpDests : 0;
  const double UnresolvedFrac =
      NJumpTotal == 0 ? 0.0
                      : static_cast<double>(J.NUnresolved) /
                            static_cast<double>(NJumpTotal);
  const double JDBlockedFrac =
      NumJumpDests == 0 ? 0.0
                        : static_cast<double>(NJDBlocked) /
                              static_cast<double>(NumJumpDests);
  const size_t SPPZeroed =
      C.NMeterBefore > C.NMeterAfter ? C.NMeterBefore - C.NMeterAfter : 0;
  const size_t NMulti = Built.Cache.ResolvedJumpMultiTargets.size();

  std::printf(
      "%s,%s,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%.6f,%zu,%.6f,%zu,%zu,%zu,%zu,%zu,"
      "%zu,%.3f,%d,%d,%zu\n",
      Label.c_str(), UsedSlice.c_str(), Code.size(), NumJumpDests, J.NJump,
      J.NJumpi, NJumpTotal, J.NResolved, J.NUnresolved, UnresolvedFrac,
      NJDBlocked, JDBlockedFrac, J.NUnresolved, C.NChunks, C.NMeterBefore,
      C.NMeterAfter, SPPZeroed, C.NShifted, Built.Us, EnableR1 ? 1 : 0,
      EnableSPP ? 1 : 0, NMulti);
  return 0;
}
