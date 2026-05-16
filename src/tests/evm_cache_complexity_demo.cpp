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
// Output: CSV `<label>,<n_jumpdests>,<build_us>` on stdout.
// With ZEN_EVM_CACHE_PROFILE=ON, per-phase rows also emit on stderr.

#include "evm/evm_cache.h"
#include "platform/platform.h"

#include <evmc/evmc.h>
#include <evmc/instructions.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {

constexpr uint8_t OP_STOP = static_cast<uint8_t>(evmc_opcode::OP_STOP);
constexpr uint8_t OP_CALLDATALOAD =
    static_cast<uint8_t>(evmc_opcode::OP_CALLDATALOAD);
constexpr uint8_t OP_JUMP = static_cast<uint8_t>(evmc_opcode::OP_JUMP);
constexpr uint8_t OP_JUMPDEST = static_cast<uint8_t>(evmc_opcode::OP_JUMPDEST);

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

size_t countJumpDests(const std::vector<uint8_t> &Code) {
  size_t Count = 0;
  for (size_t Pc = 0; Pc < Code.size();) {
    const uint8_t Op = Code[Pc];
    if (Op == OP_JUMPDEST)
      ++Count;
    if (Op >= static_cast<uint8_t>(evmc_opcode::OP_PUSH1) &&
        Op <= static_cast<uint8_t>(evmc_opcode::OP_PUSH32)) {
      Pc += Op - static_cast<uint8_t>(evmc_opcode::OP_PUSH1) + 2;
    } else {
      Pc += 1;
    }
  }
  return Count;
}

double timeCacheBuildUs(const std::vector<uint8_t> &Code) {
  using Clock = zen::common::SteadyClock;
  const auto Start = Clock::now();
  zen::evm::EVMBytecodeCache Cache;
  zen::evm::buildBytecodeCache(Cache,
                               reinterpret_cast<const std::byte *>(Code.data()),
                               Code.size(), EVMC_CANCUN, /*EnableSPP=*/true);
  const auto End = Clock::now();
  return std::chrono::duration<double, std::micro>(End - Start).count();
}

[[noreturn]] void usage(const char *Argv0, int RC) {
  std::fprintf(stderr,
               "usage: %s <n_jumpdests>\n"
               "       %s --bytecode <hex-or-bin-file> [--label <tag>]\n",
               Argv0, Argv0);
  std::exit(RC);
}

} // namespace

int main(int Argc, char **Argv) {
  if (Argc < 2)
    usage(Argv[0], 2);

  std::string Label;
  std::string BytecodePath;
  size_t SyntheticN = 0;
  bool Synthetic = true;

  for (int I = 1; I < Argc; ++I) {
    const std::string Arg = Argv[I];
    if (Arg == "--bytecode" && I + 1 < Argc) {
      BytecodePath = Argv[++I];
      Synthetic = false;
    } else if (Arg == "--label" && I + 1 < Argc) {
      Label = Argv[++I];
    } else if (Arg.size() > 0 &&
               std::isdigit(static_cast<unsigned char>(Arg[0]))) {
      SyntheticN = static_cast<size_t>(std::stoull(Arg));
      Synthetic = true;
    } else {
      usage(Argv[0], 2);
    }
  }

  std::vector<uint8_t> Code;
  size_t NumJumpDests = 0;
  if (Synthetic) {
    Code = makeDynDispatchContract(SyntheticN);
    NumJumpDests = SyntheticN;
    if (Label.empty())
      Label = "synthetic";
  } else {
    Code = loadBytecodeFile(BytecodePath);
    NumJumpDests = countJumpDests(Code);
    if (Label.empty()) {
      // Derive label from filename (last path component, no extension)
      auto Slash = BytecodePath.find_last_of('/');
      const std::string Base = Slash == std::string::npos
                                   ? BytecodePath
                                   : BytecodePath.substr(Slash + 1);
      auto Dot = Base.find_last_of('.');
      Label = Dot == std::string::npos ? Base : Base.substr(0, Dot);
    }
  }

  const double Us = timeCacheBuildUs(Code);
  std::printf("%s,%zu,%.3f\n", Label.c_str(), NumJumpDests, Us);
  return 0;
}
