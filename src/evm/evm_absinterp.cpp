// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "evm/evm_absinterp.h"

#include <algorithm>
#include <cstdint>
#include <deque>
#include <map>
#include <utility>
#include <vector>

namespace zen::evm {
namespace {

constexpr size_t kMaxAbsStackDepth = 64;
constexpr size_t kMaxConstSet = 16;
constexpr uint32_t kIterFactor = 8;
constexpr uint32_t kNoBlock = ~uint32_t{0};

enum class AbsKind : uint8_t { Const = 0, ConstSet = 1, Top = 2 };

struct AbsValue {
  AbsKind Kind = AbsKind::Top;
  uint64_t ConstVal = 0;
  uint16_t SetId = 0;

  static AbsValue top() { return {}; }
  static AbsValue fromConst(uint64_t V) {
    AbsValue A;
    A.Kind = AbsKind::Const;
    A.ConstVal = V;
    return A;
  }

  bool operator==(const AbsValue &O) const {
    if (Kind != O.Kind) {
      return false;
    }
    if (Kind == AbsKind::Const) {
      return ConstVal == O.ConstVal;
    }
    if (Kind == AbsKind::ConstSet) {
      return SetId == O.SetId;
    }
    return true;
  }
  bool operator!=(const AbsValue &O) const { return !(*this == O); }
};

using AbsStack = std::vector<AbsValue>;

class ConstSetInterner {
public:
  const std::vector<uint64_t> &get(uint16_t Id) const { return Sets.at(Id); }

  AbsValue fromSet(std::vector<uint64_t> Vals) {
    std::sort(Vals.begin(), Vals.end());
    Vals.erase(std::unique(Vals.begin(), Vals.end()), Vals.end());
    if (Vals.empty()) {
      return AbsValue::top();
    }
    if (Vals.size() == 1) {
      return AbsValue::fromConst(Vals[0]);
    }
    if (Vals.size() > kMaxConstSet) {
      return AbsValue::top();
    }
    auto It = Index.find(Vals);
    if (It != Index.end()) {
      AbsValue A;
      A.Kind = AbsKind::ConstSet;
      A.SetId = It->second;
      return A;
    }
    if (Sets.size() >= 0xFFFE) {
      return AbsValue::top();
    }
    const uint16_t Id = static_cast<uint16_t>(Sets.size());
    Index.emplace(Vals, Id);
    Sets.push_back(std::move(Vals));
    AbsValue A;
    A.Kind = AbsKind::ConstSet;
    A.SetId = Id;
    return A;
  }

  AbsValue join(AbsValue A, AbsValue B) {
    if (A.Kind == AbsKind::Top || B.Kind == AbsKind::Top) {
      return AbsValue::top();
    }
    if (A == B) {
      return A;
    }
    std::vector<uint64_t> Vals;
    append(Vals, A);
    append(Vals, B);
    return fromSet(std::move(Vals));
  }

  bool allValidJumpDest(AbsValue V, const std::vector<uint8_t> &JD,
                        size_t CodeSize, std::vector<uint32_t> &Out) const {
    Out.clear();
    if (V.Kind == AbsKind::Const) {
      if (V.ConstVal < CodeSize && JD[static_cast<size_t>(V.ConstVal)] != 0) {
        Out.push_back(static_cast<uint32_t>(V.ConstVal));
        return true;
      }
      return false;
    }
    if (V.Kind != AbsKind::ConstSet) {
      return false;
    }
    for (uint64_t D : get(V.SetId)) {
      if (D >= CodeSize || JD[static_cast<size_t>(D)] == 0) {
        return false;
      }
      Out.push_back(static_cast<uint32_t>(D));
    }
    return !Out.empty();
  }

private:
  void append(std::vector<uint64_t> &Out, AbsValue V) const {
    if (V.Kind == AbsKind::Const) {
      Out.push_back(V.ConstVal);
    } else if (V.Kind == AbsKind::ConstSet) {
      const auto &S = get(V.SetId);
      Out.insert(Out.end(), S.begin(), S.end());
    }
  }

  std::vector<std::vector<uint64_t>> Sets;
  std::map<std::vector<uint64_t>, uint16_t> Index;
};

static uint8_t opcodeLen(uint8_t Op) {
  if (Op >= static_cast<uint8_t>(evmc_opcode::OP_PUSH1) &&
      Op <= static_cast<uint8_t>(evmc_opcode::OP_PUSH32)) {
    return static_cast<uint8_t>(Op - static_cast<uint8_t>(evmc_opcode::OP_PUSH1) +
                                2);
  }
  return 1;
}

static bool isHardTerminator(uint8_t Op) {
  switch (static_cast<evmc_opcode>(Op)) {
  case evmc_opcode::OP_STOP:
  case evmc_opcode::OP_RETURN:
  case evmc_opcode::OP_REVERT:
  case evmc_opcode::OP_SELFDESTRUCT:
  case evmc_opcode::OP_INVALID:
  case evmc_opcode::OP_JUMP:
    return true;
  default:
    return false;
  }
}

static AbsValue pushConst(const common::Byte *Code, size_t CodeSize,
                          size_t ImmStart, size_t ImmSize) {
  if (ImmSize == 0) {
    return AbsValue::fromConst(0);
  }
  bool FitsU64 = true;
  if (ImmSize > sizeof(uint64_t)) {
    for (size_t I = 0; I < ImmSize - sizeof(uint64_t); ++I) {
      const size_t Idx = ImmStart + I;
      if (Idx < CodeSize && static_cast<uint8_t>(Code[Idx]) != 0) {
        FitsU64 = false;
        break;
      }
    }
  }
  if (!FitsU64) {
    return AbsValue::top();
  }
  uint64_t Low = 0;
  const size_t ValueStart =
      ImmSize > sizeof(uint64_t) ? ImmSize - sizeof(uint64_t) : size_t{0};
  for (size_t I = ValueStart; I < ImmSize; ++I) {
    const size_t Idx = ImmStart + I;
    const uint8_t B =
        Idx < CodeSize ? static_cast<uint8_t>(Code[Idx]) : uint8_t{0};
    Low = (Low << 8) | static_cast<uint64_t>(B);
  }
  return AbsValue::fromConst(Low);
}

static void capStack(AbsStack &S) {
  if (S.size() > kMaxAbsStackDepth) {
    S.assign(kMaxAbsStackDepth, AbsValue::top());
  }
}

static void ensureDepth(AbsStack &S, size_t Required) {
  if (S.size() >= Required) {
    return;
  }
  S.insert(S.begin(), Required - S.size(), AbsValue::top());
  capStack(S);
}

static AbsStack joinStacks(const AbsStack &A, const AbsStack &B,
                           ConstSetInterner &Intern) {
  const size_t NA = A.size();
  const size_t NB = B.size();
  const size_t N = std::max(NA, NB);
  if (N == 0) {
    return {};
  }
  if (N > kMaxAbsStackDepth) {
    return AbsStack(kMaxAbsStackDepth, AbsValue::top());
  }
  AbsStack R(N, AbsValue::top());
  for (size_t Dist = 0; Dist < N; ++Dist) {
    const AbsValue VA =
        Dist < NA ? A[NA - 1 - Dist] : AbsValue::top();
    const AbsValue VB =
        Dist < NB ? B[NB - 1 - Dist] : AbsValue::top();
    R[N - 1 - Dist] = Intern.join(VA, VB);
  }
  return R;
}

struct AIBlock {
  uint32_t Start = 0;
  uint32_t End = 0;
  uint32_t LastPc = 0;
  uint8_t LastOp = 0;
};

struct BlockEffect {
  AbsValue JumpDest = AbsValue::top();
  AbsStack Exit;
  bool IsJump = false;
  bool IsJumpi = false;
  bool Fallthrough = false;
};

static void buildAIBlocks(const common::Byte *Code, size_t CodeSize,
                          std::vector<AIBlock> &Blocks,
                          std::vector<uint32_t> &BlockAtPc,
                          std::vector<uint32_t> &JumpDestBlocks) {
  BlockAtPc.assign(CodeSize, kNoBlock);
  Blocks.clear();
  JumpDestBlocks.clear();
  if (CodeSize == 0) {
    return;
  }
  Blocks.reserve(CodeSize);

  size_t Pc = 0;
  while (Pc < CodeSize) {
    const uint8_t StartOp = static_cast<uint8_t>(Code[Pc]);
    if (StartOp == static_cast<uint8_t>(evmc_opcode::OP_JUMPDEST)) {
      JumpDestBlocks.push_back(static_cast<uint32_t>(Blocks.size()));
    }

    AIBlock Block;
    Block.Start = static_cast<uint32_t>(Pc);
    size_t Cur = Pc;
    while (Cur < CodeSize) {
      const uint8_t Op = static_cast<uint8_t>(Code[Cur]);
      if (Cur != Block.Start &&
          Op == static_cast<uint8_t>(evmc_opcode::OP_JUMPDEST)) {
        break;
      }
      Block.LastPc = static_cast<uint32_t>(Cur);
      Block.LastOp = Op;
      Cur += opcodeLen(Op);
      if (isHardTerminator(Op) ||
          Op == static_cast<uint8_t>(evmc_opcode::OP_JUMPI)) {
        break;
      }
    }
    Block.End = static_cast<uint32_t>(Cur);
    BlockAtPc[Block.Start] = static_cast<uint32_t>(Blocks.size());
    Blocks.push_back(Block);
    Pc = Cur;
  }
}

static BlockEffect interpretBlock(const AIBlock &Block, const AbsStack &Entry,
                                  const common::Byte *Code, size_t CodeSize,
                                  const evmc_instruction_metrics *Metrics) {
  BlockEffect Eff;
  AbsStack S = Entry;
  size_t Pc = Block.Start;
  while (Pc < Block.End && Pc < CodeSize) {
    const uint8_t Op = static_cast<uint8_t>(Code[Pc]);
    const size_t ImmSize =
        (Op >= static_cast<uint8_t>(evmc_opcode::OP_PUSH0) &&
         Op <= static_cast<uint8_t>(evmc_opcode::OP_PUSH32))
            ? static_cast<size_t>(Op -
                                  static_cast<uint8_t>(evmc_opcode::OP_PUSH0))
            : size_t{0};
    ++Pc;

    if (Op == static_cast<uint8_t>(evmc_opcode::OP_JUMP)) {
      ensureDepth(S, 1);
      Eff.JumpDest = S.back();
      S.pop_back();
      Eff.IsJump = true;
      Eff.Exit = std::move(S);
      return Eff;
    }
    if (Op == static_cast<uint8_t>(evmc_opcode::OP_JUMPI)) {
      ensureDepth(S, 2);
      Eff.JumpDest = S.back();
      S.pop_back();
      S.pop_back();
      Eff.IsJumpi = true;
      Eff.IsJump = true;
      Eff.Fallthrough = true;
      Eff.Exit = std::move(S);
      return Eff;
    }
    if (isHardTerminator(Op)) {
      Eff.Exit = std::move(S);
      return Eff;
    }

    if (Op >= static_cast<uint8_t>(evmc_opcode::OP_DUP1) &&
        Op <= static_cast<uint8_t>(evmc_opcode::OP_DUP16)) {
      const size_t Depth = static_cast<size_t>(
          Op - static_cast<uint8_t>(evmc_opcode::OP_DUP1) + 1);
      ensureDepth(S, Depth);
      S.push_back(S[S.size() - Depth]);
      capStack(S);
    } else if (Op >= static_cast<uint8_t>(evmc_opcode::OP_SWAP1) &&
               Op <= static_cast<uint8_t>(evmc_opcode::OP_SWAP16)) {
      const size_t Depth = static_cast<size_t>(
          Op - static_cast<uint8_t>(evmc_opcode::OP_SWAP1) + 2);
      ensureDepth(S, Depth);
      std::swap(S.back(), S[S.size() - Depth]);
    } else if (Op >= static_cast<uint8_t>(evmc_opcode::OP_PUSH0) &&
               Op <= static_cast<uint8_t>(evmc_opcode::OP_PUSH32)) {
      S.push_back(pushConst(Code, CodeSize, Pc, ImmSize));
      Pc += ImmSize;
      capStack(S);
    } else {
      const int PopCount = Metrics[Op].stack_height_required;
      const int PushCount = PopCount + Metrics[Op].stack_height_change;
      ensureDepth(S, static_cast<size_t>(PopCount > 0 ? PopCount : 0));
      for (int I = 0; I < PopCount; ++I) {
        if (!S.empty()) {
          S.pop_back();
        }
      }
      for (int I = 0; I < PushCount; ++I) {
        S.push_back(AbsValue::top());
      }
      capStack(S);
    }
  }
  Eff.Fallthrough = Block.End < CodeSize && !isHardTerminator(Block.LastOp) &&
                    Block.LastOp != static_cast<uint8_t>(evmc_opcode::OP_JUMPI);
  Eff.Exit = std::move(S);
  return Eff;
}

static bool enqueueJoin(uint32_t Succ, const AbsStack &Incoming,
                         std::vector<AbsStack> &Entry,
                         std::vector<uint8_t> &Reached,
                         std::deque<uint32_t> &Work, ConstSetInterner &Intern) {
  if (Succ == kNoBlock) {
    return false;
  }
  if (Reached[Succ] == 0) {
    Entry[Succ] = Incoming;
    Reached[Succ] = 1;
    Work.push_back(Succ);
    return true;
  }
  AbsStack Joined = joinStacks(Entry[Succ], Incoming, Intern);
  if (Joined != Entry[Succ]) {
    Entry[Succ] = std::move(Joined);
    Work.push_back(Succ);
    return true;
  }
  return false;
}

} // namespace

void resolveJumpTargetsCrossBlock(
    const common::Byte *Code, size_t CodeSize,
    const std::vector<uint8_t> &JumpDestMap,
    const evmc_instruction_metrics *Metrics,
    std::unordered_map<uint32_t, uint32_t> &Resolved,
    std::unordered_map<uint32_t, std::vector<uint32_t>> &Multi) {
  Multi.clear();
  if (CodeSize == 0 || !Metrics) {
    return;
  }

  std::vector<AIBlock> Blocks;
  std::vector<uint32_t> BlockAtPc;
  std::vector<uint32_t> JumpDestBlocks;
  buildAIBlocks(Code, CodeSize, Blocks, BlockAtPc, JumpDestBlocks);
  if (Blocks.empty()) {
    return;
  }

  ConstSetInterner Intern;
  std::vector<AbsStack> Entry(Blocks.size());
  std::vector<uint8_t> Reached(Blocks.size(), 0);
  std::deque<uint32_t> Work;
  Entry[0] = AbsStack{};
  Reached[0] = 1;
  Work.push_back(0);

  const uint32_t IterCap =
      static_cast<uint32_t>(Blocks.size()) * kIterFactor + 1;
  uint32_t Iters = 0;
  bool Converged = true;
  bool HasTopJump = false;
  std::vector<AbsValue> JumpAbs(Blocks.size(), AbsValue::top());
  std::vector<uint8_t> JumpSeen(Blocks.size(), 0);

  while (!Work.empty()) {
    if (Iters++ >= IterCap) {
      Converged = false;
      break;
    }
    const uint32_t Id = Work.front();
    Work.pop_front();
    const BlockEffect Eff =
        interpretBlock(Blocks[Id], Entry[Id], Code, CodeSize, Metrics);
    if (Eff.IsJump) {
      JumpAbs[Id] = Eff.JumpDest;
      JumpSeen[Id] = 1;
      if (Eff.JumpDest.Kind == AbsKind::Top) {
        HasTopJump = true;
        // invalidate_suspect: any reached Top jump ⇒ fail-closed, no commit.
        break;
      }
      std::vector<uint32_t> Dests;
      if (Intern.allValidJumpDest(Eff.JumpDest, JumpDestMap, CodeSize, Dests)) {
        for (uint32_t DestPc : Dests) {
          const uint32_t Succ = BlockAtPc[DestPc];
          enqueueJoin(Succ, Eff.Exit, Entry, Reached, Work, Intern);
        }
      }
    }
    if (Eff.Fallthrough && Blocks[Id].End < CodeSize) {
      const uint32_t Succ = BlockAtPc[Blocks[Id].End];
      enqueueJoin(Succ, Eff.Exit, Entry, Reached, Work, Intern);
    }
  }

  if (!Work.empty() && !HasTopJump) {
    Converged = false;
  }

  if (!Converged || HasTopJump) {
    // Fail-closed: leave the block-local Resolved map unchanged and write
    // no multi-targets. ImplicitDynamicPredCount semantics stay as today.
    Multi.clear();
    return;
  }

  for (size_t Id = 0; Id < Blocks.size(); ++Id) {
    if (Reached[Id] == 0 || JumpSeen[Id] == 0) {
      continue;
    }
    std::vector<uint32_t> Dests;
    if (!Intern.allValidJumpDest(JumpAbs[Id], JumpDestMap, CodeSize, Dests)) {
      continue;
    }
    const uint32_t JumpPC = Blocks[Id].LastPc;
    if (Dests.size() == 1) {
      Resolved[JumpPC] = Dests[0];
      Multi.erase(JumpPC);
    } else {
      Resolved.erase(JumpPC);
      Multi[JumpPC] = std::move(Dests);
    }
  }
}

} // namespace zen::evm
