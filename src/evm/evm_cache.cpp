// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "evm/evm_cache.h"

#include "evm/evm.h"
#include "evmc/instructions.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <unordered_map>
#include <utility>

namespace zen::evm {

// - Cache entries are indexed by EVM PC (byte offset into `Code`).
// - `JumpDestMap[pc]` marks valid JUMP destinations (JUMPDEST outside PUSH
//   data).
// - `PushValueMap[pc]` stores decoded PUSHn immediates (big-endian,
//   zero-padded).
// - `GasChunkEnd/Cost[pc]` describe straight-line gas blocks whose base gas can
//   be charged once, then executed via no-gas handlers until `GasChunkEnd[pc]`.
//   In SPP mode, the cost can be shifted to earlier blocks to reduce metering
//   points. Blocks stop at JUMPDEST boundaries and control/host opcodes;
//   dynamic/extra gas remains charged inside opcode handlers.

namespace {

// Returns the total byte length of an opcode (including PUSH immediate bytes).
static uint8_t opcodeLen(uint8_t OpcodeU8) {
  if (OpcodeU8 >= static_cast<uint8_t>(evmc_opcode::OP_PUSH1) &&
      OpcodeU8 <= static_cast<uint8_t>(evmc_opcode::OP_PUSH32)) {
    return static_cast<uint8_t>(
        OpcodeU8 - static_cast<uint8_t>(evmc_opcode::OP_PUSH1) + 2);
  }
  return 1;
}

static bool isGasChunkTerminator(uint8_t OpcodeU8) {
  switch (static_cast<evmc_opcode>(OpcodeU8)) {
  case evmc_opcode::OP_STOP:
  case evmc_opcode::OP_RETURN:
  case evmc_opcode::OP_REVERT:
  case evmc_opcode::OP_SELFDESTRUCT:
  case evmc_opcode::OP_INVALID:
  case evmc_opcode::OP_JUMP:
  case evmc_opcode::OP_JUMPI:
  case evmc_opcode::OP_GAS:
  case evmc_opcode::OP_CREATE:
  case evmc_opcode::OP_CREATE2:
  case evmc_opcode::OP_CALL:
  case evmc_opcode::OP_CALLCODE:
  case evmc_opcode::OP_DELEGATECALL:
  case evmc_opcode::OP_STATICCALL:
    return true;
  default:
    return false;
  }
}

static bool isJumpOpcode(uint8_t OpcodeU8) {
  return OpcodeU8 == static_cast<uint8_t>(evmc_opcode::OP_JUMP) ||
         OpcodeU8 == static_cast<uint8_t>(evmc_opcode::OP_JUMPI);
}

static bool isConditionalJumpOpcode(uint8_t OpcodeU8) {
  return OpcodeU8 == static_cast<uint8_t>(evmc_opcode::OP_JUMPI);
}

static bool isPushOpcode(uint8_t OpcodeU8) {
  return OpcodeU8 >= static_cast<uint8_t>(evmc_opcode::OP_PUSH1) &&
         OpcodeU8 <= static_cast<uint8_t>(evmc_opcode::OP_PUSH32);
}

static uint64_t loadBeUint64(const zen::common::Byte *Src) {
  uint64_t Value = 0;
  std::memcpy(&Value, Src, sizeof(Value));
  return intx::to_big_endian(Value);
}

static uint64_t loadBeUint64Partial(const zen::common::Byte *Src, size_t Len) {
  if (Len == 0) {
    return 0;
  }
  if (Len == 8) {
    return loadBeUint64(Src);
  }
  uint64_t Value = 0;
  std::memcpy(reinterpret_cast<uint8_t *>(&Value) + (sizeof(Value) - Len), Src,
              Len);
  return intx::to_big_endian(Value);
}

static intx::uint256 loadBeUint256(const zen::common::Byte *Src, size_t Len) {
  intx::uint256 Value;
  if (Len <= 8) {
    Value[0] = loadBeUint64Partial(Src, Len);
    return Value;
  }

  Value[0] = loadBeUint64(Src + Len - 8);
  if (Len <= 16) {
    Value[1] = loadBeUint64Partial(Src, Len - 8);
    return Value;
  }

  Value[1] = loadBeUint64(Src + Len - 16);
  if (Len <= 24) {
    Value[2] = loadBeUint64Partial(Src, Len - 16);
    return Value;
  }

  Value[2] = loadBeUint64(Src + Len - 24);
  Value[3] = loadBeUint64Partial(Src, Len - 24);
  return Value;
}

// Decodes the PUSH immediate at `Pc` and zero-pads if the code ends early.
static intx::uint256 loadPushValue(const zen::common::Byte *Code,
                                   size_t CodeSize, size_t Pc,
                                   uint8_t NumBytes) {
  const size_t Offset = Pc + 1;
  if (Offset >= CodeSize) {
    return 0;
  }

  const size_t AvailableBytes = CodeSize - Offset;
  const size_t CopyBytes = std::min<size_t>(NumBytes, AvailableBytes);
  if (CopyBytes == 0) {
    return 0;
  }

  intx::uint256 Value = loadBeUint256(Code + Offset, CopyBytes);
  const size_t MissingBytes = static_cast<size_t>(NumBytes) - CopyBytes;
  if (MissingBytes != 0) {
    Value <<= static_cast<uint64_t>(MissingBytes * 8);
  }
  return Value;
}

static void
buildJumpDestMapAndPushCache(const zen::common::Byte *Code, size_t CodeSize,
                             std::vector<uint8_t> &JumpDestMap,
                             std::vector<intx::uint256> &PushValueMap) {
  for (size_t Pc = 0; Pc < CodeSize; ++Pc) {
    const zen::common::Byte CurOpcode = Code[Pc];
    if (CurOpcode == static_cast<zen::common::Byte>(evmc_opcode::OP_JUMPDEST)) {
      JumpDestMap[Pc] = 1;
      continue;
    }
    const uint8_t CurOpcodeU8 = static_cast<uint8_t>(CurOpcode);
    if (CurOpcodeU8 >= static_cast<uint8_t>(evmc_opcode::OP_PUSH1) &&
        CurOpcodeU8 <= static_cast<uint8_t>(evmc_opcode::OP_PUSH32)) {
      const uint8_t NumBytes =
          CurOpcodeU8 - static_cast<uint8_t>(evmc_opcode::OP_PUSH1) + 1;
      PushValueMap[Pc] = loadPushValue(Code, CodeSize, Pc, NumBytes);
      Pc += NumBytes;
    }
  }
}

struct GasBlock {
  uint32_t Start = 0;
  uint32_t End = 0;
  uint32_t LastPc = 0;
  uint32_t PrevPc = UINT32_MAX;
  uint8_t LastOpcode = 0;
  uint8_t PrevOpcode = 0;
  uint64_t Cost = 0;
  std::vector<uint32_t> Succs;
  std::vector<uint32_t> Preds;
};

static void addEdge(std::vector<GasBlock> &Blocks, uint32_t From, uint32_t To) {
  auto &FromSuccs = Blocks[From].Succs;
  if (std::find(FromSuccs.begin(), FromSuccs.end(), To) == FromSuccs.end()) {
    FromSuccs.push_back(To);
  }
  auto &ToPreds = Blocks[To].Preds;
  if (std::find(ToPreds.begin(), ToPreds.end(), From) == ToPreds.end()) {
    ToPreds.push_back(From);
  }
}

// Split critical edges: insert empty blocks on edges from nodes with
// multiple successors to nodes with multiple predecessors.
// Returns true if any edges were split.
static bool splitCriticalEdges(std::vector<GasBlock> &Blocks, size_t CodeSize) {
  bool Changed = false;
  std::vector<std::pair<uint32_t, uint32_t>> EdgesToSplit;

  // Find critical edges
  for (size_t FromId = 0; FromId < Blocks.size(); ++FromId) {
    if (Blocks[FromId].Succs.size() <= 1) {
      continue; // Not a critical edge source
    }
    for (uint32_t ToId : Blocks[FromId].Succs) {
      if (Blocks[ToId].Preds.size() > 1) {
        // Critical edge: From has multiple succs, To has multiple preds
        EdgesToSplit.push_back({static_cast<uint32_t>(FromId), ToId});
      }
    }
  }

  // Split each critical edge by inserting an empty block
  for (const auto &[FromId, ToId] : EdgesToSplit) {
    // Create new empty block
    GasBlock NewBlock;
    NewBlock.Start = Blocks[FromId].End; // Logically between From and To

    if (NewBlock.Start >= CodeSize) {
      continue;
    }

    NewBlock.End = Blocks[FromId].End;
    NewBlock.LastPc = Blocks[FromId].End;
    NewBlock.PrevPc = UINT32_MAX;
    NewBlock.LastOpcode = 0;
    NewBlock.PrevOpcode = 0;
    NewBlock.Cost = 0; // Empty block has no cost

    const uint32_t NewId = static_cast<uint32_t>(Blocks.size());

    // Remove edge From -> To
    auto &FromSuccs = Blocks[FromId].Succs;
    FromSuccs.erase(std::remove(FromSuccs.begin(), FromSuccs.end(), ToId),
                    FromSuccs.end());
    auto &ToPreds = Blocks[ToId].Preds;
    ToPreds.erase(std::remove(ToPreds.begin(), ToPreds.end(), FromId),
                  ToPreds.end());

    // Add edges: From -> New, New -> To
    Blocks.push_back(NewBlock);
    addEdge(Blocks, FromId, NewId);
    addEdge(Blocks, NewId, ToId);

    Changed = true;
  }

  return Changed;
}

static void buildGasBlocks(const zen::common::Byte *Code, size_t CodeSize,
                           const evmc_instruction_metrics *MetricsTable,
                           std::vector<GasBlock> &Blocks,
                           std::vector<uint32_t> &BlockAtPc) {
  if (CodeSize == 0) {
    return;
  }

  std::vector<uint8_t> IsBlockStart(CodeSize, 0);
  IsBlockStart[0] = 1;

  for (size_t Pc = 0; Pc < CodeSize;) {
    const uint8_t CurOpcodeU8 = static_cast<uint8_t>(Code[Pc]);
    if (CurOpcodeU8 == static_cast<uint8_t>(evmc_opcode::OP_JUMPDEST)) {
      IsBlockStart[Pc] = 1;
    }

    const uint8_t Len = opcodeLen(CurOpcodeU8);
    if (isGasChunkTerminator(CurOpcodeU8)) {
      const size_t NextPc = Pc + Len;
      if (NextPc < CodeSize) {
        IsBlockStart[NextPc] = 1;
      }
    }
    Pc += Len;
  }

  BlockAtPc.assign(CodeSize, UINT32_MAX);

  size_t Pc = 0;
  while (Pc < CodeSize) {
    if (IsBlockStart[Pc] == 0) {
      ++Pc;
      continue;
    }

    GasBlock Block;
    Block.Start = static_cast<uint32_t>(Pc);

    if (Block.Start >= CodeSize) {
      break;
    }

    size_t CurPc = Pc;
    while (CurPc < CodeSize) {
      if (CurPc != Block.Start && IsBlockStart[CurPc] != 0) {
        break;
      }

      const uint8_t CurOpcodeU8 = static_cast<uint8_t>(Code[CurPc]);
      Block.PrevPc = Block.LastPc;
      Block.PrevOpcode = Block.LastOpcode;
      Block.LastPc = static_cast<uint32_t>(CurPc);
      Block.LastOpcode = CurOpcodeU8;
      Block.Cost += MetricsTable[CurOpcodeU8].gas_cost;

      CurPc += opcodeLen(CurOpcodeU8);
      if (isGasChunkTerminator(CurOpcodeU8)) {
        break;
      }
    }

    Block.End = static_cast<uint32_t>(CurPc);
    const uint32_t BlockId = static_cast<uint32_t>(Blocks.size());
    Blocks.push_back(std::move(Block));
    BlockAtPc[Pc] = BlockId;
    Pc = CurPc;
  }
}

static bool resolveConstantJumpTarget(const std::vector<uint8_t> &JumpDestMap,
                                      const std::vector<intx::uint256> &PushMap,
                                      size_t CodeSize, const GasBlock &Block,
                                      uint32_t &DestPc) {
  if (!isJumpOpcode(Block.LastOpcode) || Block.PrevPc == UINT32_MAX) {
    return false;
  }

  if (!isPushOpcode(Block.PrevOpcode)) {
    return false;
  }

  if (Block.PrevPc + opcodeLen(Block.PrevOpcode) != Block.LastPc) {
    return false;
  }

  const intx::uint256 Value = PushMap[Block.PrevPc];
  if ((Value >> 64) != 0) {
    return false;
  }

  const uint64_t Dest = static_cast<uint64_t>(Value);
  if (Dest >= CodeSize) {
    return false;
  }

  if (JumpDestMap[Dest] == 0) {
    return false;
  }

  DestPc = static_cast<uint32_t>(Dest);
  return true;
}

static size_t bitsetWordCount(size_t NumBits) { return (NumBits + 63) / 64; }

static void bitsetSetAll(std::vector<uint64_t> &Bits, size_t NumBits) {
  std::fill(Bits.begin(), Bits.end(), ~uint64_t{0});
  const size_t Remainder = NumBits % 64;
  if (Remainder != 0) {
    Bits.back() = (uint64_t{1} << Remainder) - 1;
  }
}

static void bitsetSet(std::vector<uint64_t> &Bits, size_t Index) {
  Bits[Index / 64] |= (uint64_t{1} << (Index % 64));
}

static bool bitsetTest(const std::vector<uint64_t> &Bits, size_t Index) {
  return (Bits[Index / 64] & (uint64_t{1} << (Index % 64))) != 0;
}

static bool bitsetEqual(const std::vector<uint64_t> &A,
                        const std::vector<uint64_t> &B) {
  return A == B;
}

static bool bitsetIsSubset(const std::vector<uint64_t> &Small,
                           const std::vector<uint64_t> &Large) {
  for (size_t I = 0; I < Small.size(); ++I) {
    if ((Small[I] & ~Large[I]) != 0) {
      return false;
    }
  }
  return true;
}

static bool bitsetIntersects(const std::vector<uint64_t> &A,
                             const std::vector<uint64_t> &B) {
  for (size_t I = 0; I < A.size(); ++I) {
    if ((A[I] & B[I]) != 0) {
      return true;
    }
  }
  return false;
}

static size_t bitsetCount(const std::vector<uint64_t> &Bits) {
  size_t Count = 0;
  for (uint64_t Word : Bits) {
    Count += static_cast<size_t>(__builtin_popcountll(Word));
  }
  return Count;
}

static std::vector<uint8_t>
computeReachable(const std::vector<GasBlock> &Blocks, uint32_t EntryId) {
  const size_t NumBlocks = Blocks.size();
  std::vector<uint8_t> Reachable(NumBlocks, 0);
  if (NumBlocks == 0 || EntryId >= NumBlocks) {
    return Reachable;
  }

  std::vector<uint32_t> Stack;
  Stack.push_back(EntryId);
  Reachable[EntryId] = 1;
  while (!Stack.empty()) {
    const uint32_t Node = Stack.back();
    Stack.pop_back();
    for (uint32_t Succ : Blocks[Node].Succs) {
      if (Reachable[Succ] == 0) {
        Reachable[Succ] = 1;
        Stack.push_back(Succ);
      }
    }
  }
  return Reachable;
}

static std::vector<std::vector<uint64_t>>
computeDominators(const std::vector<GasBlock> &Blocks,
                  const std::vector<uint8_t> &Reachable) {
  const size_t NumBlocks = Blocks.size();
  const size_t Words = bitsetWordCount(NumBlocks);
  std::vector<std::vector<uint64_t>> Dom(NumBlocks,
                                         std::vector<uint64_t>(Words, 0));
  std::vector<uint64_t> All(Words, 0);
  if (NumBlocks > 0) {
    bitsetSetAll(All, NumBlocks);
  }

  for (size_t Node = 0; Node < NumBlocks; ++Node) {
    if (Reachable[Node] == 0 || Blocks[Node].Preds.empty()) {
      Dom[Node].assign(Words, 0);
      bitsetSet(Dom[Node], Node);
    } else {
      Dom[Node] = All;
    }
  }

  bool Changed = true;
  std::vector<uint64_t> NewDom(Words, 0);
  while (Changed) {
    Changed = false;
    for (size_t Node = 0; Node < NumBlocks; ++Node) {
      if (Reachable[Node] == 0 || Blocks[Node].Preds.empty()) {
        continue;
      }

      NewDom = All;
      bool HasPred = false;
      for (uint32_t Pred : Blocks[Node].Preds) {
        if (Reachable[Pred] == 0) {
          continue;
        }
        HasPred = true;
        for (size_t W = 0; W < Words; ++W) {
          NewDom[W] &= Dom[Pred][W];
        }
      }

      if (!HasPred) {
        std::fill(NewDom.begin(), NewDom.end(), 0);
      }

      bitsetSet(NewDom, Node);
      if (!bitsetEqual(NewDom, Dom[Node])) {
        Dom[Node] = NewDom;
        Changed = true;
      }
    }
  }

  return Dom;
}

static void
findBackEdgesUsingDominators(const std::vector<GasBlock> &Blocks,
                             const std::vector<std::vector<uint64_t>> &Dom,
                             std::vector<std::vector<uint32_t>> &BackEdges) {
  const size_t NumBlocks = Blocks.size();
  BackEdges.assign(NumBlocks, {});

  for (size_t From = 0; From < NumBlocks; ++From) {
    for (uint32_t To : Blocks[From].Succs) {
      if (bitsetTest(Dom[From], To)) {
        BackEdges[From].push_back(To);
      }
    }
  }
}

static bool isBackEdge(const std::vector<std::vector<uint32_t>> &BackEdges,
                       uint32_t From, uint32_t To) {
  const auto &Edges = BackEdges[From];
  return std::find(Edges.begin(), Edges.end(), To) != Edges.end();
}

static std::vector<uint32_t>
computeReverseTopo(const std::vector<GasBlock> &Blocks,
                   const std::vector<std::vector<uint32_t>> &BackEdges) {
  const size_t NumBlocks = Blocks.size();
  std::vector<uint8_t> Visited(NumBlocks, 0);
  std::vector<uint32_t> Order;
  Order.reserve(NumBlocks);

  std::function<void(uint32_t)> Dfs = [&](uint32_t Node) {
    Visited[Node] = 1;
    for (uint32_t Succ : Blocks[Node].Succs) {
      if (isBackEdge(BackEdges, Node, Succ)) {
        continue;
      }
      if (Visited[Succ] == 0) {
        Dfs(Succ);
      }
    }
    Order.push_back(Node);
  };

  for (size_t Node = 0; Node < NumBlocks; ++Node) {
    if (Visited[Node] == 0) {
      Dfs(static_cast<uint32_t>(Node));
    }
  }

  return Order;
}

struct LoopInfo {
  uint32_t Header = 0;
  std::vector<uint32_t> Nodes;
  std::vector<uint32_t> Members;
  std::vector<uint32_t> Exits;
  std::vector<uint64_t> NodeMask;
  uint32_t Parent = UINT32_MAX;
};

static std::vector<uint64_t>
collectNaturalLoop(uint32_t From, uint32_t Header,
                   const std::vector<GasBlock> &Blocks, size_t NumBlocks,
                   const std::vector<uint8_t> &Reachable) {
  std::vector<uint64_t> LoopBits(bitsetWordCount(NumBlocks), 0);
  bitsetSet(LoopBits, Header);
  bitsetSet(LoopBits, From);
  std::vector<uint32_t> Stack;
  Stack.push_back(From);
  while (!Stack.empty()) {
    const uint32_t Node = Stack.back();
    Stack.pop_back();
    for (uint32_t Pred : Blocks[Node].Preds) {
      if (Reachable[Pred] == 0) {
        continue;
      }
      if (!bitsetTest(LoopBits, Pred)) {
        bitsetSet(LoopBits, Pred);
        Stack.push_back(Pred);
      }
    }
  }
  return LoopBits;
}

static bool buildLoopsUsingDominance(
    const std::vector<GasBlock> &Blocks,
    const std::vector<std::vector<uint64_t>> &Dom,
    const std::vector<uint8_t> &Reachable, std::vector<LoopInfo> &Loops,
    std::vector<int32_t> &LoopOf, std::vector<std::vector<uint32_t>> &ExitLoops,
    std::vector<std::vector<uint8_t>> &ExitFlags) {
  const size_t NumBlocks = Blocks.size();
  const size_t Words = bitsetWordCount(NumBlocks);

  struct LoopBuild {
    uint32_t Header = 0;
    std::vector<uint64_t> Bits;
  };
  std::vector<LoopBuild> LoopBuilds;
  std::unordered_map<uint32_t, size_t> HeaderIndex;

  for (size_t From = 0; From < NumBlocks; ++From) {
    if (Reachable[From] == 0) {
      continue;
    }
    for (uint32_t To : Blocks[From].Succs) {
      if (!bitsetTest(Dom[From], To)) {
        continue;
      }
      auto It = HeaderIndex.find(To);
      if (It == HeaderIndex.end()) {
        LoopBuilds.push_back({To, std::vector<uint64_t>(Words, 0)});
        It = HeaderIndex.emplace(To, LoopBuilds.size() - 1).first;
      }

      std::vector<uint64_t> LoopBits = collectNaturalLoop(
          static_cast<uint32_t>(From), To, Blocks, NumBlocks, Reachable);
      auto &TargetBits = LoopBuilds[It->second].Bits;
      for (size_t W = 0; W < Words; ++W) {
        TargetBits[W] |= LoopBits[W];
      }
    }
  }

  Loops.clear();
  Loops.reserve(LoopBuilds.size());
  for (const auto &Entry : LoopBuilds) {
    std::vector<uint64_t> Bits = Entry.Bits;
    for (size_t Node = 0; Node < NumBlocks; ++Node) {
      if (Reachable[Node] == 0 && bitsetTest(Bits, Node)) {
        Bits[Node / 64] &= ~(uint64_t{1} << (Node % 64));
      }
    }

    if (bitsetCount(Bits) == 0) {
      continue;
    }

    LoopInfo Loop;
    Loop.Header = Entry.Header;
    Loop.NodeMask = Bits;
    for (size_t Node = 0; Node < NumBlocks; ++Node) {
      if (bitsetTest(Bits, Node)) {
        Loop.Nodes.push_back(static_cast<uint32_t>(Node));
      }
    }
    Loops.push_back(std::move(Loop));
  }

  for (const auto &Loop : Loops) {
    for (uint32_t Node : Loop.Nodes) {
      if (!bitsetTest(Dom[Node], Loop.Header)) {
        return false;
      }
    }
  }

  for (size_t I = 0; I < Loops.size(); ++I) {
    for (size_t J = I + 1; J < Loops.size(); ++J) {
      const auto &A = Loops[I].NodeMask;
      const auto &B = Loops[J].NodeMask;
      if (!bitsetIntersects(A, B)) {
        continue;
      }
      const bool AInB = bitsetIsSubset(A, B);
      const bool BInA = bitsetIsSubset(B, A);
      if (!AInB && !BInA) {
        return false;
      }
    }
  }

  std::vector<size_t> LoopOrder(Loops.size(), 0);
  for (size_t I = 0; I < Loops.size(); ++I) {
    LoopOrder[I] = I;
  }
  std::sort(LoopOrder.begin(), LoopOrder.end(), [&](size_t A, size_t B) {
    return Loops[A].Nodes.size() < Loops[B].Nodes.size();
  });

  for (size_t I = 0; I < Loops.size(); ++I) {
    const auto &LoopBits = Loops[I].NodeMask;
    size_t BestParent = SIZE_MAX;
    for (size_t J = 0; J < Loops.size(); ++J) {
      if (I == J) {
        continue;
      }
      if (Loops[J].Nodes.size() <= Loops[I].Nodes.size()) {
        continue;
      }
      if (!bitsetIsSubset(LoopBits, Loops[J].NodeMask)) {
        continue;
      }
      if (BestParent == SIZE_MAX ||
          Loops[J].Nodes.size() < Loops[BestParent].Nodes.size()) {
        BestParent = J;
      }
    }
    if (BestParent != SIZE_MAX) {
      Loops[I].Parent = static_cast<uint32_t>(BestParent);
    }
  }

  LoopOf.assign(NumBlocks, -1);
  for (size_t OrderIndex = 0; OrderIndex < LoopOrder.size(); ++OrderIndex) {
    const size_t LoopId = LoopOrder[OrderIndex];
    for (uint32_t Node : Loops[LoopId].Nodes) {
      if (LoopOf[Node] == -1) {
        LoopOf[Node] = static_cast<int32_t>(LoopId);
      }
    }
  }

  for (size_t Node = 0; Node < NumBlocks; ++Node) {
    const int32_t LoopId = LoopOf[Node];
    if (LoopId >= 0) {
      Loops[LoopId].Members.push_back(static_cast<uint32_t>(Node));
    }
  }

  ExitLoops.assign(NumBlocks, {});
  ExitFlags.assign(Loops.size(), std::vector<uint8_t>(NumBlocks, 0));
  for (size_t LoopId = 0; LoopId < Loops.size(); ++LoopId) {
    auto &Loop = Loops[LoopId];
    for (uint32_t Node : Loop.Nodes) {
      bool IsExit = false;
      for (uint32_t Succ : Blocks[Node].Succs) {
        if (!bitsetTest(Loop.NodeMask, Succ)) {
          IsExit = true;
          break;
        }
      }
      if (IsExit) {
        Loop.Exits.push_back(Node);
        ExitLoops[Node].push_back(static_cast<uint32_t>(LoopId));
        ExitFlags[LoopId][Node] = 1;
      }
    }
  }

  return true;
}

// Lemma 6.14 Update: move minimum successor cost to current node
static bool lemma614Update(uint32_t NodeId, const std::vector<GasBlock> &Blocks,
                           const std::vector<std::vector<uint32_t>> *BackEdges,
                           const std::vector<uint64_t> *AllowedMask,
                           std::vector<uint64_t> &Metering) {
  const auto &Node = Blocks[NodeId];

  uint64_t MinSucc = UINT64_MAX;
  for (uint32_t Succ : Node.Succs) {
    if (BackEdges && isBackEdge(*BackEdges, NodeId, Succ)) {
      continue;
    }
    if (AllowedMask && !bitsetTest(*AllowedMask, Succ)) {
      continue;
    }
    MinSucc = std::min(MinSucc, Metering[Succ]);
  }

  if (MinSucc == 0 || MinSucc == UINT64_MAX) {
    return false;
  }

  Metering[NodeId] += MinSucc;
  for (uint32_t Succ : Node.Succs) {
    if (BackEdges && isBackEdge(*BackEdges, NodeId, Succ)) {
      continue;
    }
    if (AllowedMask && !bitsetTest(*AllowedMask, Succ)) {
      continue;
    }
    Metering[Succ] -= MinSucc;
  }

  return true;
}

static bool buildGasChunksSPP(const zen::common::Byte *Code, size_t CodeSize,
                              const evmc_instruction_metrics *MetricsTable,
                              const std::vector<uint8_t> &JumpDestMap,
                              const std::vector<intx::uint256> &PushValueMap,
                              std::vector<uint32_t> &GasChunkEnd,
                              std::vector<uint64_t> &GasChunkCost) {
  std::vector<GasBlock> Blocks;
  std::vector<uint32_t> BlockAtPc;
  buildGasBlocks(Code, CodeSize, MetricsTable, Blocks, BlockAtPc);

  if (Blocks.empty()) {
    return true;
  }

  std::vector<uint32_t> JumpDestBlocks;
  if (!JumpDestMap.empty()) {
    std::vector<uint8_t> SeenBlocks(Blocks.size(), 0);
    for (size_t Pc = 0; Pc < CodeSize; ++Pc) {
      if (JumpDestMap[Pc] == 0) {
        continue;
      }
      const uint32_t BlockId = BlockAtPc[Pc];
      if (BlockId == UINT32_MAX || BlockId >= Blocks.size()) {
        continue;
      }
      if (SeenBlocks[BlockId] == 0) {
        SeenBlocks[BlockId] = 1;
        JumpDestBlocks.push_back(BlockId);
      }
    }
  }

  // Build CFG
  for (size_t BlockId = 0; BlockId < Blocks.size(); ++BlockId) {
    auto &Block = Blocks[BlockId];
    const bool IsBarrier = isGasChunkTerminator(Block.LastOpcode);
    const bool IsCondJump = isConditionalJumpOpcode(Block.LastOpcode);

    // Add fallthrough edge (if not a barrier, or if conditional jump)
    if ((!IsBarrier || IsCondJump) && Block.End < CodeSize) {
      const uint32_t SuccId = BlockAtPc[Block.End];
      if (SuccId != UINT32_MAX) {
        addEdge(Blocks, static_cast<uint32_t>(BlockId), SuccId);
      }
    }

    // Add jump edge (if static jump)
    if (isJumpOpcode(Block.LastOpcode)) {
      uint32_t DestPc = 0;
      if (resolveConstantJumpTarget(JumpDestMap, PushValueMap, CodeSize, Block,
                                    DestPc)) {
        const uint32_t SuccId = BlockAtPc[DestPc];
        if (SuccId != UINT32_MAX) {
          addEdge(Blocks, static_cast<uint32_t>(BlockId), SuccId);
        }
      } else {
        // Dynamic jump: over-approx to all jump destinations.
        for (uint32_t SuccId : JumpDestBlocks) {
          addEdge(Blocks, static_cast<uint32_t>(BlockId), SuccId);
        }
      }
    }
  }

  // Split critical edges (required for safe SPP optimization)
  splitCriticalEdges(Blocks, CodeSize);

  const std::vector<uint8_t> Reachable = computeReachable(Blocks, 0);
  const std::vector<std::vector<uint64_t>> Dom =
      computeDominators(Blocks, Reachable);

  // Find back edges and compute reverse topological order
  std::vector<std::vector<uint32_t>> BackEdges;
  findBackEdgesUsingDominators(Blocks, Dom, BackEdges);
  const std::vector<uint32_t> RevTopo = computeReverseTopo(Blocks, BackEdges);
  std::vector<size_t> RevTopoIndex(Blocks.size(), 0);
  for (size_t Index = 0; Index < RevTopo.size(); ++Index) {
    RevTopoIndex[RevTopo[Index]] = Index;
  }

  std::vector<LoopInfo> Loops;
  std::vector<int32_t> LoopOf;
  std::vector<std::vector<uint32_t>> ExitLoops;
  std::vector<std::vector<uint8_t>> ExitFlags;
  bool UseLinearSPP = buildLoopsUsingDominance(Blocks, Dom, Reachable, Loops,
                                               LoopOf, ExitLoops, ExitFlags);

  // Initialize m = c (metering function = cost function)
  std::vector<uint64_t> Metering(Blocks.size(), 0);
  for (size_t Id = 0; Id < Blocks.size(); ++Id) {
    Metering[Id] = Blocks[Id].Cost;
  }

  if (!UseLinearSPP) {
    for (uint32_t NodeId : RevTopo) {
      lemma614Update(NodeId, Blocks, &BackEdges, nullptr, Metering);
    }
  } else {
    std::vector<std::vector<uint32_t>> Recorded(Loops.size());
    std::vector<size_t> RecordedCount(Loops.size(), 0);
    std::vector<size_t> ExitSeenCount(Loops.size(), 0);
    std::vector<uint8_t> LoopProcessed(Loops.size(), 0);

    for (size_t LoopId = 0; LoopId < Loops.size(); ++LoopId) {
      Recorded[LoopId].reserve(Loops[LoopId].Members.size());
    }

    auto maybeFastForward = [&](uint32_t LoopId) {
      if (LoopId >= Loops.size() || LoopProcessed[LoopId] != 0) {
        return;
      }
      if (RecordedCount[LoopId] != Loops[LoopId].Members.size()) {
        return;
      }
      if (ExitSeenCount[LoopId] != Loops[LoopId].Exits.size()) {
        return;
      }

      // Fast-forward the loop in reverse topo order within the loop.
      auto &Order = Recorded[LoopId];
      std::sort(Order.begin(), Order.end(), [&](uint32_t A, uint32_t B) {
        return RevTopoIndex[A] < RevTopoIndex[B];
      });
      for (uint32_t NodeId : Order) {
        lemma614Update(NodeId, Blocks, nullptr, &Loops[LoopId].NodeMask,
                       Metering);
      }
      LoopProcessed[LoopId] = 1;
    };

    for (uint32_t NodeId : RevTopo) {
      const int32_t LoopId = (NodeId < LoopOf.size()) ? LoopOf[NodeId] : -1;
      if (LoopId < 0) {
        lemma614Update(NodeId, Blocks, &BackEdges, nullptr, Metering);
      } else {
        Recorded[LoopId].push_back(NodeId);
        ++RecordedCount[LoopId];
      }

      for (uint32_t ExitLoopId : ExitLoops[NodeId]) {
        if (ExitFlags[ExitLoopId][NodeId] == 1) {
          ExitFlags[ExitLoopId][NodeId] = 2;
          ++ExitSeenCount[ExitLoopId];
        }
      }

      if (LoopId >= 0) {
        maybeFastForward(static_cast<uint32_t>(LoopId));
      }
      for (uint32_t ExitLoopId : ExitLoops[NodeId]) {
        maybeFastForward(ExitLoopId);
      }
    }
  }

  // Write results to output arrays
  for (size_t Id = 0; Id < Blocks.size(); ++Id) {
    GasChunkEnd[Blocks[Id].Start] = Blocks[Id].End;
    GasChunkCost[Blocks[Id].Start] = Metering[Id];
  }

  return true;
}

} // namespace

void buildBytecodeCache(EVMBytecodeCache &Cache, const common::Byte *Code,
                        size_t CodeSize) {
  Cache.JumpDestMap.assign(CodeSize, 0);
  Cache.PushValueMap.resize(CodeSize);
  Cache.GasChunkEnd.assign(CodeSize, 0);
  Cache.GasChunkCost.assign(CodeSize, 0);

  buildJumpDestMapAndPushCache(Code, CodeSize, Cache.JumpDestMap,
                               Cache.PushValueMap);
  static const auto *MetricsTable =
      evmc_get_instruction_metrics_table(DEFAULT_REVISION);

  buildGasChunksSPP(Code, CodeSize, MetricsTable, Cache.JumpDestMap,
                    Cache.PushValueMap, Cache.GasChunkEnd, Cache.GasChunkCost);
}

} // namespace zen::evm
