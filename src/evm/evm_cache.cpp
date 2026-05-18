// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "evm/evm_cache.h"

#include "evm/evm.h"
#include "evm/evm_cache_for_testing.h"
#include "evmc/instructions.h"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <unordered_map>
#include <utility>

// Optional per-phase wall-clock instrumentation for the SPP cache build
// pipeline. Enabled by `-DZEN_EVM_CACHE_PROFILE=ON` at configure time. OFF
// (default) macro-elides all chrono calls so release builds carry zero
// runtime overhead. Emits one stderr CSV row per timed phase:
//   `EVM_CACHE_PROFILE,<phase>,<microseconds>`
#ifdef ZEN_EVM_CACHE_PROFILE
#include <chrono>
#include <cstdio>
#define EVM_PROFILE_BEGIN(name)                                                \
  const auto _evm_profile_##name##_t0 = std::chrono::steady_clock::now()
#define EVM_PROFILE_END(name)                                                  \
  do {                                                                         \
    const auto _us =                                                           \
        std::chrono::duration_cast<std::chrono::microseconds>(                 \
            std::chrono::steady_clock::now() - _evm_profile_##name##_t0)       \
            .count();                                                          \
    std::fprintf(stderr, "EVM_CACHE_PROFILE,%s,%ld\n", #name, (long)_us);      \
  } while (0)
#else
#define EVM_PROFILE_BEGIN(name) ((void)0)
#define EVM_PROFILE_END(name) ((void)0)
#endif

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
  case evmc_opcode::OP_SSTORE:
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

static bool isControlFlowTerminator(uint8_t OpcodeU8) {
  switch (static_cast<evmc_opcode>(OpcodeU8)) {
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

static bool isGasSensitiveTerminator(uint8_t OpcodeU8) {
  switch (static_cast<evmc_opcode>(OpcodeU8)) {
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

// GasBlock holds the per-block scalar metadata read by every downstream
// pass. Compacted to 32 bytes by (a) keeping Succs/Preds in a parallel
// EdgeTables structure and (b) ordering fields so the lone uint64 Cost
// sits at the natural 8-byte boundary with no trailing padding. Halves
// the per-block stride versus the original 80-byte layout and lets two
// blocks share a single 64-byte cache line in the dominator / loop /
// writeback scans.
//
// Layout (offsets shown):
//   0  Start                       uint32
//   4  End                         uint32
//   8  LastPc                      uint32
//   12 PrevPc                      uint32
//   16 ImplicitDynamicPredCount    uint32
//   20 LastOpcode                  uint8
//   21 PrevOpcode                  uint8
//   22 pad[2]                      (2 alignment bytes before Cost)
//   24 Cost                        uint64
//   32 sizeof
struct GasBlock {
  uint32_t Start = 0;
  uint32_t End = 0;
  uint32_t LastPc = 0;
  uint32_t PrevPc = UINT32_MAX;
  // Count of dynamic-jump blocks in this contract that could land here at
  // runtime. Only nonzero for JUMPDEST blocks when the contract has at
  // least one unresolved dynamic jump. Carried separately so we avoid
  // materialising D*J explicit over-approximation edges (see buildCFGEdges).
  uint32_t ImplicitDynamicPredCount = 0;
  uint8_t LastOpcode = 0;
  uint8_t PrevOpcode = 0;
  uint64_t Cost = 0;
};
static_assert(sizeof(GasBlock) == 32,
              "GasBlock layout drifted -- cache-density wins depend on the "
              "32-byte stride; re-tune profile measurements if intentional.");

// Mutable adjacency used during CFG build (buildCFGEdges) and edge split
// (splitCriticalEdges). After freezing, downstream passes read from the
// CSR-flattened SuccsCSR / PredsCSR (built by buildAdjacencyCSR below)
// instead, so these per-block vectors are write-once during this phase.
struct EdgeTables {
  std::vector<std::vector<uint32_t>> Succs;
  std::vector<std::vector<uint32_t>> Preds;

  void resize(size_t N) {
    Succs.resize(N);
    Preds.resize(N);
  }

  size_t size() const { return Succs.size(); }
};

// Compressed-sparse-row adjacency: one big contiguous edge-data array shared
// across all nodes plus an offset table indexed by node id. Built once after
// CFG mutation finishes (post-splitCriticalEdges); read by every downstream
// pass (reachability, dominator, back-edge, loop, SCC, lemma614, writeback).
// Compared to vector<vector<uint32_t>> this removes N small heap allocations
// (one per non-empty Preds/Succs) and lays out neighbour lists sequentially
// for prefetchers.
struct CSRGraph {
  std::vector<uint32_t> Off;  // size = NumNodes + 1
  std::vector<uint32_t> Data; // size = total edges

  struct Range {
    const uint32_t *B;
    const uint32_t *E;
    const uint32_t *begin() const { return B; }
    const uint32_t *end() const { return E; }
    size_t size() const { return static_cast<size_t>(E - B); }
    bool empty() const { return B == E; }
    uint32_t operator[](size_t I) const { return B[I]; }
  };

  Range operator[](uint32_t Node) const {
    // Guard against `Data.data()` being null (empty CSR, e.g. a single-block
    // contract with no edges): `nullptr + 0` is undefined pointer arithmetic
    // per [expr.add]/4 even when the offset is zero, which UBSan flags.
    if (Data.empty()) {
      return {nullptr, nullptr};
    }
    const uint32_t *Base = Data.data();
    return {Base + Off[Node], Base + Off[Node + 1]};
  }

  uint32_t degree(uint32_t Node) const { return Off[Node + 1] - Off[Node]; }
};

// Project EdgeTables.Succs (or .Preds) into CSR form by copying. We leave
// the per-block vectors intact rather than swap()ing them out: N
// back-to-back std::vector dealloc()s cost more than the readers reclaim
// downstream. Memory peaks ~50% higher during the lifetime of
// buildGasChunksSPP but the per-call cache build is short-lived.
template <bool SelectSuccs>
static CSRGraph buildAdjacencyCSR(const EdgeTables &Edges) {
  CSRGraph G;
  const auto &Tables = SelectSuccs ? Edges.Succs : Edges.Preds;
  const size_t N = Tables.size();
  G.Off.resize(N + 1);
  G.Off[0] = 0;
  for (size_t I = 0; I < N; ++I) {
    G.Off[I + 1] = G.Off[I] + static_cast<uint32_t>(Tables[I].size());
  }
  G.Data.resize(G.Off[N]);
  for (size_t I = 0; I < N; ++I) {
    std::copy(Tables[I].begin(), Tables[I].end(), G.Data.begin() + G.Off[I]);
  }
  return G;
}

static void addEdge(EdgeTables &Edges, uint32_t From, uint32_t To) {
  auto &FromSuccs = Edges.Succs[From];
  if (std::find(FromSuccs.begin(), FromSuccs.end(), To) == FromSuccs.end()) {
    FromSuccs.push_back(To);
  }
  auto &ToPreds = Edges.Preds[To];
  if (std::find(ToPreds.begin(), ToPreds.end(), From) == ToPreds.end()) {
    ToPreds.push_back(From);
  }
}

// Split critical edges: insert empty blocks on edges from nodes with
// multiple successors to nodes with multiple predecessors.
// Returns true if any edges were split.
static bool splitCriticalEdges(std::vector<GasBlock> &Blocks, EdgeTables &Edges,
                               size_t CodeSize) {
  bool Changed = false;
  std::vector<std::pair<uint32_t, uint32_t>> EdgesToSplit;

  // Find critical edges
  for (size_t FromId = 0; FromId < Blocks.size(); ++FromId) {
    if (Edges.Succs[FromId].size() <= 1) {
      continue; // Not a critical edge source
    }
    for (uint32_t ToId : Edges.Succs[FromId]) {
      if (Edges.Preds[ToId].size() > 1) {
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
    auto &FromSuccs = Edges.Succs[FromId];
    FromSuccs.erase(std::remove(FromSuccs.begin(), FromSuccs.end(), ToId),
                    FromSuccs.end());
    auto &ToPreds = Edges.Preds[ToId];
    ToPreds.erase(std::remove(ToPreds.begin(), ToPreds.end(), FromId),
                  ToPreds.end());

    // Add the new block and grow the parallel edge tables to match.
    Blocks.push_back(NewBlock);
    Edges.Succs.emplace_back();
    Edges.Preds.emplace_back();
    addEdge(Edges, FromId, NewId);
    addEdge(Edges, NewId, ToId);

    Changed = true;
  }

  return Changed;
}

// Single-pass block partitioning: walk bytecode once, closing the current
// block when we hit a mid-block JUMPDEST (starts a new block) or a gas-chunk
// terminator (ends current, next byte starts next). Replaces the previous
// 2-pass (mark IsBlockStart[CodeSize], then walk it) which materialised a
// CodeSize-sized auxiliary array. Also emits JumpDestBlocks in block-id
// order whenever a new block opens with OP_JUMPDEST -- every JUMPDEST byte
// in valid code is a block start, so this list is exactly the set the
// previous standalone collectJumpDests pass produced.
static void buildGasBlocks(const zen::common::Byte *Code, size_t CodeSize,
                           const evmc_instruction_metrics *MetricsTable,
                           std::vector<GasBlock> &Blocks,
                           std::vector<uint32_t> &BlockAtPc,
                           std::vector<uint32_t> &JumpDestBlocks) {
  if (CodeSize == 0) {
    return;
  }

  BlockAtPc.assign(CodeSize, UINT32_MAX);
  // Reserve to the maximum possible block count (1 byte = 1 block worst
  // case, since opcodeLen >= 1) so emplace_back never reallocates and the
  // Blocks.back() reference taken below stays valid through the inner loop.
  // Real EVM code averages 3-10 bytes per block, so this over-reserves by
  // ~3-10x. The saved geometric growth (log2(N) reallocs each moving
  // ~80 bytes/block = ~MB of copy work at N=100k) is worth the transient
  // extra capacity.
  Blocks.reserve(CodeSize);

  size_t Pc = 0;
  while (Pc < CodeSize) {
    const uint8_t StartOpcode = static_cast<uint8_t>(Code[Pc]);
    if (StartOpcode == static_cast<uint8_t>(evmc_opcode::OP_JUMPDEST)) {
      JumpDestBlocks.push_back(static_cast<uint32_t>(Blocks.size()));
    }

    GasBlock &Block = Blocks.emplace_back();
    Block.Start = static_cast<uint32_t>(Pc);

    size_t CurPc = Pc;
    while (CurPc < CodeSize) {
      const uint8_t CurOpcodeU8 = static_cast<uint8_t>(Code[CurPc]);
      if (CurPc != Block.Start &&
          CurOpcodeU8 == static_cast<uint8_t>(evmc_opcode::OP_JUMPDEST)) {
        break;
      }

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
    BlockAtPc[Pc] = static_cast<uint32_t>(Blocks.size() - 1);
    Pc = CurPc;
  }
}

// Decode a PUSH immediate at PushPc and validate it as a JUMPDEST address.
// Returns true and sets DestPc on success.
static bool decodePushAsJumpDest(const std::vector<intx::uint256> &PushValueMap,
                                 const std::vector<uint8_t> &JumpDestMap,
                                 size_t CodeSize, uint32_t PushPc,
                                 uint32_t &DestPc) {
  const intx::uint256 Value = PushValueMap[PushPc];
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

  return decodePushAsJumpDest(PushMap, JumpDestMap, CodeSize, Block.PrevPc,
                              DestPc);
}

// Build CFG edges for all blocks. Static jumps (PUSH → JUMP) get precise
// single-target edges. For each unresolved dynamic jump we DO NOT add the
// D*|JUMPDEST| explicit over-approximation edges (which previously made the
// pass quadratic-to-cubic in pathological contracts). Instead we record on
// every JUMPDEST how many dynamic-jump blocks could land there at runtime
// via `ImplicitDynamicPredCount`, and `effectivePredCount` folds that count
// into its multi-predecessor check. SPP decisions are identical: a JUMPDEST
// that is a potential dynamic-jump target sees `effectivePredCount > 1` and
// `lemma614Update` refuses to shift gas across that edge, exactly as it
// would have done against an explicit over-approximated `Preds` set.
static void buildCFGEdges(std::vector<GasBlock> &Blocks, EdgeTables &Edges,
                          const std::vector<uint32_t> &BlockAtPc,
                          const std::vector<uint8_t> &JumpDestMap,
                          const std::vector<intx::uint256> &PushValueMap,
                          const std::vector<uint32_t> &JumpDestBlocks,
                          size_t CodeSize) {
  // Single pass: add fallthrough + static-jump edges, count unresolved
  // dynamic jumps inline so we can stamp every JUMPDEST with the right
  // implicit-predecessor count once at the end (in O(N) instead of O(D*J)).
  // The previous two-loop structure called resolveConstantJumpTarget twice
  // per JUMP block (once to count, once to decide the edge); fusing them
  // halves the call count and the bytecode rescan it performs.
  uint32_t DynamicJumpCount = 0;
  for (size_t BlockId = 0; BlockId < Blocks.size(); ++BlockId) {
    const auto &Block = Blocks[BlockId];
    const bool IsTerminator = isControlFlowTerminator(Block.LastOpcode);

    // Add fallthrough edge for non-terminating opcodes (CALL/CREATE/GAS,
    // JUMPI included via the generic !IsTerminator path).
    if (!IsTerminator && Block.End < CodeSize) {
      const uint32_t SuccId = BlockAtPc[Block.End];
      if (SuccId != UINT32_MAX) {
        addEdge(Edges, static_cast<uint32_t>(BlockId), SuccId);
      }
    }

    // Add jump target edge(s).
    if (isJumpOpcode(Block.LastOpcode)) {
      uint32_t DestPc = 0;
      if (resolveConstantJumpTarget(JumpDestMap, PushValueMap, CodeSize, Block,
                                    DestPc)) {
        // Static (constant) jump: single known target.
        const uint32_t SuccId = BlockAtPc[DestPc];
        if (SuccId != UINT32_MAX) {
          addEdge(Edges, static_cast<uint32_t>(BlockId), SuccId);
        }
      } else {
        ++DynamicJumpCount;
      }
      // Dynamic jump: handled by the implicit-predecessor count stamped onto
      // every JUMPDEST below. No explicit Succs/Preds edges added.
    }
  }

  if (DynamicJumpCount > 0) {
    for (uint32_t JdId : JumpDestBlocks) {
      Blocks[JdId].ImplicitDynamicPredCount = DynamicJumpCount;
    }
  }
}

static size_t bitsetWordCount(size_t NumBits) { return (NumBits + 63) / 64; }

static void bitsetSet(std::vector<uint64_t> &Bits, size_t Index) {
  Bits[Index / 64] |= (uint64_t{1} << (Index % 64));
}

static bool bitsetTest(const std::vector<uint64_t> &Bits, size_t Index) {
  return (Bits[Index / 64] & (uint64_t{1} << (Index % 64))) != 0;
}

static std::vector<uint8_t> computeInCycle(const CSRGraph &SuccsCSR,
                                           const CSRGraph &PredsCSR) {
  const size_t NumBlocks = SuccsCSR.Off.empty() ? 0 : SuccsCSR.Off.size() - 1;
  std::vector<uint8_t> Visited(NumBlocks, 0);
  std::vector<uint32_t> Order;
  Order.reserve(NumBlocks);

  struct DfsFrame {
    uint32_t Node = 0;
    size_t SuccIndex = 0;
  };

  std::vector<DfsFrame> DfsStack;
  for (uint32_t Start = 0; Start < NumBlocks; ++Start) {
    if (Visited[Start] != 0) {
      continue;
    }
    DfsStack.push_back({Start, 0});
    Visited[Start] = 1;
    while (!DfsStack.empty()) {
      DfsFrame &Frame = DfsStack.back();
      const uint32_t Node = Frame.Node;
      const auto Succs = SuccsCSR[Node];
      bool Descended = false;
      while (Frame.SuccIndex < Succs.size()) {
        const uint32_t Succ = Succs[Frame.SuccIndex++];
        if (Succ >= NumBlocks) {
          continue;
        }
        if (Visited[Succ] == 0) {
          Visited[Succ] = 1;
          DfsStack.push_back({Succ, 0});
          Descended = true;
          break;
        }
      }
      if (Descended) {
        continue;
      }
      Order.push_back(Node);
      DfsStack.pop_back();
    }
  }

  std::vector<uint8_t> InCycle(NumBlocks, 0);
  std::vector<uint8_t> Assigned(NumBlocks, 0);
  std::vector<uint32_t> Stack;
  Stack.reserve(NumBlocks);

  for (auto It = Order.rbegin(); It != Order.rend(); ++It) {
    const uint32_t Start = *It;
    if (Assigned[Start] != 0) {
      continue;
    }
    std::vector<uint32_t> Component;
    Stack.push_back(Start);
    Assigned[Start] = 1;
    while (!Stack.empty()) {
      const uint32_t Node = Stack.back();
      Stack.pop_back();
      Component.push_back(Node);
      for (uint32_t Pred : PredsCSR[Node]) {
        if (Pred >= NumBlocks) {
          continue;
        }
        if (Assigned[Pred] == 0) {
          Assigned[Pred] = 1;
          Stack.push_back(Pred);
        }
      }
    }

    if (Component.size() > 1) {
      for (uint32_t Id : Component) {
        InCycle[Id] = 1;
      }
      continue;
    }

    const uint32_t Only = Component.front();
    for (uint32_t Succ : SuccsCSR[Only]) {
      if (Succ == Only) {
        InCycle[Only] = 1;
        break;
      }
    }
  }

  return InCycle;
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

static std::vector<uint8_t> computeReachable(const CSRGraph &SuccsCSR,
                                             uint32_t EntryId) {
  const size_t NumBlocks = SuccsCSR.Off.empty() ? 0 : SuccsCSR.Off.size() - 1;
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
    for (uint32_t Succ : SuccsCSR[Node]) {
      if (Reachable[Succ] == 0) {
        Reachable[Succ] = 1;
        Stack.push_back(Succ);
      }
    }
  }
  return Reachable;
}

// Cooper-Harvey-Kennedy 2001 plus Tarjan DFS pre/post times for O(1)
// dominance queries. Root classes (seeded at init so descendants can
// intersect against a settled idom): (A) Reachable==0, (B) Preds.empty,
// (C) reachable but all preds unreachable. Multi-root divergence in the
// fixpoint collapses to self-root via the intersect UINT32_MAX sentinel.
struct DomInfo {
  std::vector<uint32_t> IDom;
  std::vector<uint32_t> Enter;
  std::vector<uint32_t> Exit;
  // Reverse post-order: forward DFS visit, postorder pushes, reversed.
  // Exposed so downstream passes that need a topo order over the
  // non-back-edge sub-DAG (e.g. computeReverseTopo, lemma614Schedule)
  // can reuse this traversal instead of running their own DFS.
  std::vector<uint32_t> RPO;

  bool dominates(uint32_t A, uint32_t B) const {
    if (A >= IDom.size() || B >= IDom.size()) {
      return false;
    }
    if (A == B) {
      return true;
    }
    return Enter[A] <= Enter[B] && Exit[B] <= Exit[A];
  }
};

static DomInfo computeDomInfo(const CSRGraph &SuccsCSR,
                              const CSRGraph &PredsCSR,
                              const std::vector<uint8_t> &Reachable) {
  const size_t N = SuccsCSR.Off.empty() ? 0 : SuccsCSR.Off.size() - 1;
  DomInfo Info;
  Info.IDom.assign(N, UINT32_MAX);
  Info.Enter.assign(N, 0);
  Info.Exit.assign(N, 0);
  if (N == 0) {
    return Info;
  }
  std::vector<uint32_t> &IDom = Info.IDom;

  // Class C (reachable but all preds unreachable) is seeded here, not
  // post-fixpoint, so its descendants can intersect against a settled
  // root in step 4 — matching the old bitset semantics that gave every
  // descendant M of class-C node N the property N ∈ Dom[M].
  for (size_t I = 0; I < N; ++I) {
    if (Reachable[I] == 0) {
      IDom[I] = static_cast<uint32_t>(I); // class A
      continue;
    }
    bool HasReachablePred = false;
    for (uint32_t Pred : PredsCSR[static_cast<uint32_t>(I)]) {
      if (Reachable[Pred] != 0) {
        HasReachablePred = true;
        break;
      }
    }
    if (!HasReachablePred) {
      IDom[I] = static_cast<uint32_t>(I); // class B (Preds.empty) or C
    }
  }

  // Iterative DFS for postorder. Reserve up front so back() refs are
  // not invalidated by push_back reallocations.
  std::vector<uint32_t> PostOrderId(N, UINT32_MAX);
  std::vector<uint32_t> &RPO = Info.RPO;
  RPO.reserve(N);
  std::vector<uint8_t> Visited(N, 0);
  struct DfsFrame {
    uint32_t Node;
    uint32_t SuccIdx;
  };
  std::vector<DfsFrame> Stack;
  Stack.reserve(N);
  uint32_t PoCounter = 0;

  auto runDfs = [&](uint32_t Start, bool RestrictReachable) {
    if (Visited[Start] != 0) {
      return;
    }
    Visited[Start] = 1;
    Stack.push_back({Start, 0});
    while (!Stack.empty()) {
      DfsFrame &Top = Stack.back();
      const auto Succs = SuccsCSR[Top.Node];
      if (Top.SuccIdx < Succs.size()) {
        const uint32_t Succ = Succs[Top.SuccIdx++];
        if (Succ < N && Visited[Succ] == 0 &&
            (!RestrictReachable || Reachable[Succ] != 0)) {
          Visited[Succ] = 1;
          Stack.push_back({Succ, 0});
        }
      } else {
        PostOrderId[Top.Node] = PoCounter++;
        RPO.push_back(Top.Node);
        Stack.pop_back();
      }
    }
  };

  for (size_t I = 0; I < N; ++I) {
    if (IDom[I] == I && Reachable[I] != 0) {
      runDfs(static_cast<uint32_t>(I), /*RestrictReachable=*/true);
    }
  }
  // Defensive: also visit any unreachable or orphan node so PostOrderId
  // is defined everywhere. Unreachable nodes already have IDom == self
  // from the init pass.
  for (size_t I = 0; I < N; ++I) {
    if (Visited[I] == 0) {
      runDfs(static_cast<uint32_t>(I), /*RestrictReachable=*/false);
    }
  }
  std::reverse(RPO.begin(), RPO.end());

  // Intersect walks the lower-postorder finger up the partially-built
  // IDom tree. Returns UINT32_MAX iff the chains diverge (one finger
  // reaches its own root before meeting the other).
  auto intersect = [&](uint32_t B1, uint32_t B2) -> uint32_t {
    while (B1 != B2) {
      while (PostOrderId[B1] < PostOrderId[B2]) {
        const uint32_t P = IDom[B1];
        if (P == B1 || P == UINT32_MAX) {
          return UINT32_MAX;
        }
        B1 = P;
      }
      while (PostOrderId[B2] < PostOrderId[B1]) {
        const uint32_t P = IDom[B2];
        if (P == B2 || P == UINT32_MAX) {
          return UINT32_MAX;
        }
        B2 = P;
      }
    }
    return B1;
  };

  bool Changed = true;
#ifdef ZEN_EVM_CACHE_PROFILE
  int FixpointRounds = 0;
#endif
  while (Changed) {
    Changed = false;
#ifdef ZEN_EVM_CACHE_PROFILE
    ++FixpointRounds;
#endif
    for (uint32_t Node : RPO) {
      if (IDom[Node] == Node) {
        continue; // root
      }
      uint32_t NewIDom = UINT32_MAX;
      bool Diverged = false;
      for (uint32_t Pred : PredsCSR[Node]) {
        if (Reachable[Pred] == 0) {
          continue;
        }
        if (IDom[Pred] == UINT32_MAX) {
          continue; // not yet processed in this round
        }
        if (NewIDom == UINT32_MAX) {
          NewIDom = Pred;
        } else {
          NewIDom = intersect(NewIDom, Pred);
          if (NewIDom == UINT32_MAX) {
            Diverged = true;
            break;
          }
        }
      }
      if (Diverged) {
        NewIDom = Node; // multi-root divergence: self-root fallback
      }
      if (NewIDom != UINT32_MAX && IDom[Node] != NewIDom) {
        IDom[Node] = NewIDom;
        Changed = true;
      }
    }
  }
#ifdef ZEN_EVM_CACHE_PROFILE
  std::fprintf(stderr, "EVM_CACHE_PROFILE,chkFixpointRounds,%d\n",
               FixpointRounds);
#endif

  // Defensive backstop: classes A/B/C are seeded at init above, so any
  // UINT32_MAX here is an orphan reachable component not reached by RPO
  // from any seeded root. Collapse to self per the bitset-pass fallback.
  for (size_t Node = 0; Node < N; ++Node) {
    if (IDom[Node] == UINT32_MAX) {
      IDom[Node] = static_cast<uint32_t>(Node);
    }
  }

  // Build the dom-tree children adjacency in CSR form (two flat vectors)
  // to avoid N small heap allocations for vector<vector<uint32_t>>.
  std::vector<uint32_t> ChildStart(N + 1, 0);
  for (uint32_t I = 0; I < N; ++I) {
    if (IDom[I] != I) {
      ++ChildStart[IDom[I] + 1];
    }
  }
  for (size_t I = 1; I <= N; ++I) {
    ChildStart[I] += ChildStart[I - 1];
  }
  std::vector<uint32_t> ChildIdx(ChildStart[N]);
  std::vector<uint32_t> CursorTmp = ChildStart;
  for (uint32_t I = 0; I < N; ++I) {
    if (IDom[I] != I) {
      ChildIdx[CursorTmp[IDom[I]]++] = I;
    }
  }

  // Tarjan DFS pre/post times over the dom tree give O(1) dominance
  // queries via interval containment. Each root contributes a disjoint
  // [Enter, Exit] interval on a single global timeline, so cross-root
  // pairs answer non-dominating by non-containment.
  struct EtFrame {
    uint32_t Node;
    uint32_t Cursor; // index into ChildIdx
  };
  std::vector<EtFrame> EtStack;
  EtStack.reserve(N);
  uint32_t Time = 0;
  for (uint32_t Root = 0; Root < N; ++Root) {
    if (IDom[Root] != Root) {
      continue;
    }
    Info.Enter[Root] = Time++;
    EtStack.push_back({Root, ChildStart[Root]});
    while (!EtStack.empty()) {
      EtFrame &Top = EtStack.back();
      const uint32_t End = ChildStart[Top.Node + 1];
      if (Top.Cursor < End) {
        const uint32_t C = ChildIdx[Top.Cursor++];
        Info.Enter[C] = Time++;
        EtStack.push_back({C, ChildStart[C]});
      } else {
        Info.Exit[Top.Node] = Time++;
        EtStack.pop_back();
      }
    }
  }

  return Info;
}

static void
findBackEdgesUsingDominators(const CSRGraph &SuccsCSR, const DomInfo &Dom,
                             std::vector<std::vector<uint32_t>> &BackEdges) {
  const size_t NumBlocks = SuccsCSR.Off.empty() ? 0 : SuccsCSR.Off.size() - 1;
  BackEdges.assign(NumBlocks, {});

  for (size_t From = 0; From < NumBlocks; ++From) {
    for (uint32_t To : SuccsCSR[static_cast<uint32_t>(From)]) {
      // Classic back-edge: target dominates source.
      if (Dom.dominates(To, static_cast<uint32_t>(From))) {
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

// Reverse-topo order for lemma614Schedule. This is the postorder of the
// forward DFS that visits every node once and never follows back-edges
// (back-edges always target an already-visited ancestor, so they are
// implicitly skipped by the visited check). computeDomInfo already runs
// exactly that DFS and stores reverse(postorder) in DomInfo::RPO, so we
// just return its reverse here instead of repeating the traversal.
static std::vector<uint32_t> computeReverseTopo(const DomInfo &Dom) {
  std::vector<uint32_t> Order;
  Order.reserve(Dom.RPO.size());
  for (auto It = Dom.RPO.rbegin(); It != Dom.RPO.rend(); ++It) {
    Order.push_back(*It);
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
collectNaturalLoop(uint32_t From, uint32_t Header, const CSRGraph &PredsCSR,
                   size_t NumBlocks, const std::vector<uint8_t> &Reachable) {
  std::vector<uint64_t> LoopBits(bitsetWordCount(NumBlocks), 0);
  bitsetSet(LoopBits, Header);
  bitsetSet(LoopBits, From);
  std::vector<uint32_t> Stack;
  Stack.push_back(From);
  while (!Stack.empty()) {
    const uint32_t Node = Stack.back();
    Stack.pop_back();
    for (uint32_t Pred : PredsCSR[Node]) {
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
    const CSRGraph &SuccsCSR, const CSRGraph &PredsCSR, const DomInfo &Dom,
    const std::vector<uint8_t> &Reachable, std::vector<LoopInfo> &Loops,
    std::vector<int32_t> &LoopOf, std::vector<std::vector<uint32_t>> &ExitLoops,
    std::vector<std::vector<uint8_t>> &ExitFlags) {
  const size_t NumBlocks = SuccsCSR.Off.empty() ? 0 : SuccsCSR.Off.size() - 1;
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
    for (uint32_t To : SuccsCSR[static_cast<uint32_t>(From)]) {
      // Header discovery: a back-edge From -> To exists iff To dominates From.
      if (!Dom.dominates(To, static_cast<uint32_t>(From))) {
        continue;
      }
      auto It = HeaderIndex.find(To);
      if (It == HeaderIndex.end()) {
        LoopBuilds.push_back({To, std::vector<uint64_t>(Words, 0)});
        It = HeaderIndex.emplace(To, LoopBuilds.size() - 1).first;
      }

      std::vector<uint64_t> LoopBits = collectNaturalLoop(
          static_cast<uint32_t>(From), To, PredsCSR, NumBlocks, Reachable);
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
      // Loop-body sanity: every node in the loop must be dominated by
      // the loop header.
      if (!Dom.dominates(Loop.Header, Node)) {
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
      for (uint32_t Succ : SuccsCSR[Node]) {
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

// Effective predecessor count: the entry block (Start == 0) is always reachable
// from the program start, adding an implicit path not represented in the CFG.
//
// Blocks with `ImplicitDynamicPredCount > 0` (every JUMPDEST in a contract
// that has at least one dynamic jump) carry the over-approximated dynamic
// predecessors as a count instead of explicit edges; folding them in here
// keeps `lemma614Update`'s "shift only into single-pred successors" check
// equivalent to the explicit over-approximation.
static size_t effectivePredCount(uint32_t NodeId,
                                 const std::vector<GasBlock> &Blocks,
                                 const CSRGraph &PredsCSR) {
  size_t Count = PredsCSR.degree(NodeId);
  if (Blocks[NodeId].Start == 0) {
    ++Count;
  }
  Count += Blocks[NodeId].ImplicitDynamicPredCount;
  return Count;
}

// Lemma 6.14 Update: move minimum successor cost to current node
static bool lemma614Update(uint32_t NodeId, const std::vector<GasBlock> &Blocks,
                           const CSRGraph &SuccsCSR, const CSRGraph &PredsCSR,
                           const std::vector<std::vector<uint32_t>> *BackEdges,
                           const std::vector<uint64_t> *AllowedMask,
                           std::vector<uint64_t> &Metering) {
  const auto &Node = Blocks[NodeId];
  if (isGasSensitiveTerminator(Node.LastOpcode)) {
    return false;
  }

  uint64_t MinSucc = UINT64_MAX;
  for (uint32_t Succ : SuccsCSR[NodeId]) {
    if (BackEdges && isBackEdge(*BackEdges, NodeId, Succ)) {
      continue;
    }
    if (AllowedMask && !bitsetTest(*AllowedMask, Succ)) {
      // Non-back-edge successor excluded from shifting — its path would
      // see the inflated parent cost without compensation.
      MinSucc = 0;
      continue;
    }
    if (effectivePredCount(Succ, Blocks, PredsCSR) != 1) {
      MinSucc = 0;
      continue;
    }
    if (isGasChunkTerminator(Blocks[Succ].LastOpcode)) {
      MinSucc = 0;
      continue;
    }
    MinSucc = std::min(MinSucc, Metering[Succ]);
  }

  if (MinSucc == 0 || MinSucc == UINT64_MAX) {
    return false;
  }

  Metering[NodeId] += MinSucc;
  for (uint32_t Succ : SuccsCSR[NodeId]) {
    if (BackEdges && isBackEdge(*BackEdges, NodeId, Succ)) {
      continue;
    }
    if (AllowedMask && !bitsetTest(*AllowedMask, Succ)) {
      continue;
    }
    if (effectivePredCount(Succ, Blocks, PredsCSR) != 1) {
      continue;
    }
    if (isGasChunkTerminator(Blocks[Succ].LastOpcode)) {
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
                              std::vector<uint64_t> &GasChunkCost,
                              std::vector<uint64_t> &GasChunkCostSPP,
                              bool EnableSPP) {
  std::vector<GasBlock> Blocks;
  std::vector<uint32_t> BlockAtPc;
  std::vector<uint32_t> JumpDestBlocks;
  EVM_PROFILE_BEGIN(buildGasBlocks);
  buildGasBlocks(Code, CodeSize, MetricsTable, Blocks, BlockAtPc,
                 JumpDestBlocks);
  EVM_PROFILE_END(buildGasBlocks);

  if (Blocks.empty()) {
    return true;
  }

  if (!EnableSPP) {
    // Interpreter-only fast path: emit unshifted per-block costs and skip
    // the expensive CFG / call-site / metering pipeline. The JIT consumer
    // path (which would read GasChunkCostSPP) is never wired up for this
    // module, so no SPP-shifted values are needed.
    for (const auto &Block : Blocks) {
      if (Block.Start < CodeSize) {
        GasChunkEnd[Block.Start] = Block.End;
        GasChunkCost[Block.Start] = Block.Cost;
      }
    }
    return true;
  }

  // Always build CFG — no early exit for dynamic jumps.
  // Unresolved jumps get over-approximated edges to all JUMPDESTs.

  // JumpDestBlocks is now produced inline by buildGasBlocks (one push per
  // block whose first opcode is OP_JUMPDEST), eliminating the prior bytecode
  // re-scan + SeenBlocks dedup. The two enumerations are equivalent because
  // every JUMPDEST byte under EVM semantics starts a new gas block.

  // Static jumps get precise single-target edges. For unresolved dynamic
  // jumps, the CFG over-approximation is encoded as
  // ImplicitDynamicPredCount on each JUMPDEST (folded into
  // effectivePredCount). Narrowing to partial call-site resolution would
  // under-approximate the CFG and let SPP shift gas along non-existent
  // edges, producing unsafe metering.
  EdgeTables Edges;
  Edges.resize(Blocks.size());

  EVM_PROFILE_BEGIN(buildCFGEdges);
  buildCFGEdges(Blocks, Edges, BlockAtPc, JumpDestMap, PushValueMap,
                JumpDestBlocks, CodeSize);
  EVM_PROFILE_END(buildCFGEdges);

  EVM_PROFILE_BEGIN(splitCriticalEdges);
  splitCriticalEdges(Blocks, Edges, CodeSize);
  EVM_PROFILE_END(splitCriticalEdges);

  // Freeze adjacency: collapse the per-block Succs/Preds vectors into CSR
  // (one heap alloc per direction) so downstream passes traverse neighbour
  // lists out of contiguous arrays instead of chasing N small heap chunks.
  // Invariant: Edges must stay in lockstep with Blocks. splitCriticalEdges
  // grows both in pairs; if a future change adds a Blocks.push_back that
  // forgets to grow Edges, downstream CSR indexing would silently use the
  // wrong node count. Assert here so the next reviewer sees the failure.
  assert(Edges.Succs.size() == Blocks.size() &&
         Edges.Preds.size() == Blocks.size() &&
         "EdgeTables size drifted from Blocks size");
  EVM_PROFILE_BEGIN(buildCSR);
  const CSRGraph SuccsCSR = buildAdjacencyCSR<true>(Edges);
  const CSRGraph PredsCSR = buildAdjacencyCSR<false>(Edges);
  EVM_PROFILE_END(buildCSR);

  EVM_PROFILE_BEGIN(computeReachable);
  std::vector<uint8_t> Reachable = computeReachable(SuccsCSR, 0);
  // Seed dyn-target JUMPDESTs as reachability roots so dom/loop analyses
  // include them and their static successors. Statically-dead JUMPDESTs
  // (no static pred, no dyn-jump in the contract) are intentionally left
  // unreachable.
  {
    std::vector<uint32_t> Stack;
    for (uint32_t JdId : JumpDestBlocks) {
      if (Blocks[JdId].ImplicitDynamicPredCount == 0) {
        continue;
      }
      if (Reachable[JdId] == 0) {
        Reachable[JdId] = 1;
        Stack.push_back(JdId);
      }
    }
    while (!Stack.empty()) {
      const uint32_t Node = Stack.back();
      Stack.pop_back();
      for (uint32_t Succ : SuccsCSR[Node]) {
        if (Reachable[Succ] == 0) {
          Reachable[Succ] = 1;
          Stack.push_back(Succ);
        }
      }
    }
  }
  EVM_PROFILE_END(computeReachable);

  EVM_PROFILE_BEGIN(computeDomInfo);
  const DomInfo Dom = computeDomInfo(SuccsCSR, PredsCSR, Reachable);
  EVM_PROFILE_END(computeDomInfo);

  EVM_PROFILE_BEGIN(findBackEdges);
  std::vector<std::vector<uint32_t>> BackEdges;
  findBackEdgesUsingDominators(SuccsCSR, Dom, BackEdges);
  EVM_PROFILE_END(findBackEdges);

  EVM_PROFILE_BEGIN(computeReverseTopo);
  const std::vector<uint32_t> RevTopo = computeReverseTopo(Dom);
  std::vector<size_t> RevTopoIndex(Blocks.size(), 0);
  for (size_t Index = 0; Index < RevTopo.size(); ++Index) {
    RevTopoIndex[RevTopo[Index]] = Index;
  }
  EVM_PROFILE_END(computeReverseTopo);

  EVM_PROFILE_BEGIN(buildLoopsUsingDominance);
  std::vector<LoopInfo> Loops;
  std::vector<int32_t> LoopOf;
  std::vector<std::vector<uint32_t>> ExitLoops;
  std::vector<std::vector<uint8_t>> ExitFlags;
  bool UseLinearSPP = buildLoopsUsingDominance(
      SuccsCSR, PredsCSR, Dom, Reachable, Loops, LoopOf, ExitLoops, ExitFlags);
  EVM_PROFILE_END(buildLoopsUsingDominance);

  // InCycle is a performance fast-path filter for lemma614Update, NOT the
  // soundness mechanism. On reducible CFGs (UseLinearSPP=true) the union of
  // natural-loop NodeMasks coincides with the in-cycle set Tarjan SCC would
  // produce, so we skip the standalone Tarjan pass. On irreducible CFGs
  // (UseLinearSPP=false) buildLoopsUsingDominance can miss multi-entry
  // cycles (e.g. an irreducible 2-entry cycle A<->B with no dominator-based
  // back-edge), so the Tarjan SCC backstop fills InCycle for those nodes.
  //
  // Soundness on irreducible CFGs ultimately rests on lemma614Update's
  // effectivePredCount(Succ) != 1 multi-pred guard at line 1224: every SCC
  // node has at least one in-cycle predecessor on top of any out-of-cycle
  // entry, so its effectivePredCount is >= 2 and the shift is refused even
  // when InCycle is empty. See docs/modules/evm/cache-build.md §Invariants
  // -- do NOT remove the multi-pred guard on the assumption that InCycle
  // covers it.
  EVM_PROFILE_BEGIN(computeInCycle);
  std::vector<uint8_t> InCycle;
  if (UseLinearSPP) {
    const size_t Words = bitsetWordCount(Blocks.size());
    std::vector<uint64_t> CycleBits(Words, 0);
    for (const auto &Loop : Loops) {
      for (size_t W = 0; W < Words; ++W) {
        CycleBits[W] |= Loop.NodeMask[W];
      }
    }
    InCycle.assign(Blocks.size(), 0);
    for (size_t I = 0; I < Blocks.size(); ++I) {
      if (bitsetTest(CycleBits, I)) {
        InCycle[I] = 1;
      }
    }
  } else {
    InCycle = computeInCycle(SuccsCSR, PredsCSR);
  }
  EVM_PROFILE_END(computeInCycle);

  EVM_PROFILE_BEGIN(meteringInit);
  // Initialize m = c (metering function = cost function)
  std::vector<uint64_t> Metering(Blocks.size(), 0);
  for (size_t Id = 0; Id < Blocks.size(); ++Id) {
    Metering[Id] = Blocks[Id].Cost;
  }

  std::vector<uint64_t> NonCycleMask(bitsetWordCount(Blocks.size()), 0);
  for (size_t Id = 0; Id < Blocks.size(); ++Id) {
    if (InCycle[Id] == 0) {
      bitsetSet(NonCycleMask, Id);
    }
  }
  EVM_PROFILE_END(meteringInit);

  EVM_PROFILE_BEGIN(lemma614Schedule);
  if (!UseLinearSPP) {
    for (uint32_t NodeId : RevTopo) {
      if (InCycle[NodeId] != 0) {
        continue;
      }
      lemma614Update(NodeId, Blocks, SuccsCSR, PredsCSR, &BackEdges,
                     &NonCycleMask, Metering);
    }
  } else {
    std::vector<std::vector<uint64_t>> LoopNonCycleMask(Loops.size());
    for (size_t LoopId = 0; LoopId < Loops.size(); ++LoopId) {
      LoopNonCycleMask[LoopId] = Loops[LoopId].NodeMask;
      for (size_t W = 0; W < LoopNonCycleMask[LoopId].size(); ++W) {
        LoopNonCycleMask[LoopId][W] &= NonCycleMask[W];
      }
    }

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
        if (InCycle[NodeId] != 0) {
          continue;
        }
        lemma614Update(NodeId, Blocks, SuccsCSR, PredsCSR, nullptr,
                       &LoopNonCycleMask[LoopId], Metering);
      }
      LoopProcessed[LoopId] = 1;
    };

    for (uint32_t NodeId : RevTopo) {
      const int32_t LoopId = (NodeId < LoopOf.size()) ? LoopOf[NodeId] : -1;
      if (LoopId < 0) {
        if (InCycle[NodeId] != 0) {
          continue;
        }
        lemma614Update(NodeId, Blocks, SuccsCSR, PredsCSR, &BackEdges,
                       &NonCycleMask, Metering);
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
  EVM_PROFILE_END(lemma614Schedule);

  EVM_PROFILE_BEGIN(writeback);
  // Write results to output arrays
  for (size_t Id = 0; Id < Blocks.size(); ++Id) {
    // Skip empty blocks created by splitCriticalEdges to avoid overwriting
    // valid block entries. Empty blocks have no instructions and their Start
    // position may conflict with real blocks.
    if (Blocks[Id].Start == Blocks[Id].End) {
      continue;
    }
    GasChunkEnd[Blocks[Id].Start] = Blocks[Id].End;
    GasChunkCost[Blocks[Id].Start] = Blocks[Id].Cost;
    // Export SPP-shifted cost on a separate output array so the JIT can read
    // it without perturbing the interpreter fast path, which continues to see
    // the unshifted per-block cost above.
    GasChunkCostSPP[Blocks[Id].Start] = Metering[Id];
  }
  EVM_PROFILE_END(writeback);

  return true;
}

} // namespace

void buildBytecodeCache(EVMBytecodeCache &Cache, const common::Byte *Code,
                        size_t CodeSize, evmc_revision Rev, bool EnableSPP) {
  Cache.JumpDestMap.assign(CodeSize, 0);
  Cache.PushValueMap.resize(CodeSize);
  Cache.GasChunkEnd.assign(CodeSize, 0);
  Cache.GasChunkCost.assign(CodeSize, 0);
  if (EnableSPP) {
    Cache.GasChunkCostSPP.assign(CodeSize, 0);
  } else {
    Cache.GasChunkCostSPP.clear();
  }

  EVM_PROFILE_BEGIN(buildJumpDestMap);
  buildJumpDestMapAndPushCache(Code, CodeSize, Cache.JumpDestMap,
                               Cache.PushValueMap);
  EVM_PROFILE_END(buildJumpDestMap);
  const auto *MetricsTable = evmc_get_instruction_metrics_table(Rev);
  if (!MetricsTable) {
    MetricsTable = evmc_get_instruction_metrics_table(DEFAULT_REVISION);
  }

  buildGasChunksSPP(Code, CodeSize, MetricsTable, Cache.JumpDestMap,
                    Cache.PushValueMap, Cache.GasChunkEnd, Cache.GasChunkCost,
                    Cache.GasChunkCostSPP, EnableSPP);
}

namespace for_testing {

std::vector<uint32_t>
computeIDomForTesting(const std::vector<std::vector<uint32_t>> &Succs,
                      const std::vector<uint8_t> &Reachable) {
  const size_t N = Succs.size();
  if (Reachable.size() != N) {
    return std::vector<uint32_t>(N, UINT32_MAX);
  }
  // Flatten Succs[] into CSR directly, then derive Preds CSR from it. The
  // helper exists only to drive computeDomInfo in isolation; we do not need
  // the GasBlock vector here.
  CSRGraph SuccsCSR;
  SuccsCSR.Off.resize(N + 1, 0);
  for (size_t I = 0; I < N; ++I) {
    SuccsCSR.Off[I + 1] =
        SuccsCSR.Off[I] + static_cast<uint32_t>(Succs[I].size());
  }
  SuccsCSR.Data.resize(SuccsCSR.Off[N]);
  for (size_t I = 0; I < N; ++I) {
    uint32_t Pos = SuccsCSR.Off[I];
    for (uint32_t S : Succs[I]) {
      SuccsCSR.Data[Pos++] = S;
    }
  }
  // Build Preds CSR by counting in-degree then bucketing.
  CSRGraph PredsCSR;
  PredsCSR.Off.assign(N + 1, 0);
  for (size_t I = 0; I < N; ++I) {
    for (uint32_t S : Succs[I]) {
      if (S < N) {
        ++PredsCSR.Off[S + 1];
      }
    }
  }
  for (size_t I = 1; I <= N; ++I) {
    PredsCSR.Off[I] += PredsCSR.Off[I - 1];
  }
  PredsCSR.Data.resize(PredsCSR.Off[N]);
  std::vector<uint32_t> Cursor = PredsCSR.Off;
  for (size_t I = 0; I < N; ++I) {
    for (uint32_t S : Succs[I]) {
      if (S < N) {
        PredsCSR.Data[Cursor[S]++] = static_cast<uint32_t>(I);
      }
    }
  }
  return computeDomInfo(SuccsCSR, PredsCSR, Reachable).IDom;
}

} // namespace for_testing

} // namespace zen::evm
