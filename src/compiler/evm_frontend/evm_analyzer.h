// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef EVM_FRONTEND_EVM_ANALYZER_H
#define EVM_FRONTEND_EVM_ANALYZER_H

#include "common/defines.h"
#include "compiler/evm_frontend/evm_value_range.h"
#include "evm/evm.h"
#include "evmc/evmc.h"
#include "evmc/instructions.h"

#include <algorithm>
#include <cstdint>
#include <map>
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace COMPILER {

// ============== JIT Suitability Analysis =====================================
//
// Certain EVM opcodes expand to very large MIR instruction sequences (long
// SelectInstruction chains or heavy intermediate value fan-out).  When hundreds
// of these appear in a single basic block the greedy register allocator's cost
// becomes superlinear, causing compilation times to explode.
//
// The analysis below detects pathological patterns in O(n) time during the
// existing bytecode scan and provides a structured verdict on whether JIT
// compilation should be attempted.

/// Approximate MIR instruction count generated per EVM opcode.
/// Derived from the compiler frontend: inline arithmetic expands to many
/// instructions while runtime-call opcodes are cheap.
// clang-format off
static constexpr uint32_t MIR_OPCODE_WEIGHT[256] = {
  // 0x00 STOP    ADD     MUL     SUB     DIV     SDIV    MOD     SMOD
         5,       12,     12,     20,     5,      5,      5,      5,
  // 0x08 ADDMOD  MULMOD  EXP     SIGNEXT (0x0c-0x0f undefined)
         5,       5,      5,      20,     2,      2,      2,      2,
  // 0x10 LT      GT      SLT     SGT     EQ      ISZERO  AND     OR
         12,      12,     12,     12,     12,     8,      8,      8,
  // 0x18 XOR     NOT     BYTE    SHL     SHR     SAR     CLZ     (0x1f)
         8,       8,      8,      15,     15,     15,     8,      2,
  // 0x20 KECCAK256  (0x21-0x2f undefined)
         5,       2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,
  // 0x30 ADDRESS BALANCE ORIGIN  CALLER  CALLVAL CLDLOAD CLDSIZE CLDCOPY
         5,       5,      5,      5,      5,      5,      5,      8,
  // 0x38 CODESIZE CODECOPY GASPRICE EXTCDSZ EXTCDCP RETDSZ  RETDCP  EXTCDHASH
         5,       8,       5,       5,       8,      5,      8,      5,
  // 0x40 BLKHASH COINBASE TIMESTAMP NUMBER PREVRAND GASLIM CHAINID SELFBAL
         5,       5,       5,        5,     5,       5,     5,      5,
  // 0x48 BASEFEE BLOBHASH BLOBBASE (0x4b-0x4f undefined)
         5,       5,       5,       2,      2,      2,      2,      2,
  // 0x50 POP     MLOAD   MSTORE  MSTORE8 SLOAD   SSTORE  JUMP    JUMPI
         2,       8,      8,      8,      5,      5,      5,      5,
  // 0x58 PC      MSIZE   GAS     JMPDEST TLOAD   TSTORE  MCOPY   (PUSH0)
         5,       5,      5,      2,      5,      5,      8,      4,
  // 0x60 PUSH1 .. PUSH32 (0x60-0x7f): all weight 4
         4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,  // PUSH1-PUSH16
         4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,  // PUSH17-PUSH32
  // 0x80 DUP1 .. DUP16 (0x80-0x8f): all weight 4
         4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
  // 0x90 SWAP1 .. SWAP16 (0x90-0x9f): all weight 4
         4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
  // 0xa0 LOG0-LOG4 (0xa0-0xa4), rest undefined
         8, 8, 8, 8, 8,  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
  // 0xb0-0xef: undefined / reserved, weight 2
         2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,  // 0xb0-0xbf
         2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,  // 0xc0-0xcf
         2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,  // 0xd0-0xdf
         2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,  // 0xe0-0xef
  // 0xf0 CREATE  CALL    CALLCODE RETURN  DELCALL (0xf5) CREAT2  (0xf7)
         5,       5,      5,       5,      5,      2,     5,      2,
  // 0xf8 (undef) (undef) STATIC   (undef) (undef) REVERT (INVALID) SELFDEST
         2,       2,      5,       2,      2,      5,     2,       5,
};
// clang-format on

/// Returns true if the opcode expands to complex MIR structures (long Select
/// chains or heavy intermediate value fan-out) that cause superlinear register
/// allocation cost when they appear in high density.
inline bool isRAExpensiveOpcode(uint8_t Op) {
  switch (Op) {
  case 0x0b: // SIGNEXTEND — ~21 Selects, two dependency chain loops
  case 0x1b: // SHL  — ~92 Selects, nested J,K loops
  case 0x1c: // SHR  — ~96 Selects, nested J,K loops
  case 0x1d: // SAR  — ~52 Selects, sign-extended variant
    return true;
  default:
    return false;
  }
}

/// Returns true if the opcode is a DUP or SWAP (transparent for consecutive
/// RA-expensive run detection since they don't generate heavy MIR).
inline bool isDupOrSwapOpcode(uint8_t Op) {
  return (Op >= 0x80 && Op <= 0x8f) || // DUP1..DUP16
         (Op >= 0x90 && Op <= 0x9f);   // SWAP1..SWAP16
}

/// Returns true if the opcode is a DUP instruction.
inline bool isDupOpcode(uint8_t Op) {
  return Op >= 0x80 && Op <= 0x8f; // DUP1..DUP16
}

/// Structured result of JIT suitability analysis.  Provides fine-grained
/// metrics so callers can log diagnostics or tune thresholds.
struct JITSuitabilityResult {
  bool ShouldFallback = false;
  size_t BytecodeSize = 0;
  size_t MirEstimate = 0;             // linear MIR instruction estimate
  size_t RAExpensiveCount = 0;        // total RA-expensive opcodes
  size_t MaxConsecutiveExpensive = 0; // longest unbroken run
  size_t MaxBlockExpensiveCount = 0;  // max RA-expensive ops in one block
  size_t DupFeedbackPatternCount = 0; // DUPn immediately before RA-expensive
};

/// Thresholds for JIT suitability fallback. These limits bound bytecode size
/// and estimated MIR / RA complexity to avoid pathological JIT compile-time
/// blowups (e.g., superlinear register allocation on dense RA-expensive
/// instruction patterns), while keeping typical contracts on the JIT path.
static constexpr size_t MAX_JIT_BYTECODE_SIZE = 0x6000;
static constexpr size_t MAX_JIT_MIR_ESTIMATE = 0x50000;        // 327,680
static constexpr size_t MAX_CONSECUTIVE_RA_EXPENSIVE = 0x3000; // 12,288
static constexpr size_t MAX_BLOCK_RA_EXPENSIVE = 0x3000;       // 12,288
static constexpr size_t MAX_DUP_FEEDBACK_PATTERN = 0x3000;     // 12,288

class EVMAnalyzer {
  using Byte = zen::common::Byte;

public:
  EVMAnalyzer(evmc_revision Rev = zen::evm::DEFAULT_REVISION) : Revision(Rev) {
    InstructionMetrics = evmc_get_instruction_metrics_table(Revision);
    if (!InstructionMetrics) {
      InstructionMetrics =
          evmc_get_instruction_metrics_table(zen::evm::DEFAULT_REVISION);
    }
    InstructionNames = evmc_get_instruction_names_table(Revision);
    if (!InstructionNames) {
      InstructionNames =
          evmc_get_instruction_names_table(zen::evm::DEFAULT_REVISION);
    }
  }

  struct BlockInfo {
    uint64_t EntryPC = 0;
    uint64_t BodyStartPC = 0;
    uint64_t BodyEndPC = 0;
    int32_t MaxStackHeight = 0;
    int32_t MinStackHeight = 0;
    int32_t MinPopHeight = 0;
    int32_t StackHeightDiff = 0;
    int32_t EntryStackDepth = 0;
    int32_t ResolvedEntryStackDepth = -1;
    int32_t ResolvedExitStackDepth = -1;
    int32_t FullEntryStateDepth = -1;
    int32_t HiddenLiveInPrefixDepth = 0;
    bool HasInconsistentEntryDepth = false;
    bool IsEntryStateCompatible = false;
    bool HasHiddenLiveInPrefix = false;
    bool RequiresEntryMergeState = false;
    bool HasDeferredEntryMerge = false;
    bool IsDynamicJumpTargetCandidate = false;
    bool HasCompatibleDynamicJumpTargetShape = false;
    bool IsJumpDest = false;
    bool HasUndefinedInstr = false;
    bool HasDynamicJump = false;
    bool HasConditionalJump = false;
    bool HasConstantJump = false;
    bool CanLiftStack = false;
    uint64_t ConstantJumpTargetPC = 0;
    uint64_t DynamicJumpTargetRegionEntryPC = 0;
    std::vector<uint64_t> DynamicJumpTargetRegions;
    uint32_t RAExpensiveCount = 0;
    std::vector<uint64_t> Successors;
    std::vector<uint64_t> Predecessors;

    // Per-stack-slot value-range at block entry, populated by
    // EVMRangeAnalyzer.  Index 0 is the bottom of the entry stack, last is the
    // top.  Empty when no Range info is available (treat as ValueRange::U256).
    std::vector<EVMValueRange> EntryStackRanges;

    BlockInfo() = default;
    BlockInfo(uint64_t PC, uint64_t StartPC = 0, bool JumpDest = false)
        : EntryPC(PC), BodyStartPC(StartPC), BodyEndPC(StartPC),
          IsJumpDest(JumpDest) {}
  };

  const std::map<uint64_t, BlockInfo> &getBlockInfos() const {
    return BlockInfos;
  }

  struct DynamicJumpRegionInfo {
    uint64_t RegionEntryPC = 0;
    std::vector<uint64_t> SourceBlocks;
    std::vector<uint64_t> TargetBlocks;
    int32_t UniformEntryDepth = -1;
    int32_t FullEntryStateDepth = -1;
    int32_t HiddenLiveInPrefixDepth = 0;
    bool RequiresEntryMergeState = false;
    bool HasUniformEntryDepth = false;
    bool HasCompatibleTargetShape = false;
    uint32_t ShapeClassId = 0;
  };

  const std::map<uint64_t, DynamicJumpRegionInfo> &
  getDynamicJumpRegions() const {
    return DynamicJumpRegions;
  }

  const DynamicJumpRegionInfo *
  getDynamicJumpRegionInfo(uint64_t RegionEntryPC) const {
    auto It = DynamicJumpRegions.find(RegionEntryPC);
    if (It == DynamicJumpRegions.end()) {
      return nullptr;
    }
    return &It->second;
  }

  std::vector<uint32_t>
  getCompatibleDynamicJumpShapeClassIdsForBlock(uint64_t BlockPC) const {
    std::vector<uint32_t> ShapeClassIds;
    auto It = BlockInfos.find(BlockPC);
    if (It == BlockInfos.end()) {
      return ShapeClassIds;
    }

    for (uint64_t RegionEntryPC : It->second.DynamicJumpTargetRegions) {
      const auto *RegionInfo = getDynamicJumpRegionInfo(RegionEntryPC);
      if (!RegionInfo || !RegionInfo->HasCompatibleTargetShape ||
          RegionInfo->ShapeClassId == 0) {
        continue;
      }
      if (std::find(ShapeClassIds.begin(), ShapeClassIds.end(),
                    RegionInfo->ShapeClassId) == ShapeClassIds.end()) {
        ShapeClassIds.push_back(RegionInfo->ShapeClassId);
      }
    }
    return ShapeClassIds;
  }

  uint32_t
  getUniqueCompatibleDynamicJumpShapeClassForBlock(uint64_t BlockPC) const {
    const std::vector<uint32_t> ShapeClassIds =
        getCompatibleDynamicJumpShapeClassIdsForBlock(BlockPC);
    return ShapeClassIds.size() == 1 ? ShapeClassIds.front() : 0;
  }

  uint32_t
  getOutgoingCompatibleDynamicJumpShapeClassForBlock(uint64_t BlockPC) const {
    auto It = BlockInfos.find(BlockPC);
    if (It == BlockInfos.end()) {
      return 0;
    }
    if (!It->second.HasDynamicJump ||
        It->second.DynamicJumpTargetRegionEntryPC == 0) {
      return 0;
    }

    const auto *RegionInfo =
        getDynamicJumpRegionInfo(It->second.DynamicJumpTargetRegionEntryPC);
    if (!RegionInfo || !RegionInfo->HasCompatibleTargetShape) {
      return 0;
    }
    return RegionInfo->ShapeClassId;
  }

  bool blockHasCompatibleDynamicJumpShapeClass(uint64_t BlockPC,
                                               uint32_t ShapeClassId) const {
    if (ShapeClassId == 0) {
      return false;
    }
    const std::vector<uint32_t> ShapeClassIds =
        getCompatibleDynamicJumpShapeClassIdsForBlock(BlockPC);
    return std::find(ShapeClassIds.begin(), ShapeClassIds.end(),
                     ShapeClassId) != ShapeClassIds.end();
  }

  bool blocksShareCompatibleDynamicJumpShapeClass(uint64_t BlockPC,
                                                  uint64_t OtherBlockPC) const {
    const std::vector<uint32_t> ShapeClassIds =
        getCompatibleDynamicJumpShapeClassIdsForBlock(BlockPC);
    const std::vector<uint32_t> OtherShapeClassIds =
        getCompatibleDynamicJumpShapeClassIdsForBlock(OtherBlockPC);
    for (uint32_t ShapeClassId : ShapeClassIds) {
      if (std::find(OtherShapeClassIds.begin(), OtherShapeClassIds.end(),
                    ShapeClassId) != OtherShapeClassIds.end()) {
        return true;
      }
    }

    const uint32_t OutgoingShapeClassId =
        getOutgoingCompatibleDynamicJumpShapeClassForBlock(BlockPC);
    if (OutgoingShapeClassId != 0 &&
        (blockHasCompatibleDynamicJumpShapeClass(OtherBlockPC,
                                                 OutgoingShapeClassId) ||
         OutgoingShapeClassId ==
             getOutgoingCompatibleDynamicJumpShapeClassForBlock(
                 OtherBlockPC))) {
      return true;
    }

    const uint32_t OtherOutgoingShapeClassId =
        getOutgoingCompatibleDynamicJumpShapeClassForBlock(OtherBlockPC);
    return OtherOutgoingShapeClassId != 0 &&
           blockHasCompatibleDynamicJumpShapeClass(BlockPC,
                                                   OtherOutgoingShapeClassId);
  }

  std::vector<uint64_t>
  getDynamicJumpSourceBlocksForBlock(uint64_t BlockPC) const {
    auto It = BlockInfos.find(BlockPC);
    if (It == BlockInfos.end()) {
      return {};
    }
    return collectDynamicJumpSourceBlocksForInfo(It->second);
  }

  std::vector<uint64_t>
  getPotentialEntryPredecessorsForBlock(uint64_t BlockPC) const {
    auto It = BlockInfos.find(BlockPC);
    if (It == BlockInfos.end()) {
      return {};
    }

    std::vector<uint64_t> PredBlockPCs(It->second.Predecessors.begin(),
                                       It->second.Predecessors.end());
    for (uint64_t PredBlockPC :
         collectDynamicJumpSourceBlocksForInfo(It->second)) {
      appendUniqueBlockPC(PredBlockPCs, PredBlockPC);
    }
    return PredBlockPCs;
  }

  std::vector<uint64_t>
  getCompatibleDynamicJumpTargetBlocksForSourceBlock(uint64_t BlockPC) const {
    auto It = BlockInfos.find(BlockPC);
    if (It == BlockInfos.end()) {
      return {};
    }
    uint32_t OutgoingShapeClassId =
        getOutgoingCompatibleDynamicJumpShapeClassForBlock(BlockPC);
    if (OutgoingShapeClassId == 0 && It->second.HasDynamicJump) {
      OutgoingShapeClassId =
          getUniqueCompatibleDynamicJumpShapeClassForBlock(BlockPC);
    }
    if (OutgoingShapeClassId != 0) {
      std::vector<uint64_t> TargetBlockPCs;
      for (const auto &[EntryPC, Info] : BlockInfos) {
        if (!Info.HasCompatibleDynamicJumpTargetShape) {
          continue;
        }
        if (blockHasCompatibleDynamicJumpShapeClass(EntryPC,
                                                    OutgoingShapeClassId)) {
          appendUniqueBlockPC(TargetBlockPCs, EntryPC);
        }
      }
      return TargetBlockPCs;
    }
    if (!It->second.HasDynamicJump ||
        It->second.DynamicJumpTargetRegionEntryPC == 0) {
      return {};
    }

    const auto *RegionInfo =
        getDynamicJumpRegionInfo(It->second.DynamicJumpTargetRegionEntryPC);
    if (!RegionInfo || !RegionInfo->HasCompatibleTargetShape) {
      return {};
    }
    return RegionInfo->TargetBlocks;
  }

  bool hasDeferredLiftedEntryMerge(uint64_t BlockPC) const {
    auto It = BlockInfos.find(BlockPC);
    return It != BlockInfos.end() && It->second.CanLiftStack &&
           It->second.HasDeferredEntryMerge;
  }

  bool canTransferLiftedEntryStateWithoutRuntimeMaterialization(
      uint64_t BlockPC) const {
    auto It = BlockInfos.find(BlockPC);
    return It != BlockInfos.end() && It->second.CanLiftStack;
  }

  bool canTransferCompatibleDynamicJumpTargetsWithoutRuntimeMaterialization(
      uint64_t BlockPC) const {
    const std::vector<uint64_t> TargetBlockPCs =
        getCompatibleDynamicJumpTargetBlocksForSourceBlock(BlockPC);
    return !TargetBlockPCs.empty() &&
           std::all_of(
               TargetBlockPCs.begin(), TargetBlockPCs.end(),
               [this](uint64_t TargetBlockPC) {
                 return canTransferLiftedEntryStateWithoutRuntimeMaterialization(
                     TargetBlockPC);
               });
  }

  const JITSuitabilityResult &getJITSuitability() const { return JITResult; }

  bool hasUnresolvedNonLiftedDeepEntryRisk() const {
    for (const auto &[BlockPC, Info] : BlockInfos) {
      if (Info.CanLiftStack || Info.ResolvedEntryStackDepth >= 0) {
        continue;
      }

      const int32_t RequiredEntryDepth = -Info.MinStackHeight;
      if (RequiredEntryDepth <= 1) {
        continue;
      }

      for (uint64_t PredBlockPC : Info.Predecessors) {
        auto PredIt = BlockInfos.find(PredBlockPC);
        if (PredIt == BlockInfos.end()) {
          continue;
        }

        const BlockInfo &PredInfo = PredIt->second;
        if (PredInfo.CanLiftStack || PredInfo.ResolvedEntryStackDepth >= 0) {
          continue;
        }

        return true;
      }
    }

    return false;
  }

  bool hasCanonicalJumpDest(uint64_t PC) const {
    return JumpDestCanonicalPCs.count(PC) != 0;
  }

  uint64_t getCanonicalJumpDestPC(uint64_t PC) const {
    auto It = JumpDestCanonicalPCs.find(PC);
    return It == JumpDestCanonicalPCs.end() ? PC : It->second;
  }

  void setResolvedJumpTargets(
      const std::unordered_map<uint32_t, uint32_t> *Targets) {
    SharedResolvedJumpTargets = Targets;
  }

  bool hasUnknownDynamicJumpTargets() const { return HasUnknownDynamicJump; }

  bool analyzeSuitabilityOnly(const uint8_t *Bytecode, size_t BytecodeSize) {
    resetAnalysisState();
    analyzeSuitability(Bytecode, BytecodeSize);
    return true;
  }

  bool analyze(const uint8_t *Bytecode, size_t BytecodeSize) {
    resetAnalysisState();
    analyzeSuitability(Bytecode, BytecodeSize);
    buildJumpDestRuns(Bytecode, BytecodeSize);
    buildBlocks(Bytecode, BytecodeSize);
    linkPredecessors();
    resolveEntryDepths();
    markDynamicJumpTargetCandidates();
    resolveDynamicJumpTargetEntryDepths();
    finalizeEntryShapeMetadata();
    finalizeLiftability();
    runRangeAnalysis(Bytecode, BytecodeSize);
    return true;
  }

private:
  // Fallback: look up pre-resolved jump target from the shared cache.
  // Used when local abstract stack analysis cannot resolve the jump.
  // The shared map stores raw (non-canonicalized) PCs; we canonicalize here
  // because the SSA analyzer uses canonical JUMPDEST PCs for block identity.
  // Overload for JUMP (unconditional).
  bool tryResolveFromSharedMap(size_t JumpPC, BlockInfo &Info) {
    if (!SharedResolvedJumpTargets) {
      return false;
    }
    auto It = SharedResolvedJumpTargets->find(static_cast<uint32_t>(JumpPC));
    if (It == SharedResolvedJumpTargets->end()) {
      return false;
    }
    uint64_t RawPC = static_cast<uint64_t>(It->second);
    uint64_t TargetPC = getCanonicalJumpDestPC(RawPC);
    Info.HasConstantJump = true;
    Info.ConstantJumpTargetPC = TargetPC;
    Info.Successors.push_back(TargetPC);
    return true;
  }

  // Overload for JUMPI (conditional): also receives FallthroughEntryPC to
  // avoid adding a duplicate successor edge.
  bool tryResolveFromSharedMap(size_t JumpPC, BlockInfo &Info,
                               uint64_t FallthroughEntryPC) {
    if (!SharedResolvedJumpTargets) {
      return false;
    }
    auto It = SharedResolvedJumpTargets->find(static_cast<uint32_t>(JumpPC));
    if (It == SharedResolvedJumpTargets->end()) {
      return false;
    }
    uint64_t RawPC = static_cast<uint64_t>(It->second);
    uint64_t TargetPC = getCanonicalJumpDestPC(RawPC);
    Info.HasConstantJump = true;
    Info.ConstantJumpTargetPC = TargetPC;
    if (TargetPC != FallthroughEntryPC) {
      Info.Successors.push_back(TargetPC);
    }
    return true;
  }

  void resetAnalysisState() {
    BlockInfos.clear();
    DynamicJumpRegions.clear();
    JumpDestCanonicalPCs.clear();
    EntryBlockPC = 0;
    HasUnknownDynamicJump = false;
  }

  struct AbstractValue {
    bool KnownConst = false;
    bool FitsU64 = false;
    uint64_t Low = 0;

    static AbstractValue unknown() { return {}; }

    static AbstractValue constFromPush(const uint8_t *Bytecode,
                                       size_t BytecodeSize, size_t Start,
                                       size_t Size) {
      AbstractValue V;
      V.KnownConst = true;
      V.FitsU64 = true;
      V.Low = 0;
      if (Size == 0) {
        return V;
      }

      const size_t Available =
          Start < BytecodeSize ? (BytecodeSize - Start) : 0;
      const size_t ReadCount = std::min(Size, Available);
      auto readPushByte = [&](size_t Index) -> uint8_t {
        if (Index >= ReadCount) {
          return 0;
        }
        return Bytecode[Start + Index];
      };

      size_t ValueStart = 0;
      if (Size > sizeof(uint64_t)) {
        for (size_t I = 0; I < Size - sizeof(uint64_t); ++I) {
          if (readPushByte(I) != 0) {
            V.FitsU64 = false;
            break;
          }
        }
        ValueStart = Size - sizeof(uint64_t);
      }
      for (size_t I = ValueStart; I < Size; ++I) {
        V.Low = (V.Low << 8) | static_cast<uint64_t>(readPushByte(I));
      }
      return V;
    }
  };

  static bool isBlockTerminator(evmc_opcode Opcode) {
    switch (Opcode) {
    case OP_JUMP:
    case OP_STOP:
    case OP_RETURN:
    case OP_INVALID:
    case OP_REVERT:
    case OP_SELFDESTRUCT:
      return true;
    default:
      return false;
    }
  }

  static size_t immediateSize(evmc_opcode Opcode) {
    if (Opcode >= OP_PUSH0 && Opcode <= OP_PUSH32) {
      return static_cast<size_t>(Opcode - OP_PUSH0);
    }
    return 0;
  }

  void analyzeSuitability(const uint8_t *Bytecode, size_t BytecodeSize) {
    JITResult = JITSuitabilityResult();
    JITResult.BytecodeSize = BytecodeSize;

    size_t CurConsecutiveExpensive = 0;
    size_t CurBlockExpensiveCount = 0;
    bool PrevWasDup = false;

    size_t PCIndex = 0;
    while (PCIndex < BytecodeSize) {
      evmc_opcode Opcode = static_cast<evmc_opcode>(Bytecode[PCIndex]);
      uint8_t OpcodeU8 = static_cast<uint8_t>(Opcode);

      JITResult.MirEstimate += MIR_OPCODE_WEIGHT[OpcodeU8];

      if (isRAExpensiveOpcode(OpcodeU8)) {
        JITResult.RAExpensiveCount++;
        CurBlockExpensiveCount++;
        CurConsecutiveExpensive++;
        if (PrevWasDup) {
          JITResult.DupFeedbackPatternCount++;
        }
        PrevWasDup = false;
      } else if (isDupOrSwapOpcode(OpcodeU8)) {
        PrevWasDup = isDupOpcode(OpcodeU8);
      } else {
        JITResult.MaxConsecutiveExpensive = std::max(
            JITResult.MaxConsecutiveExpensive, CurConsecutiveExpensive);
        CurConsecutiveExpensive = 0;
        PrevWasDup = false;
      }

      bool IsBlockBoundary = (Opcode == OP_JUMPI || Opcode == OP_JUMPDEST ||
                              isBlockTerminator(Opcode));
      if (IsBlockBoundary) {
        JITResult.MaxBlockExpensiveCount =
            std::max(JITResult.MaxBlockExpensiveCount, CurBlockExpensiveCount);
        CurBlockExpensiveCount = 0;
        JITResult.MaxConsecutiveExpensive = std::max(
            JITResult.MaxConsecutiveExpensive, CurConsecutiveExpensive);
        CurConsecutiveExpensive = 0;
        PrevWasDup = false;
      }

      size_t PushBytes = immediateSize(Opcode);
      PCIndex += 1 + PushBytes;
    }

    JITResult.MaxConsecutiveExpensive =
        std::max(JITResult.MaxConsecutiveExpensive, CurConsecutiveExpensive);
    JITResult.MaxBlockExpensiveCount =
        std::max(JITResult.MaxBlockExpensiveCount, CurBlockExpensiveCount);

    JITResult.ShouldFallback =
        BytecodeSize > MAX_JIT_BYTECODE_SIZE ||
        JITResult.MirEstimate > MAX_JIT_MIR_ESTIMATE ||
        JITResult.MaxConsecutiveExpensive > MAX_CONSECUTIVE_RA_EXPENSIVE ||
        JITResult.MaxBlockExpensiveCount > MAX_BLOCK_RA_EXPENSIVE ||
        JITResult.DupFeedbackPatternCount > MAX_DUP_FEEDBACK_PATTERN;
  }

  void buildJumpDestRuns(const uint8_t *Bytecode, size_t BytecodeSize) {
    size_t PCIndex = 0;
    while (PCIndex < BytecodeSize) {
      evmc_opcode Opcode = static_cast<evmc_opcode>(Bytecode[PCIndex]);
      if (Opcode == OP_JUMPDEST) {
        size_t RunStart = PCIndex;
        size_t RunEnd = PCIndex;
        while (RunEnd + 1 < BytecodeSize &&
               static_cast<evmc_opcode>(Bytecode[RunEnd + 1]) == OP_JUMPDEST) {
          ++RunEnd;
        }
        for (size_t PC = RunStart; PC <= RunEnd; ++PC) {
          JumpDestCanonicalPCs[static_cast<uint64_t>(PC)] =
              static_cast<uint64_t>(RunEnd);
        }
        PCIndex = RunEnd + 1;
        continue;
      }
      PCIndex += 1 + immediateSize(Opcode);
    }
  }

  void ensureAbstractDepth(std::vector<AbstractValue> &Stack,
                           size_t &EntryDepth, size_t RequiredDepth) {
    if (Stack.size() >= RequiredDepth) {
      return;
    }
    size_t Deficit = RequiredDepth - Stack.size();
    Stack.insert(Stack.begin(), Deficit, AbstractValue::unknown());
    EntryDepth += Deficit;
  }

  void analyzeBlockBody(BlockInfo &Info, const uint8_t *Bytecode,
                        size_t BytecodeSize, size_t &ScanPC,
                        uint64_t &NextEntryPC, size_t &NextBodyStartPC,
                        bool &HasNextBlock) {

    std::vector<AbstractValue> Stack;
    size_t EntryDepth = 0;
    Info.MaxStackHeight = 0;
    Info.MinStackHeight = 0;
    Info.MinPopHeight = 0;
    Info.StackHeightDiff = 0;
    Info.EntryStackDepth = 0;
    Info.BodyEndPC = Info.BodyStartPC;

    auto updateHeights = [&]() {
      int32_t RelativeHeight =
          static_cast<int32_t>(Stack.size()) - static_cast<int32_t>(EntryDepth);
      Info.StackHeightDiff = RelativeHeight;
      Info.MaxStackHeight = std::max(Info.MaxStackHeight, RelativeHeight);
      Info.MinStackHeight = std::min(Info.MinStackHeight, RelativeHeight);
      Info.MinPopHeight =
          std::min(Info.MinPopHeight, -static_cast<int32_t>(EntryDepth));
    };

    HasNextBlock = false;
    NextEntryPC = 0;
    NextBodyStartPC = BytecodeSize;

    while (ScanPC < BytecodeSize) {
      evmc_opcode Opcode = static_cast<evmc_opcode>(Bytecode[ScanPC]);

      if (Opcode == OP_JUMPDEST) {
        uint64_t CanonicalPC =
            getCanonicalJumpDestPC(static_cast<uint64_t>(ScanPC));
        Info.Successors.push_back(CanonicalPC);
        NextEntryPC = CanonicalPC;
        NextBodyStartPC = static_cast<size_t>(CanonicalPC) + 1;
        HasNextBlock = true;
        Info.BodyEndPC = static_cast<uint64_t>(ScanPC);
        break;
      }

      bool IsUndefined = (InstructionNames[Opcode] == nullptr);
      if (IsUndefined) {
        Info.HasUndefinedInstr = true;
#ifdef ZEN_ENABLE_JIT_FALLBACK_TEST
        Info.HasUndefinedInstr = false;
#endif
        ++ScanPC;
        Info.BodyEndPC = static_cast<uint64_t>(ScanPC);
        skipDeadCode(Bytecode, BytecodeSize, ScanPC, NextEntryPC,
                     NextBodyStartPC, HasNextBlock);
        break;
      }

      uint8_t OpcodeU8 = static_cast<uint8_t>(Opcode);
      if (isRAExpensiveOpcode(OpcodeU8)) {
        Info.RAExpensiveCount++;
      }

      ++ScanPC;
      size_t PushBytes = immediateSize(Opcode);

      if (Opcode == OP_JUMP) {
        ensureAbstractDepth(Stack, EntryDepth, 1);
        AbstractValue Dest = Stack.back();
        Stack.pop_back();
        updateHeights();

        if (Dest.KnownConst && Dest.FitsU64 && hasCanonicalJumpDest(Dest.Low)) {
          Info.HasConstantJump = true;
          Info.ConstantJumpTargetPC = getCanonicalJumpDestPC(Dest.Low);
          Info.Successors.push_back(Info.ConstantJumpTargetPC);
        } else if (tryResolveFromSharedMap(ScanPC - 1, Info)) {
          // Resolved via shared cache (covers patterns like SWAPn→JUMP).
        } else {
          Info.HasDynamicJump = true;
          HasUnknownDynamicJump = true;
        }
        Info.BodyEndPC = static_cast<uint64_t>(ScanPC);
        skipDeadCode(Bytecode, BytecodeSize, ScanPC, NextEntryPC,
                     NextBodyStartPC, HasNextBlock);
        if (Info.HasDynamicJump && HasNextBlock) {
          Info.DynamicJumpTargetRegionEntryPC = NextEntryPC;
        }
        break;
      }

      if (Opcode == OP_JUMPI) {
        ensureAbstractDepth(Stack, EntryDepth, 2);
        AbstractValue Dest = Stack.back();
        Stack.pop_back();
        Stack.pop_back();
        updateHeights();

        uint64_t FallthroughEntryPC = static_cast<uint64_t>(ScanPC);
        size_t FallthroughBodyStartPC = ScanPC;
        if (ScanPC < BytecodeSize &&
            static_cast<evmc_opcode>(Bytecode[ScanPC]) == OP_JUMPDEST) {
          FallthroughEntryPC = getCanonicalJumpDestPC(FallthroughEntryPC);
          FallthroughBodyStartPC = static_cast<size_t>(FallthroughEntryPC) + 1;
        }

        Info.HasConditionalJump = true;
        Info.Successors.push_back(FallthroughEntryPC);
        if (Dest.KnownConst && Dest.FitsU64 && hasCanonicalJumpDest(Dest.Low)) {
          Info.HasConstantJump = true;
          Info.ConstantJumpTargetPC = getCanonicalJumpDestPC(Dest.Low);
          if (Info.ConstantJumpTargetPC != FallthroughEntryPC) {
            Info.Successors.push_back(Info.ConstantJumpTargetPC);
          }
        } else if (!Dest.KnownConst || !Dest.FitsU64) {
          if (tryResolveFromSharedMap(ScanPC - 1, Info, FallthroughEntryPC)) {
            // Resolved via shared cache.
          } else {
            Info.HasDynamicJump = true;
            HasUnknownDynamicJump = true;
            Info.DynamicJumpTargetRegionEntryPC = FallthroughEntryPC;
          }
        }
        // Note: the implicit else (KnownConst && FitsU64 but NOT a valid
        // JUMPDEST) is intentionally left without a successor for the taken
        // branch — at runtime that path traps with BAD_JUMP_DESTINATION,
        // so it is effectively dead. Only the fallthrough is reachable.
        NextEntryPC = FallthroughEntryPC;
        NextBodyStartPC = FallthroughBodyStartPC;
        HasNextBlock = true;
        Info.BodyEndPC = static_cast<uint64_t>(ScanPC);
        break;
      }

      if (isBlockTerminator(Opcode)) {
        const auto &Metrics = InstructionMetrics[Opcode];
        int PopCount = Metrics.stack_height_required;
        int PushCount = PopCount + Metrics.stack_height_change;
        ensureAbstractDepth(Stack, EntryDepth, static_cast<size_t>(PopCount));
        for (int I = 0; I < PopCount; ++I) {
          Stack.pop_back();
        }
        for (int I = 0; I < PushCount; ++I) {
          Stack.push_back(AbstractValue::unknown());
        }
        updateHeights();
        Info.BodyEndPC = static_cast<uint64_t>(ScanPC);
        skipDeadCode(Bytecode, BytecodeSize, ScanPC, NextEntryPC,
                     NextBodyStartPC, HasNextBlock);
        break;
      }

      if (Opcode >= OP_DUP1 && Opcode <= OP_DUP16) {
        size_t RequiredDepth = static_cast<size_t>(Opcode - OP_DUP1 + 1);
        ensureAbstractDepth(Stack, EntryDepth, RequiredDepth);
        Stack.push_back(Stack[Stack.size() - RequiredDepth]);
        updateHeights();
      } else if (Opcode >= OP_SWAP1 && Opcode <= OP_SWAP16) {
        size_t RequiredDepth = static_cast<size_t>(Opcode - OP_SWAP1 + 2);
        ensureAbstractDepth(Stack, EntryDepth, RequiredDepth);
        std::swap(Stack.back(), Stack[Stack.size() - RequiredDepth]);
        updateHeights();
      } else if (Opcode >= OP_PUSH0 && Opcode <= OP_PUSH32) {
        Stack.push_back(AbstractValue::constFromPush(Bytecode, BytecodeSize,
                                                     ScanPC, PushBytes));
        ScanPC += PushBytes;
        updateHeights();
      } else {
        const auto &Metrics = InstructionMetrics[Opcode];
        int PopCount = Metrics.stack_height_required;
        int PushCount = PopCount + Metrics.stack_height_change;
        ensureAbstractDepth(Stack, EntryDepth, static_cast<size_t>(PopCount));
        for (int I = 0; I < PopCount; ++I) {
          Stack.pop_back();
        }
        for (int I = 0; I < PushCount; ++I) {
          Stack.push_back(AbstractValue::unknown());
        }
        updateHeights();
      }
    }

    if (ScanPC >= BytecodeSize) {
      Info.BodyEndPC = static_cast<uint64_t>(BytecodeSize);
    }

    Info.EntryStackDepth = static_cast<int32_t>(EntryDepth);
    Info.MinStackHeight = std::min(Info.MinStackHeight, -Info.EntryStackDepth);
    Info.MinPopHeight = std::min(Info.MinPopHeight, -Info.EntryStackDepth);
    Info.StackHeightDiff =
        static_cast<int32_t>(Stack.size()) - static_cast<int32_t>(EntryDepth);
  }

  void skipDeadCode(const uint8_t *Bytecode, size_t BytecodeSize,
                    size_t &ScanPC, uint64_t &NextEntryPC,
                    size_t &NextBodyStartPC, bool &HasNextBlock) {
    while (ScanPC < BytecodeSize) {
      evmc_opcode NextOp = static_cast<evmc_opcode>(Bytecode[ScanPC]);
      if (NextOp == OP_JUMPDEST) {
        uint64_t CanonicalPC =
            getCanonicalJumpDestPC(static_cast<uint64_t>(ScanPC));
        NextEntryPC = CanonicalPC;
        NextBodyStartPC = static_cast<size_t>(CanonicalPC) + 1;
        HasNextBlock = true;
        return;
      }
      ScanPC += 1 + immediateSize(NextOp);
    }
    HasNextBlock = false;
  }

  void buildBlocks(const uint8_t *Bytecode, size_t BytecodeSize) {
    if (BytecodeSize == 0) {
      BlockInfos.emplace(0, BlockInfo(0, 0, false));
      EntryBlockPC = 0;
      return;
    }

    size_t BodyStartPC = 0;
    bool StartsWithJumpDest =
        static_cast<evmc_opcode>(Bytecode[0]) == OP_JUMPDEST;
    bool IsJumpDestBlock = false;
    if (StartsWithJumpDest) {
      EntryBlockPC = getCanonicalJumpDestPC(0);
      BodyStartPC = static_cast<size_t>(EntryBlockPC) + 1;
      IsJumpDestBlock = true;
    } else {
      EntryBlockPC = 0;
    }

    uint64_t CurEntryPC = EntryBlockPC;
    while (true) {
      BlockInfo Info(CurEntryPC, BodyStartPC, IsJumpDestBlock);
      size_t ScanPC = BodyStartPC;
      uint64_t NextEntryPC = 0;
      size_t NextBodyStartPC = BytecodeSize;
      bool HasNextBlock = false;
      analyzeBlockBody(Info, Bytecode, BytecodeSize, ScanPC, NextEntryPC,
                       NextBodyStartPC, HasNextBlock);
      BlockInfos[CurEntryPC] = Info;
      if (!HasNextBlock) {
        break;
      }
      CurEntryPC = NextEntryPC;
      BodyStartPC = NextBodyStartPC;
      IsJumpDestBlock = hasCanonicalJumpDest(CurEntryPC) &&
                        getCanonicalJumpDestPC(CurEntryPC) == CurEntryPC;
      if (BodyStartPC > BytecodeSize) {
        break;
      }
    }
  }

  void linkPredecessors() {
    for (auto &[EntryPC, Info] : BlockInfos) {
      (void)EntryPC;
      for (uint64_t Succ : Info.Successors) {
        auto It = BlockInfos.find(Succ);
        if (It == BlockInfos.end()) {
          continue;
        }
        auto &Preds = It->second.Predecessors;
        if (std::find(Preds.begin(), Preds.end(), Info.EntryPC) ==
            Preds.end()) {
          Preds.push_back(Info.EntryPC);
        }
      }
    }
  }

  void invalidateReachableEntryDepths(uint64_t EntryPC) {
    std::queue<uint64_t> InvalidateWorkList;
    std::map<uint64_t, bool> InvalidateVisited;
    InvalidateWorkList.push(EntryPC);
    InvalidateVisited[EntryPC] = true;

    while (!InvalidateWorkList.empty()) {
      uint64_t InvalidPC = InvalidateWorkList.front();
      InvalidateWorkList.pop();
      auto InvalidIt = BlockInfos.find(InvalidPC);
      if (InvalidIt == BlockInfos.end()) {
        continue;
      }
      auto &InvalidInfo = InvalidIt->second;
      InvalidInfo.HasInconsistentEntryDepth = true;
      InvalidInfo.ResolvedEntryStackDepth = -1;
      InvalidInfo.ResolvedExitStackDepth = -1;
      for (uint64_t NextSucc : InvalidInfo.Successors) {
        if (InvalidateVisited.emplace(NextSucc, true).second) {
          InvalidateWorkList.push(NextSucc);
        }
      }
    }
  }

  void resolveEntryDepths() {
    auto EntryIt = BlockInfos.find(EntryBlockPC);
    if (EntryIt == BlockInfos.end()) {
      return;
    }

    EntryIt->second.ResolvedEntryStackDepth = 0;
    std::queue<uint64_t> WorkList;
    WorkList.push(EntryBlockPC);
    propagateEntryDepths(WorkList);
  }

  void propagateEntryDepths(std::queue<uint64_t> &WorkList) {
    while (!WorkList.empty()) {
      uint64_t EntryPC = WorkList.front();
      WorkList.pop();
      auto &Info = BlockInfos[EntryPC];
      if (Info.ResolvedEntryStackDepth < 0) {
        continue;
      }

      int32_t ExitDepth = Info.ResolvedEntryStackDepth + Info.StackHeightDiff;
      Info.ResolvedExitStackDepth = ExitDepth;

      for (uint64_t Succ : Info.Successors) {
        auto SuccIt = BlockInfos.find(Succ);
        if (SuccIt == BlockInfos.end()) {
          continue;
        }
        auto &SuccInfo = SuccIt->second;
        if (SuccInfo.HasInconsistentEntryDepth) {
          continue;
        }
        if (SuccInfo.ResolvedEntryStackDepth < 0) {
          SuccInfo.ResolvedEntryStackDepth = ExitDepth;
          WorkList.push(Succ);
        } else if (SuccInfo.ResolvedEntryStackDepth != ExitDepth) {
          invalidateReachableEntryDepths(Succ);
        }
      }
    }
  }

  std::vector<uint64_t> collectReachableDynamicJumpRegions() const {
    std::vector<uint64_t> Regions;
    for (const auto &[EntryPC, Info] : BlockInfos) {
      (void)EntryPC;
      if (!Info.HasDynamicJump || Info.ResolvedEntryStackDepth < 0 ||
          Info.DynamicJumpTargetRegionEntryPC == 0) {
        continue;
      }
      if (std::find(Regions.begin(), Regions.end(),
                    Info.DynamicJumpTargetRegionEntryPC) == Regions.end()) {
        Regions.push_back(Info.DynamicJumpTargetRegionEntryPC);
      }
    }
    return Regions;
  }

  static bool hasDynamicJumpRegion(const BlockInfo &Info,
                                   uint64_t RegionEntryPC) {
    return std::find(Info.DynamicJumpTargetRegions.begin(),
                     Info.DynamicJumpTargetRegions.end(),
                     RegionEntryPC) != Info.DynamicJumpTargetRegions.end();
  }

  static void addDynamicJumpRegion(BlockInfo &Info, uint64_t RegionEntryPC) {
    if (!hasDynamicJumpRegion(Info, RegionEntryPC)) {
      Info.DynamicJumpTargetRegions.push_back(RegionEntryPC);
    }
  }

  static void appendUniqueBlockPC(std::vector<uint64_t> &BlockPCs,
                                  uint64_t BlockPC) {
    if (std::find(BlockPCs.begin(), BlockPCs.end(), BlockPC) ==
        BlockPCs.end()) {
      BlockPCs.push_back(BlockPC);
    }
  }

  std::vector<uint64_t>
  collectDynamicJumpSourceBlocksForInfo(const BlockInfo &Info) const {
    std::vector<uint64_t> SourceBlockPCs;
    if (Info.HasCompatibleDynamicJumpTargetShape) {
      for (const auto &[EntryPC, RegionSourceInfo] : BlockInfos) {
        if (!RegionSourceInfo.HasDynamicJump ||
            RegionSourceInfo.ResolvedEntryStackDepth < 0) {
          continue;
        }
        if (blocksShareCompatibleDynamicJumpShapeClass(EntryPC, Info.EntryPC)) {
          appendUniqueBlockPC(SourceBlockPCs, EntryPC);
        }
      }
      return SourceBlockPCs;
    }

    if (Info.DynamicJumpTargetRegions.empty()) {
      if (!HasUnknownDynamicJump || !Info.IsDynamicJumpTargetCandidate) {
        return SourceBlockPCs;
      }
      for (const auto &[EntryPC, RegionSourceInfo] : BlockInfos) {
        if (!RegionSourceInfo.HasDynamicJump ||
            RegionSourceInfo.ResolvedEntryStackDepth < 0) {
          continue;
        }
        appendUniqueBlockPC(SourceBlockPCs, EntryPC);
      }
      return SourceBlockPCs;
    }

    for (uint64_t RegionEntryPC : Info.DynamicJumpTargetRegions) {
      for (const auto &[EntryPC, RegionSourceInfo] : BlockInfos) {
        if (!RegionSourceInfo.HasDynamicJump ||
            RegionSourceInfo.DynamicJumpTargetRegionEntryPC != RegionEntryPC) {
          continue;
        }
        appendUniqueBlockPC(SourceBlockPCs, EntryPC);
      }
    }
    return SourceBlockPCs;
  }

  // Codegen's indirect-jump dispatch wires an edge from every block that emits
  // a dynamic (computed) JUMP/JUMPI to every JUMPDEST in the global jump-dest
  // table (see implementIndirectJump / getOrCreateIndirectJumpBB). The set of
  // such dispatch source blocks is therefore independent of the analyzer's
  // shape-class partitioning. Enumerate it so the lifter can size phis to match
  // the edges codegen actually wires.
  std::vector<uint64_t> collectAllDynamicJumpDispatchSourceBlocks() const {
    std::vector<uint64_t> SourceBlockPCs;
    for (const auto &[EntryPC, Info] : BlockInfos) {
      // Codegen emits the indirect-jump dispatch for every block whose JUMP /
      // JUMPI target is non-constant (Info.HasDynamicJump), independent of
      // whether the analyzer could resolve that block's entry stack depth. The
      // depth filter used elsewhere would drop sources codegen still wires, so
      // it must not be applied here.
      if (!Info.HasDynamicJump) {
        continue;
      }
      appendUniqueBlockPC(SourceBlockPCs, EntryPC);
    }
    return SourceBlockPCs;
  }

  // A dynamic-jump-target block is only safe to lift when the static
  // predecessor enumeration that sizes its merge phis
  // (getPotentialEntryPredecessorsForBlock) already accounts for every
  // dynamic-jump dispatch source codegen will wire. Otherwise the phi is
  // undersized relative to the block's actual MIR predecessor count and the
  // verifier/regalloc path breaks.
  // DispatchSources is the codegen dispatch-source set, computed once by the
  // caller (collectAllDynamicJumpDispatchSourceBlocks) and reused across blocks
  // to avoid rescanning all BlockInfos per block.
  bool dynamicJumpTargetPredecessorsCoverCodegenEdges(
      uint64_t BlockPC, const std::vector<uint64_t> &DispatchSources) const {
    auto It = BlockInfos.find(BlockPC);
    if (It == BlockInfos.end() || !It->second.IsDynamicJumpTargetCandidate) {
      return true;
    }

    const std::vector<uint64_t> EnumeratedSources =
        collectDynamicJumpSourceBlocksForInfo(It->second);
    const std::unordered_set<uint64_t> EnumeratedSet(EnumeratedSources.begin(),
                                                     EnumeratedSources.end());
    for (uint64_t DispatchSourcePC : DispatchSources) {
      if (EnumeratedSet.find(DispatchSourcePC) == EnumeratedSet.end()) {
        return false;
      }
    }
    return true;
  }

  bool getUniformDynamicJumpEntryDepthForRegion(uint64_t RegionEntryPC,
                                                int32_t &EntryDepth) const {
    bool SawDynamicJump = false;
    for (const auto &[EntryPC, Info] : BlockInfos) {
      (void)EntryPC;
      if (!Info.HasDynamicJump ||
          Info.DynamicJumpTargetRegionEntryPC != RegionEntryPC) {
        continue;
      }
      if (Info.ResolvedEntryStackDepth < 0) {
        continue;
      }
      if (Info.ResolvedExitStackDepth < 0) {
        return false;
      }
      if (!SawDynamicJump) {
        EntryDepth = Info.ResolvedExitStackDepth;
        SawDynamicJump = true;
        continue;
      }
      if (EntryDepth != Info.ResolvedExitStackDepth) {
        return false;
      }
    }
    return SawDynamicJump;
  }

  void markDynamicJumpTargetCandidates() {
    for (auto &[EntryPC, Info] : BlockInfos) {
      (void)EntryPC;
      Info.IsDynamicJumpTargetCandidate = false;
      Info.HasCompatibleDynamicJumpTargetShape = false;
      Info.DynamicJumpTargetRegions.clear();
    }

    if (!HasUnknownDynamicJump) {
      return;
    }

    const std::vector<uint64_t> Regions = collectReachableDynamicJumpRegions();
    if (Regions.empty()) {
      for (auto &[EntryPC, Info] : BlockInfos) {
        (void)EntryPC;
        if (Info.IsJumpDest) {
          Info.IsDynamicJumpTargetCandidate = true;
        }
      }
      return;
    }

    for (uint64_t RegionEntryPC : Regions) {
      std::queue<uint64_t> WorkList;
      std::map<uint64_t, bool> Visited;
      Visited[RegionEntryPC] = true;
      WorkList.push(RegionEntryPC);

      while (!WorkList.empty()) {
        uint64_t BlockPC = WorkList.front();
        WorkList.pop();
        auto It = BlockInfos.find(BlockPC);
        if (It == BlockInfos.end()) {
          continue;
        }
        auto &Info = It->second;
        if (Info.IsJumpDest) {
          Info.IsDynamicJumpTargetCandidate = true;
          addDynamicJumpRegion(Info, RegionEntryPC);
        }
        for (uint64_t SuccPC : Info.Successors) {
          if (Visited.emplace(SuccPC, true).second) {
            WorkList.push(SuccPC);
          }
        }
      }
    }

    // The runtime indirect-jump lowering validates against the full
    // JUMPDEST table, not just blocks reachable from the analyzer's
    // fallthrough region approximation. Any remaining JUMPDEST must therefore
    // stay on the conservative dynamic-target path.
    for (auto &[EntryPC, Info] : BlockInfos) {
      (void)EntryPC;
      if (Info.IsJumpDest && !Info.IsDynamicJumpTargetCandidate) {
        Info.IsDynamicJumpTargetCandidate = true;
      }
    }
  }

  struct DynamicJumpTargetShape {
    int32_t FullEntryStateDepth = -1;
    int32_t HiddenLiveInPrefixDepth = 0;
    bool RequiresEntryMergeState = false;

    bool operator==(const DynamicJumpTargetShape &Other) const {
      return FullEntryStateDepth == Other.FullEntryStateDepth &&
             HiddenLiveInPrefixDepth == Other.HiddenLiveInPrefixDepth &&
             RequiresEntryMergeState == Other.RequiresEntryMergeState;
    }
  };

  struct DynamicJumpShapeClassKey {
    int32_t FullEntryStateDepth = -1;
    int32_t HiddenLiveInPrefixDepth = 0;
    bool RequiresEntryMergeState = false;

    bool operator<(const DynamicJumpShapeClassKey &Other) const {
      if (FullEntryStateDepth != Other.FullEntryStateDepth) {
        return FullEntryStateDepth < Other.FullEntryStateDepth;
      }
      if (HiddenLiveInPrefixDepth != Other.HiddenLiveInPrefixDepth) {
        return HiddenLiveInPrefixDepth < Other.HiddenLiveInPrefixDepth;
      }
      return RequiresEntryMergeState < Other.RequiresEntryMergeState;
    }
  };

  void resolveDynamicJumpTargetEntryDepths() {
    if (!HasUnknownDynamicJump) {
      return;
    }

    for (uint64_t RegionEntryPC : collectReachableDynamicJumpRegions()) {
      int32_t DynamicJumpEntryDepth = -1;
      if (!getUniformDynamicJumpEntryDepthForRegion(RegionEntryPC,
                                                    DynamicJumpEntryDepth)) {
        continue;
      }

      std::queue<uint64_t> WorkList;
      for (auto &[EntryPC, Info] : BlockInfos) {
        (void)EntryPC;
        if (!hasDynamicJumpRegion(Info, RegionEntryPC) ||
            Info.HasInconsistentEntryDepth) {
          continue;
        }
        if (Info.ResolvedEntryStackDepth < 0) {
          Info.ResolvedEntryStackDepth = DynamicJumpEntryDepth;
          WorkList.push(Info.EntryPC);
          continue;
        }
        if (Info.ResolvedEntryStackDepth != DynamicJumpEntryDepth) {
          invalidateReachableEntryDepths(Info.EntryPC);
        }
      }

      propagateEntryDepths(WorkList);
    }
  }

  bool hasCompatibleDynamicJumpTargetsForRegion(uint64_t RegionEntryPC) const {
    int32_t DynamicJumpEntryDepth = -1;
    if (!getUniformDynamicJumpEntryDepthForRegion(RegionEntryPC,
                                                  DynamicJumpEntryDepth)) {
      return false;
    }
    DynamicJumpTargetShape ExpectedShape;
    bool SawJumpDest = false;
    for (const auto &[EntryPC, Info] : BlockInfos) {
      (void)EntryPC;
      if (!hasDynamicJumpRegion(Info, RegionEntryPC)) {
        continue;
      }
      if (!Info.IsEntryStateCompatible) {
        return false;
      }
      if (Info.FullEntryStateDepth != DynamicJumpEntryDepth) {
        return false;
      }

      DynamicJumpTargetShape CurrentShape = {
          Info.FullEntryStateDepth,
          Info.HiddenLiveInPrefixDepth,
          Info.RequiresEntryMergeState,
      };
      if (!SawJumpDest) {
        ExpectedShape = CurrentShape;
        SawJumpDest = true;
        continue;
      }
      if (!(ExpectedShape == CurrentShape)) {
        return false;
      }
    }
    return SawJumpDest;
  }

  bool hasGloballyIncompatibleDynamicJumpSource(uint64_t TargetBlockPC) const {
    auto It = BlockInfos.find(TargetBlockPC);
    if (It == BlockInfos.end() || !It->second.IsDynamicJumpTargetCandidate ||
        !It->second.HasCompatibleDynamicJumpTargetShape) {
      return false;
    }

    const std::vector<uint64_t> TargetRegions =
        It->second.DynamicJumpTargetRegions;
    for (const auto &[EntryPC, Info] : BlockInfos) {
      if (!Info.HasDynamicJump || Info.ResolvedEntryStackDepth < 0 ||
          Info.DynamicJumpTargetRegionEntryPC == 0) {
        continue;
      }
      if (!TargetRegions.empty() &&
          std::find(TargetRegions.begin(), TargetRegions.end(),
                    Info.DynamicJumpTargetRegionEntryPC) ==
              TargetRegions.end()) {
        continue;
      }
      if (!blocksShareCompatibleDynamicJumpShapeClass(EntryPC, TargetBlockPC)) {
        return true;
      }
    }
    return false;
  }

  bool hasNonLiftableDynamicJumpSource(uint64_t TargetBlockPC) const {
    for (uint64_t SourceBlockPC :
         getDynamicJumpSourceBlocksForBlock(TargetBlockPC)) {
      auto SourceIt = BlockInfos.find(SourceBlockPC);
      if (SourceIt == BlockInfos.end()) {
        return true;
      }
      const auto &SourceInfo = SourceIt->second;
      const bool SourceEntryKnown = SourceInfo.IsEntryStateCompatible &&
                                    !SourceInfo.HasInconsistentEntryDepth;
      if (!SourceEntryKnown || SourceInfo.HasUndefinedInstr) {
        return true;
      }
    }
    return false;
  }

  void finalizeLiftability() {
    // Computed once and reused across blocks; independent of the per-block
    // loop.
    const std::vector<uint64_t> DispatchSources =
        collectAllDynamicJumpDispatchSourceBlocks();
    for (auto &[EntryPC, Info] : BlockInfos) {
      (void)EntryPC;
      bool EntryKnown = Info.IsEntryStateCompatible;
      bool DynamicJumpDestConflict = HasUnknownDynamicJump &&
                                     Info.IsDynamicJumpTargetCandidate &&
                                     !Info.HasCompatibleDynamicJumpTargetShape;
      bool NonLiftableDynamicSource = HasUnknownDynamicJump &&
                                      Info.IsDynamicJumpTargetCandidate &&
                                      hasNonLiftableDynamicJumpSource(EntryPC);
      Info.CanLiftStack = EntryKnown && !Info.HasUndefinedInstr &&
                          !Info.HasInconsistentEntryDepth &&
                          !DynamicJumpDestConflict && !NonLiftableDynamicSource;
      if (Info.CanLiftStack && Info.IsDynamicJumpTargetCandidate &&
          Info.HasDeferredEntryMerge && Info.HiddenLiveInPrefixDepth > 0 &&
          getDynamicJumpSourceBlocksForBlock(EntryPC).empty()) {
        Info.CanLiftStack = false;
      }
      if (Info.CanLiftStack && Info.IsDynamicJumpTargetCandidate &&
          Info.HasDeferredEntryMerge &&
          getDynamicJumpSourceBlocksForBlock(EntryPC).size() > 1 &&
          getPotentialEntryPredecessorsForBlock(EntryPC).size() > 4) {
        Info.CanLiftStack = false;
      }
      // Never lift a dynamic-jump-target block whose statically enumerated
      // predecessor set (which sizes its stack-merge phis) cannot account for
      // every dynamic-jump dispatch edge codegen wires. The shape-class source
      // enumeration is a strict subset of codegen's "all JUMPDESTs reachable
      // from every dynamic jump" wiring, so such a block's phi would be
      // undersized relative to its actual MIR predecessor count.
      if (Info.CanLiftStack && !dynamicJumpTargetPredecessorsCoverCodegenEdges(
                                   EntryPC, DispatchSources)) {
        Info.CanLiftStack = false;
      }
    }
  }

  void finalizeEntryShapeMetadata() {
    for (auto &[EntryPC, Info] : BlockInfos) {
      (void)EntryPC;
      Info.FullEntryStateDepth = Info.ResolvedEntryStackDepth;
      Info.IsEntryStateCompatible =
          Info.ResolvedEntryStackDepth >= 0 && !Info.HasInconsistentEntryDepth;
      Info.HiddenLiveInPrefixDepth = 0;
      Info.HasHiddenLiveInPrefix = false;
      if (Info.IsEntryStateCompatible &&
          Info.ResolvedEntryStackDepth > Info.EntryStackDepth) {
        Info.HiddenLiveInPrefixDepth =
            Info.ResolvedEntryStackDepth - Info.EntryStackDepth;
        Info.HasHiddenLiveInPrefix = Info.HiddenLiveInPrefixDepth > 0;
      }
      Info.RequiresEntryMergeState =
          Info.IsEntryStateCompatible &&
          getPotentialEntryPredecessorsForBlock(EntryPC).size() > 1;
      Info.HasDeferredEntryMerge = false;
    }

    std::map<uint64_t, bool> CompatibleDynamicJumpRegions;
    for (uint64_t RegionEntryPC : collectReachableDynamicJumpRegions()) {
      CompatibleDynamicJumpRegions[RegionEntryPC] =
          hasCompatibleDynamicJumpTargetsForRegion(RegionEntryPC);
    }

    finalizeDynamicJumpRegionMetadata(CompatibleDynamicJumpRegions);

    for (auto &[EntryPC, Info] : BlockInfos) {
      (void)EntryPC;
      bool AllCompatibleRegions = Info.IsDynamicJumpTargetCandidate;
      for (uint64_t RegionEntryPC : Info.DynamicJumpTargetRegions) {
        auto It = CompatibleDynamicJumpRegions.find(RegionEntryPC);
        if (It == CompatibleDynamicJumpRegions.end() || !It->second) {
          AllCompatibleRegions = false;
          break;
        }
      }
      Info.HasCompatibleDynamicJumpTargetShape = AllCompatibleRegions;
      if (Info.HasCompatibleDynamicJumpTargetShape &&
          hasGloballyIncompatibleDynamicJumpSource(EntryPC)) {
        Info.HasCompatibleDynamicJumpTargetShape = false;
      }
      Info.HasDeferredEntryMerge = Info.HasCompatibleDynamicJumpTargetShape;
    }
  }

  void finalizeDynamicJumpRegionMetadata(
      const std::map<uint64_t, bool> &CompatibleDynamicJumpRegions) {
    DynamicJumpRegions.clear();

    std::map<DynamicJumpShapeClassKey, uint32_t> ShapeClassIds;
    uint32_t NextShapeClassId = 1;

    for (uint64_t RegionEntryPC : collectReachableDynamicJumpRegions()) {
      auto &RegionInfo = DynamicJumpRegions[RegionEntryPC];
      RegionInfo.RegionEntryPC = RegionEntryPC;
      RegionInfo.HasCompatibleTargetShape =
          CompatibleDynamicJumpRegions.count(RegionEntryPC) != 0 &&
          CompatibleDynamicJumpRegions.at(RegionEntryPC);
      RegionInfo.HasUniformEntryDepth =
          getUniformDynamicJumpEntryDepthForRegion(
              RegionEntryPC, RegionInfo.UniformEntryDepth);

      for (const auto &[EntryPC, Info] : BlockInfos) {
        if (Info.HasDynamicJump &&
            Info.DynamicJumpTargetRegionEntryPC == RegionEntryPC) {
          RegionInfo.SourceBlocks.push_back(EntryPC);
        }
        if (!hasDynamicJumpRegion(Info, RegionEntryPC)) {
          continue;
        }
        RegionInfo.TargetBlocks.push_back(EntryPC);
        if (!RegionInfo.HasCompatibleTargetShape) {
          continue;
        }
        RegionInfo.FullEntryStateDepth = Info.FullEntryStateDepth;
        RegionInfo.HiddenLiveInPrefixDepth = Info.HiddenLiveInPrefixDepth;
        RegionInfo.RequiresEntryMergeState = Info.RequiresEntryMergeState;
      }

      if (!RegionInfo.HasCompatibleTargetShape) {
        continue;
      }

      DynamicJumpShapeClassKey ShapeKey = {
          RegionInfo.FullEntryStateDepth,
          RegionInfo.HiddenLiveInPrefixDepth,
          RegionInfo.RequiresEntryMergeState,
      };
      auto [It, Inserted] = ShapeClassIds.emplace(ShapeKey, NextShapeClassId);
      if (Inserted) {
        ++NextShapeClassId;
      }
      RegionInfo.ShapeClassId = It->second;
    }
  }

  // ============== EVMRangeAnalyzer ==========================================
  //
  // Forward dataflow analysis over the lattice { U64, U128, U256 } for each
  // EVM stack slot at every block entry.  Bottom is U64, top is U256, and the
  // meet operator is `max` (widen to the more pessimistic value).  At fixed
  // point, each block's `EntryStackRanges` is sized to its
  // `ResolvedEntryStackDepth`, with index 0 the bottom of the entry stack and
  // the last index the top.  Empty when entry depth is unresolved.

  static EVMValueRange meetRange(EVMValueRange A, EVMValueRange B) {
    return A > B ? A : B;
  }

  static EVMValueRange widenRange(EVMValueRange R) {
    switch (R) {
    case EVMValueRange::U64:
      return EVMValueRange::U128;
    case EVMValueRange::U128:
    case EVMValueRange::U256:
    default:
      return EVMValueRange::U256;
    }
  }

  // Magnitude-only signed div/mod range. If a sign-known sub-lattice is added
  // later (see PR #493 docs/changes README "Non-Goals"), THIS is the helper
  // to replace -- it isolates the "signed reasoning lives in a single place"
  // property.
  static EVMValueRange signedDivModRange(EVMValueRange Dividend,
                                         EVMValueRange Divisor) {
    // If either operand is U256, it may be negative (bit 255 set), so the
    // signed result can be negative U256 (all high limbs set). Otherwise
    // both are non-negative (bit 255 == 0), the operation degenerates to
    // unsigned, and |result| <= |Dividend|, so the result fits in Dividend's
    // range.
    if (Dividend == EVMValueRange::U256 || Divisor == EVMValueRange::U256) {
      return EVMValueRange::U256;
    }
    return Dividend;
  }

  // Classify a PUSH literal of `Size` bytes starting at byte `Start` in
  // `Bytecode`.  Defensive against truncated tail.
  static EVMValueRange rangeFromPushLiteral(const uint8_t *Bytecode,
                                            size_t BytecodeSize, size_t Start,
                                            size_t Size) {
    if (Size == 0) {
      return EVMValueRange::U64;
    }
    const size_t Available = Start < BytecodeSize ? (BytecodeSize - Start) : 0;
    const size_t ReadCount = std::min(Size, Available);
    auto readPushByte = [&](size_t Index) -> uint8_t {
      if (Index >= ReadCount) {
        return 0;
      }
      return Bytecode[Start + Index];
    };

    // Bytes are big-endian.  Inspect prefix to bound magnitude.
    if (Size > 16) {
      for (size_t I = 0; I < Size - 16; ++I) {
        if (readPushByte(I) != 0) {
          return EVMValueRange::U256;
        }
      }
    }
    if (Size > 8) {
      const size_t U128PrefixEnd = Size > 16 ? Size - 16 : 0;
      const size_t U64PrefixEnd = Size - 8;
      for (size_t I = U128PrefixEnd; I < U64PrefixEnd; ++I) {
        if (readPushByte(I) != 0) {
          return EVMValueRange::U128;
        }
      }
    }
    return EVMValueRange::U64;
  }

  // Pop `Count` entries from `Stack`, padding with U256 if the stack is
  // shallower than expected (under-approximated entry stack should never
  // happen after `resolveEntryDepths` succeeded, but guard defensively).
  static void popStackRanges(std::vector<EVMValueRange> &Stack, size_t Count) {
    while (Count > 0 && !Stack.empty()) {
      Stack.pop_back();
      --Count;
    }
  }

  // Compute the exit-stack Range vector for a block by linearly scanning its
  // body bytes and applying per-opcode transfer rules.  `Stack` starts as the
  // block's entry-stack vector and is mutated in place.
  void applyRangeTransferForBlock(const BlockInfo &Info,
                                  const uint8_t *Bytecode, size_t BytecodeSize,
                                  std::vector<EVMValueRange> &Stack) const {
    size_t PC = Info.BodyStartPC;
    const size_t EndPC = std::min<size_t>(Info.BodyEndPC, BytecodeSize);

    auto pushTop = [&]() { Stack.push_back(EVMValueRange::U256); };
    auto pushU64 = [&]() { Stack.push_back(EVMValueRange::U64); };
    auto top = [&](size_t IndexFromTop) -> EVMValueRange {
      if (Stack.size() <= IndexFromTop) {
        return EVMValueRange::U256;
      }
      return Stack[Stack.size() - 1 - IndexFromTop];
    };

    while (PC < EndPC) {
      const uint8_t OpcodeU8 = Bytecode[PC];
      const evmc_opcode Opcode = static_cast<evmc_opcode>(OpcodeU8);

      // Undefined opcodes terminate range analysis for this block; the
      // analyzer already marked HasUndefinedInstr and stopped scanning here.
      if (InstructionNames[Opcode] == nullptr) {
        return;
      }

      // PUSH N: parse literal magnitude.
      if (Opcode >= OP_PUSH0 && Opcode <= OP_PUSH32) {
        const size_t Size =
            static_cast<size_t>(Opcode) - static_cast<size_t>(OP_PUSH0);
        Stack.push_back(
            rangeFromPushLiteral(Bytecode, BytecodeSize, PC + 1, Size));
        PC += 1 + Size;
        continue;
      }

      // DUP_N: duplicate slot N from the top.
      if (Opcode >= OP_DUP1 && Opcode <= OP_DUP16) {
        const size_t N = static_cast<size_t>(Opcode - OP_DUP1 + 1);
        Stack.push_back(top(N - 1));
        ++PC;
        continue;
      }

      // SWAP_N: swap top with slot N below the top.
      if (Opcode >= OP_SWAP1 && Opcode <= OP_SWAP16) {
        const size_t N = static_cast<size_t>(Opcode - OP_SWAP1 + 1);
        if (Stack.size() > N) {
          std::swap(Stack.back(), Stack[Stack.size() - 1 - N]);
        }
        ++PC;
        continue;
      }

      // LOG_N: pops 2 + N, pushes nothing.
      if (Opcode >= OP_LOG0 && Opcode <= OP_LOG4) {
        const size_t N = static_cast<size_t>(Opcode - OP_LOG0);
        popStackRanges(Stack, 2 + N);
        ++PC;
        continue;
      }

      switch (Opcode) {
      // No-effect on Range: pure pops or block-terminators handled below.
      case OP_POP:
        popStackRanges(Stack, 1);
        break;

      // Bitwise.
      case OP_AND: {
        EVMValueRange A = top(0);
        EVMValueRange B = top(1);
        popStackRanges(Stack, 2);
        EVMValueRange R = (A == EVMValueRange::U64 || B == EVMValueRange::U64)
                              ? EVMValueRange::U64
                              : (A < B ? A : B);
        Stack.push_back(R);
        break;
      }
      case OP_OR:
      case OP_XOR: {
        EVMValueRange A = top(0);
        EVMValueRange B = top(1);
        popStackRanges(Stack, 2);
        Stack.push_back(meetRange(A, B));
        break;
      }
      case OP_NOT:
        popStackRanges(Stack, 1);
        pushTop();
        break;

      // Arithmetic.
      case OP_ADD: {
        EVMValueRange A = top(0);
        EVMValueRange B = top(1);
        popStackRanges(Stack, 2);
        Stack.push_back(widenRange(meetRange(A, B)));
        break;
      }
      case OP_MUL: {
        EVMValueRange A = top(0);
        EVMValueRange B = top(1);
        popStackRanges(Stack, 2);
        Stack.push_back(widenRange(meetRange(A, B)));
        break;
      }
      case OP_SUB:
        popStackRanges(Stack, 2);
        pushTop();
        break;
      case OP_DIV:
      case OP_MOD: {
        // Unsigned: result <= dividend (top of stack before pop).
        EVMValueRange Dividend = top(0);
        popStackRanges(Stack, 2);
        Stack.push_back(Dividend);
        break;
      }
      case OP_SDIV:
      case OP_SMOD: {
        // Signed: see signedDivModRange comment for soundness.
        EVMValueRange Dividend = top(0);
        EVMValueRange Divisor = top(1);
        popStackRanges(Stack, 2);
        Stack.push_back(signedDivModRange(Dividend, Divisor));
        break;
      }
      case OP_ADDMOD:
      case OP_MULMOD: {
        // Result < modulus (third operand).  Ranges over the modulus.
        EVMValueRange Modulus = top(2);
        popStackRanges(Stack, 3);
        Stack.push_back(Modulus);
        break;
      }
      case OP_EXP:
      case OP_SIGNEXTEND:
        popStackRanges(Stack, 2);
        pushTop();
        break;

      // Comparison / boolean — always 0 or 1.
      case OP_LT:
      case OP_GT:
      case OP_SLT:
      case OP_SGT:
      case OP_EQ:
        popStackRanges(Stack, 2);
        pushU64();
        break;
      case OP_ISZERO:
        popStackRanges(Stack, 1);
        pushU64();
        break;

      // Byte / shift / clz.
      case OP_BYTE:
        popStackRanges(Stack, 2);
        pushU64();
        break;
      case OP_SHL:
        popStackRanges(Stack, 2);
        pushTop();
        break;
      case OP_SHR:
      case OP_SAR: {
        // Pops shift count (top), then value; result <= value's range.
        EVMValueRange Value = top(1);
        popStackRanges(Stack, 2);
        Stack.push_back(Value);
        break;
      }
      case OP_CLZ:
        popStackRanges(Stack, 1);
        pushU64();
        break;

      // Hash and loads.
      case OP_KECCAK256:
        popStackRanges(Stack, 2);
        pushTop();
        break;
      case OP_MLOAD:
      case OP_SLOAD:
      case OP_TLOAD:
      case OP_CALLDATALOAD:
        popStackRanges(Stack, 1);
        pushTop();
        break;

      // Account / context — U256 (addresses are 160-bit but treat as U256).
      case OP_ADDRESS:
      case OP_ORIGIN:
      case OP_CALLER:
      case OP_COINBASE:
      case OP_SELFBALANCE:
      case OP_CALLVALUE:
      case OP_GASPRICE:
        pushTop();
        break;
      case OP_BALANCE:
      case OP_EXTCODEHASH:
        popStackRanges(Stack, 1);
        pushTop();
        break;
      case OP_BLOCKHASH:
      case OP_BLOBHASH:
        popStackRanges(Stack, 1);
        pushTop();
        break;

      // Bounded context — U64.
      case OP_CALLDATASIZE:
      case OP_CODESIZE:
      case OP_RETURNDATASIZE:
      case OP_PC:
      case OP_MSIZE:
      case OP_GAS:
        pushU64();
        break;
      // Host-context opcodes returning full U256 values (EVMC declares
      // GetTimestamp/GetNumber/GetGasLimit as `U256Fn`, GetChainId as
      // `Bytes32Fn`, BaseFee/BlobBaseFee/PrevRandao as `U256Fn`).  Classify
      // conservatively as U256 to keep the u64 fast-path admission invariant
      // sound.
      case OP_TIMESTAMP:
      case OP_NUMBER:
      case OP_GASLIMIT:
      case OP_CHAINID:
      case OP_BASEFEE:
      case OP_BLOBBASEFEE:
      case OP_PREVRANDAO:
        pushTop();
        break;
      case OP_EXTCODESIZE:
        popStackRanges(Stack, 1);
        pushU64();
        break;

      // Memory / storage stores: pop only.
      case OP_MSTORE:
      case OP_MSTORE8:
      case OP_SSTORE:
      case OP_TSTORE:
        popStackRanges(Stack, 2);
        break;
      case OP_CALLDATACOPY:
      case OP_CODECOPY:
      case OP_RETURNDATACOPY:
      case OP_MCOPY:
        popStackRanges(Stack, 3);
        break;
      case OP_EXTCODECOPY:
        popStackRanges(Stack, 4);
        break;

      // Calls / creates: result is success boolean (0 or 1) → U64.
      case OP_CALL:
      case OP_CALLCODE:
        popStackRanges(Stack, 7);
        pushU64();
        break;
      case OP_DELEGATECALL:
      case OP_STATICCALL:
        popStackRanges(Stack, 6);
        pushU64();
        break;
      case OP_CREATE:
        // Pushes the created contract address (20 bytes / 160 bits) or 0
        // on failure -- not a 0/1 success bool.  An address can hold any
        // 20-byte pattern; classify conservatively as U256.
        popStackRanges(Stack, 3);
        pushTop();
        break;
      case OP_CREATE2:
        popStackRanges(Stack, 4);
        pushTop();
        break;

      // Block-boundary / terminators.
      case OP_JUMP:
        popStackRanges(Stack, 1);
        return;
      case OP_JUMPI:
        popStackRanges(Stack, 2);
        // Fallthrough block continues; exit state is current Stack.
        return;
      case OP_STOP:
      case OP_RETURN:
      case OP_REVERT:
      case OP_SELFDESTRUCT:
      case OP_INVALID:
        return;
      case OP_JUMPDEST:
        // Should never be encountered inside a body — block scan stops
        // before the next JUMPDEST.  Treat as no-op.
        break;

      default: {
        // Fallback for any opcode without an explicit rule above: use the
        // metrics table to determine pop/push count and push U256 results.
        // Constructor guarantees InstructionMetrics is non-null (falls back
        // to DEFAULT_REVISION on lookup failure).
        const auto &Metrics = InstructionMetrics[Opcode];
        int PopCount = Metrics.stack_height_required;
        int PushCount = PopCount + Metrics.stack_height_change;
        if (PopCount > 0) {
          popStackRanges(Stack, static_cast<size_t>(PopCount));
        }
        for (int I = 0; I < PushCount; ++I) {
          pushTop();
        }
        break;
      }
      }

      ++PC;
    }
  }

  // Initialize per-block entry vectors.  Function-entry block starts empty,
  // dynamic-jump-target candidates start at top (U256) for soundness, and
  // every other block starts at bottom (U64).
  void seedRangeEntryVectors() {
    for (auto &[EntryPC, Info] : BlockInfos) {
      (void)EntryPC;
      Info.EntryStackRanges.clear();
      if (Info.ResolvedEntryStackDepth < 0 || Info.HasInconsistentEntryDepth) {
        continue;
      }
      const size_t Depth = static_cast<size_t>(Info.ResolvedEntryStackDepth);
      if (EntryPC == EntryBlockPC) {
        // Function entry: stack is empty.  Depth is 0 unless live-in prefix
        // analysis raised it; in that case treat unknowns as U256.
        Info.EntryStackRanges.assign(Depth, EVMValueRange::U256);
        continue;
      }
      const EVMValueRange Init =
          Info.IsDynamicJumpTargetCandidate
              ? EVMValueRange::U256 // top — sound for unenumerated dyn-jump
              : EVMValueRange::U64; // bottom — will widen via meet
      Info.EntryStackRanges.assign(Depth, Init);
    }
  }

  // CFG worklist propagation. Compute each block's exit state from its entry
  // state via the per-opcode transfer function, then meet into every static
  // successor's entry state.  A successor whose entry vector changed is
  // requeued.  Convergence: lattice height is 3, so each slot can change at
  // most twice.
  void runRangeAnalysis(const uint8_t *Bytecode, size_t BytecodeSize) {
    seedRangeEntryVectors();

    std::queue<uint64_t> WorkList;
    std::map<uint64_t, bool> InQueue;
    for (const auto &[EntryPC, Info] : BlockInfos) {
      (void)Info;
      WorkList.push(EntryPC);
      InQueue[EntryPC] = true;
    }

    // Reuse a single ExitStack buffer across worklist iterations to avoid
    // malloc/free per block visit on pathological CFGs.
    std::vector<EVMValueRange> ExitStack;
    while (!WorkList.empty()) {
      uint64_t BlockPC = WorkList.front();
      WorkList.pop();
      InQueue[BlockPC] = false;

      auto It = BlockInfos.find(BlockPC);
      if (It == BlockInfos.end()) {
        continue;
      }
      BlockInfo &Info = It->second;
      if (Info.ResolvedEntryStackDepth < 0 || Info.HasInconsistentEntryDepth ||
          Info.HasUndefinedInstr) {
        continue;
      }

      ExitStack = Info.EntryStackRanges;
      applyRangeTransferForBlock(Info, Bytecode, BytecodeSize, ExitStack);

      for (uint64_t Succ : Info.Successors) {
        auto SuccIt = BlockInfos.find(Succ);
        if (SuccIt == BlockInfos.end()) {
          continue;
        }
        BlockInfo &SuccInfo = SuccIt->second;
        if (SuccInfo.ResolvedEntryStackDepth < 0 ||
            SuccInfo.HasInconsistentEntryDepth) {
          continue;
        }

        const size_t SuccDepth =
            static_cast<size_t>(SuccInfo.ResolvedEntryStackDepth);
        // seedRangeEntryVectors already sizes every block with
        // ResolvedEntryStackDepth >= 0 correctly; this branch is unreachable.
        ZEN_ASSERT(SuccInfo.EntryStackRanges.size() == SuccDepth);

        // Producer's exit depth and successor's entry depth are linked by
        // resolveEntryDepths and must match for every block pair reaching this
        // point (both have ResolvedEntryStackDepth >= 0 and consistent depth).
        ZEN_ASSERT(ExitStack.size() == SuccDepth);
        // Meet the producer's exit stack into the successor's entry stack.
        bool Changed = false;
        for (size_t I = 0; I < SuccDepth; ++I) {
          EVMValueRange Old = SuccInfo.EntryStackRanges[I];
          EVMValueRange New = meetRange(Old, ExitStack[I]);
          if (New != Old) {
            SuccInfo.EntryStackRanges[I] = New;
            Changed = true;
          }
        }
        if (Changed && !InQueue[Succ]) {
          WorkList.push(Succ);
          InQueue[Succ] = true;
        }
      }
    }
  }

  std::map<uint64_t, BlockInfo> BlockInfos;
  std::map<uint64_t, DynamicJumpRegionInfo> DynamicJumpRegions;
  std::map<uint64_t, uint64_t> JumpDestCanonicalPCs;
  uint64_t EntryBlockPC = 0;
  bool HasUnknownDynamicJump = false;
  evmc_revision Revision = zen::evm::DEFAULT_REVISION;
  const evmc_instruction_metrics *InstructionMetrics = nullptr;
  const char *const *InstructionNames = nullptr;
  JITSuitabilityResult JITResult;
  const std::unordered_map<uint32_t, uint32_t> *SharedResolvedJumpTargets =
      nullptr;
};

} // namespace COMPILER

#endif // EVM_FRONTEND_EVM_ANALYZER_H
