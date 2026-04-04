// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef EVM_FRONTEND_EVM_ANALYZER_H
#define EVM_FRONTEND_EVM_ANALYZER_H

#include "common/defines.h"
#include "evm/evm.h"
#include "evmc/evmc.h"
#include "evmc/instructions.h"

#include <algorithm>
#include <cstdint>
#include <map>
#include <queue>
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

/// Thresholds for JIT suitability fallback.  Normal contracts have <20
/// RA-expensive ops per block; these values are conservatively high.
static constexpr size_t MAX_JIT_BYTECODE_SIZE = 0x6000;
static constexpr size_t MAX_JIT_MIR_ESTIMATE = 50000;
static constexpr size_t MAX_CONSECUTIVE_RA_EXPENSIVE = 128;
static constexpr size_t MAX_BLOCK_RA_EXPENSIVE = 256;
static constexpr size_t MAX_DUP_FEEDBACK_PATTERN = 64;

class EVMAnalyzer {
  using Byte = zen::common::Byte;

public:
  EVMAnalyzer(evmc_revision Rev = zen::evm::DEFAULT_REVISION) : Revision(Rev) {}

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

  bool hasCanonicalJumpDest(uint64_t PC) const {
    return JumpDestCanonicalPCs.count(PC) != 0;
  }

  uint64_t getCanonicalJumpDestPC(uint64_t PC) const {
    auto It = JumpDestCanonicalPCs.find(PC);
    return It == JumpDestCanonicalPCs.end() ? PC : It->second;
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
    return true;
  }

private:
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
    const auto *InstructionMetrics =
        evmc_get_instruction_metrics_table(Revision);
    const auto *InstructionNames = evmc_get_instruction_names_table(Revision);
    if (!InstructionMetrics) {
      InstructionMetrics =
          evmc_get_instruction_metrics_table(zen::evm::DEFAULT_REVISION);
    }
    if (!InstructionNames) {
      InstructionNames =
          evmc_get_instruction_names_table(zen::evm::DEFAULT_REVISION);
    }

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
          Info.HasDynamicJump = true;
          HasUnknownDynamicJump = true;
          Info.DynamicJumpTargetRegionEntryPC = FallthroughEntryPC;
        }
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

  void finalizeLiftability() {
    for (auto &[EntryPC, Info] : BlockInfos) {
      (void)EntryPC;
      bool EntryKnown = Info.IsEntryStateCompatible;
      bool DynamicJumpDestConflict = HasUnknownDynamicJump &&
                                     Info.IsDynamicJumpTargetCandidate &&
                                     !Info.HasCompatibleDynamicJumpTargetShape;
      Info.CanLiftStack = EntryKnown && !Info.HasUndefinedInstr &&
                          !Info.HasInconsistentEntryDepth &&
                          !DynamicJumpDestConflict;
      if (Info.CanLiftStack && Info.IsDynamicJumpTargetCandidate &&
          Info.HasDeferredEntryMerge && Info.HiddenLiveInPrefixDepth > 0 &&
          getDynamicJumpSourceBlocksForBlock(EntryPC).empty()) {
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

  std::map<uint64_t, BlockInfo> BlockInfos;
  std::map<uint64_t, DynamicJumpRegionInfo> DynamicJumpRegions;
  std::map<uint64_t, uint64_t> JumpDestCanonicalPCs;
  uint64_t EntryBlockPC = 0;
  bool HasUnknownDynamicJump = false;
  evmc_revision Revision = zen::evm::DEFAULT_REVISION;
  JITSuitabilityResult JITResult;
};

} // namespace COMPILER

#endif // EVM_FRONTEND_EVM_ANALYZER_H
