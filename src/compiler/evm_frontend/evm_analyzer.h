// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef EVM_FRONTEND_EVM_ANALYZER_H
#define EVM_FRONTEND_EVM_ANALYZER_H

#include "compiler/common/common_defs.h"
#include "evm/evm.h"
#include "evmc/evmc.h"
#include "evmc/instructions.h"

#include <algorithm>

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
  using Bytes = zen::common::Bytes;

public:
  EVMAnalyzer(evmc_revision Rev = zen::evm::DEFAULT_REVISION) : Revision(Rev) {}

  struct BlockInfo {
    uint64_t EntryPC = 0;
    int32_t MaxStackHeight = 0;
    int32_t MinStackHeight = 0;
    int32_t MinPopHeight = 0;
    int32_t StackHeightDiff = 0;
    bool IsJumpDest = false;
    bool HasUndefinedInstr = false;
    uint32_t RAExpensiveCount = 0;

    BlockInfo() = default;
    BlockInfo(uint64_t PC) : EntryPC(PC) {}
  };

  const std::map<uint64_t, BlockInfo> &getBlockInfos() const {
    return BlockInfos;
  }

  /// Return the JIT suitability result computed during the last analyze() call.
  const JITSuitabilityResult &getJITSuitability() const { return JITResult; }

  bool analyze(const uint8_t *Bytecode, size_t BytecodeSize) {
    BlockInfos.clear();
    JITResult = JITSuitabilityResult();
    JITResult.BytecodeSize = BytecodeSize;

    const uint8_t *Ip = Bytecode;
    const uint8_t *IpEnd = Bytecode + BytecodeSize;

    // Get instruction tables based on revision
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

    // Initialize block info for the first block
    BlockInfo CurInfo(0);

    // JIT suitability tracking state
    size_t CurConsecutiveExpensive = 0;
    bool PrevWasDup = false;

    while (Ip < IpEnd) {
      evmc_opcode Opcode = static_cast<evmc_opcode>(*Ip);
      uint8_t OpcodeU8 = static_cast<uint8_t>(Opcode);
      ptrdiff_t Diff = Ip - Bytecode;
      PC = static_cast<uint64_t>(Diff >= 0 ? Diff : 0);

      Ip++;

      // --- JIT suitability: accumulate MIR estimate ---
      JITResult.MirEstimate += MIR_OPCODE_WEIGHT[OpcodeU8];

      // --- JIT suitability: RA-expensive pattern tracking ---
      if (isRAExpensiveOpcode(OpcodeU8)) {
        JITResult.RAExpensiveCount++;
        CurInfo.RAExpensiveCount++;
        CurConsecutiveExpensive++;
        // DUP feedback: previous opcode was DUP, now RA-expensive
        if (PrevWasDup) {
          JITResult.DupFeedbackPatternCount++;
        }
        PrevWasDup = false;
      } else if (isDupOrSwapOpcode(OpcodeU8)) {
        // DUP/SWAP are transparent — don't break consecutive run
        PrevWasDup = isDupOpcode(OpcodeU8);
      } else {
        // Any other opcode breaks the consecutive run
        JITResult.MaxConsecutiveExpensive = std::max(
            JITResult.MaxConsecutiveExpensive, CurConsecutiveExpensive);
        CurConsecutiveExpensive = 0;
        PrevWasDup = false;
      }

      // Check if opcode is undefined for current revision
      bool IsUndefined = (InstructionNames[Opcode] == nullptr);
      if (IsUndefined) {
        CurInfo.HasUndefinedInstr = true;
#ifdef ZEN_ENABLE_JIT_FALLBACK_TEST
        // Reset undefined instruction flag in fallback test
        CurInfo.HasUndefinedInstr = false;
#endif
      }

      // Get stack metrics from the instruction metrics table
      const auto &Metrics = InstructionMetrics[Opcode];
      // stack_height_required equals PopCount
      int PopCount = Metrics.stack_height_required;
      // PushCount = PopCount + stack_height_change
      int PushCount = PopCount + Metrics.stack_height_change;

      // Handle PUSH instructions - need to skip the immediate bytes
      if (Opcode >= OP_PUSH1 && Opcode <= OP_PUSH32) {
        uint8_t PushBytes = Opcode - OP_PUSH0;
        Ip += PushBytes;
      }

      // Update stack height
      CurInfo.StackHeightDiff -= PopCount;
      if (CurInfo.StackHeightDiff < CurInfo.MinStackHeight) {
        CurInfo.MinStackHeight = CurInfo.StackHeightDiff;
      }
      if (!(Opcode >= OP_SWAP1 && Opcode <= OP_SWAP16) &&
          !(Opcode >= OP_DUP1 && Opcode <= OP_DUP16)) {
        CurInfo.MinPopHeight =
            std::min(CurInfo.StackHeightDiff, CurInfo.MinPopHeight);
      }
      CurInfo.StackHeightDiff += PushCount;
      if (CurInfo.StackHeightDiff > CurInfo.MaxStackHeight) {
        CurInfo.MaxStackHeight = CurInfo.StackHeightDiff;
      }

      // Check if this is a block starting opcode
      bool IsBlockStart = (Opcode == OP_JUMPDEST || Opcode == OP_JUMPI);
      // Check if this is a block ending opcode
      bool IsBlockEnd = (Opcode == OP_JUMP || Opcode == OP_RETURN ||
                         Opcode == OP_STOP || Opcode == OP_INVALID ||
                         Opcode == OP_REVERT || Opcode == OP_SELFDESTRUCT);

      if (IsBlockStart) {
        if (PC != CurInfo.EntryPC) {
          // Finalize block: update max block RA-expensive count
          JITResult.MaxBlockExpensiveCount =
              std::max(JITResult.MaxBlockExpensiveCount,
                       static_cast<size_t>(CurInfo.RAExpensiveCount));
          BlockInfos.emplace(CurInfo.EntryPC, CurInfo);
        }
        // Create new block info
        CurInfo = BlockInfo(PC);
        if (Opcode == OP_JUMPDEST) {
          CurInfo.IsJumpDest = true;
        }
        // Block boundary also ends a consecutive run
        JITResult.MaxConsecutiveExpensive = std::max(
            JITResult.MaxConsecutiveExpensive, CurConsecutiveExpensive);
        CurConsecutiveExpensive = 0;
      } else if (IsBlockEnd) {
        // Finalize block: update max block RA-expensive count
        JITResult.MaxBlockExpensiveCount =
            std::max(JITResult.MaxBlockExpensiveCount,
                     static_cast<size_t>(CurInfo.RAExpensiveCount));
        // Save current block info
        BlockInfos.emplace(CurInfo.EntryPC, CurInfo);
        // Block boundary ends consecutive run
        JITResult.MaxConsecutiveExpensive = std::max(
            JITResult.MaxConsecutiveExpensive, CurConsecutiveExpensive);
        CurConsecutiveExpensive = 0;
        // Skip dead code
        while (Ip < IpEnd) {
          evmc_opcode NextOp = static_cast<evmc_opcode>(*Ip);
          if (NextOp == OP_JUMPDEST) {
            break;
          }
          Ip++;
          if (NextOp >= OP_PUSH0 && NextOp <= OP_PUSH32) {
            uint8_t NumBytes =
                static_cast<uint8_t>(NextOp) - static_cast<uint8_t>(OP_PUSH0);
            Ip += NumBytes;
          }
        }
      }
    }
    // Finalize last block and consecutive run
    JITResult.MaxConsecutiveExpensive =
        std::max(JITResult.MaxConsecutiveExpensive, CurConsecutiveExpensive);
    if (BlockInfos.count(CurInfo.EntryPC) == 0) {
      JITResult.MaxBlockExpensiveCount =
          std::max(JITResult.MaxBlockExpensiveCount,
                   static_cast<size_t>(CurInfo.RAExpensiveCount));
      BlockInfos.emplace(CurInfo.EntryPC, CurInfo);
    }

    // Compute final fallback verdict
    JITResult.ShouldFallback =
        BytecodeSize > MAX_JIT_BYTECODE_SIZE ||
        JITResult.MirEstimate > MAX_JIT_MIR_ESTIMATE ||
        JITResult.MaxConsecutiveExpensive > MAX_CONSECUTIVE_RA_EXPENSIVE ||
        JITResult.MaxBlockExpensiveCount > MAX_BLOCK_RA_EXPENSIVE ||
        JITResult.DupFeedbackPatternCount > MAX_DUP_FEEDBACK_PATTERN;

    return true;
  }

private:
  std::map<uint64_t, BlockInfo> BlockInfos;
  uint64_t PC = 0;
  evmc_revision Revision = zen::evm::DEFAULT_REVISION;
  JITSuitabilityResult JITResult;
};

} // namespace COMPILER

#endif // EVM_FRONTEND_EVM_ANALYZER_H
