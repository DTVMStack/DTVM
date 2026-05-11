// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/evm_frontend/evm_analyzer.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <ostream>
#include <vector>

namespace COMPILER {
// GTest finds this overload via ADL on the enum class's namespace, producing
// readable failure output like "Which is: U256" instead of raw bytes.
inline void PrintTo(EVMValueRange R, std::ostream *Os) {
  switch (R) {
  case EVMValueRange::U64:
    *Os << "U64";
    return;
  case EVMValueRange::U128:
    *Os << "U128";
    return;
  case EVMValueRange::U256:
    *Os << "U256";
    return;
  }
  *Os << "UNKNOWN(" << static_cast<int>(R) << ")";
}
} // namespace COMPILER

namespace {

using COMPILER::EVMAnalyzer;
using COMPILER::EVMValueRange;

EVMAnalyzer analyzeBytecode(const std::vector<uint8_t> &Bytecode) {
  EVMAnalyzer Analyzer(EVMC_CANCUN);
  const uint8_t *Data = Bytecode.empty() ? nullptr : Bytecode.data();
  Analyzer.analyze(Data, Bytecode.size());
  return Analyzer;
}

const EVMAnalyzer::BlockInfo *findBlock(const EVMAnalyzer &Analyzer,
                                        uint64_t EntryPC) {
  const auto &Blocks = Analyzer.getBlockInfos();
  auto It = Blocks.find(EntryPC);
  if (It == Blocks.end()) {
    return nullptr;
  }
  return &It->second;
}

struct CrossJoinBytecode {
  std::vector<uint8_t> Bytecode;
  uint64_t JumpDestPC;
};

// "PUSH1 0 NOT PUSH1 5 <Op> PUSH1 10 JUMP <INVALID pad> JUMPDEST" -- divisor on
// stack-bottom (-1 = U256), dividend on top (5 = U64).  After SDIV/SMOD, the
// single stack slot at the JUMPDEST entry is the result.
CrossJoinBytecode buildCrossJoin(uint8_t Op) {
  return CrossJoinBytecode{{0x60, 0x00, // PUSH1 0
                            0x19,       // NOT
                            0x60, 0x05, // PUSH1 5
                            Op,         // SDIV (0x05) or SMOD (0x07)
                            0x60, 0x0a, // PUSH1 10
                            0x56,       // JUMP
                            0xfe,       // INVALID padding (PC = 9)
                            0x5b},      // JUMPDEST (PC = 10)
                           10};
}

} // namespace

TEST(EVMRangeAnalyzer, SDivByU256IsU256) {
  CrossJoinBytecode Setup = buildCrossJoin(0x05 /* SDIV */);
  EVMAnalyzer Analyzer = analyzeBytecode(Setup.Bytecode);
  const auto *JumpDest = findBlock(Analyzer, Setup.JumpDestPC);
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U256);
}

TEST(EVMRangeAnalyzer, SModByU256IsU256) {
  CrossJoinBytecode Setup = buildCrossJoin(0x07 /* SMOD */);
  EVMAnalyzer Analyzer = analyzeBytecode(Setup.Bytecode);
  const auto *JumpDest = findBlock(Analyzer, Setup.JumpDestPC);
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U256);
}

TEST(EVMRangeAnalyzer, SDivU256DividendIsU256) {
  // Dividend is the U256 (-1), Divisor is the U64 (5).  Helper should still
  // widen result to U256 because dividend's bit 255 makes the value
  // signed-negative.  Catches regressions that drop the symmetric branch.
  //
  // PUSH1 5 (divisor, U64, bottom) PUSH1 0 NOT (dividend, U256, top)
  // SDIV PUSH1 10 JUMP <pad> JUMPDEST
  std::vector<uint8_t> Bytecode = {
      0x60, 0x05, // PUSH1 5         (divisor, U64, bottom)
      0x60, 0x00, // PUSH1 0
      0x19,       // NOT             (dividend, U256, top)
      0x05,       // SDIV
      0x60, 0x0a, // PUSH1 10
      0x56,       // JUMP
      0xfe,       // INVALID padding (PC = 9)
      0x5b};      // JUMPDEST (PC = 10)
  EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);
  const auto *JumpDest = findBlock(Analyzer, 10);
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U256);
}
