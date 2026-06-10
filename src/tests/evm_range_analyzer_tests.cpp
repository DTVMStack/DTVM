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

EVMAnalyzer analyzeBytecode(const std::vector<uint8_t> &Bytecode,
                            evmc_revision Revision = EVMC_CANCUN) {
  EVMAnalyzer Analyzer(Revision);
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

// Assertion helper: block must exist with a resolved positive entry depth and
// the top of its entry stack must equal Expected.  Use this instead of nested
// `if (Block != nullptr) ...` guards which silently pass if the analyzer
// stops materializing the block.
void assertEntryTop(const EVMAnalyzer::BlockInfo *Block,
                    EVMValueRange Expected) {
  ASSERT_NE(Block, nullptr);
  ASSERT_GE(Block->ResolvedEntryStackDepth, 0);
  ASSERT_FALSE(Block->EntryStackRanges.empty());
  EXPECT_EQ(Block->EntryStackRanges.back(), Expected);
}

// Assertion helper: block must exist, but its entry depth is unresolved (-1)
// or its EntryStackRanges is empty.  Use for dead-block / unresolved-block
// tests that document expected non-materialization.
void assertNoEntryState(const EVMAnalyzer::BlockInfo *Block) {
  ASSERT_NE(Block, nullptr);
  EXPECT_TRUE(Block->ResolvedEntryStackDepth < 0 ||
              Block->EntryStackRanges.empty());
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

namespace {

// Build "<HostOp> PUSH1 5 JUMP <pad> JUMPDEST" so the JUMPDEST inherits the
// host-opcode result as its single entry slot.
CrossJoinBytecode buildHostOpCrossJoin(uint8_t HostOp) {
  return CrossJoinBytecode{
      {HostOp,     // 0: TIMESTAMP / NUMBER / GASLIMIT / CHAINID
       0x60, 0x05, // 1: PUSH1 5
       0x56,       // 3: JUMP
       0xfe,       // 4: INVALID pad
       0x5b},      // 5: JUMPDEST
      5};
}

} // namespace

TEST(EVMRangeAnalyzer, TimestampIsU256) {
  CrossJoinBytecode Setup = buildHostOpCrossJoin(0x42 /* TIMESTAMP */);
  EVMAnalyzer Analyzer = analyzeBytecode(Setup.Bytecode);
  const auto *JumpDest = findBlock(Analyzer, Setup.JumpDestPC);
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U256);
}

TEST(EVMRangeAnalyzer, NumberIsU256) {
  CrossJoinBytecode Setup = buildHostOpCrossJoin(0x43 /* NUMBER */);
  EVMAnalyzer Analyzer = analyzeBytecode(Setup.Bytecode);
  const auto *JumpDest = findBlock(Analyzer, Setup.JumpDestPC);
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U256);
}

TEST(EVMRangeAnalyzer, GasLimitIsU256) {
  CrossJoinBytecode Setup = buildHostOpCrossJoin(0x45 /* GASLIMIT */);
  EVMAnalyzer Analyzer = analyzeBytecode(Setup.Bytecode);
  const auto *JumpDest = findBlock(Analyzer, Setup.JumpDestPC);
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U256);
}

TEST(EVMRangeAnalyzer, ChainIdIsU256) {
  CrossJoinBytecode Setup = buildHostOpCrossJoin(0x46 /* CHAINID */);
  EVMAnalyzer Analyzer = analyzeBytecode(Setup.Bytecode);
  const auto *JumpDest = findBlock(Analyzer, Setup.JumpDestPC);
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U256);
}

TEST(EVMRangeAnalyzer, CreateAddressIsU256) {
  // CREATE pushes the created contract address (20 bytes / 160 bits) or 0
  // on failure -- not a 0/1 success bool.  Verify analyzer widens to U256
  // so the result cannot reach a bothFitU64 fast path on the lifted path.
  //
  // PUSH1 0 (length, bottom) PUSH1 0 (offset) PUSH1 0 (value, top) CREATE
  // PUSH1 11 JUMP <pad> JUMPDEST
  std::vector<uint8_t> Bytecode = {
      0x60, 0x00, // PC 0-1:  PUSH1 0  (length, bottom of stack)
      0x60, 0x00, // PC 2-3:  PUSH1 0  (offset)
      0x60, 0x00, // PC 4-5:  PUSH1 0  (value, top before CREATE pops)
      0xf0,       // PC 6:    CREATE
      0x60, 0x0b, // PC 7-8:  PUSH1 11
      0x56,       // PC 9:    JUMP
      0xfe,       // PC 10:   INVALID padding
      0x5b};      // PC 11:   JUMPDEST
  EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);
  const auto *JumpDest = findBlock(Analyzer, 11);
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U256);
}

TEST(EVMRangeAnalyzer, Create2AddressIsU256) {
  // Same as CreateAddressIsU256 but with CREATE2 (pops 4 args incl. salt).
  //
  // PUSH1 0 x4 (salt, length, offset, value-top) CREATE2 PUSH1 13 JUMP
  // <pad> JUMPDEST
  std::vector<uint8_t> Bytecode = {
      0x60, 0x00, // PC 0-1:   PUSH1 0  (salt, bottom)
      0x60, 0x00, // PC 2-3:   PUSH1 0  (length)
      0x60, 0x00, // PC 4-5:   PUSH1 0  (offset)
      0x60, 0x00, // PC 6-7:   PUSH1 0  (value, top before CREATE2 pops)
      0xf5,       // PC 8:     CREATE2
      0x60, 0x0d, // PC 9-10:  PUSH1 13
      0x56,       // PC 11:    JUMP
      0xfe,       // PC 12:    INVALID padding
      0x5b};      // PC 13:    JUMPDEST
  EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);
  const auto *JumpDest = findBlock(Analyzer, 13);
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U256);
}

namespace {

// Build "PUSH<N> <Literal> PUSH1 <JumpDestPC> JUMP <pad> JUMPDEST" so the
// JUMPDEST inherits the literal as its single entry slot.
std::vector<uint8_t> buildPushLiteralAndJump(uint8_t PushOp,
                                             const std::vector<uint8_t> &Bytes,
                                             uint8_t PadCount = 1) {
  std::vector<uint8_t> Code;
  Code.push_back(PushOp);
  Code.insert(Code.end(), Bytes.begin(), Bytes.end());
  // JumpDest PC = 1 + Bytes + 2 (PUSH1 NN) + 1 (JUMP) + PadCount
  const uint8_t JumpDestPC =
      static_cast<uint8_t>(1 + Bytes.size() + 2 + 1 + PadCount);
  Code.push_back(0x60); // PUSH1
  Code.push_back(JumpDestPC);
  Code.push_back(0x56); // JUMP
  for (uint8_t I = 0; I < PadCount; ++I) {
    Code.push_back(0xfe); // INVALID pad
  }
  Code.push_back(0x5b); // JUMPDEST
  return Code;
}

uint64_t lastJumpDestPC(const std::vector<uint8_t> &Code) {
  return static_cast<uint64_t>(Code.size() - 1);
}

// Append "PUSH1 <JumpDestPC> JUMP <INVALID pad> JUMPDEST" to `Code`, computing
// the JUMPDEST PC after the JUMP+pad.  Returns the final JUMPDEST PC.
uint64_t appendJumpToFreshJumpDest(std::vector<uint8_t> &Code) {
  // JUMPDEST will be at Code.size() + 2 (PUSH1+arg) + 1 (JUMP) + 1 (pad) = +4.
  const uint8_t JumpDestPC = static_cast<uint8_t>(Code.size() + 4);
  Code.push_back(0x60); // PUSH1
  Code.push_back(JumpDestPC);
  Code.push_back(0x56); // JUMP
  Code.push_back(0xfe); // INVALID pad
  Code.push_back(0x5b); // JUMPDEST
  return JumpDestPC;
}

// Append a PUSH<N> instruction with the given literal bytes to `Code`.
void appendPush(std::vector<uint8_t> &Code, uint8_t PushOp,
                const std::vector<uint8_t> &Bytes) {
  Code.push_back(PushOp);
  Code.insert(Code.end(), Bytes.begin(), Bytes.end());
}

// Convenience literals for common boundary-magnitude push values.
const std::vector<uint8_t> &u64MaxLiteralPush8() {
  static const std::vector<uint8_t> V(8, 0xff);
  return V;
}
const std::vector<uint8_t> &u128MaxLiteralPush16() {
  static const std::vector<uint8_t> V(16, 0xff);
  return V;
}
const std::vector<uint8_t> &u256MaxLiteralPush32() {
  static const std::vector<uint8_t> V(32, 0xff);
  return V;
}

} // namespace

// ---------------------------------------------------------------------------
// Group A — Per-opcode transfer rules
// ---------------------------------------------------------------------------

TEST(EVMRangeAnalyzer, PushLiteralU64BoundaryMax) {
  // PUSH8 FF*8 = 2^64 - 1 — still fits in U64.
  auto Code =
      buildPushLiteralAndJump(0x67, // PUSH8
                              {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff});
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *JumpDest = findBlock(Analyzer, lastJumpDestPC(Code));
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U64);
}

TEST(EVMRangeAnalyzer, PushLiteralU128BoundaryMin) {
  // PUSH9 01 00*8 = exactly 2^64 — first byte over the U64 frontier.
  auto Code = buildPushLiteralAndJump(
      0x68, // PUSH9
      {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *JumpDest = findBlock(Analyzer, lastJumpDestPC(Code));
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U128);
}

TEST(EVMRangeAnalyzer, PushLiteralU128BoundaryMax) {
  // PUSH16 FF*16 = 2^128 - 1 — still fits in U128.
  auto Code =
      buildPushLiteralAndJump(0x6f, // PUSH16
                              {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff});
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *JumpDest = findBlock(Analyzer, lastJumpDestPC(Code));
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U128);
}

TEST(EVMRangeAnalyzer, PushLiteralU256BoundaryMin) {
  // PUSH17 01 00*16 = exactly 2^128 — first byte over the U128 frontier.
  auto Code = buildPushLiteralAndJump(0x70, // PUSH17
                                      {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00});
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *JumpDest = findBlock(Analyzer, lastJumpDestPC(Code));
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U256);
}

TEST(EVMRangeAnalyzer, PushLiteralAllZeroPush32) {
  // PUSH32 00*32 = 0 — all-zero prefix means U64.
  auto Code = buildPushLiteralAndJump(0x7f, // PUSH32
                                      std::vector<uint8_t>(32, 0x00));
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *JumpDest = findBlock(Analyzer, lastJumpDestPC(Code));
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U64);
}

TEST(EVMRangeAnalyzer, AddWidens) {
  // PUSH8 a PUSH8 b ADD → widen(meet(U64,U64)) = U128.
  std::vector<uint8_t> Code;
  appendPush(Code, 0x67, u64MaxLiteralPush8()); // PUSH8 a
  appendPush(Code, 0x67, u64MaxLiteralPush8()); // PUSH8 b
  Code.push_back(0x01);                         // ADD
  uint64_t Pc = appendJumpToFreshJumpDest(Code);
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *JumpDest = findBlock(Analyzer, Pc);
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U128);
}

TEST(EVMRangeAnalyzer, AddU128PlusU128) {
  // PUSH16 a PUSH16 b ADD → widen(meet(U128,U128)) = U256.
  std::vector<uint8_t> Code;
  appendPush(Code, 0x6f, u128MaxLiteralPush16());
  appendPush(Code, 0x6f, u128MaxLiteralPush16());
  Code.push_back(0x01); // ADD
  uint64_t Pc = appendJumpToFreshJumpDest(Code);
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *JumpDest = findBlock(Analyzer, Pc);
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U256);
}

TEST(EVMRangeAnalyzer, MulWidens) {
  // PUSH8 a PUSH8 b MUL → widen(meet(U64,U64)) = U128.
  std::vector<uint8_t> Code;
  appendPush(Code, 0x67, u64MaxLiteralPush8());
  appendPush(Code, 0x67, u64MaxLiteralPush8());
  Code.push_back(0x02); // MUL
  uint64_t Pc = appendJumpToFreshJumpDest(Code);
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *JumpDest = findBlock(Analyzer, Pc);
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U128);
}

TEST(EVMRangeAnalyzer, DivUnsigned) {
  // PUSH32 div (U256, bottom) PUSH8 dvd (U64, top = dividend) DIV
  // → result = Dividend's range = U64.
  std::vector<uint8_t> Code;
  appendPush(Code, 0x7f, u256MaxLiteralPush32());
  appendPush(Code, 0x67, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05});
  Code.push_back(0x04); // DIV
  uint64_t Pc = appendJumpToFreshJumpDest(Code);
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *JumpDest = findBlock(Analyzer, Pc);
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U64);
}

TEST(EVMRangeAnalyzer, SDivU64ByU128IsU64) {
  // PUSH16 d (U128 divisor) PUSH8 n (U64 dividend) SDIV
  // Both non-U256 → signedDivModRange returns Dividend's range = U64.
  std::vector<uint8_t> Code;
  appendPush(Code, 0x6f,
             {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00});
  appendPush(Code, 0x67, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05});
  Code.push_back(0x05); // SDIV
  uint64_t Pc = appendJumpToFreshJumpDest(Code);
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *JumpDest = findBlock(Analyzer, Pc);
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U64);
}

TEST(EVMRangeAnalyzer, AddModFromModulus) {
  // ADDMOD pops [a, b, N] top-down → push order: N (bottom), b, a (top).
  // PUSH1 N (U64) PUSH32 b PUSH32 a ADDMOD → result = N's range = U64.
  std::vector<uint8_t> Code;
  appendPush(Code, 0x60, {0x07});                 // PUSH1 N
  appendPush(Code, 0x7f, u256MaxLiteralPush32()); // PUSH32 b
  appendPush(Code, 0x7f, u256MaxLiteralPush32()); // PUSH32 a
  Code.push_back(0x08);                           // ADDMOD
  uint64_t Pc = appendJumpToFreshJumpDest(Code);
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *JumpDest = findBlock(Analyzer, Pc);
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U64);
}

TEST(EVMRangeAnalyzer, IsZeroIsU64) {
  // PUSH32 x ISZERO → boolean U64 result.
  std::vector<uint8_t> Code;
  appendPush(Code, 0x7f, u256MaxLiteralPush32());
  Code.push_back(0x15); // ISZERO
  uint64_t Pc = appendJumpToFreshJumpDest(Code);
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *JumpDest = findBlock(Analyzer, Pc);
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U64);
}

TEST(EVMRangeAnalyzer, LtIsU64) {
  // PUSH32 a PUSH32 b LT → boolean U64 result.
  std::vector<uint8_t> Code;
  appendPush(Code, 0x7f, u256MaxLiteralPush32());
  appendPush(Code, 0x7f, u256MaxLiteralPush32());
  Code.push_back(0x10); // LT
  uint64_t Pc = appendJumpToFreshJumpDest(Code);
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *JumpDest = findBlock(Analyzer, Pc);
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U64);
}

TEST(EVMRangeAnalyzer, AndShortCircuitU64) {
  // PUSH8 m (U64) PUSH32 v (U256) AND — short-circuits on U64 operand → U64.
  std::vector<uint8_t> Code;
  appendPush(Code, 0x67, u64MaxLiteralPush8());
  appendPush(Code, 0x7f, u256MaxLiteralPush32());
  Code.push_back(0x16); // AND
  uint64_t Pc = appendJumpToFreshJumpDest(Code);
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *JumpDest = findBlock(Analyzer, Pc);
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U64);
}

TEST(EVMRangeAnalyzer, AndU128AndU256) {
  // PUSH16 m (U128) PUSH32 v (U256) AND — neither U64; result = min(U128,U256)
  // = U128.
  std::vector<uint8_t> Code;
  appendPush(Code, 0x6f, u128MaxLiteralPush16());
  appendPush(Code, 0x7f, u256MaxLiteralPush32());
  Code.push_back(0x16); // AND
  uint64_t Pc = appendJumpToFreshJumpDest(Code);
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *JumpDest = findBlock(Analyzer, Pc);
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U128);
}

TEST(EVMRangeAnalyzer, AndU256AndU256) {
  // PUSH32 m (U256) PUSH32 v (U256) AND — min(U256, U256) = U256.
  std::vector<uint8_t> Code;
  appendPush(Code, 0x7f, u256MaxLiteralPush32());
  appendPush(Code, 0x7f, u256MaxLiteralPush32());
  Code.push_back(0x16); // AND
  uint64_t Pc = appendJumpToFreshJumpDest(Code);
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *JumpDest = findBlock(Analyzer, Pc);
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U256);
}

TEST(EVMRangeAnalyzer, OrTakesMax) {
  // PUSH8 a (U64) PUSH32 b (U256) OR — OR uses meetRange (max) = U256.
  std::vector<uint8_t> Code;
  appendPush(Code, 0x67, u64MaxLiteralPush8());
  appendPush(Code, 0x7f, u256MaxLiteralPush32());
  Code.push_back(0x17); // OR
  uint64_t Pc = appendJumpToFreshJumpDest(Code);
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *JumpDest = findBlock(Analyzer, Pc);
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U256);
}

TEST(EVMRangeAnalyzer, XorTakesMax) {
  // PUSH16 a (U128) PUSH32 b (U256) XOR — XOR uses meetRange (max) = U256.
  std::vector<uint8_t> Code;
  appendPush(Code, 0x6f, u128MaxLiteralPush16());
  appendPush(Code, 0x7f, u256MaxLiteralPush32());
  Code.push_back(0x18); // XOR
  uint64_t Pc = appendJumpToFreshJumpDest(Code);
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *JumpDest = findBlock(Analyzer, Pc);
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U256);
}

TEST(EVMRangeAnalyzer, ShrPreservesValueRange) {
  // EVM SHR pops shift (top), then value.  Bytecode order: PUSH value, PUSH
  // shift, SHR.  Result = value's range.  PUSH16 value (U128) + PUSH1 shift
  // → U128.
  std::vector<uint8_t> Code;
  appendPush(Code, 0x6f,
             {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00}); // PUSH16 value
  appendPush(Code, 0x60, {0x04});             // PUSH1 shift
  Code.push_back(0x1c);                       // SHR
  uint64_t Pc = appendJumpToFreshJumpDest(Code);
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *JumpDest = findBlock(Analyzer, Pc);
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U128);
}

TEST(EVMRangeAnalyzer, ClzIsU64InOsaka) {
  // CLZ is Osaka-gated; default Cancun analysis would treat 0x1e as undefined.
  std::vector<uint8_t> Code;
  appendPush(Code, 0x7f, u256MaxLiteralPush32());
  Code.push_back(0x1e); // CLZ
  uint64_t Pc = appendJumpToFreshJumpDest(Code);
  EVMAnalyzer Analyzer = analyzeBytecode(Code, EVMC_OSAKA);
  const auto *JumpDest = findBlock(Analyzer, Pc);
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U64);
}

TEST(EVMRangeAnalyzer, Keccak256IsU256) {
  // PUSH1 offset PUSH1 length KECCAK256 — hash output is U256.
  std::vector<uint8_t> Code;
  appendPush(Code, 0x60, {0x00}); // PUSH1 0
  appendPush(Code, 0x60, {0x20}); // PUSH1 32
  Code.push_back(0x20);           // KECCAK256
  uint64_t Pc = appendJumpToFreshJumpDest(Code);
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *JumpDest = findBlock(Analyzer, Pc);
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U256);
}

// ---------------------------------------------------------------------------
// Group B — CFG meet convergence
// ---------------------------------------------------------------------------

TEST(EVMRangeAnalyzer, StraightlineFallthrough) {
  // A static JUMP carries the surviving stack slot into its JUMPDEST target.
  // PUSH1 5 leaves a U64 residual below the JUMP target; after JUMP consumes
  // the target, the JUMPDEST sees the U64 as its single entry slot.
  //
  // PC 0: PUSH1 5    (U64 residual)
  // PC 2: PUSH1 6    (JUMP target)
  // PC 4: JUMP
  // PC 5: pad
  // PC 6: JUMPDEST
  // PC 7: STOP
  std::vector<uint8_t> Code = {0x60, 0x05, // PUSH1 5 (U64)
                               0x60, 0x06, // PUSH1 6
                               0x56,       // JUMP
                               0xfe,       // INVALID pad (PC=5)
                               0x5b,       // JUMPDEST (PC=6)
                               0x00};      // STOP
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *JumpDest = findBlock(Analyzer, 6);
  ASSERT_NE(JumpDest, nullptr);
  ASSERT_EQ(JumpDest->EntryStackRanges.size(), 1u);
  EXPECT_EQ(JumpDest->EntryStackRanges.back(), EVMValueRange::U64);
}

TEST(EVMRangeAnalyzer, DiamondMeetWidens) {
  // B0 conditionally branches; one path pushes U64, the other pushes U256.
  // Both static-JUMP to a merge JUMPDEST.  Merge entry top = meet(U64,U256)
  // = U256.  Layout uses explicit placeholders patched after construction.
  std::vector<uint8_t> C;
  // B0 PC=0: PUSH1 1 PUSH1 <taken> JUMPI
  C.push_back(0x60);
  C.push_back(0x01); // PC 0-1
  C.push_back(0x60);
  C.push_back(0x00); // PC 2-3 placeholder for taken target
  C.push_back(0x57); // PC 4 JUMPI
  // Fallthrough B1 PC=5: PUSH1 5 PUSH1 <merge> JUMP
  C.push_back(0x60);
  C.push_back(0x05); // PC 5-6
  C.push_back(0x60);
  C.push_back(0x00); // PC 7-8 placeholder for merge target
  C.push_back(0x56); // PC 9 JUMP
  C.push_back(0xfe); // PC 10 pad
  // Taken B2 PC=11: JUMPDEST PUSH32 ... PUSH1 <merge> JUMP
  const uint8_t TakenPC = static_cast<uint8_t>(C.size()); // 11
  C.push_back(0x5b);                                      // JUMPDEST PC=11
  C.push_back(0x7f);                                      // PUSH32 PC=12
  C.push_back(0x01);
  for (int I = 0; I < 31; ++I)
    C.push_back(0x00);
  // After PUSH32: PC = 12 + 32 = 44
  C.push_back(0x60);
  C.push_back(0x00); // PC 44-45 placeholder for merge target
  C.push_back(0x56); // PC 46 JUMP
  C.push_back(0xfe); // PC 47 pad
  // Merge B3 PC=48: JUMPDEST STOP
  const uint8_t MergePC = static_cast<uint8_t>(C.size());
  C.push_back(0x5b); // JUMPDEST PC=MergePC
  C.push_back(0x00); // STOP
  // Patch placeholders.
  C[3] = TakenPC;  // taken target
  C[8] = MergePC;  // fallthrough merge target
  C[46] = MergePC; // taken merge target (PUSH1 operand at PC=46)

  EVMAnalyzer Analyzer = analyzeBytecode(C);
  const auto *Merge = findBlock(Analyzer, MergePC);
  ASSERT_NE(Merge, nullptr);
  ASSERT_EQ(Merge->EntryStackRanges.size(), 1u);
  EXPECT_EQ(Merge->EntryStackRanges.back(), EVMValueRange::U256);
}

TEST(EVMRangeAnalyzer, DiamondMultiSlotMeet) {
  // 3-deep diamond merge: each predecessor pushes 3 values with distinct
  // per-slot ranges, verifying per-slot meet=max independence.
  //
  // B1 (fallthrough) exits with [U64,  U128, U256]
  // B2 (taken)       exits with [U128, U64,  U64 ]
  // Merge entry meet [U128, U128, U256]  (per-slot max)
  std::vector<uint8_t> C;
  // B0 PC=0: PUSH1 1 PUSH1 <taken> JUMPI
  C.push_back(0x60);
  C.push_back(0x01); // PC 0-1
  C.push_back(0x60);
  C.push_back(0x00); // PC 2-3 placeholder taken target
  C.push_back(0x57); // PC 4 JUMPI
  // B1 fallthrough PC=5: PUSH8 PUSH16 PUSH32 PUSH1 <merge> JUMP
  C.push_back(0x67); // PC 5 PUSH8
  for (int I = 0; I < 8; ++I)
    C.push_back(0xff); // PC 6-13
  C.push_back(0x6f);   // PC 14 PUSH16
  for (int I = 0; I < 16; ++I)
    C.push_back(0xff); // PC 15-30
  C.push_back(0x7f);   // PC 31 PUSH32
  C.push_back(0x01);   // PC 32
  for (int I = 0; I < 31; ++I)
    C.push_back(0x00); // PC 33-63
  C.push_back(0x60);
  C.push_back(0x00); // PC 64-65 placeholder merge target
  C.push_back(0x56); // PC 66 JUMP
  C.push_back(0xfe); // PC 67 pad
  // B2 taken PC=68: JUMPDEST PUSH16 PUSH8 PUSH8 PUSH1 <merge> JUMP
  const uint8_t TakenPC = static_cast<uint8_t>(C.size()); // 68
  C.push_back(0x5b);                                      // PC 68 JUMPDEST
  C.push_back(0x6f);                                      // PC 69 PUSH16
  for (int I = 0; I < 16; ++I)
    C.push_back(0xff); // PC 70-85
  C.push_back(0x67);   // PC 86 PUSH8
  for (int I = 0; I < 8; ++I)
    C.push_back(0xff); // PC 87-94
  C.push_back(0x67);   // PC 95 PUSH8
  for (int I = 0; I < 8; ++I)
    C.push_back(0xff); // PC 96-103
  C.push_back(0x60);
  C.push_back(0x00); // PC 104-105 placeholder merge target
  C.push_back(0x56); // PC 106 JUMP
  // B3 merge PC=107: JUMPDEST STOP
  const uint8_t MergePC = static_cast<uint8_t>(C.size()); // 107
  C.push_back(0x5b);                                      // JUMPDEST
  C.push_back(0x00);                                      // STOP
  // Patch placeholders.
  C[3] = TakenPC;
  C[65] = MergePC;
  C[105] = MergePC;

  EVMAnalyzer Analyzer = analyzeBytecode(C);
  const auto *Merge = findBlock(Analyzer, MergePC);
  ASSERT_NE(Merge, nullptr);
  ASSERT_EQ(Merge->EntryStackRanges.size(), 3u);
  // Slot 0 (bottom): meet(U64,  U128) = U128.
  EXPECT_EQ(Merge->EntryStackRanges[0], EVMValueRange::U128);
  // Slot 1:           meet(U128, U64 ) = U128.
  EXPECT_EQ(Merge->EntryStackRanges[1], EVMValueRange::U128);
  // Slot 2 (top):     meet(U256, U64 ) = U256.
  EXPECT_EQ(Merge->EntryStackRanges[2], EVMValueRange::U256);
}

TEST(EVMRangeAnalyzer, SelfLoopBackEdge) {
  // Loop header with a body that preserves the entry slot's range (no
  // widening): the back-edge meet converges in one round to a steady state.
  // Verifies that worklist analysis terminates and the loop header's entry
  // top equals the seed range (U64) rather than U256.
  //
  // PC 0: PUSH1 1                 (seed U64; fall-through into PC 2)
  // PC 2: JUMPDEST                (loop header)
  // PC 3: PUSH1 0
  // PC 5: POP                      (body brings stack back to [U64])
  // PC 6: PUSH1 2                  (constant JUMP target)
  // PC 8: JUMP                     back to PC 2
  std::vector<uint8_t> Code = {0x60, 0x01, // PUSH1 1
                               0x5b,       // JUMPDEST PC=2
                               0x60, 0x00, // PUSH1 0
                               0x50,       // POP
                               0x60, 0x02, // PUSH1 2
                               0x56};      // JUMP
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *Loop = findBlock(Analyzer, 2);
  ASSERT_NE(Loop, nullptr);
  ASSERT_EQ(Loop->EntryStackRanges.size(), 1u);
  EXPECT_EQ(Loop->EntryStackRanges.back(), EVMValueRange::U64);
}

TEST(EVMRangeAnalyzer, JumpIBranchAsymmetry) {
  // JUMPI consumes (target, cond) from the top of the stack.  Below them, B0
  // leaves PUSH1 5 (U64) as a residual slot visible to both successors.  A
  // STOP separator between the two JUMPDESTs prevents adjacent-JUMPDEST
  // canonicalization, so each successor is materialized independently with
  // its own meet from B0.
  //
  // PC 0: PUSH1 5      (residual U64)
  // PC 2: PUSH1 1      (cond)
  // PC 4: PUSH1 9      (taken target)
  // PC 6: JUMPI
  // PC 7: JUMPDEST     (fallthrough)
  // PC 8: STOP         (separator)
  // PC 9: JUMPDEST     (taken)
  std::vector<uint8_t> Code = {0x60, 0x05, // PUSH1 5
                               0x60, 0x01, // PUSH1 1
                               0x60, 0x09, // PUSH1 9
                               0x57,       // JUMPI
                               0x5b,       // JUMPDEST PC=7 (fallthrough)
                               0x00,       // STOP (separator)
                               0x5b,       // JUMPDEST PC=9 (taken)
                               0x00};      // STOP
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *FT = findBlock(Analyzer, 7);
  const auto *Taken = findBlock(Analyzer, 9);
  // Both successors see the residual U64 slot from B0 after JUMPI consumes
  // its 2 operands.  Asymmetry: each successor block is materialized
  // independently, even though their entry state happens to match here.
  assertEntryTop(FT, EVMValueRange::U64);
  assertEntryTop(Taken, EVMValueRange::U64);
}

TEST(EVMRangeAnalyzer, RevertExitDoesNotPropagate) {
  // B0 ends in REVERT — has no Successors; nothing to propagate.  The
  // JUMPDEST at PC=5 is unreachable from any static or dynamic JUMP, so its
  // entry state must remain unresolved (depth -1, empty ranges).  This pins
  // down that REVERT's exit stack does NOT silently flow into the
  // textually-adjacent JUMPDEST.
  //
  // PC 0: PUSH1 0
  // PC 2: PUSH1 0
  // PC 4: REVERT       (B0 terminator)
  // PC 5: JUMPDEST     (unreachable; no JUMP targets it)
  // PC 6: STOP
  std::vector<uint8_t> Code = {0x60, 0x00, // PUSH1 0
                               0x60, 0x00, // PUSH1 0
                               0xfd,       // REVERT
                               0x5b,       // JUMPDEST PC=5
                               0x00};      // STOP
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *Jd = findBlock(Analyzer, 5);
  assertNoEntryState(Jd);
}

TEST(EVMRangeAnalyzer, MultiBackEdgeSelfLoop) {
  // Self-loop with two back-edges into the same JUMPDEST (not a nested
  // loop — both back-edges target the same loop header).  Verifies the
  // worklist handles multiple in-edges from a single block and converges
  // without oscillation.  The body preserves the entry slot (U64), so the
  // back-edge meet stays U64 at the fixed point.
  //
  // PC 0:  PUSH1 1                 (seed U64, fall-through into PC 2)
  // PC 2:  JUMPDEST  (loop header)
  // PC 3:  PUSH1 0                 (cond=0 for JUMPI; first back-edge taken)
  // PC 5:  PUSH1 2                 (JUMPI target)
  // PC 7:  JUMPI                    pops cond + target
  // PC 8:  PUSH1 2                 (constant JUMP target)
  // PC 10: JUMP                     second back-edge
  std::vector<uint8_t> Code = {0x60, 0x01, // PUSH1 1
                               0x5b,       // JUMPDEST PC=2
                               0x60, 0x00, // PUSH1 0
                               0x60, 0x02, // PUSH1 2
                               0x57,       // JUMPI
                               0x60, 0x02, // PUSH1 2
                               0x56};      // JUMP
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *Loop = findBlock(Analyzer, 2);
  ASSERT_NE(Loop, nullptr);
  ASSERT_GE(Loop->EntryStackRanges.size(), 1u);
  EXPECT_EQ(Loop->EntryStackRanges.back(), EVMValueRange::U64);
}

TEST(EVMRangeAnalyzer, DeadBlockSkipped) {
  // A JUMPDEST that is not reachable from the entry block keeps
  // ResolvedEntryStackDepth = -1 and an empty EntryStackRanges.  A reachable
  // JUMPDEST with a residual U64 below the JUMP target gets entry top = U64.
  //
  // PC 0: PUSH1 5   (residual U64; survives the JUMP)
  // PC 2: PUSH1 6   (JUMP target)
  // PC 4: JUMP
  // PC 5: pad
  // PC 6: JUMPDEST  (reachable; entry depth 1)
  // PC 7: STOP
  // PC 8: JUMPDEST  (dead; no JUMP targets it)
  std::vector<uint8_t> Code = {0x60, 0x05, // PUSH1 5
                               0x60, 0x06, // PUSH1 6
                               0x56,       // JUMP
                               0xfe,       // pad PC=5
                               0x5b,       // JUMPDEST PC=6 (reachable)
                               0x00,       // STOP
                               0x5b};      // JUMPDEST PC=8 (dead)
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *Reachable = findBlock(Analyzer, 6);
  assertEntryTop(Reachable, EVMValueRange::U64);
  const auto *Dead = findBlock(Analyzer, 8);
  assertNoEntryState(Dead);
}

TEST(EVMRangeAnalyzer, WorklistTerminates) {
  // Long chain of JUMPDEST blocks linked by constant JUMPs.  The worklist
  // must terminate and every reachable block must have its entry populated.
  // Use 30 chained JUMPDESTs.
  std::vector<uint8_t> Code;
  // Each chain step: JUMPDEST (1 byte) + PUSH1 <next> JUMP (3 bytes) = 4 bytes.
  // Initial entry: PUSH1 <first> JUMP <pad> JUMPDEST ...
  Code.push_back(0x60);
  Code.push_back(0x00); // placeholder for first target
  Code.push_back(0x56);
  Code.push_back(0xfe);                       // pad PC=3
  const size_t FirstJumpDestPC = Code.size(); // 4
  Code[1] = static_cast<uint8_t>(FirstJumpDestPC);
  const int N = 30;
  std::vector<size_t> Pcs;
  for (int I = 0; I < N; ++I) {
    Pcs.push_back(Code.size());
    Code.push_back(0x5b); // JUMPDEST
    if (I < N - 1) {
      Code.push_back(0x60);
      Code.push_back(0x00); // patched
      Code.push_back(0x56); // JUMP
    } else {
      Code.push_back(0x00); // final STOP
    }
  }
  // Patch each PUSH1 target to next JUMPDEST.
  for (int I = 0; I < N - 1; ++I) {
    size_t Push1Operand = Pcs[I] + 2;
    Code[Push1Operand] = static_cast<uint8_t>(Pcs[I + 1]);
  }
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  for (int I = 0; I < N; ++I) {
    const auto *B = findBlock(Analyzer, Pcs[I]);
    ASSERT_NE(B, nullptr) << "block " << I << " missing";
    // Reachable JUMPDESTs should have a resolved depth >=0.
    EXPECT_GE(B->ResolvedEntryStackDepth, 0) << "block " << I;
  }
}

// ---------------------------------------------------------------------------
// Group C — Dynamic-jump-target seeding
// ---------------------------------------------------------------------------

TEST(EVMRangeAnalyzer, DynJumpTargetSeedsU256) {
  // A dynamic JUMP (target loaded from CALLDATALOAD) makes every reachable
  // JUMPDEST in the dyn-jump region a candidate, seeded at U256 by
  // seedRangeEntryVectors.  To observe the seed in EntryStackRanges, the
  // candidate must have a non-zero entry depth: push a residual U64 below
  // the loaded target so that after JUMP pops the target, the candidate's
  // entry depth is 1.
  //
  // PC 0: PUSH1 5      (residual; will be seeded U256 at the dyn target)
  // PC 2: PUSH1 0
  // PC 4: CALLDATALOAD
  // PC 5: JUMP         (dynamic — target unknown)
  // PC 6: JUMPDEST     (candidate; entry depth 1)
  // PC 7: STOP
  std::vector<uint8_t> Code = {0x60, 0x05, // PUSH1 5
                               0x60, 0x00, // PUSH1 0
                               0x35,       // CALLDATALOAD
                               0x56,       // JUMP (PC=5)
                               0x5b,       // JUMPDEST PC=6
                               0x00};      // STOP
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *Jd = findBlock(Analyzer, 6);
  ASSERT_NE(Jd, nullptr);
  // Candidate flag must be set.
  EXPECT_TRUE(Jd->IsDynamicJumpTargetCandidate);
  // With non-zero entry depth, the U256 seed is observable on the top of
  // EntryStackRanges.
  assertEntryTop(Jd, EVMValueRange::U256);
}

TEST(EVMRangeAnalyzer, StaticMeetIntoDynTargetDoesNotNarrow) {
  // A static predecessor pushes a fresh U64 into a JUMPDEST that is also a
  // dynamic-jump-target candidate (because the program contains an
  // unresolved dyn JUMP, which makes every JUMPDEST a candidate).  The
  // dyn-target seed at U256 must NOT be narrowed by the static U64 meet —
  // meet operator is max, so U256 wins.
  //
  // PC 0:  PUSH1 5         (residual; so the dyn-target has entry depth 1)
  // PC 2:  PUSH1 0
  // PC 4:  CALLDATALOAD
  // PC 5:  JUMP            (dynamic)
  // PC 6:  JUMPDEST PC=6   (dyn-cand; entry depth 1, seed U256)
  // PC 7:  POP             (drop seeded slot)
  // PC 8:  PUSH1 6         (fresh U64 on stack)
  // PC 10: PUSH1 13        (static JUMP target)
  // PC 12: JUMP            (static, to PC=13; exit depth 1, slot is U64)
  // PC 13: JUMPDEST PC=13  (dyn-cand AND static target; entry depth 1)
  // PC 14: STOP
  std::vector<uint8_t> Code = {0x60, 0x05, // PUSH1 5
                               0x60, 0x00, // PUSH1 0
                               0x35,       // CALLDATALOAD
                               0x56,       // JUMP (PC=5)
                               0x5b,       // JUMPDEST PC=6
                               0x50,       // POP
                               0x60, 0x06, // PUSH1 6
                               0x60, 0x0d, // PUSH1 13
                               0x56,       // JUMP
                               0x5b,       // JUMPDEST PC=13
                               0x00};      // STOP
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *Target = findBlock(Analyzer, 13);
  ASSERT_NE(Target, nullptr);
  EXPECT_TRUE(Target->IsDynamicJumpTargetCandidate);
  // Even though a static predecessor contributes U64, the dyn-target seed
  // is U256 and meet(U64, U256) = U256.  Entry top stays U256.
  assertEntryTop(Target, EVMValueRange::U256);
}

// ---------------------------------------------------------------------------
// Group D — Boundary / degenerate
// ---------------------------------------------------------------------------

TEST(EVMRangeAnalyzer, TruncatedPushAtTail) {
  // Truncated PUSH32 at the bytecode tail: only 4 immediate bytes are
  // available, but the opcode says 32.  rangeFromPushLiteral treats missing
  // bytes as zero, so the high prefix (first byte 0x01 within the top 16
  // bytes) classifies the literal as U256.  Since the PUSH is at the tail,
  // its result never reaches a JUMPDEST — but the test must verify (a) the
  // analyzer completed without trapping, and (b) the entry block was
  // materialized with a resolved depth (0, since the function entry has no
  // predecessors stacking anything).
  //
  // PC 0: PUSH32 <01 02 03 04> (truncated, no more bytes)
  std::vector<uint8_t> Code = {0x7f, 0x01, 0x02, 0x03, 0x04};
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *Entry = findBlock(Analyzer, 0);
  ASSERT_NE(Entry, nullptr);
  // Entry block was materialized with a resolved depth (0 for the function
  // entry).  The empty ranges follow from depth=0, not from analyzer
  // failure to visit the block.
  EXPECT_GE(Entry->ResolvedEntryStackDepth, 0);
  EXPECT_FALSE(Entry->HasUndefinedInstr);
}

TEST(EVMRangeAnalyzer, UndefinedOpcodeStops) {
  // Spec: a block containing an opcode undefined in Cancun (0x0c) must halt
  // transfer at the undef.  Any textually-following JUMPDEST that is NOT a
  // static JUMP target must therefore remain unreachable — depth -1, empty
  // ranges.  Verifies undef does not silently fall through into adjacent
  // blocks.
  //
  // PC 0: PUSH1 5
  // PC 2: 0x0c       (undefined in Cancun)
  // PC 3: STOP
  // PC 4: JUMPDEST   (textually adjacent, no JUMP targets it)
  // PC 5: STOP
  std::vector<uint8_t> Code = {0x60, 0x05, 0x0c, 0x00, 0x5b, 0x00};
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *Entry = findBlock(Analyzer, 0);
  ASSERT_NE(Entry, nullptr);
  const auto *Successor = findBlock(Analyzer, 4);
  assertNoEntryState(Successor);
}

TEST(EVMRangeAnalyzer, UnresolvedBlockSkipped) {
  // A block that is unreachable from the entry: ResolvedEntryStackDepth
  // stays -1 and EntryStackRanges remains empty after runRangeAnalysis.
  // The simplest unreachable block is a JUMPDEST that no constant JUMP
  // targets.  We don't trigger dynamic-jump-target seeding because there's
  // no JUMP in the program.
  //
  // PC 0: STOP                   (entry block; terminates immediately)
  // PC 1: JUMPDEST  PC=1         (unreachable; no JUMP targets it)
  // PC 2: STOP
  std::vector<uint8_t> Code = {0x00, 0x5b, 0x00};
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  const auto *Jd = findBlock(Analyzer, 1);
  assertNoEntryState(Jd);
}

// Transfer-rule coverage for opcodes that sit in their own switch case with no
// pinned sibling (a regression in their range assignment would otherwise be
// silent). The single stack slot at the JUMPDEST entry is the op's result.

TEST(EVMRangeAnalyzer, ByteResultIsU64) {
  // PUSH1 5; PUSH1 3; BYTE; PUSH1 9; JUMP; INVALID; JUMPDEST(PC 9)
  std::vector<uint8_t> Code = {0x60, 0x05, 0x60, 0x03, 0x1a,
                               0x60, 0x09, 0x56, 0xfe, 0x5b};
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  assertEntryTop(findBlock(Analyzer, 9), EVMValueRange::U64);
}

TEST(EVMRangeAnalyzer, NotResultIsU256) {
  // PUSH1 5; NOT; PUSH1 7; JUMP; INVALID; JUMPDEST(PC 7)
  std::vector<uint8_t> Code = {0x60, 0x05, 0x19, 0x60, 0x07, 0x56, 0xfe, 0x5b};
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  assertEntryTop(findBlock(Analyzer, 7), EVMValueRange::U256);
}

TEST(EVMRangeAnalyzer, ExpResultIsU256) {
  // PUSH1 2; PUSH1 3; EXP; PUSH1 9; JUMP; INVALID; JUMPDEST(PC 9)
  std::vector<uint8_t> Code = {0x60, 0x02, 0x60, 0x03, 0x0a,
                               0x60, 0x09, 0x56, 0xfe, 0x5b};
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  assertEntryTop(findBlock(Analyzer, 9), EVMValueRange::U256);
}

TEST(EVMRangeAnalyzer, SignextendResultIsU256) {
  // PUSH1 0; PUSH1 5; SIGNEXTEND; PUSH1 9; JUMP; INVALID; JUMPDEST(PC 9)
  std::vector<uint8_t> Code = {0x60, 0x00, 0x60, 0x05, 0x0b,
                               0x60, 0x09, 0x56, 0xfe, 0x5b};
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  assertEntryTop(findBlock(Analyzer, 9), EVMValueRange::U256);
}

TEST(EVMRangeAnalyzer, ShlResultIsU256) {
  // PUSH1 1; PUSH1 5; SHL; PUSH1 9; JUMP; INVALID; JUMPDEST(PC 9)
  std::vector<uint8_t> Code = {0x60, 0x01, 0x60, 0x05, 0x1b,
                               0x60, 0x09, 0x56, 0xfe, 0x5b};
  EVMAnalyzer Analyzer = analyzeBytecode(Code);
  assertEntryTop(findBlock(Analyzer, 9), EVMValueRange::U256);
}
