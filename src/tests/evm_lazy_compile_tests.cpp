// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/evm_lazy_compiler.h"
#include "runtime/evm_module.h"
#include "vm/dt_evmc_vm.h"
#include <cstddef>
#include <evmc/evmc.h>
#include <evmc/mocked_host.hpp>
#include <gtest/gtest.h>
#include <memory>
#include <vector>

using namespace evmc::literals;
using namespace COMPILER;

inline evmc::bytes operator""_hex(const char *S, size_t Size) {
  return evmc::from_spaced_hex({S, Size}).value();
}

/// Test fixture for EVM Lazy Compilation tests
class EVMLazyCompileTest : public ::testing::Test {
protected:
  void SetUp() override { Host = std::make_unique<evmc::MockedHost>(); }

  void TearDown() override { Host.reset(); }

  std::unique_ptr<evmc::MockedHost> Host;
};

// Test 1: EVMSegmentAnalyzer - Basic segment analysis
TEST_F(EVMLazyCompileTest, SegmentAnalyzerBasic) {
  // Simple bytecode: PUSH1 0x01, PUSH1 0x02, ADD, STOP
  // No JUMPDEST, so only 1 segment starting at PC=0
  std::vector<uint8_t> Bytecode = {
      0x60, 0x01, // PUSH1 0x01
      0x60, 0x02, // PUSH1 0x02
      0x01,       // ADD
      0x00        // STOP
  };

  EVMSegmentAnalyzer Analyzer;
  Analyzer.analyze(reinterpret_cast<const std::byte *>(Bytecode.data()),
                   Bytecode.size(), EVMC_OSAKA);

  EXPECT_EQ(Analyzer.getNumSegments(), 1u);
  EXPECT_EQ(Analyzer.getSegmentIdxForPC(0), 0u);
}

// Test 2: EVMSegmentAnalyzer - Multiple segments with JUMPDEST
TEST_F(EVMLazyCompileTest, SegmentAnalyzerWithJumpDest) {
  // Bytecode with JUMPDEST:
  // PC 0: PUSH1 0x05  (jump target)
  // PC 2: JUMP
  // PC 3: JUMPDEST    (segment 1 starts here)
  // PC 4: PUSH1 0x01
  // PC 6: STOP
  std::vector<uint8_t> Bytecode = {
      0x60, 0x05, // PUSH1 0x05 (push jump destination)
      0x56,       // JUMP
      0x5B,       // JUMPDEST (segment boundary)
      0x60, 0x01, // PUSH1 0x01
      0x00        // STOP
  };

  EVMSegmentAnalyzer Analyzer;
  Analyzer.analyze(reinterpret_cast<const std::byte *>(Bytecode.data()),
                   Bytecode.size(), EVMC_OSAKA);

  // Should have at least 1 segment (entry at PC=0)
  EXPECT_GE(Analyzer.getNumSegments(), 1u);

  // PC=0 should map to segment 0
  EXPECT_EQ(Analyzer.getSegmentIdxForPC(0), 0u);

  // PC=3 (JUMPDEST) should map to a valid segment
  EXPECT_NE(Analyzer.getSegmentIdxForPC(3), UINT32_MAX);
}

// Test 3: EVMSegmentAnalyzer - Empty bytecode
TEST_F(EVMLazyCompileTest, SegmentAnalyzerEmptyBytecode) {
  std::vector<uint8_t> Bytecode;

  EVMSegmentAnalyzer Analyzer;
  Analyzer.analyze(reinterpret_cast<const std::byte *>(Bytecode.data()),
                   Bytecode.size(), EVMC_OSAKA);

  EXPECT_EQ(Analyzer.getNumSegments(), 0u);
}

// Test 4: EVMSegmentAnalyzer - Single JUMPDEST at beginning
TEST_F(EVMLazyCompileTest, SegmentAnalyzerJumpDestAtStart) {
  // JUMPDEST at PC=0, then STOP
  std::vector<uint8_t> Bytecode = {
      0x5B, // JUMPDEST
      0x00  // STOP
  };

  EVMSegmentAnalyzer Analyzer;
  Analyzer.analyze(reinterpret_cast<const std::byte *>(Bytecode.data()),
                   Bytecode.size(), EVMC_OSAKA);

  EXPECT_GE(Analyzer.getNumSegments(), 1u);
  EXPECT_EQ(Analyzer.getSegmentIdxForPC(0), 0u);
}

// Test 5: EVMSegmentAnalyzer - Complex control flow
TEST_F(EVMLazyCompileTest, SegmentAnalyzerComplexControlFlow) {
  // Bytecode with multiple JUMPDESTs
  // PC 0-1: PUSH1 0x0A (condition)
  // PC 2-3: PUSH1 0x08 (jump destination = PC of JUMPDEST)
  // PC 4:   JUMPI (conditional jump)
  // PC 5-6: PUSH1 0x01
  // PC 7:   STOP
  // PC 8:   JUMPDEST (target)
  // PC 9-10: PUSH1 0x02
  // PC 11:  STOP
  std::vector<uint8_t> Bytecode = {
      0x60, 0x0A, // PUSH1 0x0A (condition)
      0x60, 0x08, // PUSH1 0x08 (jump destination)
      0x57,       // JUMPI
      0x60, 0x01, // PUSH1 0x01
      0x00,       // STOP
      0x5B,       // JUMPDEST
      0x60, 0x02, // PUSH1 0x02
      0x00        // STOP
  };

  EVMSegmentAnalyzer Analyzer;
  Analyzer.analyze(reinterpret_cast<const std::byte *>(Bytecode.data()),
                   Bytecode.size(), EVMC_OSAKA);

  // Should have multiple segments
  EXPECT_GE(Analyzer.getNumSegments(), 2u);

  // Verify PC to segment mapping
  EXPECT_EQ(Analyzer.getSegmentIdxForPC(0), 0u);
  EXPECT_NE(Analyzer.getSegmentIdxForPC(8), UINT32_MAX); // JUMPDEST at PC=8
}

// Test 6: EVMSegmentAnalyzer - PUSH with JUMPDEST data
TEST_F(EVMLazyCompileTest, SegmentAnalyzerPushWithJumpDestData) {
  // PUSH32 with 0x5B (JUMPDEST opcode) as data - should NOT create segment
  std::vector<uint8_t> Bytecode = {
      0x7F,                                           // PUSH32
      0x5B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x5B is data, not
                                                      // opcode
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00 // STOP
  };

  EVMSegmentAnalyzer Analyzer;
  Analyzer.analyze(reinterpret_cast<const std::byte *>(Bytecode.data()),
                   Bytecode.size(), EVMC_OSAKA);

  // Should only have 1 segment (entry), 0x5B inside PUSH data is not a JUMPDEST
  EXPECT_EQ(Analyzer.getNumSegments(), 1u);
}

// Test 7: Segment info validation
TEST_F(EVMLazyCompileTest, SegmentInfoValidation) {
  // Bytecode: JUMPDEST at PC=4
  std::vector<uint8_t> Bytecode = {
      0x60, 0x01, // PUSH1 0x01 (PC 0-1)
      0x60, 0x02, // PUSH1 0x02 (PC 2-3)
      0x5B,       // JUMPDEST (PC 4)
      0x00        // STOP (PC 5)
  };

  EVMSegmentAnalyzer Analyzer;
  Analyzer.analyze(reinterpret_cast<const std::byte *>(Bytecode.data()),
                   Bytecode.size(), EVMC_OSAKA);

  const auto &Segments = Analyzer.getSegments();

  // Validate segment properties
  for (const auto &Seg : Segments) {
    EXPECT_LT(Seg.StartPC, Seg.EndPC); // Start must be before end
    EXPECT_EQ(Seg.SegmentIdx, Analyzer.getSegmentIdxForPC(Seg.StartPC));

    // Entry segment should be at PC=0
    if (Seg.IsEntry) {
      EXPECT_EQ(Seg.StartPC, 0u);
    }
  }
}

// Test 8: Invalid PC returns UINT32_MAX
TEST_F(EVMLazyCompileTest, SegmentAnalyzerInvalidPC) {
  std::vector<uint8_t> Bytecode = {
      0x60, 0x01, // PUSH1 0x01
      0x00        // STOP
  };

  EVMSegmentAnalyzer Analyzer;
  Analyzer.analyze(reinterpret_cast<const std::byte *>(Bytecode.data()),
                   Bytecode.size(), EVMC_OSAKA);

  // Invalid PC should return UINT32_MAX
  EXPECT_EQ(Analyzer.getSegmentIdxForPC(1000), UINT32_MAX);
  EXPECT_EQ(Analyzer.getSegmentIdxForPC(static_cast<uint32_t>(-1)), UINT32_MAX);
}

// Test 9: Large bytecode with many JUMPDESTs
TEST_F(EVMLazyCompileTest, SegmentAnalyzerLargeBytecode) {
  // Create bytecode with multiple JUMPDESTs
  std::vector<uint8_t> Bytecode;

  // Add some PUSH instructions
  for (int i = 0; i < 10; ++i) {
    Bytecode.push_back(0x60); // PUSH1
    Bytecode.push_back(static_cast<uint8_t>(i));
  }

  // Add JUMPDEST every 10 bytes
  for (int i = 0; i < 5; ++i) {
    Bytecode.push_back(0x5B); // JUMPDEST
    Bytecode.push_back(0x60); // PUSH1
    Bytecode.push_back(static_cast<uint8_t>(i));
  }

  Bytecode.push_back(0x00); // STOP

  EVMSegmentAnalyzer Analyzer;
  Analyzer.analyze(reinterpret_cast<const std::byte *>(Bytecode.data()),
                   Bytecode.size(), EVMC_OSAKA);

  // Should have multiple segments
  EXPECT_GT(Analyzer.getNumSegments(), 1u);

  // Verify all JUMPDEST PCs are mapped
  for (size_t i = 20; i < 30; i += 3) {
    if (Bytecode[i] == 0x5B) {
      EXPECT_NE(Analyzer.getSegmentIdxForPC(static_cast<uint32_t>(i)),
                UINT32_MAX);
    }
  }
}

// Test 10: Consistency between getNumSegments and getSegments
TEST_F(EVMLazyCompileTest, SegmentAnalyzerConsistency) {
  std::vector<uint8_t> Bytecode = {
      0x5B,       // JUMPDEST (PC 0)
      0x60, 0x01, // PUSH1 0x01
      0x5B,       // JUMPDEST (PC 3)
      0x60, 0x02, // PUSH1 0x02
      0x00        // STOP
  };

  EVMSegmentAnalyzer Analyzer;
  Analyzer.analyze(reinterpret_cast<const std::byte *>(Bytecode.data()),
                   Bytecode.size(), EVMC_OSAKA);

  EXPECT_EQ(Analyzer.getNumSegments(), Analyzer.getSegments().size());
}
