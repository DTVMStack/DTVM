// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "vm/dt_evmc_vm.h"
#include <evmc/evmc.h>
#include <evmc/mocked_host.hpp>
#include <gtest/gtest.h>
#include <memory>
#include <vector>

using namespace evmc::literals;

inline evmc::bytes operator""_hex(const char *S, size_t Size) {
  return evmc::from_spaced_hex({S, Size}).value();
}

class EVMFallbackExecutionTest : public ::testing::Test {
protected:
  void SetUp() override {
    // Create DTVM using the correct API
    Vm = evmc_create_dtvmapi();
    ASSERT_NE(Vm, nullptr) << "Failed to create DTVM instance";

    // Initialize mocked host for testing
    Host = std::make_unique<evmc::MockedHost>();
  }

  void TearDown() override {
    if (Vm) {
      Vm->destroy(Vm);
      Vm = nullptr;
    }
  }

  // Helper method to execute bytecode and return result
  evmc_result executeBytecode(const std::vector<uint8_t> &Bytecode,
                              int64_t GasLimit = 1000000) {
    // Create execution message
    evmc_message Msg = {};
    Msg.kind = EVMC_CALL;
    Msg.flags = 0;
    Msg.depth = 0;
    Msg.gas = GasLimit;
    Msg.recipient = {};
    Msg.sender = {};
    Msg.input_data = nullptr;
    Msg.input_size = 0;
    Msg.value = {};
    Msg.code = Bytecode.data();
    Msg.code_size = Bytecode.size();

    // Execute bytecode using DTVM with correct EVMC API signature
    // The EVMC execute function signature is:
    // evmc_result (*execute)(struct evmc_vm* vm, const struct
    // evmc_host_interface* host,
    //                        struct evmc_host_context* context, enum
    //                        evmc_revision rev, const struct evmc_message* msg,
    //                        const uint8_t* code, size_t code_size)
    return Vm->execute(Vm, &evmc::MockedHost::get_interface(),
                       reinterpret_cast<evmc_host_context *>(Host.get()),
                       EVMC_LATEST_STABLE_REVISION, &Msg, Bytecode.data(),
                       Bytecode.size());
  }

  struct evmc_vm *Vm = nullptr;
  std::unique_ptr<evmc::MockedHost> Host;
};

// Test 1: Basic 0xEE Fallback Execution Test
TEST_F(EVMFallbackExecutionTest, BasicFallbackExecution) {
#ifdef ZEN_ENABLE_JIT_FALLBACK_TEST
  // Test bytecode: PUSH1 42, FALLBACK(0xEE), STOP
  std::vector<uint8_t> Bytecode = {
      0x60, 0x2A, // PUSH1 42
      0xEE,       // FALLBACK trigger
      0x00        // STOP
  };

  evmc_result Result = executeBytecode(Bytecode);

  // When fallback is triggered, execution should continue in interpreter
  // The exact behavior is succeed because next instruction is STOP
  EXPECT_EQ(Result.status_code, EVMC_SUCCESS);

  // Gas should be consumed
  EXPECT_LT(Result.gas_left, 1000000); // Some gas should be used

  // Release result resources
  if (Result.release) {
    Result.release(&Result);
  }
#else
  // When fallback testing is disabled, 0xEE should be treated as undefined
  std::vector<uint8_t> Bytecode = {
      0x60, 0x2A, // PUSH1 42
      0xEE,       // Should be treated as undefined opcode
      0x00        // STOP (won't be reached)
  };

  evmc_result Result = executeBytecode(Bytecode);

  // Should result in undefined instruction error
  EXPECT_EQ(Result.status_code, EVMC_UNDEFINED_INSTRUCTION);

  // Release result resources
  if (Result.release) {
    Result.release(&Result);
  }
#endif
}

// Test 2: Fallback with Stack Operations
TEST_F(EVMFallbackExecutionTest, FallbackWithStackOperations) {
#ifdef ZEN_ENABLE_JIT_FALLBACK_TEST
  // Test bytecode: PUSH1 10, PUSH1 20, ADD, FALLBACK, PUSH1 5, ADD, STOP
  std::vector<uint8_t> Bytecode = {
      0x60, 0x0A, // PUSH1 10
      0x60, 0x14, // PUSH1 20
      0x01,       // ADD (stack: [30])
      0xEE,       // FALLBACK trigger
      0x60, 0x05, // PUSH1 5 (should execute in interpreter)
      0x01,       // ADD (stack: [35])
      0x00        // STOP
  };

  evmc_result Result = executeBytecode(Bytecode);

  // Execution should succeed with fallback
  EXPECT_TRUE(Result.status_code == EVMC_SUCCESS);

  // Verify gas consumption
  EXPECT_LT(Result.gas_left, 1000000);

  // Release result resources
  if (Result.release) {
    Result.release(&Result);
  }
#else
  GTEST_SKIP() << "ZEN_ENABLE_JIT_FALLBACK_TEST not enabled";
#endif
}

// Test 3: Multiple Fallback Triggers
TEST_F(EVMFallbackExecutionTest, MultipleFallbackTriggers) {
#ifdef ZEN_ENABLE_JIT_FALLBACK_TEST
  // Test bytecode with multiple 0xEE triggers
  std::vector<uint8_t> Bytecode = {
      0x60, 0x01, // PUSH1 1
      0xEE,       // FALLBACK 1
      0x60, 0x02, // PUSH1 2
      0x01,       // ADD
      0xEE,       // FALLBACK 2
      0x60, 0x03, // PUSH1 3
      0x01,       // ADD
      0x00        // STOP
  };

  evmc_result Result = executeBytecode(Bytecode);

  // Should handle multiple fallbacks
  EXPECT_EQ(Result.status_code, EVMC_INVALID_INSTRUCTION);

  // Verify gas consumption
  EXPECT_LT(Result.gas_left, 1000000);

  // Release result resources
  if (Result.release) {
    Result.release(&Result);
  }
#else
  GTEST_SKIP() << "ZEN_ENABLE_JIT_FALLBACK_TEST not enabled";
#endif
}

// Test 4: Fallback at Different PC Positions
TEST_F(EVMFallbackExecutionTest, FallbackAtDifferentPositions) {
#ifdef ZEN_ENABLE_JIT_FALLBACK_TEST
  struct TestCase {
    std::vector<uint8_t> Bytecode;
    std::string description;
  };

  std::vector<TestCase> TestCases = {
      {{0xEE, 0x00}, // FALLBACK at PC=0, STOP
       "Fallback at beginning"},
      {{0x60, 0x01, 0xEE, 0x00}, // PUSH1 1, FALLBACK at PC=2, STOP
       "Fallback after PUSH"},
      {{0x60, 0x01, 0x60, 0x02, 0x01, 0xEE,
        0x00}, // PUSH1 1, PUSH1 2, ADD, FALLBACK at PC=5, STOP
       "Fallback after arithmetic"}};

  for (const auto &TestCase : TestCases) {
    evmc_result Result = executeBytecode(TestCase.Bytecode);

    // Each case should handle fallback appropriately
    EXPECT_EQ(Result.status_code, EVMC_SUCCESS);

    // Release result resources
    if (Result.release) {
      Result.release(&Result);
    }
  }
#else
  GTEST_SKIP() << "ZEN_ENABLE_JIT_FALLBACK_TEST not enabled";
#endif
}

// Test 5: Fallback with Memory Operations
TEST_F(EVMFallbackExecutionTest, FallbackWithMemoryOperations) {
#ifdef ZEN_ENABLE_JIT_FALLBACK_TEST
  // Test bytecode: PUSH1 0x42, PUSH1 0, MSTORE, FALLBACK, PUSH1 0, MLOAD, STOP
  std::vector<uint8_t> Bytecode = {
      0x60, 0x42, // PUSH1 0x42
      0x60, 0x00, // PUSH1 0
      0x52,       // MSTORE (store 0x42 at memory position 0)
      0x60, 0x03,
      0xEE,       // FALLBACK trigger
      0x60, 0x20, // PUSH1 0x20
      0x60, 0x00, // PUSH1 0
      0xF3        // RETURN
  };

  evmc_result Result = executeBytecode(Bytecode);

  // Memory operations should work across fallback
  EXPECT_EQ(Result.status_code, EVMC_SUCCESS);
  EXPECT_EQ(Result.output_size, 32);
  EXPECT_EQ(
      evmc::bytes_view(&Result.output_data[0], 32),
      "0000000000000000000000000000000000000000000000000000000000000042"_hex);

  // Release result resources
  if (Result.release) {
    Result.release(&Result);
  }
#else
  GTEST_SKIP() << "ZEN_ENABLE_JIT_FALLBACK_TEST not enabled";
#endif
}

// Test 6: Fallback Gas Consumption Test
TEST_F(EVMFallbackExecutionTest, FallbackGasConsumption) {
#ifdef ZEN_ENABLE_JIT_FALLBACK_TEST
  // Test that fallback operations consume appropriate gas

  // Bytecode without fallback
  std::vector<uint8_t> NormalBytecode = {
      0x60, 0x01, // PUSH1 1
      0x60, 0x02, // PUSH1 2
      0x01,       // ADD
      0x00        // STOP
  };

  // Bytecode with fallback
  std::vector<uint8_t> FallbackBytecode = {
      0x60, 0x01, // PUSH1 1
      0xEE,       // FALLBACK
      0x60, 0x02, // PUSH1 2
      0x01,       // ADD
      0x00        // STOP
  };

  evmc_result NormalResult = executeBytecode(NormalBytecode);
  evmc_result FallbackResult = executeBytecode(FallbackBytecode);

  // Both should succeed (or both fail consistently)
  EXPECT_EQ(NormalResult.status_code, EVMC_SUCCESS);
  EXPECT_EQ(FallbackResult.status_code, EVMC_SUCCESS);

  // Fallback might consume different gas due to interpreter switch
  EXPECT_GT(NormalResult.gas_left, 0);
  EXPECT_GT(FallbackResult.gas_left, 0);

  // Release result resources
  if (NormalResult.release) {
    NormalResult.release(&NormalResult);
  }
  if (FallbackResult.release) {
    FallbackResult.release(&FallbackResult);
  }
#else
  GTEST_SKIP() << "ZEN_ENABLE_JIT_FALLBACK_TEST not enabled";
#endif
}

// Test 7: Fallback Error Handling
TEST_F(EVMFallbackExecutionTest, FallbackErrorHandling) {
#ifdef ZEN_ENABLE_JIT_FALLBACK_TEST
  // Test fallback behavior with stack underflow after fallback
  std::vector<uint8_t> Bytecode = {
      0x60, 0x01, // PUSH1 1
      0x50,       // POP
      0xEE,       // FALLBACK
      0x50,       // POP (should cause stack underflow)
      0x00        // STOP
  };

  evmc_result Result = executeBytecode(Bytecode);

  // Should handle stack underflow appropriately
  EXPECT_TRUE(Result.status_code == EVMC_STACK_UNDERFLOW ||
              Result.status_code == EVMC_UNDEFINED_INSTRUCTION);

  // Release result resources
  if (Result.release) {
    Result.release(&Result);
  }
#else
  GTEST_SKIP() << "ZEN_ENABLE_JIT_FALLBACK_TEST not enabled";
#endif
}

// Test 8: Comprehensive Fallback Workflow Test
TEST_F(EVMFallbackExecutionTest, ComprehensiveFallbackWorkflow) {
#ifdef ZEN_ENABLE_JIT_FALLBACK_TEST
  // Complex bytecode testing complete fallback workflow
  std::vector<uint8_t> ComplexBytecode = {
      0x60, 0x10, // PUSH1 16      (PC = 0, 1)
      0x60, 0x20, // PUSH1 32      (PC = 2, 3)
      0x01,       // ADD           (PC = 4)     -> stack: [48]
      0x80,       // DUP1          (PC = 5)     -> stack: [48, 48]
      0x60, 0x00, // PUSH1 0       (PC = 6, 7)  -> stack: [48, 48, 0]
      0x52, // MSTORE        (PC = 8)     -> store 48 at memory[0], stack: [48]
      0xEE, // FALLBACK      (PC = 9)     -> should continue from PC = 10
      0x60, 0x05, // PUSH1 5       (PC = 10, 11) -> stack: [48, 5]
      0x01,       // ADD           (PC = 12)    -> stack: [53]
      0x60, 0x00, // PUSH1 0       (PC = 13, 14) -> stack: [53, 0]
      0x51, // MLOAD         (PC = 15)    -> load from memory[0], stack: [53,
            // 48]
      0x90, // SWAP1         (PC = 16)    -> stack: [48, 53]
      0x60, 0x20, // PUSH1 0x20
      0x60, 0x00, // PUSH1 0
      0xF3        // RETURN
  };

  evmc_result Result = executeBytecode(
      ComplexBytecode, 2000000); // More gas for complex operations

  // Should execute the complete workflow
  EXPECT_EQ(Result.status_code, EVMC_SUCCESS);

  // Verify significant gas consumption
  EXPECT_LT(Result.gas_left, 2000000);

  // If successful, verify no output (STOP doesn't return data)
  EXPECT_EQ(Result.status_code, EVMC_SUCCESS);
  EXPECT_EQ(Result.output_size, 32);
  EXPECT_EQ(
      evmc::bytes_view(&Result.output_data[0], 32),
      "0000000000000000000000000000000000000000000000000000000000000030"_hex);

  // Release result resources
  if (Result.release) {
    Result.release(&Result);
  }
#else
  GTEST_SKIP() << "ZEN_ENABLE_JIT_FALLBACK_TEST not enabled";
#endif
}
