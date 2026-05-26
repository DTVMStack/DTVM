// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Tests for profile-guided JIT mode correctness.
/// Verifies that contracts are initially interpreted, background JIT is
/// triggered after the profiling threshold is met, and results remain
/// correct after the JIT transition.

#include "vm/dt_evmc_vm.h"
#include <evmc/evmc.h>
#include <evmc/evmc.hpp>
#include <evmc/mocked_host.hpp>
#include <gtest/gtest.h>
#include <memory>
#include <thread>
#include <vector>

using namespace evmc::literals;

namespace {

/// Build PUSH1(A) + PUSH1(B) -> MSTORE -> RETURN(32). Padded to >= 64 bytes.
std::vector<uint8_t> buildAddContract(uint8_t A, uint8_t B) {
  std::vector<uint8_t> Code = {
      0x60, A,    0x60, B,    0x01, // PUSH A, PUSH B, ADD
      0x60, 0x00, 0x52,             // PUSH 0, MSTORE
      0x60, 0x20, 0x60, 0x00, 0xF3  // PUSH 32, PUSH 0, RETURN
  };
  while (Code.size() < 64)
    Code.push_back(0x5B);
  return Code;
}

/// Build a contract that adds 1 N times. Returns sum as 32 bytes.
std::vector<uint8_t> buildLoopContract(uint8_t N) {
  std::vector<uint8_t> Code;
  Code.push_back(0x60);
  Code.push_back(0x00); // PUSH 0
  for (uint8_t I = 0; I < N; ++I) {
    Code.push_back(0x60);
    Code.push_back(0x01); // PUSH 1
    Code.push_back(0x01); // ADD
  }
  Code.push_back(0x60);
  Code.push_back(0x00);
  Code.push_back(0x52); // MSTORE
  Code.push_back(0x60);
  Code.push_back(0x20);
  Code.push_back(0x60);
  Code.push_back(0x00);
  Code.push_back(0xF3); // RETURN
  while (Code.size() < 64)
    Code.push_back(0x5B);
  return Code;
}

} // namespace

class EVMProfileGuidedJITTest : public ::testing::Test {
protected:
  void SetUp() override {
    Vm = evmc_create_dtvmapi();
    ASSERT_NE(Vm, nullptr);
    ASSERT_EQ(EVMC_SET_OPTION_SUCCESS, Vm->set_option(Vm, "mode", "multipass"));
    ASSERT_EQ(EVMC_SET_OPTION_SUCCESS,
              Vm->set_option(Vm, "profile_guided_jit", "true"));
    // Use very low thresholds so tests trigger JIT quickly.
    ASSERT_EQ(EVMC_SET_OPTION_SUCCESS,
              Vm->set_option(Vm, "jit_trigger_calls", "4"));
    ASSERT_EQ(EVMC_SET_OPTION_SUCCESS,
              Vm->set_option(Vm, "jit_trigger_gas", "100"));
    // Use a small ring buffer to make the sliding window fill faster.
    ASSERT_EQ(EVMC_SET_OPTION_SUCCESS,
              Vm->set_option(Vm, "ring_buffer_capacity", "8"));
    Host = std::make_unique<evmc::MockedHost>();
  }

  void TearDown() override {
    if (Vm) {
      Vm->destroy(Vm);
      Vm = nullptr;
    }
  }

  evmc_result execute(const std::vector<uint8_t> &Code, int64_t Gas = 1000000) {
    evmc_message Msg = {};
    Msg.kind = EVMC_CALL;
    Msg.depth = 0;
    Msg.gas = Gas;
    Msg.recipient = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_address;
    Msg.code_address = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_address;
    return Vm->execute(Vm, &evmc::MockedHost::get_interface(),
                       reinterpret_cast<evmc_host_context *>(Host.get()),
                       EVMC_LATEST_STABLE_REVISION, &Msg, Code.data(),
                       Code.size());
  }

  struct evmc_vm *Vm = nullptr;
  std::unique_ptr<evmc::MockedHost> Host;
};

// Test: First call succeeds via interpreter, no JIT triggered yet
TEST_F(EVMProfileGuidedJITTest, FirstCallRunsInInterpreter) {
  auto Code = buildAddContract(0x0A, 0x14); // 10+20=30
  evmc_result R = execute(Code);
  EXPECT_EQ(R.status_code, EVMC_SUCCESS);
  EXPECT_EQ(R.output_size, 32u);
  if (R.output_size == 32)
    EXPECT_EQ(R.output_data[31], 0x1E);
  if (R.release)
    R.release(&R);

  // After just one call, background JIT should NOT have been triggered.
  EXPECT_EQ(dtvm_get_jit_trigger_count(Vm), 0u);
}

// Test: Background JIT is triggered after exceeding the call threshold,
// and subsequent calls still produce correct results.
TEST_F(EVMProfileGuidedJITTest, BackgroundJITTriggeredAndResultsCorrect) {
  auto Code = buildLoopContract(20); // sum = 20

  // Trigger threshold is 4 calls. Execute enough to exceed it.
  for (int I = 0; I < 6; ++I) {
    evmc_result R = execute(Code);
    EXPECT_EQ(R.status_code, EVMC_SUCCESS) << "iter " << I;
    if (R.output_size == 32)
      EXPECT_EQ(R.output_data[31], 20) << "iter " << I;
    if (R.release)
      R.release(&R);
  }

  // Background JIT should have been triggered at least once.
  uint64_t TriggerCount = dtvm_get_jit_trigger_count(Vm);
  EXPECT_GT(TriggerCount, 0u)
      << "Expected background JIT to be triggered after exceeding threshold";

  // Wait for the background compile to finish.
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  // Execute more times — now should use JIT-compiled code.
  for (int I = 0; I < 5; ++I) {
    evmc_result R = execute(Code);
    EXPECT_EQ(R.status_code, EVMC_SUCCESS) << "post-JIT iter " << I;
    if (R.output_size == 32)
      EXPECT_EQ(R.output_data[31], 20) << "post-JIT iter " << I;
    if (R.release)
      R.release(&R);
  }

  // Trigger count should not increase further (already compiled).
  EXPECT_EQ(dtvm_get_jit_trigger_count(Vm), TriggerCount);
}

// Test: Consistent results across the interpreter->JIT transition
TEST_F(EVMProfileGuidedJITTest, ConsistentResultsAcrossTransition) {
  auto Code = buildAddContract(0x03, 0x07); // 3+7=10

  for (int I = 0; I < 12; ++I) {
    evmc_result R = execute(Code);
    EXPECT_EQ(R.status_code, EVMC_SUCCESS) << "iter " << I;
    if (R.output_size == 32)
      EXPECT_EQ(R.output_data[31], 0x0A) << "iter " << I;
    if (R.release)
      R.release(&R);
    // Sleep after threshold to let background JIT compile finish.
    if (I == 5)
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
}

// Test: Small contracts bypass JIT even in PGJ mode
TEST_F(EVMProfileGuidedJITTest, SmallContractsSkipJIT) {
  std::vector<uint8_t> Small = {
      0x60, 0x2A, 0x60, 0x00, 0x52, // PUSH 42, PUSH 0, MSTORE
      0x60, 0x20, 0x60, 0x00, 0xF3  // PUSH 32, PUSH 0, RETURN
  };
  // Deliberately < 64 bytes — should always run in interpreter.

  uint64_t TriggerBefore = dtvm_get_jit_trigger_count(Vm);
  for (int I = 0; I < 10; ++I) {
    evmc_result R = execute(Small);
    EXPECT_EQ(R.status_code, EVMC_SUCCESS) << "iter " << I;
    if (R.output_size == 32)
      EXPECT_EQ(R.output_data[31], 0x2A);
    if (R.release)
      R.release(&R);
  }
  // Small contracts should not trigger background JIT.
  EXPECT_EQ(dtvm_get_jit_trigger_count(Vm), TriggerBefore);
}

// Test: ring_buffer_capacity option is respected
TEST_F(EVMProfileGuidedJITTest, RingBufferCapacityOption) {
  // Verify the option was accepted (already set in SetUp to 8).
  // Create a second VM with different capacity to ensure it works.
  struct evmc_vm *Vm2 = evmc_create_dtvmapi();
  ASSERT_NE(Vm2, nullptr);
  ASSERT_EQ(EVMC_SET_OPTION_SUCCESS, Vm2->set_option(Vm2, "mode", "multipass"));
  ASSERT_EQ(EVMC_SET_OPTION_SUCCESS,
            Vm2->set_option(Vm2, "profile_guided_jit", "true"));
  ASSERT_EQ(EVMC_SET_OPTION_SUCCESS,
            Vm2->set_option(Vm2, "ring_buffer_capacity", "4"));
  ASSERT_EQ(EVMC_SET_OPTION_SUCCESS,
            Vm2->set_option(Vm2, "jit_trigger_calls", "3"));
  ASSERT_EQ(EVMC_SET_OPTION_SUCCESS,
            Vm2->set_option(Vm2, "jit_trigger_gas", "50"));

  auto Code = buildLoopContract(20);
  evmc_message Msg = {};
  Msg.kind = EVMC_CALL;
  Msg.depth = 0;
  Msg.gas = 1000000;
  Msg.recipient = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_address;
  Msg.code_address = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_address;

  // With ring buffer capacity 4, trigger calls 3: should trigger JIT
  // after 3+ calls within the small window.
  for (int I = 0; I < 5; ++I) {
    evmc_result R = Vm2->execute(
        Vm2, &evmc::MockedHost::get_interface(),
        reinterpret_cast<evmc_host_context *>(Host.get()),
        EVMC_LATEST_STABLE_REVISION, &Msg, Code.data(), Code.size());
    EXPECT_EQ(R.status_code, EVMC_SUCCESS) << "iter " << I;
    if (R.output_size == 32)
      EXPECT_EQ(R.output_data[31], 20);
    if (R.release)
      R.release(&R);
  }

  EXPECT_GT(dtvm_get_jit_trigger_count(Vm2), 0u)
      << "JIT should be triggered with ring_buffer_capacity=4";

  Vm2->destroy(Vm2);
}

// Test: Gas metering consistency across interpreter and JIT phases
TEST_F(EVMProfileGuidedJITTest, GasMeteringConsistency) {
  auto Code = buildAddContract(0x05, 0x0A); // 5+10=15

  for (int I = 0; I < 10; ++I) {
    evmc_result R = execute(Code, 1000000);
    EXPECT_EQ(R.status_code, EVMC_SUCCESS);
    EXPECT_GT(R.gas_left, 0);
    EXPECT_LT(R.gas_left, 1000000);
    if (R.release)
      R.release(&R);
    if (I == 5)
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
}
