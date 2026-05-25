// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Tests for profile-guided JIT mode correctness.

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
    ASSERT_EQ(EVMC_SET_OPTION_SUCCESS,
              Vm->set_option(Vm, "jit_trigger_calls", "4"));
    ASSERT_EQ(EVMC_SET_OPTION_SUCCESS,
              Vm->set_option(Vm, "jit_trigger_gas", "100"));
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

// First call succeeds via interpreter
TEST_F(EVMProfileGuidedJITTest, FirstCallRunsInInterpreter) {
  auto Code = buildAddContract(0x0A, 0x14); // 10+20=30
  evmc_result R = execute(Code);
  EXPECT_EQ(R.status_code, EVMC_SUCCESS);
  EXPECT_EQ(R.output_size, 32u);
  if (R.output_size == 32)
    EXPECT_EQ(R.output_data[31], 0x1E);
  if (R.release)
    R.release(&R);
}

// Consistent results across interpreter->JIT transition
TEST_F(EVMProfileGuidedJITTest, ConsistentResultsAcrossTransition) {
  auto Code = buildAddContract(0x03, 0x07); // 3+7=10
  for (int I = 0; I < 10; ++I) {
    evmc_result R = execute(Code);
    EXPECT_EQ(R.status_code, EVMC_SUCCESS) << "iter " << I;
    if (R.output_size == 32)
      EXPECT_EQ(R.output_data[31], 0x0A) << "iter " << I;
    if (R.release)
      R.release(&R);
    if (I == 5)
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
}

// JIT triggers and produces correct results
TEST_F(EVMProfileGuidedJITTest, JITTriggersAfterThreshold) {
  auto Code = buildLoopContract(20); // sum = 20
  for (int I = 0; I < 20; ++I) {
    evmc_result R = execute(Code);
    EXPECT_EQ(R.status_code, EVMC_SUCCESS) << "iter " << I;
    if (R.output_size == 32)
      EXPECT_EQ(R.output_data[31], 20) << "iter " << I;
    if (R.release)
      R.release(&R);
    if (I == 5)
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
}

// Small contracts always use interpreter (< kMinJITCodeSize)
TEST_F(EVMProfileGuidedJITTest, SmallContractsSkipJIT) {
  std::vector<uint8_t> Small = {
      0x60, 0x2A, 0x60, 0x00, 0x52, // PUSH 42, PUSH 0, MSTORE
      0x60, 0x20, 0x60, 0x00, 0xF3  // PUSH 32, PUSH 0, RETURN
  };
  for (int I = 0; I < 10; ++I) {
    evmc_result R = execute(Small);
    EXPECT_EQ(R.status_code, EVMC_SUCCESS) << "iter " << I;
    if (R.output_size == 32)
      EXPECT_EQ(R.output_data[31], 0x2A);
    if (R.release)
      R.release(&R);
  }
}

// Gas metering works in both phases
TEST_F(EVMProfileGuidedJITTest, GasMeteringWorks) {
  auto Code = buildAddContract(0x05, 0x0A);
  for (int I = 0; I < 10; ++I) {
    evmc_result R = execute(Code, 1000000);
    EXPECT_EQ(R.status_code, EVMC_SUCCESS);
    EXPECT_GT(R.gas_left, 0);
    EXPECT_LT(R.gas_left, 1000000);
    if (R.release)
      R.release(&R);
    if (I == 5)
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
}
