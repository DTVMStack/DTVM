// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "compiler/evm_frontend/evm_analyzer.h"
#include "evm/evm.h"
#include "evm_test_host.hpp"
#include "runtime/evm_module.h"
#include "utils/evm.h"
#include "zetaengine.h"

using namespace zen;
using namespace zen::evm;
using namespace zen::runtime;

#ifdef ZEN_ENABLE_MULTIPASS_JIT

namespace {

std::filesystem::path getEvmAsmDirPath() {
  return std::filesystem::path(__FILE__).parent_path() /
         std::filesystem::path("../../tests/evm_asm");
}

void appendHexByte(std::string &Out, uint8_t Byte) {
  constexpr char Hex[] = "0123456789abcdef";
  Out.push_back(Hex[Byte >> 4]);
  Out.push_back(Hex[Byte & 0x0f]);
}

std::string
logsSignature(const std::vector<evmc::MockedHost::log_record> &Logs) {
  std::string Out;
  Out += std::to_string(Logs.size());
  Out.push_back('|');
  for (const auto &Log : Logs) {
    for (uint8_t Byte : Log.creator.bytes) {
      appendHexByte(Out, Byte);
    }
    Out.push_back(':');
    for (const auto &Topic : Log.topics) {
      for (uint8_t Byte : Topic.bytes) {
        appendHexByte(Out, Byte);
      }
      Out.push_back(',');
    }
    Out.push_back(':');
    for (uint8_t Byte : Log.data) {
      appendHexByte(Out, Byte);
    }
    Out.push_back('|');
  }
  return Out;
}

struct EVMExecutionResult {
  evmc_status_code Status = EVMC_INTERNAL_ERROR;
  int64_t GasLeft = 0;
  std::string OutputHex;
  std::string LogsSignature;
  size_t LogCount = 0;
  bool JITCompiled = false;
};

// Run `Bytecode` in `Mode`, forcing synchronous multipass compilation so the
// multipass run actually executes JIT code. The default async/multithread
// config can fall back to the interpreter for a single call, which would make
// a differential test vacuous; DisableMultipassMultithread compiles before the
// run so the JIT side is non-vacuous.
EVMExecutionResult runEvmBytecode(
    const std::string &Label, const std::vector<uint8_t> &Bytecode,
    common::RunMode Mode, const std::vector<uint8_t> &CallData = {},
    uint32_t MessageFlags = 0u, bool EnableGasMetering = false,
    uint64_t GasLimit = 0xFFFF'FFFF'FFFF - zen::evm::BASIC_EXECUTION_COST,
    evmc_revision Revision = evmc_revision::EVMC_OSAKA) {
  EVMExecutionResult Empty;

  RuntimeConfig Config;
  Config.Mode = Mode;
  Config.DisableMultipassMultithread = true; // compile before run -> JIT used
  Config.EnableEvmGasMetering = EnableGasMetering;

  auto MockedHost = std::make_unique<zen::evm::ZenMockedEVMHost>();
  MockedHost->tx_context.tx_origin = zen::evm::DEFAULT_DEPLOYER_ADDRESS;
  auto RT = Runtime::newEVMRuntime(Config, MockedHost.get());
  if (!RT) {
    ADD_FAILURE() << "runtime create failed: " << Label;
    return Empty;
  }
  MockedHost->setRuntime(RT.get());

  auto ModRet =
      RT->loadEVMModule(Label, Bytecode.data(), Bytecode.size(), Revision);
  if (!ModRet) {
    ADD_FAILURE() << "module load failed: " << Label;
    return Empty;
  }
  EVMModule *Mod = *ModRet;

  Isolation *Iso = RT->createManagedIsolation();
  if (!Iso) {
    ADD_FAILURE() << "isolation create failed: " << Label;
    return Empty;
  }

  auto InstRet = Iso->createEVMInstance(*Mod, GasLimit);
  if (!InstRet) {
    ADD_FAILURE() << "instance create failed: " << Label;
    return Empty;
  }
  EVMInstance *Inst = *InstRet;
  Inst->setRevision(Revision);

  evmc_message Msg = {
      .kind = EVMC_CALL,
      .flags = MessageFlags,
      .depth = 0,
      .gas = static_cast<int64_t>(GasLimit),
      .recipient = {},
      .sender = zen::evm::DEFAULT_DEPLOYER_ADDRESS,
      .input_data = CallData.empty() ? nullptr : CallData.data(),
      .input_size = CallData.size(),
      .value = {},
      .create2_salt = {},
      .code_address = {},
      .code = reinterpret_cast<const uint8_t *>(Mod->Code),
      .code_size = Mod->CodeSize,
  };

  evmc::Result RawResult;
  EVMExecutionResult Exec;
#ifdef ZEN_ENABLE_JIT
  Exec.JITCompiled = Mod->getJITCode() != nullptr && Mod->getJITCodeSize() > 0;
#endif
  EXPECT_NO_THROW({ RT->callEVMMain(*Inst, Msg, RawResult); });
  Exec.Status = RawResult.status_code;
  Exec.GasLeft = RawResult.gas_left;
  Exec.OutputHex =
      zen::utils::toHex(RawResult.output_data, RawResult.output_size);
  Exec.LogCount = MockedHost->recorded_logs.size();
  Exec.LogsSignature = logsSignature(MockedHost->recorded_logs);
  return Exec;
}

EVMExecutionResult
runEvmBytecodeFile(const std::string &FilePath, common::RunMode Mode,
                   const std::vector<uint8_t> &CallData = {}) {
  EVMExecutionResult Empty;

  std::ifstream Fin(FilePath);
  if (!Fin.is_open()) {
    ADD_FAILURE() << "Failed to open test file: " << FilePath;
    return Empty;
  }

  std::string Hex;
  Fin >> Hex;
  zen::utils::trimString(Hex);
  auto BytecodeBuf = zen::utils::fromHex(Hex);
  if (!BytecodeBuf) {
    ADD_FAILURE() << "Failed to convert hex to bytecode: " << FilePath;
    return Empty;
  }

  return runEvmBytecode(FilePath, *BytecodeBuf, Mode, CallData);
}

// Run `Bytecode` through interpreter and multipass, assert the interpreter
// run succeeds (a shared failure such as out-of-gas would make the comparison
// vacuous), the multipass JIT compiled, and that status + output agree.
// Returns false on any violation so matrix callers can stop flooding output.
bool expectInterpMatchesMultipass(const std::string &Label,
                                  const std::vector<uint8_t> &Bytecode,
                                  const std::vector<uint8_t> &CallData) {
  auto Interp = runEvmBytecode(Label + "_interp", Bytecode,
                               common::RunMode::InterpMode, CallData);
  auto Multi = runEvmBytecode(Label + "_multipass", Bytecode,
                              common::RunMode::MultipassMode, CallData);
#ifdef ZEN_ENABLE_JIT
  EXPECT_TRUE(Multi.JITCompiled) << "multipass did not JIT-compile: " << Label;
#endif
  EXPECT_EQ(Interp.Status, EVMC_SUCCESS)
      << "interpreter did not succeed: " << Label;
  EXPECT_EQ(Multi.Status, Interp.Status) << "status diverged: " << Label;
  EXPECT_EQ(Multi.OutputHex, Interp.OutputHex) << "output diverged: " << Label;
  EXPECT_EQ(Multi.LogCount, Interp.LogCount) << "log count diverged: " << Label;
  EXPECT_EQ(Multi.LogsSignature, Interp.LogsSignature)
      << "logs diverged: " << Label;
  return Interp.Status == EVMC_SUCCESS && Multi.Status == Interp.Status &&
         Multi.OutputHex == Interp.OutputHex &&
         Multi.LogCount == Interp.LogCount &&
         Multi.LogsSignature == Interp.LogsSignature;
}

bool expectInterpStatusMatchesMultipass(const std::string &Label,
                                        const std::vector<uint8_t> &Bytecode,
                                        evmc_status_code ExpectedStatus) {
  auto Interp =
      runEvmBytecode(Label + "_interp", Bytecode, common::RunMode::InterpMode);
  auto Multi = runEvmBytecode(Label + "_multipass", Bytecode,
                              common::RunMode::MultipassMode);
#ifdef ZEN_ENABLE_JIT
  EXPECT_TRUE(Multi.JITCompiled) << "multipass did not JIT-compile: " << Label;
#endif
  EXPECT_EQ(Interp.Status, ExpectedStatus)
      << "interpreter status mismatch: " << Label;
  EXPECT_EQ(Multi.Status, Interp.Status) << "status diverged: " << Label;
  EXPECT_EQ(Multi.OutputHex, Interp.OutputHex) << "output diverged: " << Label;
  return Interp.Status == ExpectedStatus && Multi.Status == Interp.Status &&
         Multi.OutputHex == Interp.OutputHex;
}

std::string
expectInterpMatchesMultipassWithGas(const std::string &Label,
                                    const std::vector<uint8_t> &Bytecode,
                                    const std::vector<uint8_t> &CallData) {
  const auto Interp =
      runEvmBytecode(Label + "_interp", Bytecode, common::RunMode::InterpMode,
                     CallData, 0u, true);
  const auto Multi =
      runEvmBytecode(Label + "_multipass", Bytecode,
                     common::RunMode::MultipassMode, CallData, 0u, true);
#ifdef ZEN_ENABLE_JIT
  EXPECT_TRUE(Multi.JITCompiled) << "multipass did not JIT-compile: " << Label;
#endif
  EXPECT_EQ(Interp.Status, EVMC_SUCCESS)
      << "interpreter did not succeed: " << Label;
  EXPECT_EQ(Multi.Status, Interp.Status) << "status diverged: " << Label;
  EXPECT_EQ(Multi.GasLeft, Interp.GasLeft) << "gas diverged: " << Label;
  EXPECT_EQ(Multi.OutputHex, Interp.OutputHex) << "output diverged: " << Label;
  return Interp.OutputHex;
}

// Fixture-file variant of the assertion above: load a hex fixture, run both
// engines, and require the multipass JIT output to match the interpreter (the
// full-width ground truth) for the named stem.
void expectFixtureInterpMatchesMultipass(const std::string &Stem) {
  const auto FilePath = (getEvmAsmDirPath() / (Stem + ".evm.hex")).string();

  auto Interp = runEvmBytecodeFile(FilePath, common::RunMode::InterpMode);
  auto Multi = runEvmBytecodeFile(FilePath, common::RunMode::MultipassMode);

#ifdef ZEN_ENABLE_JIT
  EXPECT_TRUE(Multi.JITCompiled) << "Multipass JIT should compile " << Stem;
#endif

  EXPECT_EQ(Interp.Status, EVMC_SUCCESS)
      << "Interpreter did not succeed for " << Stem;
  EXPECT_EQ(Multi.Status, Interp.Status)
      << "Multipass status diverged from interpreter for " << Stem;
  EXPECT_EQ(Multi.OutputHex, Interp.OutputHex)
      << "Multipass output diverged from interpreter for " << Stem;
}

std::string fixtureTestName(const testing::TestParamInfo<std::string> &Info) {
  return Info.param;
}

} // namespace

TEST(EVMPreparedCopyFallbackDifferential,
     DynamicDestinationMatchesInterpreterOutputAndGas) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1,        0x04, // copy size
      OP_PUSH0,              // code offset
      OP_PUSH0,              // calldata offset
      OP_CALLDATALOAD,
      OP_CODECOPY, // dynamic destination offset
      OP_PUSH1,        0x04, OP_PUSH1, 0x80, OP_RETURN,
  };
  std::vector<uint8_t> CallData(32, 0);
  CallData.back() = 0x80;

  const auto Output = expectInterpMatchesMultipassWithGas(
      "codecopy_dynamic_destination_fallback", Bytecode, CallData);
  EXPECT_EQ(Output, "60045F5F");
}

TEST(EVMMemoryBaseCacheDifferential,
     HelperGrownMemoryIsAddressableFromALaterBlock) {
  // The JIT caches the EVM memory base and size in function-entry locals. A
  // frame starts with a null base, because EVM memory is allocated lazily on
  // the frame's first growth, and the expansion branch is the only place the
  // base cache is refreshed.
  //
  // Here the first growth happens inside the CALLDATACOPY runtime helper - a
  // dynamic copy length keeps it on the generic, memory-growing helper rather
  // than a prepared one - so the helper performs the lazy allocation and moves
  // the instance's base off null. The two constant-offset stores in the next
  // block share one block precheck, whose expansion is already satisfied by
  // the reloaded size, so they address memory through the cached base without
  // taking the expansion branch. If that cache was not refreshed alongside the
  // size it still holds the entry-time null and the stores dereference it.
  const std::vector<uint8_t> Bytecode = {
      0x36,       // PC0:  CALLDATASIZE, dynamic copy length
      0x5f,       // PC1:  PUSH0 calldata offset
      0x5f,       // PC2:  PUSH0 destination offset
      0x37,       // PC3:  CALLDATACOPY, grows memory inside the helper
      0x60, 0x08, // PC4:  PUSH1 successor
      0x56,       // PC6:  JUMP
      0x5b,       // PC7:  unreachable padding
      0x5b,       // PC8:  JUMPDEST
      0x60, 0x01, // PC9:  PUSH1 1
      0x5f,       // PC11: PUSH0 store offset
      0x52,       // PC12: MSTORE through the cached base
      0x60, 0x02, // PC13: PUSH1 2
      0x60, 0x20, // PC15: PUSH1 store offset
      0x52,       // PC17: MSTORE, second op sharing the block precheck
      0x60, 0x40, // PC18: PUSH1 return length
      0x5f,       // PC20: PUSH0 return offset
      0xf3,       // PC21: RETURN
  };
  // 64 bytes of calldata, so the helper grows memory to exactly the 64 bytes
  // the two stores need and the block precheck finds nothing left to expand.
  const std::vector<uint8_t> CallData(64, 0xab);

  const auto Output = expectInterpMatchesMultipassWithGas(
      "memory_base_cache_after_helper_growth", Bytecode, CallData);
  EXPECT_EQ(Output,
            "0000000000000000000000000000000000000000000000000000000000000001"
            "0000000000000000000000000000000000000000000000000000000000000002");
}

TEST(EVMKeccakMemoryProofDifferential,
     CrossBlockProofReusePreservesHashAndGas) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x01, // PC0: PUSH1 1
      0x60, 0x80, // PC2: PUSH1 0x80
      0x52,       // PC4: MSTORE, proves memory through 0xa0
      0x60, 0x08, // PC5: PUSH1 successor
      0x56,       // PC7: JUMP
      0x5b,       // PC8: JUMPDEST
      0x60, 0x20, // PC9: PUSH1 hash length
      0x60, 0x80, // PC11: PUSH1 hash offset
      0x20,       // PC13: KECCAK256
      0x5f,       // PC14: PUSH0 result offset
      0x52,       // PC15: MSTORE hash result
      0x60, 0x20, // PC16: PUSH1 return length
      0x5f,       // PC18: PUSH0 return offset
      0xf3,       // PC19: RETURN
  };

  const auto Output =
      expectInterpMatchesMultipassWithGas("keccak_cfg_proof", Bytecode, {});
  EXPECT_EQ(Output,
            "B10E2D527612073B26EECDFD717E6A320CF44B4AFAC2B0732D9FCBE2B7FA0CF6");
}

TEST(EVMKeccakMemoryProofDifferential,
     WordGasOutOfGasBoundaryMatchesInterpreter) {
  // KECCAK256 is the final operation, so one gas below the successful
  // execution budget exercises its final dynamic word-gas charge.
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x01, // PUSH1 1
      0x60, 0x80, // PUSH1 0x80
      0x52,       // MSTORE, expands memory before KECCAK256
      0x60, 0x20, // PUSH1 hash length
      0x60, 0x80, // PUSH1 hash offset
      0x20,       // KECCAK256
  };
  constexpr uint64_t ProbeGasLimit = 1'000'000;
  const auto Reference =
      runEvmBytecode("keccak_word_gas_reference", Bytecode,
                     common::RunMode::InterpMode, {}, 0u, true, ProbeGasLimit);
  ASSERT_EQ(Reference.Status, EVMC_SUCCESS);
  ASSERT_GE(Reference.GasLeft, 0);
  const auto RequiredGas =
      ProbeGasLimit - static_cast<uint64_t>(Reference.GasLeft);
  ASSERT_GT(RequiredGas, uint64_t{1});

  const auto Interp = runEvmBytecode("keccak_word_gas_oog_interp", Bytecode,
                                     common::RunMode::InterpMode, {}, 0u, true,
                                     RequiredGas - 1);
  const auto Multi = runEvmBytecode("keccak_word_gas_oog_multipass", Bytecode,
                                    common::RunMode::MultipassMode, {}, 0u,
                                    true, RequiredGas - 1);
#ifdef ZEN_ENABLE_JIT
  EXPECT_TRUE(Multi.JITCompiled);
#endif
  EXPECT_EQ(Interp.Status, EVMC_OUT_OF_GAS);
  EXPECT_EQ(Multi.Status, Interp.Status);
  EXPECT_EQ(Multi.GasLeft, Interp.GasLeft);
  EXPECT_EQ(Multi.OutputHex, Interp.OutputHex);
}

// ===========================================================================
// Fixture-based differential suite.
//
// Each fixture feeds a dynamic (analyzer-unprovable) operand through an opcode
// whose multipass lowering has a value-range fast path, then asserts the JIT
// output matches the interpreter (the full-width reference) exactly. A
// divergence means a narrowed fold produced a wrong value, not merely a slower
// one. The fixtures hold on the plain lowering as well as the narrowed one, so
// they guard the invariant independently of whether the fast paths are present.
// ===========================================================================

class EVMFixtureDifferentialTest
    : public ::testing::TestWithParam<std::string> {};

TEST_P(EVMFixtureDifferentialTest, InterpMatchesMultipass) {
  expectFixtureInterpMatchesMultipass(GetParam());
}

TEST(EVMMemoryTerminationDifferential, ReturnLargeRangeMatchesInterpreter) {
  const std::vector<uint8_t> Bytecode = {0x60, 0x20, // PUSH1 32: return length
                                         0x61, 0x10,
                                         0x00,  // PUSH2 0x1000: return offset
                                         0xf3}; // RETURN
  ASSERT_TRUE(expectInterpStatusMatchesMultipass("return_large_range", Bytecode,
                                                 EVMC_SUCCESS));
}

TEST(EVMMemoryTerminationDifferential, RevertLargeRangeMatchesInterpreter) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x20,       // PUSH1 32: revert data length
      0x61, 0x10, 0x00, // PUSH2 0x1000: revert data offset
      0xfd};            // REVERT
  ASSERT_TRUE(expectInterpStatusMatchesMultipass("revert_large_range", Bytecode,
                                                 EVMC_REVERT));
}

TEST(EVMMemoryTerminationDifferential, EmptyReturnIgnoresHighOffset) {
  std::vector<uint8_t> Bytecode = {
      0x5f, // PUSH0: return length
      0x7f, // PUSH32: high offset must be ignored when length is zero
  };
  Bytecode.push_back(0x01);
  Bytecode.insert(Bytecode.end(), 31, 0x00);
  Bytecode.push_back(0xf3); // RETURN

  ASSERT_TRUE(expectInterpStatusMatchesMultipass("empty_return_high_offset",
                                                 Bytecode, EVMC_SUCCESS));
}

TEST(EVMMemoryTerminationDifferential, EmptyRevertIgnoresHighOffset) {
  std::vector<uint8_t> Bytecode = {
      0x5f, // PUSH0: revert data length
      0x7f, // PUSH32: high offset must be ignored when length is zero
  };
  Bytecode.push_back(0x01);
  Bytecode.insert(Bytecode.end(), 31, 0x00);
  Bytecode.push_back(0xfd); // REVERT

  ASSERT_TRUE(expectInterpStatusMatchesMultipass("empty_revert_high_offset",
                                                 Bytecode, EVMC_REVERT));
}

TEST(EVMMemoryTerminationDifferential, DynamicEmptyReturnIgnoresHighOffset) {
  std::vector<uint8_t> Bytecode = {
      0x36, // CALLDATASIZE: dynamic zero return length
      0x7f, // PUSH32: high offset must be ignored when length is zero
  };
  Bytecode.push_back(0x01);
  Bytecode.insert(Bytecode.end(), 31, 0x00);
  Bytecode.push_back(0xf3); // RETURN

  ASSERT_TRUE(expectInterpStatusMatchesMultipass(
      "dynamic_empty_return_high_offset", Bytecode, EVMC_SUCCESS));
}

TEST(EVMMemoryTerminationDifferential, DynamicEmptyRevertIgnoresHighOffset) {
  std::vector<uint8_t> Bytecode = {
      0x36, // CALLDATASIZE: dynamic zero revert data length
      0x7f, // PUSH32: high offset must be ignored when length is zero
  };
  Bytecode.push_back(0x01);
  Bytecode.insert(Bytecode.end(), 31, 0x00);
  Bytecode.push_back(0xfd); // REVERT

  ASSERT_TRUE(expectInterpStatusMatchesMultipass(
      "dynamic_empty_revert_high_offset", Bytecode, EVMC_REVERT));
}

TEST(EVMMemoryTerminationDifferential,
     CrossBlockCoveredRangeMatchesStatusOutputAndGas) {
  const std::vector<uint8_t> Prefix = {
      0x60, 0x01, // PC0 PUSH1 1: value
      0x60, 0x80, // PC2 PUSH1 0x80: memory offset
      0x52,       // PC4 MSTORE: prove memory covers [0, 0xa0)
      0x60, 0x08, // PC5 PUSH1 8
      0x56,       // PC7 JUMP
      0x5b,       // PC8 JUMPDEST
      0x60, 0x20, // PC9 PUSH1 32: output size
      0x60, 0x80, // PC11 PUSH1 0x80: output offset
  };
  const std::string ExpectedOutput =
      "0000000000000000000000000000000000000000000000000000000000000001";

  for (const auto &[Name, Terminator, ExpectedStatus] :
       std::vector<std::tuple<const char *, uint8_t, evmc_status_code>>{
           {"return", 0xf3, EVMC_SUCCESS},
           {"revert", 0xfd, EVMC_REVERT},
       }) {
    std::vector<uint8_t> Bytecode = Prefix;
    Bytecode.push_back(Terminator);

    const auto Interp =
        runEvmBytecode(std::string(Name) + "_covered_range_interp", Bytecode,
                       common::RunMode::InterpMode, {}, 0u, true);
    const auto Multi =
        runEvmBytecode(std::string(Name) + "_covered_range_multipass", Bytecode,
                       common::RunMode::MultipassMode, {}, 0u, true);
#ifdef ZEN_ENABLE_JIT
    EXPECT_TRUE(Multi.JITCompiled);
#endif
    EXPECT_EQ(Interp.Status, ExpectedStatus);
    EXPECT_EQ(Multi.Status, Interp.Status);
    EXPECT_EQ(Multi.GasLeft, Interp.GasLeft);
    EXPECT_EQ(Multi.OutputHex, Interp.OutputHex);
    EXPECT_EQ(Interp.OutputHex, ExpectedOutput);
  }
}

// Range-narrowed lowering paths: the range-narrowed ISZERO/JUMPI folds,
// U64-tagged OR/XOR, and the signed-compare (SLT/SGT) u64-const fast paths in
// the multipass lowering. Each fixture feeds a dynamic operand so the narrowed
// path is actually taken.
INSTANTIATE_TEST_SUITE_P(
    RangeNarrowing, EVMFixtureDifferentialTest,
    ::testing::Values("iszero_dyn_u64_nonzero", "iszero_dyn_highsparse",
                      "iszero_calldatasize", "jumpi_iszero_fused_taken",
                      "jumpi_iszero_fused_nottaken_highsparse",
                      "jumpi_iszero_iszero_fused", "jumpi_u64_cond_taken",
                      "jumpi_u64_cond_nottaken", "or_dyn_u64_u64",
                      "xor_dyn_u64_u64", "or_dyn_u64_wide", "xor_dyn_u64_wide",
                      "slt_dyn_neg_vs_const", "slt_dyn_highsparse_vs_const",
                      "slt_dyn_msb64_vs_const", "slt_dyn_eq_const",
                      "sgt_dyn_neg_vs_const", "sgt_dyn_highsparse_vs_const",
                      "sgt_dyn_msb64_vs_const", "slt_const_vs_dyn",
                      "sgt_const_vs_dyn"),
    fixtureTestName);

// Const-shift guard pruning and range-aware source-limb pruning in handleShift.
// Each fixture must yield identical output in the interpreter and the multipass
// JIT, and the multipass module must JIT.
INSTANTIATE_TEST_SUITE_P(
    ConstShiftPruning, EVMFixtureDifferentialTest,
    ::testing::Values("shl_const4_dyn", "shl_const96_dyn",
                      "shl_const136_u64val", "shl_const200_u64val",
                      "shl_const256_dyn", "shl_const_highlimb_dyn",
                      "shr_const4_dyn", "shr_const72_dyn", "shr_const8_u64val",
                      "shr_const256_dyn", "sar_const8_neg", "sar_const64_pos",
                      "shl_dyn_amount"),
    fixtureTestName);

// Range-based u64 SUB fast path. Each stem exercises (a - b) mod 2^256 with
// both operands range-proven u64 (except the wide control), including the
// adversarial underflow cases where the upper 192 bits sign-fill to all-ones.
// Interpreter and multipass JIT must agree.
INSTANTIATE_TEST_SUITE_P(
    SubWrapU64, EVMFixtureDifferentialTest,
    ::testing::Values("sub_u64_pair_nounderflow", "sub_u64_pair_underflow",
                      "sub_u64_pair_equal", "sub_u64_pair_wrap_boundary",
                      "sub_u64_pair_zero_rhs_dyn", "sub_wide_u64_control"),
    fixtureTestName);

// ===========================================================================
// Value-range lowering differential matrix harness.
//
// A multipass value-range fast path that emits a single- or double-limb result
// MUST be bit-identical to the full 4-limb path for every input the range tag
// claims to cover. A too-narrow tag silently miscompiles only on operands with
// non-zero high limbs, which ordinary corpora rarely carry. Each test drives an
// opcode with an adversarial operand matrix (value-range boundaries +
// high-sparse {0,x,0,0}/{0,0,0,x}) and asserts the multipass JIT agrees
// bit-for-bit with the interpreter (the full-width reference).
//
// Coverage split (the operands decide which lowering path fires):
//   - BinaryOpsMatchInterpreterOnAdversarialOperands feeds two CALLDATALOAD
//     operands, which are dynamic and U256-range, so they do NOT enter the
//     bothFitU64 / AND-narrow fast paths: this test gates the FULL-width
//     4-limb lowering (the #487-class high-limb-corruption surface). It sweeps
//     20 binary opcodes (arithmetic, comparison, bitwise, BYTE, SIGNEXTEND,
//     and the three shifts). EXP is excluded because its gas cost scales with
//     the exponent byte length, so high-limb operands would trip out-of-gas
//     instead of exposing a value-range divergence.
//   - ShiftAmountsMatchInterpreterOnLimbBoundaries sweeps SHL/SHR/SAR with
//     shift amounts in the limb-crossing region 2..255. The 11-value operand
//     matrix, used as a shift amount, only realizes {0, 1, >=2^64}, so the
//     dynamic-shift cross-limb carry/offset logic is unreachable from the
//     binary-op sweep above; this test covers it.
//   - The AndU64Mask* tests construct a provably-U64 operand (AND with a u64
//     constant) and feed it directly / through a bothFitU64 ADD, so they gate
//     the actual narrowing fast paths.
// ===========================================================================

namespace {

// Build a big-endian 32-byte word holding `Val` in 64-bit limb `Limb`
// (limb 0 = least significant). OR several together for multi-limb operands.
std::vector<uint8_t> matrixLimb(int Limb, uint64_t Val) {
  std::vector<uint8_t> W(32, 0);
  const int Base = 24 - Limb * 8; // limb 0 -> bytes [24..31]
  for (int I = 0; I < 8; ++I) {
    W[Base + 7 - I] = static_cast<uint8_t>((Val >> (8 * I)) & 0xff);
  }
  return W;
}

std::vector<uint8_t> matrixOr(std::vector<uint8_t> A,
                              const std::vector<uint8_t> &B) {
  for (size_t I = 0; I < A.size(); ++I) {
    A[I] |= B[I];
  }
  return A;
}

// Adversarial operand matrix: each entry is a 32-byte big-endian u256.
std::vector<std::vector<uint8_t>> matrixOperands() {
  const uint64_t Max = 0xFFFFFFFFFFFFFFFFull;
  std::vector<std::vector<uint8_t>> Ops;
  Ops.push_back(matrixLimb(0, 0));   // 0
  Ops.push_back(matrixLimb(0, 1));   // 1
  Ops.push_back(matrixLimb(0, Max)); // 2^64 - 1 (U64 boundary)
  Ops.push_back(matrixLimb(1, 1));   // 2^64
  Ops.push_back(matrixOr(matrixLimb(0, Max), matrixLimb(1, Max))); // U128-1
  Ops.push_back(matrixLimb(2, 1)); // 2^128 (U128 boundary)
  Ops.push_back(matrixLimb(3, 1)); // 2^192 (high-sparse {0,0,0,x})
  Ops.push_back(matrixOr(matrixLimb(3, 1), matrixLimb(0, 5))); // 2^192+5
  Ops.push_back(matrixLimb(1, 5));                     // high-sparse {0,x,0,0}
  Ops.push_back(matrixLimb(3, 0x8000000000000000ull)); // 2^255 (sign bit)
  Ops.push_back(
      matrixOr(matrixOr(matrixLimb(0, Max), matrixLimb(1, Max)),
               matrixOr(matrixLimb(2, Max), matrixLimb(3, Max)))); // 2^256-1
  return Ops;
}

std::vector<uint8_t> matrixCalldata(const std::vector<uint8_t> &A,
                                    const std::vector<uint8_t> &B) {
  std::vector<uint8_t> CD;
  CD.insert(CD.end(), A.begin(), A.end());
  CD.insert(CD.end(), B.begin(), B.end());
  return CD;
}

// "a = calldata[0:32]; b = calldata[32:64]; OP". After the two pushes, b is on
// top of the stack, so EVM evaluates `b OP a` (e.g. SUB = b - a; for shifts the
// shift amount is b). The exact convention is irrelevant to a differential test
// — both engines run identical bytecode — and the nested A*B sweep feeds every
// matrix value into both slots regardless.
std::vector<uint8_t> matrixBinOp(uint8_t Op) {
  return {0x60, 0x00, 0x35,              // PUSH1 0    CALLDATALOAD -> a
          0x60, 0x20, 0x35,              // PUSH1 0x20 CALLDATALOAD -> b
          Op,                            // b OP a
          0x60, 0x00, 0x52,              // PUSH1 0 MSTORE
          0x60, 0x20, 0x60, 0x00, 0xf3}; // RETURN(0, 32)
}

} // namespace

// Differential over every binary opcode whose lowering touches limbs. Operands
// are dynamic CALLDATALOAD (U256-range), so this gates the FULL-width 4-limb
// path, not the narrow fast paths (those are gated by the AndU64Mask* tests).
// On the first divergent (op, operand) pair the whole test returns, so a single
// regression reports one op and skips the rest — intentional output-flood
// control, not full per-op isolation.
//
// EXP (0x0a) is intentionally excluded: its gas cost scales with the byte
// length of the exponent, so the high-limb operands in this matrix (2^192,
// 2^255, 2^256-1) would charge enormous dynamic gas and obscure a pure
// value-range divergence behind out-of-gas noise. Shift amounts, which need
// the limb-crossing region 2..255, are swept separately by
// ShiftAmountsMatchInterpreterOnLimbBoundaries below.
TEST(EVMRangeDifferential, BinaryOpsMatchInterpreterOnAdversarialOperands) {
  struct OpCase {
    uint8_t Op;
    const char *Name;
  };
  const OpCase Cases[] = {
      {0x01, "ADD"},  {0x02, "MUL"}, {0x03, "SUB"},  {0x04, "DIV"},
      {0x05, "SDIV"}, {0x06, "MOD"}, {0x07, "SMOD"}, {0x0b, "SIGNEXTEND"},
      {0x10, "LT"},   {0x11, "GT"},  {0x12, "SLT"},  {0x13, "SGT"},
      {0x14, "EQ"},   {0x16, "AND"}, {0x17, "OR"},   {0x18, "XOR"},
      {0x1a, "BYTE"}, {0x1b, "SHL"}, {0x1c, "SHR"},  {0x1d, "SAR"},
  };
  const auto Operands = matrixOperands();
  for (const auto &C : Cases) {
    const auto Bytecode = matrixBinOp(C.Op);
    for (const auto &A : Operands) {
      for (const auto &B : Operands) {
        if (!expectInterpMatchesMultipass(C.Name, Bytecode,
                                          matrixCalldata(A, B))) {
          return; // one divergence is enough; avoid output flood
        }
      }
    }
  }
}

TEST(EVMRangeDifferential, DynamicExpDivisorMatchesInterpreter) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x20, 0x35,              // exponent = CALLDATALOAD(32)
      0x61, 0x01, 0x00, 0x0a,        // divisor = 256**exponent
      0x60, 0x00, 0x35,              // dividend = CALLDATALOAD(0)
      0x04,                          // DIV
      0x60, 0x00, 0x52,              // MSTORE(0, quotient)
      0x60, 0x20, 0x60, 0x00, 0xf3}; // RETURN(0, 32)
  std::vector<uint8_t> CallData(64, 0);
  CallData[0] = 0x06;  // dividend = 6 * 2**248
  CallData[63] = 0x1f; // exponent = 31, divisor = 2**248

  const auto Output = expectInterpMatchesMultipassWithGas("dynamic_exp_divisor",
                                                          Bytecode, CallData);
  EXPECT_EQ(Output,
            "0000000000000000000000000000000000000000000000000000000000000006");
}

TEST(EVMRangeDifferential,
     DynamicExpDividendWithConstU64DivisorMatchesInterpreter) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x03,                    // divisor = 3
      0x60, 0x00, 0x35,              // exponent = CALLDATALOAD(0)
      0x61, 0x01, 0x00, 0x0a,        // dividend = 256**exponent
      0x04,                          // DIV
      0x60, 0x00, 0x52,              // MSTORE(0, quotient)
      0x60, 0x20, 0x60, 0x00, 0xf3}; // RETURN(0, 32)
  std::vector<uint8_t> CallData(32, 0);
  CallData.back() = 0x08;

  const auto Output = expectInterpMatchesMultipassWithGas(
      "constant_u64_divisor", Bytecode, CallData);
  EXPECT_EQ(Output,
            "0000000000000000000000000000000000000000000000005555555555555555");
}

TEST(EVMRangeDifferential, UnresolvedJumpiTakenTargetPreservesGas) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x00, 0x35, // PC0  condition = calldata[0]
      0x60, 0x20, 0x35, // PC3  destination = calldata[32]
      0x57,             // PC6  dynamic JUMPI
      0x5f, 0x50,       // PC7  untaken-only fallthrough cost
      0x5b, 0x5a,       // PC9  dynamic target; observe GAS
      0x5f, 0x52,       // PC11 MSTORE(0, gas)
      0x60, 0x20, 0x5f, 0xf3,
  };
  std::vector<uint8_t> TakenCallData(64, 0);
  TakenCallData[31] = 1;
  TakenCallData[63] = 9;

  const auto TakenInterp =
      runEvmBytecode("unresolved_jumpi_taken_target_interp", Bytecode,
                     common::RunMode::InterpMode, TakenCallData, 0u, true,
                     0x2210, evmc_revision::EVMC_CANCUN);
  const auto TakenMulti =
      runEvmBytecode("unresolved_jumpi_taken_target_multipass", Bytecode,
                     common::RunMode::MultipassMode, TakenCallData, 0u, true,
                     0x2210, evmc_revision::EVMC_CANCUN);
#ifdef ZEN_ENABLE_JIT
  EXPECT_TRUE(TakenMulti.JITCompiled);
#endif
  constexpr char ExpectedTakenGasOutput[] =
      "00000000000000000000000000000000000000000000000000000000000021F7";
  EXPECT_EQ(TakenInterp.Status, EVMC_SUCCESS);
  EXPECT_EQ(TakenInterp.OutputHex, ExpectedTakenGasOutput);
  EXPECT_EQ(TakenMulti.Status, TakenInterp.Status);
  EXPECT_EQ(TakenMulti.GasLeft, TakenInterp.GasLeft);
  EXPECT_EQ(TakenMulti.OutputHex, ExpectedTakenGasOutput);

  std::vector<uint8_t> FallthroughCallData = TakenCallData;
  FallthroughCallData[31] = 0;
  const auto FallthroughInterp =
      runEvmBytecode("unresolved_jumpi_fallthrough_interp", Bytecode,
                     common::RunMode::InterpMode, FallthroughCallData, 0u, true,
                     0x2210, evmc_revision::EVMC_CANCUN);
  const auto FallthroughMulti =
      runEvmBytecode("unresolved_jumpi_fallthrough_multipass", Bytecode,
                     common::RunMode::MultipassMode, FallthroughCallData, 0u,
                     true, 0x2210, evmc_revision::EVMC_CANCUN);
#ifdef ZEN_ENABLE_JIT
  EXPECT_TRUE(FallthroughMulti.JITCompiled);
#endif
  constexpr char ExpectedFallthroughGasOutput[] =
      "00000000000000000000000000000000000000000000000000000000000021F3";
  EXPECT_EQ(FallthroughInterp.Status, EVMC_SUCCESS);
  EXPECT_EQ(FallthroughInterp.OutputHex, ExpectedFallthroughGasOutput);
  EXPECT_EQ(FallthroughMulti.Status, FallthroughInterp.Status);
  EXPECT_EQ(FallthroughMulti.GasLeft, FallthroughInterp.GasLeft);
  EXPECT_EQ(FallthroughMulti.OutputHex, ExpectedFallthroughGasOutput);
}

// Sweep SHL/SHR/SAR with shift amounts that land inside the limb-crossing
// region 2..255. The 11-value operand matrix, when fed as a shift amount, only
// realizes {0, 1, >=2^64}; it never produces an amount in 2..255, so the
// dynamic-shift lowering's cross-limb carry/offset logic (which moves bits
// across 64-bit limb boundaries at amounts 64/128/192 and within a limb at the
// rest) is never exercised by BinaryOpsMatchInterpreterOnAdversarialOperands.
//
// matrixBinOp puts the shift amount in slot b (calldata[32:64], the stack top
// SHL/SHR/SAR pops first) and the shifted value in slot a (calldata[0:32]).
// Both are CALLDATALOAD, so the full-width dynamic shift path fires. The
// shifted value sweeps the full adversarial matrix; the amount sweeps the
// boundary set below, covering both the on-limb-boundary amounts (64, 128, 192)
// and the in-limb amounts (2, 7, 31, 63, 65, 127, ...).
TEST(EVMRangeDifferential, ShiftAmountsMatchInterpreterOnLimbBoundaries) {
  struct OpCase {
    uint8_t Op;
    const char *Name;
  };
  const OpCase Cases[] = {
      {0x1b, "SHL"},
      {0x1c, "SHR"},
      {0x1d, "SAR"},
  };
  const uint64_t Amounts[] = {2,   7,   8,   31,  63,  64,  65, 127,
                              128, 129, 136, 191, 192, 200, 255};
  const auto Values = matrixOperands();
  for (const auto &C : Cases) {
    const auto Bytecode = matrixBinOp(C.Op);
    for (const auto &Value : Values) {
      for (uint64_t Amount : Amounts) {
        const auto AmountWord = matrixLimb(0, Amount);
        if (!expectInterpMatchesMultipass(C.Name, Bytecode,
                                          matrixCalldata(Value, AmountWord))) {
          return; // one divergence is enough; avoid output flood
        }
      }
    }
  }
}

// Directly exercise the AND-with-u64-constant fast path (CONST_U64): it tags
// the result U64 and MUST zero limbs[1..3]. Returning the result directly (not
// through a later narrow op that would discard the high limbs) is what makes a
// too-narrow / too-wide limb bug observable. Feeding high-sparse calldata, the
// masked result must equal the interpreter's.
//   a = calldata[0:32]; MSTORE(0, a AND 0xFFFFFFFFFFFFFFFF); RETURN 32.
TEST(EVMRangeDifferential, AndU64MaskMatchesInterpreter) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x00, 0x35,                                     // CALLDATALOAD a
      0x67, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // PUSH8 u64 mask
      0x16,                                                 // AND -> m (U64)
      0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3};      // RETURN(0,32)
  const auto Operands = matrixOperands();
  for (const auto &A : Operands) {
    if (!expectInterpMatchesMultipass("and_u64_mask", Bytecode,
                                      matrixCalldata(A, A))) {
      return;
    }
  }
}

// Exercise a narrow-result CONSUMER: AND with a u64 constant produces a U64
// value that feeds a self-ADD on the bothFitU64 narrow path. The summed result
// is returned; for any high-sparse input the narrowed two-limb sum must match
// the interpreter's full-width sum.
//   a = calldata[0:32]; m = a AND 0xFFFFFFFFFFFFFFFF; MSTORE(0, m + m); RETURN.
TEST(EVMRangeDifferential, AndU64MaskThenNarrowAddMatchesInterpreter) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x00, 0x35,                                     // CALLDATALOAD a
      0x67, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // PUSH8 u64 mask
      0x16,                                                 // AND -> m (U64)
      0x80,                                                 // DUP1
      0x01,                                            // ADD m + m (narrow)
      0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3}; // RETURN(0,32)
  const auto Operands = matrixOperands();
  for (const auto &A : Operands) {
    if (!expectInterpMatchesMultipass("and_u64_mask_then_add", Bytecode,
                                      matrixCalldata(A, A))) {
      return;
    }
  }
}

TEST(EVMRangeDifferential, DeadUnderResolvedFallthroughMatchesInterpreter) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x01, // PC0 PUSH1 0x01 (take JUMPI)
      0x60, 0x0b, // PC2 PUSH1 0x0b
      0x57,       // PC4 JUMPI
      0x01,       // PC5 ADD (dead under-resolved fallthrough)
      0x60, 0x00, // PC6 PUSH1 0x00
      0x60, 0x0b, // PC8 PUSH1 0x0b
      0x56,       // PC10 JUMP
      0x5b,       // PC11 JUMPDEST
      0x00,       // PC12 STOP
  };

  EXPECT_TRUE(expectInterpMatchesMultipass("dead_under_resolved_fallthrough",
                                           Bytecode, {}));
}

TEST(EVMLiftedStackMerge,
     JumpiFallthroughSharedJumpDestMatchesInterpreterOnBothEdges) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0xaa, // PC0  PUSH1 0xaa (first incoming value)
      0x5f,       // PC2  PUSH0 (first condition offset)
      0x35,       // PC3  CALLDATALOAD
      0x60, 0x10, // PC4  PUSH1 16 (shared merge target)
      0x57,       // PC6  JUMPI
      0x50,       // PC7  POP
      0x60, 0xbb, // PC8  PUSH1 0xbb (second incoming value)
      0x60, 0x20, // PC10 PUSH1 32 (independent second condition offset)
      0x35,       // PC12 CALLDATALOAD
      0x60, 0x17, // PC13 PUSH1 23 (unused taken target)
      0x57,       // PC15 JUMPI (fallthrough = shared target)
      0x5b,       // PC16 JUMPDEST (shared merge target)
      0x5f,       // PC17 PUSH0
      0x52,       // PC18 MSTORE (store merged 0xaa/0xbb)
      0x60, 0x20, // PC19 PUSH1 32
      0x5f,       // PC21 PUSH0
      0xf3,       // PC22 RETURN
      0x5b,       // PC23 JUMPDEST (unused taken target)
      0x00,       // PC24 STOP
  };

  std::vector<uint8_t> SecondIncomingCallData(64, 0);
  const std::string SecondIncomingOutput = expectInterpMatchesMultipassWithGas(
      "jumpi_fallthrough_shared_jumpdest_second_incoming", Bytecode,
      SecondIncomingCallData);

  std::vector<uint8_t> FirstIncomingCallData = SecondIncomingCallData;
  FirstIncomingCallData[31] = 1;
  const std::string FirstIncomingOutput = expectInterpMatchesMultipassWithGas(
      "jumpi_fallthrough_shared_jumpdest_first_incoming", Bytecode,
      FirstIncomingCallData);

  EXPECT_EQ(FirstIncomingOutput,
            "00000000000000000000000000000000000000000000000000000000000000AA");
  EXPECT_EQ(SecondIncomingOutput,
            "00000000000000000000000000000000000000000000000000000000000000BB");
}

TEST(EVMLiftedStackMerge,
     TerminatingBlockBeforeSharedJumpDestDoesNotAddDeadPredecessor) {
  const std::vector<uint8_t> BaseBytecode = {
      0x5f,       // PC0  PUSH0 (error-path selector offset)
      0x35,       // PC1  CALLDATALOAD
      0x60, 0x13, // PC2  PUSH1 19 (terminating error block)
      0x57,       // PC4  JUMPI
      0x60, 0xaa, // PC5  PUSH1 0xaa (first incoming value)
      0x60, 0x20, // PC7  PUSH1 32 (merge-path selector offset)
      0x35,       // PC9  CALLDATALOAD
      0x60, 0x17, // PC10 PUSH1 23 (shared merge target)
      0x57,       // PC12 JUMPI
      0x50,       // PC13 POP
      0x60, 0xbb, // PC14 PUSH1 0xbb (second incoming value)
      0x60, 0x17, // PC16 PUSH1 23 (shared merge target)
      0x56,       // PC18 JUMP
      0x5b,       // PC19 JUMPDEST (error block)
      0x5f,       // PC20 PUSH0
      0x5f,       // PC21 PUSH0
      0xfd,       // PC22 REVERT (replaced with RETURN in the second case)
      0x5b,       // PC23 JUMPDEST (shared merge target)
      0x5f,       // PC24 PUSH0
      0x52,       // PC25 MSTORE
      0x60, 0x20, // PC26 PUSH1 32
      0x5f,       // PC28 PUSH0
      0xf3,       // PC29 RETURN
  };

  COMPILER::EVMAnalyzer Analyzer(EVMC_CANCUN);
  Analyzer.analyze(BaseBytecode.data(), BaseBytecode.size());
  const auto MergeIt = Analyzer.getBlockInfos().find(23);
  ASSERT_NE(MergeIt, Analyzer.getBlockInfos().end());
  EXPECT_TRUE(MergeIt->second.CanLiftStack);
  EXPECT_TRUE(MergeIt->second.RequiresEntryMergeState);

  for (const auto &[Name, Terminator] :
       std::vector<std::pair<const char *, uint8_t>>{
           {"revert", 0xfd},
           {"return", 0xf3},
       }) {
    std::vector<uint8_t> Bytecode = BaseBytecode;
    Bytecode[22] = Terminator;

    std::vector<uint8_t> SecondIncomingCallData(64, 0);
    const std::string SecondIncomingOutput =
        expectInterpMatchesMultipassWithGas(
            std::string(Name) + "_before_shared_jumpdest_second_incoming",
            Bytecode, SecondIncomingCallData);

    std::vector<uint8_t> FirstIncomingCallData = SecondIncomingCallData;
    FirstIncomingCallData[63] = 1;
    const std::string FirstIncomingOutput = expectInterpMatchesMultipassWithGas(
        std::string(Name) + "_before_shared_jumpdest_first_incoming", Bytecode,
        FirstIncomingCallData);

    EXPECT_EQ(
        FirstIncomingOutput,
        "00000000000000000000000000000000000000000000000000000000000000AA");
    EXPECT_EQ(
        SecondIncomingOutput,
        "00000000000000000000000000000000000000000000000000000000000000BB");

    std::vector<uint8_t> TerminatorCallData(64, 0);
    TerminatorCallData[31] = 1;
    const auto Interp = runEvmBytecode(std::string(Name) + "_terminator_interp",
                                       Bytecode, common::RunMode::InterpMode,
                                       TerminatorCallData, 0u, true);
    const auto Multi = runEvmBytecode(
        std::string(Name) + "_terminator_multipass", Bytecode,
        common::RunMode::MultipassMode, TerminatorCallData, 0u, true);
#ifdef ZEN_ENABLE_JIT
    EXPECT_TRUE(Multi.JITCompiled);
#endif
    EXPECT_EQ(Multi.Status, Interp.Status);
    EXPECT_EQ(Multi.GasLeft, Interp.GasLeft);
    EXPECT_EQ(Multi.OutputHex, Interp.OutputHex);
    EXPECT_EQ(Interp.Status, Terminator == 0xfd ? EVMC_REVERT : EVMC_SUCCESS);
    EXPECT_TRUE(Interp.OutputHex.empty());
  }
}

TEST(EVMLiftedStackMerge,
     ConsecutiveJumpDestSharedMergeMatchesInterpreterOnBothEdges) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0xaa, // PC0  PUSH1 0xaa (first incoming value)
      0x5f,       // PC2  PUSH0 (first condition offset)
      0x35,       // PC3  CALLDATALOAD
      0x60, 0x11, // PC4  PUSH1 17 (canonical shared merge target)
      0x57,       // PC6  JUMPI
      0x50,       // PC7  POP
      0x60, 0xbb, // PC8  PUSH1 0xbb (second incoming value)
      0x60, 0x20, // PC10 PUSH1 32 (independent second condition offset)
      0x35,       // PC12 CALLDATALOAD
      0x60, 0x18, // PC13 PUSH1 24 (unused taken target)
      0x57,       // PC15 JUMPI (fallthrough begins JUMPDEST run)
      0x5b,       // PC16 JUMPDEST (alias of PC17)
      0x5b,       // PC17 JUMPDEST (canonical shared merge target)
      0x5f,       // PC18 PUSH0
      0x52,       // PC19 MSTORE (store merged 0xaa/0xbb)
      0x60, 0x20, // PC20 PUSH1 32
      0x5f,       // PC22 PUSH0
      0xf3,       // PC23 RETURN
      0x5b,       // PC24 JUMPDEST (unused taken target)
      0x00,       // PC25 STOP
  };

  std::vector<uint8_t> SecondIncomingCallData(64, 0);
  const std::string SecondIncomingOutput = expectInterpMatchesMultipassWithGas(
      "consecutive_jumpdest_shared_merge_second_incoming", Bytecode,
      SecondIncomingCallData);

  std::vector<uint8_t> FirstIncomingCallData = SecondIncomingCallData;
  FirstIncomingCallData[31] = 1;
  const std::string FirstIncomingOutput = expectInterpMatchesMultipassWithGas(
      "consecutive_jumpdest_shared_merge_first_incoming", Bytecode,
      FirstIncomingCallData);

  EXPECT_EQ(FirstIncomingOutput,
            "00000000000000000000000000000000000000000000000000000000000000AA");
  EXPECT_EQ(SecondIncomingOutput,
            "00000000000000000000000000000000000000000000000000000000000000BB");
}

TEST(EVMLiftedStackMerge,
     DistinctInstructionBackedValuesMaterializeAtSharedEntry) {
  const std::vector<uint8_t> Bytecode = {
      0x5f,       // PC0  PUSH0 (condition offset)
      0x35,       // PC1  CALLDATALOAD
      0x60, 0x0e, // PC2  PUSH1 14 (taken branch)
      0x57,       // PC4  JUMPI
      0x60, 0x20, // PC5  PUSH1 32 (first value offset)
      0x35,       // PC7  CALLDATALOAD
      0x60, 0x01, // PC8  PUSH1 1
      0x01,       // PC10 ADD (first instruction-backed value)
      0x60, 0x18, // PC11 PUSH1 24 (merge)
      0x56,       // PC13 JUMP
      0x5b,       // PC14 JUMPDEST (taken branch)
      0x60, 0x40, // PC15 PUSH1 64 (second value offset)
      0x35,       // PC17 CALLDATALOAD
      0x60, 0x01, // PC18 PUSH1 1
      0x01,       // PC20 ADD (second instruction-backed value)
      0x60, 0x18, // PC21 PUSH1 24 (merge)
      0x56,       // PC23 JUMP
      0x5b,       // PC24 JUMPDEST (merge)
      0x5f,       // PC25 PUSH0
      0x52,       // PC26 MSTORE
      0x60, 0x20, // PC27 PUSH1 32
      0x5f,       // PC29 PUSH0
      0xf3,       // PC30 RETURN
  };

  COMPILER::EVMAnalyzer Analyzer(EVMC_CANCUN);
  Analyzer.analyze(Bytecode.data(), Bytecode.size());
  const auto MergeIt = Analyzer.getBlockInfos().find(24);
  ASSERT_NE(MergeIt, Analyzer.getBlockInfos().end());
  EXPECT_TRUE(MergeIt->second.CanLiftStack);
  EXPECT_TRUE(MergeIt->second.RequiresEntryMergeState);

  std::vector<uint8_t> FirstEdgeCallData(96, 0);
  FirstEdgeCallData[63] = 0x11;
  FirstEdgeCallData[95] = 0x22;
  const std::string FirstEdgeOutput = expectInterpMatchesMultipassWithGas(
      "distinct_instruction_merge_first_edge", Bytecode, FirstEdgeCallData);

  std::vector<uint8_t> SecondEdgeCallData = FirstEdgeCallData;
  SecondEdgeCallData[31] = 1;
  const std::string SecondEdgeOutput = expectInterpMatchesMultipassWithGas(
      "distinct_instruction_merge_second_edge", Bytecode, SecondEdgeCallData);

  EXPECT_NE(FirstEdgeOutput, SecondEdgeOutput)
      << "both paths returned the same value";
}

TEST(EVMDeepEntry, DeadCfgDoesNotBlockJITAndMatchesInterpreter) {
  const std::vector<uint8_t> Bytecode = {
      0x00, // PC0 STOP
      0x5b, // PC1 JUMPDEST (dead dynamic source)
      0x5f, // PC2 PUSH0
      0x35, // PC3 CALLDATALOAD
      0x56, // PC4 JUMP (unreachable dynamic jump)
      0x5b, // PC5 JUMPDEST (dead predecessor)
      0x50, // PC6 POP
      0x5b, // PC7 JUMPDEST (dead, requires two entry slots)
      0x01, // PC8 ADD
      0x00, // PC9 STOP
  };
  const auto Interp = runEvmBytecode("dead_deep_entry_interp", Bytecode,
                                     common::RunMode::InterpMode);
  const auto Multi = runEvmBytecode("dead_deep_entry_multipass", Bytecode,
                                    common::RunMode::MultipassMode);
#ifdef ZEN_ENABLE_JIT
  EXPECT_TRUE(Multi.JITCompiled) << "dead CFG blocked JIT compilation";
#endif
  EXPECT_EQ(Multi.Status, Interp.Status);
  EXPECT_EQ(Multi.OutputHex, Interp.OutputHex);
}

TEST(EVMDeepEntry, InvalidConstantJumpJITsAndTraps) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0xff, // PC0 PUSH1 0xff (invalid jump destination)
      0x56,       // PC2 JUMP
      0x5b,       // PC3 JUMPDEST (dead predecessor)
      0x50,       // PC4 POP
      0x5b,       // PC5 JUMPDEST (dead, requires two entry slots)
      0x01,       // PC6 ADD
      0x00,       // PC7 STOP
  };
  COMPILER::EVMAnalyzer Analyzer(EVMC_CANCUN);
  ASSERT_TRUE(Analyzer.analyze(Bytecode.data(), Bytecode.size()));
  const auto &Blocks = Analyzer.getBlockInfos();
  const auto SourceIt = Blocks.find(0);
  ASSERT_NE(SourceIt, Blocks.end());
  EXPECT_FALSE(Analyzer.hasUnknownDynamicJumpTargets());
  EXPECT_FALSE(SourceIt->second.HasDynamicJump);
  const auto Interp = runEvmBytecode("invalid_constant_jump_interp", Bytecode,
                                     common::RunMode::InterpMode);
  const auto Multi = runEvmBytecode("invalid_constant_jump_multipass", Bytecode,
                                    common::RunMode::MultipassMode);
#ifdef ZEN_ENABLE_JIT
  EXPECT_TRUE(Multi.JITCompiled) << "constant-invalid jump did not JIT";
#endif
  EXPECT_NE(Interp.Status, EVMC_SUCCESS);
  EXPECT_EQ(Interp.Status, EVMC_BAD_JUMP_DESTINATION);
  EXPECT_EQ(Multi.Status, Interp.Status);
  EXPECT_EQ(Multi.OutputHex, Interp.OutputHex);
}

// Regression: a lifted block with a hidden live-in prefix (HiddenLiveInPrefix
// Depth > 0) that takes a materializing exit must spill its logical stack from
// the stack bottom, not from byte offset Hidden*32. The lifted logical stack
// already spans the full absolute entry depth, so an offset spill writes the
// stack Hidden slots too high and inflates the recorded StackSize by Hidden.
// The inflated depth suppresses a runtime underflow check in a later block,
// diverging from the interpreter.
//
// Shape (confirmed by analysis): block S at PC12 is lifted with Hidden=1 and
// exits via a constant JUMP to the non-lifted block T at PC16, which pops two
// slots while only the single prefix slot is live. The interpreter underflows
// at the second POP; before the fix the JIT's inflated StackSize lets the
// underflow check pass and the block runs to STOP, so status diverges.
TEST(EVMLiftedStackDepth, HiddenPrefixMaterializingExitMatchesInterp) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0xAA, // PC0  PUSH1 0xAA  (live-in prefix)
      0x60, 0x01, // PC2  PUSH1 0x01  (cond = 1, jump taken)
      0x60, 0x0C, // PC4  PUSH1 0x0C  (S entry = 12)
      0x57,       // PC6  JUMPI
      0x60, 0xBB, // PC7  PUSH1 0xBB  (F: second, depth-2 predecessor of T)
      0x60, 0x10, // PC9  PUSH1 0x10  (T = 16)
      0x56,       // PC11 JUMP        (F -> T at depth 2)
      0x5b,       // PC12 JUMPDEST    (S: lifted, Hidden = 1)
      0x60, 0x10, // PC13 PUSH1 0x10  (T = 16)
      0x56,       // PC15 JUMP        (S -> T at depth 1, materializing)
      0x5b,       // PC16 JUMPDEST    (T: non-lifted, pops 2)
      0x50,       // PC17 POP
      0x50,       // PC18 POP         (underflow: only 1 slot present)
      0x00,       // PC19 STOP
  };
  const std::vector<uint8_t> CallData;
  auto Interp = runEvmBytecode("hidden_prefix_interp", Bytecode,
                               common::RunMode::InterpMode, CallData);
  auto Multi = runEvmBytecode("hidden_prefix_multipass", Bytecode,
                              common::RunMode::MultipassMode, CallData);
#ifdef ZEN_ENABLE_JIT
  EXPECT_TRUE(Multi.JITCompiled) << "multipass did not JIT-compile";
#endif
  // The interpreter is the reference: the second POP underflows, so the run
  // must not report success. If this ever succeeds the test has stopped
  // exercising the underflow boundary and must be revisited.
  EXPECT_NE(Interp.Status, EVMC_SUCCESS)
      << "interpreter unexpectedly succeeded; test no longer exercises the "
         "underflow boundary";
  EXPECT_EQ(Multi.Status, Interp.Status) << "status diverged";
  EXPECT_EQ(Multi.OutputHex, Interp.OutputHex) << "output diverged";
}

TEST(EVMLiftedStackDepth, BackwardDynamicEntryMatchesInterpreter) {
  // A reachable indirect jump can target PC3 backward with a hidden stack
  // value. PC3 also has a statically resolved depth-0 entry, but that depth
  // must not allow its plain successor PC8 to lift and discard the hidden
  // value before PC11 consumes it.
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x0e, // PC0  PUSH1 14
      0x56,       // PC2  JUMP
      0x5b,       // PC3  JUMPDEST (backward dynamic target)
      0x5f,       // PC4  PUSH0 (condition false)
      0x60, 0x0b, // PC5  PUSH1 11
      0x57,       // PC7  JUMPI
      0x60, 0x0b, // PC8  PUSH1 11 (plain static successor)
      0x56,       // PC10 JUMP
      0x5b,       // PC11 JUMPDEST
      0x50,       // PC12 POP (consumes hidden 0xaa)
      0x00,       // PC13 STOP
      0x5b,       // PC14 JUMPDEST
      0x5f,       // PC15 PUSH0 (condition false)
      0x60, 0x03, // PC16 PUSH1 3
      0x57,       // PC18 JUMPI (static depth-0 edge to PC3)
      0x60, 0xaa, // PC19 PUSH1 0xaa (hidden caller-frame value)
      0x5f,       // PC21 PUSH0 (CALLDATALOAD offset)
      0x35,       // PC22 CALLDATALOAD
      0x56,       // PC23 dynamic backward JUMP to PC3
  };
  std::vector<uint8_t> CallData(32, 0);
  CallData.back() = 0x03;

  expectInterpMatchesMultipassWithGas("backward_dynamic_entry", Bytecode,
                                      CallData);
}

// Deep-entry risk shape: block PC33 is a shared "increment-and-return"
// subroutine that returns via a stack-passed return PC (SWAP1 then dynamic
// JUMP), so per-block abstract-stack analysis cannot resolve its return
// continuations. Their ResolvedEntryStackDepth stays < 0 and the invalidation
// cascades along the static CFG.
//
// One continuation (PC18) falls through to PC22, whose ADD reads two stack
// slots -- a static successor of an unresolved-depth block that reads 2 slots.
// The non-lifted path reads its required values from the runtime stack and does
// not need a statically resolved absolute entry depth.
//
// Execution: two calls into PC33 turn the initial 0x05 into 0x08 (0x05+1 in the
// outer frame, 0x07+1 in the inner frame), which is MSTOREd and RETURNed as a
// single 32-byte word.
TEST(EVMDeepEntry, ReachableInternalCallJITsAndMatchesInterpreter) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x08, // PC0  PUSH1 0x08
      0x60, 0x05, // PC2  PUSH1 0x05  (value threaded through the subroutine)
      0x60, 0x21, // PC4  PUSH1 0x21  (return PC = 33)
      0x56,       // PC6  JUMP        (call subroutine at PC33)
      0xfe,       // PC7  INVALID
      0x5b,       // PC8  JUMPDEST    (outer return continuation)
      0x60, 0x00, // PC9  PUSH1 0x00
      0x60, 0x12, // PC11 PUSH1 0x12  (return PC = 18)
      0x60, 0x07, // PC13 PUSH1 0x07
      0x60, 0x21, // PC15 PUSH1 0x21  (call subroutine at PC33)
      0x56,       // PC17 JUMP
      0x5b,       // PC18 JUMPDEST    (inner return continuation)
      0x60, 0x00, // PC19 PUSH1 0x00
      0x50,       // PC21 POP
      0x5b,       // PC22 JUMPDEST    (static successor: ADD reads 2 slots)
      0x01,       // PC23 ADD
      0x60, 0x00, // PC24 PUSH1 0x00
      0x52,       // PC26 MSTORE
      0x60, 0x20, // PC27 PUSH1 0x20
      0x60, 0x00, // PC29 PUSH1 0x00
      0xf3,       // PC31 RETURN
      0xfe,       // PC32 INVALID
      0x5b,       // PC33 JUMPDEST    (increment-and-return subroutine)
      0x60, 0x01, // PC34 PUSH1 0x01
      0x01,       // PC36 ADD
      0x90,       // PC37 SWAP1
      0x56,       // PC38 JUMP        (dynamic return via stack PC)
  };
  COMPILER::EVMAnalyzer Analyzer(EVMC_CANCUN);
  ASSERT_TRUE(Analyzer.analyze(Bytecode.data(), Bytecode.size()));
  const auto DeepEntryIt = Analyzer.getBlockInfos().find(22);
  ASSERT_NE(DeepEntryIt, Analyzer.getBlockInfos().end());
  EXPECT_LT(DeepEntryIt->second.ResolvedEntryStackDepth, 0);
  EXPECT_FALSE(DeepEntryIt->second.CanLiftStack);

  const std::vector<uint8_t> CallData;
  auto Interp = runEvmBytecode("deep_entry_interp", Bytecode,
                               common::RunMode::InterpMode, CallData);
  auto Multi = runEvmBytecode("deep_entry_multipass", Bytecode,
                              common::RunMode::MultipassMode, CallData);
#ifdef ZEN_ENABLE_JIT
  EXPECT_TRUE(Multi.JITCompiled) << "deep-entry module did not JIT-compile";
#endif
  EXPECT_EQ(Interp.Status, EVMC_SUCCESS) << "interpreter did not succeed";
  EXPECT_EQ(Multi.Status, Interp.Status) << "status diverged";
  EXPECT_EQ(Multi.OutputHex, Interp.OutputHex) << "output diverged";
  // Ground truth: 32-byte word holding 0x08, guarding against both engines
  // agreeing on a wrong value.
  EXPECT_EQ(Interp.OutputHex,
            "0000000000000000000000000000000000000000000000000000000000000008");
}

namespace {

void appendPush2(std::vector<uint8_t> &Code, uint16_t Value) {
  Code.push_back(0x61);
  Code.push_back(static_cast<uint8_t>(Value >> 8));
  Code.push_back(static_cast<uint8_t>(Value));
}

void appendPush32Pattern(std::vector<uint8_t> &Code, uint8_t Seed) {
  Code.push_back(0x7f);
  for (uint8_t I = 0; I < 32; ++I) {
    Code.push_back(static_cast<uint8_t>(Seed + I));
  }
}

void appendPush32HighOffset(std::vector<uint8_t> &Code) {
  Code.push_back(0x7f);
  Code.push_back(0x01);
  Code.insert(Code.end(), 31, 0x00);
}

std::vector<uint8_t> log0LargeRangeBytecode() {
  std::vector<uint8_t> Code;
  appendPush32Pattern(Code, 0x11);
  appendPush2(Code, 0x1000);
  Code.push_back(0x52); // MSTORE(0x1000, pattern)
  Code.push_back(0x60);
  Code.push_back(0x20);
  appendPush2(Code, 0x1000);
  Code.push_back(0xa0); // LOG0(0x1000, 32)
  return Code;
}

std::vector<uint8_t> log4LargeRangeBytecode() {
  std::vector<uint8_t> Code;
  appendPush32Pattern(Code, 0x41);
  appendPush2(Code, 0x2000);
  Code.push_back(0x52); // MSTORE(0x2000, pattern)
  Code.insert(Code.end(), {0x60, 0x01, 0x60, 0x02, 0x60, 0x03, 0x60, 0x04});
  Code.push_back(0x60);
  Code.push_back(0x20);
  appendPush2(Code, 0x2000);
  Code.push_back(0xa4); // LOG4(0x2000, 32, topics)
  return Code;
}

std::vector<uint8_t> log0DynamicEmptyHighOffsetBytecode() {
  std::vector<uint8_t> Code;
  Code.push_back(0x36); // CALLDATASIZE, zero in this test
  appendPush32HighOffset(Code);
  Code.push_back(0xa0); // LOG0(high_offset, calldata_size)
  return Code;
}

std::vector<uint8_t> log0StaticHighOffsetBytecode() {
  std::vector<uint8_t> Code;
  Code.push_back(0x60);
  Code.push_back(0x20);
  appendPush32HighOffset(Code);
  Code.push_back(0xa0); // must fail as static-mode violation, not OOG
  return Code;
}

std::vector<uint8_t> preparedCallMemoryBytecode(evmc_opcode Opcode) {
  std::vector<uint8_t> Code;
  appendPush32Pattern(Code, 0x21);
  Code.insert(Code.end(), {0x60, 0x80, 0x52}); // MSTORE(0x80, pattern)
  Code.insert(Code.end(), {0x5f, 0x60, 0xa0, 0x52});
  // Transfer to a successor block so the CALL consumes a propagated CFG fact.
  Code.push_back(0x60);
  const size_t JumpDestImmediate = Code.size();
  Code.push_back(0x00);
  Code.push_back(0x56);
  Code[JumpDestImmediate] = static_cast<uint8_t>(Code.size());
  Code.push_back(0x5b);

  Code.insert(Code.end(), {
                              0x60, 0x20, // return size
                              0x60, 0xa0, // return offset
                              0x60, 0x20, // argument size
                              0x60, 0x80, // argument offset
                          });
  if (Opcode == OP_CALL || Opcode == OP_CALLCODE) {
    Code.push_back(OP_PUSH0); // value
  }
  Code.insert(Code.end(), {
                              0x60,
                              0x04, // identity precompile
                              0x61,
                              0xff,
                              0xff,
                              static_cast<uint8_t>(Opcode),
                              0x50, // POP success
                              0x60,
                              0x20, // RETURN size
                              0x60,
                              0xa0, // RETURN offset
                              0xf3,
                          });
  return Code;
}

std::vector<uint8_t> twoWordKeccakBytecode() {
  return {
      OP_CALLER, OP_PUSH0,  OP_MSTORE, OP_PUSH1, 0x05,     OP_PUSH1,
      0x20,      OP_MSTORE, OP_PUSH1,  0x40,     OP_PUSH0, OP_KECCAK256,
  };
}

std::vector<uint8_t> staticCallEmptyHighOffsetsBytecode() {
  std::vector<uint8_t> Code;
  Code.push_back(0x5f); // return size
  appendPush32HighOffset(Code);
  Code.push_back(0x5f); // argument size
  appendPush32HighOffset(Code);
  Code.insert(Code.end(), {
                              0x60,
                              0x04, // identity precompile
                              0x61,
                              0xff,
                              0xff,
                              0xfa, // STATICCALL
                              0x5f,
                              0x52, // MSTORE(0, success)
                              0x60,
                              0x20,
                              0x5f,
                              0xf3,
                          });
  return Code;
}

} // namespace

TEST(EVMLogMemoryPreexpandDifferential, LogDataMatchesInterpreter) {
  EXPECT_TRUE(expectInterpMatchesMultipass("log0_large_range",
                                           log0LargeRangeBytecode(), {}));
  EXPECT_TRUE(expectInterpMatchesMultipass("log4_large_range",
                                           log4LargeRangeBytecode(), {}));
}

TEST(EVMLogMemoryPreexpandDifferential, EmptyDynamicRangeIgnoresHighOffset) {
  EXPECT_TRUE(expectInterpMatchesMultipass("log0_dynamic_empty_high_offset",
                                           log0DynamicEmptyHighOffsetBytecode(),
                                           {}));
}

TEST(EVMLogMemoryPreexpandDifferential, StaticModePrecedesMemoryExpansion) {
  const auto Bytecode = log0StaticHighOffsetBytecode();
  auto Interp = runEvmBytecode("log0_static_high_offset_interp", Bytecode,
                               common::RunMode::InterpMode, {},
                               static_cast<uint32_t>(EVMC_STATIC));
  auto Multi = runEvmBytecode("log0_static_high_offset_multipass", Bytecode,
                              common::RunMode::MultipassMode, {},
                              static_cast<uint32_t>(EVMC_STATIC));
#ifdef ZEN_ENABLE_JIT
  EXPECT_TRUE(Multi.JITCompiled)
      << "multipass did not JIT-compile static LOG test";
#endif
  EXPECT_EQ(Interp.Status, EVMC_STATIC_MODE_VIOLATION);
  EXPECT_EQ(Multi.Status, Interp.Status);
  EXPECT_EQ(Interp.LogCount, size_t{0});
  EXPECT_EQ(Multi.LogCount, size_t{0});
  EXPECT_EQ(Multi.LogsSignature, Interp.LogsSignature);
}

TEST(EVMCallMemoryProofDifferential, PreparedIdentityCallMatchesInterpreter) {
  const auto Output = expectInterpMatchesMultipassWithGas(
      "staticcall_prepared_memory", preparedCallMemoryBytecode(OP_STATICCALL),
      {});
  EXPECT_EQ(Output,
            "2122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F40");
}

TEST(EVMCallMemoryProofDifferential,
     PreparedCallKindsMatchInterpreterOutputAndGas) {
  const std::pair<evmc_opcode, const char *> Cases[] = {
      {OP_CALL, "call"},
      {OP_CALLCODE, "callcode"},
      {OP_DELEGATECALL, "delegatecall"},
  };
  for (const auto &[Opcode, Label] : Cases) {
    const auto Output = expectInterpMatchesMultipassWithGas(
        std::string(Label) + "_prepared_memory",
        preparedCallMemoryBytecode(Opcode), {});
    EXPECT_EQ(
        Output,
        "2122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F40")
        << Label;
  }
}

TEST(EVMKeccakMemoryProofDifferential,
     TwoWordHelperWordGasOutOfGasBoundaryMatchesInterpreter) {
  const auto Bytecode = twoWordKeccakBytecode();
  constexpr uint64_t ProbeGasLimit = 1'000'000;
  const auto Reference =
      runEvmBytecode("two_word_keccak_word_gas_reference", Bytecode,
                     common::RunMode::InterpMode, {}, 0u, true, ProbeGasLimit);
  ASSERT_EQ(Reference.Status, EVMC_SUCCESS);
  ASSERT_GE(Reference.GasLeft, 0);
  const auto RequiredGas =
      ProbeGasLimit - static_cast<uint64_t>(Reference.GasLeft);
  ASSERT_GT(RequiredGas, uint64_t{1});

  const auto Interp = runEvmBytecode("two_word_keccak_word_gas_oog_interp",
                                     Bytecode, common::RunMode::InterpMode, {},
                                     0u, true, RequiredGas - 1);
  const auto Multi = runEvmBytecode("two_word_keccak_word_gas_oog_multipass",
                                    Bytecode, common::RunMode::MultipassMode,
                                    {}, 0u, true, RequiredGas - 1);
#ifdef ZEN_ENABLE_JIT
  EXPECT_TRUE(Multi.JITCompiled);
#endif
  EXPECT_EQ(Interp.Status, EVMC_OUT_OF_GAS);
  EXPECT_EQ(Multi.Status, Interp.Status);
  EXPECT_EQ(Multi.GasLeft, Interp.GasLeft);
  EXPECT_EQ(Multi.OutputHex, Interp.OutputHex);
}

TEST(EVMCallMemoryProofDifferential, EmptyRangesIgnoreHighOffsets) {
  const auto Output = expectInterpMatchesMultipassWithGas(
      "staticcall_empty_high_offsets", staticCallEmptyHighOffsetsBytecode(),
      {});
  EXPECT_EQ(Output,
            "0000000000000000000000000000000000000000000000000000000000000001");
}

#endif
