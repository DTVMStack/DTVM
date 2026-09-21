// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <gtest/gtest.h>
#include <string_view>
#include <yaml-cpp/yaml.h>

#include "evm/evm.h"
#include "evm/interpreter.h"
#include "evm_test_host.hpp"
#include "runtime/evm_module.h"
#include "utils/evm.h"
#include "zetaengine.h"

using namespace zen;
using namespace zen::evm;
using namespace zen::runtime;

namespace {

std::filesystem::path getEvmAsmDirPath() {
  return std::filesystem::path(__FILE__).parent_path() /
         std::filesystem::path("../../tests/evm_asm");
}

std::vector<std::string> getAllEvmBytecodeFiles() {
  std::vector<std::string> Files;
  std::filesystem::path DirPath = getEvmAsmDirPath();

  if (!std::filesystem::exists(DirPath)) {
    std::cerr << "tests/evm_asm does not exist: " << DirPath.string()
              << std::endl;
    return Files;
  }

  for (const auto &Entry : std::filesystem::directory_iterator(DirPath)) {
    if (Entry.is_regular_file() && Entry.path().extension() == ".hex") {
      Files.push_back(Entry.path().string());
    }
  }

  std::sort(Files.begin(), Files.end());

  if (Files.empty()) {
    std::cerr << "No EVM hex files found in tests/evm_asm, "
              << "maybe you should convert the asm to hex first" << std::endl;
  }

  return Files;
}

struct ExpectedResult {
  std::string Status;
  uint8_t ErrorCode = 0;
  std::vector<std::string> Stack;
  std::string Memory;
  std::map<std::string, std::string> Storage;
  std::map<std::string, std::string> TransientStorage;
  std::string ReturnValue;
  std::vector<std::string> Events;
};

ExpectedResult readExpectedResult(const std::string &FilePath) {
  std::filesystem::path InputFilePath(FilePath);
  ExpectedResult Result;

  std::filesystem::path ExpectedPath =
      InputFilePath.parent_path() /
      (InputFilePath.stem().stem().string() + ".expected");

  std::ifstream Fin(ExpectedPath);
  if (!Fin) {
    return Result;
  }

  try {
    YAML::Node Doc = YAML::Load(Fin);

    if (Doc["status"]) {
      Result.Status = Doc["status"].as<std::string>();
    }

    if (Doc["error_code"]) {
      Result.ErrorCode = Doc["error_code"].as<uint8_t>();
    }

    if (Doc["stack"] && Doc["stack"].IsSequence()) {
      for (const auto &item : Doc["stack"]) {
        Result.Stack.push_back(item.as<std::string>());
      }
    }

    if (Doc["memory"]) {
      Result.Memory = Doc["memory"].as<std::string>();
    }

    if (Doc["storage"]) {
      if (!Doc["storage"].IsMap()) {
        throw std::runtime_error("Expected 'storage' to be a map type");
      }
      for (const auto &item : Doc["storage"]) {
        Result.Storage[item.first.as<std::string>()] =
            item.second.as<std::string>();
      }
    }

    if (Doc["transient_storage"]) {
      if (!Doc["transient_storage"].IsMap()) {
        throw std::runtime_error(
            "Expected 'transient_storage' to be a map type");
      }
      for (const auto &item : Doc["transient_storage"]) {
        Result.TransientStorage[item.first.as<std::string>()] =
            item.second.as<std::string>();
      }
    }

    if (Doc["return"]) {
      Result.ReturnValue = Doc["return"].as<std::string>();
    }

    if (Doc["events"]) {
      if (!Doc["events"].IsSequence()) {
        throw std::runtime_error("Expected 'events' to be a sequence type");
      }
      for (const auto &item : Doc["events"]) {
        if (!item.IsScalar()) {
          throw std::runtime_error("Expected each event to be a string type");
        }
        Result.Events.push_back(item.as<std::string>());
      }
    }
  } catch (const YAML::Exception &E) {
    std::cerr << "YAML parsing error: " << E.what() << std::endl;
    return Result;
  }

  return Result;
}

#ifdef ZEN_ENABLE_MULTIPASS_JIT
struct EVMExecutionResult {
  evmc_status_code Status = EVMC_INTERNAL_ERROR;
  std::string OutputHex;
  int64_t GasLeft = 0;
  bool JITCompiled = false;
};

EVMExecutionResult executeEvmBytecode(const std::string &ModuleName,
                                      const std::vector<uint8_t> &Bytecode,
                                      common::RunMode Mode,
                                      std::vector<uint8_t> CallData = {},
                                      uint64_t ExecutionGasLimitOverride = 0) {
  EVMExecutionResult Empty;

  RuntimeConfig Config;
  Config.Mode = Mode;
  Config.EnableEvmGasMetering = true;

  auto MockedHost = std::make_unique<zen::evm::ZenMockedEVMHost>();
  MockedHost->tx_context.tx_origin = zen::evm::DEFAULT_DEPLOYER_ADDRESS;
  auto RT = Runtime::newEVMRuntime(Config, MockedHost.get());
  EXPECT_TRUE(RT != nullptr) << "Failed to create runtime";
  if (!RT) {
    return Empty;
  }
  MockedHost->setRuntime(RT.get());

  auto ModRet = RT->loadEVMModule(ModuleName, Bytecode.data(), Bytecode.size());
  EXPECT_TRUE(ModRet) << "Failed to load module: " << ModuleName;
  if (!ModRet) {
    return Empty;
  }
  EVMModule *Mod = *ModRet;

  Isolation *Iso = RT->createManagedIsolation();
  EXPECT_TRUE(Iso != nullptr) << "Failed to create isolation: " << ModuleName;
  if (!Iso) {
    return Empty;
  }

  uint64_t ExecutionGasLimit = ExecutionGasLimitOverride;
  if (ExecutionGasLimit == 0) {
    uint64_t GasLimit = 0xFFFF'FFFF'FFFF;
    const uint64_t IntrinsicGas = zen::evm::BASIC_EXECUTION_COST;
    ExecutionGasLimit = GasLimit - IntrinsicGas;
  }

  auto InstRet = Iso->createEVMInstance(*Mod, ExecutionGasLimit);
  EXPECT_TRUE(InstRet) << "Failed to create instance: " << ModuleName;
  if (!InstRet) {
    return Empty;
  }
  EVMInstance *Inst = *InstRet;
  Inst->setRevision(evmc_revision::EVMC_OSAKA);

  evmc_message Msg = {
      .kind = EVMC_CALL,
      .flags = 0u,
      .depth = 0,
      .gas = static_cast<int64_t>(ExecutionGasLimit),
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
  Exec.OutputHex =
      zen::utils::toHex(RawResult.output_data, RawResult.output_size);
  Exec.GasLeft = RawResult.gas_left;
  return Exec;
}

EVMExecutionResult executeEvmBytecodeFile(const std::string &FilePath,
                                          common::RunMode Mode,
                                          std::vector<uint8_t> CallData = {}) {
  EVMExecutionResult Empty;

  std::ifstream Fin(FilePath);
  EXPECT_TRUE(Fin.is_open()) << "Failed to open test file: " << FilePath;
  if (!Fin.is_open()) {
    return Empty;
  }

  std::string Hex;
  Fin >> Hex;
  zen::utils::trimString(Hex);
  auto BytecodeBuf = zen::utils::fromHex(Hex);
  EXPECT_TRUE(BytecodeBuf) << "Failed to convert hex to bytecode";
  if (!BytecodeBuf) {
    return Empty;
  }

  return executeEvmBytecode(FilePath, *BytecodeBuf, Mode, std::move(CallData));
}

std::vector<uint8_t> makeUint256Calldata(uint64_t Value) {
  std::vector<uint8_t> Data(32, 0);
  for (size_t I = 0; I < sizeof(Value); ++I) {
    Data[Data.size() - 1 - I] = static_cast<uint8_t>(Value & 0xff);
    Value >>= 8;
  }
  return Data;
}

std::string computeTwoWordKeccakHex(const std::vector<uint8_t> &Word0,
                                    const std::vector<uint8_t> &Word1) {
  EXPECT_EQ(Word0.size(), 32U);
  EXPECT_EQ(Word1.size(), 32U);
  std::vector<uint8_t> Input;
  Input.reserve(64);
  Input.insert(Input.end(), Word0.begin(), Word0.end());
  Input.insert(Input.end(), Word1.begin(), Word1.end());
  const auto Hash = zen::host::evm::crypto::keccak256(Input);
  return zen::utils::toHex(Hash.data(), Hash.size());
}

std::string computeKeccakHex(const std::vector<uint8_t> &Input) {
  const auto Hash = zen::host::evm::crypto::keccak256(Input);
  return zen::utils::toHex(Hash.data(), Hash.size());
}

std::vector<uint8_t> makePaddedAddressWord(const evmc::address &Address) {
  std::vector<uint8_t> Word(32, 0);
  std::memcpy(Word.data() + 12, Address.bytes, sizeof(Address.bytes));
  return Word;
}

std::vector<uint8_t> makeIncrementingBytes(size_t Size) {
  std::vector<uint8_t> Data(Size);
  for (size_t I = 0; I < Data.size(); ++I) {
    Data[I] = static_cast<uint8_t>(I);
  }
  return Data;
}

void expectInterpMatchesMultipass(const std::string &ModuleName,
                                  const std::vector<uint8_t> &Bytecode,
                                  const std::vector<uint8_t> &CallData,
                                  evmc_status_code ExpectedStatus,
                                  const std::string &ExpectedOutputHex = "",
                                  bool CheckGasLeft = true) {
  auto InterpExec = executeEvmBytecode(ModuleName + "_interp", Bytecode,
                                       common::RunMode::InterpMode, CallData);
  auto MultipassExec =
      executeEvmBytecode(ModuleName + "_multipass", Bytecode,
                         common::RunMode::MultipassMode, CallData);

#ifdef ZEN_ENABLE_JIT
  EXPECT_TRUE(MultipassExec.JITCompiled)
      << "Multipass JIT should compile " << ModuleName;
#endif

  EXPECT_EQ(InterpExec.Status, ExpectedStatus)
      << "Interpreter status mismatch for " << ModuleName;
  EXPECT_EQ(MultipassExec.Status, ExpectedStatus)
      << "Multipass status mismatch for " << ModuleName;
  EXPECT_EQ(MultipassExec.Status, InterpExec.Status)
      << "Multipass status diverged from interpreter for " << ModuleName;
  EXPECT_EQ(MultipassExec.OutputHex, InterpExec.OutputHex)
      << "Multipass output diverged from interpreter for " << ModuleName;
  if (CheckGasLeft) {
    EXPECT_EQ(MultipassExec.GasLeft, InterpExec.GasLeft)
        << "Multipass gas_left diverged from interpreter for " << ModuleName;
  }

  if (!ExpectedOutputHex.empty()) {
    EXPECT_EQ(InterpExec.OutputHex, ExpectedOutputHex)
        << "Interpreter output mismatch for " << ModuleName;
    EXPECT_EQ(MultipassExec.OutputHex, ExpectedOutputHex)
        << "Multipass output mismatch for " << ModuleName;
  }
}

void expectMemoryLinearMstoreOverlapResult(uint64_t Stride,
                                           const std::string &ExpectedHex) {
  constexpr std::string_view BytecodeHex =
      "600035808080528101808052810180805281018080528151600052805160205260406000"
      "F3";
  auto BytecodeBuf = zen::utils::fromHex(BytecodeHex);
  ASSERT_TRUE(BytecodeBuf) << "Failed to build overlap probe bytecode";

  auto Exec = executeEvmBytecode("memory_linear_overlap_probe", *BytecodeBuf,
                                 common::RunMode::MultipassMode,
                                 makeUint256Calldata(Stride));

#ifdef ZEN_ENABLE_JIT
  EXPECT_TRUE(Exec.JITCompiled);
#endif
  EXPECT_EQ(Exec.Status, EVMC_SUCCESS);
  EXPECT_EQ(Exec.OutputHex, ExpectedHex);
}

void expectMultipassJitModuleLoads(const std::string &ModuleName,
                                   const std::vector<uint8_t> &Bytecode) {
  RuntimeConfig Config;
  Config.Mode = common::RunMode::MultipassMode;

  auto MockedHost = std::make_unique<zen::evm::ZenMockedEVMHost>();
  MockedHost->tx_context.tx_origin = zen::evm::DEFAULT_DEPLOYER_ADDRESS;
  auto RT = Runtime::newEVMRuntime(Config, MockedHost.get());
  ASSERT_TRUE(RT != nullptr) << "Failed to create runtime";

  MockedHost->setRuntime(RT.get());

  auto ModRet = RT->loadEVMModule(ModuleName, Bytecode.data(), Bytecode.size());
  ASSERT_TRUE(ModRet) << "Failed to load module: " << ModuleName;

#ifdef ZEN_ENABLE_JIT
  EVMModule *Mod = *ModRet;
  EXPECT_TRUE(Mod->getJITCode() != nullptr && Mod->getJITCodeSize() > 0);
#endif
}
#endif

} // namespace

class EVMSampleTest : public ::testing::TestWithParam<std::string> {};

std::string GetTestName(const testing::TestParamInfo<std::string> &Info) {
  std::filesystem::path Path(Info.param);
  return Path.stem().stem().string();
}

TEST_P(EVMSampleTest, ExecuteSample) {
  const std::string &FilePath = GetParam();

  ASSERT_NE(FilePath, "NoEvmHexFiles")
      << "No EVM hex files found, should convert easm to hex first";

  std::ifstream Fin(FilePath);
  ASSERT_TRUE(Fin.is_open()) << "Failed to open test file: " << FilePath;

  std::string Hex;
  Fin >> Hex;
  zen::utils::trimString(Hex);
  auto BytecodeBuf = zen::utils::fromHex(Hex);
  ASSERT_TRUE(BytecodeBuf) << "Failed to convert hex to bytecode";

  RuntimeConfig Config;
  Config.Mode = common::RunMode::InterpMode;

  auto MockedHost = std::make_unique<zen::evm::ZenMockedEVMHost>();
  MockedHost->tx_context.tx_origin = zen::evm::DEFAULT_DEPLOYER_ADDRESS;

  auto RT = Runtime::newEVMRuntime(Config, MockedHost.get());
  ASSERT_TRUE(RT != nullptr) << "Failed to create runtime";

  // Set runtime for ZenMockedEVMHost to enable precompile calls
  MockedHost->setRuntime(RT.get());

  auto ModRet = RT->loadEVMModule(FilePath);
  ASSERT_TRUE(ModRet) << "Failed to load module: " << FilePath;

  EVMModule *Mod = *ModRet;

  Isolation *Iso = RT->createManagedIsolation();
  ASSERT_TRUE(Iso) << "Failed to create Isolation: " << FilePath;

  // same as evm.codes: 0xFFFF'FFFF'FFFF (281,474,976,710,655)
  uint64_t GasLimit = 0xFFFF'FFFF'FFFF;
  const uint64_t IntrinsicGas = zen::evm::BASIC_EXECUTION_COST;
  const uint64_t ExecutionGasLimit = GasLimit - IntrinsicGas;

  auto InstRet = Iso->createEVMInstance(*Mod, ExecutionGasLimit);
  ASSERT_TRUE(Iso) << "Failed to create Instance: " << FilePath;
  EVMInstance *Inst = *InstRet;
  Inst->setRevision(evmc_revision::EVMC_OSAKA);

  InterpreterExecContext Ctx(Inst);

  BaseInterpreter Interpreter(Ctx);

  evmc_message Msg = {
      .kind = EVMC_CALL,
      .flags = 0u,
      .depth = 0,
      .gas = static_cast<int64_t>(ExecutionGasLimit),
      .recipient = {},
      .sender = zen::evm::DEFAULT_DEPLOYER_ADDRESS,
      .input_data = nullptr,
      .input_size = 0,
      .value = {},
      .create2_salt = {},
      .code_address = {},
      .code = reinterpret_cast<const uint8_t *>(Mod->Code),
      .code_size = Mod->CodeSize,
  };
  Ctx.allocTopFrame(&Msg);

  EXPECT_NO_THROW({ Interpreter.interpret(); });

  // Read expected result from .expected file
  ExpectedResult Expected = readExpectedResult(FilePath);
  if (Expected.ReturnValue.empty() && Expected.Status.empty()) {
    ASSERT_TRUE(false) << "No expected file found for: " << FilePath;
  }

  evmc_status_code ActualStatus = Ctx.getStatus();
  std::string ActualStatusStr = evmc::to_string(ActualStatus);

  if (!Expected.Status.empty()) {
    EXPECT_EQ(ActualStatusStr, Expected.Status)
        << "Test: " << std::filesystem::path(FilePath).filename().string()
        << "\nExpected status: " << Expected.Status
        << "\nActual status: " << ActualStatusStr;
  }

  evmc_status_code expectedStatus =
      static_cast<evmc_status_code>(Expected.ErrorCode);
  EXPECT_EQ(ActualStatus, expectedStatus)
      << "Test: " << std::filesystem::path(FilePath).filename().string()
      << "\nExpected error_code: " << Expected.ErrorCode
      << "\nActual status: " << ActualStatus;

  const auto &Ret = Ctx.getReturnData();
  std::string HexRet = zen::utils::toHex(Ret.data(), Ret.size());

  if (!Expected.ReturnValue.empty()) {
    EXPECT_EQ(HexRet, Expected.ReturnValue)
        << "Test: " << std::filesystem::path(FilePath).filename().string()
        << "\nExpected return: " << Expected.ReturnValue
        << "\nActual return: " << HexRet;
  }

  // TODO: frame has been freed and can't check stack and memory values
  // TODO: storage, transient storage, and events check

  EXPECT_EQ(Ctx.getCurFrame(), nullptr)
      << "Frame should be deallocated after execution";
}

TEST(ZenMockedEVMHostModuleCacheTest, ReusesInternalCallModuleByCodeIdentity) {
  RuntimeConfig Config;
#ifdef ZEN_ENABLE_MULTIPASS_JIT
  Config.Mode = common::RunMode::MultipassMode;
#else
  Config.Mode = common::RunMode::InterpMode;
#endif

  auto MockedHost = std::make_unique<zen::evm::ZenMockedEVMHost>();
  auto RT = Runtime::newEVMRuntime(Config, MockedHost.get());
  ASSERT_TRUE(RT != nullptr) << "Failed to create runtime";
  MockedHost->setRuntime(RT.get());

  const evmc::address SenderAddr = evmc::literals::operator""_address(
      "a94f5374fce5edbc8e2a8697c15331677e6ebf0b");
  const evmc::address ContractAddr = evmc::literals::operator""_address(
      "00000000000000000000000000000000000000c1");

  evmc::MockedAccount SenderAccount;
  SenderAccount.set_balance(1000);
  MockedHost->accounts[SenderAddr] = SenderAccount;

  evmc::MockedAccount ContractAccount;
  ContractAccount.code = {0x60, 0x00, 0x50, 0x00}; // PUSH1 0; POP; STOP
  ContractAccount.codehash.bytes[31] = 0xaa;
  MockedHost->accounts[ContractAddr] = ContractAccount;

  evmc_message Msg{};
  Msg.kind = EVMC_CALL;
  Msg.gas = 100000;
  Msg.recipient = ContractAddr;
  Msg.sender = SenderAddr;
  Msg.code_address = ContractAddr;

  evmc::Result First = MockedHost->call(Msg);
  ASSERT_EQ(First.status_code, EVMC_SUCCESS);
  EXPECT_EQ(MockedHost->getInternalCallModuleCacheSize(), 1U);

  evmc::Result Second = MockedHost->call(Msg);
  ASSERT_EQ(Second.status_code, EVMC_SUCCESS);
  EXPECT_EQ(MockedHost->getInternalCallModuleCacheSize(), 1U);

  // Same address and codehash but different bytecode must not reuse the cached
  // module. This protects replay tests from stale code when state changes.
  MockedHost->accounts[ContractAddr].code = {0x60, 0x01, 0x50, 0x00};
  evmc::Result Third = MockedHost->call(Msg);
  ASSERT_EQ(Third.status_code, EVMC_SUCCESS);
  EXPECT_EQ(MockedHost->getInternalCallModuleCacheSize(), 2U);
}

// if there is no evm files, we add a special string to make the test run and
// handle it in the test case
auto EvmFiles = getAllEvmBytecodeFiles();
INSTANTIATE_TEST_SUITE_P(
    EVMSamples, EVMSampleTest,
    ::testing::ValuesIn(EvmFiles.empty()
                            ? std::vector<std::string>{"NoEvmHexFiles"}
                            : EvmFiles),
    GetTestName);

#ifdef ZEN_ENABLE_MULTIPASS_JIT
TEST(EVMMultipassLinearPrecheckTest, MemoryLinearMloadStepUsesNonZeroStride) {
  const auto FilePath =
      (getEvmAsmDirPath() / "memory_linear_mload_step.evm.hex").string();
  auto Exec = executeEvmBytecodeFile(FilePath, common::RunMode::MultipassMode,
                                     makeUint256Calldata(0x20));

#ifdef ZEN_ENABLE_JIT
  EXPECT_TRUE(Exec.JITCompiled);
#endif
  EXPECT_EQ(Exec.Status, EVMC_SUCCESS);
  EXPECT_EQ(Exec.OutputHex,
            "0000000000000000000000000000000000000000000000000000000000000080");
}

TEST(EVMMultipassLinearPrecheckTest, MemoryLinearMstoreStepUsesNonZeroStride) {
  const auto FilePath =
      (getEvmAsmDirPath() / "memory_linear_mstore_step.evm.hex").string();
  auto Exec = executeEvmBytecodeFile(FilePath, common::RunMode::MultipassMode,
                                     makeUint256Calldata(0x20));

#ifdef ZEN_ENABLE_JIT
  EXPECT_TRUE(Exec.JITCompiled);
#endif
  EXPECT_EQ(Exec.Status, EVMC_SUCCESS);
  EXPECT_EQ(Exec.OutputHex,
            "0000000000000000000000000000000000000000000000000000000000000080");
}

TEST(EVMMultipassLinearPrecheckTest,
     MemoryLinearMstoreOverlapStride8PreservesSemantics) {
  expectMemoryLinearMstoreOverlapResult(
      0x08, "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000020");
}

TEST(EVMMultipassLinearPrecheckTest,
     MemoryLinearMstoreOverlapStride16PreservesSemantics) {
  expectMemoryLinearMstoreOverlapResult(
      0x10, "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000040");
}

TEST(EVMMultipassLinearPrecheckTest,
     MemoryLinearMstoreOverlapStride24DisablesElisionButPreservesSemantics) {
  expectMemoryLinearMstoreOverlapResult(
      0x18, "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000060");
}

TEST(EVMMultipassDisplacedBytes32Test,
     MemoryConstMloadAboveI32DisplacementLimitCompiles) {
  const std::vector<uint8_t> Bytecode = {0x63, 0x7f, 0xff, 0xff,
                                         0xe8, 0x51, 0x00};
  expectMultipassJitModuleLoads("memory_const_mload_i32_disp_limit", Bytecode);
}

TEST(EVMMultipassDisplacedBytes32Test,
     MemoryConstMstoreAboveI32DisplacementLimitCompiles) {
  const std::vector<uint8_t> Bytecode = {0x60, 0x01, 0x63, 0x7f, 0xff,
                                         0xff, 0xe8, 0x52, 0x00};
  expectMultipassJitModuleLoads("memory_const_mstore_i32_disp_limit", Bytecode);
}

TEST(EVMMultipassDisplacedBytes32Test,
     MemoryConstMloadAboveI32DisplacementLimitReturnsOutOfGas) {
  const std::vector<uint8_t> Bytecode = {0x63, 0x7f, 0xff, 0xff,
                                         0xe8, 0x51, 0x00};
  auto Exec =
      executeEvmBytecode("memory_const_mload_i32_disp_limit_oog", Bytecode,
                         common::RunMode::MultipassMode, {}, 1'000'000);

#ifdef ZEN_ENABLE_JIT
  EXPECT_TRUE(Exec.JITCompiled);
#endif
  EXPECT_EQ(Exec.Status, EVMC_OUT_OF_GAS);
}

TEST(EVMMultipassDisplacedBytes32Test,
     MemoryConstMstoreAboveI32DisplacementLimitReturnsOutOfGas) {
  const std::vector<uint8_t> Bytecode = {0x60, 0x01, 0x63, 0x7f, 0xff,
                                         0xff, 0xe8, 0x52, 0x00};
  auto Exec =
      executeEvmBytecode("memory_const_mstore_i32_disp_limit_oog", Bytecode,
                         common::RunMode::MultipassMode, {}, 1'000'000);

#ifdef ZEN_ENABLE_JIT
  EXPECT_TRUE(Exec.JITCompiled);
#endif
  EXPECT_EQ(Exec.Status, EVMC_OUT_OF_GAS);
}

TEST(EVMMultipassCopyHelperTest,
     CallDataCopyMatchesInterpreterAfterMemoryPreExpand) {
  auto BytecodeBuf = zen::utils::fromHex("6030601060203760406020f3");
  ASSERT_TRUE(BytecodeBuf) << "Failed to parse calldata-copy bytecode";

  const std::vector<uint8_t> CallData = makeIncrementingBytes(80);
  std::vector<uint8_t> ExpectedOutput;
  ExpectedOutput.insert(ExpectedOutput.end(), CallData.begin() + 16,
                        CallData.begin() + 64);
  ExpectedOutput.resize(64, 0);

  expectInterpMatchesMultipass(
      "calldatacopy_preexpand", *BytecodeBuf, CallData, EVMC_SUCCESS,
      zen::utils::toHex(ExpectedOutput.data(), ExpectedOutput.size()));
}

TEST(EVMMultipassCopyHelperTest,
     CallDataCopyZeroSizeWithOversizedDestRemainsNoOp) {
  auto BytecodeBuf = zen::utils::fromHex(
      "60006000"
      "7f0100000000000000000000000000000000000000000000000000000000000000"
      "3760006000f3");
  ASSERT_TRUE(BytecodeBuf)
      << "Failed to parse zero-size calldata-copy bytecode";

  expectInterpMatchesMultipass("calldatacopy_zero_size_oversized_dest",
                               *BytecodeBuf, {}, EVMC_SUCCESS);
}

TEST(EVMMultipassCopyHelperTest,
     CallDataCopyNonZeroSizeWithOversizedDestReturnsOutOfGas) {
  auto BytecodeBuf = zen::utils::fromHex(
      "60016000"
      "7f0100000000000000000000000000000000000000000000000000000000000000"
      "3700");
  ASSERT_TRUE(BytecodeBuf)
      << "Failed to parse oversized calldata-copy bytecode";

  expectInterpMatchesMultipass("calldatacopy_nonzero_size_oversized_dest",
                               *BytecodeBuf, {}, EVMC_OUT_OF_GAS);
}

TEST(EVMMultipassCopyHelperTest,
     CodeCopyMatchesInterpreterAfterMemoryPreExpand) {
  auto BytecodeBuf = zen::utils::fromHex("6008600060003960206000f3");
  ASSERT_TRUE(BytecodeBuf) << "Failed to parse code-copy bytecode";

  std::vector<uint8_t> ExpectedOutput = {0x60, 0x08, 0x60, 0x00,
                                         0x60, 0x00, 0x39, 0x60};
  ExpectedOutput.resize(32, 0);

  expectInterpMatchesMultipass(
      "codecopy_preexpand", *BytecodeBuf, {}, EVMC_SUCCESS,
      zen::utils::toHex(ExpectedOutput.data(), ExpectedOutput.size()));
}

TEST(EVMMultipassCopyHelperTest,
     CodeCopyNonZeroSizeWithOversizedDestReturnsOutOfGas) {
  auto BytecodeBuf = zen::utils::fromHex(
      "60016000"
      "7f0100000000000000000000000000000000000000000000000000000000000000"
      "3900");
  ASSERT_TRUE(BytecodeBuf) << "Failed to parse oversized code-copy bytecode";

  expectInterpMatchesMultipass("codecopy_nonzero_size_oversized_dest",
                               *BytecodeBuf, {}, EVMC_OUT_OF_GAS);
}

TEST(EVMMultipassKeccakHelperTest,
     CallerConstSlotHelperMatchesInterpreterAndExpectedDigest) {
  auto BytecodeBuf =
      zen::utils::fromHex("336000526005602052604060002060005260206000f3");
  ASSERT_TRUE(BytecodeBuf) << "Failed to parse caller-slot helper bytecode";

  const std::string ExpectedDigest = computeTwoWordKeccakHex(
      makePaddedAddressWord(DEFAULT_DEPLOYER_ADDRESS), makeUint256Calldata(5));

  expectInterpMatchesMultipass("keccak_caller_const_slot", *BytecodeBuf, {},
                               EVMC_SUCCESS, ExpectedDigest);
}

TEST(EVMMultipassKeccakHelperTest,
     CallDataConstSlotHelperMatchesInterpreterAndExpectedDigest) {
  auto BytecodeBuf =
      zen::utils::fromHex("6000356000526007602052604060002060005260206000f3");
  ASSERT_TRUE(BytecodeBuf) << "Failed to parse calldata-slot helper bytecode";

  const std::vector<uint8_t> CallData = makeUint256Calldata(0x1234);
  const std::string ExpectedDigest =
      computeTwoWordKeccakHex(CallData, makeUint256Calldata(7));

  expectInterpMatchesMultipass("keccak_calldata_const_slot", *BytecodeBuf,
                               CallData, EVMC_SUCCESS, ExpectedDigest);
}

TEST(EVMMultipassKeccakHelperTest,
     CallDataConstSlotHelperMatchesInterpreterWithNonZeroStagingBase) {
  auto BytecodeBuf =
      zen::utils::fromHex("6000356040526007606052604060402060005260206000f3");
  ASSERT_TRUE(BytecodeBuf)
      << "Failed to parse calldata-slot nonzero-base bytecode";

  const std::vector<uint8_t> CallData = makeUint256Calldata(0x1234);
  const std::string ExpectedDigest =
      computeTwoWordKeccakHex(CallData, makeUint256Calldata(7));

  expectInterpMatchesMultipass("keccak_calldata_const_slot_nonzero_base",
                               *BytecodeBuf, CallData, EVMC_SUCCESS,
                               ExpectedDigest);
}

TEST(EVMMultipassKeccakHelperTest,
     CallerConstSlotHelperPreservesMemoryExpansionFailureSemantics) {
  auto BytecodeBuf = zen::utils::fromHex(
      "3362ffffe0526005630100000052604062ffffe02060005260206000f3");
  ASSERT_TRUE(BytecodeBuf)
      << "Failed to parse caller-slot memory edge bytecode";

  expectInterpMatchesMultipass("keccak_caller_const_slot_mem_oog", *BytecodeBuf,
                               {}, EVMC_OUT_OF_GAS);
}

TEST(EVMMultipassKeccakHelperTest,
     CallDataConstSlotHelperPreservesMemoryExpansionFailureSemantics) {
  auto BytecodeBuf = zen::utils::fromHex(
      "60003562ffffe0526005630100000052604062ffffe02060005260206000f3");
  ASSERT_TRUE(BytecodeBuf)
      << "Failed to parse calldata-slot memory edge bytecode";

  expectInterpMatchesMultipass("keccak_calldata_const_slot_mem_oog",
                               *BytecodeBuf, makeUint256Calldata(0x1234),
                               EVMC_OUT_OF_GAS);
}

TEST(EVMMultipassKeccakHelperTest,
     GenericKeccakPreExpandMatchesInterpreterAndExpectedDigest) {
  std::vector<uint8_t> Word(32);
  for (size_t I = 0; I < Word.size(); ++I) {
    Word[I] = static_cast<uint8_t>(I);
  }

  std::vector<uint8_t> Bytecode = {0x7f};
  Bytecode.insert(Bytecode.end(), Word.begin(), Word.end());
  const std::vector<uint8_t> Suffix = {
      0x60, 0x00, 0x52,       // MSTORE word at memory offset 0.
      0x60, 0x30, 0x60, 0x00, // KECCAK256 memory[0:48].
      0x20, 0x60, 0x00, 0x52, // Store digest at memory offset 0.
      0x60, 0x20, 0x60, 0x00, 0xf3};
  Bytecode.insert(Bytecode.end(), Suffix.begin(), Suffix.end());

  std::vector<uint8_t> KeccakInput = Word;
  KeccakInput.insert(KeccakInput.end(), 16, 0);
  const std::string ExpectedDigest = computeKeccakHex(KeccakInput);

  expectInterpMatchesMultipass("keccak_generic_preexpand_48", Bytecode, {},
                               EVMC_SUCCESS, ExpectedDigest);
}

TEST(EVMMultipassKeccakHelperTest,
     GenericKeccakZeroLengthAllowsOversizedOffset) {
  std::vector<uint8_t> Bytecode = {0x60, 0x00, 0x7f, 0x01};
  Bytecode.insert(Bytecode.end(), 31, 0x00);
  const std::vector<uint8_t> Suffix = {0x20, 0x60, 0x00, 0x52,
                                       0x60, 0x20, 0x60, 0x00};
  Bytecode.insert(Bytecode.end(), Suffix.begin(), Suffix.end());
  Bytecode.push_back(0xf3);

  const std::vector<uint8_t> EmptyInput;
  const std::string ExpectedDigest = computeKeccakHex(EmptyInput);

  expectInterpMatchesMultipass("keccak_zero_size_oversized_offset", Bytecode,
                               {}, EVMC_SUCCESS, ExpectedDigest);
}

TEST(EVMMultipassKeccakHelperTest,
     GenericKeccakNonZeroLengthRejectsOversizedOffset) {
  std::vector<uint8_t> Bytecode = {0x60, 0x01, 0x7f, 0x01};
  Bytecode.insert(Bytecode.end(), 31, 0x00);
  Bytecode.push_back(0x20);
  Bytecode.push_back(0x00);

  expectInterpMatchesMultipass("keccak_nonzero_oversized_offset", Bytecode, {},
                               EVMC_OUT_OF_GAS);
}

TEST(EVMMultipassJumpRegressionTest, InvalidJumpDestStillMatchesInterpreter) {
  const std::vector<uint8_t> Bytecode = {0x60, 0x04, 0x56, 0x00, 0x00};

  expectInterpMatchesMultipass("invalid_jumpdest_regression", Bytecode, {},
                               EVMC_BAD_JUMP_DESTINATION);
}

TEST(EVMMultipassJumpRegressionTest,
     HighLimbNonZeroJumpTargetStillRejectsOtherwiseValidLowDest) {
  std::vector<uint8_t> Bytecode = {0x7f, 0x01};
  Bytecode.insert(Bytecode.end(), 30, 0x00);
  Bytecode.push_back(0x22);
  Bytecode.push_back(0x56);
  Bytecode.push_back(0x5b);
  Bytecode.push_back(0x00);

  expectInterpMatchesMultipass("high_limb_jump_target_regression", Bytecode, {},
                               EVMC_BAD_JUMP_DESTINATION);
}

// Regression test for issue #487: multipass JIT corrupted high limbs of U256
// values written via SSTORE. Shared zero-constant MInstructions caused the
// register allocator to spill them across long live ranges; stale stack slots
// produced garbage in limbs 1-3.
TEST(EVMMultipassSstoreTest, Issue487_U256HighLimbsNotCorrupted) {
  const std::string BytecodeHex =
      "60005047585c816e0000000000000000000000000000125c6d000000000000000000"
      "000000a3485179000000000000000000000000000000000000000000a68804c0cf0a"
      "680000000000000000ef31841a097000000000000000000000000000000000c7911a"
      "1c08760000000000000000000000000000000000000000000014355f0860e3337600"
      "0000000000000000000000000000000000000000626e541c05053d6c000000000000"
      "000000000000c4720000000000000000000000000000000000006e3d770000000000"
      "000000000000000000000000000000000000a06300006f913d145d1a900330"
      "7a0000000000000000000000000000000000000000000000005f6f5c3f7c00000000"
      "000000000000000000000000000000000000000000000000b9620000ab5808634200"
      "0000556342000001556342000002556342000003556c00000000000000000000004115"
      "553d385f5f5f0a3979000000000000000000000000000000000000000000000000f6"
      "925e6168e65842453650387900000000000000000000000000000000000000000000"
      "000000db6e0000000000000000000000000000aa1005493649845e47906342000000"
      "556342000001556342000002557e00000000000000000000000000000000000000000"
      "00000000000000000018b5c79000000000000000000000000000000000000000000000"
      "00000d307634200000055634200000155634200000255";

  const std::string CalldataHex =
      "0dba1bece48614fcdabf80dc0a3d1d180b641b5a9fe0a3092ad29c772b066210"
      "e553242e7e1ad9bf1bde48e1cce998dfe1aeebf268ec679f3ca10ade95016a8d"
      "527bdf705a729d7616799a1f5806";

  auto BytecodeBuf = zen::utils::fromHex(BytecodeHex);
  ASSERT_TRUE(BytecodeBuf) << "Failed to parse bytecode hex";
  auto CalldataBuf = zen::utils::fromHex(CalldataHex);
  ASSERT_TRUE(CalldataBuf) << "Failed to parse calldata hex";

  RuntimeConfig Config;
  Config.Mode = common::RunMode::MultipassMode;
  Config.EnableEvmGasMetering = true;

  const evmc::address ContractAddr = evmc::literals::operator""_address(
      "00000000000000000000000000000000000000f1");
  const evmc::address SenderAddr = evmc::literals::operator""_address(
      "a94f5374fce5edbc8e2a8697c15331677e6ebf0b");

  auto HostPtr = std::make_unique<zen::evm::ZenMockedEVMHost>();

  evmc::MockedAccount ContractAccount;
  ContractAccount.code = {0x60, 0x00, 0x50};

  evmc::MockedAccount SenderAccount;
  SenderAccount.set_balance(0xFFFFFFFFFF);

  HostPtr->accounts[ContractAddr] = ContractAccount;
  HostPtr->accounts[SenderAddr] = SenderAccount;

  evmc_tx_context TxCtx{};
  TxCtx.tx_origin = SenderAddr;
  HostPtr->tx_context = TxCtx;

  auto RT = Runtime::newEVMRuntime(Config, HostPtr.get());
  ASSERT_TRUE(RT != nullptr) << "Failed to create runtime";
  HostPtr->setRuntime(RT.get());

  const std::string ModuleName = "issue487_reproducer";
  auto ModRet =
      RT->loadEVMModule(ModuleName, BytecodeBuf->data(), BytecodeBuf->size());
  ASSERT_TRUE(ModRet) << "Failed to load module";
  EVMModule *Mod = *ModRet;

  Isolation *Iso = RT->createManagedIsolation();
  ASSERT_TRUE(Iso != nullptr) << "Failed to create isolation";

  constexpr uint64_t GasLimit = 8000000;
  const uint64_t IntrinsicGas = zen::evm::BASIC_EXECUTION_COST;
  const uint64_t ExecutionGasLimit = GasLimit - IntrinsicGas;

  auto InstRet = Iso->createEVMInstance(*Mod, ExecutionGasLimit);
  ASSERT_TRUE(InstRet) << "Failed to create instance";
  EVMInstance *Inst = *InstRet;
  Inst->setRevision(EVMC_CANCUN);

  evmc_message Msg = {
      .kind = EVMC_CALL,
      .flags = 0u,
      .depth = 0,
      .gas = static_cast<int64_t>(ExecutionGasLimit),
      .recipient = ContractAddr,
      .sender = SenderAddr,
      .input_data = CalldataBuf->data(),
      .input_size = CalldataBuf->size(),
      .value = {},
      .create2_salt = {},
      .code_address = ContractAddr,
      .code = reinterpret_cast<const uint8_t *>(Mod->Code),
      .code_size = Mod->CodeSize,
  };

  evmc::Result RawResult;
  EXPECT_NO_THROW({ RT->callEVMMain(*Inst, Msg, RawResult); });
  ASSERT_EQ(RawResult.status_code, EVMC_SUCCESS)
      << "EVM execution failed with status code "
      << static_cast<int>(RawResult.status_code);

  // Verify SSTORE wrote correct U256 values with clean high limbs.
  auto makeKey = [](uint64_t low) {
    evmc::bytes32 Key{};
    for (int I = 0; I < 8; ++I) {
      Key.bytes[31 - I] = static_cast<uint8_t>(low & 0xFF);
      low >>= 8;
    }
    return Key;
  };

  auto checkStorageValue = [&](uint64_t KeyLow, uint64_t ExpectedLow,
                               const std::string &Label) {
    const evmc::bytes32 Key = makeKey(KeyLow);
    const auto &Storage = HostPtr->accounts[ContractAddr].storage;
    auto It = Storage.find(Key);
    ASSERT_NE(It, Storage.end()) << Label << ": key not found in storage";
    const evmc::bytes32 &Value = It->second.current;
    // All high bytes (0..23) must be zero - no garbage in upper limbs.
    for (int I = 0; I < 24; ++I) {
      EXPECT_EQ(Value.bytes[I], 0)
          << Label << ": non-zero byte at position " << I;
    }
    uint64_t ActualLow = 0;
    for (int I = 24; I < 32; ++I) {
      ActualLow = (ActualLow << 8) | Value.bytes[I];
    }
    EXPECT_EQ(ActualLow, ExpectedLow) << Label << ": low value mismatch";
  };

  checkStorageValue(0x42000001, 0x179, "slot_0x42000001");
  checkStorageValue(0x42000002, 0x68E6, "slot_0x42000002");
  checkStorageValue(0x42000003, 0xC4, "slot_0x42000003");
}

// Regression test for issue #488.
//
// Before the fix, EVMMirBuilder::handlePC produced a raw `const i64`
// MInstruction whose result virtual register was reused across basic blocks
// through the x86 lowering's expression cache (_expr_reg_map). When PC was
// later consumed by the slow path of ADDMOD (which spills the U256 augend
// through setInstanceElement in a different basic block), the cached vreg had
// been clobbered in between, so the runtime helper evmGetAddMod read a stale
// heap pointer instead of the PC value. The result was a divergence between
// the interpreter (correct) and the multipass JIT (incorrect, often throwing
// Unreachable).
//
// The fix spills the PC constant through a temporary variable in handlePC so
// each consumer re-reads it via dread.
TEST(EVMRegressionTest, Issue488_PCAsAddmodAugend_InterpMatchesMultipass) {
  const auto FilePath =
      (getEvmAsmDirPath() / "addmod_pc_augend.evm.hex").string();

  auto InterpExec =
      executeEvmBytecodeFile(FilePath, common::RunMode::InterpMode);
  auto MultipassExec =
      executeEvmBytecodeFile(FilePath, common::RunMode::MultipassMode);

#ifdef ZEN_ENABLE_JIT
  EXPECT_TRUE(MultipassExec.JITCompiled)
      << "Multipass JIT should compile addmod_pc_augend";
#endif

  EXPECT_EQ(InterpExec.Status, EVMC_SUCCESS);
  EXPECT_EQ(MultipassExec.Status, InterpExec.Status)
      << "Multipass status diverged from interpreter for issue #488 "
         "regression";
  EXPECT_EQ(MultipassExec.OutputHex, InterpExec.OutputHex)
      << "Multipass output diverged from interpreter for issue #488 "
         "regression";

  // (PC=4) + 0x10 = 20, 20 % 7 = 6, returned as a 32-byte big-endian word.
  EXPECT_EQ(InterpExec.OutputHex,
            "0000000000000000000000000000000000000000000000000000000000000006");
}

// Regression test for issue #541 (and #542): multipass JIT carry chain
// corruption when the last ADC in handleAddU64Const is not
// protectUnsafeValue'd.
//
// When ADD produces a U256 result via the handleAddU64Const fast path
// (ADD limb[0] + 3×ADC for carry propagation), the last ADC (limb[3]) was
// intentionally left as an un-materialized tree-IR expression because the
// carry flag is "dead" within the carry chain after that instruction.
// However, if the ADD result is later consumed by a CMP instruction (e.g.
// from GT/LT comparison), the CMP lowers before the last ADC, clobbering
// x86 EFLAGS (including CF). The ADC then reads the wrong CF from CMP
// instead of the correct CF from the preceding ADC, corrupting the carry
// chain.
//
// The test uses a minimal EVM program that triggers the bug:
//   PUSH24 big_val  -- a 192-bit value with non-zero limbs
//   PUSH1 0xff      -- a small value (U64 range)
//   RETURNDATASIZE  -- pushes 0 (U64 range)
//   ADD             -- ADD(0, 0xff) via handleAddU64Const
//   GT              -- GT(0xff, big_val) should return 0
//   PUSH0           -- offset for MSTORE
//   MSTORE          -- store GT result to memory
//   PUSH1 32        -- size for RETURN
//   PUSH0           -- offset for RETURN
//   RETURN
//
// Before the fix: CMP from GT clobbered CF before the last ADC was lowered,
// ADC computed wrong limb[3], GT incorrectly returned 1 instead of 0.
// For issue #542: the same root cause also caused a crash.
TEST(EVMRegressionTest, Issue541_AddU64ConstLastAdcCarryChainPreserved) {
  // Bytecode: PUSH24 big_val, PUSH1 0xff, RETURNDATASIZE, ADD, GT,
  //           PUSH0, MSTORE, PUSH1 32, PUSH0, RETURN
  //
  // big_val = 0x0000_0000_0000_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF
  // (3 non-zero limbs to force CMP in GT to set CF=1)
  const std::string BytecodeHex =
      "77000000000000ffffffffffffffffffffffffffffffffffff"
      "60ff3d01115f5260205ff3";

  auto BytecodeBuf = zen::utils::fromHex(BytecodeHex);
  ASSERT_TRUE(BytecodeBuf) << "Failed to parse bytecode hex";

  // Run interpreter (reference) and multipass JIT, compare outputs.
  auto InterpExec = executeEvmBytecode("issue541_interp", *BytecodeBuf,
                                       common::RunMode::InterpMode);
  ASSERT_EQ(InterpExec.Status, EVMC_SUCCESS) << "Interpreter execution failed";

  auto MultipassExec = executeEvmBytecode("issue541_multipass", *BytecodeBuf,
                                          common::RunMode::MultipassMode);
  ASSERT_EQ(MultipassExec.Status, EVMC_SUCCESS)
      << "Multipass JIT execution failed (crash = issue #542)";

#ifdef ZEN_ENABLE_JIT
  EXPECT_TRUE(MultipassExec.JITCompiled)
      << "Multipass JIT should compile issue541 reproducer";
#endif

  // GT(0xff, big_val) should return 0. Before the fix, multipass returned 1.
  EXPECT_EQ(MultipassExec.OutputHex, InterpExec.OutputHex)
      << "Multipass output diverged from interpreter for issue #541 "
         "regression";

  // Explicitly verify: GT(0xff, big_val) = 0 (0xff is NOT greater than
  // a 192-bit value).
  EXPECT_EQ(InterpExec.OutputHex,
            "0000000000000000000000000000000000000000000000000000000000000000");
}
#endif

// Test that chain_id and blob_base_fee can be saved and loaded via state
TEST(EVMStateSaveLoad, ChainIdAndBlobBaseFee) {
  auto Host = std::make_unique<zen::evm::ZenMockedEVMHost>();

  // Set chain_id and blob_base_fee to non-zero values
  const std::string ChainIdHex =
      "0000000000000000000000000000000000000000000000000000000000000007";
  const std::string BlobBaseFeeHex =
      "0000000000000000000000000000000000000000000000000000000000000001";

  Host->tx_context.chain_id = zen::utils::parseUint256(ChainIdHex);
  Host->tx_context.blob_base_fee = zen::utils::parseUint256(BlobBaseFeeHex);

  // Set other tx_context fields to make the state complete
  Host->tx_context.tx_gas_price = zen::utils::parseUint256(
      "0000000000000000000000000000000000000000000000000000000000000000");
  Host->tx_context.block_number = 1;
  Host->tx_context.block_timestamp = 1;
  Host->tx_context.block_gas_limit = 10000000;
  Host->tx_context.tx_origin = evmc::address{};
  Host->tx_context.block_coinbase = evmc::address{};
  Host->tx_context.block_prev_randao = zen::utils::parseUint256(
      "0000000000000000000000000000000000000000000000000000000000000000");
  Host->tx_context.block_base_fee = zen::utils::parseUint256(
      "0000000000000000000000000000000000000000000000000000000000000000");

  // Add a simple account
  evmc::address Addr = evmc::literals::operator""_address(
      "a94f5374fce5edbc8e2a8697c15331677e6ebf0b");
  evmc::MockedAccount Account;
  Account.set_balance(100);
  Account.code = {0x60, 0x00, 0x50};
  Host->accounts[Addr] = Account;

  const std::string StateFilePath = "/tmp/dtvm_test_chainid_state.json";

  // Save state
  ASSERT_TRUE(zen::utils::saveState(*Host, StateFilePath));

  // Load state into a new host
  auto NewHost = std::make_unique<zen::evm::ZenMockedEVMHost>();
  ASSERT_TRUE(zen::utils::loadState(*NewHost, StateFilePath));

  // Verify chain_id was loaded correctly
  auto ExpectedChainId = zen::utils::parseUint256(ChainIdHex);
  EXPECT_EQ(std::memcmp(NewHost->tx_context.chain_id.bytes,
                        ExpectedChainId.bytes, 32),
            0)
      << "chain_id not loaded correctly from state file";

  // Verify blob_base_fee was loaded correctly
  auto ExpectedBlobBaseFee = zen::utils::parseUint256(BlobBaseFeeHex);
  EXPECT_EQ(std::memcmp(NewHost->tx_context.blob_base_fee.bytes,
                        ExpectedBlobBaseFee.bytes, 32),
            0)
      << "blob_base_fee not loaded correctly from state file";

  // Cleanup
  std::filesystem::remove(StateFilePath);
}

// Test that loadState handles missing chain_id and blob_base_fee gracefully
// (backward compatibility: old state.json without these fields should still
// work)
TEST(EVMStateSaveLoad, MissingChainIdAndBlobBaseFee) {
  const std::string StateFilePath = "/tmp/dtvm_test_missing_chainid_state.json";

  // Use saveState to produce a valid complete JSON, then remove chain_id
  // and blob_base_fee lines to simulate an old-format state file.
  {
    auto SaveHost = std::make_unique<zen::evm::ZenMockedEVMHost>();
    SaveHost->tx_context.tx_gas_price = evmc::uint256be{};
    SaveHost->tx_context.block_number = 1;
    SaveHost->tx_context.block_timestamp = 1;
    SaveHost->tx_context.block_gas_limit = 10000000;
    SaveHost->tx_context.tx_origin = evmc::address{};
    SaveHost->tx_context.block_coinbase = evmc::address{};
    SaveHost->tx_context.block_prev_randao = evmc::uint256be{};
    SaveHost->tx_context.block_base_fee = evmc::uint256be{};
    ASSERT_TRUE(zen::utils::saveState(*SaveHost, StateFilePath));

    // Read file, remove chain_id and blob_base_fee lines, rewrite
    std::ifstream InFile(StateFilePath);
    std::string Line;
    std::string Result;
    while (std::getline(InFile, Line)) {
      if (Line.find("\"chain_id\"") != std::string::npos ||
          Line.find("\"blob_base_fee\"") != std::string::npos) {
        continue;
      }
      // Remove trailing comma from tx_origin line (now last field)
      if (Line.find("\"tx_origin\"") != std::string::npos) {
        auto CommaPos = Line.rfind(",");
        if (CommaPos != std::string::npos) {
          Line.erase(CommaPos, 1);
        }
      }
      Result += Line + "\n";
    }
    InFile.close();

    std::ofstream OutFile(StateFilePath);
    OutFile << Result;
  }

  // Load state into a new host
  auto Host = std::make_unique<zen::evm::ZenMockedEVMHost>();
  ASSERT_TRUE(zen::utils::loadState(*Host, StateFilePath));

  // Verify chain_id and blob_base_fee remain default (zero)
  evmc::uint256be ZeroValue{};
  EXPECT_EQ(std::memcmp(Host->tx_context.chain_id.bytes, ZeroValue.bytes, 32),
            0)
      << "Missing chain_id should default to zero";
  EXPECT_EQ(
      std::memcmp(Host->tx_context.blob_base_fee.bytes, ZeroValue.bytes, 32), 0)
      << "Missing blob_base_fee should default to zero";

  // Cleanup
  std::filesystem::remove(StateFilePath);
}

// ---------------------------------------------------------------------------
// Regression tests: loadState() must preserve the caller's existing
// tx_context when the state file has no tx_context member (or omits fields),
// only overlaying the fields that are actually present in the JSON. The CLI
// sets tx_origin from --sender before loadState() and relies on the state file
// to override it only when tx_origin is present; minimal/old state files must
// not silently zero the transaction context.
// ---------------------------------------------------------------------------
TEST(EVMStateSaveLoad, MissingTxContextPreservesCallerTxContext) {
  const std::string FilePath = "/tmp/dtvm_test_missing_tx_context_state.json";

  // Minimal old-format state file: accounts only, no tx_context member.
  const std::string StateJson = R"({
  "accounts": {
    "a94f5374fce5edbc8e2a8697c15331677e6ebf0b": {
      "balance": "0000000000000000000000000000000000000000000000000000000000000001",
      "nonce": 0, "code": "", "codehash": "0000000000000000000000000000000000000000000000000000000000000000", "storage": {}
    }
  }
})";
  {
    std::ofstream OutFile(FilePath);
    OutFile << StateJson;
  }

  // Pre-set the transaction context the same way the CLI does with --sender.
  auto Host = std::make_unique<zen::evm::ZenMockedEVMHost>();
  const evmc::address Sender = evmc::literals::operator""_address(
      "a94f5374fce5edbc8e2a8697c15331677e6ebf0b");
  const evmc::address Coinbase = evmc::literals::operator""_address(
      "b94f5374fce5edbc8e2a8697c15331677e6ebf0b");
  const evmc::uint256be GasPrice = zen::utils::parseUint256(
      "0000000000000000000000000000000000000000000000000000000000000010");
  const evmc::uint256be PrevRandao = zen::utils::parseUint256(
      "0000000000000000000000000000000000000000000000000000000000200000");
  const evmc::uint256be BaseFee = zen::utils::parseUint256(
      "0000000000000000000000000000000000000000000000000000000000000007");
  const evmc::uint256be ChainId = zen::utils::parseUint256(
      "0000000000000000000000000000000000000000000000000000000000000005");
  const evmc::uint256be BlobBaseFee = zen::utils::parseUint256(
      "0000000000000000000000000000000000000000000000000000000000000003");

  Host->tx_context.tx_origin = Sender;
  Host->tx_context.tx_gas_price = GasPrice;
  Host->tx_context.block_number = 42;
  Host->tx_context.block_timestamp = 1700000000;
  Host->tx_context.block_gas_limit = 30000000;
  Host->tx_context.block_coinbase = Coinbase;
  Host->tx_context.block_prev_randao = PrevRandao;
  Host->tx_context.block_base_fee = BaseFee;
  Host->tx_context.chain_id = ChainId;
  Host->tx_context.blob_base_fee = BlobBaseFee;

  ASSERT_TRUE(zen::utils::loadState(*Host, FilePath))
      << "A state file without tx_context must still load";

  // The caller's whole transaction context must survive untouched.
  EXPECT_EQ(std::memcmp(Host->tx_context.tx_origin.bytes, Sender.bytes, 20), 0)
      << "tx_origin from the caller must be preserved when the state file has "
         "no tx_context";
  EXPECT_EQ(
      std::memcmp(Host->tx_context.tx_gas_price.bytes, GasPrice.bytes, 32), 0)
      << "gas_price from the caller must be preserved";
  EXPECT_EQ(Host->tx_context.block_number, 42);
  EXPECT_EQ(Host->tx_context.block_timestamp, 1700000000);
  EXPECT_EQ(Host->tx_context.block_gas_limit, 30000000);
  EXPECT_EQ(
      std::memcmp(Host->tx_context.block_coinbase.bytes, Coinbase.bytes, 20),
      0);
  EXPECT_EQ(std::memcmp(Host->tx_context.block_prev_randao.bytes,
                        PrevRandao.bytes, 32),
            0);
  EXPECT_EQ(
      std::memcmp(Host->tx_context.block_base_fee.bytes, BaseFee.bytes, 32), 0);
  EXPECT_EQ(std::memcmp(Host->tx_context.chain_id.bytes, ChainId.bytes, 32), 0);
  EXPECT_EQ(
      std::memcmp(Host->tx_context.blob_base_fee.bytes, BlobBaseFee.bytes, 32),
      0);

  // The account from the state file must still be loaded.
  EXPECT_NE(Host->accounts.find(Sender), Host->accounts.end());

  std::filesystem::remove(FilePath);
}

TEST(EVMStateSaveLoad, PartialTxContextOverlaysOnlyPresentFields) {
  const std::string FilePath = "/tmp/dtvm_test_partial_tx_context_state.json";

  // tx_context object with only tx_origin present; every other field absent.
  const std::string StateJson = R"({
  "accounts": {},
  "tx_context": {
    "tx_origin": "b94f5374fce5edbc8e2a8697c15331677e6ebf0b"
  }
})";
  {
    std::ofstream OutFile(FilePath);
    OutFile << StateJson;
  }

  auto Host = std::make_unique<zen::evm::ZenMockedEVMHost>();
  const evmc::address CallerOrigin = evmc::literals::operator""_address(
      "a94f5374fce5edbc8e2a8697c15331677e6ebf0b");
  const evmc::address StateOrigin = evmc::literals::operator""_address(
      "b94f5374fce5edbc8e2a8697c15331677e6ebf0b");
  const evmc::uint256be GasPrice = zen::utils::parseUint256(
      "0000000000000000000000000000000000000000000000000000000000000010");

  Host->tx_context.tx_origin = CallerOrigin;
  Host->tx_context.tx_gas_price = GasPrice;
  Host->tx_context.block_number = 42;
  Host->tx_context.block_timestamp = 1700000000;
  Host->tx_context.block_gas_limit = 30000000;

  ASSERT_TRUE(zen::utils::loadState(*Host, FilePath));

  // tx_origin is present in the state file and must override the caller.
  EXPECT_EQ(
      std::memcmp(Host->tx_context.tx_origin.bytes, StateOrigin.bytes, 20), 0)
      << "tx_origin present in the state file must override the caller value";
  // Every absent field keeps the caller's value.
  EXPECT_EQ(
      std::memcmp(Host->tx_context.tx_gas_price.bytes, GasPrice.bytes, 32), 0)
      << "Absent tx_context fields must keep the caller's value";
  EXPECT_EQ(Host->tx_context.block_number, 42);
  EXPECT_EQ(Host->tx_context.block_timestamp, 1700000000);
  EXPECT_EQ(Host->tx_context.block_gas_limit, 30000000);

  std::filesystem::remove(FilePath);
}

// Regression test for https://github.com/DTVMStack/DTVM/issues/589.
// A storage value loaded from prestate is both current and original for the
// new transaction. If original remains zero, a non-zero prestate slot written
// to zero is misclassified as a dirty clear instead of a reset.
TEST(EVMStateSaveLoad, LoadedStorageInitializesOriginalForNewTransaction) {
  const std::string StateFilePath = "/tmp/dtvm_issue589_state.json";
  const std::string ContractAddr = "00000000000000000000000000000000000000f1";
  const std::string SenderAddr = "a94f5374fce5edbc8e2a8697c15331677e6ebf0b";
  const std::vector<uint8_t> Bytecode = {0x60, 0x00, 0x60, 0x00, 0x55, 0x00};

  {
    std::ofstream StateFile(StateFilePath);
    ASSERT_TRUE(StateFile) << "Failed to create issue #589 state file";
    StateFile << R"({
      "accounts": {
        ")" << ContractAddr
              << R"(": {
          "balance": "0000000000000000000000000000000000000000000000000000000000000000",
          "code": "0x600060005500",
          "nonce": 0,
          "storage": {
            "0000000000000000000000000000000000000000000000000000000000000000": {
              "value": "0000000000000000000000000000000000000000000000000000000000000005"
            }
          }
        },
        ")" << SenderAddr
              << R"(": {
          "balance": "0000000000000000000000000000000000000000000000000de0b6b3a7640000",
          "code": "0x",
          "nonce": 0,
          "storage": {}
        }
      },
      "tx_context": {
        "gas_price": "0000000000000000000000000000000000000000000000000000000000000010",
        "block_number": 1,
        "block_timestamp": 1000,
        "block_coinbase": "b94f5374fce5edbc8e2a8697c15331677e6ebf0b",
        "block_prev_randao": "0000000000000000000000000000000000000000000000000000000000000020",
        "block_gas_limit": 10000000,
        "block_base_fee": "0000000000000000000000000000000000000000000000000000000000000010",
        "tx_origin": ")"
              << SenderAddr << R"("
      }
    })";
  }

  auto HostPtr = std::make_unique<zen::evm::ZenMockedEVMHost>();
  ASSERT_TRUE(zen::utils::loadState(*HostPtr, StateFilePath));

  const evmc::address ContractAddress = zen::utils::parseAddress(ContractAddr);
  const evmc::address SenderAddress = zen::utils::parseAddress(SenderAddr);
  const evmc::bytes32 StorageKey{};
  const auto &Slot = HostPtr->accounts[ContractAddress].storage.at(StorageKey);
  const auto PrestateValue = zen::utils::parseBytes32(
      "0000000000000000000000000000000000000000000000000000000000000005");
  EXPECT_EQ(std::memcmp(Slot.current.bytes, PrestateValue.bytes, 32), 0)
      << "Prestate current storage value was not loaded";
  EXPECT_EQ(std::memcmp(Slot.original.bytes, PrestateValue.bytes, 32), 0)
      << "Prestate current value must initialize original for a new tx";

  RuntimeConfig Config;
  Config.Mode = common::RunMode::InterpMode;
  auto RT = Runtime::newEVMRuntime(Config, HostPtr.get());
  ASSERT_TRUE(RT);
  HostPtr->setRuntime(RT.get());

  zen::evm::ZenMockedEVMHost::TransactionExecutionConfig ExecConfig;
  ExecConfig.ModuleName = "issue589";
  ExecConfig.Bytecode = Bytecode.data();
  ExecConfig.BytecodeSize = Bytecode.size();
  ExecConfig.Revision = EVMC_CANCUN;
  ExecConfig.GasLimit = 100000;
  ExecConfig.IntrinsicGas = 21000;
  evmc_message Msg{};
  Msg.kind = EVMC_CALL;
  Msg.gas = 100000;
  Msg.sender = SenderAddress;
  Msg.recipient = ContractAddress;
  Msg.code_address = ContractAddress;
  ExecConfig.Message = Msg;

  auto Result = HostPtr->executeTransaction(ExecConfig);
  ASSERT_TRUE(Result.Success) << Result.ErrorMessage;
  EXPECT_EQ(Result.Status, EVMC_SUCCESS);
  // Execution gas: 2 PUSH1 + cold SLOAD + reset SSTORE = 5006.
  // Intrinsic gas: 21000. Raw refund: 4800; cap floor(26006 / 5) = 5201.
  EXPECT_EQ(Result.GasUsed, 26006u)
      << "SSTORE(5 -> 0) must charge cold access + reset gas";
  EXPECT_EQ(Result.GasRefund, 4800u)
      << "Clearing a non-zero prestate slot refunds R_clear";
  EXPECT_EQ(Result.GasCharged, 21206u)
      << "Host-path net SSTORE gas is reset cost after refund";

  std::filesystem::remove(StateFilePath);
}

// Regression test for https://github.com/DTVMStack/DTVM/issues/590.
// Warm/cold access is transaction execution state, not world state. A legacy
// prestate's access_status must not cold-skip the next transaction's first
// access, and freshly saved states must not carry the field.
TEST(EVMStateSaveLoad, AccessStatusIsNotPrestateState) {
  const std::string StateFilePath = "/tmp/dtvm_issue590_state.json";
  const std::string SavedStateFilePath = "/tmp/dtvm_issue590_saved_state.json";
  const std::string ContractAddr = "00000000000000000000000000000000000000f1";
  const std::string SenderAddr = "a94f5374fce5edbc8e2a8697c15331677e6ebf0b";
  const std::vector<uint8_t> Bytecode = {0x60, 0x03, 0x60, 0x00, 0x55, 0x00};

  {
    std::ofstream StateFile(StateFilePath);
    ASSERT_TRUE(StateFile) << "Failed to create issue #590 state file";
    StateFile << R"({
      "accounts": {
        ")" << ContractAddr
              << R"(": {
          "balance": "0000000000000000000000000000000000000000000000000000000000000000",
          "code": "0x600360005500",
          "nonce": 0,
          "storage": {
            "0000000000000000000000000000000000000000000000000000000000000000": {
              "value": "0000000000000000000000000000000000000000000000000000000000000000",
              "access_status": 1
            }
          }
        },
        ")" << SenderAddr
              << R"(": {
          "balance": "0000000000000000000000000000000000000000000000000de0b6b3a7640000",
          "code": "0x",
          "nonce": 0,
          "storage": {}
        }
      },
      "tx_context": {
        "gas_price": "0000000000000000000000000000000000000000000000000000000000000010",
        "block_number": 1,
        "block_timestamp": 1000,
        "block_coinbase": "b94f5374fce5edbc8e2a8697c15331677e6ebf0b",
        "block_prev_randao": "0000000000000000000000000000000000000000000000000000000000000020",
        "block_gas_limit": 10000000,
        "block_base_fee": "0000000000000000000000000000000000000000000000000000000000000010",
        "tx_origin": ")"
              << SenderAddr << R"("
      }
    })";
  }

  auto HostPtr = std::make_unique<zen::evm::ZenMockedEVMHost>();
  ASSERT_TRUE(zen::utils::loadState(*HostPtr, StateFilePath));

  const evmc::address ContractAddress = zen::utils::parseAddress(ContractAddr);
  const evmc::address SenderAddress = zen::utils::parseAddress(SenderAddr);
  const evmc::bytes32 StorageKey{};
  const auto &Slot = HostPtr->accounts[ContractAddress].storage.at(StorageKey);
  EXPECT_EQ(Slot.access_status, EVMC_ACCESS_COLD)
      << "Prestate access_status must not warm storage for a new transaction";

  RuntimeConfig Config;
  Config.Mode = common::RunMode::InterpMode;
  auto RT = Runtime::newEVMRuntime(Config, HostPtr.get());
  ASSERT_TRUE(RT);
  HostPtr->setRuntime(RT.get());

  zen::evm::ZenMockedEVMHost::TransactionExecutionConfig ExecConfig;
  ExecConfig.ModuleName = "issue590";
  ExecConfig.Bytecode = Bytecode.data();
  ExecConfig.BytecodeSize = Bytecode.size();
  ExecConfig.Revision = EVMC_CANCUN;
  ExecConfig.GasLimit = 100000;
  evmc_message Msg{};
  Msg.kind = EVMC_CALL;
  Msg.gas = 100000;
  Msg.sender = SenderAddress;
  Msg.recipient = ContractAddress;
  Msg.code_address = ContractAddress;
  ExecConfig.Message = Msg;

  auto Result = HostPtr->executeTransaction(ExecConfig);
  ASSERT_TRUE(Result.Success) << Result.ErrorMessage;
  EXPECT_EQ(Result.Status, EVMC_SUCCESS);
  EXPECT_EQ(Result.GasUsed, 22106u)
      << "The first SSTORE must pay cold access plus set cost";

  ASSERT_TRUE(zen::utils::saveState(*HostPtr, SavedStateFilePath));
  std::ifstream SavedStateFile(SavedStateFilePath);
  std::string SavedState((std::istreambuf_iterator<char>(SavedStateFile)),
                         std::istreambuf_iterator<char>());
  ASSERT_TRUE(SavedStateFile) << "Failed to read saved state";
  EXPECT_EQ(SavedState.find("access_status"), std::string::npos)
      << "Saved state must not contain transaction access status";
  auto SavedHost = std::make_unique<zen::evm::ZenMockedEVMHost>();
  EXPECT_TRUE(zen::utils::loadState(*SavedHost, SavedStateFilePath))
      << "Saved state must remain valid JSON";

  std::filesystem::remove(StateFilePath);
  std::filesystem::remove(SavedStateFilePath);
}

namespace {

// Helper that builds and returns the final sender balance for a transaction
// against a contract with the given Bytecode. The caller is expected to set
// initial balances, storage, and tx_context before calling this.
struct SettlementResult {
  intx::uint256 InitialSenderBalance;
  intx::uint256 FinalSenderBalance;
  uint64_t GasUsed = 0;
  uint64_t GasRefund = 0;
  uint64_t GasCharged = 0;
  bool Success = false;
};

const evmc::address SettlementContractAddr = evmc::literals::operator""_address(
    "00000000000000000000000000000000000000f1");
const evmc::address SettlementSenderAddr = evmc::literals::operator""_address(
    "a94f5374fce5edbc8e2a8697c15331677e6ebf0b");
constexpr uint64_t SettlementGasLimit = 8000000;
constexpr uint64_t SettlementSenderBalance = 0xffffffffffff;
constexpr intx::uint256 SettlementGasPrice = intx::uint256(16);

// Creates the common account/tx-context state used by settlement tests.
// SeedStorage is used by the REVERT test to ensure the first SSTORE is a
// paid reset rather than a free set.
void prepareSettlementHost(zen::evm::ZenMockedEVMHost &Host,
                           const std::vector<uint8_t> &Bytecode,
                           const evmc::address &SenderAddr,
                           const evmc::address &ContractAddr,
                           bool SeedStorage = false) {
  evmc::MockedAccount ContractAccount;
  ContractAccount.code = evmc::bytes(Bytecode.data(), Bytecode.size());
  if (SeedStorage) {
    evmc::bytes32 Key{};
    evmc::bytes32 Val{};
    Val.bytes[31] = 1;
    ContractAccount.storage[Key].current = Val;
    ContractAccount.storage[Key].original = Val;
  }
  Host.accounts[ContractAddr] = ContractAccount;

  evmc::MockedAccount SenderAccount;
  SenderAccount.set_balance(SettlementSenderBalance);
  Host.accounts[SenderAddr] = SenderAccount;

  evmc_tx_context TxCtx{};
  TxCtx.tx_origin = SenderAddr;
  TxCtx.tx_gas_price = intx::be::store<evmc::uint256be>(SettlementGasPrice);
  TxCtx.block_base_fee = intx::be::store<evmc::uint256be>(SettlementGasPrice);
  Host.tx_context = TxCtx;
}

template <typename PrepareHostT>
SettlementResult runSettlementTransaction(const evmc::address &ContractAddr,
                                          const evmc::address &SenderAddr,
                                          const std::vector<uint8_t> &Bytecode,
                                          evmc_revision Revision,
                                          uint64_t GasLimit,
                                          PrepareHostT &&PrepareHost) {
  SettlementResult Result;

  RuntimeConfig Config;
  Config.Mode = common::RunMode::InterpMode;

  auto HostPtr = std::make_unique<zen::evm::ZenMockedEVMHost>();
  std::forward<PrepareHostT>(PrepareHost)(*HostPtr);

  auto &SenderAcc = HostPtr->accounts[SenderAddr];
  Result.InitialSenderBalance =
      intx::be::load<intx::uint256>(SenderAcc.balance);

  auto RT = Runtime::newEVMRuntime(Config, HostPtr.get());
  if (!RT) {
    return Result;
  }
  HostPtr->setRuntime(RT.get());

  zen::evm::ZenMockedEVMHost::TransactionExecutionConfig ExecConfig;
  ExecConfig.ModuleName = "settlement";
  ExecConfig.Bytecode = Bytecode.data();
  ExecConfig.BytecodeSize = Bytecode.size();
  ExecConfig.Revision = Revision;
  ExecConfig.GasLimit = GasLimit;

  evmc_message Msg{};
  Msg.kind = EVMC_CALL;
  Msg.gas = static_cast<int64_t>(GasLimit);
  Msg.sender = SenderAddr;
  Msg.recipient = ContractAddr;
  Msg.code_address = ContractAddr;
  ExecConfig.Message = Msg;

  auto ExecResult = HostPtr->executeTransaction(ExecConfig);
  Result.Success = ExecResult.Success;
  Result.GasUsed = ExecResult.GasUsed;
  Result.GasRefund = ExecResult.GasRefund;
  Result.GasCharged = ExecResult.GasCharged;
  Result.FinalSenderBalance =
      intx::be::load<intx::uint256>(HostPtr->accounts[SenderAddr].balance);
  return Result;
}

// Helper that exercises the same settlement code used by the dtvm CLI:
// applyEvmUpfrontGas, callEVMMain, applyEvmPostExecutionSettlement.
template <typename PrepareHostT>
SettlementResult runDtvmCliSettlementTransaction(
    const evmc::address &ContractAddr, const evmc::address &SenderAddr,
    const std::vector<uint8_t> &Bytecode, evmc_revision Revision,
    uint64_t GasLimit, PrepareHostT &&PrepareHost) {
  SettlementResult Result;

  RuntimeConfig Config;
  Config.Mode = common::RunMode::InterpMode;

  auto HostPtr = std::make_unique<zen::evm::ZenMockedEVMHost>();
  std::forward<PrepareHostT>(PrepareHost)(*HostPtr);

  auto &SenderAcc = HostPtr->accounts[SenderAddr];
  Result.InitialSenderBalance =
      intx::be::load<intx::uint256>(SenderAcc.balance);

  auto RT = Runtime::newEVMRuntime(Config, HostPtr.get());
  if (!RT) {
    return Result;
  }
  HostPtr->setRuntime(RT.get());

  auto ModRet =
      RT->loadEVMModule("cli_settlement", Bytecode.data(), Bytecode.size());
  if (!ModRet) {
    return Result;
  }
  EVMModule *Mod = *ModRet;

  Isolation *Iso = RT->createManagedIsolation();
  if (!Iso) {
    return Result;
  }

  evmc_message Msg{};
  Msg.kind = EVMC_CALL;
  Msg.gas = static_cast<int64_t>(GasLimit);
  Msg.sender = SenderAddr;
  Msg.recipient = ContractAddr;
  Msg.code_address = ContractAddr;

  const auto UpfrontResult =
      zen::utils::applyEvmUpfrontGas(*HostPtr, Msg, GasLimit, Revision);
  if (UpfrontResult != zen::utils::EvmUpfrontGasResult::Success) {
    return Result;
  }

  auto InstRet = Iso->createEVMInstance(*Mod, static_cast<uint64_t>(Msg.gas));
  if (!InstRet) {
    return Result;
  }
  EVMInstance *Inst = *InstRet;
  Inst->setRevision(Revision);

  evmc::Result ExecResult{};
  RT->callEVMMain(*Inst, Msg, ExecResult);

  zen::utils::applyEvmPostExecutionSettlement(*HostPtr, Msg, GasLimit,
                                              ExecResult, Revision);

  Result.Success = ExecResult.status_code == EVMC_SUCCESS;
  Result.GasUsed = static_cast<uint64_t>(
      GasLimit - std::max<int64_t>(0, ExecResult.gas_left));
  const uint64_t RefundLimit =
      zen::utils::computeRefundCap(Revision, Result.GasUsed);
  Result.GasRefund = std::min(
      static_cast<uint64_t>(std::max<int64_t>(0, ExecResult.gas_refund)),
      RefundLimit);
  Result.GasCharged =
      Result.GasUsed > Result.GasRefund ? Result.GasUsed - Result.GasRefund : 0;
  Result.FinalSenderBalance =
      intx::be::load<intx::uint256>(HostPtr->accounts[SenderAddr].balance);
  return Result;
}

} // namespace

// Regression tests for https://github.com/DTVMStack/DTVM/issues/588.
// Unlike the CLI helper below, executeTransaction models the state-test path
// where intrinsic gas has already been consumed before this host method.
// These tests therefore validate the host's refund-cap behavior on execution
// gas only; the CLI-specific tests cover intrinsic gas and total settlement.
TEST(EVMRegressionTest, Issue588_CappedRefundDoesNotReduceChargesOnCancun) {
  // SSTORE set slot 0 to 5, then clear it back to 0. Cancun refunds are capped
  // at 1/5 of GasUsed.
  const std::string BytecodeHex = "6005600055600060005500";
  auto BytecodeBuf = zen::utils::fromHex(BytecodeHex);
  ASSERT_TRUE(BytecodeBuf) << "Failed to parse issue #588 bytecode";

  auto Result = runSettlementTransaction(
      SettlementContractAddr, SettlementSenderAddr, *BytecodeBuf, EVMC_CANCUN,
      SettlementGasLimit, [&](zen::evm::ZenMockedEVMHost &Host) {
        prepareSettlementHost(Host, *BytecodeBuf, SettlementSenderAddr,
                              SettlementContractAddr);
      });

  ASSERT_TRUE(Result.Success) << "Issue #588 transaction should succeed";

  // Expected host-path gas accounting:
  //   ExecutionGasUsed = 22212; intrinsic is consumed before executeTransaction
  //   refund counter = 19900, capped to 22212/5 = 4442
  //   GasCharged = 22212 - 4442 = 17770
  // Net sender cost = GasCharged * gas_price.
  EXPECT_EQ(Result.GasUsed, 22212u)
      << "ExecutionGasUsed should exclude intrinsic gas on the host path";
  EXPECT_EQ(Result.GasCharged, 17770u)
      << "Refund cap should produce the expected Cancun gas charge";

  intx::uint256 ExpectedCost = SettlementGasPrice * Result.GasCharged;
  EXPECT_EQ(Result.InitialSenderBalance - Result.FinalSenderBalance,
            ExpectedCost)
      << "Sender should be charged GasCharged * gas_price on issue #588";
}

// On the host path, ensure that a REVERT discards the refund accumulator so
// it does not reduce the sender's net gas charge.
TEST(EVMRegressionTest, Issue588_RevertResetsRefundAccumulator) {
  // SSTORE slot 0 to 5 (which would create a refund if the slot is later
  // cleared), then REVERT. The refund counter is reset on revert, so the gas
  // refunded to the sender must be (GasLimit - GasUsed) only, not more.
  const std::string BytecodeHex = "600560005560006000fd";
  auto BytecodeBuf = zen::utils::fromHex(BytecodeHex);
  ASSERT_TRUE(BytecodeBuf) << "Failed to parse revert bytecode";

  auto Result = runSettlementTransaction(
      SettlementContractAddr, SettlementSenderAddr, *BytecodeBuf, EVMC_CANCUN,
      SettlementGasLimit, [&](zen::evm::ZenMockedEVMHost &Host) {
        prepareSettlementHost(Host, *BytecodeBuf, SettlementSenderAddr,
                              SettlementContractAddr, /*SeedStorage=*/true);
      });

  ASSERT_TRUE(Result.Success) << "Revert transaction should succeed";
  EXPECT_EQ(Result.GasCharged, Result.GasUsed)
      << "REVERT must reset refund counter so no refund is applied";

  intx::uint256 ExpectedCost = SettlementGasPrice * Result.GasCharged;
  EXPECT_EQ(Result.InitialSenderBalance - Result.FinalSenderBalance,
            ExpectedCost)
      << "Sender cost must equal GasUsed * gas_price after revert";
}

// Regression test for https://github.com/DTVMStack/DTVM/issues/588.
// On the host path, pre-London forks (Byzantium) cap refunds at
// ExecutionGasUsed / 2 instead of ExecutionGasUsed / 5 (EIP-3529). The same
// SSTORE bytecode that yields a large raw refund produces a different cap and
// therefore different GasCharged.
TEST(EVMRegressionTest, Issue588_HalfRefundCapOnByzantium) {
  // Byzantium is pre-London, pre-Berlin. Storage costs use the legacy
  // schedule: Clear refund = 15000. No cold access surcharge.
  // SSTORE set slot 0 → 5 (ADDED), then clear slot 0 → 0 (ADDED_DELETED,
  // which maps to DELETED in the legacy table → ReSet=5000, Clear=15000).
  const std::string BytecodeHex = "6005600055600060005500";
  auto BytecodeBuf = zen::utils::fromHex(BytecodeHex);
  ASSERT_TRUE(BytecodeBuf) << "Failed to parse issue #588 pre-London bytecode";

  auto Result = runSettlementTransaction(
      SettlementContractAddr, SettlementSenderAddr, *BytecodeBuf,
      EVMC_BYZANTIUM, SettlementGasLimit,
      [&](zen::evm::ZenMockedEVMHost &Host) {
        prepareSettlementHost(Host, *BytecodeBuf, SettlementSenderAddr,
                              SettlementContractAddr);
      });

  ASSERT_TRUE(Result.Success)
      << "Issue #588 pre-London transaction should succeed";

  // On Byzantium:
  //   4×PUSH1(base=3) = 12
  //   SSTORE#1 (cold skip, ADDED): cold=0, warm=20000 (Set), refund=0 → 20000
  //   SSTORE#2 (warm, ADDED_DELETED→DELETED): cold=0, warm=5000 (ReSet),
  //     refund=15000 (Clear) → 5000
  //   GasUsed = 12 + 20000 + 5000 = 25012
  //   Raw refund = 15000
  //   Refund cap (pre-London) = GasUsed / 2 = 12506
  //   Applied refund = min(15000, 12506) = 12506
  //   GasCharged = 25012 - 12506 = 12996
  EXPECT_EQ(Result.GasUsed, 25012u)
      << "GasUsed should equal PUSH base + SSTORE costs on Byzantium";

  uint64_t HalfCap = Result.GasUsed / 2; // = 12506
  EXPECT_EQ(Result.GasRefund, HalfCap)
      << "Pre-London refund must be capped at GasUsed/2, not GasUsed/5";

  // Raw refund (15000) must exceed the half cap, confirming the cap is active.
  EXPECT_LT(Result.GasRefund, 15000u)
      << "Raw EIP-2200 Clear refund (15000) should be capped by /2 rule";

  EXPECT_EQ(Result.GasCharged, Result.GasUsed - HalfCap)
      << "GasCharged = GasUsed - GasUsed/2 after refund cap";

  intx::uint256 ExpectedCost = SettlementGasPrice * Result.GasCharged;
  EXPECT_EQ(Result.InitialSenderBalance - Result.FinalSenderBalance,
            ExpectedCost)
      << "Sender should be charged GasCharged * gas_price on issue #588";
}

// Regression test for https://github.com/DTVMStack/DTVM/issues/588
// SELFDESTRUCT on a pre-London revision adds EXTRA_REFUND_BEFORE_LONDON (24000)
// to the refund accumulator. The /2 refund cap must still apply.
TEST(EVMRegressionTest, Issue588_SELFDESTRUCTPreLondonRefundCapped) {
  // Bytecode: PUSH1 0x00 SELFDESTRUCT — destroys contract, transfers balance
  // to address(0). On pre-London this adds 24000 refund, capped at GasUsed/2.
  const std::string BytecodeHex = "6000FF";
  auto BytecodeBuf = zen::utils::fromHex(BytecodeHex);
  ASSERT_TRUE(BytecodeBuf) << "Failed to parse SELFDESTRUCT bytecode hex";

  auto Result = runSettlementTransaction(
      SettlementContractAddr, SettlementSenderAddr, *BytecodeBuf,
      EVMC_BYZANTIUM, SettlementGasLimit,
      [&](zen::evm::ZenMockedEVMHost &Host) {
        prepareSettlementHost(Host, *BytecodeBuf, SettlementSenderAddr,
                              SettlementContractAddr);
      });

  ASSERT_TRUE(Result.Success)
      << "SELFDESTRUCT must succeed on Byzantium without cold-access costs";

  // On Byzantium (pre-Berlin):
  //   PUSH1(base=3) + SELFDESTRUCT(base=5000) = 5003
  //   No cold access surcharge, no account creation cost (recipient balance=0)
  //   EXTRA_REFUND_BEFORE_LONDON = 24000 added to refund counter
  //   Refund cap = GasUsed / 2 = 5003 / 2 = 2501
  //   Applied refund = min(24000, 2501) = 2501
  //   GasCharged = 5003 - 2501 = 2502
  constexpr uint64_t SelfDestructGas = 3 + 5000; // PUSH1 + SELFDESTRUCT
  EXPECT_EQ(Result.GasUsed, SelfDestructGas)
      << "GasUsed must be PUSH1 + SELFDESTRUCT base cost on Byzantium";

  uint64_t HalfCap = Result.GasUsed / 2; // = 2501
  EXPECT_EQ(Result.GasRefund, HalfCap)
      << "Pre-London SELFDESTRUCT refund must be capped at GasUsed/2";
  EXPECT_LT(Result.GasRefund, zen::evm::EXTRA_REFUND_BEFORE_LONDON)
      << "Raw EXTRA_REFUND_BEFORE_LONDON (24000) must be capped";

  EXPECT_EQ(Result.GasCharged, SelfDestructGas - HalfCap)
      << "GasCharged must be GasUsed minus the /2 cap after SELFDESTRUCT";

  intx::uint256 ExpectedCost = SettlementGasPrice * Result.GasCharged;
  EXPECT_EQ(Result.InitialSenderBalance - Result.FinalSenderBalance,
            ExpectedCost)
      << "Sender must be charged GasCharged * gas_price after SELFDESTRUCT";
}

// Regression test for https://github.com/DTVMStack/DTVM/issues/588
// Exercises the actual dtvm.cpp CLI settlement path (not the test-host helper)
// to ensure intrinsic gas, refund cap, and balance update stay aligned.
TEST(EVMRegressionTest, Issue588_CliSettlement_CappedRefundOnCancun) {
  const std::string BytecodeHex = "6005600055600060005500";
  auto BytecodeBuf = zen::utils::fromHex(BytecodeHex);
  ASSERT_TRUE(BytecodeBuf)
      << "Failed to parse issue #588 CLI settlement bytecode";

  auto Result = runDtvmCliSettlementTransaction(
      SettlementContractAddr, SettlementSenderAddr, *BytecodeBuf, EVMC_CANCUN,
      SettlementGasLimit, [&](zen::evm::ZenMockedEVMHost &Host) {
        prepareSettlementHost(Host, *BytecodeBuf, SettlementSenderAddr,
                              SettlementContractAddr);
      });

  ASSERT_TRUE(Result.Success) << "CLI settlement transaction should succeed";

  EXPECT_EQ(Result.GasUsed, 43212u)
      << "CLI path should be the actual SSTORE execution cost";
  EXPECT_EQ(Result.GasCharged, 34570u)
      << "CLI path refund cap should produce the actual Cancun gas charge";

  intx::uint256 ExpectedCost = SettlementGasPrice * Result.GasCharged;
  EXPECT_EQ(Result.InitialSenderBalance - Result.FinalSenderBalance,
            ExpectedCost)
      << "CLI path sender should be charged GasCharged * gas_price";
}

// Regression test for https://github.com/DTVMStack/DTVM/issues/588
// Same as the Byzantium SSTORE test above, but driven through the CLI path.
TEST(EVMRegressionTest, Issue588_CliSettlement_HalfRefundCapOnByzantium) {
  const std::string BytecodeHex = "6005600055600060005500";
  auto BytecodeBuf = zen::utils::fromHex(BytecodeHex);
  ASSERT_TRUE(BytecodeBuf)
      << "Failed to parse issue #588 pre-London CLI settlement bytecode";

  auto Result = runDtvmCliSettlementTransaction(
      SettlementContractAddr, SettlementSenderAddr, *BytecodeBuf,
      EVMC_BYZANTIUM, SettlementGasLimit,
      [&](zen::evm::ZenMockedEVMHost &Host) {
        prepareSettlementHost(Host, *BytecodeBuf, SettlementSenderAddr,
                              SettlementContractAddr);
      });

  ASSERT_TRUE(Result.Success)
      << "CLI settlement pre-London transaction should succeed";

  EXPECT_EQ(Result.GasUsed, 46012u)
      << "CLI path GasUsed should equal PUSH base + SSTORE costs on Byzantium";

  EXPECT_EQ(Result.GasRefund, 15000u)
      << "CLI path pre-London refund must reserve the original refund counter";

  EXPECT_EQ(Result.GasCharged, 31012u)
      << "CLI path GasCharged should be GasUsed minus the refund";

  intx::uint256 ExpectedCost = SettlementGasPrice * Result.GasCharged;
  EXPECT_EQ(Result.InitialSenderBalance - Result.FinalSenderBalance,
            ExpectedCost)
      << "CLI path sender should be charged GasCharged * gas_price";
}

// Regression test for https://github.com/DTVMStack/DTVM/issues/545
// BALANCE should reflect the upfront gas deduction (gas_price * gas_limit)
// from the sender's balance, per EVM spec (Yellow Paper §6).
TEST(EVMRegressionTest, Issue545_BalanceReflectsUpfrontGasDeduction) {
  // Contract: CALLER BALANCE PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN
  // Returns the caller's balance as 32-byte output.
  const std::string BytecodeHex = "333160005260206000f3";
  auto BytecodeBuf = zen::utils::fromHex(BytecodeHex);
  ASSERT_TRUE(BytecodeBuf) << "Failed to parse bytecode hex";

  RuntimeConfig Config;
  Config.Mode = common::RunMode::InterpMode;

  const evmc::address ContractAddr = evmc::literals::operator""_address(
      "00000000000000000000000000000000000000f1");
  const evmc::address SenderAddr = evmc::literals::operator""_address(
      "a94f5374fce5edbc8e2a8697c15331677e6ebf0b");

  auto HostPtr = std::make_unique<zen::evm::ZenMockedEVMHost>();

  // Contract account with the CALLER+BALANCE bytecode
  evmc::MockedAccount ContractAccount;
  ContractAccount.code = evmc::bytes(BytecodeBuf->data(), BytecodeBuf->size());

  // Sender with initial balance 0xFFFFFFFFFF (1099511627775)
  evmc::MockedAccount SenderAccount;
  SenderAccount.set_balance(0xFFFFFFFFFF);

  HostPtr->accounts[ContractAddr] = ContractAccount;
  HostPtr->accounts[SenderAddr] = SenderAccount;

  // Set gas_price = 16, base_fee = 16 (matching issue reproduction)
  evmc_tx_context TxCtx{};
  TxCtx.tx_origin = SenderAddr;
  TxCtx.tx_gas_price = intx::be::store<evmc::uint256be>(intx::uint256(16));
  TxCtx.block_base_fee = intx::be::store<evmc::uint256be>(intx::uint256(16));
  HostPtr->tx_context = TxCtx;

  auto RT = Runtime::newEVMRuntime(Config, HostPtr.get());
  ASSERT_TRUE(RT != nullptr) << "Failed to create runtime";
  HostPtr->setRuntime(RT.get());

  auto ModRet = RT->loadEVMModule("issue545_balance_gas", BytecodeBuf->data(),
                                  BytecodeBuf->size());
  ASSERT_TRUE(ModRet) << "Failed to load module";
  EVMModule *Mod = *ModRet;

  Isolation *Iso = RT->createManagedIsolation();
  ASSERT_TRUE(Iso != nullptr) << "Failed to create isolation";

  constexpr uint64_t GasLimit = 1000000;
  const int64_t IntrinsicGas =
      zen::utils::computeIntrinsicGas(EVMC_CANCUN, EVMC_CALL, nullptr, 0);
  ASSERT_GT(GasLimit, static_cast<uint64_t>(IntrinsicGas));
  const uint64_t ExecutionGasLimit = GasLimit - IntrinsicGas;

  auto InstRet = Iso->createEVMInstance(*Mod, ExecutionGasLimit);
  ASSERT_TRUE(InstRet) << "Failed to create instance";
  EVMInstance *Inst = *InstRet;
  Inst->setRevision(EVMC_CANCUN);

  // Deduct upfront gas cost from sender's balance before execution,
  // matching EVM spec and the CLI fix for issue #545.
  intx::uint256 GasPrice =
      intx::be::load<intx::uint256>(HostPtr->tx_context.tx_gas_price);
  intx::uint256 BaseFee =
      intx::be::load<intx::uint256>(HostPtr->tx_context.block_base_fee);
  intx::uint256 EffectiveGasPrice = GasPrice > BaseFee ? GasPrice : BaseFee;
  intx::uint256 UpfrontGasCost = intx::uint256(GasLimit) * EffectiveGasPrice;
  auto &SenderAcc = HostPtr->accounts[SenderAddr];
  intx::uint256 SenderBalance =
      intx::be::load<intx::uint256>(SenderAcc.balance);
  ASSERT_GE(SenderBalance, UpfrontGasCost)
      << "Sender balance insufficient for upfront gas cost";
  SenderBalance -= UpfrontGasCost;
  SenderAcc.balance = intx::be::store<evmc::bytes32>(SenderBalance);

  evmc_message Msg = {
      .kind = EVMC_CALL,
      .flags = 0u,
      .depth = 0,
      .gas = static_cast<int64_t>(ExecutionGasLimit),
      .recipient = ContractAddr,
      .sender = SenderAddr,
      .input_data = nullptr,
      .input_size = 0,
      .value = {},
      .create2_salt = {},
      .code_address = ContractAddr,
      .code = reinterpret_cast<const uint8_t *>(Mod->Code),
      .code_size = Mod->CodeSize,
  };

  evmc::Result RawResult;
  EXPECT_NO_THROW({ RT->callEVMMain(*Inst, Msg, RawResult); });
  ASSERT_EQ(RawResult.status_code, EVMC_SUCCESS)
      << "EVM execution failed with status code "
      << static_cast<int>(RawResult.status_code);

  // Expected: initial balance - gas_price * gas_limit
  // 0xFFFFFFFFFF - 16 * 1000000 = 0xFFFF0BDBFF
  evmc::bytes32 OutputBytes{};
  std::memcpy(OutputBytes.bytes, RawResult.output_data, 32);
  intx::uint256 ReturnedBalance = intx::be::load<intx::uint256>(OutputBytes);

  intx::uint256 ExpectedBalance =
      intx::uint256(0xFFFFFFFFFF) - intx::uint256(16) * intx::uint256(1000000);

  EXPECT_EQ(ReturnedBalance, ExpectedBalance)
      << "BALANCE should return sender balance after upfront gas deduction";
}

// ---------------------------------------------------------------------------
// Regression tests for Issue #563 / #564:
//   loadState() must clamp int64_t fields (block_gas_limit, block_number,
//   block_timestamp) to INT64_MAX when JSON values exceed INT64_MAX, rather
//   than silently wrapping them to negative values.
// ---------------------------------------------------------------------------

// Helper: write a minimal state JSON with a specific tx_context field set to
// the given numeric value. All other tx_context fields use safe defaults.
static void writeInt64OverflowStateJson(const std::string &FilePath,
                                        const std::string &FieldName,
                                        const std::string &NumericValue) {
  // clang-format off
  const std::string DefaultJson = R"({
  "accounts": {
    "a94f5374fce5edbc8e2a8697c15331677e6ebf0b": {
      "balance": "000000000000000000000000000000000000000000000000000000ffffffffff",
      "nonce": 0, "code": "", "codehash": "0000000000000000000000000000000000000000000000000000000000000000", "storage": {}
    }
  },
  "tx_context": {
    "gas_price": "0000000000000000000000000000000000000000000000000000000000000010",
    "block_number": 1,
    "block_timestamp": 1000,
    "block_coinbase": "b94f5374fce5edbc8e2a8697c15331677e6ebf0b",
    "block_prev_randao": "0000000000000000000000000000000000000000000000000000000000200000",
    "block_gas_limit": 30000000,
    "block_base_fee": "0000000000000000000000000000000000000000000000000000000000000010"
  }
})";
  // clang-format on

  // Map each field name to its default value in the template above.
  std::string DefaultKeyValue;
  if (FieldName == "block_gas_limit") {
    DefaultKeyValue = "\"block_gas_limit\": 30000000";
  } else if (FieldName == "block_number") {
    DefaultKeyValue = "\"block_number\": 1";
  } else if (FieldName == "block_timestamp") {
    DefaultKeyValue = "\"block_timestamp\": 1000";
  } else {
    FAIL() << "Unsupported field name: " << FieldName;
  }

  std::string Content = DefaultJson;
  auto Pos = Content.find(DefaultKeyValue);
  ASSERT_NE(Pos, std::string::npos) << "Could not find default value for "
                                    << FieldName << " in template JSON";
  Content.replace(Pos, DefaultKeyValue.size(),
                  "\"" + FieldName + "\": " + NumericValue);

  std::ofstream OutFile(FilePath);
  OutFile << Content;
  OutFile.close();
}

// block_gas_limit = 2^63  →  clamped to INT64_MAX (no negative wrap)
TEST(EVMStateSaveLoad, BlockGasLimitOverflowInt64) {
  const std::string FilePath = "/tmp/dtvm_test_gas_limit_overflow_int64.json";
  writeInt64OverflowStateJson(FilePath, "block_gas_limit",
                              "9223372036854775808"); // 2^63

  auto Host = std::make_unique<zen::evm::ZenMockedEVMHost>();
  ASSERT_TRUE(zen::utils::loadState(*Host, FilePath));
  EXPECT_EQ(Host->tx_context.block_gas_limit,
            std::numeric_limits<int64_t>::max());
  EXPECT_GT(Host->tx_context.block_gas_limit, 0)
      << "block_gas_limit must not be negative after clamp";

  std::filesystem::remove(FilePath);
}

// block_gas_limit = 2^64 - 1  →  clamped to INT64_MAX
TEST(EVMStateSaveLoad, BlockGasLimitOverflowUint64Max) {
  const std::string FilePath =
      "/tmp/dtvm_test_gas_limit_overflow_uint64max.json";
  writeInt64OverflowStateJson(FilePath, "block_gas_limit",
                              "18446744073709551615"); // 2^64 - 1

  auto Host = std::make_unique<zen::evm::ZenMockedEVMHost>();
  ASSERT_TRUE(zen::utils::loadState(*Host, FilePath));
  EXPECT_EQ(Host->tx_context.block_gas_limit,
            std::numeric_limits<int64_t>::max());
  EXPECT_GT(Host->tx_context.block_gas_limit, 0)
      << "block_gas_limit must not be negative after clamp";

  std::filesystem::remove(FilePath);
}

// block_gas_limit = INT64_MAX  →  exact value preserved (boundary)
TEST(EVMStateSaveLoad, BlockGasLimitAtInt64Max) {
  const std::string FilePath = "/tmp/dtvm_test_gas_limit_int64max.json";
  writeInt64OverflowStateJson(FilePath, "block_gas_limit",
                              "9223372036854775807"); // INT64_MAX

  auto Host = std::make_unique<zen::evm::ZenMockedEVMHost>();
  ASSERT_TRUE(zen::utils::loadState(*Host, FilePath));
  EXPECT_EQ(Host->tx_context.block_gas_limit,
            std::numeric_limits<int64_t>::max());

  std::filesystem::remove(FilePath);
}

// block_number = 2^63  →  clamped to INT64_MAX
TEST(EVMStateSaveLoad, BlockNumberOverflowInt64) {
  const std::string FilePath =
      "/tmp/dtvm_test_block_number_overflow_int64.json";
  writeInt64OverflowStateJson(FilePath, "block_number",
                              "9223372036854775808"); // 2^63

  auto Host = std::make_unique<zen::evm::ZenMockedEVMHost>();
  ASSERT_TRUE(zen::utils::loadState(*Host, FilePath));
  EXPECT_EQ(Host->tx_context.block_number, std::numeric_limits<int64_t>::max());
  EXPECT_GT(Host->tx_context.block_number, 0)
      << "block_number must not be negative after clamp";

  std::filesystem::remove(FilePath);
}

// block_number = INT64_MAX  →  exact value preserved
TEST(EVMStateSaveLoad, BlockNumberAtInt64Max) {
  const std::string FilePath = "/tmp/dtvm_test_block_number_int64max.json";
  writeInt64OverflowStateJson(FilePath, "block_number",
                              "9223372036854775807"); // INT64_MAX

  auto Host = std::make_unique<zen::evm::ZenMockedEVMHost>();
  ASSERT_TRUE(zen::utils::loadState(*Host, FilePath));
  EXPECT_EQ(Host->tx_context.block_number, std::numeric_limits<int64_t>::max());

  std::filesystem::remove(FilePath);
}

// block_timestamp = 2^63  →  clamped to INT64_MAX
TEST(EVMStateSaveLoad, BlockTimestampOverflowInt64) {
  const std::string FilePath =
      "/tmp/dtvm_test_block_timestamp_overflow_int64.json";
  writeInt64OverflowStateJson(FilePath, "block_timestamp",
                              "9223372036854775808"); // 2^63

  auto Host = std::make_unique<zen::evm::ZenMockedEVMHost>();
  ASSERT_TRUE(zen::utils::loadState(*Host, FilePath));
  EXPECT_EQ(Host->tx_context.block_timestamp,
            std::numeric_limits<int64_t>::max());
  EXPECT_GT(Host->tx_context.block_timestamp, 0)
      << "block_timestamp must not be negative after clamp";

  std::filesystem::remove(FilePath);
}

// block_timestamp = INT64_MAX  →  exact value preserved
TEST(EVMStateSaveLoad, BlockTimestampAtInt64Max) {
  const std::string FilePath = "/tmp/dtvm_test_block_timestamp_int64max.json";
  writeInt64OverflowStateJson(FilePath, "block_timestamp",
                              "9223372036854775807"); // INT64_MAX

  auto Host = std::make_unique<zen::evm::ZenMockedEVMHost>();
  ASSERT_TRUE(zen::utils::loadState(*Host, FilePath));
  EXPECT_EQ(Host->tx_context.block_timestamp,
            std::numeric_limits<int64_t>::max());

  std::filesystem::remove(FilePath);
}
// ---------------------------------------------------------------------------
// Regression tests for upstream issues that were fixed by PR #601 - #610.
// ---------------------------------------------------------------------------
TEST(EVMStateSaveLoad, Issue601_OverlongUint256FailsWithoutAbort) {
  const std::string StateFilePath = "/tmp/dtvm_issue601_state.json";
  const std::string OverlongHex(66, 'a');
  const std::string StateJson = R"({
    "accounts": {
      "00000000000000000000000000000000000000f1": {
        "balance": ")" + OverlongHex +
                                R"(",
        "code": "0x5f00",
        "nonce": 0,
        "storage": {}
      }
    }
  })";

  {
    std::ofstream StateFile(StateFilePath);
    ASSERT_TRUE(StateFile) << "Failed to create issue #601 state file";
    StateFile << StateJson;
  }

  auto Host = std::make_unique<zen::evm::ZenMockedEVMHost>();
  EXPECT_FALSE(zen::utils::loadState(*Host, StateFilePath))
      << "An overlong uint256 must be rejected, not crash the process";
  std::filesystem::remove(StateFilePath);
}

TEST(EVMRegressionTest, Issue602_KZGPrecompileIsWarmOnCancun) {
  auto Host = std::make_unique<zen::evm::ZenMockedEVMHost>();
  evmc::address Sender{};
  evmc::address Recipient{};
  evmc::address Coinbase{};
  zen::utils::prewarmTransactionAccounts(*Host, EVMC_CANCUN, Sender, Recipient,
                                         Coinbase);
  evmc::address KZGPrecompile{};
  KZGPrecompile.bytes[19] = 0x0a;
  EXPECT_EQ(Host->access_account(KZGPrecompile), EVMC_ACCESS_WARM)
      << "EIP-4844 KZG precompile must be warm at transaction start";
}

TEST(EVMRegressionTest, Issue602_KZGPrecompileStaysColdBeforeCancun) {
  auto Host = std::make_unique<zen::evm::ZenMockedEVMHost>();
  evmc::address Sender{};
  evmc::address Recipient{};
  evmc::address Coinbase{};
  zen::utils::prewarmTransactionAccounts(*Host, EVMC_BERLIN, Sender, Recipient,
                                         Coinbase);
  evmc::address KZGPrecompile{};
  KZGPrecompile.bytes[19] = 0x0a;
  EXPECT_EQ(Host->access_account(KZGPrecompile), EVMC_ACCESS_COLD)
      << "KZG precompile must not be pre-warmed before Cancun";
}

TEST(EVMRegressionTest, Issue606_EmptyPrestateAccountChargesNewAccountGas) {
  const evmc::address SenderAddr = evmc::literals::operator""_address(
      "1111111111111111111111111111111111111111");
  const evmc::address ContractAddr = evmc::literals::operator""_address(
      "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
  const evmc::address CalleeAddr = evmc::literals::operator""_address(
      "a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7");
  std::string BytecodeHex = "5f5f5f5f600173";
  for (int I = 0; I < 20; ++I) {
    BytecodeHex += "a7";
  }
  BytecodeHex += "600ff15a6280010555";
  const std::vector<uint8_t> Bytecode =
      zen::utils::fromHex(BytecodeHex).value();

  auto Host = std::make_unique<zen::evm::ZenMockedEVMHost>();
  Host->accounts[ContractAddr].code =
      evmc::bytes(Bytecode.data(), Bytecode.size());
  Host->accounts[SenderAddr].set_balance(0x1bc16d674ec80000ULL);
  Host->accounts[CalleeAddr] = evmc::MockedAccount{};
  Host->tx_context.block_coinbase = evmc::address{};
  Host->tx_context.tx_origin = SenderAddr;
  Host->tx_context.tx_gas_price =
      intx::be::store<evmc::uint256be>(intx::uint256(1));
  Host->tx_context.block_base_fee =
      intx::be::store<evmc::uint256be>(intx::uint256(1));

  RuntimeConfig Config;
  Config.Mode = common::RunMode::InterpMode;
  auto RT = Runtime::newEVMRuntime(Config, Host.get());
  ASSERT_TRUE(RT);
  Host->setRuntime(RT.get());

  zen::evm::ZenMockedEVMHost::TransactionExecutionConfig ExecConfig;
  ExecConfig.ModuleName = "issue606";
  ExecConfig.Bytecode = Bytecode.data();
  ExecConfig.BytecodeSize = Bytecode.size();
  ExecConfig.Revision = EVMC_CANCUN;
  // The issue's CLI command starts the contract with gas-limit 1000000 minus
  // the basic intrinsic gas.  This keeps the verdict independent of the
  // CLI's different fee paths.
  ExecConfig.GasLimit = 1000000 - 21000;
  evmc_message Msg{};
  Msg.kind = EVMC_CALL;
  Msg.gas = 1000000 - 21000;
  Msg.sender = SenderAddr;
  Msg.recipient = ContractAddr;
  Msg.code_address = ContractAddr;
  ExecConfig.Message = Msg;

  auto Result = Host->executeTransaction(ExecConfig);
  ASSERT_TRUE(Result.Success) << Result.ErrorMessage;
  ASSERT_EQ(Result.Status, EVMC_SUCCESS);

  const evmc::bytes32 StorageKey = zen::utils::parseBytes32(
      "0000000000000000000000000000000000000000000000000000000000800105");
  const auto &StorageValue =
      Host->accounts[ContractAddr].storage.at(StorageKey).current;
  const evmc::bytes32 ExpectedRemainingGas = zen::utils::parseBytes32(
      "00000000000000000000000000000000000000000000000000000000000e6a29");
  EXPECT_EQ(std::memcmp(StorageValue.bytes, ExpectedRemainingGas.bytes, 32), 0)
      << "CALL with value to an empty prestate account must charge 25000 gas";
}

TEST(EVMRegressionTest, Issue593_CreateDoesNotCreditPhantomBalance) {
  const evmc::address SenderAddr = evmc::literals::operator""_address(
      "a94f5374fce5edbc8e2a8697c15331677e6ebf0b");
  const evmc::address ContractAddr = evmc::literals::operator""_address(
      "000000000000000000000000000000ca1100f022");
  const std::vector<uint8_t> Bytecode =
      zen::utils::fromHex(
          "5f5f5f5f5f5f5f63304130305f5ff13030f45f5f5ff05f5f5ff0")
          .value();
  std::vector<uint8_t> Calldata(80, 0x01);

  auto Host = std::make_unique<zen::evm::ZenMockedEVMHost>();
  Host->accounts[ContractAddr].code =
      evmc::bytes(Bytecode.data(), Bytecode.size());
  Host->accounts[SenderAddr].set_balance(0x3fffffffffffffffULL);
  evmc_tx_context TxCtx{};
  TxCtx.tx_origin = SenderAddr;
  TxCtx.tx_gas_price = intx::be::store<evmc::uint256be>(intx::uint256(0x80));
  TxCtx.block_base_fee = intx::be::store<evmc::uint256be>(intx::uint256(0x10));
  TxCtx.block_coinbase = evmc::literals::operator""_address(
      "b94f5374fce5edbc8e2a8697c15331677e6ebf0b");
  Host->tx_context = TxCtx;

  RuntimeConfig Config;
  Config.Mode = common::RunMode::InterpMode;
  auto RT = Runtime::newEVMRuntime(Config, Host.get());
  ASSERT_TRUE(RT);
  Host->setRuntime(RT.get());

  zen::evm::ZenMockedEVMHost::TransactionExecutionConfig ExecConfig;
  ExecConfig.ModuleName = "issue593";
  ExecConfig.Bytecode = Bytecode.data();
  ExecConfig.BytecodeSize = Bytecode.size();
  ExecConfig.Revision = EVMC_CANCUN;
  ExecConfig.GasLimit = 20000000;
  evmc_message Msg{};
  Msg.kind = EVMC_CALL;
  Msg.sender = SenderAddr;
  Msg.recipient = ContractAddr;
  Msg.code_address = ContractAddr;
  Msg.gas = 20000000;
  Msg.input_data = Calldata.data();
  Msg.input_size = Calldata.size();
  ExecConfig.Message = Msg;

  auto Result = Host->executeTransaction(ExecConfig);
  ASSERT_TRUE(Result.Success) << Result.ErrorMessage;

  for (const auto &[Address, Account] : Host->accounts) {
    if (Address == SenderAddr || Address == TxCtx.block_coinbase) {
      continue;
    }
    const intx::uint256 Balance =
        intx::be::load<intx::uint256>(Account.balance);
    EXPECT_EQ(Balance, intx::uint256(0))
        << "No account may receive balance out of thin air";
  }
}

TEST(EVMRegressionTest, Issue610_IntrinsicGasChargedOnce) {
  const std::vector<uint8_t> Bytecode = {0x00}; // STOP
  auto Result = runDtvmCliSettlementTransaction(
      SettlementContractAddr, SettlementSenderAddr, Bytecode, EVMC_CANCUN,
      21000, [&](zen::evm::ZenMockedEVMHost &Host) {
        prepareSettlementHost(Host, Bytecode, SettlementSenderAddr,
                              SettlementContractAddr);
      });
  ASSERT_TRUE(Result.Success) << "A plain STOP transaction should succeed";
  EXPECT_EQ(Result.GasUsed, 21000u)
      << "Only basic intrinsic gas may be charged for an empty contract";
  EXPECT_EQ(Result.GasCharged, 21000u);
  EXPECT_EQ(Result.InitialSenderBalance - Result.FinalSenderBalance,
            SettlementGasPrice * 21000);
}

#ifdef ZEN_ENABLE_MULTIPASS_JIT
TEST(EVMRegressionTest, Issue592_DelegateCallRecursionMultipassSucceeds) {
  const evmc::address SenderAddr = evmc::literals::operator""_address(
      "a94f5374fce5edbc8e2a8697c15331677e6ebf0b");
  const evmc::address ContractAddr = evmc::literals::operator""_address(
      "000000000000000000000000000000ca1100f022");
  const std::vector<uint8_t> Bytecode =
      zen::utils::fromHex("5f5f5f60305f5f5f5f5f5ff23030f45f5f535f5f53").value();

  RuntimeConfig Config;
  Config.Mode = common::RunMode::MultipassMode;
  Config.EnableEvmGasMetering = true;

  auto Host = std::make_unique<zen::evm::ZenMockedEVMHost>();
  Host->accounts[ContractAddr].code =
      evmc::bytes(Bytecode.data(), Bytecode.size());
  Host->accounts[SenderAddr].set_balance(0x3fffffffffffffffULL);
  Host->tx_context.tx_origin = SenderAddr;

  auto RT = Runtime::newEVMRuntime(Config, Host.get());
  ASSERT_TRUE(RT);
  Host->setRuntime(RT.get());

  zen::evm::ZenMockedEVMHost::TransactionExecutionConfig ExecConfig;
  ExecConfig.ModuleName = "issue592_multipass";
  ExecConfig.Bytecode = Bytecode.data();
  ExecConfig.BytecodeSize = Bytecode.size();
  ExecConfig.Revision = EVMC_CANCUN;
  ExecConfig.GasLimit = 20000000;
  evmc_message Msg{};
  Msg.kind = EVMC_CALL;
  Msg.gas = 20000000;
  Msg.sender = SenderAddr;
  Msg.recipient = ContractAddr;
  Msg.code_address = ContractAddr;
  ExecConfig.Message = Msg;

  auto Result = Host->executeTransaction(ExecConfig);
  ASSERT_TRUE(Result.Success) << Result.ErrorMessage;
  ASSERT_EQ(Result.Status, EVMC_SUCCESS)
      << "Multipass must execute the delegatecall recursion without aborting";
}

TEST(EVMRegressionTest, Issue603_KeccakOffsetThenMLoadsMultipassSucceeds) {
  const std::vector<uint8_t> Bytecode =
      zen::utils::fromHex("6020610100205f515f51").value();
  auto InterpExec = executeEvmBytecode("issue603_interp", Bytecode,
                                       common::RunMode::InterpMode);
  auto MultipassExec = executeEvmBytecode("issue603_multipass", Bytecode,
                                          common::RunMode::MultipassMode);
  ASSERT_EQ(InterpExec.Status, EVMC_SUCCESS);
  ASSERT_EQ(MultipassExec.Status, EVMC_SUCCESS)
      << "Multipass must not crash for KECCAK with a non-zero offset followed "
         "by memory loads";
#ifdef ZEN_ENABLE_JIT
  EXPECT_TRUE(MultipassExec.JITCompiled);
#endif
}

TEST(EVMRegressionTest, Issue594_JumpdestThenMloadMultipassSucceeds) {
  const std::vector<uint8_t> Bytecode =
      zen::utils::fromHex("5b5f515f5f57").value();
  auto InterpExec = executeEvmBytecode("issue594_interp", Bytecode,
                                       common::RunMode::InterpMode);
  auto MultipassExec = executeEvmBytecode("issue594_multipass", Bytecode,
                                          common::RunMode::MultipassMode);
  ASSERT_EQ(InterpExec.Status, EVMC_SUCCESS);
  ASSERT_EQ(MultipassExec.Status, EVMC_SUCCESS)
      << "Multipass must execute a simple JUMPDEST/MLOAD/JUMPI sequence";
#ifdef ZEN_ENABLE_JIT
  EXPECT_TRUE(MultipassExec.JITCompiled);
#endif
}

// ---------------------------------------------------------------------------
// Review follow-up to the Issue #603 KECCAK memory-cache fix: the specialized
// two-word KECCAK helpers (caller-slot and calldata-slot macro-ops) also take
// the prepared-memory no-expand path and can initialize/grow the instance
// memory on first use. Direct memory operations right after them must not see
// a stale cached base pointer/size.
// ---------------------------------------------------------------------------
TEST(EVMRegressionTest, KeccakCallerSlotThenMLoadsMultipassSucceeds) {
  // CALLER PUSH1 0x40 MSTORE PUSH1 5 PUSH1 0x60 MSTORE
  // PUSH1 0x40 PUSH1 0x40 KECCAK256 PUSH0 MLOAD PUSH0 MLOAD STOP
  const std::vector<uint8_t> Bytecode =
      zen::utils::fromHex("33604052600560605260406040205f515f5100").value();
  auto InterpExec = executeEvmBytecode("keccak_caller_slot_interp", Bytecode,
                                       common::RunMode::InterpMode);
  auto MultipassExec = executeEvmBytecode(
      "keccak_caller_slot_multipass", Bytecode, common::RunMode::MultipassMode);
  ASSERT_EQ(InterpExec.Status, EVMC_SUCCESS);
  ASSERT_EQ(MultipassExec.Status, EVMC_SUCCESS)
      << "Multipass must not crash for the caller-slot KECCAK macro-op "
         "followed by memory loads";
#ifdef ZEN_ENABLE_JIT
  EXPECT_TRUE(MultipassExec.JITCompiled);
#endif
}

TEST(EVMRegressionTest, KeccakCallDataSlotThenMLoadsMultipassSucceeds) {
  // PUSH1 0 CALLDATALOAD PUSH1 0x40 MSTORE PUSH1 5 PUSH1 0x60 MSTORE
  // PUSH1 0x40 PUSH1 0x40 KECCAK256 PUSH0 MLOAD PUSH0 MLOAD STOP
  const std::vector<uint8_t> Bytecode =
      zen::utils::fromHex("600035604052600560605260406040205f515f5100").value();
  const std::vector<uint8_t> CallData = makeUint256Calldata(0x1234);
  auto InterpExec = executeEvmBytecode("keccak_calldata_slot_interp", Bytecode,
                                       common::RunMode::InterpMode, CallData);
  auto MultipassExec =
      executeEvmBytecode("keccak_calldata_slot_multipass", Bytecode,
                         common::RunMode::MultipassMode, CallData);
  ASSERT_EQ(InterpExec.Status, EVMC_SUCCESS);
  ASSERT_EQ(MultipassExec.Status, EVMC_SUCCESS)
      << "Multipass must not crash for the calldata-slot KECCAK macro-op "
         "followed by memory loads";
#ifdef ZEN_ENABLE_JIT
  EXPECT_TRUE(MultipassExec.JITCompiled);
#endif
}
#endif // ZEN_ENABLE_MULTIPASS_JIT
