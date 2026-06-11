// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include <cstring>
#include <filesystem>
#include <fstream>
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

std::vector<uint8_t> makePaddedAddressWord(const evmc::address &Address) {
  std::vector<uint8_t> Word(32, 0);
  std::memcpy(Word.data() + 12, Address.bytes, sizeof(Address.bytes));
  return Word;
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
     CallerConstSlotHelperPreservesMemoryExpansionFailureSemantics) {
  auto BytecodeBuf = zen::utils::fromHex(
      "3362ffffe0526005630100000052604062ffffe02060005260206000f3");
  ASSERT_TRUE(BytecodeBuf)
      << "Failed to parse caller-slot memory edge bytecode";

  expectInterpMatchesMultipass("keccak_caller_const_slot_mem_oog", *BytecodeBuf,
                               {}, EVMC_OUT_OF_GAS);
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
