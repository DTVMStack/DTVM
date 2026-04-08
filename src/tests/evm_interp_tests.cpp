// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
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
  bool JITCompiled = false;
};

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

  RuntimeConfig Config;
  Config.Mode = Mode;

  auto MockedHost = std::make_unique<zen::evm::ZenMockedEVMHost>();
  MockedHost->tx_context.tx_origin = zen::evm::DEFAULT_DEPLOYER_ADDRESS;
  auto RT = Runtime::newEVMRuntime(Config, MockedHost.get());
  EXPECT_TRUE(RT != nullptr) << "Failed to create runtime";
  if (!RT) {
    return Empty;
  }
  MockedHost->setRuntime(RT.get());

  auto ModRet =
      RT->loadEVMModule(FilePath, BytecodeBuf->data(), BytecodeBuf->size());
  EXPECT_TRUE(ModRet) << "Failed to load module: " << FilePath;
  if (!ModRet) {
    return Empty;
  }
  EVMModule *Mod = *ModRet;

  Isolation *Iso = RT->createManagedIsolation();
  EXPECT_TRUE(Iso != nullptr) << "Failed to create isolation: " << FilePath;
  if (!Iso) {
    return Empty;
  }

  uint64_t GasLimit = 0xFFFF'FFFF'FFFF;
  const uint64_t IntrinsicGas = zen::evm::BASIC_EXECUTION_COST;
  const uint64_t ExecutionGasLimit = GasLimit - IntrinsicGas;

  auto InstRet = Iso->createEVMInstance(*Mod, ExecutionGasLimit);
  EXPECT_TRUE(InstRet) << "Failed to create instance: " << FilePath;
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
  return Exec;
}

std::vector<uint8_t> makeUint256Calldata(uint64_t Value) {
  std::vector<uint8_t> Data(32, 0);
  for (size_t I = 0; I < sizeof(Value); ++I) {
    Data[Data.size() - 1 - I] = static_cast<uint8_t>(Value & 0xff);
    Value >>= 8;
  }
  return Data;
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
#endif
