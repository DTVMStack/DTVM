// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <yaml-cpp/yaml.h>

#include "evm/interpreter.h"
#include "evm_test_host.hpp"
#include "evmc/mocked_host.hpp"
#include "runtime/evm_module.h"
#include "utils/evm.h"
#include "zetaengine.h"

using namespace zen;
using namespace zen::evm;
using namespace zen::runtime;

namespace {

std::vector<std::string> getAllEvmBytecodeFiles() {
  std::vector<std::string> Files;
  std::filesystem::path DirPath =
      std::filesystem::path(__FILE__).parent_path() /
      std::filesystem::path("../../tests/evm_asm");

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

  std::unique_ptr<evmc::Host> Host = std::make_unique<evmc::MockedHost>();

  auto RT = Runtime::newEVMRuntime(Config, Host.get());
  ASSERT_TRUE(RT != nullptr) << "Failed to create runtime";

  auto ModRet = RT->loadEVMModule(FilePath);
  ASSERT_TRUE(ModRet) << "Failed to load module: " << FilePath;

  EVMModule *Mod = *ModRet;

  Isolation *Iso = RT->createManagedIsolation();
  ASSERT_TRUE(Iso) << "Failed to create Isolation: " << FilePath;

  // same as evm.codes: 0xFFFF'FFFF'FFFF (281,474,976,710,655)
  uint64_t GasLimit = 0xFFFF'FFFF'FFFF;

  auto InstRet = Iso->createEVMInstance(*Mod, GasLimit);
  ASSERT_TRUE(Iso) << "Failed to create Instance: " << FilePath;
  EVMInstance *Inst = *InstRet;

  InterpreterExecContext Ctx(Inst);

  BaseInterpreter Interpreter(Ctx);

  evmc_message Msg = {
      .kind = EVMC_CALL,
      .flags = 0u,
      .depth = 0,
      .gas = static_cast<int64_t>(GasLimit),
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
