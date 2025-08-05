#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>

#include "evm/interpreter.h"
#include "evmc/mocked_host.hpp"
#include "utils/others.h"
#include "zetaengine-c.h"
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

std::string readExpectedReturnValue(const std::string &FilePath) {
  std::filesystem::path InputFilePath(FilePath);

  std::filesystem::path ExpectedPath =
      InputFilePath.parent_path() /
      (InputFilePath.stem().stem().string() + ".expected");

  std::ifstream Fin(ExpectedPath);
  if (!Fin) {
    return "";
  }

  rapidjson::IStreamWrapper JSONISWrapper(Fin);
  rapidjson::Document Doc;
  Doc.ParseStream(JSONISWrapper);

  if (Doc.HasParseError() || !Doc.IsObject()) {
    return "";
  }

  if (!Doc.HasMember("return") || !Doc["return"].IsString()) {
    return "";
  }

  return Doc["return"].GetString();
}

} // namespace

class EVMSampleTest : public ::testing::TestWithParam<std::string> {};

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

  uint64_t GasLimit = 1000000UL; // enough gas for most of the tests

  auto InstRet = Iso->createEVMInstance(*Mod, GasLimit);
  ASSERT_TRUE(Iso) << "Failed to create Instance: " << FilePath;
  EVMInstance *Inst = *InstRet;

  InterpreterExecContext Ctx(Inst);

  BaseInterpreter Interpreter(Ctx);

  evmc_message Msg = {
      .kind = EVMC_CREATE,
      .flags = 0,
      .depth = 0,
      .gas = (long)GasLimit,
  };
  Ctx.allocFrame(&Msg);

  EXPECT_NO_THROW({ Interpreter.interpret(); });

  const auto &Ret = Ctx.getReturnData();
  std::string HexRet = zen::utils::toHex(Ret.data(), Ret.size());

  // Read expected return value from .expected file
  std::string ExpectedReturn = readExpectedReturnValue(FilePath);
  if (!ExpectedReturn.empty()) {
    EXPECT_EQ(HexRet, ExpectedReturn)
        << "Test: " << std::filesystem::path(FilePath).filename().string()
        << "\nExpected: " << ExpectedReturn << "\nActual:   " << HexRet;
  } else {
    ASSERT_TRUE(false) << "No expected file found for: " << FilePath;
  }

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
                            : EvmFiles));
