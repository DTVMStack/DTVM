// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "host/spectest/spectest.h"
#include "host/wasi/wasi.h"
#include "tests/spectest.h"
#include "tests/test_utils.h"
#include "utils/logging.h"
#include "zetaengine.h"

#include <CLI/CLI.hpp>
#include <cstdint>
#include <fstream>
#include <functional>
#include <gtest/gtest.h>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include <fstream>

using namespace std::literals;
using namespace zen::common;
using namespace zen::runtime;
using namespace zen::host;
using namespace zen::test;
using namespace zen::utils;

namespace zen::test {
static SpecTest T(filesystem::u8path(findExecutableDir().append("/wast"sv)));
// Parameterized testing class.
class SpecUnitTest
    : public testing::TestWithParam<std::pair<std::string, std::string>> {};

void testWithUnitName(const std::pair<std::string, std::string> &UnitPair) {
  const char *CategoryName = UnitPair.first.c_str();
  const char *UnitName = UnitPair.second.c_str();
  printf("Testing unit name: %s/%s\n", CategoryName, UnitName);
  std::unique_ptr<Runtime> Runtime = Runtime::newRuntime(T.getConfig());
  LOAD_HOST_MODULE(Runtime, host, wasi_snapshot_preview1);
  LOAD_HOST_MODULE(Runtime, host, spectest);
  std::unordered_map<std::string, Instance *> InstanceMap;
  T.OnInstantiate = [&](const std::string ModuleName,
                        const std::string Filename) -> std::string {
    const auto &ModRet = Runtime->loadModule(Filename);
    Module *Mod = nullptr;
    if (ModRet) {
      Mod = *ModRet;
    } else {
      return ModRet.getError().getFormattedMessage();
    }
    Isolation *Iso = Runtime->createManagedIsolation();
    ZEN_ASSERT(Iso);
    const auto &InstRet = Iso->createInstance(*Mod);
    Instance *Inst = nullptr;
    if (InstRet) {
      Inst = *InstRet;
    } else {
      return InstRet.getError().getFormattedMessage();
    }
    ZEN_ASSERT(!ModuleName.empty());
    InstanceMap[ModuleName] = Inst;
    return "";
  };

  T.OnTrapInstantiate = [&](const std::string &Filename) -> std::string {
    const auto &ModRet = Runtime->loadModule(Filename);
    Module *Mod = nullptr;
    if (ModRet) {
      Mod = *ModRet;
    } else {
      return ModRet.getError().getFormattedMessage();
    }
    IsolationUniquePtr TmpIsolation = Runtime->createUnmanagedIsolation();
    ZEN_ASSERT(TmpIsolation);
    const auto &InstRet = TmpIsolation->createInstance(*Mod);
    if (!InstRet) {
      return InstRet.getError().getFormattedMessage();
    }
    return "";
  };

  T.OnInvoke = [&](const std::string &ModuleName, const std::string &MethodName,
                   const std::vector<TypedValue> &Params)
      -> std::tuple<std::vector<TypedValue>, std::string, uint64_t> {
    ZEN_ASSERT(!ModuleName.empty());
    ZEN_ASSERT(InstanceMap.count(ModuleName));

    Instance &Inst = *InstanceMap[ModuleName];
    // Wast allows to continue execution after a trap, so we need to clear the
    // error left by the previous execution.
    Inst.clearError();

    uint64_t SpecTestInitGasLimit = 10000;
    Inst.setGas(SpecTestInitGasLimit);

    uint32_t FuncIdx;
    std::vector<TypedValue> Results;

    if (!Inst.getModule()->getExportFunc(MethodName, FuncIdx)) {
      return {Results, "cannot find function " + MethodName, Inst.getGas()};
    }

    Runtime->callWasmFunction(Inst, FuncIdx, Params, Results);
    const Error &Err = Inst.getError();
    return {Results, Err.getFormattedMessage(), Inst.getGas()};
  };

  T.run(UnitPair);
}

TEST_P(SpecUnitTest, TestSpec) {
  const auto &UnitPair = GetParam();
  testWithUnitName(UnitPair);
}

// Initiate test suite.
INSTANTIATE_TEST_SUITE_P(spec, SpecUnitTest, testing::ValuesIn(T.enumerate()));
} // namespace zen::test

GTEST_API_ int main(int argc, char *argv[]) {
  testing::InitGoogleTest();
  CLI::App CLIParser{"SpecTests Command Line Interface\n", "specUnitTests"};
  std::string TestUnit;
  std::string TestCategory;
  LoggerLevel LogLevel = LoggerLevel::Info;
  RuntimeConfig Config;

  const std::unordered_map<std::string, InputFormat> FormatMap = {
      {"wasm", InputFormat::WASM},
      {"evm", InputFormat::EVM},
  };
  const std::unordered_map<std::string, RunMode> ModeMap = {
      {"interpreter", RunMode::InterpMode},
      {"singlepass", RunMode::SinglepassMode},
      {"multipass", RunMode::MultipassMode},
  };

  const std::unordered_map<std::string, LoggerLevel> LogMap = {
      {"trace", LoggerLevel::Trace}, {"debug", LoggerLevel::Debug},
      {"info", LoggerLevel::Info},   {"warn", LoggerLevel::Warn},
      {"error", LoggerLevel::Error}, {"fatal", LoggerLevel::Fatal},
      {"off", LoggerLevel::Off},
  };

  CLIParser.add_option("TEST_UNIT", TestUnit, "Test Unit");
  CLIParser.add_option("--format", Config.Format, "Input format")
      ->transform(CLI::CheckedTransformer(FormatMap, CLI::ignore_case));
  CLIParser.add_option("-m,--mode", Config.Mode, "Running mode")
      ->transform(CLI::CheckedTransformer(ModeMap, CLI::ignore_case));
  CLIParser.add_option("-c, --category", TestCategory, "Test Category");
  CLIParser.add_option("--log-level", LogLevel, "Log level")
      ->transform(CLI::CheckedTransformer(LogMap, CLI::ignore_case));
#ifdef ZEN_ENABLE_MULTIPASS_JIT
  CLIParser.add_flag("--disable-multipass-greedyra",
                     Config.DisableMultipassGreedyRA,
                     "Disable greedy register allocation of multipass JIT");
  auto *DMMOption = CLIParser.add_flag(
      "--disable-multipass-multithread", Config.DisableMultipassMultithread,
      "Disable multithread compilation of multipass JIT");
  CLIParser
      .add_option("--num-multipass-threads", Config.NumMultipassThreads,
                  "Number of threads for multipass JIT(set 0 for automatic "
                  "determination)")
      ->excludes(DMMOption);
  CLIParser.add_flag("--enable-multipass-lazy", Config.EnableMultipassLazy,
                     "Enable multipass lazy mode(on request compile)");
#endif // ZEN_ENABLE_MULTIPASS_JIT

  CLI11_PARSE(CLIParser, argc, argv);

  zen::setGlobalLogger(
      createConsoleLogger("zen_spec_unit_tests_logger", LogLevel));

  T.setConfig(Config);

  if (TestUnit.empty()) {
    if (!TestCategory.empty()) {
      ZEN_LOG_ERROR("category is specified but unit is not");
      return EXIT_FAILURE;
    }
    return RUN_ALL_TESTS();
  }
  if (TestCategory.empty()) {
    TestCategory = "core"; // default category
  }
  testWithUnitName({TestCategory, TestUnit});
  return EXIT_SUCCESS;
}
