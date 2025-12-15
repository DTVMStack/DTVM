// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "solidity_test_helpers.h"
#include <CLI/CLI.hpp>
#include <filesystem>
#include <gtest/gtest.h>

using namespace zen::utils;
using namespace zen::evm_test_utils;

namespace zen::test {

using SolidityTestPair = std::pair<std::string, std::string>;

std::vector<SolidityTestPair>
EnumerateSolidityTests(const std::string &TestCategory);

class SolidityContractTest : public testing::TestWithParam<SolidityTestPair> {
protected:
  static RuntimeConfig GlobalConfig;
  static uint64_t GlobalGasLimit;

public:
  static void SetGlobalConfig(const RuntimeConfig &Config) {
    GlobalConfig = Config;
  }
  static void SetGlobalGasLimit(uint64_t GasLimit) {
    GlobalGasLimit = GasLimit;
  }
  static const RuntimeConfig &GetGlobalConfig() { return GlobalConfig; }
  static uint64_t GetGlobalGasLimit() { return GlobalGasLimit; }
};

RuntimeConfig SolidityContractTest::GlobalConfig;
uint64_t SolidityContractTest::GlobalGasLimit = 0xFFFF'FFFF'FFFF;

std::vector<SolidityTestPair>
EnumerateSolidityTests(const std::string &TestCategory) {
  std::vector<SolidityTestPair> TestPairs;

  std::filesystem::path TestsRoot =
      std::filesystem::path(__FILE__).parent_path() /
      std::filesystem::path("../../tests");

  if (!TestCategory.empty()) {
    std::filesystem::path CategoryDir = TestsRoot / TestCategory;
    if (std::filesystem::exists(CategoryDir) &&
        std::filesystem::is_directory(CategoryDir)) {
      for (const auto &Entry :
           std::filesystem::directory_iterator(CategoryDir)) {
        if (Entry.is_directory()) {
          std::string ContractName = Entry.path().filename().string();
          TestPairs.emplace_back(TestCategory, ContractName);
        }
      }
    }
  } else {
    std::string DefaultCategory = "evm_solidity";
    std::filesystem::path CategoryDir = TestsRoot / DefaultCategory;

    if (std::filesystem::exists(CategoryDir) &&
        std::filesystem::is_directory(CategoryDir)) {
      for (const auto &Entry :
           std::filesystem::directory_iterator(CategoryDir)) {
        if (Entry.is_directory()) {
          std::string ContractName = Entry.path().filename().string();
          TestPairs.emplace_back(DefaultCategory, ContractName);
        }
      }
    }
  }

  return TestPairs;
}

TEST_P(SolidityContractTest, TestContract) {
  const auto &[Category, ContractName] = GetParam();
  evmc_status_code Result = executeSingleContractTest(
      GetGlobalConfig(), GetGlobalGasLimit(), Category, ContractName);
  EXPECT_EQ(Result, EVMC_SUCCESS) << "Contract Test Failed: " << ContractName;
}

INSTANTIATE_TEST_SUITE_P(
    SolidityTests, SolidityContractTest,
    testing::ValuesIn(EnumerateSolidityTests("")),
    [](const testing::TestParamInfo<SolidityTestPair> &info) {
      return info.param.second;
    });

} // namespace zen::test

using namespace zen::test;

namespace zen::evm_test_utils {

evmc_status_code executeSingleContractTest(const RuntimeConfig &Config,
                                           uint64_t GasLimit,
                                           const std::string &TestCategory,
                                           const std::string &TestContract) {
  std::filesystem::path TestDir =
      std::filesystem::path(__FILE__).parent_path() /
      std::filesystem::path("../../tests") / TestCategory;

  if (!std::filesystem::exists(TestDir)) {
    throw getError(ErrorCode::InvalidFilePath);
  }

  std::filesystem::path ContractDir = TestDir / TestContract;
  if (!std::filesystem::exists(ContractDir) ||
      !std::filesystem::is_directory(ContractDir)) {
    throw getError(ErrorCode::InvalidFilePath);
  }

  ContractDirectoryInfo DirInfo = checkCaseDirectory(ContractDir);

  SolidityContractTestData ContractTest;
  ContractTest.ContractPath = ContractDir.string();

  parseContractJson(DirInfo.SolcJsonFile, ContractTest.ContractDataMap);
  parseTestCaseJson(DirInfo.CasesFile, ContractTest);

  if (ContractTest.TestCases.empty()) {
    return EVMC_SUCCESS;
  }

  EVMTestEnvironment TestEnv(Config);
  std::map<std::string, DeployedContract> DeployedContracts;
  std::map<std::string, evmc::address> DeployedAddresses;

  // Step 1: Deploy all specified contracts
  for (const std::string &NowContractName : ContractTest.DeployContracts) {
    auto ContractIt = ContractTest.ContractDataMap.find(NowContractName);
    ZEN_ASSERT(ContractIt != ContractTest.ContractDataMap.end());

    const auto &[ContractAddress, ContractData] = *ContractIt;
    std::vector<std::pair<std::string, std::string>> Ctorargs;
    auto ArgsIt = ContractTest.ConstructorArgs.find(NowContractName);
    if (ArgsIt != ContractTest.ConstructorArgs.end()) {
      Ctorargs = ArgsIt->second;
    }

    try {
      DeployedContract Deployed =
          deployContract(TestEnv, NowContractName, ContractData, Ctorargs,
                         DeployedAddresses, GasLimit);

      DeployedContracts[NowContractName] = Deployed;
      DeployedAddresses[NowContractName] = Deployed.Address;
    } catch (const std::exception &E) {
      std::cerr << "Deployment failed for " << NowContractName << ": "
                << E.what() << std::endl;
      return EVMC_FAILURE;
    }
  }

  // Step 2: Execute all test cases
  bool AllCasePassed = true;
  for (size_t I = 0; I < ContractTest.TestCases.size(); ++I) {
    const auto &TestCase = ContractTest.TestCases[I];
    auto InstanceIt = DeployedContracts.find(TestCase.Contract);
    if (InstanceIt == DeployedContracts.end()) {
      std::cerr << "Contract instance not found: " << TestCase.Contract
                << std::endl;
      return EVMC_FAILURE;
    }
    if (TestCase.Calldata.empty()) {
      throw getError(ErrorCode::InvalidRawData);
    }

    const auto &Contract = InstanceIt->second;
    evmc::Result CallResult =
        executeContractCall(TestEnv, Contract, TestCase.Calldata, GasLimit);
    if (checkResult(TestCase, CallResult) != EVMC_SUCCESS) {
      AllCasePassed = false;
    }
  }

#ifndef NDEBUG
  std::string StateFileName = TestContract + "_state.json";
  std::filesystem::path StateFilePath = ContractDir / StateFileName;

  if (!zen::utils::saveState(*TestEnv.MockedHost, StateFilePath.string())) {
    std::cerr << "Failed to save debug state to: " << StateFilePath
              << std::endl;
  }
#endif // NDEBUG

  return AllCasePassed ? EVMC_SUCCESS : EVMC_FAILURE;
}

} // namespace zen::evm_test_utils

GTEST_API_ int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  CLI::App CLIParser{"Solidity Tests Command Line Interface\n",
                     "solidityContractTests"};

  std::string TestContract;
  std::string TestCategory;

  // same as evm.codes: 0xFFFF'FFFF'FFFF (281,474,976,710,655)
  uint64_t GasLimit = 0xFFFF'FFFF'FFFF;
  LoggerLevel LogLevel = LoggerLevel::Info;
  RuntimeConfig Config;

  const std::unordered_map<std::string, InputFormat> FormatMap = {
      {"wasm", InputFormat::WASM},
      {"evm", InputFormat::EVM},
  };
  const std::unordered_map<std::string, RunMode> ModeMap = {
      {"interpreter", RunMode::InterpMode},
      {"multipass", RunMode::MultipassMode},
  };
  const std::unordered_map<std::string, LoggerLevel> LogMap = {
      {"trace", LoggerLevel::Trace}, {"debug", LoggerLevel::Debug},
      {"info", LoggerLevel::Info},   {"warn", LoggerLevel::Warn},
      {"error", LoggerLevel::Error}, {"fatal", LoggerLevel::Fatal},
      {"off", LoggerLevel::Off},
  };

  CLIParser.add_option("-t, --test", TestContract,
                       "Specific test contract name");
  CLIParser.add_option("-c, --category", TestCategory, "Test Category");
  CLIParser.add_option("--format", Config.Format, "Input format")
      ->transform(CLI::CheckedTransformer(FormatMap, CLI::ignore_case));
  CLIParser.add_option("-m, --mode", Config.Mode, "Running mode")
      ->transform(CLI::CheckedTransformer(ModeMap, CLI::ignore_case));
  CLIParser.add_option("--gas-limit", GasLimit, "Gas limit");
  CLIParser.add_option("--log-level", LogLevel, "Log level")
      ->transform(CLI::CheckedTransformer(LogMap, CLI::ignore_case));
#ifdef ZEN_ENABLE_EVM
  CLIParser.add_flag("--enable-evm-gas", Config.EnableEvmGasMetering,
                     "Enable EVM gas metering when compiling EVM bytecode");
#endif // ZEN_ENABLE_EVM
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
      createConsoleLogger("solidity_contract_logger", LogLevel));

  // Set global config for parameterized tests
  SolidityContractTest::SetGlobalConfig(Config);
  SolidityContractTest::SetGlobalGasLimit(GasLimit);

  if (!TestContract.empty()) {
    TestCategory = TestCategory.empty() ? "evm_solidity" : TestCategory;

    return executeSingleContractTest(Config, GasLimit, TestCategory,
                                     TestContract);
  }

  std::vector<SolidityTestPair> TestPairs;
  if (TestCategory.empty()) {
    TestPairs = EnumerateSolidityTests("");
  } else {
    TestPairs = EnumerateSolidityTests(TestCategory);
  }

  if (TestPairs.empty()) {
    std::cerr << "No tests found" << std::endl;
    return EVMC_FAILURE;
  }

  // Run all tests using Google Test
  return RUN_ALL_TESTS();
}
