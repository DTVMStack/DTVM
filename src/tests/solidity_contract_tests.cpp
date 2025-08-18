#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "evm/interpreter.h"
#include "evm_test_helpers.h"
#include "evmc/mocked_host.hpp"
#include "host/evm/crypto.h"
#include "utils/others.h"
#include "zetaengine.h"

using namespace zen;
using namespace zen::evm;
using namespace zen::runtime;
using namespace zen::evm_test_utils;

namespace {
bool Debug = false;

std::string toLowerHex(const std::string &Hex) {
  std::string Result = Hex;
  for (char &C : Result) {
    C = std::tolower(static_cast<unsigned char>(C));
  }
  return Result;
}

bool hexEquals(const std::string &Hex1, const std::string &Hex2) {
  return toLowerHex(Hex1) == toLowerHex(Hex2);
}

std::string computeFunctionSelector(const std::string &FunctionSig) {
  const std::vector<uint8_t> InputBytes(FunctionSig.begin(), FunctionSig.end());

  const std::vector<uint8_t> Hash = host::evm::crypto::keccak256(InputBytes);

  if (Hash.size() >= 4) {
    return utils::toHex(Hash.data(), 4);
  }

  return "";
}

struct SolidityTestCase {
  std::string Name;
  std::string Function;
  std::string Expected;
  std::string Contract;
  std::string Calldata;
};

struct SolcContractData {
  std::string DeployBytecode;
  std::string RuntimeBytecode;
};

struct ContractInstance {
  EVMInstance *Instance;
};

struct SolidityContractTestData {
  std::string ContractPath;
  std::vector<SolidityTestCase> TestCases;
  std::map<std::string, SolcContractData> ContractDataMap;
  std::string MainContract;
  std::vector<std::string> DeployContracts;
};

std::map<std::string, SolcContractData>
loadAllSolcContractData(const std::string &JsonPath) {
  std::map<std::string, SolcContractData> ContractDataMap;
  std::ifstream File(JsonPath);
  if (!File.is_open()) {
    return ContractDataMap;
  }

  rapidjson::IStreamWrapper Isw(File);
  rapidjson::Document Doc;
  Doc.ParseStream(Isw);

  if (Doc.HasParseError()) {
    return ContractDataMap;
  }

  if (!Doc.HasMember("contracts") || !Doc["contracts"].IsObject()) {
    return ContractDataMap;
  }

  const auto &Contracts = Doc["contracts"].GetObject();
  if (Contracts.MemberCount() == 0) {
    return ContractDataMap;
  }

  for (const auto &ContractEntry : Contracts) {
    std::string ContractFullName = ContractEntry.name.GetString();
    const auto &ContractInfo = ContractEntry.value;

    std::string ContractName = ContractFullName;
    if (size_t ColonPos = ContractFullName.find(':');
        ContractFullName.find(':') != std::string::npos) {
      ContractName = ContractFullName.substr(ColonPos + 1);
    }

    SolcContractData ContractData;

    if (ContractInfo.HasMember("bin") && ContractInfo["bin"].IsString()) {
      ContractData.DeployBytecode = ContractInfo["bin"].GetString();
    }

    if (ContractInfo.HasMember("bin-runtime") &&
        ContractInfo["bin-runtime"].IsString()) {
      ContractData.RuntimeBytecode = ContractInfo["bin-runtime"].GetString();
    }

    ContractDataMap[ContractName] = ContractData;
  }

  return ContractDataMap;
}

std::vector<SolidityContractTestData> getAllSolidityContractTests() {
  std::vector<SolidityContractTestData> Tests;
  std::filesystem::path DirPath =
      std::filesystem::path(__FILE__).parent_path() /
      std::filesystem::path("../../tests/evm_solidity");

  if (!std::filesystem::exists(DirPath)) {
    std::cerr << "tests/evm_solidity does not exist: " << DirPath.string()
              << std::endl;
    return Tests;
  }

  for (const auto &Entry : std::filesystem::directory_iterator(DirPath)) {
    if (Entry.is_directory()) {
      std::filesystem::path ContractDir = Entry.path();
      std::filesystem::path TestCasesFile = ContractDir / "test_cases.json";

      std::string FolderName = ContractDir.filename().string();

      if (std::filesystem::path SolcJsonFile =
              ContractDir / (FolderName + ".json");
          std::filesystem::exists(SolcJsonFile) &&
          std::filesystem::exists(TestCasesFile)) {
        SolidityContractTestData ContractTest;
        ContractTest.ContractPath = ContractDir.string();
        ContractTest.ContractDataMap =
            loadAllSolcContractData(SolcJsonFile.string());

        if (ContractTest.ContractDataMap.empty()) {
          continue;
        }

        if (std::ifstream File(TestCasesFile); File.is_open()) {
          rapidjson::IStreamWrapper Isw(File);
          rapidjson::Document Doc;
          Doc.ParseStream(Isw);

          if (!Doc.HasParseError()) {
            if (Doc.HasMember("main_contract") &&
                Doc["main_contract"].IsString()) {
              ContractTest.MainContract = Doc["main_contract"].GetString();
            } else {
              ContractTest.MainContract =
                  ContractTest.ContractDataMap.begin()->first;
            }

            if (Doc.HasMember("deploy_contracts") &&
                Doc["deploy_contracts"].IsArray()) {
              const auto &DeployContracts = Doc["deploy_contracts"].GetArray();
              for (const auto &Contract : DeployContracts) {
                if (Contract.IsString()) {
                  ContractTest.DeployContracts.push_back(Contract.GetString());
                }
              }
            } else {
              ContractTest.DeployContracts.push_back(ContractTest.MainContract);
            }

            if (Doc.HasMember("test_cases") && Doc["test_cases"].IsArray()) {
              const auto &TestCases = Doc["test_cases"].GetArray();
              for (const auto &TestCase : TestCases) {
                if (TestCase.HasMember("name") && TestCase["name"].IsString() &&
                    TestCase.HasMember("expected") &&
                    TestCase["expected"].IsString()) {

                  SolidityTestCase Test;
                  Test.Name = TestCase["name"].GetString();
                  Test.Expected = TestCase["expected"].GetString();

                  if (TestCase.HasMember("function") &&
                      TestCase["function"].IsString()) {
                    Test.Function = TestCase["function"].GetString();
                  }

                  if (TestCase.HasMember("calldata") &&
                      TestCase["calldata"].IsString()) {
                    Test.Calldata = TestCase["calldata"].GetString();
                  } else if (!Test.Function.empty()) {
                    std::string FunctionSelector =
                        computeFunctionSelector(Test.Function);
                    if (!FunctionSelector.empty()) {
                      Test.Calldata = FunctionSelector;
                    } else {
                      // Skip test case if we can't compute calldata
                      continue;
                    }
                  } else {
                    // Skip test case if neither calldata nor function provided
                    continue;
                  }

                  if (TestCase.HasMember("contract") &&
                      TestCase["contract"].IsString()) {
                    Test.Contract = TestCase["contract"].GetString();
                  } else {
                    Test.Contract = ContractTest.MainContract;
                  }

                  ContractTest.TestCases.push_back(Test);
                }
              }
            }
          }
          File.close();
        }

        // Validate main contract exists and has required data
        auto MainContractIt =
            ContractTest.ContractDataMap.find(ContractTest.MainContract);
        if (MainContractIt != ContractTest.ContractDataMap.end() &&
            !MainContractIt->second.DeployBytecode.empty() &&
            !MainContractIt->second.RuntimeBytecode.empty() &&
            !ContractTest.TestCases.empty()) {
          Tests.push_back(ContractTest);
        }
      }
    }
  }

  return Tests;
}

} // namespace

class SolidityContractTest
    : public testing::TestWithParam<SolidityContractTestData> {};

TEST_P(SolidityContractTest, ExecuteContractSequence) {
  const auto &ContractTest = GetParam();

  std::string ContractName =
      std::filesystem::path(ContractTest.ContractPath).filename().string();
  if (Debug)
    std::cout << "\n=== Testing contract: " << ContractName
              << " ===" << std::endl;

  RuntimeConfig Config;
  Config.Mode = common::RunMode::InterpMode;
  std::unique_ptr<evmc::Host> Host = std::make_unique<evmc::MockedHost>();
  auto RT = Runtime::newEVMRuntime(Config, Host.get());
  ASSERT_TRUE(RT != nullptr) << "Failed to create runtime";

  uint64_t GasLimit = 100000000UL;
  std::map<std::string, ContractInstance> DeployedContracts;

  // Step 1: Deploy all specified contracts
  for (const std::string &NowContractName : ContractTest.DeployContracts) {
    auto ContractIt = ContractTest.ContractDataMap.find(NowContractName);
    ASSERT_NE(ContractIt, ContractTest.ContractDataMap.end())
        << "Contract not found: " << NowContractName;

    const auto &[ContractAddress, ContractData] = *ContractIt;

    if (Debug)
      std::cout << "Deploying contract: " << NowContractName << std::endl;

    ASSERT_FALSE(ContractData.DeployBytecode.empty())
        << "Deploy bytecode is empty for " << NowContractName;

    auto DeployBytecode = utils::fromHex(ContractData.DeployBytecode);
    ASSERT_TRUE(DeployBytecode) << "Failed to convert deploy hex to bytecode";

    TempHexFile TempDeployFile(ContractTest.ContractPath,
                               "temp_deploy_" + NowContractName,
                               ContractData.DeployBytecode);

    auto DeployModRet = RT->loadEVMModule(TempDeployFile.getPath());
    ASSERT_TRUE(DeployModRet)
        << "Failed to load deploy module for " << NowContractName;

    EVMModule *DeployMod = *DeployModRet;
    Isolation *DeployIso = RT->createManagedIsolation();
    ASSERT_TRUE(DeployIso) << "Failed to create deploy isolation for "
                           << NowContractName;

    auto DeployInstRet = DeployIso->createEVMInstance(*DeployMod, GasLimit);
    ASSERT_TRUE(DeployInstRet)
        << "Failed to create deploy instance for " << NowContractName;

    EVMInstance *DeployInst = *DeployInstRet;
    InterpreterExecContext DeployCtx(DeployInst);
    BaseInterpreter DeployInterpreter(DeployCtx);

    evmc_message Msg = {
        .kind = EVMC_CREATE,
        .flags = 0,
        .depth = 0,
        .gas = (long)GasLimit,
    };
    DeployCtx.allocFrame(&Msg);

    EXPECT_NO_THROW({ DeployInterpreter.interpret(); })
        << "Deploy failed for " << NowContractName;

    const auto &DeployResult = DeployCtx.getReturnData();
    ASSERT_FALSE(DeployResult.empty())
        << "Deploy should return runtime code for " << NowContractName;

    std::string DeployResultHex =
        utils::toHex(DeployResult.data(), DeployResult.size());

    if (Debug) {
      std::cout << "Deploy result hex: " << DeployResultHex << std::endl;
      std::cout << "Expected runtime bytecode: " << ContractData.RuntimeBytecode
                << std::endl;
    }

    ASSERT_TRUE(hexEquals(DeployResultHex, ContractData.RuntimeBytecode))
        << "Deploy result does not match runtime bytecode for "
        << NowContractName;

    TempHexFile TempRuntimeFile(ContractTest.ContractPath,
                                "temp_runtime_" + NowContractName,
                                DeployResultHex);

    auto CallModRet = RT->loadEVMModule(TempRuntimeFile.getPath());
    ASSERT_TRUE(CallModRet)
        << "Failed to load runtime module for " << NowContractName;

    EVMModule *CallMod = *CallModRet;
    Isolation *CallIso = RT->createManagedIsolation();
    ASSERT_TRUE(CallIso) << "Failed to create runtime isolation for "
                         << NowContractName;

    auto CallInstRet = CallIso->createEVMInstance(*CallMod, GasLimit);
    ASSERT_TRUE(CallInstRet)
        << "Failed to create runtime instance for " << NowContractName;

    EVMInstance *CallInst = *CallInstRet;

    DeployedContracts[NowContractName] = {CallInst};

    if (Debug)
      std::cout << "✓ Contract " << NowContractName << " deployed successfully"
                << std::endl;
  }

  // Step 2: Execute all test cases
  for (size_t I = 0; I < ContractTest.TestCases.size(); ++I) {
    const auto &TestCase = ContractTest.TestCases[I];

    if (Debug)
      std::cout << "\n--- Test " << (I + 1) << "/"
                << ContractTest.TestCases.size() << ": " << TestCase.Name
                << " (Contract: " << TestCase.Contract << ") ---" << std::endl;

    auto InstanceIt = DeployedContracts.find(TestCase.Contract);
    ASSERT_NE(InstanceIt, DeployedContracts.end())
        << "Contract instance not found: " << TestCase.Contract;

    const auto &ContractInstance = InstanceIt->second;

    InterpreterExecContext CallCtx(ContractInstance.Instance);

    ASSERT_FALSE(TestCase.Calldata.empty())
        << "Calldata must be provided for test: " << TestCase.Name;

    auto Calldata = utils::fromHex(TestCase.Calldata);

    evmc_message Msg = {
        .kind = EVMC_CALL,
        .flags = 0,
        .depth = 0,
        .gas = (long)GasLimit,
        .input_data = Calldata->data(),
        .input_size = Calldata->size(),
    };
    CallCtx.allocFrame(&Msg);

    BaseInterpreter CallInterpreter(CallCtx);
    EXPECT_NO_THROW({ CallInterpreter.interpret(); })
        << "Function call failed: " << TestCase.Function;

    const auto &CallResult = CallCtx.getReturnData();
    std::string ResultHex = utils::toHex(CallResult.data(), CallResult.size());

    if (Debug) {
      if (!TestCase.Function.empty()) {
        std::cout << "Function: " << TestCase.Function << std::endl;
      }
      std::cout << "Expected: " << TestCase.Expected << std::endl;
      std::cout << "Actual:   " << ResultHex << std::endl;
    }

    EXPECT_TRUE(hexEquals(ResultHex, TestCase.Expected))
        << "Test case failed: " << TestCase.Name
        << (!TestCase.Function.empty() ? "\nFunction: " + TestCase.Function
                                       : "")
        << "\nExpected: " << TestCase.Expected << "\nActual:   " << ResultHex;

    if (!hexEquals(ResultHex, TestCase.Expected)) {
      std::cout << "✗ FAILED" << std::endl;
    }
  }

  if (Debug)
    std::cout << "\n=== Contract " << ContractName << " testing completed ===\n"
              << std::endl;
}

struct SolidityTestNameGenerator {
  std::string operator()(
      const testing::TestParamInfo<SolidityContractTestData> &Info) const {
    const auto &ContractTest = Info.param;
    std::string ContractName =
        std::filesystem::path(ContractTest.ContractPath).filename().string();
    return ContractName;
  }
};

auto SolidityTests = getAllSolidityContractTests();
INSTANTIATE_TEST_SUITE_P(
    SolidityContracts, SolidityContractTest,
    ::testing::ValuesIn(
        SolidityTests.empty()
            ? std::vector<SolidityContractTestData>{{SolidityContractTestData{
                  "dummy_empty_test", {}, {}, "dummy", {}}}}
            : SolidityTests),
    SolidityTestNameGenerator{});
