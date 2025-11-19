// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "solidity_test_helpers.h"
#include "common/errors.h"
#include <iostream>

using namespace zen::common;
using namespace zen::runtime;

namespace zen::evm_test_utils {

EVMTestEnvironment::EVMTestEnvironment(const RuntimeConfig &Config) {
  TempMockedHost = std::make_unique<evmc::MockedHost>();
  Runtime = Runtime::newEVMRuntime(Config, TempMockedHost.get());

  Host = std::make_unique<zen::evm::ZenMockedEVMHost>();
  Host->setRuntime(Runtime.get());
  MockedHost = Host.get();

  MockedHost->accounts = TempMockedHost->accounts;
  MockedHost->tx_context = TempMockedHost->tx_context;
  Runtime->setEVMHost(MockedHost);

  // Set up deployer account
  uint8_t DeployerBytes[20] = {0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  std::copy(std::begin(DeployerBytes), std::end(DeployerBytes),
            DeployerAddr.bytes);
  auto &DeployerAccount = MockedHost->accounts[DeployerAddr];
  DeployerAccount.nonce = 0;
  DeployerAccount.set_balance(100000000UL);
}

EVMTestEnvironment::~EVMTestEnvironment() {
  // Cleanup is handled by unique_ptr destructors
}

DeployedContract deployContract(
    EVMTestEnvironment &Env, const std::string &ContractName,
    const SolcContractData &ContractData,
    const std::vector<std::pair<std::string, std::string>> &ConstructorArgs,
    const std::map<std::string, evmc::address> &DeployedAddresses,
    uint64_t GasLimit) {
  // Concatenation of deployed bytecode + constructor parameters
  std::string DeployHex =
      ContractData.DeployBytecode +
      encodeConstructorParams(ConstructorArgs, DeployedAddresses);

  if (ContractData.DeployBytecode.empty()) {
    throw getError(ErrorCode::InvalidRawData);
  }

  auto DeployBytecode = zen::utils::fromHex(DeployHex);
  if (!DeployBytecode.has_value()) {
    throw getError(ErrorCode::InvalidRawData);
  }

  // Create temporary file for deployment
  TempHexFile TempDeployFile(DeployHex);

  auto DeployModRet = Env.Runtime->loadEVMModule(TempDeployFile.getPath());
  if (!DeployModRet) {
    const Error &Err = DeployModRet.getError();
    ZEN_ASSERT(!Err.isEmpty());
    const auto &ErrMsg = Err.getFormattedMessage(false);
    throw std::runtime_error("Failed to load EVM module: " + ErrMsg);
  }

  EVMModule *DeployMod = *DeployModRet;
  Isolation *DeployIso = Env.Runtime->createManagedIsolation();
  if (!DeployIso) {
    throw std::runtime_error("Failed to create deploy isolation for " +
                             ContractName);
  }

  auto DeployInstRet = DeployIso->createEVMInstance(*DeployMod, GasLimit);
  if (!DeployInstRet) {
    throw std::runtime_error("Failed to create deploy instance for " +
                             ContractName);
  }

  EVMInstance *DeployInst = *DeployInstRet;

  evmc::address NewContractAddr = Env.MockedHost->computeCreateAddress(
      Env.DeployerAddr, Env.MockedHost->accounts[Env.DeployerAddr].nonce);

  evmc_message Msg = {};
  Msg.kind = EVMC_CREATE;
  Msg.gas = static_cast<int64_t>(GasLimit);
  Msg.recipient = NewContractAddr;
  Msg.sender = Env.DeployerAddr;

  evmc::Result DeployResult;
  Env.Runtime->callEVMMain(*DeployInst, Msg, DeployResult);

  if (DeployResult.status_code != EVMC_SUCCESS) {
    throw std::runtime_error(
        "Deploy failed for " + ContractName +
        " with status: " + std::to_string(DeployResult.status_code));
  }

  if (DeployResult.output_size == 0) {
    throw std::runtime_error("Deploy should return runtime code for " +
                             ContractName);
  }

  std::vector<uint8_t> DeployResultBytes(DeployResult.output_data,
                                         DeployResult.output_data +
                                             DeployResult.output_size);
  std::string DeployResultHex =
      zen::utils::toHex(DeployResultBytes.data(), DeployResultBytes.size());

  // Verify deployment result
  std::string AdjustedRuntimeBytecode = ContractData.RuntimeBytecode;
  if (isLibraryBytecode(AdjustedRuntimeBytecode)) {
    AdjustedRuntimeBytecode =
        replaceLibraryPlaceholder(AdjustedRuntimeBytecode, DeployResultHex);
  }

  if (!hexEquals(DeployResultHex, AdjustedRuntimeBytecode)) {
    throw std::runtime_error(
        "Deploy result does not match runtime bytecode for " + ContractName);
  }

  // Create runtime instance
  TempHexFile TempRuntimeFile(DeployResultHex);

  auto CallModRet = Env.Runtime->loadEVMModule(TempRuntimeFile.getPath());
  if (!CallModRet) {
    throw std::runtime_error("Failed to load runtime module for " +
                             ContractName);
  }

  EVMModule *CallMod = *CallModRet;
  Isolation *CallIso = Env.Runtime->createManagedIsolation();
  if (!CallIso) {
    throw std::runtime_error("Failed to create runtime isolation for " +
                             ContractName);
  }

  auto CallInstRet = CallIso->createEVMInstance(*CallMod, GasLimit);
  if (!CallInstRet) {
    throw std::runtime_error("Failed to create runtime instance for " +
                             ContractName);
  }

  EVMInstance *CallInst = *CallInstRet;

  // Store deployed contract
  auto &NewContractAccount = Env.MockedHost->accounts[NewContractAddr];
  NewContractAccount.code =
      std::basic_string<uint8_t, evmc::byte_traits<uint8_t>>(
          DeployResultBytes.begin(), DeployResultBytes.end());

  const std::vector<uint8_t> CodeHashVec =
      zen::host::evm::crypto::keccak256(DeployResultBytes);
  evmc::bytes32 CodeHash;
  std::memcpy(CodeHash.bytes, CodeHashVec.data(), 32);
  NewContractAccount.codehash = CodeHash;
  NewContractAccount.nonce = 1;
  Env.MockedHost->accounts[Env.DeployerAddr].nonce += 1;

  std::cout << "✓ Contract " << ContractName << " deployed successfully"
            << std::endl;

  DeployedContract Result;
  Result.Instance = CallInst;
  Result.Address = NewContractAddr;
  Result.RuntimeBytecode = DeployResultHex;
  return Result;
}

// Test execution helper functions
evmc::Result executeContractCall(EVMTestEnvironment &Env,
                                 const DeployedContract &Contract,
                                 const std::string &Calldata,
                                 uint64_t GasLimit) {
  auto CalldataBytes = zen::utils::fromHex(Calldata);
  if (!CalldataBytes.has_value()) {
    throw getError(ErrorCode::InvalidRawData);
  }
  std::vector<uint8_t> CalldataVec = *CalldataBytes;

  evmc_message Msg = {};
  Msg.kind = EVMC_CALL;
  Msg.gas = static_cast<int64_t>(GasLimit);
  Msg.recipient = Contract.Address;
  Msg.sender = Env.DeployerAddr;
  Msg.input_data = CalldataVec.data();
  Msg.input_size = CalldataVec.size();

  evmc::Result Result;
  Env.Runtime->callEVMMain(*Contract.Instance, Msg, Result);
  return Result;
}

evmc_status_code checkResult(const SolidityTestCase &Case,
                             const evmc::Result &Result) {
  if (Result.status_code != EVMC_SUCCESS) {
    return Result.status_code;
  }

  std::string ResultHex;
  if (Result.output_data && Result.output_size > 0) {
    ResultHex = zen::utils::toHex(Result.output_data, Result.output_size);
  }

  if (!hexEquals(ResultHex, Case.Expected)) {
    std::cerr << "Case failed: " << Case.Name << std::endl;
    std::cerr << "Function: " << Case.Function << std::endl;
    std::cerr << "Expected: " << Case.Expected << std::endl;
    std::cerr << "Actual:   " << ResultHex << std::endl;
    return EVMC_FAILURE;
  }

  return EVMC_SUCCESS;
}

void parseTestCasesFromJson(const rapidjson::Document &Doc,
                            SolidityContractTestData &ContractTest) {
  if (!Doc.HasMember("test_cases") || !Doc["test_cases"].IsArray()) {
    return;
  }

  const auto &TestCases = Doc["test_cases"].GetArray();
  for (const auto &TestCase : TestCases) {
    SolidityTestCase Test;
    if (!TestCase.HasMember("name") || !TestCase["name"].IsString() ||
        !TestCase.HasMember("expected") || !TestCase["expected"].IsString()) {
      continue;
    }
    Test.Name = TestCase["name"].GetString();
    Test.Expected = TestCase["expected"].GetString();

    if (TestCase.HasMember("function") && TestCase["function"].IsString()) {
      Test.Function = TestCase["function"].GetString();
    }

    if (TestCase.HasMember("calldata") && TestCase["calldata"].IsString()) {
      Test.Calldata = TestCase["calldata"].GetString();
    } else if (!Test.Function.empty()) {
      std::string FunctionSelector = computeFunctionSelector(Test.Function);
      if (!FunctionSelector.empty()) {
        Test.Calldata = FunctionSelector;
      } else {
        // Skip test case if can't compute calldata
        continue;
      }
    } else {
      // Skip test case if neither calldata nor function provided
      continue;
    }

    if (TestCase.HasMember("contract") && TestCase["contract"].IsString()) {
      Test.Contract = TestCase["contract"].GetString();
    } else {
      Test.Contract = ContractTest.MainContract;
    }
    ContractTest.TestCases.push_back(Test);
  }
}

void parseConstructorArgsFromJson(
    const rapidjson::Document &Doc,
    std::map<std::string, std::vector<std::pair<std::string, std::string>>>
        &ConstructorArgs) {
  if (!Doc.HasMember("constructor_args") ||
      !Doc["constructor_args"].IsObject()) {
    return;
  }

  const auto &ConstructorArgsJson = Doc["constructor_args"].GetObject();
  for (const auto &ArgEntry : ConstructorArgsJson) {
    std::string ContractName = ArgEntry.name.GetString();
    if (!ArgEntry.value.IsArray()) {
      continue;
    }

    std::vector<std::pair<std::string, std::string>> Args;
    for (const auto &Arg : ArgEntry.value.GetArray()) {
      if (Arg.HasMember("type") && Arg["type"].IsString() &&
          Arg.HasMember("value") && Arg["value"].IsString()) {
        Args.emplace_back(Arg["type"].GetString(), Arg["value"].GetString());
      }
    }
    ConstructorArgs[ContractName] = Args;
  }
}

void parseTestCaseJson(const std::filesystem::path &TestCaseFile,
                       SolidityContractTestData &ContractTest) {
  std::ifstream File(TestCaseFile);
  if (!File.is_open()) {
    throw getError(ErrorCode::FileAccessFailed);
  }

  rapidjson::IStreamWrapper Isw(File);
  rapidjson::Document Doc;
  Doc.ParseStream(Isw);

  if (Doc.HasParseError() || !Doc.IsObject()) {
    throw getError(ErrorCode::FileAccessFailed);
  }

  if (Doc.HasMember("skip") && Doc["skip"].IsBool() && Doc["skip"].GetBool()) {
    return;
  }

  if (Doc.HasMember("main_contract") && Doc["main_contract"].IsString()) {
    ContractTest.MainContract = Doc["main_contract"].GetString();
  } else if (!ContractTest.ContractDataMap.empty()) {
    ContractTest.MainContract = ContractTest.ContractDataMap.begin()->first;
  }

  if (Doc.HasMember("deploy_contracts") && Doc["deploy_contracts"].IsArray()) {
    const auto &Contracts = Doc["deploy_contracts"].GetArray();
    for (const auto &Contract : Contracts) {
      if (Contract.IsString()) {
        ContractTest.DeployContracts.push_back(Contract.GetString());
      }
    }
  } else {
    ContractTest.DeployContracts.push_back(ContractTest.MainContract);
  }

  parseTestCasesFromJson(Doc, ContractTest);

  parseConstructorArgsFromJson(Doc, ContractTest.ConstructorArgs);

  File.close();
}

void parseContractJson(
    const std::filesystem::path &SolcJsonFile,
    std::map<std::string, SolcContractData> &ContractDataMap) {
  std::ifstream File(SolcJsonFile);
  if (!File.is_open()) {
    throw getError(ErrorCode::FileAccessFailed);
  }

  rapidjson::IStreamWrapper Isw(File);
  rapidjson::Document Doc;
  Doc.ParseStream(Isw);
  if (Doc.HasParseError() || !Doc.HasMember("contracts") ||
      !Doc["contracts"].IsObject()) {
    throw getError(ErrorCode::InvalidRawData);
  }

  const auto &Contracts = Doc["contracts"].GetObject();
  if (Contracts.MemberCount() == 0) {
    return;
  }

  for (const auto &ContractEntry : Contracts) {
    std::string ContractFullName = ContractEntry.name.GetString();
    const auto &ContractInfo = ContractEntry.value;

    std::string ContractName = ContractFullName;
    if (size_t ColonPos = ContractFullName.find(':');
        ContractFullName.find(':') != std::string::npos) {
      ContractName = ContractFullName.substr(ColonPos + 1);
    }

    if (ContractInfo.HasMember("bin") && ContractInfo["bin"].IsString()) {
      ContractDataMap[ContractName].DeployBytecode =
          ContractInfo["bin"].GetString();
    }

    if (ContractInfo.HasMember("bin-runtime") &&
        ContractInfo["bin-runtime"].IsString()) {
      ContractDataMap[ContractName].RuntimeBytecode =
          ContractInfo["bin-runtime"].GetString();
    }
  }
  File.close();
}

ContractDirectoryInfo checkCaseDirectory(const std::filesystem::path &DirInfo) {
  ContractDirectoryInfo Info;
  std::filesystem::path CleanDirInfo = DirInfo;
  if (!DirInfo.empty() && DirInfo.string().back() == '/') {
    CleanDirInfo = DirInfo.parent_path();
  }
  Info.FolderName = CleanDirInfo.filename().string();
  Info.CasesFile = DirInfo / "test_cases.json";
  Info.SolcJsonFile = DirInfo / (Info.FolderName + ".json");

  if (!std::filesystem::exists(Info.CasesFile) ||
      !std::filesystem::exists(Info.SolcJsonFile)) {
    std::cerr << "Missing test_cases.json or " << Info.FolderName
              << ".json in directory: " << DirInfo.string() << std::endl;
  }

  return Info;
}

} // namespace zen::evm_test_utils
