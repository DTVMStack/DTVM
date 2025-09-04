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
#include "evm_test_host.hpp"
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
  evmc::address Address;
};

struct SolidityContractTestData {
  std::string ContractPath;
  std::vector<SolidityTestCase> TestCases;
  std::map<std::string, SolcContractData> ContractDataMap;
  std::string MainContract;
  std::vector<std::string> DeployContracts;

  // ConstructorArgs: contract_name -> [("reserved/unused", json_params), ...]
  // Stores constructor arguments for smart contracts.
  std::map<std::string, std::vector<std::pair<std::string, std::string>>>
      ConstructorArgs;
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
            // Parse the constructor_args and store it in the structure
            if (Doc.HasMember("constructor_args") &&
                Doc["constructor_args"].IsObject()) {
              for (const auto &Entry : Doc["constructor_args"].GetObject()) {
                std::string ContractName = Entry.name.GetString();
                if (!Entry.value.IsArray())
                  continue;
                std::vector<std::pair<std::string, std::string>> Args;
                for (const auto &Arg : Entry.value.GetArray()) {
                  if (Arg.HasMember("type") && Arg["type"].IsString() &&
                      Arg.HasMember("value") && Arg["value"].IsString()) {
                    Args.emplace_back(Arg["type"].GetString(),
                                      Arg["value"].GetString());
                  }
                }
                ContractTest.ConstructorArgs[ContractName] = Args;
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

struct AbiEncoded {
  std::string StaticPart;
  std::string DynamicPart;
};

static std::string decimalToHex(const std::string &DecimalStr) {
  std::string TrimmedStr = DecimalStr;
  zen::utils::trimString(TrimmedStr);
  if (TrimmedStr.empty() || TrimmedStr == "0") {
    return "0";
  }
  if (TrimmedStr[0] == '-') {
    ZEN_LOG_ERROR("Negative values are not supported. Value: {}",
                  DecimalStr.c_str());
    return "0";
  }
  for (char C : TrimmedStr) {
    if (!std::isdigit(C)) {
      ZEN_LOG_ERROR(
          "Invalid decimal string (contains non-digit characters). Value: {}",
          DecimalStr.c_str());
      return "0";
    }
  }
  uint64_t Value;
  try {
    Value = std::stoull(TrimmedStr);
  } catch (const std::out_of_range &E) {
    ZEN_LOG_ERROR("Value exceeds uint64_t range. Value: {}",
                  DecimalStr.c_str());
    return "0";
  } catch (const std::invalid_argument &E) {
    ZEN_LOG_ERROR("Invalid decimal string (parsing failed). Value: {}",
                  DecimalStr.c_str());
    return "0";
  }
  std::stringstream S;
  S << std::uppercase << std::hex << Value;
  std::string HexStr = S.str();
  if (HexStr.size() > 64) {
    ZEN_LOG_ERROR(
        "Hex value exceeds 64 characters (uint256 max). Length: {}, Value: {}",
        HexStr.size(), HexStr.c_str());
    HexStr = HexStr.substr(HexStr.size() - 64);
  }
  if (HexStr.size() % 2 != 0) {
    HexStr = "0" + HexStr;
  }
  return HexStr;
}
static std::string paddingLeft(const std::string &Input, size_t TargetLength,
                               char PadChar) {
  if (Input.size() >= TargetLength) {
    return Input;
  }
  return std::string(TargetLength - Input.size(), PadChar) + Input;
}
static std::string padAddressTo32Bytes(const evmc::address &Addr) {
  return "000000000000000000000000" + zen::utils::toHex(Addr.bytes, 20);
}
// Encode the parameters into the Solidity ABI format
//
// @param Type  The Solidity type of the parameter. Supported values include:
//              - "address": Ethereum address (20-byte value)
//              - "uint256": 256-bit unsigned integer
//              - "int256": 256-bit signed integer
//              - "bool": Boolean value (true/false)
//              - "string": UTF-8 string
AbiEncoded
encodeAbiParam(const std::string &Type, const std::string &Value,
               const std::map<std::string, evmc::address> &DeployedAddrs) {

  if (Type == "address") {
    std::string Encoded;
    auto It = DeployedAddrs.find(Value);
    if (It != DeployedAddrs.end()) {
      Encoded = padAddressTo32Bytes(It->second);
    } else {
      std::string AddrHex =
          (Value.substr(0, 2) == "0x" || Value.substr(0, 2) == "0X")
              ? Value.substr(2)
              : Value;
      if (AddrHex.size() < 40) {
        AddrHex = paddingLeft(AddrHex, 40, '0');
      }
      Encoded = "000000000000000000000000" + AddrHex;
    }
    return {Encoded, ""};
  }
  if (Type.substr(0, 4) == "uint") {
    std::string HexValue;
    if (Value.substr(0, 2) == "0x" || Value.substr(0, 2) == "0X") {
      HexValue = Value.substr(2);
    } else {
      HexValue = decimalToHex(Value);
    }
    size_t FirstNonZero = HexValue.find_first_not_of('0');
    if (FirstNonZero != std::string::npos) {
      HexValue = HexValue.substr(FirstNonZero);
    } else {
      HexValue = "0";
    }
    if (HexValue.size() > 64) {
      ZEN_LOG_ERROR("Hex value exceeds 64 characters (uint256 max). Length: "
                    "{}, Value: {}",
                    HexValue.size(), HexValue.c_str());
    }
    std::string Encoded = paddingLeft(HexValue, 64, '0');
    return {Encoded, ""};
  }
  if (Type == "string") {
    std::string LenStr = std::to_string(Value.size());
    AbiEncoded LenEncoded = encodeAbiParam("uint256", LenStr, DeployedAddrs);
    std::string EncodedData = zen::utils::toHex(
        reinterpret_cast<const uint8_t *>(Value.data()), Value.size());
    std::string DynamicPart = LenEncoded.StaticPart + EncodedData;
    std::string StaticPart(64, '0');
    return {StaticPart, DynamicPart};
  }
  // TODO: Unimplemented ABI types: bool, bytes, arrays, nested dynamic types,
  // etc.
  ZEN_ASSERT_TODO();
  return {"", ""};
}
std::string encodeAbiOffset(uint64_t Offset) {
  uint8_t OffsetBytes[8] = {0};
  for (int I = 7; I >= 0; --I) {
    OffsetBytes[I] = static_cast<uint8_t>(Offset & 0xFF);
    Offset >>= 8;
  }
  std::string HexStr = zen::utils::toHex(OffsetBytes, 8);
  if (HexStr.size() < 64) {
    HexStr = paddingLeft(HexStr, 64, '0');
  }
  std::transform(HexStr.begin(), HexStr.end(), HexStr.begin(), ::tolower);
  return HexStr;
}
std::string encodeConstructorParams(
    const std::vector<std::pair<std::string, std::string>> &CtorArgs,
    const std::map<std::string, evmc::address> &DeployedAddrs) {
  std::vector<AbiEncoded> EncodedParams;
  for (size_t I = 0; I < CtorArgs.size(); ++I) {
    const auto &[Type, Value] = CtorArgs[I];
    EncodedParams.push_back(encodeAbiParam(Type, Value, DeployedAddrs));
  }
  std::string StaticData;
  std::string DynamicData;
  for (size_t I = 0; I < EncodedParams.size(); ++I) {
    StaticData += EncodedParams[I].StaticPart;
    DynamicData += EncodedParams[I].DynamicPart;
  }

  size_t StaticTotalBytes = StaticData.size() / 2;
  size_t CurrentOffset = StaticTotalBytes;

  std::string FinalStaticData = StaticData;
  size_t Pos = 0;
  for (size_t I = 0; I < EncodedParams.size(); ++I) {
    const auto &Enc = EncodedParams[I];
    size_t ParamStaticLen = Enc.StaticPart.size();

    if (!Enc.DynamicPart.empty()) {
      std::string OffsetHex = encodeAbiOffset(CurrentOffset);
      FinalStaticData.replace(Pos, ParamStaticLen, OffsetHex);
      CurrentOffset += Enc.DynamicPart.size() / 2;
    }
    Pos += ParamStaticLen;
  }
  return FinalStaticData + DynamicData;
}
// Detect whether it is the bytecode of a library contract (starting with 20
// consecutive zeros after the byte 73)
bool isLibraryBytecode(const std::string &Hex) {
  // Library contract placeholder feature: The first 42 characters are "73"
  // followed by 40 zeros (20 bytes all zeros)
  return Hex.size() >= 42 && Hex.substr(0, 2) == "73" // PUSH20 opcode
         && Hex.substr(2, 40) == std::string(40, '0');
}

// Tool function: Replace placeholders in the library contract with actual
// addresses
std::string replaceLibraryPlaceholder(const std::string &ExpectedHex,
                                      const std::string &ActualHex) {
  if (ExpectedHex.size() < 42 || ActualHex.size() < 42) {
    return ExpectedHex; // Insufficient length, no processing
  }
  std::string ActualAddress = ActualHex.substr(2, 40);
  return "73" + ActualAddress + ExpectedHex.substr(42);
}

} // namespace

class SolidityContractTest
    : public testing::TestWithParam<SolidityContractTestData> {
protected:
  static void SetUpTestCase() {
    auto logger = zen::utils::createConsoleLogger(
        "evm_solidity_test_logger", zen::utils::LoggerLevel::Debug);
    zen::setGlobalLogger(logger);
  }
};

TEST_P(SolidityContractTest, ExecuteContractSequence) {
  const auto &ContractTest = GetParam();

  std::string ContractName =
      std::filesystem::path(ContractTest.ContractPath).filename().string();
  if (Debug)
    std::cout << "\n=== Testing contract: " << ContractName
              << " ===" << std::endl;

  RuntimeConfig Config;
  Config.Mode = common::RunMode::InterpMode;
  // Create temporary MockedHost first for Runtime creation
  auto TempMockedHost = std::make_unique<evmc::MockedHost>();
  auto RT = Runtime::newEVMRuntime(Config, TempMockedHost.get());
  ASSERT_TRUE(RT != nullptr) << "Failed to create runtime";

  // Create Isolation for recursive host
  Isolation *IsoForRecursive = RT->createManagedIsolation();
  ASSERT_TRUE(IsoForRecursive != nullptr)
      << "Failed to create Isolation for recursive host";
  // Now create ZenMockedEVMHost with Runtime and Isolation references
  auto HostPtr = std::make_unique<ZenMockedEVMHost>(RT.get(), IsoForRecursive);
  ZenMockedEVMHost *MockedHost = HostPtr.get();

  // Copy accounts and context from temporary host
  MockedHost->accounts = TempMockedHost->accounts;
  MockedHost->tx_context = TempMockedHost->tx_context;

  // Switch to using ZenMockedEVMHost
  std::unique_ptr<evmc::Host> Host = std::move(HostPtr);

  uint8_t DeployerBytes[20] = {0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  evmc::address DeployerAddr;
  std::copy(std::begin(DeployerBytes), std::end(DeployerBytes),
            DeployerAddr.bytes);
  auto &DeployerAccount = MockedHost->accounts[DeployerAddr];
  DeployerAccount.nonce = 0;
  DeployerAccount.set_balance(100000000UL);

  uint64_t GasLimit = 100000000UL;
  std::map<std::string, ContractInstance> DeployedContracts;

  // Step 1: Deploy all specified contracts
  std::map<std::string, evmc::address> DeployedAddresses;
  for (const std::string &NowContractName : ContractTest.DeployContracts) {
    auto ContractIt = ContractTest.ContractDataMap.find(NowContractName);
    ASSERT_NE(ContractIt, ContractTest.ContractDataMap.end())
        << "Contract not found: " << NowContractName;

    const auto &[ContractAddress, ContractData] = *ContractIt;

    std::vector<std::pair<std::string, std::string>> Ctorargs;
    auto ArgsIt = ContractTest.ConstructorArgs.find(NowContractName);
    if (ArgsIt != ContractTest.ConstructorArgs.end()) {
      Ctorargs = ArgsIt->second;
    }

    // Concatenation of deployed bytecode + constructor parameters
    std::string DeployHex =
        ContractData.DeployBytecode +
        encodeConstructorParams(Ctorargs, DeployedAddresses);

    if (Debug)
      std::cout << "Deploying contract: " << NowContractName << std::endl;

    ASSERT_FALSE(ContractData.DeployBytecode.empty())
        << "Deploy bytecode is empty for " << NowContractName;

    auto DeployBytecode = utils::fromHex(DeployHex);
    ASSERT_TRUE(DeployBytecode) << "Failed to convert deploy hex to bytecode";

    TempHexFile TempDeployFile(ContractTest.ContractPath,
                               "temp_deploy_" + NowContractName, DeployHex);

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

    evmc::address NewContractAddr =
        MockedHost->computeCreateAddress(DeployerAddr, DeployerAccount.nonce);

    evmc_message Msg = {
        .kind = EVMC_CREATE,
        .flags = 0,
        .depth = 0,
        .gas = (long)GasLimit,
        .recipient = NewContractAddr,
        .sender = DeployerAddr,
    };
    DeployCtx.allocFrame(&Msg);
    // Set the host for the execution frame
    auto *Frame = DeployCtx.getCurFrame();
    Frame->Host = MockedHost;

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
    std::string AdjustedRuntimeBytecode = ContractData.RuntimeBytecode;
    if (isLibraryBytecode(AdjustedRuntimeBytecode)) {
      AdjustedRuntimeBytecode =
          replaceLibraryPlaceholder(AdjustedRuntimeBytecode, DeployResultHex);
    }
    ASSERT_TRUE(hexEquals(DeployResultHex, AdjustedRuntimeBytecode))
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

    DeployedContracts[NowContractName] = {CallInst, NewContractAddr};
    auto &NewContractAccount = MockedHost->accounts[NewContractAddr];
    NewContractAccount.code =
        std::basic_string<uint8_t, evmc::byte_traits<uint8_t>>(
            DeployResult.begin(), DeployResult.end());

    const std::vector<uint8_t> CodeHashVec =
        host::evm::crypto::keccak256(DeployResult);
    assert(CodeHashVec.size() == 32 && "Keccak256 hash must be 32 bytes");
    evmc::bytes32 CodeHash;
    std::memcpy(CodeHash.bytes, CodeHashVec.data(), 32);
    NewContractAccount.codehash = CodeHash;
    NewContractAccount.nonce = 1;
    DeployerAccount.nonce += 1;
    DeployedAddresses[NowContractName] = NewContractAddr;

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
        .recipient = ContractInstance.Address,
        .sender = DeployerAddr,
        .input_data = Calldata->data(),
        .input_size = Calldata->size(),
    };
    CallCtx.allocFrame(&Msg);
    // Set the host for the execution frame
    auto *Frame = CallCtx.getCurFrame();
    Frame->Host = MockedHost;

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
                  "dummy_empty_test", {}, {}, "dummy", {}, {}}}}
            : SolidityTests),
    SolidityTestNameGenerator{});
