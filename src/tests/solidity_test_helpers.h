// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_TESTS_SOLIDITY_TEST_HELPERS_H
#define ZEN_TESTS_SOLIDITY_TEST_HELPERS_H

#include "evm_test_helpers.h"
#include "evm_test_host.hpp"
#include "host/evm/crypto.h"
#include "zetaengine.h"
#include <rapidjson/istreamwrapper.h>

using namespace zen::common;

namespace zen::evm_test_utils {

// test_cases.json, single case in field "test_cases"
struct SolidityTestCase {
  std::string Name;
  std::string Function;
  std::string Expected;
  std::string Contract;
  std::string Calldata;
};

// contract.json structures
struct SolcContractData {
  std::string DeployBytecode;  // "bin"
  std::string RuntimeBytecode; // "bin-runtime"
};

// test_cases.json structures
struct SolidityContractTestData {
  std::string ContractPath;
  std::vector<SolidityTestCase> TestCases; // "test_cases"
  std::map<std::string, SolcContractData>
      ContractDataMap;                      // solc.json "contracts"
  std::string MainContract;                 // "main_contract"
  std::vector<std::string> DeployContracts; // "deploy_contracts"
  std::map<std::string, std::vector<std::pair<std::string, std::string>>>
      ConstructorArgs; // "constructor_args"
};

// Utility functions
inline std::string computeFunctionSelector(const std::string &FunctionSig) {
  const std::vector<uint8_t> InputBytes(FunctionSig.begin(), FunctionSig.end());
  const std::vector<uint8_t> Hash =
      zen::host::evm::crypto::keccak256(InputBytes);
  if (Hash.size() >= 4) {
    return zen::utils::toHex(Hash.data(), 4);
  }
  return "";
}

// ABI encoding structures and functions
struct AbiEncoded {
  std::string StaticPart;
  std::string DynamicPart;
};

inline AbiEncoded
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

inline std::string encodeAbiOffset(uint64_t Offset) {
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

inline std::string encodeConstructorParams(
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

// Library contract utilities
inline bool isLibraryBytecode(const std::string &Hex) {
  // Library contract placeholder feature: The first 42 characters are "73"
  // followed by 40 zeros (20 bytes all zeros)
  return Hex.size() >= 42 && Hex.substr(0, 2) == "73" // PUSH20 opcode
         && Hex.substr(2, 40) == std::string(40, '0');
}

inline std::string replaceLibraryPlaceholder(const std::string &ExpectedHex,
                                             const std::string &ActualHex) {
  if (ExpectedHex.size() < 42 || ActualHex.size() < 42) {
    return ExpectedHex; // Insufficient length, no processing
  }
  std::string ActualAddress = ActualHex.substr(2, 40);
  return "73" + ActualAddress + ExpectedHex.substr(42);
}

// Runtime management structures and functions
struct EVMTestEnvironment {
  std::unique_ptr<zen::runtime::Runtime> Runtime;
  std::unique_ptr<evmc::MockedHost> TempMockedHost;
  std::unique_ptr<zen::evm::ZenMockedEVMHost> Host;
  zen::evm::ZenMockedEVMHost *MockedHost;
  evmc::address DeployerAddr;

  EVMTestEnvironment(const zen::runtime::RuntimeConfig &Config);
  ~EVMTestEnvironment();
};

struct DeployedContract {
  zen::runtime::EVMInstance *Instance;
  evmc::address Address;
  std::string RuntimeBytecode;
};

DeployedContract deployContract(
    EVMTestEnvironment &Env, const std::string &ContractName,
    const SolcContractData &ContractData,
    const std::vector<std::pair<std::string, std::string>> &ConstructorArgs,
    const std::map<std::string, evmc::address> &DeployedAddresses,
    uint64_t GasLimit);

// Test execution helper functions
evmc::Result executeContractCall(EVMTestEnvironment &Env,
                                 const DeployedContract &Contract,
                                 const std::string &Calldata,
                                 uint64_t GasLimit);

evmc_status_code checkResult(const SolidityTestCase &Case,
                             const evmc::Result &Result);

// JSON parsing helper functions
void parseTestCasesFromJson(const rapidjson::Document &Doc,
                            SolidityContractTestData &ContractTest);

void parseConstructorArgsFromJson(
    const rapidjson::Document &Doc,
    std::map<std::string, std::vector<std::pair<std::string, std::string>>>
        &ConstructorArgs);

void parseTestCaseJson(const std::filesystem::path &TestCaseFile,
                       SolidityContractTestData &ContractTest);

void parseContractJson(
    const std::filesystem::path &SolcJsonFile,
    std::map<std::string, SolcContractData> &ContractDataMap);

struct ContractDirectoryInfo {
  std::string FolderName;
  std::filesystem::path SolcJsonFile;
  std::filesystem::path CasesFile;
};

ContractDirectoryInfo checkCaseDirectory(const std::filesystem::path &DirPath);

evmc_status_code
executeSingleContractTest(const zen::runtime::RuntimeConfig &Config,
                          uint64_t GasLimit, const std::string &TestCategory,
                          const std::string &TestContract);

} // namespace zen::evm_test_utils

#endif // ZEN_TESTS_SOLIDITY_TEST_HELPERS_H
