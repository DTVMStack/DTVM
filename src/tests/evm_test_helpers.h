// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_TESTS_EVM_TEST_HELPERS_H
#define ZEN_TESTS_EVM_TEST_HELPERS_H

#include "evmc/evmc.hpp"
#include "evmc/mocked_host.hpp"
#include "utils/rlp_encoding.h"

#include "utils/evm.h"
#include "utils/logging.h"
#include <filesystem>
#include <fstream>
#include <rapidjson/document.h>
#include <string>

namespace zen::evm_test_utils {

class TempHexFile {
private:
  std::string FilePath;
  bool Valid = false;

public:
  explicit TempHexFile(const std::string &HexCode) {
    if (HexCode.empty() || HexCode == "0x") {
      return;
    }

    auto TempDir = std::filesystem::temp_directory_path();
    do {
      int RandomNum = std::rand() % 1000000;
      std::string FileName = "dtvm_" + std::to_string(RandomNum) + ".hex";
      FilePath = TempDir / FileName;
    } while (std::filesystem::exists(FilePath));

    std::string CleanHex = HexCode;
    if (CleanHex.size() >= 2 && CleanHex.substr(0, 2) == "0x") {
      CleanHex = CleanHex.substr(2);
    }

    std::ofstream File(FilePath);
    if (!File) {
      throw std::runtime_error("Failed to create temp file: " + FilePath);
    }
    File << CleanHex;
    File.close();
    Valid = true;
  }

  TempHexFile(const std::string &BasePath, const std::string &Suffix,
              const std::string &Content) {
    if (Content.empty()) {
      return;
    }

    FilePath = BasePath + "/" + Suffix + ".hex";

    std::ofstream File(FilePath);
    if (!File) {
      throw std::runtime_error("Failed to create temp file: " + FilePath);
    }
    File << Content;
    File.close();
    Valid = true;
  }

  ~TempHexFile() {
    if (Valid && !FilePath.empty()) {
      std::filesystem::remove(FilePath);
    }
  }

  TempHexFile(const TempHexFile &) = delete;
  TempHexFile &operator=(const TempHexFile &) = delete;

  TempHexFile(TempHexFile &&Other) noexcept
      : FilePath(std::move(Other.FilePath)), Valid(Other.Valid) {
    Other.Valid = false;
  }

  TempHexFile &operator=(TempHexFile &&Other) noexcept {
    if (this != &Other) {
      if (Valid && !FilePath.empty()) {
        std::filesystem::remove(FilePath);
      }
      FilePath = std::move(Other.FilePath);
      Valid = Other.Valid;
      Other.Valid = false;
    }
    return *this;
  }

  bool isValid() const { return Valid; }
  const std::string &getPath() const { return FilePath; }
};

void addAccountToMockedHost(evmc::MockedHost &Host, const evmc::address &Addr,
                            const evmc::MockedAccount &Account);

std::string
calculateLogsHash(const std::vector<evmc::MockedHost::log_record> &Logs);

bool verifyLogsHash(const std::vector<evmc::MockedHost::log_record> &Logs,
                    const std::string &ExpectedHash);

std::string calculateStateRootHash(evmc::MockedHost &Host);
bool verifyStateRoot(evmc::MockedHost &Host, const std::string &ExpectedHash);

std::vector<std::string> verifyPostState(evmc::MockedHost &Host,
                                         const rapidjson::Value &ExpectedState,
                                         const std::string &TestName,
                                         const std::string &Fork);

evmc_revision mapForkToRevision(const std::string &Fork);

inline std::string toLowerHex(const std::string &Hex) {
  std::string Result = Hex;
  for (char &C : Result) {
    C = std::tolower(static_cast<unsigned char>(C));
  }
  return Result;
}

inline bool hexEquals(const std::string &Hex1, const std::string &Hex2) {
  return toLowerHex(Hex1) == toLowerHex(Hex2);
}

inline std::string paddingLeft(const std::string &Input, size_t TargetLength,
                               char PadChar) {
  if (Input.size() >= TargetLength) {
    return Input;
  }
  return std::string(TargetLength - Input.size(), PadChar) + Input;
}

inline std::string padAddressTo32Bytes(const evmc::address &Addr) {
  return "000000000000000000000000" + zen::utils::toHex(Addr.bytes, 20);
}

inline std::string decimalToHex(const std::string &DecimalStr) {
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

} // namespace zen::evm_test_utils

#endif // ZEN_TESTS_EVM_TEST_HELPERS_H
