// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_TESTS_EVM_TEST_HELPERS_H
#define ZEN_TESTS_EVM_TEST_HELPERS_H

#include "evmc/mocked_host.hpp"
#include "mpt/rlp_encoding.h"

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

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

bool verifyStateRoot(evmc::MockedHost &Host, const std::string &ExpectedHash);

} // namespace zen::evm_test_utils

#endif // ZEN_TESTS_EVM_TEST_HELPERS_H
