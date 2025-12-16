// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "utils/evm.h"
#include "common/errors.h"
#include "host/evm/crypto.h"
#include "intx/intx.hpp"
#include "utils/rlp_encoding.h"
#include <fstream>
#include <iomanip>
#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>

namespace zen::utils {

using zen::common::ErrorCode;

void trimString(std::string &Str) {
  Str.erase(0, Str.find_first_not_of(" \n\r\t"));
  Str.erase(Str.find_last_not_of(" \n\r\t") + 1);
}

std::optional<std::vector<uint8_t>> fromHex(std::string_view HexStr) {
  if (auto Data = evmc::from_hex(HexStr)) {
    return std::vector<uint8_t>(Data->begin(), Data->end());
  } else {
    return std::nullopt;
  }
}

std::string stripHexPrefix(const std::string &HexStr) {
  if (HexStr.size() >= 2 &&
      (HexStr.substr(0, 2) == "0x" || HexStr.substr(0, 2) == "0X")) {
    return HexStr.substr(2);
  }
  return HexStr;
}

evmc::bytes hexToBytes(const std::string &Hex) {
  evmc::bytes Result;
  if (Hex.empty() || Hex.substr(0, 2) != "0x") {
    return Result;
  }

  std::string HexStr = Hex.substr(2);
  if (HexStr.length() % 2 != 0) {
    HexStr = "0" + HexStr;
  }

  for (size_t I = 0; I < HexStr.length(); I += 2) {
    std::string ByteStr = HexStr.substr(I, 2);
    Result.push_back(static_cast<uint8_t>(std::stoi(ByteStr, nullptr, 16)));
  }
  return Result;
}

evmc::address parseAddress(const std::string &HexAddr) {
  evmc::address Addr{};
  if (HexAddr.empty()) {
    return Addr;
  }

  if (auto Data = evmc::from_hex(HexAddr)) {
    if (Data->size() == 20) {
      std::memcpy(Addr.bytes, Data->data(), 20);
      return Addr;
    }
  }

  throw getErrorWithExtraMessage(ErrorCode::InvalidRawData,
                                 "Hex address must be 20 bytes");
}

evmc::bytes32 parseBytes32(const std::string &HexStr) {
  evmc::bytes32 Result{};
  if (auto Data = evmc::from_hex(HexStr)) {
    if (Data->size() <= 32) {
      std::memcpy(Result.bytes + (32 - Data->size()), Data->data(),
                  Data->size());
      return Result;
    }
  }

  throw getErrorWithExtraMessage(ErrorCode::InvalidRawData,
                                 "Invalid Bytes32 hex string");
}

evmc::uint256be parseUint256(const std::string &HexStr) {
  evmc::uint256be Result{};
  if (auto Data = evmc::from_hex(HexStr)) {
    if (Data->size() <= 32) {
      std::memcpy(Result.bytes + (32 - Data->size()), Data->data(),
                  Data->size());
      return Result;
    }
  }

  throw getErrorWithExtraMessage(ErrorCode::InvalidRawData,
                                 "Invalid Uint256 hex string too long");
}

std::vector<uint8_t> parseHexData(const std::string &HexStr) {
  if (HexStr.empty()) {
    return {};
  }

  auto Result = fromHex(HexStr);
  if (!Result) {
    throw getErrorWithExtraMessage(ErrorCode::InvalidRawData,
                                   "Invalid hex string");
  }
  return *Result;
}

std::string addressToHex(const evmc::address &Value) {
  return "0x" + toHex(Value.bytes, sizeof(Value.bytes));
}

std::string bytes32ToHex(const evmc::bytes32 &Value) {
  return "0x" + toHex(Value.bytes, sizeof(Value.bytes));
}

std::string bytesToHex(const std::vector<uint8_t> &Value) {
  return "0x" + toHex(Value.data(), Value.size());
}

std::vector<uint8_t> uint256beToBytes(const evmc::uint256be &Value) {
  intx::uint256 Val = intx::be::load<intx::uint256>(Value.bytes);
  if (Val == 0) {
    return {};
  }
  unsigned NumBytes = intx::count_significant_bytes(Val);
  std::vector<uint8_t> Result(32);
  intx::be::unsafe::store(Result.data(), Val);
  return std::vector<uint8_t>(Result.end() - NumBytes, Result.end());
}

evmc::address computeCreateAddress(const evmc::address &Sender,
                                   uint64_t SenderNonce) {
  static constexpr auto ADDRESS_SIZE = sizeof(Sender);
  std::vector<uint8_t> SenderBytes(Sender.bytes, Sender.bytes + ADDRESS_SIZE);

  evmc_uint256be NonceUint256 = {};
  intx::be::store(NonceUint256.bytes, intx::uint256{SenderNonce});
  std::vector<uint8_t> NonceMinimalBytes = uint256beToBytes(NonceUint256);

  std::vector<std::vector<uint8_t>> RlpListItems = {SenderBytes,
                                                    NonceMinimalBytes};
  auto EncodedList = zen::evm::rlp::encodeList(RlpListItems);
  const auto BaseHash =
      zen::host::evm::crypto::CryptoProvider::getInstance().keccak256(
          EncodedList);
  evmc::address Addr;
  std::copy_n(&BaseHash.data()[BaseHash.size() - ADDRESS_SIZE], ADDRESS_SIZE,
              Addr.bytes);
  return Addr;
}

void writeJsonString(std::ostream &Os, const std::string &Str) {
  Os << '"';
  for (char C : Str) {
    if (C == '"')
      Os << "\\\"";
    else if (C == '\\')
      Os << "\\\\";
    else if (C == '\b')
      Os << "\\b";
    else if (C == '\f')
      Os << "\\f";
    else if (C == '\n')
      Os << "\\n";
    else if (C == '\r')
      Os << "\\r";
    else if (C == '\t')
      Os << "\\t";
    else if (static_cast<unsigned char>(C) < 32) {
      Os << "\\u" << std::hex << std::setw(4) << std::setfill('0')
         << static_cast<int>(C);
    } else {
      Os << C;
    }
  }
  Os << '"';
}

bool saveState(const evmc::MockedHost &Host, const std::string &FilePath) {
  std::ofstream File(FilePath);
  if (!File.is_open()) {
    return false;
  }

  File << "{\n";

  // Serialize accounts
  File << "  \"accounts\": {\n";
  bool FirstAccount = true;
  for (const auto &[Address, Account] : Host.accounts) {
    if (!FirstAccount)
      File << ",\n";
    FirstAccount = false;

    File << "    ";
    writeJsonString(File, toHex(Address.bytes, sizeof(Address.bytes)));
    File << ": {\n";

    File << "      \"balance\": ";
    writeJsonString(
        File, toHex(Account.balance.bytes, sizeof(Account.balance.bytes)));
    File << ",\n";

    File << "      \"nonce\": " << Account.nonce << ",\n";

    File << "      \"code\": ";
    writeJsonString(File, toHex(Account.code.data(), Account.code.size()));
    File << ",\n";

    File << "      \"codehash\": ";
    writeJsonString(
        File, toHex(Account.codehash.bytes, sizeof(Account.codehash.bytes)));
    File << ",\n";

    // Serialize storage
    File << "      \"storage\": {\n";
    bool FirstStorage = true;
    for (const auto &[Key, Value] : Account.storage) {
      if (!FirstStorage)
        File << ",\n";
      FirstStorage = false;

      File << "        ";
      writeJsonString(File, toHex(Key.bytes, sizeof(Key.bytes)));
      File << ": {\n";
      File << "          \"value\": ";
      writeJsonString(File,
                      toHex(Value.current.bytes, sizeof(Value.current.bytes)));
      File << ",\n";
      File << "          \"access_status\": " << Value.access_status << "\n";
      File << "        }";
    }
    if (!FirstStorage)
      File << "\n";
    File << "      }\n";

    File << "    }";
  }
  if (!FirstAccount)
    File << "\n";
  File << "  },\n";

  // Serialize tx_context
  File << "  \"tx_context\": {\n";
  File << "    \"gas_price\": ";
  writeJsonString(File, toHex(Host.tx_context.tx_gas_price.bytes,
                              sizeof(Host.tx_context.tx_gas_price.bytes)));
  File << ",\n";
  File << "    \"block_number\": " << Host.tx_context.block_number << ",\n";
  File << "    \"block_timestamp\": " << Host.tx_context.block_timestamp
       << ",\n";
  File << "    \"block_coinbase\": ";
  writeJsonString(File, toHex(Host.tx_context.block_coinbase.bytes,
                              sizeof(Host.tx_context.block_coinbase.bytes)));
  File << ",\n";
  File << "    \"block_prev_randao\": ";
  writeJsonString(File, toHex(Host.tx_context.block_prev_randao.bytes,
                              sizeof(Host.tx_context.block_prev_randao.bytes)));
  File << ",\n";
  File << "    \"block_gas_limit\": " << Host.tx_context.block_gas_limit;
  File << ",\n";
  File << "    \"block_base_fee\": ";
  writeJsonString(File, toHex(Host.tx_context.block_base_fee.bytes,
                              sizeof(Host.tx_context.block_base_fee.bytes)));
  File << "\n";
  File << "  }\n";

  File << "}\n";
  return true;
}

bool loadState(evmc::MockedHost &Host, const std::string &FilePath) {
  std::ifstream File(FilePath);
  if (!File.is_open()) {
    return false;
  }

  rapidjson::IStreamWrapper ISW(File);
  rapidjson::Document Doc;
  Doc.ParseStream(ISW);

  if (Doc.HasParseError()) {
    return false;
  }

  if (!Doc.IsObject()) {
    return false;
  }

  Host.accounts.clear();

  // Parse accounts
  if (Doc.HasMember("accounts") && Doc["accounts"].IsObject()) {
    const rapidjson::Value &Accounts = Doc["accounts"];

    for (auto It = Accounts.MemberBegin(); It != Accounts.MemberEnd(); ++It) {
      const std::string AddressStr = It->name.GetString();
      evmc::address Address = zen::utils::parseAddress(AddressStr);

      const rapidjson::Value &AccountData = It->value;
      evmc::MockedAccount Account;

      // Parse balance
      if (AccountData.HasMember("balance") &&
          AccountData["balance"].IsString()) {
        Account.balance =
            zen::utils::parseUint256(AccountData["balance"].GetString());
      }

      // Parse nonce
      if (AccountData.HasMember("nonce") && AccountData["nonce"].IsUint64()) {
        Account.nonce = AccountData["nonce"].GetUint64();
      } else if (AccountData.HasMember("nonce") &&
                 AccountData["nonce"].IsString()) {
        std::string NonceStr =
            zen::utils::stripHexPrefix(AccountData["nonce"].GetString());
        Account.nonce = std::stoull(NonceStr, nullptr, 16);
      }

      // Parse code
      if (AccountData.HasMember("code") && AccountData["code"].IsString()) {
        Account.code = zen::utils::hexToBytes(AccountData["code"].GetString());
      }

      // Parse codehash
      if (AccountData.HasMember("codehash") &&
          AccountData["codehash"].IsString()) {
        Account.codehash =
            zen::utils::parseBytes32(AccountData["codehash"].GetString());
      }

      // Parse storage
      if (AccountData.HasMember("storage") &&
          AccountData["storage"].IsObject()) {
        const rapidjson::Value &Storage = AccountData["storage"];

        for (auto StorageIt = Storage.MemberBegin();
             StorageIt != Storage.MemberEnd(); ++StorageIt) {
          const std::string KeyStr = StorageIt->name.GetString();
          evmc::bytes32 Key = zen::utils::parseBytes32(KeyStr);

          const rapidjson::Value &StorageValue = StorageIt->value;
          evmc::StorageValue StorageVal;

          if (StorageValue.IsObject()) {
            // New format with value and access_status
            if (StorageValue.HasMember("value") &&
                StorageValue["value"].IsString()) {
              StorageVal.current =
                  zen::utils::parseBytes32(StorageValue["value"].GetString());
            }
            if (StorageValue.HasMember("access_status") &&
                StorageValue["access_status"].IsUint()) {
              StorageVal.access_status = static_cast<evmc_access_status>(
                  StorageValue["access_status"].GetUint());
            }
          } else if (StorageValue.IsString()) {
            // Old format with just value
            StorageVal.current =
                zen::utils::parseBytes32(StorageValue.GetString());
          }

          Account.storage[Key] = StorageVal;
        }
      }

      Host.accounts[Address] = Account;
    }
  }

  // Parse tx_context if available
  if (Doc.HasMember("tx_context") && Doc["tx_context"].IsObject()) {
    const rapidjson::Value &TxContext = Doc["tx_context"];

    if (TxContext.HasMember("gas_price") && TxContext["gas_price"].IsString()) {
      Host.tx_context.tx_gas_price =
          zen::utils::parseUint256(TxContext["gas_price"].GetString());
    }

    if (TxContext.HasMember("block_number") &&
        TxContext["block_number"].IsUint64()) {
      Host.tx_context.block_number = TxContext["block_number"].GetUint64();
    }

    if (TxContext.HasMember("block_timestamp") &&
        TxContext["block_timestamp"].IsUint64()) {
      Host.tx_context.block_timestamp =
          TxContext["block_timestamp"].GetUint64();
    }

    if (TxContext.HasMember("block_coinbase") &&
        TxContext["block_coinbase"].IsString()) {
      Host.tx_context.block_coinbase =
          zen::utils::parseAddress(TxContext["block_coinbase"].GetString());
    }

    if (TxContext.HasMember("block_prev_randao") &&
        TxContext["block_prev_randao"].IsString()) {
      Host.tx_context.block_prev_randao =
          zen::utils::parseUint256(TxContext["block_prev_randao"].GetString());
    }

    if (TxContext.HasMember("block_gas_limit") &&
        TxContext["block_gas_limit"].IsUint64()) {
      Host.tx_context.block_gas_limit =
          TxContext["block_gas_limit"].GetUint64();
    }

    if (TxContext.HasMember("block_base_fee") &&
        TxContext["block_base_fee"].IsString()) {
      Host.tx_context.block_base_fee =
          zen::utils::parseUint256(TxContext["block_base_fee"].GetString());
    }
  }

  return true;
}

} // namespace zen::utils
