// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "utils/evm.h"
#include "common/errors.h"
#include "evm/evm.h"
#include "host/evm/crypto.h"
#include "intx/intx.hpp"
#include "utils/rlp_encoding.h"
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <limits>
#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>

namespace zen::utils {

using zen::common::ErrorCode;

void trimString(std::string &Str) {
  Str.erase(0, Str.find_first_not_of(" \n\r\t"));
  Str.erase(Str.find_last_not_of(" \n\r\t") + 1);
}

/// Pad an odd-length hex string to even length by inserting a leading '0'
/// after the optional 0x prefix. Handles both prefixed ("0x1" -> "0x01")
/// and non-prefixed ("1" -> "01") inputs.
static std::string padHexToEvenLength(const std::string &HexStr) {
  if (HexStr.size() >= 2 && (HexStr[0] == '0') &&
      (HexStr[1] == 'x' || HexStr[1] == 'X')) {
    std::string Stripped = HexStr.substr(2);
    if (Stripped.length() % 2 != 0) {
      return "0x0" + Stripped;
    }
  } else if (!HexStr.empty() && HexStr.length() % 2 != 0) {
    return "0" + HexStr;
  }
  return HexStr;
}

std::optional<std::vector<uint8_t>> fromHex(std::string_view HexStr) {
  // Handle odd-length hex strings (e.g. "0x1" -> "0x01", "1" -> "01")
  // which are rejected by evmc::from_hex
  std::string Padded = padHexToEvenLength(std::string(HexStr));
  if (auto Data = evmc::from_hex(Padded)) {
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
  std::string Padded = padHexToEvenLength(HexStr);
  if (auto Data = evmc::from_hex(Padded)) {
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
  std::string Padded = padHexToEvenLength(HexStr);
  if (auto Data = evmc::from_hex(Padded)) {
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
      File << "\n";
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
  File << ",\n";
  File << "    \"tx_origin\": ";
  writeJsonString(File, toHex(Host.tx_context.tx_origin.bytes,
                              sizeof(Host.tx_context.tx_origin.bytes)));
  File << ",\n";
  File << "    \"chain_id\": ";
  writeJsonString(File, toHex(Host.tx_context.chain_id.bytes,
                              sizeof(Host.tx_context.chain_id.bytes)));
  File << ",\n";
  File << "    \"blob_base_fee\": ";
  writeJsonString(File, toHex(Host.tx_context.blob_base_fee.bytes,
                              sizeof(Host.tx_context.blob_base_fee.bytes)));
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

  // Parse into temporary storage first so failures cannot partially mutate the
  // caller-supplied host. Start from the caller's tx_context so a state file
  // without tx_context (or with missing fields) keeps the values the caller
  // already established (e.g. tx_origin from the CLI --sender); fields present
  // in the JSON are overlaid on top of it.
  evmc::MockedHost ParsedHost;
  ParsedHost.accounts.clear();
  ParsedHost.tx_context = Host.tx_context;

  try {
    // Parse accounts
    if (Doc.HasMember("accounts") && Doc["accounts"].IsObject()) {
      const rapidjson::Value &Accounts = Doc["accounts"];

      for (auto It = Accounts.MemberBegin(); It != Accounts.MemberEnd(); ++It) {
        const std::string AddressStr = It->name.GetString();
        evmc::address Address = zen::utils::parseAddress(AddressStr);

        const rapidjson::Value &AccountData = It->value;
        evmc::MockedAccount &Account = ParsedHost.accounts[Address];

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
          Account.code =
              zen::utils::hexToBytes(AccountData["code"].GetString());
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
              // The optional original value allows callers to provide a
              // transaction-specific original. access_status is never part of a
              // pre-state; legacy files may include it and it must be ignored.
              if (StorageValue.HasMember("value") &&
                  StorageValue["value"].IsString()) {
                StorageVal.current =
                    zen::utils::parseBytes32(StorageValue["value"].GetString());
              }
              if (StorageValue.HasMember("original") &&
                  StorageValue["original"].IsString()) {
                StorageVal.original = zen::utils::parseBytes32(
                    StorageValue["original"].GetString());
              } else {
                // A persisted transaction-final state is the start of a new
                // transaction. Unless an explicit original value is provided,
                // current is also the transaction's original value.
                StorageVal.original = StorageVal.current;
              }
            } else if (StorageValue.IsString()) {
              // Old format with just value
              StorageVal.current =
                  zen::utils::parseBytes32(StorageValue.GetString());
              StorageVal.original = StorageVal.current;
            }

            ParsedHost.accounts[Address].storage[Key] = StorageVal;
          }
        }
      }
    }

    // Parse tx_context if available
    if (Doc.HasMember("tx_context") && Doc["tx_context"].IsObject()) {
      const rapidjson::Value &TxContext = Doc["tx_context"];

      if (TxContext.HasMember("gas_price") &&
          TxContext["gas_price"].IsString()) {
        ParsedHost.tx_context.tx_gas_price =
            zen::utils::parseUint256(TxContext["gas_price"].GetString());
      }

      if (TxContext.HasMember("block_number") &&
          TxContext["block_number"].IsUint64()) {
        auto Val = TxContext["block_number"].GetUint64();
        if (Val > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
          Val = static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
        }
        ParsedHost.tx_context.block_number = static_cast<int64_t>(Val);
      }

      if (TxContext.HasMember("block_timestamp") &&
          TxContext["block_timestamp"].IsUint64()) {
        auto Val = TxContext["block_timestamp"].GetUint64();
        if (Val > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
          Val = static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
        }
        ParsedHost.tx_context.block_timestamp = static_cast<int64_t>(Val);
      }

      if (TxContext.HasMember("block_coinbase") &&
          TxContext["block_coinbase"].IsString()) {
        ParsedHost.tx_context.block_coinbase =
            zen::utils::parseAddress(TxContext["block_coinbase"].GetString());
      }

      if (TxContext.HasMember("block_prev_randao") &&
          TxContext["block_prev_randao"].IsString()) {
        ParsedHost.tx_context.block_prev_randao = zen::utils::parseUint256(
            TxContext["block_prev_randao"].GetString());
      }

      if (TxContext.HasMember("block_gas_limit") &&
          TxContext["block_gas_limit"].IsUint64()) {
        auto Val = TxContext["block_gas_limit"].GetUint64();
        if (Val > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
          Val = static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
        }
        ParsedHost.tx_context.block_gas_limit = static_cast<int64_t>(Val);
      }

      if (TxContext.HasMember("block_base_fee") &&
          TxContext["block_base_fee"].IsString()) {
        ParsedHost.tx_context.block_base_fee =
            zen::utils::parseUint256(TxContext["block_base_fee"].GetString());
      }

      if (TxContext.HasMember("tx_origin") &&
          TxContext["tx_origin"].IsString()) {
        ParsedHost.tx_context.tx_origin =
            zen::utils::parseAddress(TxContext["tx_origin"].GetString());
      }

      if (TxContext.HasMember("chain_id") && TxContext["chain_id"].IsString()) {
        ParsedHost.tx_context.chain_id =
            zen::utils::parseUint256(TxContext["chain_id"].GetString());
      }

      if (TxContext.HasMember("blob_base_fee") &&
          TxContext["blob_base_fee"].IsString()) {
        ParsedHost.tx_context.blob_base_fee =
            zen::utils::parseUint256(TxContext["blob_base_fee"].GetString());
      }
    }

    // Parse and pre-warm EIP-2930 access list if present.
    // Warm addresses cost 100 gas instead of cold 2600, warm storage slots
    // cost 100 gas instead of cold 2100.
    if (Doc.HasMember("access_list") && Doc["access_list"].IsArray()) {
      for (const auto &Entry : Doc["access_list"].GetArray()) {
        if (!Entry.IsObject() || !Entry.HasMember("address") ||
            !Entry["address"].IsString()) {
          continue;
        }
        evmc::address Address;
        try {
          Address = zen::utils::parseAddress(Entry["address"].GetString());
        } catch (...) {
          continue;
        }
        ParsedHost.access_account(Address);

        if (!Entry.HasMember("storage_keys") ||
            !Entry["storage_keys"].IsArray()) {
          continue;
        }
        // EIP-2930 requires access-list storage keys to be warm even when the
        // account is not yet present in the initial host state (e.g. when the
        // contract is created later in the same transaction). Use the host
        // access_storage API so the account entry is materialized
        // automatically.
        for (const auto &KeyVal : Entry["storage_keys"].GetArray()) {
          if (!KeyVal.IsString()) {
            continue;
          }
          try {
            evmc::bytes32 Key = zen::utils::parseBytes32(KeyVal.GetString());
            ParsedHost.access_storage(Address, Key);
          } catch (...) {
            continue;
          }
        }
      }
    }
  } catch (const std::exception &) {
    return false;
  }

  // Data is assigned only after all fields parse successfully so a malformed
  // state file cannot leave the caller with a partially-updated host.
  Host.accounts = std::move(ParsedHost.accounts);
  Host.tx_context = ParsedHost.tx_context;

  return true;
}

int64_t computeIntrinsicGas(evmc_revision Revision, evmc_call_kind MsgKind,
                            const uint8_t *InputData, size_t InputSize) {
  using namespace zen::evm;
  int64_t Gas = BASIC_EXECUTION_COST;

  // Calldata cost (EIP-2028)
  const int64_t NonZeroCost = Revision >= EVMC_ISTANBUL
                                  ? TX_DATA_NON_ZERO_GAS
                                  : TX_DATA_NON_ZERO_GAS_PRE_ISTANBUL;
  for (size_t Idx = 0; Idx < InputSize; ++Idx) {
    Gas += InputData[Idx] == 0 ? TX_DATA_ZERO_GAS : NonZeroCost;
  }

  // CREATE cost (Homestead+) and initcode cost (EIP-3860, Shanghai+)
  const bool IsCreate = MsgKind == EVMC_CREATE || MsgKind == EVMC_CREATE2;
  if (IsCreate && Revision >= EVMC_HOMESTEAD) {
    Gas += TX_CREATE_COST;
    if (Revision >= EVMC_SHANGHAI && InputSize > 0) {
      Gas += static_cast<int64_t>((InputSize + 31) / 32) * INITCODE_WORD_GAS;
    }
  }

  return Gas;
}

void prewarmTransactionAccounts(evmc::MockedHost &Host, evmc_revision Revision,
                                const evmc::address &Sender,
                                const evmc::address &Recipient,
                                const evmc::address &Coinbase) {
  // EIP-2929 (Berlin+): sender, recipient, and precompiled contracts are
  // always warm at the start of a transaction.  Cancun adds the KZG point
  // evaluation precompile at 0x0a (EIP-4844), so keep the precompile range
  // revision-aware.
  if (Revision >= EVMC_BERLIN) {
    Host.access_account(Sender);
    // Contract-creation transactions do not have a transaction-level recipient.
    // In this codebase CREATE messages use the zero address as a placeholder,
    // so avoid pre-warming it here.
    if (Recipient != evmc::address{}) {
      Host.access_account(Recipient);
    }
    const int LastPrecompileIdx = Revision >= EVMC_CANCUN ? 10 : 9;
    for (int PrecompileIdx = 1; PrecompileIdx <= LastPrecompileIdx;
         ++PrecompileIdx) {
      evmc::address PrecompileAddr{};
      PrecompileAddr.bytes[19] = PrecompileIdx;
      Host.access_account(PrecompileAddr);
    }
  }

  // EIP-3651 (Shanghai+): coinbase is warm at the start of a transaction.
  if (Revision >= EVMC_SHANGHAI) {
    Host.access_account(Coinbase);
  }
}

uint64_t computeRefundCap(evmc_revision Revision, uint64_t GasUsed) {
  // EIP-3529: London and later cap refunds at 1/5 of GasUsed; pre-London
  // capped them at 1/2.
  return Revision >= EVMC_LONDON ? GasUsed / 5 : GasUsed / 2;
}

EvmFeeComponents computeEvmTransactionFees(
    const evmc::uint256be &EffectiveOrMaxFeePerGas,
    const evmc::uint256be &BaseFee,
    const std::optional<evmc::uint256be> &MaxPriorityFee) {
  intx::uint256 GasPriceN =
      intx::be::load<intx::uint256>(EffectiveOrMaxFeePerGas);
  intx::uint256 BaseFeeN = intx::be::load<intx::uint256>(BaseFee);
  intx::uint256 PriorityFee =
      GasPriceN > BaseFeeN ? GasPriceN - BaseFeeN : intx::uint256{0};
  intx::uint256 EffectiveGasPrice = GasPriceN;

  if (MaxPriorityFee) {
    intx::uint256 MaxPriorityN = intx::be::load<intx::uint256>(*MaxPriorityFee);
    intx::uint256 MaxFeeMinusBase =
        GasPriceN > BaseFeeN ? GasPriceN - BaseFeeN : intx::uint256{0};
    PriorityFee =
        MaxPriorityN < MaxFeeMinusBase ? MaxPriorityN : MaxFeeMinusBase;
    EffectiveGasPrice = BaseFeeN + PriorityFee;
  }
  return {EffectiveGasPrice, PriorityFee};
}

EvmUpfrontGasResult applyEvmUpfrontGas(evmc::MockedHost &Host,
                                       evmc_message &Msg, uint64_t GasLimit,
                                       evmc_revision Revision) {
  // Deduct intrinsic gas before EVM execution.
  const int64_t IntrinsicGas =
      computeIntrinsicGas(Revision, Msg.kind, Msg.input_data, Msg.input_size);
  if (Msg.gas < IntrinsicGas) {
    return EvmUpfrontGasResult::IntrinsicGasExceedsLimit;
  }
  Msg.gas -= IntrinsicGas;

  // EIP-2929/EIP-3651: Pre-warm transaction-level accounts.
  zen::utils::prewarmTransactionAccounts(Host, Revision, Msg.sender,
                                         Msg.recipient,
                                         Host.tx_context.block_coinbase);

  // Deduct upfront gas cost from sender's balance before execution.
  // Per EVM spec (Yellow Paper §6), the sender's balance is reduced by
  // effective_gas_price * gas_limit at the start of transaction execution.
  const auto Fees = computeEvmTransactionFees(Host.tx_context.tx_gas_price,
                                              Host.tx_context.block_base_fee);
  intx::uint256 UpfrontGasCost =
      intx::uint256(GasLimit) * Fees.EffectiveGasPrice;
  auto &SenderAccount = Host.accounts[Msg.sender];
  intx::uint256 SenderBalance =
      intx::be::load<intx::uint256>(SenderAccount.balance);
  if (SenderBalance < UpfrontGasCost) {
    return EvmUpfrontGasResult::InsufficientBalance;
  }
  SenderBalance -= UpfrontGasCost;
  SenderAccount.balance = intx::be::store<evmc::bytes32>(SenderBalance);
  return EvmUpfrontGasResult::Success;
}

void applyEvmPostExecutionSettlement(evmc::MockedHost &Host,
                                     const evmc_message &Msg, uint64_t GasLimit,
                                     const evmc::Result &Result,
                                     evmc_revision Revision) {
  const uint64_t TotalGasUsed = static_cast<uint64_t>(
      GasLimit - (Result.gas_left > 0 ? Result.gas_left : 0));
  // Intrinsic gas was already deducted from Msg.gas before execution, so it
  // is part of TotalGasUsed above; do not add it again (double counting).
  const uint64_t RawGasRefund =
      static_cast<uint64_t>(std::max<int64_t>(0, Result.gas_refund));
  const uint64_t AppliedRefund =
      std::min(RawGasRefund, computeRefundCap(Revision, TotalGasUsed));
  const uint64_t GasCharged =
      AppliedRefund < TotalGasUsed ? TotalGasUsed - AppliedRefund : 0;

  const auto Fees = computeEvmTransactionFees(Host.tx_context.tx_gas_price,
                                              Host.tx_context.block_base_fee);
  auto &SenderAccount = Host.accounts[Msg.sender];
  intx::uint256 SenderBalance =
      intx::be::load<intx::uint256>(SenderAccount.balance);

  // Refund unused gas: (GasLimit - GasCharged) * EffectiveGasPrice
  if (GasLimit > GasCharged) {
    intx::uint256 Refund =
        intx::uint256(GasLimit - GasCharged) * Fees.EffectiveGasPrice;
    SenderBalance += Refund;
  }
  // Pay priority fee to coinbase: GasCharged * PriorityFee
  if (Fees.PriorityFee != intx::uint256{0}) {
    auto &CoinbaseAccount = Host.accounts[Host.tx_context.block_coinbase];
    intx::uint256 CoinbaseBalance =
        intx::be::load<intx::uint256>(CoinbaseAccount.balance);
    CoinbaseBalance += intx::uint256(GasCharged) * Fees.PriorityFee;
    CoinbaseAccount.balance = intx::be::store<evmc::bytes32>(CoinbaseBalance);
  }
  SenderAccount.balance = intx::be::store<evmc::bytes32>(SenderBalance);
}

} // namespace zen::utils
