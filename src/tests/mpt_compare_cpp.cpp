// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "host/evm/crypto.h"
#include "mpt/merkle_patricia_trie.h"
#include "utils/evm.h"
#include <fstream>
#include <iostream>
#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

using namespace zen::evm::mpt;

class MptCompareCpp {
private:
  std::vector<uint8_t> hexToBytes(const std::string &HexStr) {
    std::string CleanHex = HexStr;
    if (CleanHex.substr(0, 2) == "0x") {
      CleanHex = CleanHex.substr(2);
    }

    if (CleanHex.empty()) {
      return {};
    }

    if (CleanHex.length() % 2 == 1) {
      CleanHex = "0" + CleanHex;
    }

    std::vector<uint8_t> Result;
    for (size_t I = 0; I < CleanHex.length(); I += 2) {
      std::string ByteString = CleanHex.substr(I, 2);
      uint8_t Byte =
          static_cast<uint8_t>(strtol(ByteString.c_str(), nullptr, 16));
      Result.push_back(Byte);
    }
    return Result;
  }

  std::string bytesToHex(const std::vector<uint8_t> &Bytes) {
    return zen::utils::toHex(Bytes.data(), Bytes.size());
  }

  evmc_uint256be hexToUint256(const std::string &HexStr) {
    evmc_uint256be Result = {};
    auto Bytes = hexToBytes(HexStr);

    size_t Start = 32 - Bytes.size();
    std::copy(Bytes.begin(), Bytes.end(), Result.bytes + Start);

    return Result;
  }

  std::vector<uint8_t> encodeRLPLength(size_t Length, uint8_t Offset) {
    std::vector<uint8_t> Result;

    if (Length < 56) {
      Result.push_back(static_cast<uint8_t>(Length + Offset));
    } else {
      std::vector<uint8_t> LengthBytes;
      size_t Temp = Length;
      while (Temp > 0) {
        LengthBytes.insert(LengthBytes.begin(),
                           static_cast<uint8_t>(Temp & 0xFF));
        Temp >>= 8;
      }
      Result.push_back(static_cast<uint8_t>(LengthBytes.size() + Offset + 55));
      Result.insert(Result.end(), LengthBytes.begin(), LengthBytes.end());
    }

    return Result;
  }

  std::vector<uint8_t> encodeRLPString(const std::vector<uint8_t> &Input) {
    if (Input.empty()) {
      return {0x80};
    }

    if (Input.size() == 1 && Input[0] < 0x80) {
      return Input;
    }

    auto LengthBytes = encodeRLPLength(Input.size(), 0x80);
    LengthBytes.insert(LengthBytes.end(), Input.begin(), Input.end());
    return LengthBytes;
  }

  std::vector<uint8_t>
  encodeRLPList(const std::vector<std::vector<uint8_t>> &Items) {
    std::vector<uint8_t> Payload;
    for (const auto &Item : Items) {
      auto Encoded = encodeRLPString(Item);
      Payload.insert(Payload.end(), Encoded.begin(), Encoded.end());
    }

    auto LengthBytes = encodeRLPLength(Payload.size(), 0xc0);
    LengthBytes.insert(LengthBytes.end(), Payload.begin(), Payload.end());
    return LengthBytes;
  }

  std::vector<uint8_t> uint256ToMinimalBytes(const evmc_uint256be &Value) {
    const auto *Data = Value.bytes;
    size_t Start = 0;

    while (Start < 32 && Data[Start] == 0) {
      Start++;
    }

    if (Start == 32) {
      return {};
    }

    return std::vector<uint8_t>(Data + Start, Data + 32);
  }

public:
  struct ProcessedAccount {
    std::string Address;
    std::string AddressHash;
    std::string Nonce;
    std::string Balance;
    std::string StorageRoot;
    std::string CodeHash;
    std::string AccountRLP;
  };

  struct ComparisonResult {
    std::string StateRoot;
    std::vector<ProcessedAccount> Accounts;
  };

  ComparisonResult calculateStateRootFromJson(const rapidjson::Document &Doc) {
    MerklePatriciaTrie StateTrie;
    MerklePatriciaTrie EmptyStorageTrie;
    auto EmptyStorageRoot = EmptyStorageTrie.rootHash();

    ComparisonResult Result;

    for (auto It = Doc.MemberBegin(); It != Doc.MemberEnd(); ++It) {
      const std::string Address = It->name.GetString();
      const rapidjson::Value &Account = It->value;

      // Calculate address hash
      auto AddressBytes = hexToBytes(Address);
      auto AddressHash = zen::host::evm::crypto::keccak256(AddressBytes);

      // Parse account data
      auto BalanceUint256 = hexToUint256(Account["balance"].GetString());
      auto BalanceBytes = uint256ToMinimalBytes(BalanceUint256);

      // Parse nonce
      std::vector<uint8_t> NonceBytes;
      std::string NonceStr = Account["nonce"].GetString();
      if (NonceStr != "0x00" && NonceStr != "0x" && NonceStr != "0") {
        auto NonceUint256 = hexToUint256(NonceStr);
        NonceBytes = uint256ToMinimalBytes(NonceUint256);
      }

      // Calculate code hash
      auto CodeBytes = hexToBytes(Account["code"].GetString());
      auto CodeHash = zen::host::evm::crypto::keccak256(CodeBytes);

      // Handle storage (simplified for now - empty storage)
      auto StorageRoot = EmptyStorageRoot;
      if (Account.HasMember("storage") && Account["storage"].IsObject() &&
          Account["storage"].MemberCount() > 0) {
        MerklePatriciaTrie StorageTrie;
        for (auto StorageIt = Account["storage"].MemberBegin();
             StorageIt != Account["storage"].MemberEnd(); ++StorageIt) {
          std::string KeyStr = StorageIt->name.GetString();
          std::string ValueStr = StorageIt->value.GetString();

          if (ValueStr != "0x" && ValueStr != "0x00" && ValueStr != "0") {
            auto KeyBytes = hexToBytes(KeyStr);
            auto KeyHash = zen::host::evm::crypto::keccak256(KeyBytes);
            auto ValueUint256 = hexToUint256(ValueStr);
            auto ValueBytes = uint256ToMinimalBytes(ValueUint256);
            auto EncodedValue = encodeRLPString(ValueBytes);
            StorageTrie.put(KeyHash, EncodedValue);
          }
        }
        StorageRoot = StorageTrie.rootHash();
      }

      // Build account RLP: [nonce, balance, storageRoot, codeHash]
      std::vector<std::vector<uint8_t>> AccountFields = {
          NonceBytes, BalanceBytes, StorageRoot, CodeHash};

      auto AccountRLP = encodeRLPList(AccountFields);

      // Insert into state trie
      StateTrie.put(AddressHash, AccountRLP);

      // Store processed account info
      ProcessedAccount ProcessedAccountData;
      ProcessedAccountData.Address = Address;
      ProcessedAccountData.AddressHash = bytesToHex(AddressHash);
      ProcessedAccountData.Nonce = bytesToHex(NonceBytes);
      ProcessedAccountData.Balance = bytesToHex(BalanceBytes);
      ProcessedAccountData.StorageRoot = bytesToHex(StorageRoot);
      ProcessedAccountData.CodeHash = bytesToHex(CodeHash);
      ProcessedAccountData.AccountRLP = bytesToHex(AccountRLP);

      Result.Accounts.push_back(ProcessedAccountData);
    }

    auto StateRoot = StateTrie.rootHash();
    Result.StateRoot = bytesToHex(StateRoot);

    return Result;
  }
};

int main(int Argc, char *Argv[]) {
  if (Argc != 2) {
    std::cerr << "Usage: " << Argv[0] << " <json_file>" << std::endl;
    return 1;
  }

  std::string JsonFile = Argv[1];

  try {
    std::ifstream File(JsonFile);
    if (!File.is_open()) {
      throw std::runtime_error("Failed to open file: " + JsonFile);
    }

    rapidjson::IStreamWrapper ISW(File);
    rapidjson::Document Doc;
    Doc.ParseStream(ISW);

    if (Doc.HasParseError()) {
      throw std::runtime_error("Failed to parse JSON file");
    }

    MptCompareCpp Comparator;
    auto Result = Comparator.calculateStateRootFromJson(Doc);

    // Output JSON result
    rapidjson::StringBuffer Buffer;
    rapidjson::Writer<rapidjson::StringBuffer> Writer(Buffer);

    Writer.StartObject();

    Writer.Key("stateRoot");
    Writer.String(Result.StateRoot.c_str());

    Writer.Key("accounts");
    Writer.StartArray();

    for (const auto &Account : Result.Accounts) {
      Writer.StartObject();
      Writer.Key("address");
      Writer.String(Account.Address.c_str());
      Writer.Key("addressHash");
      Writer.String(Account.AddressHash.c_str());
      Writer.Key("nonce");
      Writer.String(Account.Nonce.c_str());
      Writer.Key("balance");
      Writer.String(Account.Balance.c_str());
      Writer.Key("storageRoot");
      Writer.String(Account.StorageRoot.c_str());
      Writer.Key("codeHash");
      Writer.String(Account.CodeHash.c_str());
      Writer.Key("accountRLP");
      Writer.String(Account.AccountRLP.c_str());
      Writer.EndObject();
    }

    Writer.EndArray();
    Writer.EndObject();

    std::cout << Buffer.GetString() << std::endl;

  } catch (const std::exception &E) {
    std::cerr << "Error: " << E.what() << std::endl;
    return 1;
  }

  return 0;
}
