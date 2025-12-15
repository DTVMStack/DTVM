// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "evm_test_helpers.h"
#include "evm/evm.h"
#include "host/evm/crypto.h"
#include "mpt/merkle_patricia_trie.h"
#include "utils/evm.h"

#include <algorithm>
#include <evmc/evmc.hpp>
#include <evmc/hex.hpp>
#include <intx/intx.hpp>
#include <iostream>
#include <rapidjson/document.h>

namespace zen::evm_test_utils {

void addAccountToMockedHost(evmc::MockedHost &Host, const evmc::address &Addr,
                            const evmc::MockedAccount &Account) {
  Host.accounts[Addr] = Account;
}

namespace {

std::string
calculateLogsHashImpl(const std::vector<evmc::MockedHost::log_record> &Logs) {
  std::vector<std::vector<uint8_t>> EncodedLogs;

  for (const auto &Log : Logs) {
    std::vector<std::vector<uint8_t>> LogComponents;

    std::vector<uint8_t> AddressBytes(Log.creator.bytes,
                                      Log.creator.bytes + 20);
    LogComponents.push_back(zen::evm::rlp::encodeString(AddressBytes));

    std::vector<std::vector<uint8_t>> TopicsEncoded;
    for (const auto &Topic : Log.topics) {
      std::vector<uint8_t> TopicBytes(Topic.bytes, Topic.bytes + 32);
      TopicsEncoded.push_back(zen::evm::rlp::encodeString(TopicBytes));
    }
    LogComponents.push_back(zen::evm::rlp::encodeList(TopicsEncoded));

    std::vector<uint8_t> DataBytes(Log.data.begin(), Log.data.end());
    LogComponents.push_back(zen::evm::rlp::encodeString(DataBytes));

    EncodedLogs.push_back(zen::evm::rlp::encodeList(LogComponents));
  }

  auto RlpEncodedLogs = zen::evm::rlp::encodeList(EncodedLogs);

  auto Hash = zen::host::evm::crypto::keccak256(RlpEncodedLogs);

  evmc::bytes_view HashView(
      reinterpret_cast<const unsigned char *>(Hash.data()), Hash.size());
  return evmc::hex(HashView);
}

std::vector<uint8_t> calculateStorageRoot(
    const std::unordered_map<evmc::bytes32, evmc::StorageValue> &Storage) {
  zen::evm::mpt::MerklePatriciaTrie StorageTrie;

  for (const auto &[Key, StorageValue] : Storage) {
    intx::uint256 Val =
        intx::be::load<intx::uint256>(StorageValue.current.bytes);
    if (Val == 0)
      continue;

    auto KeyHash = zen::host::evm::crypto::keccak256(
        std::vector<uint8_t>(Key.bytes, Key.bytes + sizeof(Key.bytes)));

    auto ValueBytes = zen::utils::uint256beToBytes(StorageValue.current);
    auto EncodedValue = zen::evm::rlp::encodeString(ValueBytes);

    StorageTrie.put(KeyHash, EncodedValue);
  }

  return StorageTrie.rootHash();
}

std::vector<uint8_t> encodeAccount(const evmc::MockedAccount &Account) {
  std::vector<std::vector<uint8_t>> AccountFields;

  if (Account.nonce == 0) {
    AccountFields.push_back({});
  } else {
    uint64_t Nonce = Account.nonce;
    unsigned NumBytes = (63 - __builtin_clzll(Nonce)) / 8 + 1;
    std::vector<uint8_t> NonceBytes(NumBytes);
    for (unsigned I = 0; I < NumBytes; ++I) {
      NonceBytes[NumBytes - 1 - I] = static_cast<uint8_t>(Nonce >> (I * 8));
    }
    AccountFields.push_back(NonceBytes);
  }

  auto BalanceBytes = zen::utils::uint256beToBytes(Account.balance);
  AccountFields.push_back(BalanceBytes);

  auto StorageRoot = calculateStorageRoot(Account.storage);
  AccountFields.push_back(StorageRoot);

  std::vector<uint8_t> CodeHash(Account.codehash.bytes,
                                Account.codehash.bytes +
                                    sizeof(Account.codehash.bytes));
  AccountFields.push_back(CodeHash);

  return zen::evm::rlp::encodeList(AccountFields);
}

} // anonymous namespace

std::string
calculateLogsHash(const std::vector<evmc::MockedHost::log_record> &Logs) {
  return calculateLogsHashImpl(Logs);
}

bool verifyLogsHash(const std::vector<evmc::MockedHost::log_record> &Logs,
                    const std::string &ExpectedHash) {
  std::string CalculatedHash = "0x" + calculateLogsHash(Logs);
  if (CalculatedHash != ExpectedHash) {
    std::cout << "CalculatedLogsHash: " << CalculatedHash << std::endl;
    std::cout << "ExpectedLogsHash: " << ExpectedHash << std::endl;
  }
  return CalculatedHash == ExpectedHash;
}

std::string calculateStateRootHash(evmc::MockedHost &Host) {
  zen::evm::mpt::MerklePatriciaTrie StateTrie;

  for (const auto &[Address, Account] : Host.accounts) {
    auto AddressHash = zen::host::evm::crypto::keccak256(std::vector<uint8_t>(
        Address.bytes, Address.bytes + sizeof(Address.bytes)));

    auto EncodedAccount = encodeAccount(Account);

    StateTrie.put(AddressHash, EncodedAccount);
  }

  auto StateRoot = StateTrie.rootHash();

  evmc::bytes_view HashView(StateRoot.data(), StateRoot.size());
  return "0x" + evmc::hex(HashView);
}

bool verifyStateRoot(evmc::MockedHost &Host, const std::string &ExpectedHash) {
  std::string CalculatedHash = calculateStateRootHash(Host);

  if (CalculatedHash != ExpectedHash) {
    std::cout << "CalculatedRootHash: " << CalculatedHash << std::endl;
    std::cout << "ExpectedRootHash: " << ExpectedHash << std::endl;
  }

  return CalculatedHash == ExpectedHash;
}

namespace {
std::string formatBytes32Compact(const evmc::bytes32 &Value) {
  intx::uint256 Val = intx::be::load<intx::uint256>(Value.bytes);
  if (Val == 0) {
    return "0x00";
  }
  return "0x" + intx::hex(Val);
}
} // namespace

std::vector<std::string> verifyPostState(evmc::MockedHost &Host,
                                         const rapidjson::Value &ExpectedState,
                                         const std::string &TestName,
                                         const std::string &Fork) {
  std::vector<std::string> Errors;

  if (!ExpectedState.IsObject()) {
    Errors.push_back("Expected state is not an object for " + TestName + " (" +
                     Fork + ")");
    return Errors;
  }

  for (auto AccIt = ExpectedState.MemberBegin();
       AccIt != ExpectedState.MemberEnd(); ++AccIt) {
    std::string AddressStr = AccIt->name.GetString();
    const rapidjson::Value &ExpectedAccount = AccIt->value;

    evmc::address Addr{};
    try {
      auto Data = zen::utils::fromHex(AddressStr);
      if (!Data || Data->size() != 20) {
        Errors.push_back("Invalid address format: " + AddressStr + " in " +
                         TestName + " (" + Fork + ")");
        continue;
      }
      std::memcpy(Addr.bytes, Data->data(), 20);
    } catch (const std::exception &E) {
      Errors.push_back("Failed to parse address " + AddressStr + " in " +
                       TestName + " (" + Fork + "): " + E.what());
      continue;
    }

    auto AccIter = Host.accounts.find(Addr);
    if (AccIter == Host.accounts.end()) {
      Errors.push_back("Account " + AddressStr +
                       " not found in actual state for " + TestName + " (" +
                       Fork + ")");
      continue;
    }

    const evmc::MockedAccount &ActualAccount = AccIter->second;

    if (ExpectedAccount.HasMember("nonce") &&
        ExpectedAccount["nonce"].IsString()) {
      std::string NonceStr = ExpectedAccount["nonce"].GetString();
      std::string Stripped = NonceStr;
      if (NonceStr.size() >= 2 &&
          (NonceStr.substr(0, 2) == "0x" || NonceStr.substr(0, 2) == "0X")) {
        Stripped = NonceStr.substr(2);
      }
      int ExpectedNonce = static_cast<int>(
          std::stoull(Stripped.empty() ? "0" : Stripped, nullptr, 16));

      if (ActualAccount.nonce != ExpectedNonce) {
        Errors.push_back(
            "Nonce mismatch for account " + AddressStr +
            "\n  Expected: " + std::to_string(ExpectedNonce) +
            "\n  Actual:   " + std::to_string(ActualAccount.nonce));
      }
    }

    if (ExpectedAccount.HasMember("balance") &&
        ExpectedAccount["balance"].IsString()) {
      std::string BalanceStr = ExpectedAccount["balance"].GetString();
      try {
        auto Data = zen::utils::fromHex(BalanceStr);
        if (!Data) {
          Errors.push_back("Invalid balance hex for account " + AddressStr +
                           " in " + TestName + " (" + Fork + ")");
        } else {
          evmc::uint256be ExpectedBalance{};
          size_t DataSize = std::min(Data->size(), size_t(32));
          std::memcpy(ExpectedBalance.bytes + (32 - DataSize), Data->data(),
                      DataSize);

          intx::uint256 ExpectedVal =
              intx::be::load<intx::uint256>(ExpectedBalance.bytes);
          intx::uint256 ActualVal =
              intx::be::load<intx::uint256>(ActualAccount.balance.bytes);

          if (ExpectedVal != ActualVal) {
            std::string ExpectedCompact = formatBytes32Compact(ExpectedBalance);
            std::string ActualCompact =
                formatBytes32Compact(ActualAccount.balance);
            Errors.push_back("Balance mismatch for account " + AddressStr +
                             "\n  Expected: " + ExpectedCompact +
                             "\n  Actual:   " + ActualCompact);
          }
        }
      } catch (const std::exception &E) {
        Errors.push_back("Failed to parse balance for account " + AddressStr +
                         " in " + TestName + " (" + Fork + "): " + E.what());
      }
    }

    if (ExpectedAccount.HasMember("storage") &&
        ExpectedAccount["storage"].IsObject()) {
      const rapidjson::Value &ExpectedStorage = ExpectedAccount["storage"];

      for (auto StorageIt = ExpectedStorage.MemberBegin();
           StorageIt != ExpectedStorage.MemberEnd(); ++StorageIt) {
        std::string KeyStr = StorageIt->name.GetString();
        std::string ValueStr = StorageIt->value.GetString();

        try {
          auto KeyData = zen::utils::fromHex(KeyStr);
          auto ValueData = zen::utils::fromHex(ValueStr);

          if (!KeyData || KeyData->size() > 32) {
            Errors.push_back("Invalid storage key format: " + KeyStr +
                             " for account " + AddressStr + " in " + TestName +
                             " (" + Fork + ")");
            continue;
          }

          if (!ValueData || ValueData->size() > 32) {
            Errors.push_back("Invalid storage value format: " + ValueStr +
                             " for key " + KeyStr + " for account " +
                             AddressStr + " in " + TestName + " (" + Fork +
                             ")");
            continue;
          }

          evmc::bytes32 Key{};
          std::memcpy(Key.bytes + (32 - KeyData->size()), KeyData->data(),
                      KeyData->size());

          evmc::bytes32 ExpectedValue{};
          std::memcpy(ExpectedValue.bytes + (32 - ValueData->size()),
                      ValueData->data(), ValueData->size());

          auto StorageIter = ActualAccount.storage.find(Key);
          if (StorageIter == ActualAccount.storage.end()) {
            evmc::bytes_view ExpectedValueView(ExpectedValue.bytes, 32);
            Errors.push_back("Storage key " + KeyStr +
                             " not found for account " + AddressStr + " in " +
                             TestName + " (" + Fork + "), expected value: 0x" +
                             evmc::hex(ExpectedValueView));
            continue;
          }

          const evmc::bytes32 &ActualValue = StorageIter->second.current;

          intx::uint256 ExpectedVal =
              intx::be::load<intx::uint256>(ExpectedValue.bytes);
          intx::uint256 ActualVal =
              intx::be::load<intx::uint256>(ActualValue.bytes);

          if (ExpectedVal != ActualVal) {
            std::string ExpectedCompact = formatBytes32Compact(ExpectedValue);
            std::string ActualCompact = formatBytes32Compact(ActualValue);
            Errors.push_back("Storage mismatch for account " + AddressStr +
                             ", key " + KeyStr +
                             "\n  Expected: " + ExpectedCompact +
                             "\n  Actual:   " + ActualCompact);
          }
        } catch (const std::exception &E) {
          Errors.push_back("Failed to verify storage for key " + KeyStr +
                           " for account " + AddressStr + " in " + TestName +
                           " (" + Fork + "): " + E.what());
        }
      }
    }

    if (ExpectedAccount.HasMember("code") &&
        ExpectedAccount["code"].IsString()) {
      std::string CodeStr = ExpectedAccount["code"].GetString();
      try {
        auto ExpectedCodeData = zen::utils::fromHex(CodeStr);
        if (!ExpectedCodeData) {
          Errors.push_back("Invalid code hex for account " + AddressStr +
                           " in " + TestName + " (" + Fork + ")");
        } else {
          if (ExpectedCodeData->size() != ActualAccount.code.size()) {
            Errors.push_back(
                "Code size mismatch for account " + AddressStr +
                "\n  Expected: " + std::to_string(ExpectedCodeData->size()) +
                " bytes" + "\n  Actual:   " +
                std::to_string(ActualAccount.code.size()) + " bytes");
          } else {
            bool Match =
                std::equal(ExpectedCodeData->begin(), ExpectedCodeData->end(),
                           ActualAccount.code.begin());
            if (!Match) {
              Errors.push_back("Code content mismatch for account " +
                               AddressStr);
            }
          }
        }
      } catch (const std::exception &E) {
        Errors.push_back("Failed to parse code for account " + AddressStr +
                         " in " + TestName + " (" + Fork + "): " + E.what());
      }
    }
  }

  return Errors;
}

evmc_revision mapForkToRevision(const std::string &Fork) {
  if (Fork == "Frontier") {
    return EVMC_FRONTIER;
  }
  if (Fork == "Homestead") {
    return EVMC_HOMESTEAD;
  }
  if (Fork == "TangerineWhistle") {
    return EVMC_TANGERINE_WHISTLE;
  }
  if (Fork == "SpuriousDragon") {
    return EVMC_SPURIOUS_DRAGON;
  }
  if (Fork == "Byzantium") {
    return EVMC_BYZANTIUM;
  }
  if (Fork == "Constantinople") {
    return EVMC_CONSTANTINOPLE;
  }
  if (Fork == "ConstantinopleFix" || Fork == "Petersburg") {
    return EVMC_PETERSBURG;
  }
  if (Fork == "Istanbul") {
    return EVMC_ISTANBUL;
  }
  if (Fork == "Berlin") {
    return EVMC_BERLIN;
  }
  if (Fork == "London") {
    return EVMC_LONDON;
  }
  if (Fork == "Paris") {
    return EVMC_PARIS;
  }
  if (Fork == "Shanghai") {
    return EVMC_SHANGHAI;
  }
  if (Fork == "Cancun") {
    return EVMC_CANCUN;
  }
  if (Fork == "Prague") {
    return EVMC_PRAGUE;
  }
  return zen::evm::DEFAULT_REVISION;
}

} // namespace zen::evm_test_utils
