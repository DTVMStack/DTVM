// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "evm_test_helpers.h"
#include "host/evm/crypto.h"
#include "mpt/merkle_patricia_trie.h"

#include <algorithm>
#include <evmc/hex.hpp>
#include <iostream>

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

std::vector<uint8_t> uint256beToBytes(const evmc::uint256be &Value) {
  const auto *Data = Value.bytes;
  size_t Start = 0;

  while (Start < sizeof(Value.bytes) && Data[Start] == 0) {
    Start++;
  }

  if (Start == sizeof(Value.bytes)) {
    return {};
  }

  return std::vector<uint8_t>(Data + Start, Data + sizeof(Value.bytes));
}

std::vector<uint8_t> calculateStorageRoot(
    const std::unordered_map<evmc::bytes32, evmc::StorageValue> &Storage) {
  zen::evm::mpt::MerklePatriciaTrie StorageTrie;

  for (const auto &[Key, StorageValue] : Storage) {
    bool IsEmpty = true;
    for (int I = 0; I < 32; I++) {
      if (StorageValue.current.bytes[I] != 0) {
        IsEmpty = false;
        break;
      }
    }
    if (IsEmpty)
      continue;

    auto KeyHash = zen::host::evm::crypto::keccak256(
        std::vector<uint8_t>(Key.bytes, Key.bytes + sizeof(Key.bytes)));

    auto ValueBytes = uint256beToBytes(StorageValue.current);
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
    std::vector<uint8_t> NonceBytes;
    int Nonce = Account.nonce;
    while (Nonce > 0) {
      NonceBytes.insert(NonceBytes.begin(), static_cast<uint8_t>(Nonce & 0xFF));
      Nonce >>= 8;
    }
    AccountFields.push_back(NonceBytes);
  }

  auto BalanceBytes = uint256beToBytes(Account.balance);
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

bool verifyStateRoot(evmc::MockedHost &Host, const std::string &ExpectedHash) {
  zen::evm::mpt::MerklePatriciaTrie StateTrie;

  for (const auto &[Address, Account] : Host.accounts) {
    auto AddressHash = zen::host::evm::crypto::keccak256(std::vector<uint8_t>(
        Address.bytes, Address.bytes + sizeof(Address.bytes)));

    auto EncodedAccount = encodeAccount(Account);

    StateTrie.put(AddressHash, EncodedAccount);
  }

  auto StateRoot = StateTrie.rootHash();

  evmc::bytes_view HashView(StateRoot.data(), StateRoot.size());
  std::string CalculatedHash = "0x" + evmc::hex(HashView);

  if (CalculatedHash != ExpectedHash) {
    std::cout << "CalculatedRootHash: " << CalculatedHash << std::endl;
    std::cout << "ExpectedRootHash: " << ExpectedHash << std::endl;
  }

  return CalculatedHash == ExpectedHash;
}

} // namespace zen::evm_test_utils
