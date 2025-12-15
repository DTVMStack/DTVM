// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "evm_test_fixtures.h"
#include "host/evm/crypto.h"
#include "utils/evm.h"

#include <filesystem>
#include <fstream>
#include <rapidjson/istreamwrapper.h>
#include <stdexcept>

namespace zen::evm_test_utils {
using namespace zen::utils;

std::vector<ParsedAccount> parsePreAccounts(const rapidjson::Value &Pre) {
  std::vector<ParsedAccount> Accounts;

  if (!Pre.IsObject()) {
    throw std::invalid_argument("Pre must be an object");
  }

  for (auto It = Pre.MemberBegin(); It != Pre.MemberEnd(); ++It) {
    const std::string AddrStr = It->name.GetString();
    const rapidjson::Value &AccountData = It->value;

    ParsedAccount PA;
    PA.Address = parseAddress(AddrStr);

    if (AccountData.HasMember("nonce") && AccountData["nonce"].IsString()) {
      std::string NonceStr = stripHexPrefix(AccountData["nonce"].GetString());
      PA.Account.nonce = static_cast<int>(std::stoull(NonceStr, nullptr, 16));
    }

    if (AccountData.HasMember("balance") && AccountData["balance"].IsString()) {
      PA.Account.balance = parseUint256(AccountData["balance"].GetString());
    }

    if (AccountData.HasMember("code") && AccountData["code"].IsString()) {
      auto CodeData = parseHexData(AccountData["code"].GetString());
      PA.Account.code.assign(CodeData.begin(), CodeData.end());

      auto CodeHashBytes = zen::host::evm::crypto::keccak256(CodeData);
      std::memcpy(PA.Account.codehash.bytes, CodeHashBytes.data(), 32);
    } else {
      std::vector<uint8_t> EmptyCode;
      auto EmptyCodeHash = zen::host::evm::crypto::keccak256(EmptyCode);
      std::memcpy(PA.Account.codehash.bytes, EmptyCodeHash.data(), 32);
    }

    if (AccountData.HasMember("storage") && AccountData["storage"].IsObject()) {
      const rapidjson::Value &Storage = AccountData["storage"];
      for (auto StorageIt = Storage.MemberBegin();
           StorageIt != Storage.MemberEnd(); ++StorageIt) {
        evmc::bytes32 Key = parseBytes32(StorageIt->name.GetString());
        evmc::bytes32 Value = parseBytes32(StorageIt->value.GetString());
        PA.Account.storage[Key] = evmc::StorageValue{Value};
      }
    }

    Accounts.push_back(std::move(PA));
  }

  return Accounts;
}

std::vector<std::string> findJsonFiles(const std::string &RootPath) {
  std::vector<std::string> JsonFiles;

  if (!std::filesystem::exists(RootPath)) {
    return JsonFiles;
  }

  try {
    for (const auto &Entry :
         std::filesystem::recursive_directory_iterator(RootPath)) {
      if (Entry.is_regular_file() && Entry.path().extension() == ".json") {
        JsonFiles.push_back(Entry.path().string());
      }
    }
  } catch (const std::filesystem::filesystem_error &E) {
    throw std::runtime_error("Failed to traverse directory: " +
                             std::string(E.what()));
  }

  std::sort(JsonFiles.begin(), JsonFiles.end());
  return JsonFiles;
}

std::vector<StateTestFixture> parseStateTestFile(const std::string &FilePath) {
  std::vector<StateTestFixture> Fixtures;

  std::ifstream File(FilePath);
  if (!File.is_open()) {
    throw std::runtime_error("Failed to open file: " + FilePath);
  }

  rapidjson::IStreamWrapper ISW(File);
  rapidjson::Document Doc;
  Doc.ParseStream(ISW);

  if (Doc.HasParseError()) {
    throw std::runtime_error("Failed to parse JSON file: " + FilePath);
  }

  if (!Doc.IsObject()) {
    throw std::runtime_error("JSON root must be an object");
  }

  for (auto It = Doc.MemberBegin(); It != Doc.MemberEnd(); ++It) {
    StateTestFixture Fixture;
    Fixture.TestName = It->name.GetString();

    const rapidjson::Value &TestCase = It->value;

    if (TestCase.HasMember("pre")) {
      Fixture.PreState = parsePreAccounts(TestCase["pre"]);
    }

    if (TestCase.HasMember("env")) {
      const rapidjson::Value &Env = TestCase["env"];
      Fixture.Environment = {};

      if (Env.HasMember("currentCoinbase") &&
          Env["currentCoinbase"].IsString()) {
        Fixture.Environment.block_coinbase =
            parseAddress(Env["currentCoinbase"].GetString());
      }

      if (Env.HasMember("currentNumber") && Env["currentNumber"].IsString()) {
        std::string NumStr = stripHexPrefix(Env["currentNumber"].GetString());
        Fixture.Environment.block_number =
            static_cast<int64_t>(std::stoull(NumStr, nullptr, 16));
      }

      if (Env.HasMember("currentTimestamp") &&
          Env["currentTimestamp"].IsString()) {
        std::string TimestampStr =
            stripHexPrefix(Env["currentTimestamp"].GetString());
        Fixture.Environment.block_timestamp =
            static_cast<int64_t>(std::stoull(TimestampStr, nullptr, 16));
      }

      if (Env.HasMember("currentGasLimit") &&
          Env["currentGasLimit"].IsString()) {
        std::string GasLimitStr =
            stripHexPrefix(Env["currentGasLimit"].GetString());
        Fixture.Environment.block_gas_limit =
            static_cast<int64_t>(std::stoull(GasLimitStr, nullptr, 16));
      }

      if (Env.HasMember("currentBaseFee") && Env["currentBaseFee"].IsString()) {
        Fixture.Environment.block_base_fee =
            parseUint256(Env["currentBaseFee"].GetString());
      }

      if (Env.HasMember("currentRandom") && Env["currentRandom"].IsString()) {
        Fixture.Environment.block_prev_randao =
            parseBytes32(Env["currentRandom"].GetString());
      }
    }

    if (TestCase.HasMember("transaction")) {
      Fixture.Transaction = std::make_unique<rapidjson::Document>();
      Fixture.Transaction->CopyFrom(TestCase["transaction"],
                                    Fixture.Transaction->GetAllocator());

      const rapidjson::Value &Transaction = TestCase["transaction"];
      if (Transaction.HasMember("gasPrice") &&
          Transaction["gasPrice"].IsString()) {
        // Legacy transaction format
        Fixture.Environment.tx_gas_price =
            parseUint256(Transaction["gasPrice"].GetString());
      } else if (Transaction.HasMember("maxFeePerGas") &&
                 Transaction["maxFeePerGas"].IsString() &&
                 Transaction.HasMember("maxPriorityFeePerGas") &&
                 Transaction["maxPriorityFeePerGas"].IsString()) {
        // EIP-1559 transaction format
        // For EIP-1559, tx_gas_price should be the effective gas price:
        // min(maxFeePerGas, baseFee + maxPriorityFeePerGas)
        // However, since we don't know baseFee at parsing time, we use
        // maxFeePerGas
        // The actual effective price calculation is done during execution
        Fixture.Environment.tx_gas_price =
            parseUint256(Transaction["maxFeePerGas"].GetString());
      }
    }

    if (TestCase.HasMember("post")) {
      Fixture.Post = std::make_unique<rapidjson::Document>();
      Fixture.Post->CopyFrom(TestCase["post"], Fixture.Post->GetAllocator());
    }

    Fixtures.push_back(std::move(Fixture));
  }

  return Fixtures;
}

ForkPostResult parseForkPostResult(const rapidjson::Value &PostResult) {
  ForkPostResult Result;

  if (PostResult.HasMember("hash") && PostResult["hash"].IsString()) {
    Result.ExpectedHash = PostResult["hash"].GetString();
  }

  if (PostResult.HasMember("logs") && PostResult["logs"].IsString()) {
    Result.ExpectedLogs = PostResult["logs"].GetString();
  }

  if (PostResult.HasMember("expectException") &&
      PostResult["expectException"].IsString()) {
    Result.ExpectedException = PostResult["expectException"].GetString();
  }

  if (PostResult.HasMember("txbytes") && PostResult["txbytes"].IsString()) {
    Result.ExpectedTxBytes = parseHexData(PostResult["txbytes"].GetString());
  }

  if (PostResult.HasMember("indexes") && PostResult["indexes"].IsObject()) {
    const rapidjson::Value &Indexes = PostResult["indexes"];

    if (Indexes.HasMember("data") && Indexes["data"].IsNumber()) {
      Result.Indexes.Data = Indexes["data"].GetUint();
    }

    if (Indexes.HasMember("gas") && Indexes["gas"].IsNumber()) {
      Result.Indexes.Gas = Indexes["gas"].GetUint();
    }

    if (Indexes.HasMember("value") && Indexes["value"].IsNumber()) {
      Result.Indexes.Value = Indexes["value"].GetUint();
    }
  }

  if (PostResult.HasMember("state") && PostResult["state"].IsObject()) {
    Result.ExpectedState = std::make_shared<rapidjson::Document>();
    Result.ExpectedState->CopyFrom(PostResult["state"],
                                   Result.ExpectedState->GetAllocator());
  }

  return Result;
}

ParsedTransaction
createTransactionFromIndex(const rapidjson::Document &Transaction,
                           const ForkPostResult &Result) {
  ParsedTransaction PT;
  PT.TxContext = {};
  PT.Message = std::make_unique<evmc_message>();
  PT.Message->kind = EVMC_CALL;
  PT.Message->flags = 0;
  PT.Message->depth = 0;

  if (Transaction.HasMember("sender") && Transaction["sender"].IsString()) {
    PT.Message->sender = parseAddress(Transaction["sender"].GetString());
  }

  bool IsCreateTx = true;
  if (Transaction.HasMember("to") && Transaction["to"].IsString()) {
    std::string ToStr = Transaction["to"].GetString();
    std::string Stripped = stripHexPrefix(ToStr);
    if (!ToStr.empty() && !Stripped.empty()) {
      PT.Message->recipient = parseAddress(ToStr);
      IsCreateTx = false;
    }
  } else if (Transaction.HasMember("to") && Transaction["to"].IsNull()) {
    IsCreateTx = true;
  }

  PT.Message->kind = IsCreateTx ? EVMC_CREATE : EVMC_CALL;

  if (Transaction.HasMember("gasLimit") && Transaction["gasLimit"].IsArray()) {
    const rapidjson::Value &GasArray = Transaction["gasLimit"];
    if (Result.Indexes.Gas < GasArray.Size()) {
      std::string GasStr =
          stripHexPrefix(GasArray[Result.Indexes.Gas].GetString());
      PT.Message->gas = static_cast<int64_t>(std::stoull(GasStr, nullptr, 16));
    }
  }

  if (Transaction.HasMember("value") && Transaction["value"].IsArray()) {
    const rapidjson::Value &ValueArray = Transaction["value"];
    if (Result.Indexes.Value < ValueArray.Size()) {
      PT.Message->value =
          parseUint256(ValueArray[Result.Indexes.Value].GetString());
    }
  }

  if (Transaction.HasMember("data") && Transaction["data"].IsArray()) {
    const rapidjson::Value &DataArray = Transaction["data"];
    if (Result.Indexes.Data < DataArray.Size()) {
      PT.CallData = parseHexData(DataArray[Result.Indexes.Data].GetString());
    }
  }

  PT.Message->input_data = PT.CallData.data();
  PT.Message->input_size = PT.CallData.size();

  if (Transaction.HasMember("accessLists") &&
      Transaction["accessLists"].IsArray()) {
    const rapidjson::Value &AccessListsArray = Transaction["accessLists"];
    if (Result.Indexes.Data < AccessListsArray.Size()) {
      const rapidjson::Value &AccessListForIndex =
          AccessListsArray[Result.Indexes.Data];
      if (AccessListForIndex.IsArray()) {
        for (rapidjson::SizeType I = 0; I < AccessListForIndex.Size(); ++I) {
          const rapidjson::Value &Entry = AccessListForIndex[I];
          if (!Entry.IsObject()) {
            continue;
          }

          AccessListEntry ALE;
          if (Entry.HasMember("address") && Entry["address"].IsString()) {
            ALE.Address = parseAddress(Entry["address"].GetString());
          }

          if (Entry.HasMember("storageKeys") &&
              Entry["storageKeys"].IsArray()) {
            const rapidjson::Value &StorageKeys = Entry["storageKeys"];
            for (rapidjson::SizeType J = 0; J < StorageKeys.Size(); ++J) {
              if (StorageKeys[J].IsString()) {
                ALE.StorageKeys.push_back(
                    parseBytes32(StorageKeys[J].GetString()));
              }
            }
          }

          PT.AccessList.push_back(std::move(ALE));
        }
      }
    }
  }

  return PT;
}

} // namespace zen::evm_test_utils
