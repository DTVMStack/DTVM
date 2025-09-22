// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "evm/interpreter.h"
#include "evm_test_fixtures.h"
#include "evm_test_helpers.h"
#include "evm_test_host.hpp"
#include "host/evm/crypto.h"
#include "runtime/runtime.h"
#include "utils/others.h"
#include "zetaengine.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <evmc/evmc.hpp>
#include <evmc/mocked_host.hpp>
#include <filesystem>
#include <iostream>
#include <rapidjson/document.h>
#include <string>
#include <vector>

using namespace zen;
using namespace zen::evm;
using namespace zen::runtime;
using namespace zen::evm_test_utils;

namespace {

const bool Debug = false;

std::string getDefaultTestDir() {
  std::filesystem::path DirPath =
      std::filesystem::path(__FILE__).parent_path() /
      std::filesystem::path("../../tests/evm_spec_test/state_tests");
  return DirPath.string();
}

const std::string DefaultTestDir = getDefaultTestDir();

struct ExecutionResult {
  bool Passed = false;
  std::string ErrorMessage;
};

ExecutionResult executeStateTest(const StateTestFixture &Fixture,
                                 const std::string &Fork,
                                 const ForkPostResult &ExpectedResult) {
  auto makeFailure = [&](const std::string &Msg) {
    return ExecutionResult{false, Msg};
  };

  try {
    ParsedTransaction PT =
        createTransactionFromIndex(*Fixture.Transaction, ExpectedResult);

    // Find the target account (contract to call)
    const ParsedAccount *TargetAccount = nullptr;
    for (const auto &PA : Fixture.PreState) {
      if (std::memcmp(PA.Address.bytes, PT.Message->recipient.bytes, 20) == 0) {
        TargetAccount = &PA;
        break;
      }
    }

    if (!TargetAccount) {
      if (!ExpectedResult.ExpectedException.empty()) {
        return {true, {}};
      }
      if (Debug) {
        std::cout << "No target account found for test: " << Fixture.TestName
                  << std::endl;
      }
      return makeFailure(
          "Target account " +
          evmc::hex(evmc::bytes_view(PT.Message->recipient.bytes, 20)) +
          " not present in pre-state for " + Fixture.TestName + " (" + Fork +
          ")");
    }

    // Skip if no code to execute
    if (TargetAccount->Account.code.empty()) {
      if (Debug) {
        std::cout << "No code to execute for test: " << Fixture.TestName
                  << std::endl;
      }
      return {true, {}};
    }

    // Convert code to hex string and create temp file using RAII
    std::string HexCode =
        "0x" + zen::utils::toHex(TargetAccount->Account.code.data(),
                                 TargetAccount->Account.code.size());
    TempHexFile TempFile(HexCode);
    if (!TempFile.isValid()) {
      return makeFailure("Failed to materialize temp bytecode file for " +
                         Fixture.TestName + " (" + Fork + ")");
    }

    RuntimeConfig Config;
    Config.Mode = common::RunMode::InterpMode;

    // Create temporary MockedHost first for Runtime creation
    auto TempMockedHost = std::make_unique<evmc::MockedHost>();
    TempMockedHost->tx_context = Fixture.Environment;

    for (const auto &PA : Fixture.PreState) {
      addAccountToMockedHost(*TempMockedHost, PA.Address, PA.Account);
    }

    auto RT = Runtime::newEVMRuntime(Config, TempMockedHost.get());
    if (!RT) {
      return makeFailure("Failed to create EVM runtime for " +
                         Fixture.TestName + " (" + Fork + ")");
    }

    // Create Isolation for the mocked host
    Isolation *IsoForRecursive = RT->createManagedIsolation();
    if (!IsoForRecursive) {
      return makeFailure("Failed to create isolation for recursive host in " +
                         Fixture.TestName + " (" + Fork + ")");
    }

    // Now create ZenMockedEVMHost with Runtime and Isolation references
    auto HostPtr =
        std::make_unique<ZenMockedEVMHost>(RT.get(), IsoForRecursive);
    ZenMockedEVMHost *MockedHost = HostPtr.get();

    // Copy accounts and context from temporary host
    MockedHost->accounts = TempMockedHost->accounts;
    MockedHost->tx_context = TempMockedHost->tx_context;

    auto ModRet = RT->loadEVMModule(TempFile.getPath());
    if (!ModRet) {
      return makeFailure("Failed to load module for " + Fixture.TestName +
                         " (" + Fork + ")");
    }

    EVMModule *Mod = *ModRet;

    Isolation *Iso = RT->createManagedIsolation();
    if (!Iso) {
      return makeFailure("Failed to create execution isolation for " +
                         Fixture.TestName + " (" + Fork + ")");
    }

    uint64_t GasLimit = static_cast<uint64_t>(PT.Message->gas) * 100;
    auto InstRet = Iso->createEVMInstance(*Mod, GasLimit);
    if (!InstRet) {
      return makeFailure("Failed to create interpreter instance for " +
                         Fixture.TestName + " (" + Fork + ")");
    }

    EVMInstance *Inst = *InstRet;

    InterpreterExecContext Ctx(Inst);
    BaseInterpreter Interpreter(Ctx);

    evmc_message Msg = *PT.Message;
    Ctx.allocFrame(&Msg);

    // Set the host for the execution frame
    auto *Frame = Ctx.getCurFrame();
    Frame->Host = MockedHost;

    // Update transaction-level state before execution
    evmc::address Sender = Msg.sender;
    auto &SenderAccount = MockedHost->accounts[Sender];

    // 1. Increment nonce
    SenderAccount.nonce++;

    // 2. Handle value transfer manually (MockedHost doesn't do this
    // automatically)
    intx::uint256 TransferValue = intx::be::load<intx::uint256>(Msg.value);
    if (TransferValue != 0) {
      // Subtract value from sender balance using intx arithmetic
      intx::uint256 SenderBalance =
          intx::be::load<intx::uint256>(SenderAccount.balance);
      intx::uint256 NewSenderBalance = SenderBalance - TransferValue;
      SenderAccount.balance = intx::be::store<evmc::bytes32>(NewSenderBalance);

      // Add value to recipient balance using intx arithmetic
      evmc::address Recipient = Msg.recipient;
      auto &RecipientAccount = MockedHost->accounts[Recipient];
      intx::uint256 RecipientBalance =
          intx::be::load<intx::uint256>(RecipientAccount.balance);
      intx::uint256 NewRecipientBalance = RecipientBalance + TransferValue;
      RecipientAccount.balance =
          intx::be::store<evmc::bytes32>(NewRecipientBalance);
    }

    bool ExecutionSucceeded = true;
    uint64_t ExecutionGasUsed = 0;
    std::string ExecutionError;

    try {
      Interpreter.interpret();
      ExecutionGasUsed = Ctx.getGasUsed();
    } catch (const std::exception &E) {
      ExecutionSucceeded = false;
      ExecutionError = E.what();
      std::cout << "Execution failed for " << Fixture.TestName << ": "
                << E.what() << std::endl;
    }

    if (Debug) {
      std::cout << "ExecutionSucceeded: " << ExecutionSucceeded << std::endl;
      std::cout << "ExecutionGasUsed: " << ExecutionGasUsed << std::endl;
    }
    // 3. Deduct gas cost after execution (gas_used * gas_price)
    if (ExecutionSucceeded) {
      intx::uint256 GasPrice256 =
          intx::be::load<intx::uint256>(MockedHost->tx_context.tx_gas_price);
      uint64_t GasPrice =
          static_cast<uint64_t>(GasPrice256 & 0xFFFFFFFFFFFFFFFFULL);

      // Get base fee from tx_context
      intx::uint256 BaseFee256 =
          intx::be::load<intx::uint256>(MockedHost->tx_context.block_base_fee);
      uint64_t BaseFee =
          static_cast<uint64_t>(BaseFee256 & 0xFFFFFFFFFFFFFFFFULL);

      // EIP-1559: Calculate priority fee (tip) for coinbase
      // Priority fee = min(maxPriorityFeePerGas, maxFeePerGas - baseFee)
      uint64_t PriorityFee = 0;

      // Check if this is an EIP-1559 transaction by looking for
      // maxPriorityFeePerGas
      const rapidjson::Value &Transaction = *Fixture.Transaction;
      if (Transaction.HasMember("maxPriorityFeePerGas") &&
          Transaction["maxPriorityFeePerGas"].IsString()) {
        // EIP-1559 transaction
        evmc::uint256be MaxPriorityFee256be =
            parseUint256(Transaction["maxPriorityFeePerGas"].GetString());
        intx::uint256 MaxPriorityFee256 =
            intx::be::load<intx::uint256>(MaxPriorityFee256be);
        uint64_t MaxPriorityFeePerGas =
            static_cast<uint64_t>(MaxPriorityFee256 & 0xFFFFFFFFFFFFFFFFULL);
        uint64_t MaxFeeMinusBase = GasPrice > BaseFee ? GasPrice - BaseFee : 0;
        PriorityFee = std::min(MaxPriorityFeePerGas, MaxFeeMinusBase);
      } else {
        // Legacy transaction: all gas price goes to miner minus base fee
        PriorityFee = GasPrice > BaseFee ? GasPrice - BaseFee : 0;
      }

      uint64_t TotalGasCost = ExecutionGasUsed * GasPrice;
      uint64_t CoinBaseGas = ExecutionGasUsed * PriorityFee;

      // Subtract gas cost from sender balance using intx arithmetic
      intx::uint256 SenderBalance =
          intx::be::load<intx::uint256>(SenderAccount.balance);
      intx::uint256 NewSenderBalance =
          SenderBalance - intx::uint256(TotalGasCost);
      SenderAccount.balance = intx::be::store<evmc::bytes32>(NewSenderBalance);

      // Add gas cost to coinbase balance
      evmc::address Coinbase = MockedHost->tx_context.block_coinbase;
      auto &CoinbaseAccount = MockedHost->accounts[Coinbase];

      // Set correct codehash for newly created coinbase account (empty code
      // hash)
      std::vector<uint8_t> EmptyCode;
      auto EmptyCodeHash = zen::host::evm::crypto::keccak256(EmptyCode);
      std::memcpy(CoinbaseAccount.codehash.bytes, EmptyCodeHash.data(), 32);

      // Add coinbase gas to coinbase balance using intx arithmetic
      intx::uint256 CurrentBalance =
          intx::be::load<intx::uint256>(CoinbaseAccount.balance);
      intx::uint256 NewBalance = CurrentBalance + intx::uint256(CoinBaseGas);
      CoinbaseAccount.balance = intx::be::store<evmc::bytes32>(NewBalance);
    }

    if (!ExpectedResult.ExpectedException.empty()) {
      if (ExecutionSucceeded) {
        return makeFailure("Expected exception '" +
                           ExpectedResult.ExpectedException + "' for " +
                           Fixture.TestName + " (" + Fork +
                           ") but execution succeeded");
      }
      return {true, {}};
    }

    if (!ExecutionSucceeded) {
      return makeFailure("Execution threw exception for " + Fixture.TestName +
                         " (" + Fork + "): " + ExecutionError);
    }

    std::string ActualStateRoot = calculateStateRootHash(*MockedHost);
    if (ActualStateRoot != ExpectedResult.ExpectedHash) {
      return makeFailure("State root mismatch for " + Fixture.TestName + " (" +
                         Fork + ") expected " + ExpectedResult.ExpectedHash +
                         " got " + ActualStateRoot);
    }

    std::string ActualLogsHash =
        "0x" + calculateLogsHash(MockedHost->recorded_logs);
    if (ActualLogsHash != ExpectedResult.ExpectedLogs) {
      return makeFailure("Logs hash mismatch for " + Fixture.TestName + " (" +
                         Fork + ") expected " + ExpectedResult.ExpectedLogs +
                         " got " + ActualLogsHash);
    }

    return {true, {}};

  } catch (const std::exception &E) {
    return makeFailure("Exception in executeStateTest for " + Fixture.TestName +
                       " (" + Fork + "): " + E.what());
  }
}

struct StateTestCaseParam {
  const StateTestFixture *Fixture = nullptr;
  std::string ForkName;
  ForkPostResult Expected;
  bool Valid = false;
  std::string LoadError;
  std::string CaseName;
};

const std::vector<StateTestFixture> &getStateFixtures() {
  static std::vector<StateTestFixture> Fixtures = [] {
    std::vector<StateTestFixture> Loaded;
    auto JsonFiles = findJsonFiles(DefaultTestDir);
    if (Debug) {
      std::cout << "Found " << JsonFiles.size() << " JSON test files in "
                << DefaultTestDir << std::endl;
    }

    for (const auto &FilePath : JsonFiles) {
      auto FixturesFromFile = parseStateTestFile(FilePath);
      for (auto &Fixture : FixturesFromFile) {
        if (Debug) {
          std::cout << "Loaded fixture: " << Fixture.TestName << std::endl;
        }
        Loaded.push_back(std::move(Fixture));
      }
    }

    if (Debug) {
      std::cout << "Total fixtures loaded: " << Loaded.size() << std::endl;
    }

    return Loaded;
  }();

  return Fixtures;
}

const std::vector<StateTestCaseParam> &getStateTestParams() {
  static std::vector<StateTestCaseParam> Params = [] {
    std::vector<StateTestCaseParam> Cases;
    const auto &Fixtures = getStateFixtures();

    size_t CaseCounter = 0;

    for (const auto &Fixture : Fixtures) {
      if (!Fixture.Post || !Fixture.Post->IsObject()) {
        StateTestCaseParam Param;
        Param.Fixture = &Fixture;
        Param.Valid = false;
        Param.LoadError = "Invalid test fixture: " + Fixture.TestName +
                          " - Post section missing or invalid";
        Param.CaseName =
            Fixture.TestName + "_InvalidPost_" + std::to_string(CaseCounter++);
        Cases.push_back(std::move(Param));
        continue;
      }

      for (const auto &Fork : Fixture.Post->GetObject()) {
        std::string ForkName = Fork.name.GetString();

        const rapidjson::Value &ForkResults = Fork.value;
        if (!ForkResults.IsArray()) {
          StateTestCaseParam Param;
          Param.Fixture = &Fixture;
          Param.Valid = false;
          Param.LoadError = "Invalid fork results format for: " + ForkName +
                            " in test: " + Fixture.TestName;
          Param.CaseName = Fixture.TestName + "_" + ForkName +
                           "_InvalidResults_" + std::to_string(CaseCounter++);
          Cases.push_back(std::move(Param));
          continue;
        }

        for (rapidjson::SizeType I = 0; I < ForkResults.Size(); ++I) {
          try {
            ForkPostResult ExpectedResult = parseForkPostResult(ForkResults[I]);

            StateTestCaseParam Param;
            Param.Fixture = &Fixture;
            Param.ForkName = ForkName;
            Param.Expected = std::move(ExpectedResult);
            Param.Valid = true;
            Param.CaseName =
                Fixture.TestName + "_" + ForkName + "_" + std::to_string(I);
            Cases.push_back(std::move(Param));
          } catch (const std::exception &E) {
            StateTestCaseParam Param;
            Param.Fixture = &Fixture;
            Param.Valid = false;
            Param.LoadError = "Failed to parse post result " +
                              std::to_string(I) + " for fork " + ForkName +
                              " in test " + Fixture.TestName + ": " + E.what();
            Param.CaseName = Fixture.TestName + "_" + ForkName +
                             "_ParseError_" + std::to_string(CaseCounter++);
            Cases.push_back(std::move(Param));
          }
        }
      }
    }

    if (Debug) {
      std::cout << "Generated " << Cases.size() << " state test cases"
                << std::endl;
    }

    return Cases;
  }();

  return Params;
}

std::string sanitizeTestName(const std::string &Name) {
  std::string Result;
  Result.reserve(Name.size());
  for (char C : Name) {
    if (std::isalnum(static_cast<unsigned char>(C))) {
      Result.push_back(C);
    } else {
      Result.push_back('_');
    }
  }
  if (Result.empty()) {
    Result = "Case";
  }
  if (std::isdigit(static_cast<unsigned char>(Result.front()))) {
    Result.insert(Result.begin(), '_');
  }
  return Result;
}

class EVMStateTest : public testing::TestWithParam<StateTestCaseParam> {};

TEST_P(EVMStateTest, ExecutesStateTest) {
  const auto &Param = GetParam();

  if (!Param.Valid) {
    FAIL() << Param.LoadError;
    return;
  }

  ASSERT_NE(Param.Fixture, nullptr);

  ExecutionResult Result =
      executeStateTest(*Param.Fixture, Param.ForkName, Param.Expected);

  EXPECT_TRUE(Result.Passed) << Result.ErrorMessage;
}

INSTANTIATE_TEST_SUITE_P(ExecuteAllStateTests, EVMStateTest,
                         ::testing::ValuesIn(getStateTestParams()),
                         [](const auto &Info) {
                           return sanitizeTestName(Info.param.CaseName);
                         });

} // anonymous namespace
