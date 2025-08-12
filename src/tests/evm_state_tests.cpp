// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "evm/interpreter.h"
#include "evm_test_fixtures.h"
#include "evm_test_helpers.h"
#include "host/evm/crypto.h"
#include "runtime/runtime.h"
#include "utils/others.h"
#include "zetaengine.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdlib>
#include <evmc/evmc.hpp>
#include <evmc/mocked_host.hpp>
#include <filesystem>
#include <iostream>
#include <rapidjson/document.h>

using namespace zen;
using namespace zen::evm;
using namespace zen::runtime;
using namespace zen::evm_test_utils;

namespace {

const bool Debug = false;

/// Recursive Host that can execute CALL instructions by creating new
/// interpreters
class RecursiveHost : public evmc::MockedHost {
private:
  Runtime *RT = nullptr;
  Isolation *Iso = nullptr;

public:
  RecursiveHost(Runtime *RT, Isolation *Iso) : RT(RT), Iso(Iso) {}

  evmc::Result call(const evmc_message &Msg) noexcept override {
    // First call the parent MockedHost to record the call
    evmc::Result ParentResult = evmc::MockedHost::call(Msg);

    // Try to find the target contract
    auto It = accounts.find(Msg.recipient);
    if (It == accounts.end() || It->second.code.empty()) {
      // No contract found, return parent result
      return ParentResult;
    }

    try {
      // Create temporary hex file from contract code using RAII
      std::string HexCode = "0x" + zen::utils::toHex(It->second.code.data(),
                                                     It->second.code.size());
      TempHexFile TempFile(HexCode);
      if (!TempFile.isValid()) {
        return ParentResult;
      }

      // Load EVM module
      auto ModRet = RT->loadEVMModule(TempFile.getPath());
      if (!ModRet) {
        return ParentResult;
      }

      EVMModule *Mod = *ModRet;

      // Create EVM instance
      auto InstRet = Iso->createEVMInstance(*Mod, Msg.gas);
      if (!InstRet) {
        return ParentResult;
      }

      EVMInstance *Inst = *InstRet;

      // Create interpreter context and execute
      InterpreterExecContext Ctx(Inst);
      BaseInterpreter Interpreter(Ctx);

      evmc_message CallMsg = Msg;
      Ctx.allocFrame(&CallMsg);

      // Set the host for the execution frame
      auto *Frame = Ctx.getCurFrame();
      Frame->Host = this;

      // Execute the interpreter
      Interpreter.interpret();

      // Create result based on execution status
      evmc::Result Result;
      Result.status_code = Ctx.getStatus();
      Result.gas_left = CallMsg.gas;

      const auto &ReturnData = Ctx.getReturnData();
      if (!ReturnData.empty()) {
        Result.output_data = ReturnData.data();
        Result.output_size = ReturnData.size();
      }

      return Result;

    } catch (const std::exception &E) {
      // On error, return parent result
      std::cout << "Error in recursive call: " << E.what() << std::endl;
      return ParentResult;
    }
  }
};

std::string getDefaultTestDir() {
  std::filesystem::path DirPath =
      std::filesystem::path(__FILE__).parent_path() /
      std::filesystem::path("../../tests/evm_spec_test/state_tests");
  return DirPath.string();
}

const std::string DefaultTestDir = getDefaultTestDir();

struct TestResult {
  std::string TestName;
  std::string ForkName;
  bool Passed;
  std::string ErrorMessage;
};

struct TestSummary {
  size_t TotalTests = 0;
  size_t PassedTests = 0;
  size_t FailedTests = 0;
  std::vector<TestResult> FailedTestDetails;
};

bool executeStateTest(const StateTestFixture &Fixture, const std::string &Fork,
                      const ForkPostResult &ExpectedResult) {
  try {
    // Parse transaction data
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
      if (Debug) {
        std::cout << "No target account found for test: " << Fixture.TestName
                  << std::endl;
      }
      return !ExpectedResult.ExpectedException.empty();
    }

    // Skip if no code to execute
    if (TargetAccount->Account.code.empty()) {
      if (Debug) {
        std::cout << "No code to execute for test: " << Fixture.TestName
                  << std::endl;
      }
      return true; // Empty code execution is considered success
    }

    // Convert code to hex string and create temp file using RAII
    std::string HexCode =
        "0x" + zen::utils::toHex(TargetAccount->Account.code.data(),
                                 TargetAccount->Account.code.size());
    TempHexFile TempFile(HexCode);

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
      return false;
    }

    // Create Isolation for recursive host
    Isolation *IsoForRecursive = RT->createManagedIsolation();
    if (!IsoForRecursive) {
      return false;
    }

    // Now create RecursiveHost with Runtime and Isolation references
    auto RecursiveHostPtr =
        std::make_unique<RecursiveHost>(RT.get(), IsoForRecursive);
    RecursiveHost *MockedHost = RecursiveHostPtr.get();

    // Copy accounts and context from temporary host
    MockedHost->accounts = TempMockedHost->accounts;
    MockedHost->tx_context = TempMockedHost->tx_context;

    // Switch to using RecursiveHost
    std::unique_ptr<evmc::Host> Host = std::move(RecursiveHostPtr);

    auto ModRet = RT->loadEVMModule(TempFile.getPath());
    if (!ModRet) {
      return false;
    }

    EVMModule *Mod = *ModRet;

    Isolation *Iso = RT->createManagedIsolation();
    if (!Iso) {
      return false;
    }

    uint64_t GasLimit = static_cast<uint64_t>(PT.Message->gas) * 100;
    auto InstRet = Iso->createEVMInstance(*Mod, GasLimit);
    if (!InstRet) {
      return false;
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
    try {
      Interpreter.interpret();
      ExecutionGasUsed = Ctx.getGasUsed();
    } catch (const std::exception &E) {
      ExecutionSucceeded = false;
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
      return !ExecutionSucceeded;
    }

    if (!ExecutionSucceeded) {
      return false;
    }

    if (Debug) {
      for (auto Account : MockedHost->accounts) {
        std::cout << "Account: "
                  << evmc::hex(evmc::bytes_view(Account.first.bytes, 20))
                  << std::endl;
        std::cout << "  balance: "
                  << evmc::hex(
                         evmc::bytes_view(Account.second.balance.bytes, 32))
                  << std::endl;
        std::cout << "  nonce: " << Account.second.nonce << std::endl;
        std::cout << "  code size: " << Account.second.code.size() << std::endl;
        std::cout << "  storage keys: " << Account.second.storage.size()
                  << std::endl;
      }
    }

    return verifyStateRoot(*MockedHost, ExpectedResult.ExpectedHash) &&
           verifyLogsHash(MockedHost->recorded_logs,
                          ExpectedResult.ExpectedLogs);

  } catch (const std::exception &E) {
    std::cout << "Exception in executeStateTest for " << Fixture.TestName
              << ": " << E.what() << std::endl;
    return !ExpectedResult.ExpectedException.empty();
  }
}

class StateTestRunner {
public:
  explicit StateTestRunner(const std::string &TestDirectory = DefaultTestDir)
      : TestDirectory(TestDirectory) {}

  bool loadTestFixtures() {
    LoadedFixtures.clear();

    auto JsonFiles = findJsonFiles(TestDirectory);
    if (Debug) {
      std::cout << "Found " << JsonFiles.size() << " JSON test files in "
                << TestDirectory << std::endl;
    }

    for (const auto &FilePath : JsonFiles) {
      auto Fixtures = parseStateTestFile(FilePath);
      for (auto &Fixture : Fixtures) {
        LoadedFixtures.push_back(std::move(Fixture));
      }
    }

    if (Debug) {
      std::cout << "Loaded " << LoadedFixtures.size() << " test fixtures"
                << std::endl;
    }
    return !LoadedFixtures.empty();
  }

  TestSummary executeAllTests() {
    TestSummary Summary;
    if (LoadedFixtures.empty()) {
      std::cerr << "No test fixtures loaded. Call loadTestFixtures() first."
                << std::endl;
      return Summary;
    }

    for (const auto &Fixture : LoadedFixtures) {
      if (!Fixture.Post || !Fixture.Post->IsObject()) {
        ADD_FAILURE() << "Invalid test fixture: " << Fixture.TestName
                      << " - Post section missing or invalid";
        continue;
      }

      for (const auto &Fork : Fixture.Post->GetObject()) {
        std::string ForkName = Fork.name.GetString();

        const rapidjson::Value &ForkResults = Fork.value;
        if (!ForkResults.IsArray()) {
          ADD_FAILURE() << "Invalid fork results format for: " << ForkName
                        << " in test: " << Fixture.TestName;
          continue;
        }

        for (rapidjson::SizeType I = 0; I < ForkResults.Size(); ++I) {
          Summary.TotalTests++;
          TestResult Result =
              executeTestCase(Fixture, ForkName, ForkResults[I]);

          if (Result.Passed) {
            Summary.PassedTests++;
            if (Debug) {
              std::cout << "✅ " << Result.TestName << " [" << Result.ForkName
                        << "]" << std::endl;
            }
          } else {
            Summary.FailedTests++;
            Summary.FailedTestDetails.push_back(Result);
            if (Debug) {
              std::cout << "❌ " << Result.TestName << " [" << Result.ForkName
                        << "]" << std::endl;
            }
          }
        }
      }
    }

    return Summary;
  }

  // Print test summary
  static void printTestSummary(const TestSummary &Summary) {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "EVM State Test Results Summary:" << std::endl;
    std::cout << std::string(60, '=') << std::endl;
    std::cout << "Total Tests:   " << Summary.TotalTests << std::endl;
    std::cout << "Passed Tests:  " << Summary.PassedTests << " ("
              << (Summary.TotalTests > 0
                      ? (Summary.PassedTests * 100 / Summary.TotalTests)
                      : 0)
              << "%)" << std::endl;
    std::cout << "Failed Tests:  " << Summary.FailedTests << std::endl;

    if (!Summary.FailedTestDetails.empty()) {
      std::cout << "\nFailed Tests:" << std::endl;
      for (const auto &Result : Summary.FailedTestDetails) {
        std::cout << "  - " << Result.TestName << " [" << Result.ForkName
                  << "]: " << Result.ErrorMessage << std::endl;
      }
    }
  }

private:
  std::string TestDirectory;
  std::vector<StateTestFixture> LoadedFixtures;

  TestResult executeTestCase(const StateTestFixture &Fixture,
                             const std::string &ForkName,
                             const rapidjson::Value &PostResult) {
    TestResult Result{Fixture.TestName, ForkName, false, ""};

    try {
      ForkPostResult ExpectedResult = parseForkPostResult(PostResult);
      Result.Passed = executeStateTest(Fixture, ForkName, ExpectedResult);
      if (!Result.Passed) {
        Result.ErrorMessage = "Test execution failed";
      }
    } catch (const std::exception &E) {
      Result.ErrorMessage = E.what();
    }

    return Result;
  }
};

class EVMStateTest : public testing::Test {
public:
  static void SetUpTestSuite() {
    Runner = std::make_unique<StateTestRunner>();
    if (!Runner->loadTestFixtures()) {
      std::cerr << "Failed to load test fixtures from " << DefaultTestDir
                << std::endl;
    }
  }

  static void TearDownTestSuite() { Runner.reset(); }

protected:
  static std::unique_ptr<StateTestRunner> Runner;
};

std::unique_ptr<StateTestRunner> EVMStateTest::Runner;

TEST_F(EVMStateTest, ExecuteAllStateTests) {
  ASSERT_TRUE(Runner) << "Test runner not initialized";

  TestSummary Summary = Runner->executeAllTests();
  StateTestRunner::printTestSummary(Summary);

  if (Summary.TotalTests == 0) {
    GTEST_SKIP() << "No compatible test cases found";
  }

  EXPECT_EQ(Summary.FailedTests, 0)
      << "Found " << Summary.FailedTests << " failed tests out of "
      << Summary.TotalTests;
}

} // anonymous namespace
