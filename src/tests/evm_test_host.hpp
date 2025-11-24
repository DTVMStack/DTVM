// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef ZEN_TESTS_EVM_TEST_HOST_HPP
#define ZEN_TESTS_EVM_TEST_HOST_HPP

#include "evm/evm.h"
#include "evm/interpreter.h"
#include "evmc/mocked_host.hpp"
#include "host/evm/crypto.h"
#include "mpt/rlp_encoding.h"
#include "runtime/evm_instance.h"
#include "runtime/isolation.h"
#include "runtime/runtime.h"
#include "utils/logging.h"
#include <algorithm>
#include <atomic>
#include <cstring>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <vector>

using namespace zen;
using namespace zen::runtime;

namespace zen::evm {

/// Recursive Host that can execute CALL instructions by creating new
/// interpreters
class ZenMockedEVMHost : public evmc::MockedHost {
private:
  struct IsolationDeleter {
    Runtime *RT = nullptr;
    void operator()(Isolation *Iso) const {
      if (Iso && RT) {
        RT->deleteManagedIsolation(Iso);
      }
    }
  };
  using IsolationPtr = std::unique_ptr<Isolation, IsolationDeleter>;

  Runtime *RT = nullptr;
  std::vector<uint8_t> ReturnData;
  static inline std::atomic<uint64_t> ModuleCounter = 0;

public:
  struct AccountInitEntry {
    evmc::address Address{};
    evmc::MockedAccount Account{};
  };

  struct AccessListEntry {
    evmc::address Address;
    std::vector<evmc::bytes32> StorageKeys;
  };

  struct TransactionExecutionConfig {
    std::string ModuleName;
    const uint8_t *Bytecode = nullptr;
    size_t BytecodeSize = 0;
    evmc_message Message{};
    uint64_t GasLimit = 0;
    uint64_t GasLimitMultiplier = 1;
    std::optional<evmc::uint256be> MaxPriorityFeePerGas;
    std::vector<AccessListEntry> AccessList;
  };

  struct TransactionExecutionResult {
    bool Success = false; // indicates host infrastructure success
    uint64_t GasUsed = 0;
    uint64_t GasCharged = 0;
    uint64_t GasRefund = 0;
    int64_t RemainingGas = 0;
    evmc_status_code Status = EVMC_INTERNAL_ERROR;
    std::string ErrorMessage;
  };

  ZenMockedEVMHost() = default;

  void setRuntime(Runtime *NewRT) { RT = NewRT; }
  Runtime *getRuntime() const { return RT; }

  void loadInitialState(const evmc_tx_context &Context,
                        const std::vector<AccountInitEntry> &Accounts,
                        bool ClearExisting = true) {
    tx_context = Context;
    if (ClearExisting) {
      accounts.clear();
      recorded_logs.clear();
    }
    for (const auto &Entry : Accounts) {
      accounts[Entry.Address] = Entry.Account;
    }
  }

  TransactionExecutionResult
  executeTransaction(const TransactionExecutionConfig &Config) {
    TransactionExecutionResult Result;
    if (!RT) {
      Result.ErrorMessage = "Runtime is not attached to ZenMockedEVMHost";
      return Result;
    }
    if (!Config.Bytecode || Config.BytecodeSize == 0) {
      Result.ErrorMessage = "Bytecode buffer is empty";
      return Result;
    }

    uint64_t GasLimit = Config.GasLimit;
    if (GasLimit == 0) {
      if (Config.Message.gas <= 0) {
        Result.ErrorMessage = "Invalid gas provided in message";
        return Result;
      }
      GasLimit = static_cast<uint64_t>(Config.Message.gas);
    }
    if (Config.GasLimitMultiplier > 1) {
      if (GasLimit >
          std::numeric_limits<uint64_t>::max() / Config.GasLimitMultiplier) {
        Result.ErrorMessage = "Gas limit overflow detected";
        return Result;
      }
      GasLimit *= Config.GasLimitMultiplier;
    }

    // Process access list (EIP-2930): calculate intrinsic gas first
    constexpr uint64_t ACCESS_LIST_ADDRESS_COST = 2400;
    constexpr uint64_t ACCESS_LIST_STORAGE_KEY_COST = 1900;
    constexpr uint64_t TX_DATA_ZERO_GAS = 4;
    constexpr uint64_t TX_DATA_NON_ZERO_GAS = 16;
    uint64_t AccessListIntrinsicGas = 0;
    uint64_t TxDataIntrinsicGas = 0;

    for (const auto &AccessEntry : Config.AccessList) {
      AccessListIntrinsicGas += ACCESS_LIST_ADDRESS_COST;
      AccessListIntrinsicGas +=
          ACCESS_LIST_STORAGE_KEY_COST * AccessEntry.StorageKeys.size();
    }

    if (Config.Message.input_data && Config.Message.input_size > 0) {
      const uint8_t *Data = static_cast<const uint8_t *>(Config.Message.input_data);
      for (size_t I = 0; I < Config.Message.input_size; ++I) {
        TxDataIntrinsicGas += Data[I] == 0 ? TX_DATA_ZERO_GAS
                                            : TX_DATA_NON_ZERO_GAS;
      }
    }

    const uint64_t TotalIntrinsicGas = AccessListIntrinsicGas + TxDataIntrinsicGas;

    // Deduct access list intrinsic gas from available gas
    if (GasLimit < TotalIntrinsicGas) {
      Result.ErrorMessage = "Insufficient gas for intrinsic transaction costs";
      return Result;
    }
    uint64_t AvailableGas = GasLimit - TotalIntrinsicGas;

    uint64_t Counter = ModuleCounter++;
    std::string ModuleName = Config.ModuleName.empty()
                                 ? ("tx_exec_mod_" + std::to_string(Counter))
                                 : (Config.ModuleName + "_" +
                                    std::to_string(Counter));

    auto ModRet =
        RT->loadEVMModule(ModuleName, Config.Bytecode, Config.BytecodeSize);
    if (!ModRet) {
      Result.ErrorMessage = "Failed to load EVM module: " + ModuleName;
      return Result;
    }
    EVMModule *Mod = *ModRet;

    IsolationPtr Iso(nullptr, IsolationDeleter{RT});
    Iso.reset(RT->createManagedIsolation());
    if (!Iso) {
      Result.ErrorMessage = "Failed to create managed isolation";
      return Result;
    }

    auto InstRet = Iso->createEVMInstance(*Mod, AvailableGas);
    if (!InstRet) {
      Result.ErrorMessage = "Failed to create EVM instance for module " +
                            ModuleName;
      return Result;
    }
    EVMInstance *Inst = *InstRet;

    evmc_message Msg = Config.Message;
    Msg.gas = static_cast<int64_t>(AvailableGas);
    uint64_t OriginalGas = static_cast<uint64_t>(Inst->getGas());

    // Warm access list addresses and storage slots
    for (const auto &AccessEntry : Config.AccessList) {
      access_account(AccessEntry.Address);

      auto AccountIt = accounts.find(AccessEntry.Address);
      if (AccountIt != accounts.end()) {
        for (const auto &StorageKey : AccessEntry.StorageKeys) {
          auto &StorageSlot = AccountIt->second.storage[StorageKey];
          StorageSlot.access_status = EVMC_ACCESS_WARM;
        }
      }
    }

    if (!applyPreExecutionState(Msg, Result)) {
      return Result;
    }

    evmc::Result ExecResult{};
    try {
      RT->callEVMMain(*Inst, Msg, ExecResult);
    } catch (const std::exception &E) {
      Result.ErrorMessage = E.what();
      Result.Success = false;
      Result.Status = EVMC_INTERNAL_ERROR;
      Result.RemainingGas = Inst->getGas();
      ReturnData.clear();
      return Result;
    }

    Result.Status = ExecResult.status_code;
    Result.Success = true;
    Result.RemainingGas = Inst->getGas();
    if (ExecResult.output_data && ExecResult.output_size > 0) {
      ReturnData.assign(ExecResult.output_data,
                        ExecResult.output_data + ExecResult.output_size);
    } else {
      ReturnData.clear();
    }

    if (OriginalGas >= static_cast<uint64_t>(Result.RemainingGas)) {
      Result.GasUsed =
          OriginalGas - static_cast<uint64_t>(Result.RemainingGas);
    }

    // Add access list intrinsic gas to GasUsed (EIP-2930)
    Result.GasUsed += AccessListIntrinsicGas + TxDataIntrinsicGas;

    uint64_t GasRefund =
        static_cast<uint64_t>(std::max<int64_t>(0, Inst->getGasRefund()));
    uint64_t RefundLimit = Result.GasUsed / 5;
    Result.GasRefund = std::min(GasRefund, RefundLimit);
    Result.GasCharged =
        Result.GasUsed > Result.GasRefund ? Result.GasUsed - Result.GasRefund
                                          : 0;

    if (Result.GasCharged != 0) {
      settleGasCharges(Result.GasCharged, Config, Msg, Result);
    }

    return Result;
  }

  evmc::Result call(const evmc_message &Msg) noexcept override {
    if (!RT) {
      ZEN_LOG_ERROR("Runtime is not attached to ZenMockedEVMHost");
      return evmc::MockedHost::call(Msg);
    }
    if (Msg.kind == EVMC_CREATE || Msg.kind == EVMC_CREATE2) {
      return handleCreate(Msg);
    }
    evmc::Result ParentResult = evmc::MockedHost::call(Msg);

    // For CALLCODE and DELEGATECALL, code comes from code_address, not
    // recipient
    const evmc::address &CodeAddr =
        (Msg.kind == EVMC_CALLCODE || Msg.kind == EVMC_DELEGATECALL)
            ? Msg.code_address
            : Msg.recipient;

    auto It = accounts.find(CodeAddr);
    if (It == accounts.end() || It->second.code.empty()) {
      // No contract found, return parent result
      ZEN_LOG_DEBUG(
          "No contract found for code address {}, return parent result",
          evmc::hex(evmc::bytes_view(CodeAddr.bytes, 20)).c_str());
      return ParentResult;
    }

    try {
      const auto &ContractCode = It->second.code;
      if (ContractCode.empty()) {
        ZEN_LOG_DEBUG(
            "Contract code is empty for recipient {}",
            evmc::hex(evmc::bytes_view(Msg.recipient.bytes, 20)).c_str());
        return ParentResult;
      }
      uint64_t Counter = ModuleCounter++;
      std::string ModName =
          "evm_model_" + evmc::hex(evmc::bytes_view(Msg.recipient.bytes, 20)) +
          "_" + std::to_string(Counter);
      ;

      auto ModRet =
          RT->loadEVMModule(ModName, ContractCode.data(), ContractCode.size());
      if (!ModRet) {
        ZEN_LOG_ERROR("Failed to load EVM module: {}", ModName.c_str());
        return ParentResult;
      }

      EVMModule *Mod = *ModRet;

      IsolationPtr Iso(nullptr, IsolationDeleter{RT});
      Iso.reset(RT->createManagedIsolation());
      if (!Iso) {
        ZEN_LOG_ERROR("Failed to create isolation for module: {}",
                      ModName.c_str());
        return ParentResult;
      }

      // Create EVM instance
      auto InstRet = Iso->createEVMInstance(*Mod, Msg.gas);
      if (!InstRet) {
        ZEN_LOG_ERROR("Failed to create EVM instance for module: {}",
                      ModName.c_str());
        return ParentResult;
      }

      EVMInstance *Inst = *InstRet;

      evmc_message CallMsg = Msg;
      evmc::Result ExecResult{};

      try {
        RT->callEVMMain(*Inst, CallMsg, ExecResult);
      } catch (const std::exception &E) {
        ZEN_LOG_ERROR("Error in recursive call: {}", E.what());
        return ParentResult;
      }

      if (ExecResult.output_data && ExecResult.output_size > 0) {
        ReturnData.assign(ExecResult.output_data,
                          ExecResult.output_data + ExecResult.output_size);
      } else {
        ReturnData.clear();
      }
      int64_t RemainingGas = static_cast<int64_t>(Inst->getGas());
      int64_t GasRefund = static_cast<int64_t>(Inst->getGasRefund());
      return evmc::Result(ExecResult.status_code, RemainingGas, GasRefund,
                          ReturnData.empty() ? nullptr : ReturnData.data(),
                          ReturnData.size());

    } catch (const std::exception &E) {
      // On error, return parent result
      ZEN_LOG_ERROR("Error in recursive call: {}", E.what());
      return ParentResult;
    }
  }
  using hash256 = evmc::bytes32;
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
  evmc::address computeCreateAddress(const evmc::address &Sender,
                                     uint64_t SenderNonce) noexcept {
    static constexpr auto ADDRESS_SIZE = sizeof(Sender);

    std::vector<uint8_t> SenderBytes(Sender.bytes, Sender.bytes + ADDRESS_SIZE);
    auto EncodedSender = zen::evm::rlp::encodeString(SenderBytes);

    evmc_uint256be NonceUint256 = {};
    intx::be::store(NonceUint256.bytes, intx::uint256{SenderNonce});
    std::vector<uint8_t> NonceMinimalBytes = uint256beToBytes(NonceUint256);
    auto EncodedNonce = zen::evm::rlp::encodeString(NonceMinimalBytes);

    std::vector<std::vector<uint8_t>> RlpListItems = {EncodedSender,
                                                      EncodedNonce};
    auto EncodedList = zen::evm::rlp::encodeList(RlpListItems);

    const auto BaseHash = zen::host::evm::crypto::keccak256(EncodedList);
    evmc::address Addr;
    std::copy_n(&BaseHash.data()[BaseHash.size() - ADDRESS_SIZE], ADDRESS_SIZE,
                Addr.bytes);
    return Addr;
  }
  hash256 keccak256(evmc::bytes_view Data) noexcept {
    std::vector<uint8_t> Tmp(Data.begin(), Data.end());
    auto BytesVec = zen::host::evm::crypto::keccak256(Tmp);
    hash256 Result{};
    std::memcpy(Result.bytes, BytesVec.data(), sizeof(Result.bytes));
    return Result;
  }
  evmc::address computeCreate2Address(const evmc::address &Sender,
                                      const evmc::bytes32 &Salt,
                                      evmc::bytes_view InitCode) noexcept {
    const auto InitCodeHash = keccak256(InitCode);
    uint8_t Buffer[1 + sizeof(Sender) + sizeof(Salt) + sizeof(InitCodeHash)];
    static_assert(std::size(Buffer) == 85);
    auto *It = std::begin(Buffer);
    *It++ = 0xff;
    It = std::copy_n(Sender.bytes, sizeof(Sender), It);
    It = std::copy_n(Salt.bytes, sizeof(Salt), It);
    std::copy_n(InitCodeHash.bytes, sizeof(InitCodeHash), It);
    const auto BaseHash = keccak256({Buffer, std::size(Buffer)});
    evmc::address Addr;
    std::copy_n(&BaseHash.bytes[sizeof(BaseHash) - sizeof(Addr)], sizeof(Addr),
                Addr.bytes);
    return Addr;
  }
  bool isCreateCollision(const evmc::MockedAccount &Acc) const noexcept {
    if (Acc.nonce != 0)
      return true;
    if (Acc.codehash != EMPTY_CODE_HASH)
      return true;
    return false;
  }
  evmc_message prepareMessage(evmc_message Msg) noexcept {
    if (Msg.kind == EVMC_CREATE || Msg.kind == EVMC_CREATE2) {
      const auto &SenderAcc = accounts[Msg.sender];
      if (Msg.kind == EVMC_CREATE)
        Msg.recipient = computeCreateAddress(Msg.sender, SenderAcc.nonce);
      else if (Msg.kind == EVMC_CREATE2) {
        Msg.recipient = computeCreate2Address(Msg.sender, Msg.create2_salt,
                                              {Msg.input_data, Msg.input_size});
      }
    }
    return Msg;
  }
  evmc::Result handleCreate(const evmc_message &OrigMsg) noexcept {
    // 1 Calculate the contract address
    if (!RT) {
      ZEN_LOG_ERROR("Runtime is not attached to ZenMockedEVMHost");
      return evmc::Result{EVMC_FAILURE, OrigMsg.gas, 0, evmc::address{}};
    }
    evmc_message Msg = prepareMessage(OrigMsg);
    try {
      // 2 Check for address conflicts (if the address already exists and is not
      // empty, creation will fail)
      evmc::address NewAddr = Msg.recipient;
      auto It = accounts.find(NewAddr);
      if (It != accounts.end() && !isCreateCollision(It->second)) {
        ZEN_LOG_ERROR("Create collision at address {}",
                      evmc::hex(NewAddr).c_str());
        return evmc::Result{EVMC_FAILURE, Msg.gas, 0, NewAddr};
      }
      // Create EVM module and instance for the new contract
      uint64_t Counter = ModuleCounter++;
      std::string ModName =
          "evm_create_mod_" +
          evmc::hex(evmc::bytes_view(Msg.recipient.bytes, 20)) + "_" +
          std::to_string(Counter);
      auto ModRet = RT->loadEVMModule(ModName, Msg.input_data, Msg.input_size);
      if (!ModRet) {
        accounts.erase(NewAddr);
        ZEN_LOG_ERROR("Failed to load EVM module: {}", ModName.c_str());
        return evmc::Result{EVMC_FAILURE, Msg.gas, 0, NewAddr};
      }
      EVMModule *Mod = *ModRet;

      IsolationPtr Iso(nullptr, IsolationDeleter{RT});
      Iso.reset(RT->createManagedIsolation());
      if (!Iso) {
        accounts.erase(NewAddr);
        ZEN_LOG_ERROR("Failed to create isolation for module: {}",
                      ModName.c_str());
        return evmc::Result{EVMC_FAILURE, Msg.gas, 0, NewAddr};
      }

      auto InstRet = Iso->createEVMInstance(*Mod, Msg.gas);
      if (!InstRet) {
        accounts.erase(NewAddr);
        ZEN_LOG_ERROR("Failed to create EVM instance for module: {}",
                      ModName.c_str());
        return evmc::Result{EVMC_FAILURE, Msg.gas, 0, NewAddr};
      }

      EVMInstance *Inst = *InstRet;
      // 3 Create new account status
      auto &NewAcc = accounts[NewAddr];
      // TODO: Obtain Revision to initialize nounce
      //  NewAcc.nonce = (Inst->getRevision() >= EVMC_SPURIOUS_DRAGON) ? 1 : 0;
      NewAcc.nonce = 0;
      NewAcc.balance = evmc::bytes32{0};

      // 4 Transfer the balance (from the sender to the new account)
      auto &SenderAcc = accounts[Msg.sender];
      const auto Value = intx::be::load<intx::uint256>(Msg.value);
      intx::uint256 SenderBalance =
          intx::be::load<intx::uint256>(SenderAcc.balance);
      if (SenderBalance < Value) {
        ZEN_LOG_ERROR("Insufficient balance for CREATE: have {}, need {}",
                      SenderBalance, Value);
        return evmc::Result{EVMC_INSUFFICIENT_BALANCE, Msg.gas, 0, NewAddr};
      }
      SenderBalance -= Value;
      intx::uint256 NewAccBalance =
          intx::be::load<intx::uint256>(NewAcc.balance);
      NewAccBalance += Value;
      SenderAcc.balance = intx::be::store<evmc::bytes32>(SenderBalance);
      NewAcc.balance = intx::be::store<evmc::bytes32>(NewAccBalance);

      evmc_message CallMsg = Msg;
      evmc::Result ExecResult{};
      try {
        RT->callEVMMain(*Inst, CallMsg, ExecResult);
      } catch (const std::exception &E) {
        accounts.erase(NewAddr);
        ZEN_LOG_ERROR("Error in handleCreate execution: {}", E.what());
        return evmc::Result{EVMC_FAILURE, Msg.gas, 0, evmc::address{}};
      }

      if (ExecResult.output_data && ExecResult.output_size > 0) {
        ReturnData.assign(ExecResult.output_data,
                          ExecResult.output_data + ExecResult.output_size);
      } else {
        ReturnData.clear();
      }

      const int64_t RemainingGas = static_cast<int64_t>(Inst->getGas());
      const int64_t GasRefund =
          static_cast<int64_t>(Inst->getGasRefund());

      // 6 Deploy the contract code (the output is the runtime code)
      if (ExecResult.status_code != EVMC_SUCCESS) {
        accounts.erase(NewAddr);
        evmc::Result Failure(ExecResult.status_code, RemainingGas, GasRefund);
        Failure.create_address = NewAddr;
        return Failure;
      }
      if (!ReturnData.empty()) {
        if (ReturnData.size() > MAX_CODE_SIZE) {
          accounts.erase(NewAddr);
          evmc::Result Failure(EVMC_FAILURE, RemainingGas, GasRefund);
          Failure.create_address = NewAddr;
          return Failure;
        }
        NewAcc.code = evmc::bytes(ReturnData.data(), ReturnData.size());
        const std::vector<uint8_t> CodeHashVec =
            host::evm::crypto::keccak256(ReturnData);
        assert(CodeHashVec.size() == 32 && "Keccak256 hash must be 32 bytes");
        evmc::bytes32 CodeHash;
        std::memcpy(CodeHash.bytes, CodeHashVec.data(), 32);
        NewAcc.codehash = CodeHash;
      }
      // 7 Update the sender's nonce (for CREATE, the nonce must be incremented)
      if (Msg.kind == EVMC_CREATE) {
        SenderAcc.nonce++;
      }

      evmc::Result CreateResult(EVMC_SUCCESS, RemainingGas, GasRefund,
                                NewAcc.code.empty() ? nullptr
                                                    : NewAcc.code.data(),
                                NewAcc.code.size());
      CreateResult.create_address = NewAddr;
      return CreateResult;
    } catch (const std::exception &E) {
      ZEN_LOG_ERROR("Error in handleCreate: {}", E.what());
      return evmc::Result{EVMC_FAILURE, Msg.gas, 0, evmc::address{}};
    }
  }

private:
  static intx::uint256 toUint256Bytes(const evmc::bytes32 &Value) {
    return intx::be::load<intx::uint256>(Value);
  }

  static intx::uint256 toUint256BE(const evmc::uint256be &Value) {
    return intx::be::load<intx::uint256>(Value);
  }

  static evmc::bytes32 toBytes32(const intx::uint256 &Value) {
    return intx::be::store<evmc::bytes32>(Value);
  }

  void ensureAccountHasCodeHash(evmc::MockedAccount &Account) {
    if (Account.code.empty() &&
        std::memcmp(Account.codehash.bytes, EMPTY_CODE_HASH.bytes, 32) != 0) {
      Account.codehash = EMPTY_CODE_HASH;
    }
  }

  bool applyPreExecutionState(const evmc_message &Msg,
                              TransactionExecutionResult &Result) {
    auto &SenderAccount = accounts[Msg.sender];
    ensureAccountHasCodeHash(SenderAccount);
    SenderAccount.nonce++;

    intx::uint256 TransferValue = toUint256BE(Msg.value);
    if (TransferValue == 0) {
      return true;
    }

    auto &RecipientAccount = accounts[Msg.recipient];
    ensureAccountHasCodeHash(RecipientAccount);

    intx::uint256 SenderBalance = toUint256Bytes(SenderAccount.balance);
    intx::uint256 RecipientBalance = toUint256Bytes(RecipientAccount.balance);

    if (SenderBalance < TransferValue) {
      Result.Success = false;
      Result.ErrorMessage = "Insufficient balance for value transfer";
      return false;
    }

    SenderBalance -= TransferValue;
    RecipientBalance += TransferValue;

    SenderAccount.balance = toBytes32(SenderBalance);
    RecipientAccount.balance = toBytes32(RecipientBalance);
    return true;
  }

  void settleGasCharges(uint64_t GasCharged,
                        const TransactionExecutionConfig &Config,
                        const evmc_message &Msg,
                        TransactionExecutionResult &Result) {
    intx::uint256 GasPrice = toUint256BE(tx_context.tx_gas_price);
    intx::uint256 BaseFee = toUint256BE(tx_context.block_base_fee);
    intx::uint256 PriorityFee =
        GasPrice > BaseFee ? GasPrice - BaseFee : intx::uint256{0};

    if (Config.MaxPriorityFeePerGas) {
      intx::uint256 MaxPriority =
          toUint256BE(*Config.MaxPriorityFeePerGas);
      intx::uint256 MaxFeeMinusBase =
          GasPrice > BaseFee ? GasPrice - BaseFee : intx::uint256{0};
      PriorityFee =
          MaxPriority < MaxFeeMinusBase ? MaxPriority : MaxFeeMinusBase;
    }

    intx::uint256 GasCharged256 = intx::uint256(GasCharged);
    intx::uint256 TotalGasCost = GasCharged256 * GasPrice;
    intx::uint256 CoinbaseReward = GasCharged256 * PriorityFee;

    auto &SenderAccount = accounts[Msg.sender];
    ensureAccountHasCodeHash(SenderAccount);
    intx::uint256 SenderBalance = toUint256Bytes(SenderAccount.balance);
    if (SenderBalance < TotalGasCost) {
      Result.Success = false;
      Result.ErrorMessage = "Sender balance insufficient for gas settlement";
      return;
    }
    SenderBalance -= TotalGasCost;
    SenderAccount.balance = toBytes32(SenderBalance);

    if (CoinbaseReward != 0 ||
        accounts.find(tx_context.block_coinbase) != accounts.end()) {
      auto &CoinbaseAccount = accounts[tx_context.block_coinbase];
      ensureAccountHasCodeHash(CoinbaseAccount);
      intx::uint256 CoinbaseBalance = toUint256Bytes(CoinbaseAccount.balance);
      CoinbaseBalance += CoinbaseReward;
      CoinbaseAccount.balance = toBytes32(CoinbaseBalance);
    }
  }
};

} // namespace zen::evm

#endif // ZEN_TESTS_EVM_TEST_HOST_HPP
