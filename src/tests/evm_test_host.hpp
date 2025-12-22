// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef ZEN_TESTS_EVM_TEST_HOST_HPP
#define ZEN_TESTS_EVM_TEST_HOST_HPP

#include "evm/interpreter.h"
#include "evm_precompiles.hpp"
#include "evmc/mocked_host.hpp"
#include "host/evm/crypto.h"
#include "runtime/evm_instance.h"
#include "runtime/isolation.h"
#include "utils/evm.h"
#include "utils/rlp_encoding.h"

using namespace zen;
using namespace zen::runtime;

namespace zen::evm {
constexpr evmc::address DEFAULT_DEPLOYER_ADDRESS =
    evmc::literals::operator""_address(
        "1000000000000000000000000000000000000000");

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
  evmc_revision Revision = zen::evm::DEFAULT_REVISION;

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
    uint64_t IntrinsicGas = 0;
    std::optional<evmc::uint256be> MaxPriorityFeePerGas;
    std::vector<AccessListEntry> AccessList;
    evmc_revision Revision = zen::evm::DEFAULT_REVISION;
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
    const bool IsCreateTx = Config.Message.kind == EVMC_CREATE ||
                            Config.Message.kind == EVMC_CREATE2;
    if ((!Config.Bytecode || Config.BytecodeSize == 0) && !IsCreateTx) {
      Result.ErrorMessage = "Bytecode buffer is empty";
      return Result;
    }

    uint64_t GasLimit = Config.GasLimit;
    const evmc_revision ActiveRevision = Config.Revision;
    Revision = ActiveRevision;
    if (GasLimit == 0) {
      if (Config.Message.gas < 0) {
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

    // EIP-3651: coinbase is warm starting from Shanghai
    if (ActiveRevision >= EVMC_SHANGHAI) {
      access_account(tx_context.block_coinbase);
    }

    uint64_t AvailableGas = GasLimit;

    evmc_message Msg = Config.Message;
    Msg.gas = static_cast<int64_t>(AvailableGas);

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

    if (IsCreateTx) {
      auto CreateResult = handleCreate(Msg);

      if (CreateResult.output_data && CreateResult.output_size > 0) {
        ReturnData.assign(CreateResult.output_data,
                          CreateResult.output_data + CreateResult.output_size);
      } else {
        ReturnData.clear();
      }

      Result.Status = CreateResult.status_code;
      Result.Success = true;
      Result.RemainingGas = CreateResult.gas_left;
      const uint64_t GasLeft =
          Result.RemainingGas > 0 ? static_cast<uint64_t>(Result.RemainingGas)
                                  : 0;
      Result.GasUsed = AvailableGas > GasLeft ? AvailableGas - GasLeft : 0;
      Result.GasUsed += Config.IntrinsicGas;
      uint64_t GasRefund = static_cast<uint64_t>(
          std::max<int64_t>(0, CreateResult.gas_refund));
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

    static const uint8_t STOP_BYTE = 0x00;
    const uint8_t *BytecodePtr = Config.Bytecode;
    size_t BytecodeSize = Config.BytecodeSize;
    if (BytecodeSize == 0) {
      BytecodePtr = &STOP_BYTE;
      BytecodeSize = 1;
    }

    uint64_t Counter = ModuleCounter++;
    std::string ModuleName = Config.ModuleName.empty()
                                 ? ("tx_exec_mod_" + std::to_string(Counter))
                                 : (Config.ModuleName + "_" +
                                    std::to_string(Counter));

    auto ModRet =
        RT->loadEVMModule(ModuleName, BytecodePtr, BytecodeSize);
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
    Inst->setRevision(ActiveRevision);

    uint64_t OriginalGas = static_cast<uint64_t>(Inst->getGas());

    auto StateSnapshot = captureHostState();
    if (!applyPreExecutionState(Msg, Result)) {
      restoreHostState(StateSnapshot);
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

    if (shouldRevertState(ExecResult.status_code)) {
      restoreHostState(StateSnapshot);
      auto &SenderAccount = accounts[Msg.sender];
      ensureAccountHasCodeHash(SenderAccount);
      SenderAccount.nonce++;
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

    Result.GasUsed =
        OriginalGas > static_cast<uint64_t>(Result.RemainingGas)
            ? OriginalGas - static_cast<uint64_t>(Result.RemainingGas)
            : 0;

    Result.GasUsed += Config.IntrinsicGas;

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

    const evmc::address &PrecompileAddr =
        (Msg.kind == EVMC_CALLCODE || Msg.kind == EVMC_DELEGATECALL)
            ? Msg.code_address
            : Msg.recipient;
    if (precompile::isBlake2bPrecompile(PrecompileAddr, Revision)) {
      return precompile::executeBlake2b(Msg, ReturnData);
    }
    if (precompile::isModExpPrecompile(PrecompileAddr)) {
      return precompile::executeModExp(Msg, Revision, ReturnData);
    }

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
      if (ParentResult.status_code == EVMC_SUCCESS &&
          ParentResult.gas_left == 0) {
        ParentResult.gas_left = Msg.gas;
      }
      return ParentResult;
    }

    auto StateSnapshot = captureHostState();
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
      Inst->setRevision(Revision);

      evmc_message CallMsg = Msg;
      evmc::Result ExecResult{};

      try {
        RT->callEVMMain(*Inst, CallMsg, ExecResult);
      } catch (const std::exception &E) {
        ZEN_LOG_ERROR("Error in recursive call: {}", E.what());
        restoreHostState(StateSnapshot);
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
      if (std::getenv("TRACE_WARM_COINBASE")) {
        const auto ErrCode = Inst->getError().getCode();
        std::fprintf(stderr,
                     "[TRACE_WARM_COINBASE] depth=%d kind=%d to=%s gas=%lld "
                     "status=%d gas_left=%lld err=%u\n",
                     Msg.depth, static_cast<int>(Msg.kind),
                     evmc::hex(evmc::bytes_view(Msg.recipient.bytes, 20)).c_str(),
                     static_cast<long long>(Msg.gas),
                     static_cast<int>(ExecResult.status_code),
                     static_cast<long long>(RemainingGas),
                     static_cast<unsigned>(ErrCode));
      }
      if (shouldRevertState(ExecResult.status_code)) {
        restoreHostState(StateSnapshot);
      }
      return evmc::Result(ExecResult.status_code, RemainingGas, GasRefund,
                          ReturnData.empty() ? nullptr : ReturnData.data(),
                          ReturnData.size());

    } catch (const std::exception &E) {
      // On error, return parent result
      ZEN_LOG_ERROR("Error in recursive call: {}", E.what());
      restoreHostState(StateSnapshot);
      return ParentResult;
    }
  }
  using hash256 = evmc::bytes32;
  evmc::address computeCreateAddress(const evmc::address &Sender,
                                     uint64_t SenderNonce) noexcept {
    static constexpr auto ADDRESS_SIZE = sizeof(Sender);

    std::vector<uint8_t> SenderBytes(Sender.bytes, Sender.bytes + ADDRESS_SIZE);

    evmc_uint256be NonceUint256 = {};
    intx::be::store(NonceUint256.bytes, intx::uint256{SenderNonce});
    std::vector<uint8_t> NonceMinimalBytes = zen::utils::uint256beToBytes(NonceUint256);

    std::vector<std::vector<uint8_t>> RlpListItems = {SenderBytes,
                                                      NonceMinimalBytes};
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
    auto StateSnapshot = captureHostState();
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
      static const uint8_t STOP_BYTE = 0x00;
      const uint8_t *InitcodePtr = Msg.input_data;
      size_t InitcodeSize = Msg.input_size;
      if (InitcodeSize == 0) {
        InitcodePtr = &STOP_BYTE;
        InitcodeSize = 1;
      }
      auto ModRet = RT->loadEVMModule(ModName, InitcodePtr, InitcodeSize);
      if (!ModRet) {
        restoreHostState(StateSnapshot);
        ZEN_LOG_ERROR("Failed to load EVM module: {}", ModName.c_str());
        return evmc::Result{EVMC_FAILURE, Msg.gas, 0, NewAddr};
      }
      EVMModule *Mod = *ModRet;

      IsolationPtr Iso(nullptr, IsolationDeleter{RT});
      Iso.reset(RT->createManagedIsolation());
      if (!Iso) {
        restoreHostState(StateSnapshot);
        ZEN_LOG_ERROR("Failed to create isolation for module: {}",
                      ModName.c_str());
        return evmc::Result{EVMC_FAILURE, Msg.gas, 0, NewAddr};
      }

      auto InstRet = Iso->createEVMInstance(*Mod, Msg.gas);
      if (!InstRet) {
        restoreHostState(StateSnapshot);
        ZEN_LOG_ERROR("Failed to create EVM instance for module: {}",
                      ModName.c_str());
        return evmc::Result{EVMC_FAILURE, Msg.gas, 0, NewAddr};
      }

      EVMInstance *Inst = *InstRet;
      Inst->setRevision(Revision);
      // 3 Create new account status
      auto &NewAcc = accounts[NewAddr];
      NewAcc.nonce = Revision >= EVMC_SPURIOUS_DRAGON ? 1 : 0;
      NewAcc.balance = evmc::bytes32{0};

      // 4 Transfer the balance (from the sender to the new account)
      auto &SenderAcc = accounts[Msg.sender];
      const auto Value = intx::be::load<intx::uint256>(Msg.value);
      intx::uint256 SenderBalance =
          intx::be::load<intx::uint256>(SenderAcc.balance);
      if (SenderBalance < Value) {
        restoreHostState(StateSnapshot);
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
        restoreHostState(StateSnapshot);
        ZEN_LOG_ERROR("Error in handleCreate execution: {}", E.what());
        return evmc::Result{EVMC_FAILURE, Msg.gas, 0, evmc::address{}};
      }

      if (ExecResult.output_data && ExecResult.output_size > 0) {
        ReturnData.assign(ExecResult.output_data,
                          ExecResult.output_data + ExecResult.output_size);
      } else {
        ReturnData.clear();
      }

      int64_t RemainingGas = static_cast<int64_t>(Inst->getGas());
      const int64_t GasRefund =
          static_cast<int64_t>(Inst->getGasRefund());

      // 6 Deploy the contract code (the output is the runtime code)
      if (ExecResult.status_code != EVMC_SUCCESS) {
        restoreHostState(StateSnapshot);
        auto SenderIt = accounts.find(Msg.sender);
        if (SenderIt != accounts.end() &&
            (Msg.kind == EVMC_CREATE || Msg.kind == EVMC_CREATE2)) {
          SenderIt->second.nonce++;
        }
        evmc::Result Failure(ExecResult.status_code, RemainingGas, GasRefund);
        Failure.create_address = NewAddr;
        return Failure;
      }
      if (!ReturnData.empty()) {
        if (ReturnData.size() > MAX_CODE_SIZE) {
          restoreHostState(StateSnapshot);
          evmc::Result Failure(EVMC_FAILURE, RemainingGas, GasRefund);
          Failure.create_address = NewAddr;
          return Failure;
        }
        constexpr uint64_t CODE_DEPOSIT_COST_PER_BYTE = 200;
        const uint64_t CodeDepositCost =
            CODE_DEPOSIT_COST_PER_BYTE * ReturnData.size();
        if (RemainingGas < static_cast<int64_t>(CodeDepositCost)) {
          restoreHostState(StateSnapshot);
          auto SenderIt = accounts.find(Msg.sender);
          if (SenderIt != accounts.end() &&
              (Msg.kind == EVMC_CREATE || Msg.kind == EVMC_CREATE2)) {
            SenderIt->second.nonce++;
          }
          evmc::Result Failure(EVMC_OUT_OF_GAS, 0, 0);
          Failure.create_address = NewAddr;
          return Failure;
        }
        RemainingGas -= static_cast<int64_t>(CodeDepositCost);
        NewAcc.code = evmc::bytes(ReturnData.data(), ReturnData.size());
        const std::vector<uint8_t> CodeHashVec =
            host::evm::crypto::keccak256(ReturnData);
        assert(CodeHashVec.size() == 32 && "Keccak256 hash must be 32 bytes");
        evmc::bytes32 CodeHash;
        std::memcpy(CodeHash.bytes, CodeHashVec.data(), 32);
        NewAcc.codehash = CodeHash;
      } else {
        NewAcc.codehash = EMPTY_CODE_HASH;
      }
      // 7 Update the sender's nonce (for CREATE, the nonce must be incremented)
      if (Msg.kind == EVMC_CREATE || Msg.kind == EVMC_CREATE2) {
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
      restoreHostState(StateSnapshot);
      return evmc::Result{EVMC_FAILURE, Msg.gas, 0, evmc::address{}};
    }
  }

private:
  struct HostStateSnapshot {
    decltype(accounts) Accounts;
    decltype(recorded_logs) Logs;
    decltype(recorded_selfdestructs) Selfdestructs;
  };

  HostStateSnapshot captureHostState() const {
    return HostStateSnapshot{accounts, recorded_logs, recorded_selfdestructs};
  }

  void restoreHostState(const HostStateSnapshot &Snapshot) {
    accounts = Snapshot.Accounts;
    recorded_logs = Snapshot.Logs;
    recorded_selfdestructs = Snapshot.Selfdestructs;
  }

  static bool shouldRevertState(evmc_status_code Status) {
    return Status != EVMC_SUCCESS;
  }

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

