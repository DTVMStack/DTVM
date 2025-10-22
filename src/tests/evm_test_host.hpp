// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef ZEN_TESTS_EVM_TEST_HOST_HPP
#define ZEN_TESTS_EVM_TEST_HOST_HPP

#include "evm/evm.h"
#include "evm/interpreter.h"
#include "evmc/mocked_host.hpp"
#include "host/evm/crypto.h"
#include "host/evm/keccak/keccak.hpp"
#include "mpt/rlp_encoding.h"
#include "runtime/evm_instance.h"
#include "runtime/isolation.h"
#include "runtime/runtime.h"
#include "utils/logging.h"
#include "utils/others.h"
#include <iostream>

using namespace zen;
using namespace zen::runtime;

namespace zen::evm {

/// Recursive Host that can execute CALL instructions by creating new
/// interpreters
class ZenMockedEVMHost : public evmc::MockedHost {
private:
  Runtime *RT = nullptr;
  Isolation *Iso = nullptr;
  std::vector<uint8_t> ReturnData;
  static inline std::atomic<uint64_t> ModuleCounter = 0;

public:
  ZenMockedEVMHost(Runtime *RT, Isolation *Iso) : RT(RT), Iso(Iso) {}

  evmc::Result call(const evmc_message &Msg) noexcept override {
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

      // Create EVM instance
      auto InstRet = Iso->createEVMInstance(*Mod, Msg.gas);
      if (!InstRet) {
        ZEN_LOG_ERROR("Failed to create EVM instance for module: {}",
                      ModName.c_str());
        return ParentResult;
      }

      EVMInstance *Inst = *InstRet;

      // Create interpreter context and execute
      InterpreterExecContext Ctx(Inst);
      BaseInterpreter Interpreter(Ctx);

      evmc_message CallMsg = Msg;
      Ctx.allocTopFrame(&CallMsg);

      // Set the host for the execution frame
      auto *Frame = Ctx.getCurFrame();
      Frame->Host = this;

      // Execute the interpreter
      Interpreter.interpret();

      // Calculate gas consumed and remaining
      int64_t RemainingGas = Msg.gas - Ctx.getInstance()->getGasUsed();
      int64_t GasRefund = Ctx.getInstance()->getGasRefund();
      ReturnData = Ctx.getReturnData();

      return evmc::Result(Ctx.getStatus(), RemainingGas, GasRefund,
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
      auto InstRet = Iso->createEVMInstance(*Mod, Msg.gas);
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

      // 5 Execute the contract creation code
      InterpreterExecContext Ctx(Inst);
      BaseInterpreter Interp(Ctx);

      evmc_message CallMsg = Msg;
      Ctx.allocTopFrame(&CallMsg);
      auto *Frame = Ctx.getCurFrame();
      Frame->Host = this;
      Interp.interpret();

      // Calculate gas consumed and remaining
      const int64_t RemainingGas = Msg.gas - Ctx.getInstance()->getGasUsed();
      const auto Status = Ctx.getStatus();
      ReturnData = Ctx.getReturnData();

      // 6 Deploy the contract code (the output is the runtime code)
      if (Status != EVMC_SUCCESS) {
        accounts.erase(NewAddr);
        return evmc::Result{Status, RemainingGas, 0, NewAddr};
      }
      if (!ReturnData.empty()) {
        if (ReturnData.size() > MAX_CODE_SIZE) {
          accounts.erase(NewAddr);
          return evmc::Result{EVMC_FAILURE, RemainingGas, 0, NewAddr};
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

      evmc::Result CreateResult(EVMC_SUCCESS, RemainingGas, 0,
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
};

} // namespace zen::evm

#endif // ZEN_TESTS_EVM_TEST_HOST_HPP
