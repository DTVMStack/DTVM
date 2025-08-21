// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef ZEN_TESTS_EVM_TEST_HOST_HPP
#define ZEN_TESTS_EVM_TEST_HOST_HPP

#include "evm/interpreter.h"
#include "evmc/mocked_host.hpp"
#include "host/evm/crypto.h"
#include "host/evm/keccak/keccak.hpp"
#include "mpt/rlp_encoding.h"
#include "runtime/isolation.h"
#include "runtime/runtime.h"
#include "utils/others.h"
#include <iostream>
#include "utils/logging.h"

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
    evmc::Result ParentResult = evmc::MockedHost::call(Msg);
    // Try to find the target contract
    auto It = accounts.find(Msg.recipient);
    if (It == accounts.end() || It->second.code.empty()) {
      // No contract found, return parent result
       ZEN_LOG_DEBUG("No contract found for recipient {},return parent result", 
                   evmc::hex(evmc::bytes_view(Msg.recipient.bytes, 20)).c_str());
      return ParentResult;
    }

    try {
      const auto &ContractCode = It->second.code;
      if (ContractCode.empty()) {
        ZEN_LOG_DEBUG("Contract code is empty for recipient {}",
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
        ZEN_LOG_ERROR("Failed to create EVM instance for module: {}", ModName.c_str());
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

      ReturnData = Ctx.getReturnData();
      if (!ReturnData.empty()) {
        Result.output_data = ReturnData.data();
        Result.output_size = ReturnData.size();
      }
      return Result;

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
};

} // namespace zen::evm

#endif // ZEN_TESTS_EVM_TEST_HOST_HPP
