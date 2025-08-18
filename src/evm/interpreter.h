// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_EVM_INTERPRETER_H
#define ZEN_EVM_INTERPRETER_H

#include "common/errors.h"
#include "evm/evm.h"
#include "evm/gas_storage_cost.h"
#include "evmc/evmc.hpp"
#include "intx/intx.hpp"

#include <array>
#include <map>
#include <vector>

namespace zen {

namespace runtime {
class EVMInstance;
} // namespace runtime

namespace evm {

struct EVMFrame {
  // TODO: use EVMMemory class in the future
  std::array<intx::uint256, MAXSTACK> Stack;
  std::vector<uint8_t> Memory;

  std::vector<uint8_t> CallData;
  std::unique_ptr<evmc_message> Msg;
  evmc::Host *Host = nullptr;
  evmc_revision Rev = DEFAULT_REVISION;
  evmc_tx_context MTx = {};

  size_t Sp = 0;
  uint64_t GasRefund = 0;
  uint64_t Pc = 0;
  intx::uint256 Value = 0;

  inline void push(const intx::uint256 &V) {
    if (Sp >= MAXSTACK) {
      throw getError(common::ErrorCode::EVMStackOverflow);
    }
    Stack[Sp++] = V; // TODO: use EVMMemory class in the future
  }

  inline intx::uint256 pop() {
    if (Sp <= 0) {
      throw getError(common::ErrorCode::EVMStackUnderflow);
    }
    return Stack[--Sp]; // TODO: use EVMMemory class in the future
  }

  inline intx::uint256 &peek(size_t Index = 0) {
    if (Index >= Sp) {
      throw getError(common::ErrorCode::EVMStackUnderflow);
    }
    return Stack[Sp - 1 - Index]; // TODO: use EVMMemory class in the future
  }

  inline size_t stackHeight() const { return Sp; }

  const evmc_tx_context &getTxContext() noexcept {
    if (INTX_UNLIKELY(MTx.block_timestamp == 0))
      MTx = Host->get_tx_context();
    return MTx;
  }
  bool isStaticMode() const { return (Msg->flags & EVMC_STATIC) != 0; }
};

class InterpreterExecContext {
private:
  runtime::EVMInstance *Inst;
  std::vector<EVMFrame> FrameStack;
  evmc_status_code Status = EVMC_SUCCESS;
  std::vector<uint8_t> ReturnData;
  uint64_t GasUsed = 0;

public:
  bool IsJump = false;

  InterpreterExecContext(runtime::EVMInstance *Inst) : Inst(Inst) {}

  EVMFrame *allocFrame(evmc_message *ParentMsg, uint64_t GasLimit,
                       evmc_call_kind Kind, evmc::address Recipient,
                       evmc::address Sender, std::vector<uint8_t> CallData,
                       intx::uint256 Value);
  EVMFrame *allocFrame(evmc_message *Msg);
  void freeBackFrame();

  EVMFrame *getCurFrame() {
    if (FrameStack.empty()) {
      return nullptr;
    }
    return &FrameStack.back();
  }

  runtime::EVMInstance *getInstance() { return Inst; }

  uint64_t getGasUsed() const { return GasUsed; }

  void setCallData(const std::vector<uint8_t> &Data);
  void setTxContext(const evmc_tx_context &TxContext);
  void setResource();

  evmc_status_code getStatus() const { return Status; }
  void setStatus(evmc_status_code Status) { this->Status = Status; }

  const std::vector<uint8_t> &getReturnData() const { return ReturnData; }
  void setReturnData(std::vector<uint8_t> Data) {
    ReturnData = std::move(Data);
  }
};

class BaseInterpreter {
private:
  InterpreterExecContext &Context;

public:
  explicit BaseInterpreter(InterpreterExecContext &Ctx) : Context(Ctx) {}
  void interpret();
};

} // namespace evm
} // namespace zen

#endif // ZEN_EVM_INTERPRETER_H
