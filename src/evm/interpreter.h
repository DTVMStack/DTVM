// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_EVM_INTERPRETER_H
#define ZEN_EVM_INTERPRETER_H

#include "common/errors.h"
#include "evmc/evmc.h"
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
  static constexpr size_t MAXSTACK = 1024;

  // TODO: use EVMMemory class in the future
  std::array<intx::uint256, MAXSTACK> Stack;
  std::vector<uint8_t> Memory;
  // TODO: use EVMHost in the future
  std::map<intx::uint256, intx::uint256> Storage;

  size_t Sp = 0;
  uint64_t GasLeft = 0;
  uint64_t GasLimit = 0;
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
};

class InterpreterExecContext {
private:
  runtime::EVMInstance *Inst;
  std::vector<EVMFrame> FrameStack;
  evmc_status_code Status = EVMC_SUCCESS;
  std::vector<uint8_t> ReturnData;

public:
  bool IsJump = false;

  InterpreterExecContext(runtime::EVMInstance *Inst) : Inst(Inst) {}

  EVMFrame *allocFrame(uint64_t GasLimit = 0);
  void freeBackFrame();

  EVMFrame *getCurFrame() {
    if (FrameStack.empty()) {
      return nullptr;
    }
    return &FrameStack.back();
  }

  runtime::EVMInstance *getInstance() { return Inst; }

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
