// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "evm/interpreter.h"
#include "common/errors.h"
#include "evm/opcode_handlers.h"
#include "evmc/instructions.h"
#include "runtime/evm_instance.h"

namespace {

int64_t
getGasCost(enum evmc_opcode Code,
           enum evmc_revision Revision = EVMC_CANCUN) { // EVMC_CANCUN = 12
  // Get the instruction index table for the specified EVM version
  const struct evmc_instruction_metrics *MetricsTable =
      evmc_get_instruction_metrics_table(Revision);

  if (MetricsTable == nullptr) {
    throw zen::common::getError(zen::common::ErrorCode::EVMInvalidInstruction);
  }
  int16_t GasCost = MetricsTable[Code].gas_cost;
  return GasCost;
}

} // namespace

using namespace zen;
using namespace zen::evm;
using namespace zen::runtime;
using zen::common::getError;
using zen::common::ErrorCode;

EVMFrame *InterpreterExecContext::allocFrame(uint64_t GasLimit) {
  FrameStack.emplace_back();

  EVMFrame &Frame = FrameStack.back();
  Frame.GasLimit = GasLimit;
  Frame.GasLeft = GasLimit;

  return &Frame;
}

// We only need to free the last frame (top of the stack),
// since EVM's control flow is purely stack-based.
void InterpreterExecContext::freeBackFrame() {
  if (FrameStack.empty())
    return;

  FrameStack.pop_back();
}

void BaseInterpreter::interpret() {
  Context.allocFrame(Context.getInstance()->getGas());
  EVMFrame *Frame = Context.getCurFrame();

  const EVMModule *Mod = Context.getInstance()->getModule();

  size_t CodeSize = Mod->CodeSize;
  uint8_t *Code = Mod->Code;

  while (Frame->Pc < CodeSize) {
    uint8_t OpcodeByte = Code[Frame->Pc];
    evmc_opcode Op = static_cast<evmc_opcode>(OpcodeByte);
    bool IsJumpSuccess = false;

    // Check and deduct gas before executing operation
    uint64_t GasCost = getGasCost(Op);
    if (Frame->GasLeft < GasCost) {
      throw getError(ErrorCode::EVMOutOfGas);
    }
    Frame->GasLeft -= GasCost;

    switch (Op) {
    case evmc_opcode::OP_STOP:
      Context.freeBackFrame();
      Frame = Context.getCurFrame();
      if (!Frame) {
        return;
      }
      continue;

    case evmc_opcode::OP_ADD: {
      handleOpADD(Frame);
      break;
    }

    case evmc_opcode::OP_SUB: {
      handleOpSUB(Frame);
      break;
    }

    case evmc_opcode::OP_MUL: {
      handleOpMUL(Frame);
      break;
    }

    case evmc_opcode::OP_DIV: {
      handleOpDIV(Frame);
      break;
    }

    case evmc_opcode::OP_MOD: {
      handleOpMOD(Frame);
      break;
    }

    case evmc_opcode::OP_AND: {
      handleOpAND(Frame);
      break;
    }

    case evmc_opcode::OP_EQ: {
      handleOpEQ(Frame);
      break;
    }

    case evmc_opcode::OP_ISZERO: {
      handleOpISZERO(Frame);
      break;
    }

    case evmc_opcode::OP_LT: {
      handleOpLT(Frame);
      break;
    }

    case evmc_opcode::OP_GT: {
      handleOpGT(Frame);
      break;
    }

    case evmc_opcode::OP_SLT: {
      handleOpSLT(Frame);
      break;
    }

    case evmc_opcode::OP_SGT: {
      handleOpSGT(Frame);
      break;
    }

    case evmc_opcode::OP_ADDMOD: {
      handleOpADDMOD(Frame);
      break;
    }

    case evmc_opcode::OP_MULMOD: {
      handleOpMULMOD(Frame);
      break;
    }

    case evmc_opcode::OP_EXP: {
      handleOpEXP(Frame);
      break;
    }

    case evmc_opcode::OP_SDIV: {
      handleOpSDIV(Frame);
      break;
    }

    case evmc_opcode::OP_SMOD: {
      handleOpSMOD(Frame);
      break;
    }
    case evmc_opcode::OP_SIGNEXTEND: {
      handleOpSIGNEXTEND(Frame);
      break;
    }

    case evmc_opcode::OP_OR: {
      handleOpOR(Frame);
      break;
    }

    case evmc_opcode::OP_XOR: {
      handleOpXOR(Frame);
      break;
    }

    case evmc_opcode::OP_NOT: {
      handleOpNOT(Frame);
      break;
    }

    case evmc_opcode::OP_BYTE: {
      handleOpBYTE(Frame);
      break;
    }

    case evmc_opcode::OP_SHL: {
      handleOpSHL(Frame);
      break;
    }

    case evmc_opcode::OP_SHR: {
      handleOpSHR(Frame);
      break;
    }

    case evmc_opcode::OP_SAR: {
      handleOpSAR(Frame);
      break;
    }

    case evmc_opcode::OP_MSTORE: {
      handleOpMSTORE(Frame);
      break;
    }

    case evmc_opcode::OP_MSTORE8: {
      handleOpMSTORE8(Frame);
      break;
    }
    case evmc_opcode::OP_MLOAD: {
      handleOpMLOAD(Frame);
      break;
    }

    case evmc_opcode::OP_JUMP: {
      IsJumpSuccess = handleOpJUMP(Frame, Mod->Code, Mod->CodeSize);
      break;
    }

    case evmc_opcode::OP_JUMPI: {
      IsJumpSuccess = handleOpJUMPI(Frame, Mod->Code, Mod->CodeSize);
      break;
    }

    case evmc_opcode::OP_PC: {
      handleOpPC(Frame);
      break;
    }
    case evmc_opcode::OP_MSIZE: {
      handleOpMSize(Frame);
      break;
    }

    case evmc_opcode::OP_JUMPDEST: {
      break;
    }

    case evmc_opcode::OP_GAS: {
      handleOpGAS(Frame);
      break;
    }
    case evmc_opcode::OP_GASLIMIT: {
      handleOpGASLIMIT(Frame);
      break;
    }

    case evmc_opcode::OP_RETURN: {
      handleOpRETURN(Context, Frame);
      Frame = Context.getCurFrame();
      if (!Frame) {
        return;
      }
      break;
    }

    case evmc_opcode::OP_REVERT: {
      handleOpREVERT(Context, Frame);
      Frame = Context.getCurFrame();
      if (!Frame) {
        return;
      }
      break;
    }

    case evmc_opcode::OP_POP: {
      if (Frame->stackHeight() < 1) {
        throw getError(ErrorCode::UnexpectedNumArgs);
      }
      Frame->pop();
      break;
    }

    case evmc_opcode::OP_INVALID: {
      throw getError(ErrorCode::EVMInvalidInstruction);
    }

    default:
      if (OpcodeByte >= static_cast<uint8_t>(evmc_opcode::OP_PUSH1) &&
          OpcodeByte <= static_cast<uint8_t>(evmc_opcode::OP_PUSH32)) {
        // PUSH1 ~ PUSH32
        handleOpPUSH(Frame, OpcodeByte, Code, CodeSize);
        break;
      } else if (OpcodeByte >= static_cast<uint8_t>(evmc_opcode::OP_DUP1) &&
                 OpcodeByte <= static_cast<uint8_t>(evmc_opcode::OP_DUP16)) {
        // DUP1 ~ DUP16
        handleOpDUP(OpcodeByte, Frame);
        break;
      } else if (OpcodeByte >= static_cast<uint8_t>(evmc_opcode::OP_SWAP1) &&
                 OpcodeByte <= static_cast<uint8_t>(evmc_opcode::OP_SWAP16)) {
        // SWAP1 ~ SWAP16
        handleOpSWAP(OpcodeByte, Frame);
        break;
      } else {
        throw getError(ErrorCode::UnsupportedOpcode);
      }
    }

    if (IsJumpSuccess) {
      continue;
    }

    Frame->Pc++;
  }
}
