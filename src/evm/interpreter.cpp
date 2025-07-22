// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "evm/interpreter.h"
#include "common/errors.h"
#include "evm/opcode_handlers.h"
#include "evmc/instructions.h"
#include "runtime/evm_instance.h"

using namespace zen;
using namespace zen::evm;
using namespace zen::runtime;
using zen::common::ErrorCode;
using zen::common::getError;

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

  EVMResource::setExecutionContext(Frame, &Context);

  size_t CodeSize = Mod->CodeSize;
  uint8_t *Code = Mod->Code;

  while (Frame->Pc < CodeSize) {
    uint8_t OpcodeByte = Code[Frame->Pc];
    evmc_opcode Op = static_cast<evmc_opcode>(OpcodeByte);
    bool IsJumpSuccess = false;

    switch (Op) {
    case evmc_opcode::OP_STOP:
      Context.freeBackFrame();
      Frame = Context.getCurFrame();
      if (!Frame) {
        return;
      }
      continue;

    case evmc_opcode::OP_ADD: {
      EVMOpcodeHandlerRegistry::getAddHandler().execute();
      break;
    }

    case evmc_opcode::OP_SUB: {
      EVMOpcodeHandlerRegistry::getSubHandler().execute();
      break;
    }

    case evmc_opcode::OP_MUL: {
      EVMOpcodeHandlerRegistry::getMulHandler().execute();
      break;
    }

    case evmc_opcode::OP_DIV: {
      EVMOpcodeHandlerRegistry::getDivHandler().execute();
      break;
    }

    case evmc_opcode::OP_MOD: {
      EVMOpcodeHandlerRegistry::getModHandler().execute();
      break;
    }

    case evmc_opcode::OP_AND: {
      EVMOpcodeHandlerRegistry::getAndHandler().execute();
      break;
    }

    case evmc_opcode::OP_EQ: {
      EVMOpcodeHandlerRegistry::getEqHandler().execute();
      break;
    }

    case evmc_opcode::OP_ISZERO: {
      EVMOpcodeHandlerRegistry::getIsZeroHandler().execute();
      break;
    }

    case evmc_opcode::OP_LT: {
      EVMOpcodeHandlerRegistry::getLtHandler().execute();
      break;
    }

    case evmc_opcode::OP_GT: {
      EVMOpcodeHandlerRegistry::getGtHandler().execute();
      break;
    }

    case evmc_opcode::OP_SLT: {
      EVMOpcodeHandlerRegistry::getSltHandler().execute();
      break;
    }

    case evmc_opcode::OP_SGT: {
      EVMOpcodeHandlerRegistry::getSgtHandler().execute();
      break;
    }

    case evmc_opcode::OP_ADDMOD: {
      EVMOpcodeHandlerRegistry::getAddmodHandler().execute();
      break;
    }

    case evmc_opcode::OP_MULMOD: {
      EVMOpcodeHandlerRegistry::getMulmodHandler().execute();
      break;
    }

    case evmc_opcode::OP_EXP: {
      EVMOpcodeHandlerRegistry::getExpHandler().execute();
      break;
    }

    case evmc_opcode::OP_SDIV: {
      EVMOpcodeHandlerRegistry::getSDivHandler().execute();
      break;
    }

    case evmc_opcode::OP_SMOD: {
      EVMOpcodeHandlerRegistry::getSModHandler().execute();
      break;
    }
    case evmc_opcode::OP_SIGNEXTEND: {
      EVMOpcodeHandlerRegistry::getSignExtendHandler().execute();
      break;
    }

    case evmc_opcode::OP_OR: {
      EVMOpcodeHandlerRegistry::getOrHandler().execute();
      break;
    }

    case evmc_opcode::OP_XOR: {
      EVMOpcodeHandlerRegistry::getXorHandler().execute();
      break;
    }

    case evmc_opcode::OP_NOT: {
      EVMOpcodeHandlerRegistry::getNotHandler().execute();
      break;
    }

    case evmc_opcode::OP_BYTE: {
      EVMOpcodeHandlerRegistry::getByteHandler().execute();
      break;
    }

    case evmc_opcode::OP_SHL: {
      EVMOpcodeHandlerRegistry::getShlHandler().execute();
      break;
    }

    case evmc_opcode::OP_SHR: {
      EVMOpcodeHandlerRegistry::getShrHandler().execute();
      break;
    }

    case evmc_opcode::OP_SAR: {
      EVMOpcodeHandlerRegistry::getSarHandler().execute();
      break;
    }

    case evmc_opcode::OP_MSTORE: {
      EVMOpcodeHandlerRegistry::getMStoreHandler().execute();
      break;
    }

    case evmc_opcode::OP_MSTORE8: {
      EVMOpcodeHandlerRegistry::getMStore8Handler().execute();
      break;
    }
    case evmc_opcode::OP_MLOAD: {
      EVMOpcodeHandlerRegistry::getMLoadHandler().execute();
      break;
    }

    case evmc_opcode::OP_JUMP: {
      EVMOpcodeHandlerRegistry::getJumpHandler().execute();
      IsJumpSuccess = Context.IsJump;
      Context.IsJump = false;
      break;
    }

    case evmc_opcode::OP_JUMPI: {
      EVMOpcodeHandlerRegistry::getJumpIHandler().execute();
      IsJumpSuccess = Context.IsJump;
      Context.IsJump = false;
      break;
    }

    case evmc_opcode::OP_PC: {
      EVMOpcodeHandlerRegistry::getPCHandler().execute();
      break;
    }
    case evmc_opcode::OP_MSIZE: {
      EVMOpcodeHandlerRegistry::getMSizeHandler().execute();
      break;
    }

    case evmc_opcode::OP_JUMPDEST: {
      break;
    }

    case evmc_opcode::OP_GAS: {
      EVMOpcodeHandlerRegistry::getGasHandler().execute();
      break;
    }
    case evmc_opcode::OP_GASLIMIT: {
      EVMOpcodeHandlerRegistry::getGasLimitHandler().execute();
      break;
    }

    case evmc_opcode::OP_RETURN: {
      EVMOpcodeHandlerRegistry::getReturnHandler().execute();
      Frame = Context.getCurFrame();
      if (!Frame) {
        return;
      }
      break;
    }

    case evmc_opcode::OP_REVERT: {
      EVMOpcodeHandlerRegistry::getRevertHandler().execute();
      Frame = Context.getCurFrame();
      if (!Frame) {
        return;
      }
      break;
    }

    case evmc_opcode::OP_POP: {
      EVM_THROW_IF(Frame->stackHeight(), <, 1, UnexpectedNumArgs);
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
        EVMOpcodeHandlerRegistry::getPUSHHandler().execute();
        break;
      } else if (OpcodeByte >= static_cast<uint8_t>(evmc_opcode::OP_DUP1) &&
                 OpcodeByte <= static_cast<uint8_t>(evmc_opcode::OP_DUP16)) {
        // DUP1 ~ DUP16
        EVMOpcodeHandlerRegistry::getDUPHandler().execute();
        break;
      } else if (OpcodeByte >= static_cast<uint8_t>(evmc_opcode::OP_SWAP1) &&
                 OpcodeByte <= static_cast<uint8_t>(evmc_opcode::OP_SWAP16)) {
        // SWAP1 ~ SWAP16
        EVMOpcodeHandlerRegistry::getSWAPHandler().execute();
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
