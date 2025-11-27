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

EVMFrame *InterpreterExecContext::allocTopFrame(evmc_message *Msg) {
  // Only deduct intrinsic gas (BASIC_EXECUTION_COST) for top-level transactions
  // (depth == 0) Nested calls (depth > 0) should not pay intrinsic gas
  const bool IsTopLevel = (Msg->depth == 0);
  const int64_t IntrinsicGas = IsTopLevel ? BASIC_EXECUTION_COST : 0;

  EVM_REQUIRE(Msg->gas >= IntrinsicGas, GasLimitExceeded);

  FrameStack.emplace_back();

  EVMFrame &Frame = FrameStack.back();

  Frame.Msg = std::make_unique<evmc_message>(*Msg);
  Inst->pushMessage(Frame.Msg.get());

  Frame.Msg->gas = Frame.Msg->gas - IntrinsicGas;
  return &Frame;
}

// We only need to free the last frame (top of the stack),
// since EVM's control flow is purely stack-based.
void InterpreterExecContext::freeBackFrame() {
  if (FrameStack.empty())
    return;

  EVMFrame &Frame = FrameStack.back();

  Inst->setGas(static_cast<uint64_t>(Frame.Msg->gas));

  if (FrameStack.size() > 1) {
    Inst->popMessage();
  }

  // Destroy frame (and its message)
  FrameStack.pop_back();
}

void InterpreterExecContext::setCallData(const std::vector<uint8_t> &Data) {
  EVM_FRAME_CHECK(getCurFrame());
  getCurFrame()->CallData = Data;
  getCurFrame()->Msg->input_data = getCurFrame()->CallData.data();
  getCurFrame()->Msg->input_size = getCurFrame()->CallData.size();
}

void InterpreterExecContext::setTxContext(const evmc_tx_context &TxContext) {
  EVM_FRAME_CHECK(getCurFrame());
  getCurFrame()->MTx = TxContext;
}

void InterpreterExecContext::setResource() {
  EVMResource::setExecutionContext(getCurFrame(), this);
}

void BaseInterpreter::interpret() {
  EVMFrame *Frame = Context.getCurFrame();

  EVM_FRAME_CHECK(Frame);

  Context.setStatus(EVMC_SUCCESS);

  const EVMModule *Mod = Context.getInstance()->getModule();

  EVMResource::setExecutionContext(Frame, &Context);

  size_t CodeSize = Mod->CodeSize;
  Byte *Code = Mod->Code;

  if (!Frame->Host) {
    Frame->Host = Context.getInstance()->getRuntime()->getEVMHost();
  }

  while (Frame->Pc < CodeSize) {
    Byte OpcodeByte = Code[Frame->Pc];
    evmc_opcode Op = static_cast<evmc_opcode>(OpcodeByte);
    bool IsJumpSuccess = false;

    switch (Op) {
    case evmc_opcode::OP_STOP:
      Context.freeBackFrame();
      Frame = Context.getCurFrame();
      if (!Frame) {
        const auto &ReturnData = Context.getReturnData();
        evmc::Result ExeResult(EVMC_SUCCESS, Frame ? Frame->Msg->gas : 0,
                               Context.getInstance()->getGasRefund(),
                               ReturnData.data(), ReturnData.size());
        Context.setExeResult(std::move(ExeResult));
        return;
      }
      continue;

    case evmc_opcode::OP_ADD: {
      EVMOpcodeHandlerRegistry::getAddHandler().execute();
      break;
    }

    case evmc_opcode::OP_MUL: {
      EVMOpcodeHandlerRegistry::getMulHandler().execute();
      break;
    }

    case evmc_opcode::OP_SUB: {
      EVMOpcodeHandlerRegistry::getSubHandler().execute();
      break;
    }

    case evmc_opcode::OP_DIV: {
      EVMOpcodeHandlerRegistry::getDivHandler().execute();
      break;
    }

    case evmc_opcode::OP_SDIV: {
      EVMOpcodeHandlerRegistry::getSDivHandler().execute();
      break;
    }

    case evmc_opcode::OP_MOD: {
      EVMOpcodeHandlerRegistry::getModHandler().execute();
      break;
    }

    case evmc_opcode::OP_SMOD: {
      EVMOpcodeHandlerRegistry::getSModHandler().execute();
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

    case evmc_opcode::OP_SIGNEXTEND: {
      EVMOpcodeHandlerRegistry::getSignExtendHandler().execute();
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

    case evmc_opcode::OP_EQ: {
      EVMOpcodeHandlerRegistry::getEqHandler().execute();
      break;
    }

    case evmc_opcode::OP_ISZERO: {
      EVMOpcodeHandlerRegistry::getIsZeroHandler().execute();
      break;
    }

    case evmc_opcode::OP_AND: {
      EVMOpcodeHandlerRegistry::getAndHandler().execute();
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

    case evmc_opcode::OP_KECCAK256: {
      EVMOpcodeHandlerRegistry::getKeccak256Handler().execute();
      break;
    }

    case evmc_opcode::OP_ADDRESS: {
      EVMOpcodeHandlerRegistry::getAddressHandler().execute();
      break;
    }

    case evmc_opcode::OP_BALANCE: {
      EVMOpcodeHandlerRegistry::getBalanceHandler().execute();
      break;
    }

    case evmc_opcode::OP_ORIGIN: {
      EVMOpcodeHandlerRegistry::getOriginHandler().execute();
      break;
    }

    case evmc_opcode::OP_CALLER: {
      EVMOpcodeHandlerRegistry::getCallerHandler().execute();
      break;
    }

    case evmc_opcode::OP_CALLVALUE: {
      EVMOpcodeHandlerRegistry::getCallValueHandler().execute();
      break;
    }

    case evmc_opcode::OP_CALLDATALOAD: {
      EVMOpcodeHandlerRegistry::getCallDataLoadHandler().execute();
      break;
    }

    case evmc_opcode::OP_CALLDATASIZE: {
      EVMOpcodeHandlerRegistry::getCallDataSizeHandler().execute();
      break;
    }

    case evmc_opcode::OP_CALLDATACOPY: {
      EVMOpcodeHandlerRegistry::getCallDataCopyHandler().execute();
      break;
    }

    case evmc_opcode::OP_CODESIZE: {
      EVMOpcodeHandlerRegistry::getCodeSizeHandler().execute();
      break;
    }

    case evmc_opcode::OP_CODECOPY: {
      EVMOpcodeHandlerRegistry::getCodeCopyHandler().execute();
      break;
    }

    case evmc_opcode::OP_GASPRICE: {
      EVMOpcodeHandlerRegistry::getGasPriceHandler().execute();
      break;
    }

    case evmc_opcode::OP_EXTCODESIZE: {
      EVMOpcodeHandlerRegistry::getExtCodeSizeHandler().execute();
      break;
    }

    case evmc_opcode::OP_EXTCODECOPY: {
      EVMOpcodeHandlerRegistry::getExtCodeCopyHandler().execute();
      break;
    }

    case evmc_opcode::OP_RETURNDATASIZE: {
      EVMOpcodeHandlerRegistry::getReturnDataSizeHandler().execute();
      break;
    }

    case evmc_opcode::OP_RETURNDATACOPY: {
      EVMOpcodeHandlerRegistry::getReturnDataCopyHandler().execute();
      break;
    }

    case evmc_opcode::OP_EXTCODEHASH: {
      EVMOpcodeHandlerRegistry::getExtCodeHashHandler().execute();
      break;
    }

    case evmc_opcode::OP_BLOCKHASH: {
      EVMOpcodeHandlerRegistry::getBlockHashHandler().execute();
      break;
    }

    case evmc_opcode::OP_COINBASE: {
      EVMOpcodeHandlerRegistry::getCoinBaseHandler().execute();
      break;
    }

    case evmc_opcode::OP_TIMESTAMP: {
      EVMOpcodeHandlerRegistry::getTimeStampHandler().execute();
      break;
    }

    case evmc_opcode::OP_NUMBER: {
      EVMOpcodeHandlerRegistry::getNumberHandler().execute();
      break;
    }

    case evmc_opcode::OP_PREVRANDAO: {
      EVMOpcodeHandlerRegistry::getPrevRanDaoHandler().execute();
      break;
    }

    case evmc_opcode::OP_GASLIMIT: {
      EVMOpcodeHandlerRegistry::getGasLimitHandler().execute();
      break;
    }

    case evmc_opcode::OP_CHAINID: {
      EVMOpcodeHandlerRegistry::getChainIdHandler().execute();
      break;
    }

    case evmc_opcode::OP_SELFBALANCE: {
      EVMOpcodeHandlerRegistry::getSelfBalanceHandler().execute();
      break;
    }

    case evmc_opcode::OP_BASEFEE: {
      EVMOpcodeHandlerRegistry::getBaseFeeHandler().execute();
      break;
    }

    case evmc_opcode::OP_BLOBHASH: {
      EVMOpcodeHandlerRegistry::getBlobHashHandler().execute();
      break;
    }

    case evmc_opcode::OP_BLOBBASEFEE: {
      EVMOpcodeHandlerRegistry::getBlobBaseFeeHandler().execute();
      break;
    }

    case evmc_opcode::OP_POP: {
      EVMOpcodeHandlerRegistry::getPopHandler().execute();
      break;
    }

    case evmc_opcode::OP_MLOAD: {
      EVMOpcodeHandlerRegistry::getMLoadHandler().execute();
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

    case evmc_opcode::OP_SLOAD: {
      EVMOpcodeHandlerRegistry::getSLoadHandler().execute();
      break;
    }

    case evmc_opcode::OP_SSTORE: {
      EVMOpcodeHandlerRegistry::getSStoreHandler().execute();
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

    case evmc_opcode::OP_GAS: {
      EVMOpcodeHandlerRegistry::getGasHandler().execute();
      break;
    }

    case evmc_opcode::OP_JUMPDEST: {
      EVMOpcodeHandlerRegistry::getJumpDestHandler().execute();
      break;
    }

    case evmc_opcode::OP_TLOAD: {
      EVMOpcodeHandlerRegistry::getTLoadHandler().execute();
      break;
    }

    case evmc_opcode::OP_TSTORE: {
      EVMOpcodeHandlerRegistry::getTStoreHandler().execute();
      break;
    }

    case evmc_opcode::OP_MCOPY: {
      EVMOpcodeHandlerRegistry::getMCopyHandler().execute();
      break;
    }

    case evmc_opcode::OP_PUSH0: { // PUSH0 (EIP-3855)
      EVMOpcodeHandlerRegistry::getPush0Handler().execute();
      break;
    }

    case evmc_opcode::OP_LOG0:
    case evmc_opcode::OP_LOG1:
    case evmc_opcode::OP_LOG2:
    case evmc_opcode::OP_LOG3:
    case evmc_opcode::OP_LOG4: {
      EVMOpcodeHandlerRegistry::getLogHandler(
          static_cast<evmc_opcode>(OpcodeByte))
          .execute();
      break;
    }

    case evmc_opcode::OP_RETURN: {
      EVMOpcodeHandlerRegistry::getReturnHandler().execute();
      Frame = Context.getCurFrame();
      if (!Frame) {
        const auto &ReturnData = Context.getReturnData();
        evmc::Result ExeResult(EVMC_SUCCESS, 0,
                               Context.getInstance()->getGasRefund(),
                               ReturnData.data(), ReturnData.size());
        Context.setExeResult(std::move(ExeResult));
        return;
      }
      break;
    }

    case evmc_opcode::OP_REVERT: {
      EVMOpcodeHandlerRegistry::getRevertHandler().execute();
      Frame = Context.getCurFrame();
      if (!Frame) {
        const auto &ReturnData = Context.getReturnData();
        evmc::Result ExeResult(EVMC_REVERT, 0,
                               Context.getInstance()->getGasRefund(),
                               ReturnData.data(), ReturnData.size());
        Context.setExeResult(std::move(ExeResult));
        return;
      }
      break;
    }

    case evmc_opcode::OP_INVALID: {
      Context.setStatus(EVMC_INVALID_INSTRUCTION);
      break;
    }

    case evmc_opcode::OP_SELFDESTRUCT: {
      EVMOpcodeHandlerRegistry::getSelfDestructHandler().execute();
      Frame = Context.getCurFrame();
      if (!Frame) {
        const auto &ReturnData = Context.getReturnData();
        evmc::Result ExeResult(EVMC_SUCCESS, 0,
                               Context.getInstance()->getGasRefund(),
                               ReturnData.data(), ReturnData.size());
        Context.setExeResult(std::move(ExeResult));
        return;
      }
      break;
    }

    default:
      if (OpcodeByte >= static_cast<Byte>(evmc_opcode::OP_PUSH1) &&
          OpcodeByte <= static_cast<Byte>(evmc_opcode::OP_PUSH32)) {
        // PUSH1 ~ PUSH32
        EVMOpcodeHandlerRegistry::getPushHandler(
            static_cast<evmc_opcode>(OpcodeByte))
            .execute();
        break;
      } else if (OpcodeByte >= static_cast<Byte>(evmc_opcode::OP_DUP1) &&
                 OpcodeByte <= static_cast<Byte>(evmc_opcode::OP_DUP16)) {
        // DUP1 ~ DUP16
        EVMOpcodeHandlerRegistry::getDupHandler(
            static_cast<evmc_opcode>(OpcodeByte))
            .execute();
        break;
      } else if (OpcodeByte >= static_cast<Byte>(evmc_opcode::OP_SWAP1) &&
                 OpcodeByte <= static_cast<Byte>(evmc_opcode::OP_SWAP16)) {
        // SWAP1 ~ SWAP16
        EVMOpcodeHandlerRegistry::getSwapHandler(
            static_cast<evmc_opcode>(OpcodeByte))
            .execute();
        break;
      } else if (OpcodeByte == static_cast<Byte>(evmc_opcode::OP_CREATE) ||
                 OpcodeByte == static_cast<Byte>(evmc_opcode::OP_CREATE2)) {
        EVMOpcodeHandlerRegistry::getCreateHandler(
            static_cast<evmc_opcode>(OpcodeByte))
            .execute();
        break;
      } else if (OpcodeByte == static_cast<Byte>(evmc_opcode::OP_CALL) ||
                 OpcodeByte == static_cast<Byte>(evmc_opcode::OP_CALLCODE) ||
                 OpcodeByte ==
                     static_cast<Byte>(evmc_opcode::OP_DELEGATECALL) ||
                 OpcodeByte == static_cast<Byte>(evmc_opcode::OP_STATICCALL)) {
        EVMOpcodeHandlerRegistry::getCallHandler(
            static_cast<evmc_opcode>(OpcodeByte))
            .execute();
        break;
      } else {
        Context.setStatus(EVMC_INVALID_INSTRUCTION);
      }
    }

    if (IsJumpSuccess) {
      continue;
    }

    if (Context.getStatus() != EVMC_SUCCESS) {
      // Handle execution errors according to EVM specification
      evmc_status_code Status = Context.getStatus();

      switch (Status) {
      case EVMC_REVERT:
        // REVERT: Keep remaining gas and return data
        // Gas and return data are already set by RevertHandler
        break;

      case EVMC_OUT_OF_GAS:
      case EVMC_STACK_OVERFLOW:
      case EVMC_STACK_UNDERFLOW:
      case EVMC_INVALID_INSTRUCTION:
      case EVMC_UNDEFINED_INSTRUCTION:
      case EVMC_BAD_JUMP_DESTINATION:
      case EVMC_INVALID_MEMORY_ACCESS:
      case EVMC_CALL_DEPTH_EXCEEDED:
      case EVMC_STATIC_MODE_VIOLATION:
      case EVMC_INSUFFICIENT_BALANCE:
        // Fatal errors: consume all remaining gas and clear return data
        Frame->Msg->gas = 0;
        Context.getInstance()->setGasRefund(0);
        Context.setReturnData(std::vector<uint8_t>());
        Context.freeBackFrame();
        Frame = Context.getCurFrame();
        if (!Frame) {
          const auto &ReturnData = Context.getReturnData();
          evmc::Result ExeResult(Context.getStatus(),
                                 Frame ? Frame->Msg->gas : 0,
                                 Context.getInstance()->getGasRefund(),
                                 ReturnData.data(), ReturnData.size());
          Context.setExeResult(std::move(ExeResult));
          return;
        }
        break;

      case EVMC_FAILURE:
      default:
        // Generic failure: consume all remaining gas and clear return data
        Frame->Msg->gas = 0;
        Context.getInstance()->setGasRefund(0);
        Context.setReturnData(std::vector<uint8_t>());
        Context.freeBackFrame();
        Frame = Context.getCurFrame();
        if (!Frame) {
          const auto &ReturnData = Context.getReturnData();
          evmc::Result ExeResult(Context.getStatus(),
                                 Frame ? Frame->Msg->gas : 0,
                                 Context.getInstance()->getGasRefund(),
                                 ReturnData.data(), ReturnData.size());
          Context.setExeResult(std::move(ExeResult));
          return;
        }
      }

      break;
    }

    Frame->Pc++;
  }
  Context.freeBackFrame();
  const auto &ReturnData = Context.getReturnData();
  uint64_t GasLeft = Context.getInstance()->getGas();
  if (auto *Cur = Context.getCurFrame()) {
    GasLeft = static_cast<uint64_t>(Cur->Msg->gas);
  }
  evmc::Result ExeResult(Context.getStatus(), GasLeft,
                         Context.getInstance()->getGasRefund(),
                         ReturnData.data(), ReturnData.size());
  Context.setExeResult(std::move(ExeResult));
}
