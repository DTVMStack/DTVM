// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "evm/interpreter.h"
#include "evm/evm_cache.h"
#include "evm/opcode_handlers.h"
#include "evmc/instructions.h"
#include "runtime/evm_instance.h"

#include <cstddef>
#include <cstring>
#include <limits>

using namespace zen;
using namespace zen::evm;
using namespace zen::runtime;

#ifndef ZEN_EVM_INTERP_HELPER
#ifdef ZEN_ENABLE_LINUX_PERF
#define ZEN_EVM_INTERP_HELPER __attribute__((noinline))
#else
#define ZEN_EVM_INTERP_HELPER inline
#endif
#endif

namespace {

static ZEN_EVM_INTERP_HELPER bool
chargeGas(zen::evm::EVMFrame *Frame, zen::evm::InterpreterExecContext &Context,
          const evmc_instruction_metrics *MetricsTable, uint8_t Opcode) {
  const uint64_t GasCost = MetricsTable[Opcode].gas_cost;
  if ((uint64_t)Frame->Msg.gas < GasCost) {
    Context.setStatus(EVMC_OUT_OF_GAS);
    return false;
  }
  Frame->Msg.gas -= GasCost;
  return true;
}

static ZEN_EVM_INTERP_HELPER bool
chargeGas(zen::evm::EVMFrame *Frame, zen::evm::InterpreterExecContext &Context,
          uint64_t GasCost) {
  if ((uint64_t)Frame->Msg.gas < GasCost) {
    Context.setStatus(EVMC_OUT_OF_GAS);
    return false;
  }
  Frame->Msg.gas -= GasCost;
  return true;
}

static ZEN_EVM_INTERP_HELPER void executePush0Opcode(
    zen::evm::EVMFrame *Frame, zen::evm::InterpreterExecContext &Context,
    const evmc_instruction_metrics *MetricsTable, uint8_t OpcodeU8) {
  if (!chargeGas(Frame, Context, MetricsTable, OpcodeU8)) {
    return;
  }
  if (Frame->Sp >= MAXSTACK) {
    Context.setStatus(EVMC_STACK_OVERFLOW);
    return;
  }
  Frame->Stack[Frame->Sp++] = 0;
}

static ZEN_EVM_INTERP_HELPER void
executePush0OpcodeNoGas(zen::evm::EVMFrame *Frame,
                        zen::evm::InterpreterExecContext &Context) {
  if (Frame->Sp >= MAXSTACK) {
    Context.setStatus(EVMC_STACK_OVERFLOW);
    return;
  }
  Frame->Stack[Frame->Sp++] = 0;
}

static ZEN_EVM_INTERP_HELPER void executePushNOpcode(
    zen::evm::EVMFrame *Frame, zen::evm::InterpreterExecContext &Context,
    const evmc_instruction_metrics *MetricsTable, uint8_t OpcodeU8,
    const intx::uint256 *__restrict PushValueMap) {
  if (!chargeGas(Frame, Context, MetricsTable, OpcodeU8)) {
    return;
  }
  if (Frame->Sp >= MAXSTACK) {
    Context.setStatus(EVMC_STACK_OVERFLOW);
    return;
  }

  const size_t Pc = static_cast<size_t>(Frame->Pc);
  Frame->Stack[Frame->Sp++] = PushValueMap[Pc];
  const uint8_t NumBytes =
      OpcodeU8 - static_cast<uint8_t>(evmc_opcode::OP_PUSH1) + 1;
  Frame->Pc += NumBytes;
}

static ZEN_EVM_INTERP_HELPER void executePushNOpcodeNoGas(
    zen::evm::EVMFrame *Frame, zen::evm::InterpreterExecContext &Context,
    uint8_t OpcodeU8, const intx::uint256 *__restrict PushValueMap) {
  if (Frame->Sp >= MAXSTACK) {
    Context.setStatus(EVMC_STACK_OVERFLOW);
    return;
  }

  const size_t Pc = static_cast<size_t>(Frame->Pc);
  Frame->Stack[Frame->Sp++] = PushValueMap[Pc];
  const uint8_t NumBytes =
      OpcodeU8 - static_cast<uint8_t>(evmc_opcode::OP_PUSH1) + 1;
  Frame->Pc += NumBytes;
}

static ZEN_EVM_INTERP_HELPER void executePopOpcode(
    zen::evm::EVMFrame *Frame, zen::evm::InterpreterExecContext &Context,
    const evmc_instruction_metrics *MetricsTable, uint8_t OpcodeU8) {
  if (!chargeGas(Frame, Context, MetricsTable, OpcodeU8)) {
    return;
  }
  if (Frame->Sp < 1) {
    Context.setStatus(EVMC_STACK_UNDERFLOW);
    return;
  }
  --Frame->Sp;
}

static ZEN_EVM_INTERP_HELPER void
executePopOpcodeNoGas(zen::evm::EVMFrame *Frame,
                      zen::evm::InterpreterExecContext &Context) {
  if (Frame->Sp < 1) {
    Context.setStatus(EVMC_STACK_UNDERFLOW);
    return;
  }
  --Frame->Sp;
}

static ZEN_EVM_INTERP_HELPER void executeDupOpcode(
    zen::evm::EVMFrame *Frame, zen::evm::InterpreterExecContext &Context,
    const evmc_instruction_metrics *MetricsTable, uint8_t OpcodeU8) {
  if (!chargeGas(Frame, Context, MetricsTable, OpcodeU8)) {
    return;
  }
  const uint32_t N = OpcodeU8 - static_cast<uint8_t>(evmc_opcode::OP_DUP1) + 1;
  if (Frame->Sp < N) {
    Context.setStatus(EVMC_STACK_UNDERFLOW);
    return;
  }
  if (Frame->Sp >= MAXSTACK) {
    Context.setStatus(EVMC_STACK_OVERFLOW);
    return;
  }
  Frame->Stack[Frame->Sp] = Frame->Stack[Frame->Sp - N];
  ++Frame->Sp;
}

static ZEN_EVM_INTERP_HELPER void
executeDupOpcodeNoGas(zen::evm::EVMFrame *Frame,
                      zen::evm::InterpreterExecContext &Context,
                      uint8_t OpcodeU8) {
  const uint32_t N = OpcodeU8 - static_cast<uint8_t>(evmc_opcode::OP_DUP1) + 1;
  if (Frame->Sp < N) {
    Context.setStatus(EVMC_STACK_UNDERFLOW);
    return;
  }
  if (Frame->Sp >= MAXSTACK) {
    Context.setStatus(EVMC_STACK_OVERFLOW);
    return;
  }
  Frame->Stack[Frame->Sp] = Frame->Stack[Frame->Sp - N];
  ++Frame->Sp;
}

static ZEN_EVM_INTERP_HELPER void executeSwapOpcode(
    zen::evm::EVMFrame *Frame, zen::evm::InterpreterExecContext &Context,
    const evmc_instruction_metrics *MetricsTable, uint8_t OpcodeU8) {
  if (!chargeGas(Frame, Context, MetricsTable, OpcodeU8)) {
    return;
  }
  const uint32_t N = OpcodeU8 - static_cast<uint8_t>(evmc_opcode::OP_SWAP1) + 1;
  if (Frame->Sp < N + 1) {
    Context.setStatus(EVMC_STACK_UNDERFLOW);
    return;
  }

  const size_t TopIndex = Frame->Sp - 1;
  const size_t NthIndex = Frame->Sp - 1 - N;
  auto &Top = Frame->Stack[TopIndex];
  auto &Nth = Frame->Stack[NthIndex];
  const intx::uint256 Tmp = Top;
  Top = Nth;
  Nth = Tmp;
}

static ZEN_EVM_INTERP_HELPER void
executeSwapOpcodeNoGas(zen::evm::EVMFrame *Frame,
                       zen::evm::InterpreterExecContext &Context,
                       uint8_t OpcodeU8) {
  const uint32_t N = OpcodeU8 - static_cast<uint8_t>(evmc_opcode::OP_SWAP1) + 1;
  if (Frame->Sp < N + 1) {
    Context.setStatus(EVMC_STACK_UNDERFLOW);
    return;
  }

  const size_t TopIndex = Frame->Sp - 1;
  const size_t NthIndex = Frame->Sp - 1 - N;
  auto &Top = Frame->Stack[TopIndex];
  auto &Nth = Frame->Stack[NthIndex];
  const intx::uint256 Tmp = Top;
  Top = Nth;
  Nth = Tmp;
}

static ZEN_EVM_INTERP_HELPER bool
handleExecutionStatus(zen::evm::EVMFrame *&Frame,
                      zen::evm::InterpreterExecContext &Context) {
  if (Context.getStatus() == EVMC_SUCCESS) {
    return false;
  }

  const evmc_status_code Status = Context.getStatus();
  switch (Status) {
  case EVMC_REVERT:
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
    Frame->Msg.gas = 0;
    Context.getInstance()->setGasRefund(Frame->GasRefundSnapshot);
    Context.setReturnData(std::vector<uint8_t>());
    Context.freeBackFrame();
    Frame = Context.getCurFrame();
    if (!Frame) {
      const auto &ReturnData = Context.getReturnData();
      evmc::Result ExeResult(Context.getStatus(), 0,
                             Context.getInstance()->getGasRefund(),
                             ReturnData.data(), ReturnData.size());
      Context.setExeResult(std::move(ExeResult));
      return true;
    }
    break;

  case EVMC_FAILURE:
  default:
    Frame->Msg.gas = 0;
    Context.getInstance()->setGasRefund(Frame->GasRefundSnapshot);
    Context.setReturnData(std::vector<uint8_t>());
    Context.freeBackFrame();
    Frame = Context.getCurFrame();
    if (!Frame) {
      const auto &ReturnData = Context.getReturnData();
      evmc::Result ExeResult(Context.getStatus(), 0,
                             Context.getInstance()->getGasRefund(),
                             ReturnData.data(), ReturnData.size());
      Context.setExeResult(std::move(ExeResult));
      return true;
    }
    break;
  }
  return false;
}

} // namespace

EVMFrame *InterpreterExecContext::allocTopFrame(evmc_message *Msg) {
  FrameStack.emplace_back();

  EVMFrame &Frame = FrameStack.back();

  Frame.Msg = *Msg;
  Inst->pushMessage(&Frame.Msg);
  Frame.GasRefundSnapshot = Inst ? Inst->getGasRefund() : 0;

  return &Frame;
}

// We only need to free the last frame (top of the stack),
// since EVM's control flow is purely stack-based.
void InterpreterExecContext::freeBackFrame() {
  if (FrameStack.empty())
    return;

  EVMFrame &Frame = FrameStack.back();

  Inst->setGas(static_cast<uint64_t>(Frame.Msg.gas));

  if (FrameStack.size() > 1) {
    Inst->popMessage();
  }

  // Destroy frame (and its message)
  FrameStack.pop_back();
}

void InterpreterExecContext::setCallData(const std::vector<uint8_t> &Data) {
  EVM_FRAME_CHECK(getCurFrame());
  getCurFrame()->CallData = Data;
  getCurFrame()->Msg.input_data = getCurFrame()->CallData.data();
  getCurFrame()->Msg.input_size = getCurFrame()->CallData.size();
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
  evmc_revision Revision = Context.getInstance()->getRevision();
  const auto *MetricsTable = evmc_get_instruction_metrics_table(Revision);
  const auto *NamesTable = evmc_get_instruction_names_table(Revision);
  const auto &Cache = Mod->getBytecodeCache();
  const uint8_t *__restrict JumpDestMap = Cache.JumpDestMap.data();
  const intx::uint256 *__restrict PushValueMap = Cache.PushValueMap.data();
  const uint32_t *__restrict GasChunkEnd = Cache.GasChunkEnd.data();
  const uint64_t *__restrict GasChunkCost = Cache.GasChunkCost.data();

  if (!Frame->Host) {
    Frame->Host = Context.getInstance()->getRuntime()->getEVMHost();
  }

  auto Uint256ToUint64 = [](const intx::uint256 &Value) -> uint64_t {
    if ((Value[3] | Value[2] | Value[1]) != 0) {
      return std::numeric_limits<uint64_t>::max();
    }
    return Value[0];
  };

  while (Frame->Pc < CodeSize) {
    const size_t ChunkStartPc = static_cast<size_t>(Frame->Pc);
    if (ChunkStartPc < CodeSize && GasChunkEnd[ChunkStartPc] > ChunkStartPc &&
        (uint64_t)Frame->Msg.gas >= GasChunkCost[ChunkStartPc]) {
      const uint32_t ChunkEnd = GasChunkEnd[ChunkStartPc];
      Frame->Msg.gas -= GasChunkCost[ChunkStartPc];
      bool RestartDispatch = false;
      while (Frame->Pc < ChunkEnd) {
        const Byte OpcodeByte = Code[Frame->Pc];
        const uint8_t OpcodeU8 = static_cast<uint8_t>(OpcodeByte);
        const evmc_opcode Op = static_cast<evmc_opcode>(OpcodeByte);

        // Use EVMC names with latest opcodes like MCOPY, CLZ...
        if (NamesTable[Op] == NULL) {
          // Undefined instruction
          Context.setStatus(EVMC_UNDEFINED_INSTRUCTION);
          break;
        }

        switch (Op) {
        case evmc_opcode::OP_STOP: {
          const uint64_t RemainingGas = Frame->Msg.gas;
          Context.setReturnData(std::vector<uint8_t>());
          Context.freeBackFrame();
          Frame = Context.getCurFrame();
          if (!Frame) {
            const auto &ReturnData = Context.getReturnData();
            const uint64_t GasLeft = Context.getInstance()->getGas();
            evmc::Result ExeResult(EVMC_SUCCESS, GasLeft,
                                   Context.getInstance()->getGasRefund(),
                                   ReturnData.data(), ReturnData.size());
            Context.setExeResult(std::move(ExeResult));
            return;
          }
          Frame->Msg.gas += RemainingGas;
          RestartDispatch = true;
        } break;

        case evmc_opcode::OP_ADD:
          AddHandler::doExecute();
          break;
        case evmc_opcode::OP_MUL:
          MulHandler::doExecute();
          break;
        case evmc_opcode::OP_SUB:
          SubHandler::doExecute();
          break;
        case evmc_opcode::OP_DIV:
          DivHandler::doExecute();
          break;
        case evmc_opcode::OP_SDIV:
          SDivHandler::doExecute();
          break;
        case evmc_opcode::OP_MOD:
          ModHandler::doExecute();
          break;
        case evmc_opcode::OP_SMOD:
          SModHandler::doExecute();
          break;
        case evmc_opcode::OP_ADDMOD:
          AddmodHandler::doExecute();
          break;
        case evmc_opcode::OP_MULMOD:
          MulmodHandler::doExecute();
          break;
        case evmc_opcode::OP_EXP:
          ExpHandler::doExecute();
          break;

        case evmc_opcode::OP_SIGNEXTEND:
          SignExtendHandler::doExecute();
          break;

        case evmc_opcode::OP_LT:
          LtHandler::doExecute();
          break;
        case evmc_opcode::OP_GT:
          GtHandler::doExecute();
          break;
        case evmc_opcode::OP_SLT:
          SltHandler::doExecute();
          break;
        case evmc_opcode::OP_SGT:
          SgtHandler::doExecute();
          break;
        case evmc_opcode::OP_EQ:
          EqHandler::doExecute();
          break;

        case evmc_opcode::OP_ISZERO:
          IsZeroHandler::doExecute();
          break;
        case evmc_opcode::OP_AND:
          AndHandler::doExecute();
          break;
        case evmc_opcode::OP_OR:
          OrHandler::doExecute();
          break;
        case evmc_opcode::OP_XOR:
          XorHandler::doExecute();
          break;
        case evmc_opcode::OP_NOT:
          NotHandler::doExecute();
          break;

        case evmc_opcode::OP_BYTE:
          ByteHandler::doExecute();
          break;
        case evmc_opcode::OP_SHL:
          ShlHandler::doExecute();
          break;
        case evmc_opcode::OP_SHR:
          ShrHandler::doExecute();
          break;
        case evmc_opcode::OP_SAR:
          SarHandler::doExecute();
          break;
        case evmc_opcode::OP_CLZ:
          ClzHandler::doExecute();
          break;

        case evmc_opcode::OP_KECCAK256:
          Keccak256Handler::doExecute();
          break;

        case evmc_opcode::OP_ADDRESS:
          AddressHandler::doExecute();
          break;
        case evmc_opcode::OP_BALANCE:
          BalanceHandler::doExecute();
          break;
        case evmc_opcode::OP_ORIGIN:
          OriginHandler::doExecute();
          break;
        case evmc_opcode::OP_CALLER:
          CallerHandler::doExecute();
          break;
        case evmc_opcode::OP_CALLVALUE:
          CallValueHandler::doExecute();
          break;
        case evmc_opcode::OP_CALLDATALOAD:
          CallDataLoadHandler::doExecute();
          break;
        case evmc_opcode::OP_CALLDATASIZE:
          CallDataSizeHandler::doExecute();
          break;
        case evmc_opcode::OP_CALLDATACOPY:
          CallDataCopyHandler::doExecute();
          break;
        case evmc_opcode::OP_CODESIZE:
          CodeSizeHandler::doExecute();
          break;
        case evmc_opcode::OP_CODECOPY:
          CodeCopyHandler::doExecute();
          break;
        case evmc_opcode::OP_GASPRICE:
          GasPriceHandler::doExecute();
          break;
        case evmc_opcode::OP_EXTCODESIZE:
          ExtCodeSizeHandler::doExecute();
          break;
        case evmc_opcode::OP_EXTCODECOPY:
          ExtCodeCopyHandler::doExecute();
          break;
        case evmc_opcode::OP_RETURNDATASIZE:
          ReturnDataSizeHandler::doExecute();
          break;
        case evmc_opcode::OP_RETURNDATACOPY:
          ReturnDataCopyHandler::doExecute();
          break;
        case evmc_opcode::OP_EXTCODEHASH:
          ExtCodeHashHandler::doExecute();
          break;

        case evmc_opcode::OP_BLOCKHASH:
          BlockHashHandler::doExecute();
          break;
        case evmc_opcode::OP_COINBASE:
          CoinBaseHandler::doExecute();
          break;
        case evmc_opcode::OP_TIMESTAMP:
          TimeStampHandler::doExecute();
          break;
        case evmc_opcode::OP_NUMBER:
          NumberHandler::doExecute();
          break;
        case evmc_opcode::OP_PREVRANDAO:
          PrevRanDaoHandler::doExecute();
          break;
        case evmc_opcode::OP_GASLIMIT:
          GasLimitHandler::doExecute();
          break;
        case evmc_opcode::OP_CHAINID:
          ChainIdHandler::doExecute();
          break;
        case evmc_opcode::OP_SELFBALANCE:
          SelfBalanceHandler::doExecute();
          break;
        case evmc_opcode::OP_BASEFEE:
          BaseFeeHandler::doExecute();
          break;
        case evmc_opcode::OP_BLOBHASH:
          BlobHashHandler::doExecute();
          break;
        case evmc_opcode::OP_BLOBBASEFEE:
          BlobBaseFeeHandler::doExecute();
          break;

        case evmc_opcode::OP_POP:
          executePopOpcodeNoGas(Frame, Context);
          break;

        case evmc_opcode::OP_MLOAD:
          MLoadHandler::doExecute();
          break;
        case evmc_opcode::OP_MSTORE:
          MStoreHandler::doExecute();
          break;
        case evmc_opcode::OP_MSTORE8:
          MStore8Handler::doExecute();
          break;

        case evmc_opcode::OP_SLOAD:
          SLoadHandler::doExecute();
          break;
        case evmc_opcode::OP_SSTORE:
          SStoreHandler::doExecute();
          break;

        case evmc_opcode::OP_JUMP: {
          if (Frame->Sp < 1) {
            Context.setStatus(EVMC_STACK_UNDERFLOW);
            break;
          }

          --Frame->Sp;
          const uint64_t Dest = Uint256ToUint64(Frame->Stack[Frame->Sp]);
          if (Dest >= CodeSize) {
            Context.setStatus(EVMC_BAD_JUMP_DESTINATION);
            break;
          }
          if (JumpDestMap[Dest] == 0) {
            Context.setStatus(EVMC_BAD_JUMP_DESTINATION);
            break;
          }

          Frame->Pc = Dest;
          RestartDispatch = true;
          break;
        }

        case evmc_opcode::OP_JUMPI: {
          if (Frame->Sp < 2) {
            Context.setStatus(EVMC_STACK_UNDERFLOW);
            break;
          }

          --Frame->Sp;
          const uint64_t Dest = Uint256ToUint64(Frame->Stack[Frame->Sp]);
          --Frame->Sp;
          const intx::uint256 &Cond = Frame->Stack[Frame->Sp];
          if (!Cond) {
            break;
          }
          if (Dest >= CodeSize) {
            Context.setStatus(EVMC_BAD_JUMP_DESTINATION);
            break;
          }
          if (JumpDestMap[Dest] == 0) {
            Context.setStatus(EVMC_BAD_JUMP_DESTINATION);
            break;
          }

          Frame->Pc = Dest;
          RestartDispatch = true;
          break;
        }

        case evmc_opcode::OP_PC:
          PCHandler::doExecute();
          break;
        case evmc_opcode::OP_MSIZE:
          MSizeHandler::doExecute();
          break;
        case evmc_opcode::OP_GAS:
          GasHandler::doExecute();
          break;

        case evmc_opcode::OP_JUMPDEST:
          break;

        case evmc_opcode::OP_TLOAD:
          TLoadHandler::doExecute();
          break;
        case evmc_opcode::OP_TSTORE:
          TStoreHandler::doExecute();
          break;

        case evmc_opcode::OP_MCOPY:
          MCopyHandler::doExecute();
          break;

        case evmc_opcode::OP_PUSH0:
          executePush0OpcodeNoGas(Frame, Context);
          break;

        case evmc_opcode::OP_LOG0:
        case evmc_opcode::OP_LOG1:
        case evmc_opcode::OP_LOG2:
        case evmc_opcode::OP_LOG3:
        case evmc_opcode::OP_LOG4:
          LogHandler::OpCode = Op;
          LogHandler::doExecute();
          break;

        case evmc_opcode::OP_RETURN: {
          ReturnHandler::doExecute();
          Frame = Context.getCurFrame();
          if (!Frame) {
            const auto &ReturnData = Context.getReturnData();
            const uint64_t GasLeft = Context.getInstance()->getGas();
            evmc::Result ExeResult(EVMC_SUCCESS, GasLeft,
                                   Context.getInstance()->getGasRefund(),
                                   ReturnData.data(), ReturnData.size());
            Context.setExeResult(std::move(ExeResult));
            return;
          }
          RestartDispatch = true;
          break;
        }

        case evmc_opcode::OP_REVERT: {
          RevertHandler::doExecute();
          Frame = Context.getCurFrame();
          if (!Frame) {
            const auto &ReturnData = Context.getReturnData();
            const uint64_t GasLeft = Context.getInstance()->getGas();
            evmc::Result ExeResult(EVMC_REVERT, GasLeft,
                                   Context.getInstance()->getGasRefund(),
                                   ReturnData.data(), ReturnData.size());
            Context.setExeResult(std::move(ExeResult));
            return;
          }
          RestartDispatch = true;
          break;
        }

        case evmc_opcode::OP_INVALID:
          Context.setStatus(EVMC_INVALID_INSTRUCTION);
          break;

        case evmc_opcode::OP_SELFDESTRUCT: {
          SelfDestructHandler::doExecute();
          Frame = Context.getCurFrame();
          if (!Frame) {
            const auto &ReturnData = Context.getReturnData();
            const uint64_t GasLeft = Context.getInstance()->getGas();
            evmc::Result ExeResult(EVMC_SUCCESS, GasLeft,
                                   Context.getInstance()->getGasRefund(),
                                   ReturnData.data(), ReturnData.size());
            Context.setExeResult(std::move(ExeResult));
            return;
          }
          RestartDispatch = true;
          break;
        }

        default:
          if (OpcodeU8 >= static_cast<uint8_t>(evmc_opcode::OP_PUSH1) &&
              OpcodeU8 <= static_cast<uint8_t>(evmc_opcode::OP_PUSH32)) {
            executePushNOpcodeNoGas(Frame, Context, OpcodeU8, PushValueMap);
            break;
          }
          if (OpcodeU8 >= static_cast<uint8_t>(evmc_opcode::OP_DUP1) &&
              OpcodeU8 <= static_cast<uint8_t>(evmc_opcode::OP_DUP16)) {
            executeDupOpcodeNoGas(Frame, Context, OpcodeU8);
            break;
          }
          if (OpcodeU8 >= static_cast<uint8_t>(evmc_opcode::OP_SWAP1) &&
              OpcodeU8 <= static_cast<uint8_t>(evmc_opcode::OP_SWAP16)) {
            executeSwapOpcodeNoGas(Frame, Context, OpcodeU8);
            break;
          }
          if (OpcodeByte == static_cast<Byte>(evmc_opcode::OP_CREATE) ||
              OpcodeByte == static_cast<Byte>(evmc_opcode::OP_CREATE2)) {
            CreateHandler::OpCode = static_cast<evmc_opcode>(OpcodeByte);
            CreateHandler::doExecute();
            break;
          }
          if (OpcodeByte == static_cast<Byte>(evmc_opcode::OP_CALL) ||
              OpcodeByte == static_cast<Byte>(evmc_opcode::OP_CALLCODE) ||
              OpcodeByte == static_cast<Byte>(evmc_opcode::OP_DELEGATECALL) ||
              OpcodeByte == static_cast<Byte>(evmc_opcode::OP_STATICCALL)) {
            CallHandler::OpCode = static_cast<evmc_opcode>(OpcodeByte);
            CallHandler::doExecute();
            break;
          }
          Context.setStatus(EVMC_UNDEFINED_INSTRUCTION);
        }

        if (INTX_UNLIKELY(Context.getStatus() != EVMC_SUCCESS)) {
          break;
        }
        if (RestartDispatch) {
          break;
        }
        Frame->Pc++;
      }
      if (INTX_UNLIKELY(Context.getStatus() != EVMC_SUCCESS)) {
        if (handleExecutionStatus(Frame, Context)) {
          return;
        }
        break;
      }
      if (RestartDispatch) {
        continue;
      }
      continue;
    }

    Byte OpcodeByte = Code[Frame->Pc];
    evmc_opcode Op = static_cast<evmc_opcode>(OpcodeByte);

    switch (Op) {
    case evmc_opcode::OP_STOP:
      Context.setReturnData(std::vector<uint8_t>());
      Context.freeBackFrame();
      Frame = Context.getCurFrame();
      if (!Frame) {
        const auto &ReturnData = Context.getReturnData();
        const uint64_t GasLeft = Context.getInstance()->getGas();
        evmc::Result ExeResult(EVMC_SUCCESS, GasLeft,
                               Context.getInstance()->getGasRefund(),
                               ReturnData.data(), ReturnData.size());
        Context.setExeResult(std::move(ExeResult));
        return;
      }
      continue;

    case evmc_opcode::OP_ADD: {
      AddHandler::execute();
      break;
    }

    case evmc_opcode::OP_MUL: {
      MulHandler::execute();
      break;
    }

    case evmc_opcode::OP_SUB: {
      SubHandler::execute();
      break;
    }

    case evmc_opcode::OP_DIV: {
      DivHandler::execute();
      break;
    }

    case evmc_opcode::OP_SDIV: {
      SDivHandler::execute();
      break;
    }

    case evmc_opcode::OP_MOD: {
      ModHandler::execute();
      break;
    }

    case evmc_opcode::OP_SMOD: {
      SModHandler::execute();
      break;
    }

    case evmc_opcode::OP_ADDMOD: {
      AddmodHandler::execute();
      break;
    }

    case evmc_opcode::OP_MULMOD: {
      MulmodHandler::execute();
      break;
    }

    case evmc_opcode::OP_EXP: {
      ExpHandler::execute();
      break;
    }

    case evmc_opcode::OP_SIGNEXTEND: {
      SignExtendHandler::execute();
      break;
    }

    case evmc_opcode::OP_LT: {
      LtHandler::execute();
      break;
    }

    case evmc_opcode::OP_GT: {
      GtHandler::execute();
      break;
    }

    case evmc_opcode::OP_SLT: {
      SltHandler::execute();
      break;
    }

    case evmc_opcode::OP_SGT: {
      SgtHandler::execute();
      break;
    }

    case evmc_opcode::OP_EQ: {
      EqHandler::execute();
      break;
    }

    case evmc_opcode::OP_ISZERO: {
      IsZeroHandler::execute();
      break;
    }

    case evmc_opcode::OP_AND: {
      AndHandler::execute();
      break;
    }

    case evmc_opcode::OP_OR: {
      OrHandler::execute();
      break;
    }

    case evmc_opcode::OP_XOR: {
      XorHandler::execute();
      break;
    }

    case evmc_opcode::OP_NOT: {
      NotHandler::execute();
      break;
    }

    case evmc_opcode::OP_BYTE: {
      ByteHandler::execute();
      break;
    }

    case evmc_opcode::OP_SHL: {
      ShlHandler::execute();
      break;
    }

    case evmc_opcode::OP_SHR: {
      ShrHandler::execute();
      break;
    }

    case evmc_opcode::OP_SAR: {
      SarHandler::execute();
      break;
    }

    case evmc_opcode::OP_CLZ: {
      ClzHandler::execute();
      break;
    }

    case evmc_opcode::OP_KECCAK256: {
      Keccak256Handler::execute();
      break;
    }

    case evmc_opcode::OP_ADDRESS: {
      AddressHandler::execute();
      break;
    }

    case evmc_opcode::OP_BALANCE: {
      BalanceHandler::execute();
      break;
    }

    case evmc_opcode::OP_ORIGIN: {
      OriginHandler::execute();
      break;
    }

    case evmc_opcode::OP_CALLER: {
      CallerHandler::execute();
      break;
    }

    case evmc_opcode::OP_CALLVALUE: {
      CallValueHandler::execute();
      break;
    }

    case evmc_opcode::OP_CALLDATALOAD: {
      CallDataLoadHandler::execute();
      break;
    }

    case evmc_opcode::OP_CALLDATASIZE: {
      CallDataSizeHandler::execute();
      break;
    }

    case evmc_opcode::OP_CALLDATACOPY: {
      CallDataCopyHandler::execute();
      break;
    }

    case evmc_opcode::OP_CODESIZE: {
      CodeSizeHandler::execute();
      break;
    }

    case evmc_opcode::OP_CODECOPY: {
      CodeCopyHandler::execute();
      break;
    }

    case evmc_opcode::OP_GASPRICE: {
      GasPriceHandler::execute();
      break;
    }

    case evmc_opcode::OP_EXTCODESIZE: {
      ExtCodeSizeHandler::execute();
      break;
    }

    case evmc_opcode::OP_EXTCODECOPY: {
      ExtCodeCopyHandler::execute();
      break;
    }

    case evmc_opcode::OP_RETURNDATASIZE: {
      ReturnDataSizeHandler::execute();
      break;
    }

    case evmc_opcode::OP_RETURNDATACOPY: {
      ReturnDataCopyHandler::execute();
      break;
    }

    case evmc_opcode::OP_EXTCODEHASH: {
      ExtCodeHashHandler::execute();
      break;
    }

    case evmc_opcode::OP_BLOCKHASH: {
      BlockHashHandler::execute();
      break;
    }

    case evmc_opcode::OP_COINBASE: {
      CoinBaseHandler::execute();
      break;
    }

    case evmc_opcode::OP_TIMESTAMP: {
      TimeStampHandler::execute();
      break;
    }

    case evmc_opcode::OP_NUMBER: {
      NumberHandler::execute();
      break;
    }

    case evmc_opcode::OP_PREVRANDAO: {
      PrevRanDaoHandler::execute();
      break;
    }

    case evmc_opcode::OP_GASLIMIT: {
      GasLimitHandler::execute();
      break;
    }

    case evmc_opcode::OP_CHAINID: {
      ChainIdHandler::execute();
      break;
    }

    case evmc_opcode::OP_SELFBALANCE: {
      SelfBalanceHandler::execute();
      break;
    }

    case evmc_opcode::OP_BASEFEE: {
      BaseFeeHandler::execute();
      break;
    }

    case evmc_opcode::OP_BLOBHASH: {
      BlobHashHandler::execute();
      break;
    }

    case evmc_opcode::OP_BLOBBASEFEE: {
      BlobBaseFeeHandler::execute();
      break;
    }

    case evmc_opcode::OP_POP: {
      executePopOpcode(Frame, Context, MetricsTable,
                       static_cast<uint8_t>(OpcodeByte));
      break;
    }

    case evmc_opcode::OP_MLOAD: {
      MLoadHandler::execute();
      break;
    }

    case evmc_opcode::OP_MSTORE: {
      MStoreHandler::execute();
      break;
    }

    case evmc_opcode::OP_MSTORE8: {
      MStore8Handler::execute();
      break;
    }

    case evmc_opcode::OP_SLOAD: {
      SLoadHandler::execute();
      break;
    }

    case evmc_opcode::OP_SSTORE: {
      SStoreHandler::execute();
      break;
    }

    case evmc_opcode::OP_JUMP: {
      if (!chargeGas(Frame, Context, MetricsTable,
                     static_cast<uint8_t>(OpcodeByte))) {
        break;
      }
      if (Frame->Sp < 1) {
        Context.setStatus(EVMC_STACK_UNDERFLOW);
        break;
      }

      --Frame->Sp;
      const uint64_t Dest = Uint256ToUint64(Frame->Stack[Frame->Sp]);
      if (Dest >= CodeSize) {
        Context.setStatus(EVMC_BAD_JUMP_DESTINATION);
        break;
      }
      if (JumpDestMap[Dest] == 0) {
        Context.setStatus(EVMC_BAD_JUMP_DESTINATION);
        break;
      }

      Frame->Pc = Dest;
      continue;
    }

    case evmc_opcode::OP_JUMPI: {
      if (!chargeGas(Frame, Context, MetricsTable,
                     static_cast<uint8_t>(OpcodeByte))) {
        break;
      }
      if (Frame->Sp < 2) {
        Context.setStatus(EVMC_STACK_UNDERFLOW);
        break;
      }

      --Frame->Sp;
      const uint64_t Dest = Uint256ToUint64(Frame->Stack[Frame->Sp]);
      --Frame->Sp;
      const intx::uint256 &Cond = Frame->Stack[Frame->Sp];
      if (!Cond) {
        break;
      }
      if (Dest >= CodeSize) {
        Context.setStatus(EVMC_BAD_JUMP_DESTINATION);
        break;
      }
      if (JumpDestMap[Dest] == 0) {
        Context.setStatus(EVMC_BAD_JUMP_DESTINATION);
        break;
      }

      Frame->Pc = Dest;
      continue;
    }

    case evmc_opcode::OP_PC: {
      PCHandler::execute();
      break;
    }

    case evmc_opcode::OP_MSIZE: {
      MSizeHandler::execute();
      break;
    }

    case evmc_opcode::OP_GAS: {
      GasHandler::execute();
      break;
    }

    case evmc_opcode::OP_JUMPDEST: {
      if (!chargeGas(Frame, Context, MetricsTable,
                     static_cast<uint8_t>(OpcodeByte))) {
        break;
      }
      break;
    }

    case evmc_opcode::OP_TLOAD: {
      TLoadHandler::execute();
      break;
    }

    case evmc_opcode::OP_TSTORE: {
      TStoreHandler::execute();
      break;
    }

    case evmc_opcode::OP_MCOPY: {
      MCopyHandler::execute();
      break;
    }

    case evmc_opcode::OP_PUSH0: { // PUSH0 (EIP-3855)
      executePush0Opcode(Frame, Context, MetricsTable,
                         static_cast<uint8_t>(OpcodeByte));
      break;
    }

    case evmc_opcode::OP_LOG0:
    case evmc_opcode::OP_LOG1:
    case evmc_opcode::OP_LOG2:
    case evmc_opcode::OP_LOG3:
    case evmc_opcode::OP_LOG4: {
      LogHandler::OpCode = static_cast<evmc_opcode>(OpcodeByte);
      LogHandler::execute();
      break;
    }

    case evmc_opcode::OP_RETURN: {
      ReturnHandler::execute();
      Frame = Context.getCurFrame();
      if (!Frame) {
        const auto &ReturnData = Context.getReturnData();
        const uint64_t GasLeft = Context.getInstance()->getGas();
        evmc::Result ExeResult(EVMC_SUCCESS, GasLeft,
                               Context.getInstance()->getGasRefund(),
                               ReturnData.data(), ReturnData.size());
        Context.setExeResult(std::move(ExeResult));
        return;
      }
      break;
    }

    case evmc_opcode::OP_REVERT: {
      RevertHandler::execute();
      Frame = Context.getCurFrame();
      if (!Frame) {
        const auto &ReturnData = Context.getReturnData();
        const uint64_t GasLeft = Context.getInstance()->getGas();
        evmc::Result ExeResult(EVMC_REVERT, GasLeft,
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
      SelfDestructHandler::execute();
      Frame = Context.getCurFrame();
      if (!Frame) {
        const auto &ReturnData = Context.getReturnData();
        const uint64_t GasLeft = Context.getInstance()->getGas();
        evmc::Result ExeResult(EVMC_SUCCESS, GasLeft,
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
        executePushNOpcode(Frame, Context, MetricsTable,
                           static_cast<uint8_t>(OpcodeByte), PushValueMap);
        break;
      } else if (OpcodeByte >= static_cast<Byte>(evmc_opcode::OP_DUP1) &&
                 OpcodeByte <= static_cast<Byte>(evmc_opcode::OP_DUP16)) {
        // DUP1 ~ DUP16
        executeDupOpcode(Frame, Context, MetricsTable,
                         static_cast<uint8_t>(OpcodeByte));
        break;
      } else if (OpcodeByte >= static_cast<Byte>(evmc_opcode::OP_SWAP1) &&
                 OpcodeByte <= static_cast<Byte>(evmc_opcode::OP_SWAP16)) {
        // SWAP1 ~ SWAP16
        executeSwapOpcode(Frame, Context, MetricsTable,
                          static_cast<uint8_t>(OpcodeByte));
        break;
      } else if (OpcodeByte == static_cast<Byte>(evmc_opcode::OP_CREATE) ||
                 OpcodeByte == static_cast<Byte>(evmc_opcode::OP_CREATE2)) {
        CreateHandler::OpCode = static_cast<evmc_opcode>(OpcodeByte);
        CreateHandler::execute();
        break;
      } else if (OpcodeByte == static_cast<Byte>(evmc_opcode::OP_CALL) ||
                 OpcodeByte == static_cast<Byte>(evmc_opcode::OP_CALLCODE) ||
                 OpcodeByte ==
                     static_cast<Byte>(evmc_opcode::OP_DELEGATECALL) ||
                 OpcodeByte == static_cast<Byte>(evmc_opcode::OP_STATICCALL)) {
        CallHandler::OpCode = static_cast<evmc_opcode>(OpcodeByte);
        CallHandler::execute();
        break;
      } else {
        Context.setStatus(EVMC_INVALID_INSTRUCTION);
      }
    }

    if (INTX_UNLIKELY(Context.getStatus() != EVMC_SUCCESS)) {
      if (handleExecutionStatus(Frame, Context)) {
        return;
      }
      break;
    }

    Frame->Pc++;
  }
  Context.freeBackFrame();
  const auto &ReturnData = Context.getReturnData();
  uint64_t GasLeft = Context.getInstance()->getGas();
  if (auto *Cur = Context.getCurFrame()) {
    GasLeft = static_cast<uint64_t>(Cur->Msg.gas);
  }
  evmc::Result ExeResult(Context.getStatus(), GasLeft,
                         Context.getInstance()->getGasRefund(),
                         ReturnData.data(), ReturnData.size());
  Context.setExeResult(std::move(ExeResult));
}
