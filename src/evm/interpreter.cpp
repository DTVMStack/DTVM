// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "evm/interpreter.h"
#include "common/errors.h"
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
    Context.clearReturnData();
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
    Context.clearReturnData();
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

namespace {

/// Beyond this retained capacity, Memory / CallData are shrink_to_fit() after
/// clear() so reusing EVMFrame objects does not grow RSS without bound.
constexpr size_t kMaxRetainedFrameBufferBytes = 1024 * 1024;

static void clearFrameTransientBuffers(EVMFrame &Frame) {
  Frame.Memory.clear();
  if (Frame.Memory.capacity() > kMaxRetainedFrameBufferBytes)
    Frame.Memory.shrink_to_fit();
  Frame.CallData.clear();
  if (Frame.CallData.capacity() > kMaxRetainedFrameBufferBytes)
    Frame.CallData.shrink_to_fit();
}

static void releaseAllFrameBuffersIfLarge(std::vector<EVMFrame> &Frames) {
  for (EVMFrame &F : Frames)
    clearFrameTransientBuffers(F);
}

} // namespace

void InterpreterExecContext::resetForNewCall(runtime::EVMInstance *NewInst) {
  Inst = NewInst;
  FrameCount = 0;
  releaseAllFrameBuffersIfLarge(FrameStack);
  Status = EVMC_SUCCESS;
  ReturnData.clear();
  IsJump = false;
  ExeResult = evmc::Result{EVMC_SUCCESS, 0, 0};
}

EVMFrame *InterpreterExecContext::allocTopFrame(evmc_message *Msg) {
  const bool Reuse = (FrameCount < FrameStack.size());
  if (!Reuse) {
    FrameStack.emplace_back();
  }
  EVMFrame &Frame = FrameStack[FrameCount];
  if (Reuse) {
    // Reuse an existing EVMFrame object – avoids zero-initializing the
    // 32 KB uint256 stack array.  Only reset the fields that matter.
    Frame.Sp = 0;
    Frame.Pc = 0;
    Frame.Host = nullptr;
    clearFrameTransientBuffers(Frame);
    Frame.MTx = {};
    Frame.Value = 0;
  }
  ++FrameCount;

  Frame.Msg = *Msg;
  Inst->pushMessage(&Frame.Msg);
  Frame.GasRefundSnapshot = Inst ? Inst->getGasRefund() : 0;

  return &Frame;
}

// We only need to free the last frame (top of the stack),
// since EVM's control flow is purely stack-based.
void InterpreterExecContext::freeBackFrame() {
  if (FrameCount == 0)
    return;

  EVMFrame &Frame = FrameStack[FrameCount - 1];

  Inst->setGas(static_cast<uint64_t>(Frame.Msg.gas));

  if (FrameCount > 1) {
    Inst->popMessage();
  }

  // Logically free the frame but keep the EVMFrame object alive so its
  // 32 KB stack array can be reused by the next allocTopFrame().
  --FrameCount;
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
  const auto *Table = evmc_get_instruction_metrics_table(Inst->getRevision());
  EVMResource::setMetricsTable(Table);
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
  EVMResource::setMetricsTable(MetricsTable);
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
#if defined(__GNUC__)
      // =================== COMPUTED GOTO FAST PATH ===================
      // Uses computed goto (GCC/Clang extension) for better branch
      // prediction (one indirect branch predictor entry per opcode),
      // local stack pointer for register allocation, and inlined hot
      // opcodes to eliminate EVMResource static global loads.
      {
        uint64_t Pc = Frame->Pc;
        size_t sp = Frame->Sp;

        // Per-revision dispatch tables: opcodes not available in a given
        // revision map to TARGET_UNDEFINED.  Initialized once on first
        // call.  EVMC execute() is single-threaded per VM instance, so
        // no data race in practice.  std::call_once cannot be used here
        // because &&label (GCC/Clang extension) requires labels to be in
        // the same function, and a lambda creates a separate function.
        static void *cgoto_tables[EVMC_MAX_REVISION + 1][256];
        static bool cgoto_initialized = false;
        if (!cgoto_initialized) {
          void *undef = &&TARGET_UNDEFINED;
          void *base[256];
          for (int i = 0; i < 256; i++)
            base[i] = undef;
          base[0x00] = &&TARGET_STOP;
          base[0x01] = &&TARGET_ADD;
          base[0x02] = &&TARGET_MUL;
          base[0x03] = &&TARGET_SUB;
          base[0x04] = &&TARGET_DIV;
          base[0x05] = &&TARGET_SDIV;
          base[0x06] = &&TARGET_MOD;
          base[0x07] = &&TARGET_SMOD;
          base[0x08] = &&TARGET_ADDMOD;
          base[0x09] = &&TARGET_MULMOD;
          base[0x0a] = &&TARGET_EXP;
          base[0x0b] = &&TARGET_SIGNEXTEND;
          base[0x10] = &&TARGET_LT;
          base[0x11] = &&TARGET_GT;
          base[0x12] = &&TARGET_SLT;
          base[0x13] = &&TARGET_SGT;
          base[0x14] = &&TARGET_EQ;
          base[0x15] = &&TARGET_ISZERO;
          base[0x16] = &&TARGET_AND;
          base[0x17] = &&TARGET_OR;
          base[0x18] = &&TARGET_XOR;
          base[0x19] = &&TARGET_NOT;
          base[0x1a] = &&TARGET_BYTE;
          base[0x1b] = &&TARGET_SHL;
          base[0x1c] = &&TARGET_SHR;
          base[0x1d] = &&TARGET_SAR;
          base[0x1e] = &&TARGET_CLZ;
          base[0x20] = &&TARGET_KECCAK256;
          base[0x30] = &&TARGET_ADDRESS;
          base[0x31] = &&TARGET_BALANCE;
          base[0x32] = &&TARGET_ORIGIN;
          base[0x33] = &&TARGET_CALLER;
          base[0x34] = &&TARGET_CALLVALUE;
          base[0x35] = &&TARGET_CALLDATALOAD;
          base[0x36] = &&TARGET_CALLDATASIZE;
          base[0x37] = &&TARGET_CALLDATACOPY;
          base[0x38] = &&TARGET_CODESIZE;
          base[0x39] = &&TARGET_CODECOPY;
          base[0x3a] = &&TARGET_GASPRICE;
          base[0x3b] = &&TARGET_EXTCODESIZE;
          base[0x3c] = &&TARGET_EXTCODECOPY;
          base[0x3d] = &&TARGET_RETURNDATASIZE;
          base[0x3e] = &&TARGET_RETURNDATACOPY;
          base[0x3f] = &&TARGET_EXTCODEHASH;
          base[0x40] = &&TARGET_BLOCKHASH;
          base[0x41] = &&TARGET_COINBASE;
          base[0x42] = &&TARGET_TIMESTAMP;
          base[0x43] = &&TARGET_NUMBER;
          base[0x44] = &&TARGET_PREVRANDAO;
          base[0x45] = &&TARGET_GASLIMIT;
          base[0x46] = &&TARGET_CHAINID;
          base[0x47] = &&TARGET_SELFBALANCE;
          base[0x48] = &&TARGET_BASEFEE;
          base[0x49] = &&TARGET_BLOBHASH;
          base[0x4a] = &&TARGET_BLOBBASEFEE;
          base[0x50] = &&TARGET_POP;
          base[0x51] = &&TARGET_MLOAD;
          base[0x52] = &&TARGET_MSTORE;
          base[0x53] = &&TARGET_MSTORE8;
          base[0x54] = &&TARGET_SLOAD;
          base[0x55] = &&TARGET_SSTORE;
          base[0x56] = &&TARGET_JUMP;
          base[0x57] = &&TARGET_JUMPI;
          base[0x58] = &&TARGET_PC;
          base[0x59] = &&TARGET_MSIZE;
          base[0x5a] = &&TARGET_GAS;
          base[0x5b] = &&TARGET_JUMPDEST;
          base[0x5c] = &&TARGET_TLOAD;
          base[0x5d] = &&TARGET_TSTORE;
          base[0x5e] = &&TARGET_MCOPY;
          base[0x5f] = &&TARGET_PUSH0;
          for (int i = 0x60; i <= 0x7f; i++)
            base[i] = &&TARGET_PUSHX;
          for (int i = 0x80; i <= 0x8f; i++)
            base[i] = &&TARGET_DUPX;
          for (int i = 0x90; i <= 0x9f; i++)
            base[i] = &&TARGET_SWAPX;
          for (int i = 0xa0; i <= 0xa4; i++)
            base[i] = &&TARGET_LOGX;
          base[0xf0] = &&TARGET_CREATEX;
          base[0xf1] = &&TARGET_CALLX;
          base[0xf2] = &&TARGET_CALLX;
          base[0xf3] = &&TARGET_RETURN;
          base[0xf4] = &&TARGET_CALLX;
          base[0xf5] = &&TARGET_CREATEX;
          base[0xfa] = &&TARGET_CALLX;
          base[0xfd] = &&TARGET_REVERT;
          base[0xfe] = &&TARGET_INVALID;
          base[0xff] = &&TARGET_SELFDESTRUCT;

          for (int rev = 0; rev <= EVMC_MAX_REVISION; ++rev) {
            const auto *names = evmc_get_instruction_names_table(
                static_cast<evmc_revision>(rev));
            for (int i = 0; i < 256; i++)
              cgoto_tables[rev][i] = names[i] ? base[i] : undef;
          }
          cgoto_initialized = true;
        }
        void *const *cgoto_table = cgoto_tables[Revision];

// Dispatch to next opcode or exit if chunk boundary reached
#define DISPATCH_NEXT                                                          \
  do {                                                                         \
    if (INTX_UNLIKELY(Pc >= ChunkEnd))                                         \
      goto cgoto_chunk_done;                                                   \
    goto *cgoto_table[static_cast<uint8_t>(Code[Pc])];                         \
  } while (0)

// Write back local sp/Pc, set EVMResource, call handler, reload sp,
// advance Pc, check status, and dispatch next opcode
#define HANDLER_CALL(handler_expr)                                             \
  do {                                                                         \
    Frame->Sp = sp;                                                            \
    Frame->Pc = Pc;                                                            \
    EVMResource::setExecutionContext(Frame, &Context);                         \
    handler_expr;                                                              \
    sp = Frame->Sp;                                                            \
    ++Pc;                                                                      \
    if (INTX_UNLIKELY(Context.getStatus() != EVMC_SUCCESS))                    \
      goto cgoto_error;                                                        \
    DISPATCH_NEXT;                                                             \
  } while (0)

        // Initial dispatch
        goto *cgoto_table[static_cast<uint8_t>(Code[Pc])];

      // ---- Inline binary arithmetic/logic ops ----
      TARGET_ADD : {
        if (INTX_UNLIKELY(sp < 2)) {
          Context.setStatus(EVMC_STACK_UNDERFLOW);
          goto cgoto_error;
        }
        auto &A = Frame->Stack[sp - 1];
        auto &B = Frame->Stack[sp - 2];
        B = A + B;
        --sp;
        ++Pc;
        DISPATCH_NEXT;
      }
      TARGET_MUL : {
        if (INTX_UNLIKELY(sp < 2)) {
          Context.setStatus(EVMC_STACK_UNDERFLOW);
          goto cgoto_error;
        }
        auto &A = Frame->Stack[sp - 1];
        auto &B = Frame->Stack[sp - 2];
        B = A * B;
        --sp;
        ++Pc;
        DISPATCH_NEXT;
      }
      TARGET_SUB : {
        if (INTX_UNLIKELY(sp < 2)) {
          Context.setStatus(EVMC_STACK_UNDERFLOW);
          goto cgoto_error;
        }
        auto &A = Frame->Stack[sp - 1];
        auto &B = Frame->Stack[sp - 2];
        B = A - B;
        --sp;
        ++Pc;
        DISPATCH_NEXT;
      }
      TARGET_DIV : {
        if (INTX_UNLIKELY(sp < 2)) {
          Context.setStatus(EVMC_STACK_UNDERFLOW);
          goto cgoto_error;
        }
        auto &A = Frame->Stack[sp - 1];
        auto &B = Frame->Stack[sp - 2];
        B = (B == 0) ? intx::uint256(0) : (A / B);
        --sp;
        ++Pc;
        DISPATCH_NEXT;
      }
      TARGET_SDIV : {
        if (INTX_UNLIKELY(sp < 2)) {
          Context.setStatus(EVMC_STACK_UNDERFLOW);
          goto cgoto_error;
        }
        auto &A = Frame->Stack[sp - 1];
        auto &B = Frame->Stack[sp - 2];
        B = (B == 0) ? intx::uint256(0) : intx::sdivrem(A, B).quot;
        --sp;
        ++Pc;
        DISPATCH_NEXT;
      }
      TARGET_MOD : {
        if (INTX_UNLIKELY(sp < 2)) {
          Context.setStatus(EVMC_STACK_UNDERFLOW);
          goto cgoto_error;
        }
        auto &A = Frame->Stack[sp - 1];
        auto &B = Frame->Stack[sp - 2];
        B = (B == 0) ? intx::uint256(0) : A % B;
        --sp;
        ++Pc;
        DISPATCH_NEXT;
      }
      TARGET_SMOD : {
        if (INTX_UNLIKELY(sp < 2)) {
          Context.setStatus(EVMC_STACK_UNDERFLOW);
          goto cgoto_error;
        }
        auto &A = Frame->Stack[sp - 1];
        auto &B = Frame->Stack[sp - 2];
        B = (B == 0) ? intx::uint256(0) : intx::sdivrem(A, B).rem;
        --sp;
        ++Pc;
        DISPATCH_NEXT;
      }
      TARGET_LT : {
        if (INTX_UNLIKELY(sp < 2)) {
          Context.setStatus(EVMC_STACK_UNDERFLOW);
          goto cgoto_error;
        }
        auto &A = Frame->Stack[sp - 1];
        auto &B = Frame->Stack[sp - 2];
        B = intx::uint256(A < B);
        --sp;
        ++Pc;
        DISPATCH_NEXT;
      }
      TARGET_GT : {
        if (INTX_UNLIKELY(sp < 2)) {
          Context.setStatus(EVMC_STACK_UNDERFLOW);
          goto cgoto_error;
        }
        auto &A = Frame->Stack[sp - 1];
        auto &B = Frame->Stack[sp - 2];
        B = intx::uint256(A > B);
        --sp;
        ++Pc;
        DISPATCH_NEXT;
      }
      TARGET_SLT : {
        if (INTX_UNLIKELY(sp < 2)) {
          Context.setStatus(EVMC_STACK_UNDERFLOW);
          goto cgoto_error;
        }
        auto &A = Frame->Stack[sp - 1];
        auto &B = Frame->Stack[sp - 2];
        B = intx::uint256(intx::slt(A, B));
        --sp;
        ++Pc;
        DISPATCH_NEXT;
      }
      TARGET_SGT : {
        if (INTX_UNLIKELY(sp < 2)) {
          Context.setStatus(EVMC_STACK_UNDERFLOW);
          goto cgoto_error;
        }
        auto &A = Frame->Stack[sp - 1];
        auto &B = Frame->Stack[sp - 2];
        B = intx::uint256(intx::slt(B, A));
        --sp;
        ++Pc;
        DISPATCH_NEXT;
      }
      TARGET_EQ : {
        if (INTX_UNLIKELY(sp < 2)) {
          Context.setStatus(EVMC_STACK_UNDERFLOW);
          goto cgoto_error;
        }
        auto &A = Frame->Stack[sp - 1];
        auto &B = Frame->Stack[sp - 2];
        B = intx::uint256(A == B);
        --sp;
        ++Pc;
        DISPATCH_NEXT;
      }
      TARGET_AND : {
        if (INTX_UNLIKELY(sp < 2)) {
          Context.setStatus(EVMC_STACK_UNDERFLOW);
          goto cgoto_error;
        }
        auto &A = Frame->Stack[sp - 1];
        auto &B = Frame->Stack[sp - 2];
        B = A & B;
        --sp;
        ++Pc;
        DISPATCH_NEXT;
      }
      TARGET_OR : {
        if (INTX_UNLIKELY(sp < 2)) {
          Context.setStatus(EVMC_STACK_UNDERFLOW);
          goto cgoto_error;
        }
        auto &A = Frame->Stack[sp - 1];
        auto &B = Frame->Stack[sp - 2];
        B = A | B;
        --sp;
        ++Pc;
        DISPATCH_NEXT;
      }
      TARGET_XOR : {
        if (INTX_UNLIKELY(sp < 2)) {
          Context.setStatus(EVMC_STACK_UNDERFLOW);
          goto cgoto_error;
        }
        auto &A = Frame->Stack[sp - 1];
        auto &B = Frame->Stack[sp - 2];
        B = A ^ B;
        --sp;
        ++Pc;
        DISPATCH_NEXT;
      }
      TARGET_SHL : {
        if (INTX_UNLIKELY(sp < 2)) {
          Context.setStatus(EVMC_STACK_UNDERFLOW);
          goto cgoto_error;
        }
        auto &A = Frame->Stack[sp - 1];
        auto &B = Frame->Stack[sp - 2];
        B = (A < 256) ? (B << A) : intx::uint256(0);
        --sp;
        ++Pc;
        DISPATCH_NEXT;
      }
      TARGET_SHR : {
        if (INTX_UNLIKELY(sp < 2)) {
          Context.setStatus(EVMC_STACK_UNDERFLOW);
          goto cgoto_error;
        }
        auto &A = Frame->Stack[sp - 1];
        auto &B = Frame->Stack[sp - 2];
        B = (A < 256) ? (B >> A) : intx::uint256(0);
        --sp;
        ++Pc;
        DISPATCH_NEXT;
      }

      // ---- Inline ternary ops ----
      TARGET_ADDMOD : {
        if (INTX_UNLIKELY(sp < 3)) {
          Context.setStatus(EVMC_STACK_UNDERFLOW);
          goto cgoto_error;
        }
        auto &A = Frame->Stack[sp - 1];
        auto &B = Frame->Stack[sp - 2];
        auto &C = Frame->Stack[sp - 3];
        C = (C == 0) ? intx::uint256(0) : intx::addmod(A, B, C);
        sp -= 2;
        ++Pc;
        DISPATCH_NEXT;
      }
      TARGET_MULMOD : {
        if (INTX_UNLIKELY(sp < 3)) {
          Context.setStatus(EVMC_STACK_UNDERFLOW);
          goto cgoto_error;
        }
        auto &A = Frame->Stack[sp - 1];
        auto &B = Frame->Stack[sp - 2];
        auto &C = Frame->Stack[sp - 3];
        C = (C == 0) ? intx::uint256(0) : intx::mulmod(A, B, C);
        sp -= 2;
        ++Pc;
        DISPATCH_NEXT;
      }

      // ---- Inline unary ops ----
      TARGET_ISZERO : {
        if (INTX_UNLIKELY(sp < 1)) {
          Context.setStatus(EVMC_STACK_UNDERFLOW);
          goto cgoto_error;
        }
        auto &A = Frame->Stack[sp - 1];
        A = intx::uint256(A == 0);
        ++Pc;
        DISPATCH_NEXT;
      }
      TARGET_NOT : {
        if (INTX_UNLIKELY(sp < 1)) {
          Context.setStatus(EVMC_STACK_UNDERFLOW);
          goto cgoto_error;
        }
        auto &A = Frame->Stack[sp - 1];
        A = ~A;
        ++Pc;
        DISPATCH_NEXT;
      }
      TARGET_CLZ : {
        if (INTX_UNLIKELY(sp < 1)) {
          Context.setStatus(EVMC_STACK_UNDERFLOW);
          goto cgoto_error;
        }
        auto &A = Frame->Stack[sp - 1];
        A = intx::clz(A);
        ++Pc;
        DISPATCH_NEXT;
      }

      // ---- Inline stack ops ----
      TARGET_POP : {
        if (INTX_UNLIKELY(sp < 1)) {
          Context.setStatus(EVMC_STACK_UNDERFLOW);
          goto cgoto_error;
        }
        --sp;
        ++Pc;
        DISPATCH_NEXT;
      }
      TARGET_PUSH0 : {
        if (INTX_UNLIKELY(Revision < EVMC_SHANGHAI)) {
          Context.setStatus(EVMC_UNDEFINED_INSTRUCTION);
          goto cgoto_error;
        }
        if (INTX_UNLIKELY(sp >= MAXSTACK)) {
          Context.setStatus(EVMC_STACK_OVERFLOW);
          goto cgoto_error;
        }
        Frame->Stack[sp++] = 0;
        ++Pc;
        DISPATCH_NEXT;
      }
      TARGET_PUSHX : {
        if (INTX_UNLIKELY(sp >= MAXSTACK)) {
          Context.setStatus(EVMC_STACK_OVERFLOW);
          goto cgoto_error;
        }
        Frame->Stack[sp++] = PushValueMap[Pc];
        const uint8_t NumBytes = static_cast<uint8_t>(Code[Pc]) -
                                 static_cast<uint8_t>(evmc_opcode::OP_PUSH1) +
                                 1;
        Pc += 1 + NumBytes;
        DISPATCH_NEXT;
      }
      TARGET_DUPX : {
        const uint32_t N = static_cast<uint8_t>(Code[Pc]) -
                           static_cast<uint8_t>(evmc_opcode::OP_DUP1) + 1;
        if (INTX_UNLIKELY(sp < N)) {
          Context.setStatus(EVMC_STACK_UNDERFLOW);
          goto cgoto_error;
        }
        if (INTX_UNLIKELY(sp >= MAXSTACK)) {
          Context.setStatus(EVMC_STACK_OVERFLOW);
          goto cgoto_error;
        }
        Frame->Stack[sp] = Frame->Stack[sp - N];
        ++sp;
        ++Pc;
        DISPATCH_NEXT;
      }
      TARGET_SWAPX : {
        const uint32_t N = static_cast<uint8_t>(Code[Pc]) -
                           static_cast<uint8_t>(evmc_opcode::OP_SWAP1) + 1;
        if (INTX_UNLIKELY(sp < N + 1)) {
          Context.setStatus(EVMC_STACK_UNDERFLOW);
          goto cgoto_error;
        }
        const size_t TopIdx = sp - 1;
        const size_t NthIdx = sp - 1 - N;
        const intx::uint256 Tmp = Frame->Stack[TopIdx];
        Frame->Stack[TopIdx] = Frame->Stack[NthIdx];
        Frame->Stack[NthIdx] = Tmp;
        ++Pc;
        DISPATCH_NEXT;
      }

      // ---- Inline control flow ops ----
      TARGET_JUMP : {
        if (INTX_UNLIKELY(sp < 1)) {
          Context.setStatus(EVMC_STACK_UNDERFLOW);
          goto cgoto_error;
        }
        --sp;
        const uint64_t Dest = Uint256ToUint64(Frame->Stack[sp]);
        if (INTX_UNLIKELY(Dest >= CodeSize)) {
          Context.setStatus(EVMC_BAD_JUMP_DESTINATION);
          goto cgoto_error;
        }
        if (INTX_UNLIKELY(JumpDestMap[Dest] == 0)) {
          Context.setStatus(EVMC_BAD_JUMP_DESTINATION);
          goto cgoto_error;
        }
        Pc = Dest;
        Frame->Sp = sp;
        Frame->Pc = Pc;
        goto cgoto_restart;
      }
      TARGET_JUMPI : {
        if (INTX_UNLIKELY(sp < 2)) {
          Context.setStatus(EVMC_STACK_UNDERFLOW);
          goto cgoto_error;
        }
        --sp;
        const uint64_t Dest = Uint256ToUint64(Frame->Stack[sp]);
        --sp;
        const intx::uint256 &Cond = Frame->Stack[sp];
        if (!Cond) {
          ++Pc;
          DISPATCH_NEXT;
        }
        if (INTX_UNLIKELY(Dest >= CodeSize)) {
          Context.setStatus(EVMC_BAD_JUMP_DESTINATION);
          goto cgoto_error;
        }
        if (INTX_UNLIKELY(JumpDestMap[Dest] == 0)) {
          Context.setStatus(EVMC_BAD_JUMP_DESTINATION);
          goto cgoto_error;
        }
        Pc = Dest;
        Frame->Sp = sp;
        Frame->Pc = Pc;
        goto cgoto_restart;
      }
      TARGET_JUMPDEST : {
        ++Pc;
        DISPATCH_NEXT;
      }
      TARGET_STOP : {
        Frame->Sp = sp;
        Frame->Pc = Pc;
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
        goto cgoto_restart;
      }
      TARGET_INVALID : {
        Context.setStatus(EVMC_INVALID_INSTRUCTION);
        goto cgoto_error;
      }
      TARGET_UNDEFINED : {
        Context.setStatus(EVMC_UNDEFINED_INSTRUCTION);
        goto cgoto_error;
      }

      // ---- Complex handler ops (delegate to doExecute) ----
      TARGET_EXP:
        HANDLER_CALL(ExpHandler::doExecute());
      TARGET_SIGNEXTEND:
        HANDLER_CALL(SignExtendHandler::doExecute());
      TARGET_BYTE:
        HANDLER_CALL(ByteHandler::doExecute());
      TARGET_SAR:
        HANDLER_CALL(SarHandler::doExecute());
      TARGET_KECCAK256:
        HANDLER_CALL(Keccak256Handler::doExecute());

      // Environment information
      TARGET_ADDRESS:
        HANDLER_CALL(AddressHandler::doExecute());
      TARGET_BALANCE:
        HANDLER_CALL(BalanceHandler::doExecute());
      TARGET_ORIGIN:
        HANDLER_CALL(OriginHandler::doExecute());
      TARGET_CALLER:
        HANDLER_CALL(CallerHandler::doExecute());
      TARGET_CALLVALUE:
        HANDLER_CALL(CallValueHandler::doExecute());
      TARGET_CALLDATALOAD:
        HANDLER_CALL(CallDataLoadHandler::doExecute());
      TARGET_CALLDATASIZE:
        HANDLER_CALL(CallDataSizeHandler::doExecute());
      TARGET_CALLDATACOPY:
        HANDLER_CALL(CallDataCopyHandler::doExecute());
      TARGET_CODESIZE:
        HANDLER_CALL(CodeSizeHandler::doExecute());
      TARGET_CODECOPY:
        HANDLER_CALL(CodeCopyHandler::doExecute());
      TARGET_GASPRICE:
        HANDLER_CALL(GasPriceHandler::doExecute());
      TARGET_EXTCODESIZE:
        HANDLER_CALL(ExtCodeSizeHandler::doExecute());
      TARGET_EXTCODECOPY:
        HANDLER_CALL(ExtCodeCopyHandler::doExecute());
      TARGET_RETURNDATASIZE:
        HANDLER_CALL(ReturnDataSizeHandler::doExecute());
      TARGET_RETURNDATACOPY:
        HANDLER_CALL(ReturnDataCopyHandler::doExecute());
      TARGET_EXTCODEHASH:
        HANDLER_CALL(ExtCodeHashHandler::doExecute());

      // Block information
      TARGET_BLOCKHASH:
        HANDLER_CALL(BlockHashHandler::doExecute());
      TARGET_COINBASE:
        HANDLER_CALL(CoinBaseHandler::doExecute());
      TARGET_TIMESTAMP:
        HANDLER_CALL(TimeStampHandler::doExecute());
      TARGET_NUMBER:
        HANDLER_CALL(NumberHandler::doExecute());
      TARGET_PREVRANDAO:
        HANDLER_CALL(PrevRanDaoHandler::doExecute());
      TARGET_GASLIMIT:
        HANDLER_CALL(GasLimitHandler::doExecute());
      TARGET_CHAINID:
        HANDLER_CALL(ChainIdHandler::doExecute());
      TARGET_SELFBALANCE:
        HANDLER_CALL(SelfBalanceHandler::doExecute());
      TARGET_BASEFEE:
        HANDLER_CALL(BaseFeeHandler::doExecute());
      TARGET_BLOBHASH:
        HANDLER_CALL(BlobHashHandler::doExecute());
      TARGET_BLOBBASEFEE:
        HANDLER_CALL(BlobBaseFeeHandler::doExecute());

      // Memory & storage
      TARGET_MLOAD:
        HANDLER_CALL(MLoadHandler::doExecute());
      TARGET_MSTORE:
        HANDLER_CALL(MStoreHandler::doExecute());
      TARGET_MSTORE8:
        HANDLER_CALL(MStore8Handler::doExecute());
      TARGET_SLOAD:
        HANDLER_CALL(SLoadHandler::doExecute());
      TARGET_SSTORE:
        HANDLER_CALL(SStoreHandler::doExecute());

      // Misc
      TARGET_PC:
        HANDLER_CALL(PCHandler::doExecute());
      TARGET_MSIZE:
        HANDLER_CALL(MSizeHandler::doExecute());
      TARGET_GAS:
        HANDLER_CALL(GasHandler::doExecute());
      TARGET_TLOAD:
        HANDLER_CALL(TLoadHandler::doExecute());
      TARGET_TSTORE:
        HANDLER_CALL(TStoreHandler::doExecute());
      TARGET_MCOPY:
        HANDLER_CALL(MCopyHandler::doExecute());

      // Multi-opcode handlers: LOG, CALL, CREATE
      TARGET_LOGX : {
        Frame->Sp = sp;
        Frame->Pc = Pc;
        EVMResource::setExecutionContext(Frame, &Context);
        LogHandler::OpCode =
            static_cast<evmc_opcode>(static_cast<uint8_t>(Code[Pc]));
        LogHandler::doExecute();
        sp = Frame->Sp;
        ++Pc;
        if (INTX_UNLIKELY(Context.getStatus() != EVMC_SUCCESS))
          goto cgoto_error;
        DISPATCH_NEXT;
      }
      TARGET_CALLX : {
        Frame->Sp = sp;
        Frame->Pc = Pc;
        EVMResource::setExecutionContext(Frame, &Context);
        CallHandler::OpCode =
            static_cast<evmc_opcode>(static_cast<uint8_t>(Code[Pc]));
        CallHandler::doExecute();
        sp = Frame->Sp;
        ++Pc;
        if (INTX_UNLIKELY(Context.getStatus() != EVMC_SUCCESS))
          goto cgoto_error;
        DISPATCH_NEXT;
      }
      TARGET_CREATEX : {
        Frame->Sp = sp;
        Frame->Pc = Pc;
        EVMResource::setExecutionContext(Frame, &Context);
        CreateHandler::OpCode =
            static_cast<evmc_opcode>(static_cast<uint8_t>(Code[Pc]));
        CreateHandler::doExecute();
        sp = Frame->Sp;
        ++Pc;
        if (INTX_UNLIKELY(Context.getStatus() != EVMC_SUCCESS))
          goto cgoto_error;
        DISPATCH_NEXT;
      }

      // ---- Special termination handlers (may change Frame) ----
      TARGET_RETURN : {
        Frame->Sp = sp;
        Frame->Pc = Pc;
        EVMResource::setExecutionContext(Frame, &Context);
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
        if (INTX_UNLIKELY(Context.getStatus() != EVMC_SUCCESS)) {
          if (handleExecutionStatus(Frame, Context)) {
            return;
          }
          goto cgoto_break_outer;
        }
        goto cgoto_restart;
      }
      TARGET_REVERT : {
        Frame->Sp = sp;
        Frame->Pc = Pc;
        EVMResource::setExecutionContext(Frame, &Context);
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
        if (INTX_UNLIKELY(Context.getStatus() != EVMC_SUCCESS)) {
          if (handleExecutionStatus(Frame, Context)) {
            return;
          }
          goto cgoto_break_outer;
        }
        goto cgoto_restart;
      }
      TARGET_SELFDESTRUCT : {
        Frame->Sp = sp;
        Frame->Pc = Pc;
        EVMResource::setExecutionContext(Frame, &Context);
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
        if (INTX_UNLIKELY(Context.getStatus() != EVMC_SUCCESS)) {
          if (handleExecutionStatus(Frame, Context)) {
            return;
          }
          goto cgoto_break_outer;
        }
        goto cgoto_restart;
      }

      // ---- Exit labels ----
      cgoto_chunk_done:
        Frame->Sp = sp;
        Frame->Pc = Pc;
        goto cgoto_continue_outer;

      cgoto_restart:
        goto cgoto_continue_outer;

      cgoto_error:
        Frame->Sp = sp;
        Frame->Pc = Pc;
        if (handleExecutionStatus(Frame, Context)) {
          return;
        }
        goto cgoto_break_outer;

#undef DISPATCH_NEXT
#undef HANDLER_CALL
      }
    cgoto_continue_outer:
      continue;
    cgoto_break_outer:
      break;
#else
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
          Context.clearReturnData();
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
#endif
    }

    Byte OpcodeByte = Code[Frame->Pc];
    evmc_opcode Op = static_cast<evmc_opcode>(OpcodeByte);
    const uint8_t OpcodeU8 = static_cast<uint8_t>(OpcodeByte);

    if (NamesTable[OpcodeU8] == NULL) {
      Context.setStatus(EVMC_UNDEFINED_INSTRUCTION);
      if (handleExecutionStatus(Frame, Context)) {
        return;
      }
      break;
    }

    switch (Op) {
    case evmc_opcode::OP_STOP:
      Context.clearReturnData();
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
  // When execution falls through (PC >= CodeSize), it's an implicit STOP.
  // Per EVM semantics, return data should be cleared for implicit STOP,
  // as only RETURN/REVERT preserve return data.
  Context.clearReturnData();
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

void InterpreterExecContext::restoreStateFromInstance(uint64_t StartPC) {
  // Restore execution state from EVMInstance for fallback support
  runtime::EVMInstance *Instance = getInstance();

  // Validate PC bounds
  const EVMModule *Mod = Instance->getModule();
  if (StartPC >= Mod->CodeSize) {
    setStatus(EVMC_BAD_JUMP_DESTINATION);
    return;
  }

  // Get current frame (should already be allocated)
  EVMFrame *Frame = getCurFrame();
  if (!Frame) {
    setStatus(EVMC_INVALID_INSTRUCTION);
    return;
  }

  // Restore PC
  Frame->Pc = StartPC;

  // Restore stack state from EVMInstance
  // The EVMInstance maintains the stack state that was synchronized from JIT
  // Copy stack data from EVMInstance to EVMFrame

  const uint8_t *EvmStackData = Instance->getEVMStack();
  uint64_t EvmStackSize = Instance->getEVMStackSize();

  // Calculate number of stack elements (each element is 32 bytes)
  constexpr size_t ELEMENT_SIZE = 32; // 256 bits = 32 bytes
  size_t NumElements = EvmStackSize / ELEMENT_SIZE;

  // Validate stack size
  if (NumElements > MAXSTACK) {
    setStatus(EVMC_STACK_OVERFLOW);
    return;
  }

  // Copy stack elements from EVMInstance to EVMFrame
  Frame->Sp = NumElements;
  for (size_t I = 0; I < NumElements; ++I) {
    // Each stack element is 32 bytes, copy as intx::uint256
    const uint8_t *ElementData = EvmStackData + (I * ELEMENT_SIZE);

    // Convert from bytes to intx::uint256 using proper byte order
    intx::uint256 Value;
    for (size_t J = 0; J < ELEMENT_SIZE / 8; J++) {
      Value[J] = static_cast<uint64_t>(*ElementData);
      ElementData += 8;
    }
    Frame->Stack[I] = Value;
  }

  // Ensure memory state consistency between JIT and interpreter
  // The EVMInstance maintains the authoritative memory state
  // Synchronize EVMFrame memory with EVMInstance memory
  uint8_t *InstanceMemory = Instance->getMemoryBase();
  uint64_t InstanceMemorySize = Instance->getMemorySize();

  if (InstanceMemory && InstanceMemorySize > 0) {
    // Resize frame memory to match instance memory size
    Frame->Memory.resize(InstanceMemorySize);

    // Copy memory contents from EVMInstance to EVMFrame
    std::memcpy(Frame->Memory.data(), InstanceMemory, InstanceMemorySize);
  } else {
    // Initialize with empty memory if instance has no memory allocated
    Frame->Memory.clear();
  }

  // Reset execution status
  setStatus(EVMC_SUCCESS);
}
