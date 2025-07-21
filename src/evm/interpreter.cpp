// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "evm/interpreter.h"
#include "evmc/instructions.h"
#include "runtime/evm_instance.h"

#define EVM_STACK_CHECK(FramePtr, N)                                           \
  if ((FramePtr)->stackHeight() < (N)) {                                       \
    throw common::getError(common::ErrorCode::UnexpectedNumArgs);              \
  }

namespace {
static uint64_t uint256ToUint64(const intx::uint256 &Value) {
  return static_cast<uint64_t>(Value & 0xFFFFFFFFFFFFFFFFULL);
}

} // namespace

using namespace zen;
using namespace zen::evm;
using namespace zen::runtime;

EVMFrame *InterpreterExecContext::allocFrame() {
  FrameStack.emplace_back();

  EVMFrame &Frame = FrameStack.back();
  Frame.GasLeft = 0;

  return &Frame;
}

// We only need to free the last frame (top of the stack),
// since EVM's control flow is purely stack-based.
void InterpreterExecContext::freeBackFrame() {
  if (FrameStack.empty())
    return;

  FrameStack.pop_back();
}

namespace {
// Opcode processing function
void handleOpADD(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 C = A + B;
  Frame->push(C);
}
void handleOpSUB(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 Res = A - B;
  Frame->push(Res);
}
void handleOpMUL(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 Res = A * B;
  Frame->push(Res);
}

void handleOpDIV(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 Q = (B == 0) ? intx::uint256(0) : A / B;
  Frame->push(Q);
}
void handleOpMOD(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 R = (B == 0) ? intx::uint256(0) : A % B;
  Frame->push(R);
}
void handleOpAND(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 Res = A & B;
  Frame->push(Res);
}
void handleOpEQ(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 Res = (A == B) ? intx::uint256(1) : intx::uint256(0);
  Frame->push(Res);
}
void handleOpISZERO(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 1);
  intx::uint256 V = Frame->pop();
  intx::uint256 Res = (V == 0) ? intx::uint256(1) : intx::uint256(0);
  Frame->push(Res);
}
void handleOpLT(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 Res = (A < B) ? intx::uint256(1) : intx::uint256(0);
  Frame->push(Res);
}
void handleOpGT(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 Res = (A > B) ? intx::uint256(1) : intx::uint256(0);
  Frame->push(Res);
}
void handleOpSLT(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 Res = intx::slt(A, B);
  Frame->push(Res);
}
void handleOpSGT(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 Res = intx::slt(B, A);
  Frame->push(Res);
}
void handleOpADDMOD(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 3);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 C = Frame->pop();
  intx::uint256 Res = (C == 0) ? intx::uint256(0) : intx::addmod(A, B, C);
  Frame->push(Res);
}
void handleOpMULMOD(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 3);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 C = Frame->pop();
  intx::uint256 Res = (C == 0) ? intx::uint256(0) : intx::mulmod(A, B, C);
  Frame->push(Res);
}
void handleOpEXP(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 Base = Frame->pop();
  intx::uint256 Exp = Frame->pop();
  intx::uint256 Res = intx::exp(Base, Exp);
  Frame->push(Res);
}
void handleOpSDIV(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 Res = (B == 0) ? intx::uint256(0) : intx::sdivrem(A, B).quot;
  Frame->push(Res);
}
void handleOpSMOD(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 Res = (B == 0) ? intx::uint256(0) : intx::sdivrem(A, B).rem;
  Frame->push(Res);
}
void handleOpSIGNEXTEND(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 I = Frame->pop();
  intx::uint256 V = Frame->pop();

  intx::uint256 Res = V;
  if (I < 31) {
    // Calculate the sign bit position (the highest bit of the Ith byte,
    // i.e., bit 8*I+7)
    intx::uint256 SignBitPosition = 8 * I + 7;

    // Extract the sign bit
    bool SignBit = (V & (intx::uint256(1) << SignBitPosition)) != 0;

    if (SignBit) {
      // Generate mask: lower I*8 bits are 0, the rest are 1
      intx::uint256 Mask = (intx::uint256(1) << SignBitPosition) - 1;
      // Apply mask: extend the sign bit to higher bits
      Res |= ~Mask;
    }
    // If the sign bit is 0, no processing is needed, keep the original
    // value unchanged
  }
  Frame->push(Res);
}
void handleOpOR(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 Res = A | B;
  Frame->push(Res);
}
void handleOpXOR(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 Res = A ^ B;
  Frame->push(Res);
}
void handleOpNOT(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 1);
  intx::uint256 V = Frame->pop();
  intx::uint256 Res = ~V;
  Frame->push(Res);
}
void handleOpBYTE(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 I = Frame->pop();
  intx::uint256 Val = Frame->pop();

  intx::uint256 Res = 0;
  if (I < 32) {
    uint8_t ByteVal = static_cast<uint8_t>((Val >> (8 * (31 - I))) & 0xFF);
    Res = intx::uint256(ByteVal);
  }
  Frame->push(Res);
}
void handleOpSHL(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 Shift = Frame->pop();
  intx::uint256 Value = Frame->pop();

  intx::uint256 Res = 0;
  if (Shift < 256) {
    Res = Value << Shift;
  }
  Frame->push(Res);
}
void handleOpSHR(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 Shift = Frame->pop();
  intx::uint256 Value = Frame->pop();

  intx::uint256 Res = 0;
  if (Shift < 256) {
    Res = Value >> Shift;
  }
  Frame->push(Res);
}
void handleOpSAR(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 Shift = Frame->pop();
  intx::uint256 Value = Frame->pop();

  intx::uint256 Res = 0;
  if (Shift < 256) {
    intx::uint256 IsNegative = (Value >> 255) & 1;
    Res = Value >> Shift;

    if (IsNegative && Shift > 0) {
      intx::uint256 Mask = (intx::uint256(1) << (256 - Shift)) - 1;
      Mask = ~Mask;
      Res |= Mask;
    }
  } else {
    intx::uint256 IsNegative = (Value >> 255) & 1;
    Res = IsNegative ? intx::uint256(-1) : intx::uint256(0);
  }
  Frame->push(Res);
}
void handleOpMSTORE(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 OffsetVal = Frame->pop();
  intx::uint256 Value = Frame->pop();

  uint64_t Offset = uint256ToUint64(OffsetVal);
  if (Offset > UINT32_MAX) {
    throw common::getError(common::ErrorCode::IntegerOverflow);
  }

  uint64_t ReqSize = Offset + 32;
  // TODO: use EVMMemory class in the future
  if (ReqSize > Frame->Memory.size()) {
    Frame->Memory.resize(ReqSize, 0);
  }

  uint8_t ValueBytes[32];
  intx::be::store(ValueBytes, Value);
  // TODO: use EVMMemory class in the future
  std::memcpy(Frame->Memory.data() + Offset, ValueBytes, 32);
}
void handleOpMLOAD(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 1);
  intx::uint256 OffsetVal = Frame->pop();
  uint64_t Offset = uint256ToUint64(OffsetVal);

  if (Offset > UINT32_MAX) {
    throw common::getError(common::ErrorCode::IntegerOverflow);
  }

  uint64_t ReqSize = Offset + 32;
  // TODO: use EVMMemory class in the future
  if (ReqSize > Frame->Memory.size()) {
    Frame->Memory.resize(ReqSize, 0);
  }

  uint8_t ValueBytes[32];
  // TODO: use EVMMemory class in the future
  std::memcpy(ValueBytes, Frame->Memory.data() + Offset, 32);

  intx::uint256 Value = intx::be::load<intx::uint256>(ValueBytes);
  Frame->push(Value);
}
void handleOpRETURN(InterpreterExecContext &Context, EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 OffsetVal = Frame->pop();
  intx::uint256 SizeVal = Frame->pop();
  uint64_t Offset = uint256ToUint64(OffsetVal);
  uint64_t Size = uint256ToUint64(SizeVal);

  if (Offset > UINT32_MAX || Size > UINT32_MAX) {
    throw common::getError(common::ErrorCode::IntegerOverflow);
  }

  uint64_t ReqSize = Offset + Size;
  // TODO: use EVMMemory class in the future
  if (ReqSize > Frame->Memory.size()) {
    Frame->Memory.resize(ReqSize, 0);
  }
  // TODO: use EVMMemory class in the future
  std::vector<uint8_t> ReturnData(Frame->Memory.begin() + Offset,
                                  Frame->Memory.begin() + Offset + Size);
  Context.setReturnData(std::move(ReturnData));

  Context.freeBackFrame();
}
void handleOpPUSH(EVMFrame *Frame, uint8_t OpcodeByte, const uint8_t *Code,
                  size_t CodeSize) {
  // PUSH1 ~ PUSH32
  uint32_t NumBytes =
      OpcodeByte - static_cast<uint8_t>(evmc_opcode::OP_PUSH1) + 1;
  if (Frame->Pc + NumBytes >= CodeSize) {
    throw common::getError(common::ErrorCode::UnexpectedEnd);
  }
  uint8_t ValueBytes[32];
  memset(ValueBytes, 0, sizeof(ValueBytes));
  std::memcpy(ValueBytes + (32 - NumBytes), Code + Frame->Pc + 1, NumBytes);
  intx::uint256 Val = intx::be::load<intx::uint256>(ValueBytes);
  Frame->push(Val);
  Frame->Pc += NumBytes;
}
void handleOpDUP(uint8_t OpcodeByte, EVMFrame *Frame) {
  // DUP1 ~ DUP16
  uint32_t N = OpcodeByte - static_cast<uint8_t>(evmc_opcode::OP_DUP1) + 1;
  if (Frame->stackHeight() < N) {
    throw common::getError(common::ErrorCode::UnexpectedNumArgs);
  }
  intx::uint256 V = Frame->peek(N - 1);
  Frame->push(V);
}
void handleOpSWAP(uint8_t OpcodeByte, EVMFrame *Frame) {
  // SWAP1 ~ SWAP16
  uint32_t N = OpcodeByte - static_cast<uint8_t>(evmc_opcode::OP_SWAP1) + 1;
  if (Frame->stackHeight() < N + 1) {
    throw common::getError(common::ErrorCode::UnexpectedNumArgs);
  }
  intx::uint256 &Top = Frame->peek(0);
  intx::uint256 &Nth = Frame->peek(N);
  std::swap(Top, Nth);
}
} // namespace

void BaseInterpreter::interpret() {
  Context.allocFrame();
  EVMFrame *Frame = Context.getCurFrame();

  const EVMModule *Mod = Context.getInstance()->getModule();

  size_t CodeSize = Mod->CodeSize;
  uint8_t *Code = Mod->Code;

  while (Frame->Pc < CodeSize) {
    uint8_t OpcodeByte = Code[Frame->Pc];
    evmc_opcode Op = static_cast<evmc_opcode>(OpcodeByte);

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

    case evmc_opcode::OP_MLOAD: {
      handleOpMLOAD(Frame);
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

    case evmc_opcode::OP_POP: {
      EVM_STACK_CHECK(Frame, 1);
      Frame->pop();
      break;
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
        throw common::getError(common::ErrorCode::UnsupportedOpcode);
      }
    }

    Frame->Pc++;
  }
}
