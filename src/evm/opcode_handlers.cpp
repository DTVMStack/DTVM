// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "evm/opcode_handlers.h"
#include "common/errors.h"
#include "evm/interpreter.h"
#include "evmc/instructions.h"


namespace {
uint64_t uint256ToUint64(const intx::uint256 &Value) {
  return static_cast<uint64_t>(Value & 0xFFFFFFFFFFFFFFFFULL);
}

int64_t getGasCost(enum evmc_opcode Code,
                   enum evmc_revision Revision = EVMC_CANCUN) { // EVMC_CANCUN = 12
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

// Calculate memory expansion gas cost
uint64_t zen::evm::calculateMemoryExpansionCost(uint64_t CurrentSize, uint64_t NewSize) {
  if (NewSize <= CurrentSize) {
    return 0; // No expansion needed
  }

  // EVM memory expansion cost formula:
  // cost = (new_words^2 / 512) + (3 * new_words) - (current_words^2 / 512) - (3
  // * current_words) where words = (size + 31) / 32 (round up to nearest word)

  uint64_t CurrentWords = (CurrentSize + 31) / 32;
  uint64_t NewWords = (NewSize + 31) / 32;

  auto MemoryCost = [](uint64_t Words) -> uint64_t {
    __int128 W = Words;
    return static_cast<uint64_t>(W * W / 512 + 3 * W);
  };

  uint64_t CurrentCost = MemoryCost(CurrentWords);
  uint64_t NewCost = MemoryCost(NewWords);

  return NewCost - CurrentCost;
}

// Arithmetic operations
void zen::evm::handleOpADD(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 C = A + B;
  Frame->push(C);
}

void zen::evm::handleOpSUB(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 Res = A - B;
  Frame->push(Res);
}

void zen::evm::handleOpMUL(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 Res = A * B;
  Frame->push(Res);
}

void zen::evm::handleOpDIV(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 Q = (B == 0) ? intx::uint256(0) : A / B;
  Frame->push(Q);
}

void zen::evm::handleOpMOD(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 R = (B == 0) ? intx::uint256(0) : A % B;
  Frame->push(R);
}

void zen::evm::handleOpADDMOD(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 3);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 C = Frame->pop();
  intx::uint256 Res = (C == 0) ? intx::uint256(0) : intx::addmod(A, B, C);
  Frame->push(Res);
}

void zen::evm::handleOpMULMOD(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 3);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 C = Frame->pop();
  intx::uint256 Res = (C == 0) ? intx::uint256(0) : intx::mulmod(A, B, C);
  Frame->push(Res);
}

void zen::evm::handleOpEXP(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 Base = Frame->pop();
  intx::uint256 Exp = Frame->pop();
  intx::uint256 Res = intx::exp(Base, Exp);
  Frame->push(Res);
}

void zen::evm::handleOpSDIV(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 Res = (B == 0) ? intx::uint256(0) : intx::sdivrem(A, B).quot;
  Frame->push(Res);
}

void zen::evm::handleOpSMOD(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 Res = (B == 0) ? intx::uint256(0) : intx::sdivrem(A, B).rem;
  Frame->push(Res);
}

void zen::evm::handleOpSIGNEXTEND(EVMFrame *Frame) {
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

// Bitwise operations
void zen::evm::handleOpAND(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 Res = A & B;
  Frame->push(Res);
}

void zen::evm::handleOpOR(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 Res = A | B;
  Frame->push(Res);
}

void zen::evm::handleOpXOR(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 Res = A ^ B;
  Frame->push(Res);
}

void zen::evm::handleOpNOT(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 1);
  intx::uint256 V = Frame->pop();
  intx::uint256 Res = ~V;
  Frame->push(Res);
}

void zen::evm::handleOpBYTE(EVMFrame *Frame) {
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

void zen::evm::handleOpSHL(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 Shift = Frame->pop();
  intx::uint256 Value = Frame->pop();

  intx::uint256 Res = 0;
  if (Shift < 256) {
    Res = Value << Shift;
  }
  Frame->push(Res);
}

void zen::evm::handleOpSHR(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 Shift = Frame->pop();
  intx::uint256 Value = Frame->pop();

  intx::uint256 Res = 0;
  if (Shift < 256) {
    Res = Value >> Shift;
  }
  Frame->push(Res);
}

void zen::evm::handleOpSAR(EVMFrame *Frame) {
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

// Comparison operations
void zen::evm::handleOpEQ(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 Res = (A == B) ? intx::uint256(1) : intx::uint256(0);
  Frame->push(Res);
}

void zen::evm::handleOpISZERO(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 1);
  intx::uint256 V = Frame->pop();
  intx::uint256 Res = (V == 0) ? intx::uint256(1) : intx::uint256(0);
  Frame->push(Res);
}

void zen::evm::handleOpLT(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 Res = (A < B) ? intx::uint256(1) : intx::uint256(0);
  Frame->push(Res);
}

void zen::evm::handleOpGT(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 Res = (A > B) ? intx::uint256(1) : intx::uint256(0);
  Frame->push(Res);
}

void zen::evm::handleOpSLT(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 Res = intx::slt(A, B);
  Frame->push(Res);
}

void zen::evm::handleOpSGT(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 A = Frame->pop();
  intx::uint256 B = Frame->pop();
  intx::uint256 Res = intx::slt(B, A);
  Frame->push(Res);
}

// Memory operations
void zen::evm::handleOpMSTORE(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 OffsetVal = Frame->pop();
  intx::uint256 Value = Frame->pop();

  uint64_t Offset = uint256ToUint64(OffsetVal);
  EVM_THROW_IF(Offset, >, UINT32_MAX, IntegerOverflow);

  uint64_t ReqSize = Offset + 32;
  uint64_t CurrentSize = Frame->Memory.size();

  // Calculate and charge memory expansion gas
  uint64_t MemoryExpansionCost =
      calculateMemoryExpansionCost(CurrentSize, ReqSize);
  EVM_THROW_IF(Frame->GasLeft, <, MemoryExpansionCost, EVMOutOfGas);
  Frame->GasLeft -= MemoryExpansionCost;

  // TODO: use EVMMemory class in the future
  if (ReqSize > CurrentSize) {
    Frame->Memory.resize(ReqSize, 0);
  }

  uint8_t ValueBytes[32];
  intx::be::store(ValueBytes, Value);
  // TODO: use EVMMemory class in the future
  std::memcpy(Frame->Memory.data() + Offset, ValueBytes, 32);
}

void zen::evm::handleOpMSTORE8(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 OffsetVal = Frame->pop();
  intx::uint256 Value = Frame->pop();

  uint64_t Offset = uint256ToUint64(OffsetVal);
  EVM_THROW_IF(Offset, >, UINT32_MAX, IntegerOverflow);

  uint64_t ReqSize = Offset + 1;
  uint64_t CurrentSize = Frame->Memory.size();

  // Calculate and charge memory expansion gas
  uint64_t MemoryExpansionCost =
      calculateMemoryExpansionCost(CurrentSize, ReqSize);
  EVM_THROW_IF(Frame->GasLeft, <, MemoryExpansionCost, EVMOutOfGas);
  Frame->GasLeft -= MemoryExpansionCost;

  // TODO: use EVMMemory class in the future
  if (ReqSize > CurrentSize) {
    Frame->Memory.resize(ReqSize, 0);
  }
  uint8_t ByteValue = static_cast<uint8_t>(Value & intx::uint256{0xFF});
  Frame->Memory[Offset] = ByteValue;
}

void zen::evm::handleOpMLOAD(EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 1);
  intx::uint256 OffsetVal = Frame->pop();
  uint64_t Offset = uint256ToUint64(OffsetVal);

  EVM_THROW_IF(Offset, >, UINT32_MAX, IntegerOverflow);

  uint64_t ReqSize = Offset + 32;
  uint64_t CurrentSize = Frame->Memory.size();

  // Calculate and charge memory expansion gas
  uint64_t MemoryExpansionCost =
      calculateMemoryExpansionCost(CurrentSize, ReqSize);
  EVM_THROW_IF(Frame->GasLeft, <, MemoryExpansionCost, EVMOutOfGas);
  Frame->GasLeft -= MemoryExpansionCost;

  // TODO: use EVMMemory class in the future
  if (ReqSize > CurrentSize) {
    Frame->Memory.resize(ReqSize, 0);
  }

  uint8_t ValueBytes[32];
  // TODO: use EVMMemory class in the future
  std::memcpy(ValueBytes, Frame->Memory.data() + Offset, 32);

  intx::uint256 Value = intx::be::load<intx::uint256>(ValueBytes);
  Frame->push(Value);
}

// Control flow operations
bool zen::evm::handleOpJUMP(EVMFrame *Frame, const uint8_t *Code, const size_t CodeSize) {
  EVM_STACK_CHECK(Frame, 1);
  // We can assume that valid destination can't greater than uint64_t
  uint64_t Dest = uint256ToUint64(Frame->pop());

  EVM_THROW_IF(Dest, >=, CodeSize, EVMBadJumpDestination);
  EVM_THROW_IF(static_cast<evmc_opcode>(Code[Dest]), !=, evmc_opcode::OP_JUMPDEST, EVMBadJumpDestination);

  Frame->Pc = Dest;
  return true;
}

bool zen::evm::handleOpJUMPI(EVMFrame *Frame, const uint8_t *Code, const size_t CodeSize) {
  EVM_STACK_CHECK(Frame, 2);
  // We can assume that valid destination can't greater than uint64_t
  uint64_t Dest = uint256ToUint64(Frame->pop());
  intx::uint256 Cond = Frame->pop();

  if (!Cond) {
    return false;
  }
  EVM_THROW_IF(Dest, >=, CodeSize, EVMBadJumpDestination);
  EVM_THROW_IF(static_cast<evmc_opcode>(Code[Dest]), !=, evmc_opcode::OP_JUMPDEST, EVMBadJumpDestination);

  Frame->Pc = Dest;
  return true;
}

// Environment operations
void zen::evm::handleOpPC(EVMFrame *Frame) { 
  Frame->push(intx::uint256(Frame->Pc)); 
}

void zen::evm::handleOpMSize(EVMFrame *Frame) {
  // Return the current memory size in bytes
  intx::uint256 MemSize = Frame->Memory.size();
  Frame->push(MemSize);
}

void zen::evm::handleOpGAS(EVMFrame *Frame) {
  Frame->push(intx::uint256(Frame->GasLeft - getGasCost(evmc_opcode::OP_GAS)));
}

void zen::evm::handleOpGASLIMIT(EVMFrame *Frame) {
  Frame->push(intx::uint256(Frame->GasLimit));
}

// Return operations
void zen::evm::handleOpRETURN(InterpreterExecContext &Context, EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 OffsetVal = Frame->pop();
  intx::uint256 SizeVal = Frame->pop();
  uint64_t Offset = uint256ToUint64(OffsetVal);
  uint64_t Size = uint256ToUint64(SizeVal);

  // Check for overflow: Offset + Size > UINT32_MAX
  EVM_THROW_IF(Offset + Size, >, UINT32_MAX, IntegerOverflow);

  uint64_t ReqSize = Offset + Size;
  // TODO: use EVMMemory class in the future
  if (ReqSize > Frame->Memory.size()) {
    Frame->Memory.resize(ReqSize, 0);
  }
  // TODO: use EVMMemory class in the future
  std::vector<uint8_t> ReturnData(Frame->Memory.begin() + Offset,
                                  Frame->Memory.begin() + Offset + Size);
  Context.setReturnData(std::move(ReturnData));

  Context.setStatus(EVMC_SUCCESS);
  // Return remaining gas to parent frame before freeing current frame
  uint64_t RemainingGas = Frame->GasLeft;
  Context.freeBackFrame();
  if (Context.getCurFrame() != nullptr) {
    Context.getCurFrame()->GasLeft += RemainingGas;
  }
}

// TODO: implement host storage revert in the future
void zen::evm::handleOpREVERT(InterpreterExecContext &Context, EVMFrame *Frame) {
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 OffsetVal = Frame->pop();
  intx::uint256 SizeVal = Frame->pop();
  uint64_t Offset = uint256ToUint64(OffsetVal);
  uint64_t Size = uint256ToUint64(SizeVal);

  // Check for overflow: Offset + Size > UINT32_MAX
  EVM_THROW_IF(Offset + Size, >, UINT32_MAX, IntegerOverflow);

  uint64_t ReqSize = Offset + Size;
  // TODO: use EVMMemory class in the future
  if (ReqSize > Frame->Memory.size()) {
    Frame->Memory.resize(ReqSize, 0);
  }
  std::vector<uint8_t> RevertData(Frame->Memory.begin() + Offset,
                                  Frame->Memory.begin() + Offset + Size);

  Context.setStatus(EVMC_REVERT);
  Context.setReturnData(std::move(RevertData));
  // Return remaining gas to parent frame before freeing current frame
  uint64_t RemainingGas = Frame->GasLeft;
  Context.freeBackFrame();
  if (Context.getCurFrame() != nullptr) {
    Context.getCurFrame()->GasLeft += RemainingGas;
  }
}

// Stack operations
void zen::evm::handleOpPUSH(EVMFrame *Frame, uint8_t OpcodeByte, const uint8_t *Code, size_t CodeSize) {
  // PUSH1 ~ PUSH32
  uint32_t NumBytes =
      OpcodeByte - static_cast<uint8_t>(evmc_opcode::OP_PUSH1) + 1;
  EVM_THROW_IF(Frame->Pc + NumBytes, >=, CodeSize, UnexpectedEnd);
  uint8_t ValueBytes[32];
  memset(ValueBytes, 0, sizeof(ValueBytes));
  std::memcpy(ValueBytes + (32 - NumBytes), Code + Frame->Pc + 1, NumBytes);
  intx::uint256 Val = intx::be::load<intx::uint256>(ValueBytes);
  Frame->push(Val);
  Frame->Pc += NumBytes;
}

void zen::evm::handleOpDUP(uint8_t OpcodeByte, EVMFrame *Frame) {
  // DUP1 ~ DUP16
  uint32_t N = OpcodeByte - static_cast<uint8_t>(evmc_opcode::OP_DUP1) + 1;
  EVM_THROW_IF(Frame->stackHeight(), <, N, UnexpectedNumArgs);
  intx::uint256 V = Frame->peek(N - 1);
  Frame->push(V);
}

void zen::evm::handleOpSWAP(uint8_t OpcodeByte, EVMFrame *Frame) {
  // SWAP1 ~ SWAP16
  uint32_t N = OpcodeByte - static_cast<uint8_t>(evmc_opcode::OP_SWAP1) + 1;
  EVM_THROW_IF(Frame->stackHeight(), <, N + 1, UnexpectedNumArgs);
  intx::uint256 &Top = Frame->peek(0);
  intx::uint256 &Nth = Frame->peek(N);
  std::swap(Top, Nth);
}
