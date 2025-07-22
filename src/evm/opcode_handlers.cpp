// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "evm/opcode_handlers.h"
#include "common/errors.h"
#include "evm/interpreter.h"
#include "evmc/instructions.h"
#include "runtime/evm_instance.h"

zen::evm::EVMFrame *zen::evm::EVMResource::CurrentFrame = nullptr;
zen::evm::InterpreterExecContext *zen::evm::EVMResource::CurrentContext =
    nullptr;

namespace {
uint64_t uint256ToUint64(const intx::uint256 &Value) {
  return static_cast<uint64_t>(Value & 0xFFFFFFFFFFFFFFFFULL);
}

int64_t
getGasCost(enum evmc_opcode Code,
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
uint64_t zen::evm::calculateMemoryExpansionCost(uint64_t CurrentSize,
                                                uint64_t NewSize) {
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

void GasHandler::execute() {
  EVMFrame *Frame = getFrame();
  uint64_t GasCost = calculateGas(evmc_opcode::OP_GAS);
  Frame->push(intx::uint256(Frame->GasLeft - GasCost));
}

void SignExtendHandler::execute() {
  using Base = EVMOpcodeHandlerBase<SignExtendHandler>;
  auto *Frame = Base::getFrame();
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

void ByteHandler::execute() {
  using Base = EVMOpcodeHandlerBase<ByteHandler>;
  auto *Frame = Base::getFrame();
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

void SarHandler::execute() {
  using Base = EVMOpcodeHandlerBase<SarHandler>;
  auto *Frame = Base::getFrame();
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

// Memory operations
void MStoreHandler::execute() {
  using Base = EVMOpcodeHandlerBase<MStoreHandler>;
  auto *Frame = Base::getFrame();
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

void MStore8Handler::execute() {
  using Base = EVMOpcodeHandlerBase<MStore8Handler>;
  auto *Frame = Base::getFrame();
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

void MLoadHandler::execute() {
  using Base = EVMOpcodeHandlerBase<MLoadHandler>;
  auto *Frame = Base::getFrame();
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
void JumpHandler::execute() {
  using Base = EVMOpcodeHandlerBase<JumpHandler>;
  auto *Frame = Base::getFrame();
  auto *Context = Base::getContext();
  auto *Inst = Context->getInstance();
  auto *Mod = Inst->getModule();
  const uint8_t *Code = Mod->Code;
  size_t CodeSize = Mod->CodeSize;
  EVM_STACK_CHECK(Frame, 1);
  // We can assume that valid destination can't greater than uint64_t
  uint64_t Dest = uint256ToUint64(Frame->pop());

  EVM_THROW_IF(Dest, >=, CodeSize, EVMBadJumpDestination);
  EVM_THROW_IF(static_cast<evmc_opcode>(Code[Dest]), !=,
               evmc_opcode::OP_JUMPDEST, EVMBadJumpDestination);

  Frame->Pc = Dest;
  Context->IsJump = true;
}

void JumpIHandler::execute() {
  using Base = EVMOpcodeHandlerBase<JumpIHandler>;
  auto *Frame = Base::getFrame();
  auto *Context = Base::getContext();
  auto *Inst = Context->getInstance();
  auto *Mod = Inst->getModule();
  const uint8_t *Code = Mod->Code;
  size_t CodeSize = Mod->CodeSize;
  EVM_STACK_CHECK(Frame, 2);
  // We can assume that valid destination can't greater than uint64_t
  uint64_t Dest = uint256ToUint64(Frame->pop());
  intx::uint256 Cond = Frame->pop();

  if (!Cond) {
    return;
  }
  EVM_THROW_IF(Dest, >=, CodeSize, EVMBadJumpDestination);
  EVM_THROW_IF(static_cast<evmc_opcode>(Code[Dest]), !=,
               evmc_opcode::OP_JUMPDEST, EVMBadJumpDestination);

  Frame->Pc = Dest;
  Context->IsJump = true;
}

// Environment operations
void PCHandler::execute() {
  using Base = EVMOpcodeHandlerBase<PCHandler>;
  auto *Frame = Base::getFrame();
  Frame->push(intx::uint256(Frame->Pc));
}

void MSizeHandler::execute() {
  using Base = EVMOpcodeHandlerBase<MSizeHandler>;
  auto *Frame = Base::getFrame();
  // Return the current memory size in bytes
  intx::uint256 MemSize = Frame->Memory.size();
  Frame->push(MemSize);
}

void GasLimitHandler::execute() {
  using Base = EVMOpcodeHandlerBase<GasLimitHandler>;
  auto *Frame = Base::getFrame();
  Frame->push(intx::uint256(Frame->GasLimit));
}

// Return operations
void ReturnHandler::execute() {
  using Base = EVMOpcodeHandlerBase<ReturnHandler>;
  auto *Frame = Base::getFrame();
  auto *Context = Base::getContext();
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
  Context->setReturnData(std::move(ReturnData));

  Context->setStatus(EVMC_SUCCESS);
  // Return remaining gas to parent frame before freeing current frame
  uint64_t RemainingGas = Frame->GasLeft;
  Context->freeBackFrame();
  if (Context->getCurFrame() != nullptr) {
    Context->getCurFrame()->GasLeft += RemainingGas;
  }
}

// TODO: implement host storage revert in the future
void RevertHandler::execute() {
  using Base = EVMOpcodeHandlerBase<RevertHandler>;
  auto *Frame = Base::getFrame();
  auto *Context = Base::getContext();
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

  Context->setStatus(EVMC_REVERT);
  Context->setReturnData(std::move(RevertData));
  // Return remaining gas to parent frame before freeing current frame
  uint64_t RemainingGas = Frame->GasLeft;
  Context->freeBackFrame();
  if (Context->getCurFrame() != nullptr) {
    Context->getCurFrame()->GasLeft += RemainingGas;
  }
}

// Stack operations
void PUSHHandler::execute() {
  using Base = EVMOpcodeHandlerBase<PUSHHandler>;
  auto *Frame = Base::getFrame();
  auto *Context = Base::getContext();
  auto *Inst = Context->getInstance();
  auto *Mod = Inst->getModule();
  const uint8_t *Code = Mod->Code;
  uint8_t OpcodeByte = Code[Frame->Pc];
  size_t CodeSize = Mod->CodeSize;
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

void DUPHandler::execute() {
  using Base = EVMOpcodeHandlerBase<DUPHandler>;
  auto *Frame = Base::getFrame();
  auto *Context = Base::getContext();
  auto *Inst = Context->getInstance();
  auto *Mod = Inst->getModule();
  const uint8_t *Code = Mod->Code;
  uint8_t OpcodeByte = Code[Frame->Pc];
  // DUP1 ~ DUP16
  uint32_t N = OpcodeByte - static_cast<uint8_t>(evmc_opcode::OP_DUP1) + 1;
  EVM_THROW_IF(Frame->stackHeight(), <, N, UnexpectedNumArgs);
  intx::uint256 V = Frame->peek(N - 1);
  Frame->push(V);
}

void SWAPHandler::execute() {
  using Base = EVMOpcodeHandlerBase<SWAPHandler>;
  auto *Frame = Base::getFrame();
  auto *Context = Base::getContext();
  auto *Inst = Context->getInstance();
  auto *Mod = Inst->getModule();
  const uint8_t *Code = Mod->Code;
  uint8_t OpcodeByte = Code[Frame->Pc];
  // SWAP1 ~ SWAP16
  uint32_t N = OpcodeByte - static_cast<uint8_t>(evmc_opcode::OP_SWAP1) + 1;
  EVM_THROW_IF(Frame->stackHeight(), <, N + 1, UnexpectedNumArgs);
  intx::uint256 &Top = Frame->peek(0);
  intx::uint256 &Nth = Frame->peek(N);
  std::swap(Top, Nth);
}
