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

using namespace zen;
using namespace zen::evm;
using namespace zen::runtime;

/* ---------- Define gas cost macros begin ---------- */

#define DEFINE_CALCULATE_GAS(OpName, OpCode)                                   \
  template <> uint64_t OpName##Handler::calculateGas() {                       \
    static auto Table = evmc_get_instruction_metrics_table(DEFAULT_REVISION);  \
    static const auto Cost = Table[OpCode].gas_cost;                           \
    return Cost;                                                               \
  }

#define DEFINE_NOT_TEMPLATE_CALCULATE_GAS(OpName, OpCode)                      \
  uint64_t OpName##Handler::calculateGas() {                                   \
    static auto Table = evmc_get_instruction_metrics_table(DEFAULT_REVISION);  \
    static const auto Cost = Table[OpCode].gas_cost;                           \
    return Cost;                                                               \
  }

/* ---------- Define gas cost macros end ---------- */

/* ---------- Implement gas cost begin ---------- */

// Arithmetic operations
DEFINE_CALCULATE_GAS(Add, OP_ADD);
DEFINE_CALCULATE_GAS(Sub, OP_SUB);
DEFINE_CALCULATE_GAS(Mul, OP_MUL);
DEFINE_CALCULATE_GAS(Div, OP_DIV);
DEFINE_CALCULATE_GAS(Mod, OP_MOD);
DEFINE_CALCULATE_GAS(Exp, OP_EXP);
DEFINE_CALCULATE_GAS(SDiv, OP_SDIV);
DEFINE_CALCULATE_GAS(SMod, OP_SMOD);

// Modular arithmetic operations
DEFINE_CALCULATE_GAS(Addmod, OP_ADDMOD);
DEFINE_CALCULATE_GAS(Mulmod, OP_MULMOD);

// Unary operations
DEFINE_CALCULATE_GAS(Not, OP_NOT);
DEFINE_CALCULATE_GAS(IsZero, OP_ISZERO);

// Bitwise operations
DEFINE_CALCULATE_GAS(And, OP_AND);
DEFINE_CALCULATE_GAS(Or, OP_OR);
DEFINE_CALCULATE_GAS(Xor, OP_XOR);
DEFINE_CALCULATE_GAS(Shl, OP_SHL);
DEFINE_CALCULATE_GAS(Shr, OP_SHR);
DEFINE_CALCULATE_GAS(Eq, OP_EQ);
DEFINE_CALCULATE_GAS(Lt, OP_LT);
DEFINE_CALCULATE_GAS(Gt, OP_GT);
DEFINE_CALCULATE_GAS(Slt, OP_SLT);
DEFINE_CALCULATE_GAS(Sgt, OP_SGT);

// Arithmetic operations
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(SignExtend, OP_SIGNEXTEND);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(Byte, OP_BYTE);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(Sar, OP_SAR);

// Environmental information
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(Address, OP_ADDRESS);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(Balance, OP_BALANCE);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(Origin, OP_ORIGIN);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(Caller, OP_CALLER);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(CallValue, OP_CALLVALUE);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(CallDataLoad, OP_CALLDATALOAD);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(CallDataSize, OP_CALLDATASIZE);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(CallDataCopy, OP_CALLDATACOPY);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(CodeSize, OP_CODESIZE);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(CodeCopy, OP_CODECOPY);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(GasPrice, OP_GASPRICE);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(ExtCodeSize, OP_EXTCODESIZE);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(ExtCodeCopy, OP_EXTCODECOPY);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(ReturnDataSize, OP_RETURNDATASIZE);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(ReturnDataCopy, OP_RETURNDATACOPY);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(ExtCodeHash, OP_EXTCODEHASH);
// Block message
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(BlockHash, OP_BLOCKHASH);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(CoinBase, OP_COINBASE);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(TimeStamp, OP_TIMESTAMP);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(Number, OP_NUMBER);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(PrevRanDao, OP_PREVRANDAO);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(ChainId, OP_CHAINID);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(SelfBalance, OP_SELFBALANCE);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(BaseFee, OP_BASEFEE);
// Storage operations
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(SLoad, OP_SLOAD);

// Memory operations
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(MStore, OP_MSTORE);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(MStore8, OP_MSTORE8);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(MLoad, OP_MLOAD);

// Control flow operations
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(Jump, OP_JUMP);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(JumpI, OP_JUMPI);

// Environment operations
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(PC, OP_PC);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(MSize, OP_MSIZE);

// Return operations
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(Gas, OP_GAS);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(GasLimit, OP_GASLIMIT);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(Return, OP_RETURN);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(Revert, OP_REVERT);

// Stack operations
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(PUSH, OP_PUSH1);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(DUP, OP_DUP1);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(SWAP, OP_SWAP1);

/* ---------- Implement gas cost end ---------- */

/* ---------- Implement utility functions begin ---------- */
namespace {
// Calculate memory expansion gas cost
uint64_t calculateMemoryExpansionCost(uint64_t CurrentSize, uint64_t NewSize) {
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

// Expand memory and charge gas
void expandMemoryAndChargeGas(EVMFrame *Frame, uint64_t RequiredSize) {
  EVM_REQUIRE(RequiredSize <= MAX_REQUIRED_MEMORY_SIZE,
              EVMTooLargeRequiredMemory);
  uint64_t CurrentSize = Frame->Memory.size();

  // Calculate and charge memory expansion gas
  uint64_t MemoryExpansionCost =
      calculateMemoryExpansionCost(CurrentSize, RequiredSize);
  EVM_REQUIRE(Frame->GasLeft >= MemoryExpansionCost, EVMOutOfGas);
  Frame->GasLeft -= MemoryExpansionCost;

  // Expand memory if needed
  if (RequiredSize > CurrentSize) {
    Frame->Memory.resize(RequiredSize, 0);
  }
}

// Check memory requirements of a reasonable size.
void checkMemoryExpandAndChargeGas(EVMFrame *Frame, const intx::uint256 &Offset,
                                   uint64_t Size) {
  EVM_REQUIRE(Offset <= std::numeric_limits<uint64_t>::max(),
              EVMTooLargeRequiredMemory);
  EVM_REQUIRE(static_cast<uint64_t>(Offset) < UINT64_MAX - Size,
              IntegerOverflow);
  const auto NewSize = static_cast<uint64_t>(Offset) + Size;
  expandMemoryAndChargeGas(Frame, NewSize);
}
void checkMemoryExpandAndChargeGas(EVMFrame *Frame, const intx::uint256 &Offset,
                                   const intx::uint256 &Size) {
  if (Size == 0) {
    return; // No memory required
  }
  EVM_REQUIRE(Size <= std::numeric_limits<uint64_t>::max(),
              EVMTooLargeRequiredMemory);
  checkMemoryExpandAndChargeGas(Frame, Offset, static_cast<uint64_t>(Size));
}

// Convert uint256 to uint64
uint64_t uint256ToUint64(const intx::uint256 &Value) {
  return static_cast<uint64_t>(Value & 0xFFFFFFFFFFFFFFFFULL);
}
} // anonymous namespace
/* ---------- Implement utility functions end ---------- */

/* ---------- Implement opcode handlers begin ---------- */

void GasHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<GasHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(intx::uint256(Frame->GasLeft));
}

void SignExtendHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<SignExtendHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
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

void ByteHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<ByteHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
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

void SarHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<SarHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 Shift = Frame->pop();
  intx::uint256 Value = Frame->pop();

  intx::uint256 Res;
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
// environmental information operations
void AddressHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<AddressHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(intx::be::load<intx::uint256>(Frame->Msg->recipient));
}

void BalanceHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<BalanceHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 1);
  intx::uint256 X = Frame->pop();
  const auto Addr = intx::be::trunc<evmc::address>(X);

  if (Frame->Rev >= EVMC_BERLIN &&
      Frame->Host->access_account(Addr) == EVMC_ACCESS_COLD) {
    EVM_REQUIRE(Frame->GasLeft >= ADDITIONAL_COLD_ACCOUNT_ACCESS_COST,
                EVMOutOfGas);
    Frame->GasLeft -= ADDITIONAL_COLD_ACCOUNT_ACCESS_COST;
  }

  intx::uint256 Balance =
      intx::be::load<intx::uint256>(Frame->Host->get_balance(Addr));
  Frame->push(Balance);
}
void OriginHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<OriginHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(intx::be::load<intx::uint256>(Frame->get_tx_context().tx_origin));
}
void CallerHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<CallerHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(intx::be::load<intx::uint256>(Frame->Msg->sender));
}
void CallValueHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<CallValueHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(intx::be::load<intx::uint256>(Frame->Msg->value));
}
void CallDataLoadHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<CallDataLoadHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 1);
  intx::uint256 OffsetVal = Frame->pop();
  uint64_t Offset = uint256ToUint64(OffsetVal);

  if (Offset >= Frame->Msg->input_size) {
    Frame->push(intx::uint256(0));
    return;
  }

  uint8_t DataBytes[32] = {0};
  std::memcpy(DataBytes, Frame->Msg->input_data + Offset,
              std::min<size_t>(32, Frame->Msg->input_size - Offset));

  intx::uint256 Value = intx::be::load<intx::uint256>(DataBytes);
  Frame->push(Value);
}
void CallDataSizeHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<CallDataSizeHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(intx::uint256(Frame->Msg->input_size));
}
void CallDataCopyHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<CallDataCopyHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 3);
  intx::uint256 DestOffsetVal = Frame->pop();
  intx::uint256 OffsetVal = Frame->pop();
  intx::uint256 SizeVal = Frame->pop();
  // Ensure memory is large enough
  checkMemoryExpandAndChargeGas(Frame, DestOffsetVal, SizeVal);

  uint64_t DestOffset = uint256ToUint64(DestOffsetVal);
  uint64_t Offset = uint256ToUint64(OffsetVal);
  uint64_t Size = uint256ToUint64(SizeVal);

  auto src = Frame->Msg->input_size < Offset ? Frame->Msg->input_size : Offset;
  auto copy_size = std::min(Size, Frame->Msg->input_size - src);

  // Copy data to memory
  if (copy_size > 0) {
    std::memcpy(Frame->Memory.data() + DestOffset, Frame->Msg->input_data + src,
                copy_size);
  }
  if (Size > copy_size) {
    // Fill the rest with zeros if Size is larger than the actual copied size
    std::memset(Frame->Memory.data() + DestOffset + copy_size, 0,
                Size - copy_size);
  }
}
void CodeSizeHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<CodeSizeHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);

  auto *Context = Base::getContext();
  auto *Inst = Context->getInstance();
  auto *Mod = Inst->getModule();
  size_t CodeSize = Mod->CodeSize;

  Frame->push(intx::uint256(CodeSize));
}
void CodeCopyHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<CodeCopyHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 3);

  auto *Context = Base::getContext();
  auto *Inst = Context->getInstance();
  auto *Mod = Inst->getModule();
  const uint8_t *Code = Mod->Code;
  size_t CodeSize = Mod->CodeSize;

  intx::uint256 DestOffsetVal = Frame->pop();
  intx::uint256 OffsetVal = Frame->pop();
  intx::uint256 SizeVal = Frame->pop();
  // Ensure memory is large enough
  checkMemoryExpandAndChargeGas(Frame, DestOffsetVal, SizeVal);

  uint64_t DestOffset = uint256ToUint64(DestOffsetVal);
  uint64_t Offset = uint256ToUint64(OffsetVal);
  uint64_t Size = uint256ToUint64(SizeVal);

  // Copy code to memory
  if (Offset < CodeSize) {
    auto copy_size = std::min(Size, CodeSize - Offset);
    std::memcpy(Frame->Memory.data() + DestOffset, Code + Offset, copy_size);
    if (Size > copy_size) {
      // Fill the rest with zeros if Size is larger than the actual copied size
      std::memset(Frame->Memory.data() + DestOffset + copy_size, 0,
                  Size - copy_size);
    }
  } else {
    // If Offset is beyond the code size, fill with zeros
    if (Size > 0) {
      std::memset(Frame->Memory.data() + DestOffset, 0, Size);
    }
  }
}
void GasPriceHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<GasPriceHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(
      intx::be::load<intx::uint256>(Frame->get_tx_context().tx_gas_price));
}
void ExtCodeSizeHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<ExtCodeSizeHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 1);
  intx::uint256 X = Frame->pop();
  const auto Addr = intx::be::trunc<evmc::address>(X);

  if (Frame->Rev >= EVMC_BERLIN &&
      Frame->Host->access_account(Addr) == EVMC_ACCESS_COLD) {
    EVM_REQUIRE(Frame->GasLeft >= ADDITIONAL_COLD_ACCOUNT_ACCESS_COST,
                EVMOutOfGas);
    Frame->GasLeft -= ADDITIONAL_COLD_ACCOUNT_ACCESS_COST;
  }

  size_t CodeSize = Frame->Host->get_code_size(Addr);
  Frame->push(intx::uint256(CodeSize));
}
void ExtCodeCopyHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<ExtCodeCopyHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 4);
  intx::uint256 X = Frame->pop();
  intx::uint256 DestOffsetVal = Frame->pop();
  intx::uint256 OffsetVal = Frame->pop();
  intx::uint256 SizeVal = Frame->pop();
  const auto Addr = intx::be::trunc<evmc::address>(X);

  // Ensure memory is large enough
  checkMemoryExpandAndChargeGas(Frame, DestOffsetVal, SizeVal);

  uint64_t DestOffset = uint256ToUint64(DestOffsetVal);
  uint64_t Offset = uint256ToUint64(OffsetVal);
  uint64_t Size = uint256ToUint64(SizeVal);

  if (Frame->Rev >= EVMC_BERLIN &&
      Frame->Host->access_account(Addr) == EVMC_ACCESS_COLD) {
    EVM_REQUIRE(Frame->GasLeft >= ADDITIONAL_COLD_ACCOUNT_ACCESS_COST,
                EVMOutOfGas);
    Frame->GasLeft -= ADDITIONAL_COLD_ACCOUNT_ACCESS_COST;
  }

  size_t CodeSize = Frame->Host->get_code_size(Addr);

  if (Offset >= CodeSize) {
    // If Offset is beyond the code size, fill with zeros
    if (Size > 0) {
      std::memset(Frame->Memory.data() + DestOffset, 0, Size);
    }
  } else {
    // Copy code to memory
    auto copy_size = std::min(Size, CodeSize - Offset);
    size_t CopiedSize = Frame->Host->copy_code(
        Addr, Offset, Frame->Memory.data() + DestOffset, copy_size);
    if (CopiedSize < Size) {
      // If the copied size is less than requested, fill the rest with zeros
      std::memset(Frame->Memory.data() + DestOffset + CopiedSize, 0,
                  Size - CopiedSize);
    }
  }
}
void ReturnDataSizeHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<ReturnDataSizeHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  auto *Context = Base::getContext();
  const auto &ReturnData = Context->getReturnData();
  Frame->push(ReturnData.size());
}
void ReturnDataCopyHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<ReturnDataCopyHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 3);
  intx::uint256 DestOffsetVal = Frame->pop();
  intx::uint256 OffsetVal = Frame->pop();
  intx::uint256 SizeVal = Frame->pop();
  // Ensure memory is large enough
  checkMemoryExpandAndChargeGas(Frame, DestOffsetVal, SizeVal);

  uint64_t DestOffset = uint256ToUint64(DestOffsetVal);
  uint64_t Offset = uint256ToUint64(OffsetVal);
  uint64_t Size = uint256ToUint64(SizeVal);

  auto *Context = Base::getContext();
  const auto &ReturnData = Context->getReturnData();

  if (Offset >= ReturnData.size()) {
    // If Offset is beyond the return data size, fill with zeros
    if (Size > 0) {
      std::memset(Frame->Memory.data() + DestOffset, 0, Size);
    }
    return;
  }

  // Copy return data to memory
  auto copy_size = std::min(Size, ReturnData.size() - Offset);

  std::memcpy(Frame->Memory.data() + DestOffset, ReturnData.data() + Offset,
              copy_size);

  if (Size > copy_size) {
    // Fill the rest with zeros if Size is larger than the actual copied size
    std::memset(Frame->Memory.data() + DestOffset + copy_size, 0,
                Size - copy_size);
  }
}
void ExtCodeHashHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<ExtCodeHashHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 1);
  intx::uint256 X = Frame->pop();
  const auto Addr = intx::be::trunc<evmc::address>(X);

  if (Frame->Rev >= EVMC_BERLIN &&
      Frame->Host->access_account(Addr) == EVMC_ACCESS_COLD) {
    EVM_REQUIRE(Frame->GasLeft >= ADDITIONAL_COLD_ACCOUNT_ACCESS_COST,
                EVMOutOfGas);
    Frame->GasLeft -= ADDITIONAL_COLD_ACCOUNT_ACCESS_COST;
  }

  Frame->push(intx::be::load<intx::uint256>(Frame->Host->get_code_hash(Addr)));
}

// block message operations
void BlockHashHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<BlockHashHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 1);
  intx::uint256 BlockNumberVal = Frame->pop();

  const auto UpperBound = Frame->get_tx_context().block_number;
  const auto LowerBound = std::max(UpperBound - 256, decltype(UpperBound){0});
  int64_t BlockNumber = static_cast<int64_t>(BlockNumberVal);
  const auto Header = (BlockNumberVal < UpperBound && BlockNumber >= LowerBound)
                          ? Frame->Host->get_block_hash(BlockNumber)
                          : evmc::bytes32{};
  Frame->push(intx::be::load<intx::uint256>(Header));
}
void CoinBaseHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<CoinBaseHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(
      intx::be::load<intx::uint256>(Frame->get_tx_context().block_coinbase));
}
void TimeStampHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<TimeStampHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(intx::uint256(Frame->get_tx_context().block_timestamp));
}
void NumberHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<NumberHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(intx::uint256(Frame->get_tx_context().block_number));
}
void PrevRanDaoHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<PrevRanDaoHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(
      intx::be::load<intx::uint256>(Frame->get_tx_context().block_prev_randao));
}
void ChainIdHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<ChainIdHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(intx::be::load<intx::uint256>(Frame->get_tx_context().chain_id));
}
void SelfBalanceHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<SelfBalanceHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(intx::be::load<intx::uint256>(
      Frame->Host->get_balance(Frame->Msg->recipient)));
}
void BaseFeeHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<BaseFeeHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(
      intx::be::load<intx::uint256>(Frame->get_tx_context().block_base_fee));
}
// Storage operations
void SLoadHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<SLoadHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 1);
  intx::uint256 Key = Frame->pop();
  const auto KeyAddr = intx::be::store<evmc::bytes32>(Key);
  if (Frame->Rev >= EVMC_BERLIN &&
      Frame->Host->access_account(Frame->Msg->recipient) == EVMC_ACCESS_COLD) {
    EVM_REQUIRE(Frame->GasLeft >= ADDITIONAL_COLD_ACCOUNT_ACCESS_COST,
                EVMOutOfGas);
    Frame->GasLeft -= ADDITIONAL_COLD_ACCOUNT_ACCESS_COST;
  }
  intx::uint256 Value = intx::be::load<intx::uint256>(
      Frame->Host->get_storage(Frame->Msg->recipient, KeyAddr));
  Frame->push(Value);
}

// Memory operations
void MStoreHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<MStoreHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 OffsetVal = Frame->pop();
  intx::uint256 Value = Frame->pop();

  checkMemoryExpandAndChargeGas(Frame, OffsetVal, 32);
  uint64_t Offset = uint256ToUint64(OffsetVal);

  uint8_t ValueBytes[32];
  intx::be::store(ValueBytes, Value);
  // TODO: use EVMMemory class in the future
  std::memcpy(Frame->Memory.data() + Offset, ValueBytes, 32);
}

void MStore8Handler::doExecute() {
  using Base = EVMOpcodeHandlerBase<MStore8Handler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 OffsetVal = Frame->pop();
  intx::uint256 Value = Frame->pop();

  checkMemoryExpandAndChargeGas(Frame, OffsetVal, 1);
  uint64_t Offset = uint256ToUint64(OffsetVal);

  uint8_t ByteValue = static_cast<uint8_t>(Value & intx::uint256{0xFF});
  Frame->Memory[Offset] = ByteValue;
}

void MLoadHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<MLoadHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 1);
  intx::uint256 OffsetVal = Frame->pop();

  checkMemoryExpandAndChargeGas(Frame, OffsetVal, 32);
  uint64_t Offset = uint256ToUint64(OffsetVal);

  uint8_t ValueBytes[32];
  // TODO: use EVMMemory class in the future
  std::memcpy(ValueBytes, Frame->Memory.data() + Offset, 32);

  intx::uint256 Value = intx::be::load<intx::uint256>(ValueBytes);
  Frame->push(Value);
}

// Control flow operations
void JumpHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<JumpHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  auto *Context = Base::getContext();
  auto *Inst = Context->getInstance();
  auto *Mod = Inst->getModule();
  const uint8_t *Code = Mod->Code;
  size_t CodeSize = Mod->CodeSize;
  EVM_STACK_CHECK(Frame, 1);
  // We can assume that valid destination can't greater than uint64_t
  uint64_t Dest = uint256ToUint64(Frame->pop());

  EVM_REQUIRE(Dest < CodeSize, EVMBadJumpDestination);
  EVM_REQUIRE(static_cast<evmc_opcode>(Code[Dest]) == evmc_opcode::OP_JUMPDEST,
              EVMBadJumpDestination);

  Frame->Pc = Dest;
  Context->IsJump = true;
}

void JumpIHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<JumpIHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
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
  EVM_REQUIRE(Dest < CodeSize, EVMBadJumpDestination);
  EVM_REQUIRE(static_cast<evmc_opcode>(Code[Dest]) == evmc_opcode::OP_JUMPDEST,
              EVMBadJumpDestination);

  Frame->Pc = Dest;
  Context->IsJump = true;
}

// Environment operations
void PCHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<PCHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(intx::uint256(Frame->Pc));
}

void MSizeHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<MSizeHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  // Return the current memory size in bytes
  intx::uint256 MemSize = Frame->Memory.size();
  Frame->push(MemSize);
}

void GasLimitHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<GasLimitHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(intx::uint256(Frame->GasLimit));
}

// Return operations
void ReturnHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<ReturnHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  auto *Context = Base::getContext();
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 OffsetVal = Frame->pop();
  intx::uint256 SizeVal = Frame->pop();

  checkMemoryExpandAndChargeGas(Frame, OffsetVal, SizeVal);
  uint64_t Offset = uint256ToUint64(OffsetVal);
  uint64_t Size = uint256ToUint64(SizeVal);

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
void RevertHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<RevertHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  auto *Context = Base::getContext();
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 OffsetVal = Frame->pop();
  intx::uint256 SizeVal = Frame->pop();

  checkMemoryExpandAndChargeGas(Frame, OffsetVal, SizeVal);
  uint64_t Offset = uint256ToUint64(OffsetVal);
  uint64_t Size = uint256ToUint64(SizeVal);

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
void PUSHHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<PUSHHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  auto *Context = Base::getContext();
  auto *Inst = Context->getInstance();
  auto *Mod = Inst->getModule();
  const uint8_t *Code = Mod->Code;
  uint8_t OpcodeByte = Code[Frame->Pc];
  size_t CodeSize = Mod->CodeSize;
  // PUSH1 ~ PUSH32
  uint32_t NumBytes =
      OpcodeByte - static_cast<uint8_t>(evmc_opcode::OP_PUSH1) + 1;
  EVM_REQUIRE(Frame->Pc + NumBytes < CodeSize, UnexpectedEnd);
  uint8_t ValueBytes[32];
  memset(ValueBytes, 0, sizeof(ValueBytes));
  std::memcpy(ValueBytes + (32 - NumBytes), Code + Frame->Pc + 1, NumBytes);
  intx::uint256 Val = intx::be::load<intx::uint256>(ValueBytes);
  Frame->push(Val);
  Frame->Pc += NumBytes;
}

void DUPHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<DUPHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  auto *Context = Base::getContext();
  auto *Inst = Context->getInstance();
  auto *Mod = Inst->getModule();
  const uint8_t *Code = Mod->Code;
  uint8_t OpcodeByte = Code[Frame->Pc];
  // DUP1 ~ DUP16
  uint32_t N = OpcodeByte - static_cast<uint8_t>(evmc_opcode::OP_DUP1) + 1;
  EVM_REQUIRE(Frame->stackHeight() >= N, UnexpectedNumArgs);
  intx::uint256 V = Frame->peek(N - 1);
  Frame->push(V);
}

void SWAPHandler::doExecute() {
  using Base = EVMOpcodeHandlerBase<SWAPHandler>;
  auto *Frame = Base::getFrame();
  EVM_FRAME_CHECK(Frame);
  auto *Context = Base::getContext();
  auto *Inst = Context->getInstance();
  auto *Mod = Inst->getModule();
  const uint8_t *Code = Mod->Code;
  uint8_t OpcodeByte = Code[Frame->Pc];
  // SWAP1 ~ SWAP16
  uint32_t N = OpcodeByte - static_cast<uint8_t>(evmc_opcode::OP_SWAP1) + 1;
  EVM_REQUIRE(Frame->stackHeight() >= (N + 1), UnexpectedNumArgs);
  intx::uint256 &Top = Frame->peek(0);
  intx::uint256 &Nth = Frame->peek(N);
  std::swap(Top, Nth);
}

/* ---------- Implement opcode handlers end ---------- */
