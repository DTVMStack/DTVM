// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "evm/opcode_handlers.h"
#include "common/errors.h"
#include "evm/interpreter.h"
#include "evmc/instructions.h"
#include "host/evm/crypto.h"
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

#define DEFINE_MULTICODE_NOT_TEMPLATE_CALCULATE_GAS(OpName)                    \
  uint64_t OpName##Handler::calculateGas() {                                   \
    static auto Table = evmc_get_instruction_metrics_table(DEFAULT_REVISION);  \
    static const auto Cost = Table[OpCode].gas_cost;                           \
    return Cost;                                                               \
  }

#define DEFINE_UNIMPLEMENT_CALCULATE_GAS(OpName, Cost)                         \
  uint64_t OpName##Handler::calculateGas() { return Cost; }

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
DEFINE_UNIMPLEMENT_CALCULATE_GAS(BlobHash, BLOBHASH_GAS_COST);
DEFINE_UNIMPLEMENT_CALCULATE_GAS(BlobBaseFee, BLOBBASEFEE_GAS_COST);
// Storage operations
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(SLoad, OP_SLOAD);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(SStore, OP_SSTORE);

// Memory operations
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(MStore, OP_MSTORE);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(MStore8, OP_MSTORE8);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(MLoad, OP_MLOAD);

// Control flow operations
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(Jump, OP_JUMP);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(JumpI, OP_JUMPI);
// Temporary Storage
// Evmc do not support these opcodes
DEFINE_UNIMPLEMENT_CALCULATE_GAS(TLoad, TLOAD_GAS_COST);
DEFINE_UNIMPLEMENT_CALCULATE_GAS(TStore, TSTORE_GAS_COST);
DEFINE_UNIMPLEMENT_CALCULATE_GAS(MCopy, MCOPY_GAS_COST);

// Environment operations
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(PC, OP_PC);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(MSize, OP_MSIZE);

// Return operations
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(Gas, OP_GAS);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(GasLimit, OP_GASLIMIT);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(Return, OP_RETURN);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(Revert, OP_REVERT);

// Stack operations
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(Pop, OP_POP);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(Push, OP_PUSH1);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(Push0, OP_PUSH0);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(Dup, OP_DUP1);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(Swap, OP_SWAP1);

// Call operations
DEFINE_MULTICODE_NOT_TEMPLATE_CALCULATE_GAS(Create) // CREATE CREATE
DEFINE_MULTICODE_NOT_TEMPLATE_CALCULATE_GAS(
    Call) // CALL CALLCODE STATICCALL DELEGATECALL

// Logging operations
DEFINE_MULTICODE_NOT_TEMPLATE_CALCULATE_GAS(Log) // LOG0 LOG1 LOG2 LOG3 LOG4

// Crypto operations
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(Keccak256, OP_KECCAK256);

// Self-destruct operation
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(SelfDestruct, OP_SELFDESTRUCT)

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

bool chargeGas(EVMFrame *Frame, uint64_t GasCost) {
  if ((uint64_t)Frame->Msg->gas < GasCost) {
    return false;
  }
  Frame->Msg->gas -= GasCost;
  return true;
}
// copy cose and charge gas
constexpr int64_t numWords(uint64_t Size) noexcept {
  /// The size of the EVM 256-bit word.
  constexpr auto WORD_SIZE = 32;
  return static_cast<int64_t>((Size + (WORD_SIZE - 1)) / WORD_SIZE);
}
bool copyCodeAndChargeGas(EVMFrame *Frame, uint64_t Size) {
  return chargeGas(Frame, numWords(Size) * WORD_COPY_COST);
}

// Expand memory and charge gas
bool expandMemoryAndChargeGas(EVMFrame *Frame, uint64_t RequiredSize) {
  EVM_REQUIRE(RequiredSize <= MAX_REQUIRED_MEMORY_SIZE,
              EVMTooLargeRequiredMemory);
  uint64_t CurrentSize = Frame->Memory.size();

  // Calculate and charge memory expansion gas
  uint64_t MemoryExpansionCost =
      calculateMemoryExpansionCost(CurrentSize, RequiredSize);
  if (!chargeGas(Frame, MemoryExpansionCost)) {
    return false;
  }

  // Expand memory if needed
  if (RequiredSize > CurrentSize) {
    Frame->Memory.resize(RequiredSize, 0);
  }
  return true;
}

// Check memory requirements of a reasonable size.
bool checkMemoryExpandAndChargeGas(EVMFrame *Frame, const intx::uint256 &Offset,
                                   uint64_t Size) {
  EVM_REQUIRE(Offset <= std::numeric_limits<uint64_t>::max(),
              EVMTooLargeRequiredMemory);
  EVM_REQUIRE(static_cast<uint64_t>(Offset) < UINT64_MAX - Size,
              IntegerOverflow);
  const auto NewSize = static_cast<uint64_t>(Offset) + Size;
  return expandMemoryAndChargeGas(Frame, NewSize);
}
bool checkMemoryExpandAndChargeGas(EVMFrame *Frame, const intx::uint256 &Offset,
                                   const intx::uint256 &Size) {
  if (Size == 0) {
    return true; // No memory required
  }
  EVM_REQUIRE(Size <= std::numeric_limits<uint64_t>::max(),
              EVMTooLargeRequiredMemory);
  return checkMemoryExpandAndChargeGas(Frame, Offset,
                                       static_cast<uint64_t>(Size));
}

// Convert uint256 to uint64
uint64_t uint256ToUint64(const intx::uint256 &Value) {
  return static_cast<uint64_t>(Value & 0xFFFFFFFFFFFFFFFFULL);
}

} // anonymous namespace
/* ---------- Implement utility functions end ---------- */

/* ---------- Implement opcode handlers begin ---------- */

void GasHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(intx::uint256(Frame->Msg->gas));
}

void SignExtendHandler::doExecute() {
  auto *Frame = getFrame();
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
  auto *Frame = getFrame();
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
  auto *Frame = getFrame();
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
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(intx::be::load<intx::uint256>(Frame->Msg->recipient));
}

void BalanceHandler::doExecute() {
  auto *Frame = getFrame();
  auto *Context = getContext();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 1);
  intx::uint256 X = Frame->pop();
  const auto Addr = intx::be::trunc<evmc::address>(X);

  if (Frame->Rev >= EVMC_BERLIN &&
      Frame->Host->access_account(Addr) == EVMC_ACCESS_COLD) {
    if (!chargeGas(Frame, ADDITIONAL_COLD_ACCOUNT_ACCESS_COST)) {
      Context->setStatus(EVMC_OUT_OF_GAS);
      return;
    }
  }

  intx::uint256 Balance =
      intx::be::load<intx::uint256>(Frame->Host->get_balance(Addr));
  Frame->push(Balance);
}
void OriginHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(intx::be::load<intx::uint256>(Frame->getTxContext().tx_origin));
}
void CallerHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(intx::be::load<intx::uint256>(Frame->Msg->sender));
}
void CallValueHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(intx::be::load<intx::uint256>(Frame->Msg->value));
}
void CallDataLoadHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 1);
  intx::uint256 OffsetVal = Frame->pop();
  uint64_t Offset = uint256ToUint64(OffsetVal);

  if (OffsetVal > intx::uint256(Frame->Msg->input_size)) {
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
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(intx::uint256(Frame->Msg->input_size));
}
void CallDataCopyHandler::doExecute() {
  auto *Frame = getFrame();
  auto *Context = getContext();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 3);
  intx::uint256 DestOffsetVal = Frame->pop();
  intx::uint256 OffsetVal = Frame->pop();
  intx::uint256 SizeVal = Frame->pop();
  // Ensure memory is large enough
  if (!checkMemoryExpandAndChargeGas(Frame, DestOffsetVal, SizeVal)) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  uint64_t DestOffset = uint256ToUint64(DestOffsetVal);
  uint64_t Offset = uint256ToUint64(OffsetVal);
  uint64_t Size = uint256ToUint64(SizeVal);

  auto Src = Frame->Msg->input_size < Offset ? Frame->Msg->input_size : Offset;
  auto CopySize = std::min(Size, Frame->Msg->input_size - Src);
  if (copyCodeAndChargeGas(Frame, Size) == false) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  // Copy data to memory
  if (CopySize > 0) {
    std::memcpy(Frame->Memory.data() + DestOffset, Frame->Msg->input_data + Src,
                CopySize);
  }
  if (Size > CopySize) {
    // Fill the rest with zeros if Size is larger than the actual copied size
    std::memset(Frame->Memory.data() + DestOffset + CopySize, 0,
                Size - CopySize);
  }
}
void CodeSizeHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);

  auto *Context = getContext();
  auto *Inst = Context->getInstance();
  auto *Mod = Inst->getModule();
  size_t CodeSize = Mod->CodeSize;

  Frame->push(intx::uint256(CodeSize));
}
void CodeCopyHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 3);

  auto *Context = getContext();
  auto *Inst = Context->getInstance();
  auto *Mod = Inst->getModule();
  const uint8_t *Code = Mod->Code;
  size_t CodeSize = Mod->CodeSize;

  intx::uint256 DestOffsetVal = Frame->pop();
  intx::uint256 OffsetVal = Frame->pop();
  intx::uint256 SizeVal = Frame->pop();
  // Ensure memory is large enough
  if (!checkMemoryExpandAndChargeGas(Frame, DestOffsetVal, SizeVal)) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  uint64_t DestOffset = uint256ToUint64(DestOffsetVal);
  uint64_t Offset = uint256ToUint64(OffsetVal);
  uint64_t Size = uint256ToUint64(SizeVal);
  if (copyCodeAndChargeGas(Frame, Size) == false) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  // Copy code to memory
  if (Offset < CodeSize) {
    auto CopySize = std::min(Size, CodeSize - Offset);
    std::memcpy(Frame->Memory.data() + DestOffset, Code + Offset, CopySize);
    if (Size > CopySize) {
      // Fill the rest with zeros if Size is larger than the actual copied size
      std::memset(Frame->Memory.data() + DestOffset + CopySize, 0,
                  Size - CopySize);
    }
  } else {
    // If Offset is beyond the code size, fill with zeros
    if (Size > 0) {
      std::memset(Frame->Memory.data() + DestOffset, 0, Size);
    }
  }
}
void GasPriceHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(
      intx::be::load<intx::uint256>(Frame->getTxContext().tx_gas_price));
}
void ExtCodeSizeHandler::doExecute() {
  auto *Frame = getFrame();
  auto *Context = getContext();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 1);
  intx::uint256 X = Frame->pop();
  const auto Addr = intx::be::trunc<evmc::address>(X);

  if (Frame->Rev >= EVMC_BERLIN &&
      Frame->Host->access_account(Addr) == EVMC_ACCESS_COLD) {
    if (Frame->Msg->gas < ADDITIONAL_COLD_ACCOUNT_ACCESS_COST) {
      Context->setStatus(EVMC_OUT_OF_GAS);
      return;
    }
    Frame->Msg->gas -= ADDITIONAL_COLD_ACCOUNT_ACCESS_COST;
  }

  size_t CodeSize = Frame->Host->get_code_size(Addr);
  Frame->push(intx::uint256(CodeSize));
}
void ExtCodeCopyHandler::doExecute() {
  auto *Frame = getFrame();
  auto *Context = getContext();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 4);
  intx::uint256 X = Frame->pop();
  intx::uint256 DestOffsetVal = Frame->pop();
  intx::uint256 OffsetVal = Frame->pop();
  intx::uint256 SizeVal = Frame->pop();
  const auto Addr = intx::be::trunc<evmc::address>(X);

  // Ensure memory is large enough
  if (!checkMemoryExpandAndChargeGas(Frame, DestOffsetVal, SizeVal)) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  uint64_t DestOffset = uint256ToUint64(DestOffsetVal);
  uint64_t Offset = uint256ToUint64(OffsetVal);
  uint64_t Size = uint256ToUint64(SizeVal);
  if (copyCodeAndChargeGas(Frame, Size) == false) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  if (Frame->Rev >= EVMC_BERLIN &&
      Frame->Host->access_account(Addr) == EVMC_ACCESS_COLD) {
    if (Frame->Msg->gas < ADDITIONAL_COLD_ACCOUNT_ACCESS_COST) {
      Context->setStatus(EVMC_OUT_OF_GAS);
      return;
    }
    Frame->Msg->gas -= ADDITIONAL_COLD_ACCOUNT_ACCESS_COST;
  }

  size_t CodeSize = Frame->Host->get_code_size(Addr);

  if (Offset >= CodeSize) {
    // If Offset is beyond the code size, fill with zeros
    if (Size > 0) {
      std::memset(Frame->Memory.data() + DestOffset, 0, Size);
    }
  } else {
    // Copy code to memory
    auto CopySize = std::min(Size, CodeSize - Offset);
    size_t CopiedSize = Frame->Host->copy_code(
        Addr, Offset, Frame->Memory.data() + DestOffset, CopySize);
    if (CopiedSize < Size) {
      // If the copied size is less than requested, fill the rest with zeros
      std::memset(Frame->Memory.data() + DestOffset + CopiedSize, 0,
                  Size - CopiedSize);
    }
  }
}
void ReturnDataSizeHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  auto *Context = getContext();
  const auto &ReturnData = Context->getReturnData();
  Frame->push(ReturnData.size());
}
void ReturnDataCopyHandler::doExecute() {
  auto *Frame = getFrame();
  auto *Context = getContext();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 3);
  intx::uint256 DestOffsetVal = Frame->pop();
  intx::uint256 OffsetVal = Frame->pop();
  intx::uint256 SizeVal = Frame->pop();
  // Ensure memory is large enough
  if (!checkMemoryExpandAndChargeGas(Frame, DestOffsetVal, SizeVal)) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  uint64_t DestOffset = uint256ToUint64(DestOffsetVal);
  uint64_t Offset = uint256ToUint64(OffsetVal);
  uint64_t Size = uint256ToUint64(SizeVal);
  if (copyCodeAndChargeGas(Frame, Size) == false) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  const auto &ReturnData = Context->getReturnData();

  if (Offset >= ReturnData.size()) {
    // If Offset is beyond the return data size, fill with zeros
    if (Size > 0) {
      std::memset(Frame->Memory.data() + DestOffset, 0, Size);
    }
    return;
  }

  // Copy return data to memory
  auto CopySize = std::min(Size, ReturnData.size() - Offset);

  std::memcpy(Frame->Memory.data() + DestOffset, ReturnData.data() + Offset,
              CopySize);

  if (Size > CopySize) {
    // Fill the rest with zeros if Size is larger than the actual copied size
    std::memset(Frame->Memory.data() + DestOffset + CopySize, 0,
                Size - CopySize);
  }
}
void ExtCodeHashHandler::doExecute() {
  auto *Frame = getFrame();
  auto *Context = getContext();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 1);
  intx::uint256 X = Frame->pop();
  const auto Addr = intx::be::trunc<evmc::address>(X);

  if (Frame->Rev >= EVMC_BERLIN &&
      Frame->Host->access_account(Addr) == EVMC_ACCESS_COLD) {
    if (Frame->Msg->gas < ADDITIONAL_COLD_ACCOUNT_ACCESS_COST) {
      Context->setStatus(EVMC_OUT_OF_GAS);
      return;
    }
    Frame->Msg->gas -= ADDITIONAL_COLD_ACCOUNT_ACCESS_COST;
  }

  Frame->push(intx::be::load<intx::uint256>(Frame->Host->get_code_hash(Addr)));
}

// block message operations
void BlockHashHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 1);
  intx::uint256 BlockNumberVal = Frame->pop();

  const auto UpperBound = Frame->getTxContext().block_number;
  const auto LowerBound = std::max(UpperBound - 256, decltype(UpperBound){0});
  int64_t BlockNumber = static_cast<int64_t>(BlockNumberVal);
  const auto Header = (BlockNumberVal < UpperBound && BlockNumber >= LowerBound)
                          ? Frame->Host->get_block_hash(BlockNumber)
                          : evmc::bytes32{};
  Frame->push(intx::be::load<intx::uint256>(Header));
}
void CoinBaseHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(
      intx::be::load<intx::uint256>(Frame->getTxContext().block_coinbase));
}
void TimeStampHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(intx::uint256(Frame->getTxContext().block_timestamp));
}
void NumberHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(intx::uint256(Frame->getTxContext().block_number));
}
void PrevRanDaoHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(
      intx::be::load<intx::uint256>(Frame->getTxContext().block_prev_randao));
}
void ChainIdHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(intx::be::load<intx::uint256>(Frame->getTxContext().chain_id));
}
void SelfBalanceHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(intx::be::load<intx::uint256>(
      Frame->Host->get_balance(Frame->Msg->recipient)));
}
void BaseFeeHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(
      intx::be::load<intx::uint256>(Frame->getTxContext().block_base_fee));
}
void BlobHashHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 1);
  intx::uint256 IndexVal = Frame->pop();
  uint64_t Index = uint256ToUint64(IndexVal);

  if (IndexVal >= Frame->getTxContext().blob_hashes_count) {
    Frame->push(intx::uint256(0));
    return;
  }

  const auto &BlobHash = Frame->getTxContext().blob_hashes[Index];
  Frame->push(intx::be::load<intx::uint256>(BlobHash));
}
void BlobBaseFeeHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(
      intx::be::load<intx::uint256>(Frame->getTxContext().blob_base_fee));
}
// Storage operations
void SLoadHandler::doExecute() {
  auto *Frame = getFrame();
  auto *Context = getContext();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 1);
  intx::uint256 Key = Frame->pop();
  const auto KeyAddr = intx::be::store<evmc::bytes32>(Key);
  if (Frame->Rev >= EVMC_BERLIN &&
      Frame->Host->access_storage(Frame->Msg->recipient, KeyAddr) ==
          EVMC_ACCESS_COLD) {
    if (Frame->Msg->gas < ADDITIONAL_COLD_ACCOUNT_ACCESS_COST) {
      Context->setStatus(EVMC_OUT_OF_GAS);
      return;
    }
    Frame->Msg->gas -= ADDITIONAL_COLD_ACCOUNT_ACCESS_COST;
  }
  intx::uint256 Value = intx::be::load<intx::uint256>(
      Frame->Host->get_storage(Frame->Msg->recipient, KeyAddr));
  Frame->push(Value);
}
void SStoreHandler::doExecute() {
  auto *Frame = getFrame();
  auto *Context = getContext();
  EVM_FRAME_CHECK(Frame);
  EVM_REQUIRE(!Frame->isStaticMode(), EVMStaticModeViolation);

  EVM_STACK_CHECK(Frame, 2);
  const auto Key = intx::be::store<evmc::bytes32>(Frame->pop());
  const auto Value = intx::be::store<evmc::bytes32>(Frame->pop());

  const auto GasCostCold = (Frame->Rev >= EVMC_BERLIN &&
                            Frame->Host->access_storage(
                                Frame->Msg->recipient, Key) == EVMC_ACCESS_COLD)
                               ? COLD_SLOAD_COST
                               : 0;
  const auto Status =
      Frame->Host->set_storage(Frame->Msg->recipient, Key, Value);

  const auto [GasCostWarm, GasReFund] = SstoreCosts[Frame->Rev][Status];

  const auto GasCost = GasCostCold + GasCostWarm;
  if (Frame->Msg->gas < GasCost) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }
  Frame->Msg->gas -= GasCost;
  Frame->GasRefund += GasReFund;
}

void Keccak256Handler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 2);

  const auto Offset = Frame->pop();
  const auto Length = Frame->pop();

  const size_t MemOffset = static_cast<size_t>(Offset);
  const size_t DataLength = static_cast<size_t>(Length);

  if (!checkMemoryExpandAndChargeGas(Frame, MemOffset, DataLength)) {
    getContext()->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  const uint8_t *InputData = Frame->Memory.data() + MemOffset;

  uint8_t HashResult[32];
  host::evm::crypto::keccak256(InputData, DataLength, HashResult);

  const auto ResultValue = intx::be::load<intx::uint256>(HashResult);
  Frame->push(ResultValue);
}

// Memory operations
void MStoreHandler::doExecute() {
  auto *Frame = getFrame();
  auto *Context = getContext();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 OffsetVal = Frame->pop();
  intx::uint256 Value = Frame->pop();

  uint64_t Offset = uint256ToUint64(OffsetVal);
  if (!checkMemoryExpandAndChargeGas(Frame, Offset, 32)) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  uint8_t ValueBytes[32];
  intx::be::store(ValueBytes, Value);
  // TODO: use EVMMemory class in the future
  std::memcpy(Frame->Memory.data() + Offset, ValueBytes, 32);
}

void MStore8Handler::doExecute() {
  auto *Frame = getFrame();
  auto *Context = getContext();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 OffsetVal = Frame->pop();
  intx::uint256 Value = Frame->pop();

  uint64_t Offset = uint256ToUint64(OffsetVal);
  if (!checkMemoryExpandAndChargeGas(Frame, Offset, 1)) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  uint8_t ByteValue = static_cast<uint8_t>(Value & intx::uint256{0xFF});
  Frame->Memory[Offset] = ByteValue;
}

void MLoadHandler::doExecute() {
  auto *Frame = getFrame();
  auto *Context = getContext();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 1);
  intx::uint256 OffsetVal = Frame->pop();

  uint64_t Offset = uint256ToUint64(OffsetVal);
  if (!checkMemoryExpandAndChargeGas(Frame, Offset, 32)) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  uint8_t ValueBytes[32];
  // TODO: use EVMMemory class in the future
  std::memcpy(ValueBytes, Frame->Memory.data() + Offset, 32);

  intx::uint256 Value = intx::be::load<intx::uint256>(ValueBytes);
  Frame->push(Value);
}

// Control flow operations
void JumpHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  auto *Context = getContext();
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
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  auto *Context = getContext();
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
// Temporary storage operations
void TLoadHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 1);
  intx::uint256 X = Frame->pop(); // Key is uint256, can be used as index
  const auto Key = intx::be::store<evmc::bytes32>(X);
  const auto Value =
      Frame->Host->get_transient_storage(Frame->Msg->recipient, Key);
  Frame->push(intx::be::load<intx::uint256>(Value));
}
void TStoreHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_REQUIRE(!Frame->isStaticMode(), EVMStaticModeViolation);

  EVM_STACK_CHECK(Frame, 2);
  const auto Key = intx::be::store<evmc::bytes32>(Frame->pop());
  const auto Value = intx::be::store<evmc::bytes32>(Frame->pop());

  Frame->Host->set_transient_storage(Frame->Msg->recipient, Key, Value);
}
void MCopyHandler::doExecute() {
  auto *Frame = getFrame();
  auto *Context = getContext();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 3);
  intx::uint256 DestOffsetVal = Frame->pop();
  intx::uint256 OffsetVal = Frame->pop();
  intx::uint256 SizeVal = Frame->pop();

  // Ensure memory is large enough
  if (!checkMemoryExpandAndChargeGas(Frame, std::max(DestOffsetVal, OffsetVal),
                                     SizeVal)) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  uint64_t DestOffset = uint256ToUint64(DestOffsetVal);
  uint64_t Offset = uint256ToUint64(OffsetVal);
  uint64_t Size = uint256ToUint64(SizeVal);

  if (copyCodeAndChargeGas(Frame, Size) == false) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }
  if (Size > 0) {
    std::memmove(Frame->Memory.data() + DestOffset,
                 Frame->Memory.data() + Offset, Size);
  }
}

// Environment operations
void PCHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(intx::uint256(Frame->Pc));
}

void MSizeHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  // Return the current memory size in bytes
  intx::uint256 MemSize = Frame->Memory.size();
  Frame->push(MemSize);
}

void GasLimitHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(intx::uint256(Frame->getTxContext().block_gas_limit));
}

// Return operations
void ReturnHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  auto *Context = getContext();
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 OffsetVal = Frame->pop();
  intx::uint256 SizeVal = Frame->pop();

  uint64_t Offset = uint256ToUint64(OffsetVal);
  uint64_t Size = uint256ToUint64(SizeVal);
  if (!checkMemoryExpandAndChargeGas(Frame, Offset, Size)) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  // TODO: use EVMMemory class in the future
  std::vector<uint8_t> ReturnData(Frame->Memory.begin() + Offset,
                                  Frame->Memory.begin() + Offset + Size);
  Context->setReturnData(std::move(ReturnData));

  Context->setStatus(EVMC_SUCCESS);
  // Return remaining gas to parent frame before freeing current frame
  uint64_t RemainingGas = Frame->Msg->gas;
  Context->freeBackFrame();
  if (Context->getCurFrame() != nullptr) {
    Context->getCurFrame()->Msg->gas += RemainingGas;
  }
}

// TODO: implement host storage revert in the future
void RevertHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  auto *Context = getContext();
  EVM_STACK_CHECK(Frame, 2);
  intx::uint256 OffsetVal = Frame->pop();
  intx::uint256 SizeVal = Frame->pop();

  uint64_t Offset = uint256ToUint64(OffsetVal);
  uint64_t Size = uint256ToUint64(SizeVal);
  if (!checkMemoryExpandAndChargeGas(Frame, Offset, Size)) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  std::vector<uint8_t> RevertData(Frame->Memory.begin() + Offset,
                                  Frame->Memory.begin() + Offset + Size);

  Context->setStatus(EVMC_REVERT);
  Context->setReturnData(std::move(RevertData));
  // Return remaining gas to parent frame before freeing current frame
  uint64_t RemainingGas = Frame->Msg->gas;
  Context->freeBackFrame();
  if (Context->getCurFrame() != nullptr) {
    Context->getCurFrame()->Msg->gas += RemainingGas;
  }
}

// Stack operations
void PopHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 1);
  Frame->pop();
}

void PushHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  auto *Context = getContext();
  auto *Inst = Context->getInstance();
  auto *Mod = Inst->getModule();
  auto *Code = Mod->Code;
  uint8_t OpcodeByte = static_cast<uint8_t>(OpCode);
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

void Push0Handler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  Frame->push(0);
}

void DupHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  uint8_t OpcodeByte = static_cast<uint8_t>(OpCode);
  // DUP1 ~ DUP16
  uint32_t N = OpcodeByte - static_cast<uint8_t>(evmc_opcode::OP_DUP1) + 1;
  EVM_REQUIRE(Frame->stackHeight() >= N, UnexpectedNumArgs);
  intx::uint256 V = Frame->peek(N - 1);
  Frame->push(V);
}

void SwapHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  uint8_t OpcodeByte = static_cast<uint8_t>(OpCode);
  // SWAP1 ~ SWAP16
  uint32_t N = OpcodeByte - static_cast<uint8_t>(evmc_opcode::OP_SWAP1) + 1;
  EVM_REQUIRE(Frame->stackHeight() >= (N + 1), UnexpectedNumArgs);
  intx::uint256 &Top = Frame->peek(0);
  intx::uint256 &Nth = Frame->peek(N);
  std::swap(Top, Nth);
}

void CreateHandler::doExecute() {
  auto *Frame = getFrame();
  auto *Context = getContext();

  EVM_FRAME_CHECK(Frame);
  if (OpCode == evmc_opcode::OP_CREATE) {
    EVM_STACK_CHECK(Frame, 3);
  } else if (OpCode == evmc_opcode::OP_CREATE2) {
    EVM_STACK_CHECK(Frame, 4);
  } else {
    // in fact, this should never happen, but we still need to handle it
    throw common::getError(common::ErrorCode::EVMInvalidInstruction);
  }

  intx::uint256 Value = Frame->pop();
  intx::uint256 CodeOffset = Frame->pop();
  intx::uint256 CodeSizeVal = Frame->pop();
  intx::uint256 Salt =
      (OpCode == evmc_opcode::OP_CREATE2 ? Frame->pop() : intx::uint256(0));

  // Assume failure
  Frame->push(0);
  Context->setReturnData(std::vector<uint8_t>());

  if (Frame->isStaticMode()) {
    Context->setStatus(EVMC_STATIC_MODE_VIOLATION);
    return;
  }

  // EIP-3860
  if (Frame->Rev >= EVMC_SHANGHAI and CodeSizeVal > MAX_SIZE_OF_INITCODE) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }
  const auto InitCodeWordCost =
      6 * (OpCode == OP_CREATE2) + 2 * (Frame->Rev >= EVMC_SHANGHAI);
  const auto InitCodeSize =
      uint256ToUint64((CodeSizeVal + 31) / 32); // round up to the nearest word
  const auto InitCodeCost = InitCodeWordCost * InitCodeSize;
  if (!chargeGas(Frame, InitCodeCost)) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  if (Frame->Msg->depth >= MAXSTACK) {
    Context->setStatus(EVMC_SUCCESS); // "Light" failure
    return;
  }

  if (intx::be::load<intx::uint256>(
          Frame->Host->get_balance(Frame->Msg->recipient)) < Value) {
    Context->setStatus(EVMC_SUCCESS); // "Light" failure
    return;
  }

  if (!expandMemoryAndChargeGas(Frame,
                                uint256ToUint64(CodeOffset + CodeSizeVal))) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  evmc_message NewMsg{.kind = evmc_call_kind::EVMC_CREATE,
                      .depth = Frame->Msg->depth + 1,
                      .gas = Frame->Msg->gas,
                      .sender = Frame->Msg->sender,
                      .input_data =
                          Frame->Memory.data() + uint256ToUint64(CodeOffset),
                      .input_size = uint256ToUint64(CodeSizeVal),
                      .value = intx::be::store<evmc::bytes32>(Value),
                      .create2_salt = intx::be::store<evmc::bytes32>(Salt)};

  // EIP-150
  if (Frame->Rev >= EVMC_TANGERINE_WHISTLE) {
    NewMsg.gas = NewMsg.gas - NewMsg.gas / 64;
  }

  evmc::Result Result = Frame->Host->call(NewMsg);
  chargeGas(Frame,
            NewMsg.gas - Result.gas_left); // it's safe to charge gas here
  Frame->GasRefund += Result.gas_refund;

  Context->setReturnData(std::vector<uint8_t>(
      Result.output_data, Result.output_data + Result.output_size));
  if (Result.status_code == EVMC_SUCCESS) {
    Frame->pop(); // pop the assume value
    Frame->push(intx::be::load<intx::uint256>(Result.create_address));
  }
  Context->setStatus(Result.status_code);
}

void CallHandler::doExecute() {
  auto *Frame = getFrame();
  auto *Context = getContext();

  EVM_FRAME_CHECK(Frame);

  bool NeedValue = false;
  if (OpCode == evmc_opcode::OP_CALL or OpCode == evmc_opcode::OP_CALLCODE) {
    EVM_STACK_CHECK(Frame, 7);
    NeedValue = true;
  } else if (OpCode == evmc_opcode::OP_DELEGATECALL or
             OpCode == evmc_opcode::OP_STATICCALL) {
    EVM_STACK_CHECK(Frame, 6);
  } else {
    // in fact, this should never happen, but we still need to handle it
    throw common::getError(common::ErrorCode::EVMInvalidInstruction);
  }

  const auto Gas = Frame->pop();
  auto Dest = intx::be::trunc<evmc::address>(Frame->pop());
  const auto Value = NeedValue ? Frame->pop() : 0;
  const auto InputOffset = Frame->pop();
  const auto InputSize = Frame->pop();
  const auto OutputOffset = Frame->pop();
  const auto OutputSize = Frame->pop();

  // Assume failure
  Frame->push(0);
  Context->setReturnData(std::vector<uint8_t>());

  // EIP-2929
  if (Frame->Rev >= EVMC_BERLIN and
      Frame->Host->access_account(Dest) == EVMC_ACCESS_COLD) {
    if (!chargeGas(Frame, COLD_ACCOUNT_ACCESS_COST)) {
      Context->setStatus(EVMC_OUT_OF_GAS);
      return;
    }
  } else {
    if (!chargeGas(Frame, WARM_ACCOUNT_ACCESS_COST)) {
      Context->setStatus(EVMC_OUT_OF_GAS);
      return;
    }
  }

  if (Frame->Msg->depth >= MAXSTACK) {
    Context->setStatus(EVMC_SUCCESS); // "Light" failure
    return;
  }

  if (NeedValue and intx::be::load<intx::uint256>(Frame->Host->get_balance(
                        Frame->Msg->recipient)) < Value) {
    Context->setStatus(EVMC_SUCCESS); // "Light" failure
    return;
  }

  if (!expandMemoryAndChargeGas(Frame,
                                uint256ToUint64(InputOffset + InputSize)) or
      !expandMemoryAndChargeGas(Frame,
                                uint256ToUint64(OutputOffset + OutputSize))) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  evmc_message NewMsg{
      .kind = static_cast<evmc_call_kind>(OpCode),
      .flags = (OpCode == evmc_opcode::OP_STATICCALL) ? uint32_t{EVMC_STATIC}
                                                      : Frame->Msg->flags,
      .depth = Frame->Msg->depth + 1,
      .gas = static_cast<int64_t>(Gas),
      .recipient = (OpCode == OP_CALL or OpCode == OP_STATICCALL)
                       ? Dest
                       : Frame->Msg->recipient,
      .sender = (OpCode == OP_DELEGATECALL) ? Frame->Msg->sender
                                            : Frame->Msg->recipient,
      .input_data = Frame->Memory.data() + uint256ToUint64(InputOffset),
      .input_size = uint256ToUint64(InputSize),
      .value = (OpCode == OP_DELEGATECALL)
                   ? Frame->Msg->value
                   : intx::be::store<evmc::bytes32>(Value),
      .code_address = Dest,
  };

  if (Frame->Rev >= EVMC_TANGERINE_WHISTLE) {
    NewMsg.gas = std::min(NewMsg.gas, (Frame->Msg->gas - Frame->Msg->gas / 64));
  } else if (NewMsg.gas > Frame->Msg->gas) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  int64_t Cost = NeedValue ? CALL_VALUE_COST : 0;

  if (OpCode == OP_CALL) {
    if (Frame->isStaticMode()) {
      Context->setStatus(EVMC_STATIC_MODE_VIOLATION);
      return;
    }
    if (!Frame->Host->account_exists(Dest)) {
      Cost += ACCOUNT_CREATION_COST;
    }
  }

  if (!chargeGas(Frame, Cost)) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    Frame->push(0);
    return;
  }

  // EIP-150
  if (NeedValue) {
    NewMsg.gas += CALL_GAS_STIPEND;
  }

  const auto Result = Frame->Host->call(NewMsg);
  Context->setResource();
  if (Result.status_code == EVMC_SUCCESS) {
    Frame->pop(); // pop the assume value
    Frame->push(intx::uint256(1));
  }
  Context->setReturnData(std::vector<uint8_t>(
      Result.output_data, Result.output_data + Result.output_size));

  const auto CopySize =
      std::min((size_t)uint256ToUint64(OutputSize), Result.output_size);
  if (CopySize > 0) {
    std::memcpy(Frame->Memory.data() + uint256ToUint64(OutputOffset),
                Result.output_data, CopySize);
  }

  const auto GasUsed = NewMsg.gas - Result.gas_left;
  chargeGas(Frame, GasUsed); // it's safe to charge gas here
  Frame->GasRefund += Result.gas_refund;
  Context->setStatus(Result.status_code);
}

void LogHandler::doExecute() {
  auto *Frame = getFrame();
  auto *Context = getContext();
  EVM_FRAME_CHECK(Frame);

  if (Frame->isStaticMode()) {
    Context->setStatus(EVMC_STATIC_MODE_VIOLATION);
    return;
  }

  uint8_t OpcodeByte = static_cast<uint8_t>(OpCode);
  // LOG0 ~ LOG4
  uint32_t NumTopics = OpcodeByte - static_cast<uint8_t>(evmc_opcode::OP_LOG0);
  EVM_STACK_CHECK(Frame, NumTopics + 2);

  intx::uint256 OffsetVal = Frame->pop();
  intx::uint256 SizeVal = Frame->pop();

  uint64_t Offset = uint256ToUint64(OffsetVal);
  uint64_t Size = uint256ToUint64(SizeVal);
  uint64_t ReqSize = Offset + Size;

  if (!expandMemoryAndChargeGas(Frame, ReqSize)) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  // Charge additional gas for log data (8 gas per byte)
  uint64_t LogDataCost = 8 * Size;
  if (!chargeGas(Frame, LogDataCost)) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  evmc::bytes32 Topics[4];
  for (uint32_t I = 0; I < NumTopics; ++I) {
    intx::uint256 Topic = Frame->pop();
    Topics[I] = intx::be::store<evmc::bytes32>(Topic);
  }

  Frame->Host->emit_log(Frame->Msg->recipient, Frame->Memory.data() + Offset,
                        Size, Topics, NumTopics);
}

void SelfDestructHandler::doExecute() {
  auto *Frame = getFrame();
  auto *Context = getContext();
  EVM_FRAME_CHECK(Frame);

  if (Frame->isStaticMode()) {
    Context->setStatus(EVMC_STATIC_MODE_VIOLATION);
    return;
  }

  EVM_STACK_CHECK(Frame, 1);
  intx::uint256 BeneficiaryAddr = Frame->pop();
  const auto Beneficiary = intx::be::trunc<evmc::address>(BeneficiaryAddr);

  // EIP-161: if target account does not exist, charge account creation cost
  if (Frame->Rev >= EVMC_SPURIOUS_DRAGON &&
      !Frame->Host->account_exists(Beneficiary)) {
    if (!chargeGas(Frame, ACCOUNT_CREATION_COST)) {
      Context->setStatus(EVMC_OUT_OF_GAS);
      return;
    }
  }

  // EIP-2929: Charge cold account access cost if needed
  if (Frame->Rev >= EVMC_BERLIN &&
      Frame->Host->access_account(Beneficiary) == EVMC_ACCESS_COLD) {
    if (!chargeGas(Frame, ADDITIONAL_COLD_ACCOUNT_ACCESS_COST)) {
      Context->setStatus(EVMC_OUT_OF_GAS);
      return;
    }
  }

  Frame->Host->selfdestruct(Frame->Msg->recipient, Beneficiary);

  uint64_t RemainingGas = Frame->Msg->gas;
  Context->freeBackFrame();
  if (Context->getCurFrame() != nullptr) {
    Context->getCurFrame()->Msg->gas += RemainingGas;
  }
}

/* ---------- Implement opcode handlers end ---------- */
