// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "evm/opcode_handlers.h"
#include "common/errors.h"
#include "evm/gas_storage_cost.h"
#include "evm/interpreter.h"
#include "evmc/evmc.h"
#include "evmc/instructions.h"
#include "host/evm/crypto.h"
#include "runtime/evm_instance.h"

zen::evm::EVMFrame *zen::evm::EVMResource::CurrentFrame = nullptr;
zen::evm::InterpreterExecContext *zen::evm::EVMResource::CurrentContext =
    nullptr;

using namespace zen;
using namespace zen::evm;
using namespace zen::runtime;

namespace {

evmc_revision currentRevision() {
  auto *Context = EVMResource::getInterpreterExecContext();
  if (!Context) {
    return DEFAULT_REVISION;
  }
  auto *Instance = Context->getInstance();
  return Instance ? Instance->getRevision() : DEFAULT_REVISION;
}

} // namespace

/* ---------- Define gas cost macros begin ---------- */

#define DEFINE_CALCULATE_GAS(OpName, OpCode)                                   \
  template <> uint64_t OpName##Handler::calculateGas() {                       \
    static auto Table = evmc_get_instruction_metrics_table(currentRevision()); \
    static const auto Cost = Table[OpCode].gas_cost;                           \
    return Cost;                                                               \
  }

#define DEFINE_NOT_TEMPLATE_CALCULATE_GAS(OpName, OpCode)                      \
  uint64_t OpName##Handler::calculateGas() {                                   \
    static auto Table = evmc_get_instruction_metrics_table(currentRevision()); \
    static const auto Cost = Table[OpCode].gas_cost;                           \
    return Cost;                                                               \
  }

#define DEFINE_MULTICODE_NOT_TEMPLATE_CALCULATE_GAS(OpName)                    \
  uint64_t OpName##Handler::calculateGas() {                                   \
    static auto Table = evmc_get_instruction_metrics_table(currentRevision()); \
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
DEFINE_CALCULATE_GAS(SDiv, OP_SDIV);
DEFINE_CALCULATE_GAS(SMod, OP_SMOD);

// Modular arithmetic operations
DEFINE_CALCULATE_GAS(Addmod, OP_ADDMOD);
DEFINE_CALCULATE_GAS(Mulmod, OP_MULMOD);

// Unary operations
DEFINE_CALCULATE_GAS(Not, OP_NOT);
DEFINE_CALCULATE_GAS(IsZero, OP_ISZERO);
DEFINE_CALCULATE_GAS(Clz, OP_CLZ);

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
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(Exp, OP_EXP);
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
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(BlobHash, OP_BLOBHASH);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(BlobBaseFee, OP_BLOBBASEFEE);
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
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(JumpDest, OP_JUMPDEST);
// Temporary Storage
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(TLoad, OP_TLOAD);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(TStore, OP_TSTORE);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(MCopy, OP_MCOPY);

// Environment operations
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(PC, OP_PC);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(MSize, OP_MSIZE);

// Return operations
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(Gas, OP_GAS);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(GasLimit, OP_GASLIMIT);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(Return, OP_RETURN);
DEFINE_NOT_TEMPLATE_CALCULATE_GAS(Revert, OP_REVERT);

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
  if ((uint64_t)Frame->Msg.gas < GasCost) {
    return false;
  }
  Frame->Msg.gas -= GasCost;
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
  if (RequiredSize > MAX_REQUIRED_MEMORY_SIZE) {
    return false;
  }
  uint64_t CurrentSize = Frame->Memory.size();

  // Calculate and charge memory expansion gas
  RequiredSize = (RequiredSize + 31) / 32 * 32; // align to 32 bytes
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
  if (Offset > std::numeric_limits<uint64_t>::max()) {
    return false;
  }
  const uint64_t Offset64 = static_cast<uint64_t>(Offset);
  if (Offset64 > std::numeric_limits<uint64_t>::max() - Size) {
    return false;
  }
  const auto NewSize = Offset64 + Size;
  return expandMemoryAndChargeGas(Frame, NewSize);
}
bool checkMemoryExpandAndChargeGas(EVMFrame *Frame, const intx::uint256 &Offset,
                                   const intx::uint256 &Size) {
  if (Size == 0) {
    return true; // No memory required
  }
  if (Size > std::numeric_limits<uint64_t>::max()) {
    return false;
  }
  return checkMemoryExpandAndChargeGas(Frame, Offset,
                                       static_cast<uint64_t>(Size));
}

// Convert uint256 to uint64
uint64_t uint256ToUint64(const intx::uint256 &Value) {
  if ((Value[3] | Value[2] | Value[1]) != 0) {
    return std::numeric_limits<uint64_t>::max();
  }
  return Value[0];
}

} // anonymous namespace
/* ---------- Implement utility functions end ---------- */

/* ---------- Implement opcode handlers begin ---------- */

void GasHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_REQUIRE_STACK_SPACE(Frame, 1);
  Frame->push(intx::uint256(Frame->Msg.gas));
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
    // Generate mask: lower I*8 bits are 0, the rest are 1
    intx::uint256 Mask = (intx::uint256(1) << SignBitPosition) - 1;

    if (SignBit) {
      // Apply mask: extend the sign bit to higher bits
      Res |= ~Mask;
    } else {
      // Apply mask: extend the sign bit to higher bits
      Res &= Mask;
    }
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
    Res = IsNegative ? ~intx::uint256(0) : intx::uint256(0);
  }
  Frame->push(Res);
}

void ExpHandler::doExecute() {
  auto *Frame = getFrame();
  auto *Context = getContext();
  EVM_STACK_CHECK(Frame, 2);

  auto &A = Frame->Stack[Frame->Sp - 1];
  auto &B = Frame->Stack[Frame->Sp - 2];
  uint64_t BytesNum = intx::count_significant_bytes(B);
  uint64_t ByteGas = currentRevision() < EVMC_SPURIOUS_DRAGON
                         ? EXP_BYTE_GAS_PRE_SPURIOUS_DRAGON
                         : EXP_BYTE_GAS;
  if (!chargeGas(Frame, BytesNum * ByteGas)) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }
  B = intx::exp(A, B);
  --Frame->Sp;
}

// environmental information operations
void AddressHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_REQUIRE_STACK_SPACE(Frame, 1);
  Frame->push(intx::be::load<intx::uint256>(Frame->Msg.recipient));
}

void BalanceHandler::doExecute() {
  auto *Frame = getFrame();
  auto *Context = getContext();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 1);
  intx::uint256 X = Frame->pop();
  const auto Addr = intx::be::trunc<evmc::address>(X);

  const auto Rev = currentRevision();
  if (Rev >= EVMC_BERLIN &&
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
  EVM_REQUIRE_STACK_SPACE(Frame, 1);
  Frame->push(intx::be::load<intx::uint256>(Frame->getTxContext().tx_origin));
}
void CallerHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_REQUIRE_STACK_SPACE(Frame, 1);
  Frame->push(intx::be::load<intx::uint256>(Frame->Msg.sender));
}
void CallValueHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_REQUIRE_STACK_SPACE(Frame, 1);
  Frame->push(intx::be::load<intx::uint256>(Frame->Msg.value));
}
void CallDataLoadHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 1);
  intx::uint256 OffsetVal = Frame->pop();
  uint64_t Offset = uint256ToUint64(OffsetVal);

  if (OffsetVal > intx::uint256(Frame->Msg.input_size)) {
    Frame->push(intx::uint256(0));
    return;
  }

  uint8_t DataBytes[32] = {0};
  std::memcpy(DataBytes, Frame->Msg.input_data + Offset,
              std::min<size_t>(32, Frame->Msg.input_size - Offset));

  intx::uint256 Value = intx::be::load<intx::uint256>(DataBytes);
  Frame->push(Value);
}
void CallDataSizeHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_REQUIRE_STACK_SPACE(Frame, 1);
  Frame->push(intx::uint256(Frame->Msg.input_size));
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

  auto Src = Frame->Msg.input_size < Offset ? Frame->Msg.input_size : Offset;
  auto CopySize = std::min(Size, Frame->Msg.input_size - Src);
  if (copyCodeAndChargeGas(Frame, Size) == false) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  // Copy data to memory
  if (CopySize > 0) {
    std::memcpy(Frame->Memory.data() + DestOffset, Frame->Msg.input_data + Src,
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

  EVM_REQUIRE_STACK_SPACE(Frame, 1);
  Frame->push(intx::uint256(CodeSize));
}
void CodeCopyHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 3);

  auto *Context = getContext();
  auto *Inst = Context->getInstance();
  auto *Mod = Inst->getModule();
  const Byte *Code = Mod->Code;
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
  EVM_REQUIRE_STACK_SPACE(Frame, 1);
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

  const auto Rev = currentRevision();
  if (Rev >= EVMC_BERLIN &&
      Frame->Host->access_account(Addr) == EVMC_ACCESS_COLD) {
    if (Frame->Msg.gas < ADDITIONAL_COLD_ACCOUNT_ACCESS_COST) {
      Context->setStatus(EVMC_OUT_OF_GAS);
      return;
    }
    Frame->Msg.gas -= ADDITIONAL_COLD_ACCOUNT_ACCESS_COST;
  }

  size_t CodeSize = Frame->Host->get_code_size(Addr);
  EVM_REQUIRE_STACK_SPACE(Frame, 1);
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

  const auto Rev = currentRevision();
  if (Rev >= EVMC_BERLIN &&
      Frame->Host->access_account(Addr) == EVMC_ACCESS_COLD) {
    if (Frame->Msg.gas < ADDITIONAL_COLD_ACCOUNT_ACCESS_COST) {
      Context->setStatus(EVMC_OUT_OF_GAS);
      return;
    }
    Frame->Msg.gas -= ADDITIONAL_COLD_ACCOUNT_ACCESS_COST;
  }

  if (Size > 0) {
    // Copy code to memory
    size_t CopiedSize = Frame->Host->copy_code(
        Addr, Offset, Frame->Memory.data() + DestOffset, Size);
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
  EVM_REQUIRE_STACK_SPACE(Frame, 1);
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

  const auto &ReturnData = Context->getReturnData();
  // EIP-211: RETURNDATACOPY reverts if offset + size > returndata.size()
  if (OffsetVal > ReturnData.size() || SizeVal > ReturnData.size() ||
      OffsetVal + SizeVal > ReturnData.size()) {
    Context->setStatus(EVMC_INVALID_MEMORY_ACCESS);
    return;
  }

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

  // Copy return data to memory
  if (Size > 0) {
    std::memcpy(Frame->Memory.data() + DestOffset, ReturnData.data() + Offset,
                Size);
  }
}
void ExtCodeHashHandler::doExecute() {
  auto *Frame = getFrame();
  auto *Context = getContext();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 1);
  intx::uint256 X = Frame->pop();
  const auto Addr = intx::be::trunc<evmc::address>(X);

  const auto Rev = currentRevision();
  if (Rev >= EVMC_BERLIN &&
      Frame->Host->access_account(Addr) == EVMC_ACCESS_COLD) {
    if (Frame->Msg.gas < ADDITIONAL_COLD_ACCOUNT_ACCESS_COST) {
      Context->setStatus(EVMC_OUT_OF_GAS);
      return;
    }
    Frame->Msg.gas -= ADDITIONAL_COLD_ACCOUNT_ACCESS_COST;
  }
  EVM_REQUIRE_STACK_SPACE(Frame, 1);
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
  EVM_REQUIRE_STACK_SPACE(Frame, 1);
  Frame->push(
      intx::be::load<intx::uint256>(Frame->getTxContext().block_coinbase));
}
void TimeStampHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_REQUIRE_STACK_SPACE(Frame, 1);
  Frame->push(intx::uint256(Frame->getTxContext().block_timestamp));
}
void NumberHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_REQUIRE_STACK_SPACE(Frame, 1);
  Frame->push(intx::uint256(Frame->getTxContext().block_number));
}
void PrevRanDaoHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_REQUIRE_STACK_SPACE(Frame, 1);
  Frame->push(
      intx::be::load<intx::uint256>(Frame->getTxContext().block_prev_randao));
}
void ChainIdHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_REQUIRE_STACK_SPACE(Frame, 1);
  Frame->push(intx::be::load<intx::uint256>(Frame->getTxContext().chain_id));
}
void SelfBalanceHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_REQUIRE_STACK_SPACE(Frame, 1);
  Frame->push(intx::be::load<intx::uint256>(
      Frame->Host->get_balance(Frame->Msg.recipient)));
}
void BaseFeeHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_REQUIRE_STACK_SPACE(Frame, 1);
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
  EVM_REQUIRE_STACK_SPACE(Frame, 1);
  Frame->push(intx::be::load<intx::uint256>(BlobHash));
}
void BlobBaseFeeHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_REQUIRE_STACK_SPACE(Frame, 1);
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
  const auto Rev = currentRevision();
  if (Rev >= EVMC_BERLIN &&
      Frame->Host->access_storage(Frame->Msg.recipient, KeyAddr) ==
          EVMC_ACCESS_COLD) {
    if (Frame->Msg.gas < ADDITIONAL_COLD_SLOAD_COST) {
      Context->setStatus(EVMC_OUT_OF_GAS);
      return;
    }
    Frame->Msg.gas -= ADDITIONAL_COLD_SLOAD_COST;
  }
  intx::uint256 Value = intx::be::load<intx::uint256>(
      Frame->Host->get_storage(Frame->Msg.recipient, KeyAddr));
  Frame->push(Value);
}
void SStoreHandler::doExecute() {
  auto *Frame = getFrame();
  auto *Context = getContext();
  EVM_FRAME_CHECK(Frame);
  EVM_SET_EXCEPTION_UNLESS(!Frame->isStaticMode(), EVMC_STATIC_MODE_VIOLATION);

  const auto Rev = currentRevision();
  if (Rev >= EVMC_ISTANBUL && Frame->Msg.gas <= SSTORE_REQUIRED_ISTANBUL) {
    getContext()->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  EVM_STACK_CHECK(Frame, 2);
  const auto Key = intx::be::store<evmc::bytes32>(Frame->pop());
  const auto Value = intx::be::store<evmc::bytes32>(Frame->pop());

  const auto GasCostCold =
      (Rev >= EVMC_BERLIN && Frame->Host->access_storage(
                                 Frame->Msg.recipient, Key) == EVMC_ACCESS_COLD)
          ? COLD_SLOAD_COST
          : 0;
  const auto Status =
      Frame->Host->set_storage(Frame->Msg.recipient, Key, Value);

  const auto [GasCostWarm, GasReFund] = SSTORE_COSTS[Rev][Status];

  const auto GasCost = GasCostCold + GasCostWarm;
  if (!chargeGas(Frame, GasCost)) {
    getContext()->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  // Track refund at Instance level (consolidate all gas refund tracking there)
  Context->getInstance()->addGasRefund(GasReFund);
}

void Keccak256Handler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 2);

  const auto Offset = Frame->pop();
  const auto Length = Frame->pop();

  if (!checkMemoryExpandAndChargeGas(Frame, Offset, Length)) {
    getContext()->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  const uint64_t DataLength = static_cast<uint64_t>(Length);
  const uint64_t MemOffset =
      DataLength == 0 ? 0 : static_cast<uint64_t>(Offset);
  const uint64_t ExtraGas =
      static_cast<uint64_t>(numWords(static_cast<uint64_t>(DataLength))) * 6;
  // Calculate the gas cost of keccak itself based on word count
  if (!chargeGas(Frame, ExtraGas)) {
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

  if (!checkMemoryExpandAndChargeGas(Frame, OffsetVal, 32)) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }
  uint64_t Offset = static_cast<uint64_t>(OffsetVal);

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

  if (!checkMemoryExpandAndChargeGas(Frame, OffsetVal, 1)) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }
  uint64_t Offset = static_cast<uint64_t>(OffsetVal);
  uint8_t ByteValue = static_cast<uint8_t>(Value & intx::uint256{0xFF});
  Frame->Memory[Offset] = ByteValue;
}

void MLoadHandler::doExecute() {
  auto *Frame = getFrame();
  auto *Context = getContext();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 1);
  intx::uint256 OffsetVal = Frame->pop();

  if (!checkMemoryExpandAndChargeGas(Frame, OffsetVal, 32)) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }
  uint64_t Offset = static_cast<uint64_t>(OffsetVal);

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
  const Byte *Code = Mod->Code;
  size_t CodeSize = Mod->CodeSize;
  EVM_STACK_CHECK(Frame, 1);
  // We can assume that valid destination can't greater than uint64_t
  uint64_t Dest = uint256ToUint64(Frame->pop());

  EVM_SET_EXCEPTION_UNLESS(Dest < CodeSize, EVMC_BAD_JUMP_DESTINATION);
  EVM_SET_EXCEPTION_UNLESS(static_cast<evmc_opcode>(Code[Dest]) ==
                               evmc_opcode::OP_JUMPDEST,
                           EVMC_BAD_JUMP_DESTINATION);

  Frame->Pc = Dest;
  Context->IsJump = true;
}

void JumpIHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  auto *Context = getContext();
  auto *Inst = Context->getInstance();
  auto *Mod = Inst->getModule();
  const Byte *Code = Mod->Code;
  size_t CodeSize = Mod->CodeSize;
  EVM_STACK_CHECK(Frame, 2);
  // We can assume that valid destination can't greater than uint64_t
  uint64_t Dest = uint256ToUint64(Frame->pop());
  intx::uint256 Cond = Frame->pop();

  if (!Cond) {
    return;
  }
  EVM_SET_EXCEPTION_UNLESS(Dest < CodeSize, EVMC_BAD_JUMP_DESTINATION);
  EVM_SET_EXCEPTION_UNLESS(static_cast<evmc_opcode>(Code[Dest]) ==
                               evmc_opcode::OP_JUMPDEST,
                           EVMC_BAD_JUMP_DESTINATION);

  Frame->Pc = Dest;
  Context->IsJump = true;
}

void JumpDestHandler::doExecute() {
  // No additional state updates required; gas is charged in execute().
}
// Temporary storage operations
void TLoadHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 1);
  intx::uint256 X = Frame->pop(); // Key is uint256, can be used as index
  const auto Key = intx::be::store<evmc::bytes32>(X);
  const auto Value =
      Frame->Host->get_transient_storage(Frame->Msg.recipient, Key);
  Frame->push(intx::be::load<intx::uint256>(Value));
}
void TStoreHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_SET_EXCEPTION_UNLESS(!Frame->isStaticMode(), EVMC_STATIC_MODE_VIOLATION);

  EVM_STACK_CHECK(Frame, 2);
  const auto Key = intx::be::store<evmc::bytes32>(Frame->pop());
  const auto Value = intx::be::store<evmc::bytes32>(Frame->pop());

  Frame->Host->set_transient_storage(Frame->Msg.recipient, Key, Value);
}
void MCopyHandler::doExecute() {
  auto *Frame = getFrame();
  auto *Context = getContext();
  EVM_FRAME_CHECK(Frame);
  EVM_STACK_CHECK(Frame, 3);
  intx::uint256 DestOffsetVal = Frame->pop();
  intx::uint256 OffsetVal = Frame->pop();
  intx::uint256 SizeVal = Frame->pop();

  if (SizeVal == 0) {
    return;
  }

  // Ensure memory is large enough
  if (!checkMemoryExpandAndChargeGas(Frame, std::max(DestOffsetVal, OffsetVal),
                                     SizeVal)) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  uint64_t DestOffset = static_cast<uint64_t>(DestOffsetVal);
  uint64_t Offset = static_cast<uint64_t>(OffsetVal);
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
  EVM_REQUIRE_STACK_SPACE(Frame, 1);
  Frame->push(intx::uint256(Frame->Pc));
}

void MSizeHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  // Return the current memory size in bytes
  intx::uint256 MemSize = Frame->Memory.size();
  EVM_REQUIRE_STACK_SPACE(Frame, 1);
  Frame->push(MemSize);
}

void GasLimitHandler::doExecute() {
  auto *Frame = getFrame();
  EVM_FRAME_CHECK(Frame);
  EVM_REQUIRE_STACK_SPACE(Frame, 1);
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

  // First check memory expansion with uint256 values
  if (!checkMemoryExpandAndChargeGas(Frame, OffsetVal, SizeVal)) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  // Only convert to uint64 after successful memory check
  uint64_t Size = static_cast<uint64_t>(SizeVal);
  uint64_t Offset = Size == 0 ? 0 : static_cast<uint64_t>(OffsetVal);

  // TODO: use EVMMemory class in the future
  std::vector<uint8_t> ReturnData(Frame->Memory.begin() + Offset,
                                  Frame->Memory.begin() + Offset + Size);
  Context->setReturnData(std::move(ReturnData));

  Context->setStatus(EVMC_SUCCESS);
  // Return remaining gas to parent frame before freeing current frame
  uint64_t RemainingGas = Frame->Msg.gas;
  Context->freeBackFrame();
  if (Context->getCurFrame() != nullptr) {
    Context->getCurFrame()->Msg.gas += RemainingGas;
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

  // First check memory expansion with uint256 values
  if (!checkMemoryExpandAndChargeGas(Frame, OffsetVal, SizeVal)) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  // Only convert to uint64 after successful memory check
  uint64_t Size = static_cast<uint64_t>(SizeVal);
  uint64_t Offset = Size == 0 ? 0 : static_cast<uint64_t>(OffsetVal);

  std::vector<uint8_t> RevertData(Frame->Memory.begin() + Offset,
                                  Frame->Memory.begin() + Offset + Size);

  Context->setStatus(EVMC_REVERT);
  Context->setReturnData(std::move(RevertData));
  Context->getInstance()->setGasRefund(Frame->GasRefundSnapshot);
  // Return remaining gas to parent frame before freeing current frame
  uint64_t RemainingGas = Frame->Msg.gas;
  Context->freeBackFrame();
  if (Context->getCurFrame() != nullptr) {
    Context->getCurFrame()->Msg.gas += RemainingGas;
  }
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
    Context->setStatus(EVMC_INVALID_INSTRUCTION);
    return;
  }

  intx::uint256 Value = Frame->pop();
  intx::uint256 CodeOffset = Frame->pop();
  intx::uint256 CodeSizeVal = Frame->pop();
  intx::uint256 Salt =
      (OpCode == evmc_opcode::OP_CREATE2 ? Frame->pop() : intx::uint256(0));

  // Assume failure
  EVM_REQUIRE_STACK_SPACE(Frame, 1);
  Frame->push(0);
  Context->setReturnData(std::vector<uint8_t>());

  if (Frame->isStaticMode()) {
    Context->setStatus(EVMC_STATIC_MODE_VIOLATION);
    return;
  }

  // First check memory expansion with uint256 values
  if (!checkMemoryExpandAndChargeGas(Frame, CodeOffset, CodeSizeVal)) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  const auto Rev = currentRevision();
  // EIP-3860
  if (Rev >= EVMC_SHANGHAI and CodeSizeVal > MAX_SIZE_OF_INITCODE) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }
  const auto InitCodeWordCost =
      6 * (OpCode == OP_CREATE2) + 2 * (Rev >= EVMC_SHANGHAI);
  const auto InitCodeSize =
      uint256ToUint64((CodeSizeVal + 31) / 32); // round up to the nearest word
  const auto InitCodeCost = InitCodeWordCost * InitCodeSize;
  if (!chargeGas(Frame, InitCodeCost)) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  if (Frame->Msg.depth >= MAXSTACK) {
    Context->setStatus(EVMC_SUCCESS); // "Light" failure
    return;
  }

  if (intx::be::load<intx::uint256>(
          Frame->Host->get_balance(Frame->Msg.recipient)) < Value) {
    Context->setStatus(EVMC_SUCCESS); // "Light" failure
    return;
  }

  uint64_t CodeSize = static_cast<uint64_t>(CodeSizeVal);
  uint64_t CodeOffset64 = CodeSize == 0 ? 0 : static_cast<uint64_t>(CodeOffset);

  evmc_message NewMsg{.kind =
                          (OpCode == OP_CREATE2 ? evmc_call_kind::EVMC_CREATE2
                                                : evmc_call_kind::EVMC_CREATE),
                      .flags = 0u,
                      .depth = Frame->Msg.depth + 1,
                      .gas = Frame->Msg.gas,
                      .recipient = {},
                      .sender = Frame->Msg.recipient,
                      .input_data = Frame->Memory.data() + CodeOffset64,
                      .input_size = CodeSize,
                      .value = intx::be::store<evmc::bytes32>(Value),
                      .create2_salt = intx::be::store<evmc::bytes32>(Salt),
                      .code_address = {},
                      .code = nullptr,
                      .code_size = 0};

  // EIP-150
  if (Rev >= EVMC_TANGERINE_WHISTLE) {
    NewMsg.gas = NewMsg.gas - NewMsg.gas / 64;
  }

  evmc::Result Result = Frame->Host->call(NewMsg);
  Context->setResource();
  const uint64_t CallGas =
      NewMsg.gas > 0 ? static_cast<uint64_t>(NewMsg.gas) : 0;
  uint64_t GasLeft =
      Result.gas_left > 0 ? static_cast<uint64_t>(Result.gas_left) : 0;
  if (CallGas > GasLeft) {
    chargeGas(Frame, CallGas - GasLeft); // it's safe to charge gas here
  }
  Context->getInstance()->addGasRefund(Result.gas_refund);

  if (Result.status_code == EVMC_REVERT) {
    Context->setReturnData(std::vector<uint8_t>(
        Result.output_data, Result.output_data + Result.output_size));
  } else {
    Context->setReturnData(std::vector<uint8_t>());
  }
  if (Result.status_code == EVMC_SUCCESS) {
    Frame->pop(); // pop the assume value
    Frame->push(intx::be::load<intx::uint256>(Result.create_address));
  }
  Context->setStatus(EVMC_SUCCESS);
}

void CallHandler::doExecute() {
  auto *Frame = getFrame();
  auto *Context = getContext();

  EVM_FRAME_CHECK(Frame);

  bool HasValueArgs = false;
  if (OpCode == evmc_opcode::OP_CALL or OpCode == evmc_opcode::OP_CALLCODE) {
    EVM_STACK_CHECK(Frame, 7);
    HasValueArgs = true;
  } else if (OpCode == evmc_opcode::OP_DELEGATECALL or
             OpCode == evmc_opcode::OP_STATICCALL) {
    EVM_STACK_CHECK(Frame, 6);
  } else {
    // in fact, this should never happen, but we still need to handle it
    Context->setStatus(EVMC_INVALID_INSTRUCTION);
    return;
  }

  const auto Gas = Frame->pop();
  auto Dest = intx::be::trunc<evmc::address>(Frame->pop());
  const auto Value = HasValueArgs ? Frame->pop() : 0;
  const auto InputOffset = Frame->pop();
  const auto InputSize = Frame->pop();
  const auto OutputOffset = Frame->pop();
  const auto OutputSize = Frame->pop();

  const bool HasValue = Value != 0;

  // Assume failure
  EVM_REQUIRE_STACK_SPACE(Frame, 1);
  Frame->push(0);
  Context->setReturnData(std::vector<uint8_t>());

  // EIP-2929
  // Note: The base gas cost (WARM_STORAGE_READ_COST = 100) is already charged
  // in execute(). We only need to charge the ADDITIONAL cost for cold access.
  const auto Rev = currentRevision();
  if (Rev >= EVMC_BERLIN &&
      Frame->Host->access_account(Dest) == EVMC_ACCESS_COLD) {
    // Charge additional cold access cost (2600 - 100 = 2500)
    if (!chargeGas(Frame, ADDITIONAL_COLD_ACCOUNT_ACCESS_COST)) {
      Context->setStatus(EVMC_OUT_OF_GAS);
      return;
    }
  }

  if (OpCode == evmc_opcode::OP_CALL && HasValue && Frame->isStaticMode()) {
    Context->setStatus(EVMC_STATIC_MODE_VIOLATION);
    return;
  }

  // Check memory expansion with uint256 values first
  if (!checkMemoryExpandAndChargeGas(Frame, InputOffset, InputSize)) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }
  if (!checkMemoryExpandAndChargeGas(Frame, OutputOffset, OutputSize)) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  // Map opcode to evmc_call_kind
  evmc_call_kind CallKind;
  switch (OpCode) {
  case OP_CALL:
    CallKind = EVMC_CALL;
    break;
  case OP_CALLCODE:
    CallKind = EVMC_CALLCODE;
    break;
  case OP_DELEGATECALL:
    CallKind = EVMC_DELEGATECALL;
    break;
  case OP_STATICCALL:
    CallKind = EVMC_CALL; // STATICCALL uses EVMC_CALL with EVMC_STATIC flag
    break;
  default:
    throw common::getError(common::ErrorCode::EVMInvalidInstruction);
  }

  if (HasValueArgs) {
    uint64_t GasCost = HasValue ? CALL_VALUE_COST : 0;
    if (CallKind == EVMC_CALL) {
      if (HasValue || Rev < EVMC_SPURIOUS_DRAGON) {
        if (!Frame->Host->account_exists(Dest)) {
          GasCost += ACCOUNT_CREATION_COST;
        }
      }
    }
    if (!chargeGas(Frame, GasCost)) {
      Context->setStatus(EVMC_OUT_OF_GAS);
      return;
    }
  }

  uint64_t CallGas = static_cast<uint64_t>(Gas);
  uint64_t GasLeft = (uint64_t)Frame->Msg.gas;
  if (Rev >= EVMC_TANGERINE_WHISTLE) {
    const uint64_t GasCap = GasLeft - GasLeft / 64;
    CallGas = std::min(CallGas, GasCap);
  } else if (CallGas > GasLeft) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  if (HasValueArgs) {
    if (HasValue) {
      Frame->Msg.gas += CALL_GAS_STIPEND;
      CallGas += CALL_GAS_STIPEND;
      const auto CallerBalance = intx::be::load<intx::uint256>(
          Frame->Host->get_balance(Frame->Msg.recipient));
      bool HasEnoughBalance = CallerBalance >= Value;

      if (!HasEnoughBalance) {
        Context->setStatus(EVMC_SUCCESS);
        return;
      }
    }
  }

  if (Frame->Msg.depth >= MAXSTACK) {
    Context->setStatus(EVMC_SUCCESS); // "Light" failure
    return;
  }

  // Only convert to uint64 after successful memory checks
  uint64_t InputSize64 = static_cast<uint64_t>(InputSize);
  uint64_t InputOffset64 =
      InputSize64 == 0 ? 0 : static_cast<uint64_t>(InputOffset);
  uint64_t OutputSize64 = static_cast<uint64_t>(OutputSize);
  uint64_t OutputOffset64 =
      OutputSize64 == 0 ? 0 : static_cast<uint64_t>(OutputOffset);

  evmc_message NewMsg{
      .kind = CallKind,
      .flags = (OpCode == evmc_opcode::OP_STATICCALL) ? uint32_t{EVMC_STATIC}
                                                      : Frame->Msg.flags,
      .depth = Frame->Msg.depth + 1,
      .gas = static_cast<int64_t>(CallGas),
      .recipient = (OpCode == OP_CALL or OpCode == OP_STATICCALL)
                       ? Dest
                       : Frame->Msg.recipient,
      .sender = (OpCode == OP_DELEGATECALL) ? Frame->Msg.sender
                                            : Frame->Msg.recipient,
      .input_data = Frame->Memory.data() + InputOffset64,
      .input_size = InputSize64,
      .value = (OpCode == OP_DELEGATECALL)
                   ? Frame->Msg.value
                   : intx::be::store<evmc::bytes32>(Value),
      .create2_salt = {},
      .code_address = Dest,
      .code = nullptr,
      .code_size = 0,
  };

  const auto Result = Frame->Host->call(NewMsg);
  Context->setResource();
  if (Result.status_code == EVMC_SUCCESS) {
    Frame->pop(); // pop the assume value
    Frame->push(intx::uint256(1));
  }
  Context->setReturnData(std::vector<uint8_t>(
      Result.output_data, Result.output_data + Result.output_size));

  const auto CopySize =
      std::min(static_cast<size_t>(OutputSize64), Result.output_size);
  if (CopySize > 0) {
    std::memcpy(Frame->Memory.data() + OutputOffset64, Result.output_data,
                CopySize);
  }

  CallGas = NewMsg.gas > 0 ? static_cast<uint64_t>(NewMsg.gas) : 0;
  GasLeft = Result.gas_left > 0 ? static_cast<uint64_t>(Result.gas_left) : 0;
  if (Result.status_code != EVMC_SUCCESS && Result.status_code != EVMC_REVERT) {
    GasLeft = 0;
  }
  uint64_t GasUsed = CallGas > GasLeft ? CallGas - GasLeft : 0;
  if (GasUsed > 0 && !chargeGas(Frame, GasUsed)) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  // Track subcall refund at Instance level (may be negative)
  Context->getInstance()->addGasRefund(Result.gas_refund);
  Context->setStatus(EVMC_SUCCESS);
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

  // First check memory expansion with uint256 values
  if (!checkMemoryExpandAndChargeGas(Frame, OffsetVal, SizeVal)) {
    Context->setStatus(EVMC_OUT_OF_GAS);
    return;
  }

  // Only convert to uint64 after successful memory check
  uint64_t Size = static_cast<uint64_t>(SizeVal);
  uint64_t Offset = Size == 0 ? 0 : static_cast<uint64_t>(OffsetVal);

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

  Frame->Host->emit_log(Frame->Msg.recipient, Frame->Memory.data() + Offset,
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

  const auto Rev = currentRevision();
  // EIP-2929: charge cold account access cost if needed.
  if (Rev >= EVMC_BERLIN) {
    if (Frame->Host->access_account(Beneficiary) == EVMC_ACCESS_COLD &&
        !chargeGas(Frame, COLD_ACCOUNT_ACCESS_COST)) {
      Context->setStatus(EVMC_OUT_OF_GAS);
      return;
    }
  }

  // EIP-161: if target account does not exist AND self has balance to transfer,
  // charge account creation cost.
  if (Rev >= EVMC_TANGERINE_WHISTLE) {
    if (Rev == EVMC_TANGERINE_WHISTLE ||
        Frame->Host->get_balance(Frame->Msg.recipient)) {
      if (!Frame->Host->account_exists(Beneficiary) &&
          !chargeGas(Frame, ACCOUNT_CREATION_COST)) {
        Context->setStatus(EVMC_OUT_OF_GAS);
        return;
      }
    }
  }

  if (Frame->Host->selfdestruct(Frame->Msg.recipient, Beneficiary)) {
    if (Rev < EVMC_LONDON) {
      Context->getInstance()->addGasRefund(EXTRA_REFUND_BEFORE_LONDON);
    }
  }

  Context->setStatus(EVMC_SUCCESS);
  // Return remaining gas to parent frame before freeing current frame.
  uint64_t RemainingGas = Frame->Msg.gas;
  Context->freeBackFrame();
  if (Context->getCurFrame() != nullptr) {
    Context->getCurFrame()->Msg.gas += RemainingGas;
  }
}

/* ---------- Implement opcode handlers end ---------- */
