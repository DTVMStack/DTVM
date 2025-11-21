// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/evm_frontend/evm_imported.h"
#include "common/errors.h"
#include "host/evm/crypto.h"
#include "runtime/evm_instance.h"
#include "runtime/evm_module.h"
#include <cstdint>
#include <evmc/evmc.h>
#include <vector>

namespace COMPILER {

namespace {
thread_local intx::uint256 Uint256ReturnBuffer;

const intx::uint256 *storeUint256Result(const intx::uint256 &Value) {
  Uint256ReturnBuffer = Value;
  return &Uint256ReturnBuffer;
}
inline uint64_t calculateWordCopyGas(uint64_t Size) {
  if (Size == 0) {
    return 0;
  }
  constexpr uint64_t WordBytes = 32;
  uint64_t Words = (Size + (WordBytes - 1)) / WordBytes;
  return Words * static_cast<uint64_t>(zen::evm::WORD_COPY_COST);
}
} // namespace

const RuntimeFunctions &getRuntimeFunctionTable() {
  static const RuntimeFunctions Table = {
      .GetMul = &evmGetMul,
      .GetDiv = &evmGetDiv,
      .GetSDiv = &evmGetSDiv,
      .GetMod = &evmGetMod,
      .GetSMod = &evmGetSMod,
      .GetAddMod = &evmGetAddMod,
      .GetMulMod = &evmGetMulMod,
      .GetExp = &evmGetExp,
      .GetAddress = &evmGetAddress,
      .GetBalance = &evmGetBalance,
      .GetOrigin = &evmGetOrigin,
      .GetCaller = &evmGetCaller,
      .GetCallValue = &evmGetCallValue,
      .GetCallDataLoad = &evmGetCallDataLoad,
      .GetCallDataSize = &evmGetCallDataSize,
      .GetCodeSize = &evmGetCodeSize,
      .SetCodeCopy = &evmSetCodeCopy,
      .GetGasPrice = &evmGetGasPrice,
      .GetExtCodeSize = &evmGetExtCodeSize,
      .GetExtCodeHash = &evmGetExtCodeHash,
      .GetBlockHash = &evmGetBlockHash,
      .GetCoinBase = &evmGetCoinBase,
      .GetTimestamp = &evmGetTimestamp,
      .GetNumber = &evmGetNumber,
      .GetPrevRandao = &evmGetPrevRandao,
      .GetGasLimit = &evmGetGasLimit,
      .GetChainId = &evmGetChainId,
      .GetSelfBalance = &evmGetSelfBalance,
      .GetBaseFee = &evmGetBaseFee,
      .GetBlobHash = &evmGetBlobHash,
      .GetBlobBaseFee = &evmGetBlobBaseFee,
      .GetMSize = &evmGetMSize,
      .GetMLoad = &evmGetMLoad,
      .SetMStore = &evmSetMStore,
      .SetMStore8 = &evmSetMStore8,
      .GetSLoad = &evmGetSLoad,
      .SetSStore = &evmSetSStore,
      .GetGas = &evmGetGas,
      .GetTLoad = &evmGetTLoad,
      .SetTStore = &evmSetTStore,
      .SetMCopy = &evmSetMCopy,
      .SetCallDataCopy = &evmSetCallDataCopy,
      .SetExtCodeCopy = &evmSetExtCodeCopy,
      .SetReturnDataCopy = &evmSetReturnDataCopy,
      .GetReturnDataSize = &evmGetReturnDataSize,
      .EmitLog = &evmEmitLog,
      .HandleCreate = &evmHandleCreate,
      .HandleCreate2 = &evmHandleCreate2,
      .HandleCall = &evmHandleCall,
      .HandleCallCode = &evmHandleCallCode,
      .SetReturn = &evmSetReturn,
      .HandleDelegateCall = &evmHandleDelegateCall,
      .HandleStaticCall = &evmHandleStaticCall,
      .SetRevert = &evmSetRevert,
      .HandleInvalid = &evmHandleInvalid,
      .HandleSelfDestruct = &evmHandleSelfDestruct,
      .GetKeccak256 = &evmGetKeccak256};
  return Table;
}

const intx::uint256 *evmGetMul(zen::runtime::EVMInstance *Instance,
                               const intx::uint256 &Multiplicand,
                               const intx::uint256 &Multiplier) {
  // EVM: Multiplicand * Multiplier % (2^256)
  return storeUint256Result(Multiplicand * Multiplier);
}

const intx::uint256 *evmGetDiv(zen::runtime::EVMInstance *Instance,
                               const intx::uint256 &Dividend,
                               const intx::uint256 &Divisor) {
  if (Divisor == 0) {
    return storeUint256Result(intx::uint256{0});
  }
  return storeUint256Result(Dividend / Divisor);
}

const intx::uint256 *evmGetSDiv(zen::runtime::EVMInstance *Instance,
                                const intx::uint256 &Dividend,
                                const intx::uint256 &Divisor) {
  if (Divisor == 0) {
    return storeUint256Result(intx::uint256{0});
  }

  // Check if dividend is negative (MSB set)
  bool isDividendNegative = (Dividend >> 255) != 0;
  bool isDivisorNegative = (Divisor >> 255) != 0;

  // Convert to absolute values
  intx::uint256 absDividend = isDividendNegative ? (~Dividend + 1) : Dividend;
  intx::uint256 absDivisor = isDivisorNegative ? (~Divisor + 1) : Divisor;

  // Perform unsigned division
  intx::uint256 absResult = absDividend / absDivisor;

  // Apply sign: result is negative if signs differ
  bool isResultNegative = isDividendNegative != isDivisorNegative;

  return storeUint256Result(isResultNegative ? (~absResult + 1) : absResult);
}

const intx::uint256 *evmGetMod(zen::runtime::EVMInstance *Instance,
                               const intx::uint256 &Dividend,
                               const intx::uint256 &Divisor) {
  if (Divisor == 0) {
    return storeUint256Result(intx::uint256{0});
  }
  return storeUint256Result(Dividend % Divisor);
}

const intx::uint256 *evmGetSMod(zen::runtime::EVMInstance *Instance,
                                const intx::uint256 &Dividend,
                                const intx::uint256 &Divisor) {
  if (Divisor == 0) {
    return storeUint256Result(intx::uint256{0});
  }

  // Check if dividend is negative (MSB set)
  bool isDividendNegative = (Dividend >> 255) != 0;

  // Convert to absolute values
  intx::uint256 absDividend = isDividendNegative ? (~Dividend + 1) : Dividend;
  intx::uint256 absDivisor = Divisor; // Divisor sign doesn't affect modulo

  // Perform unsigned modulo
  intx::uint256 absResult = absDividend % absDivisor;

  // Apply sign: result has same sign as dividend
  return storeUint256Result(isDividendNegative ? (~absResult + 1) : absResult);
}

const intx::uint256 *evmGetAddMod(zen::runtime::EVMInstance *Instance,
                                  const intx::uint256 &Augend,
                                  const intx::uint256 &Addend,
                                  const intx::uint256 &Modulus) {
  // Handle edge case: modulo 0
  if (Modulus == 0) {
    return storeUint256Result(intx::uint256{0});
  }

  // (Augend + Addend) % Modulus
  // Use 512-bit intermediate to prevent overflow
  intx::uint512 Sum = intx::uint512(Augend) + intx::uint512(Addend);
  intx::uint256 Result = intx::uint256(Sum % Modulus);
  return storeUint256Result(Result);
}

const intx::uint256 *evmGetMulMod(zen::runtime::EVMInstance *Instance,
                                  const intx::uint256 &Multiplicand,
                                  const intx::uint256 &Multiplier,
                                  const intx::uint256 &Modulus) {
  // Handle edge case: modulo 0
  if (Modulus == 0) {
    return storeUint256Result(intx::uint256{0});
  }

  // (Multiplicand * Multiplier) % Modulus
  // Use 512-bit intermediate to prevent overflow
  intx::uint512 Product =
      intx::uint512(Multiplicand) * intx::uint512(Multiplier);
  intx::uint256 Result = intx::uint256(Product % Modulus);
  return storeUint256Result(Result);
}

const intx::uint256 *evmGetExp(zen::runtime::EVMInstance *Instance,
                               const intx::uint256 &Base,
                               const intx::uint256 &Exponent) {
  // Handle edge cases
  if (Exponent == 0) {
    return storeUint256Result(intx::uint256{1});
  }
  if (Base == 0) {
    return storeUint256Result(intx::uint256{0});
  }
  if (Exponent == 1) {
    return storeUint256Result(Base);
  }

  // EVM: (Base ^ Exponent) % (2^256)
  intx::uint256 Result = 1;
  intx::uint256 CurrentBase = Base;
  intx::uint256 ExponentCopy = Exponent;

  while (ExponentCopy > 0) {
    if (ExponentCopy & 1) {
      Result *= CurrentBase;
    }
    CurrentBase *= CurrentBase;
    ExponentCopy >>= 1;
  }

  return storeUint256Result(Result);
}

const uint8_t *evmGetAddress(zen::runtime::EVMInstance *Instance) {
  const evmc_message *Msg = Instance->getCurrentMessage();
  ZEN_ASSERT(Msg && "No current message set in EVMInstance");
  return Msg->recipient.bytes;
}

const intx::uint256 *evmGetBalance(zen::runtime::EVMInstance *Instance,
                                   const uint8_t *Address) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);

  evmc::address Addr;
  std::memcpy(Addr.bytes, Address, sizeof(Addr.bytes));

  evmc::bytes32 BalanceBytes = Module->Host->get_balance(Addr);
  intx::uint256 Balance = intx::be::load<intx::uint256>(BalanceBytes);
  return storeUint256Result(Balance);
}

const uint8_t *evmGetOrigin(zen::runtime::EVMInstance *Instance) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);

  auto &Cache = Instance->getMessageCache();
  if (!Cache.TxContextCached) {
    Cache.TxContext = Module->Host->get_tx_context();
    Cache.TxContextCached = true;
  }
  return Cache.TxContext.tx_origin.bytes;
}

const uint8_t *evmGetCaller(zen::runtime::EVMInstance *Instance) {
  const evmc_message *Msg = Instance->getCurrentMessage();
  ZEN_ASSERT(Msg && "No current message set in EVMInstance");
  return Msg->sender.bytes;
}

const uint8_t *evmGetCallValue(zen::runtime::EVMInstance *Instance) {
  const evmc_message *Msg = Instance->getCurrentMessage();
  ZEN_ASSERT(Msg && "No current message set in EVMInstance");
  return Msg->value.bytes;
}

const uint8_t *evmGetCallDataLoad(zen::runtime::EVMInstance *Instance,
                                  uint64_t Offset) {
  const evmc_message *Msg = Instance->getCurrentMessage();
  ZEN_ASSERT(Msg && "No current message set in EVMInstance");

  auto &Cache = Instance->getMessageCache();
  auto Key = std::make_pair(Msg, Offset);
  auto It = Cache.CalldataLoads.find(Key);
  if (It == Cache.CalldataLoads.end()) {
    evmc::bytes32 Result{};
    if (Offset < Msg->input_size) {
      size_t CopySize = std::min<size_t>(32, Msg->input_size - Offset);
      std::memcpy(Result.bytes, Msg->input_data + Offset, CopySize);
    }
    Cache.CalldataLoads[Key] = Result;
    return Cache.CalldataLoads[Key].bytes;
  }
  return It->second.bytes;
}

const intx::uint256 *evmGetGasPrice(zen::runtime::EVMInstance *Instance) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);
  evmc_tx_context TxContext = Module->Host->get_tx_context();
  return storeUint256Result(
      intx::be::load<intx::uint256>(TxContext.tx_gas_price));
}

uint64_t evmGetExtCodeSize(zen::runtime::EVMInstance *Instance,
                           const uint8_t *Address) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);

  evmc::address Addr;
  std::memcpy(Addr.bytes, Address, sizeof(Addr.bytes));

  uint64_t Size = Module->Host->get_code_size(Addr);
  return Size;
}

const uint8_t *evmGetExtCodeHash(zen::runtime::EVMInstance *Instance,
                                 const uint8_t *Address) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);

  evmc::address Addr;
  std::memcpy(Addr.bytes, Address, sizeof(Addr.bytes));

  auto &Cache = Instance->getMessageCache();
  evmc::bytes32 Hash = Module->Host->get_code_hash(Addr);
  Cache.ExtcodeHashes.push_back(Hash);

  return Cache.ExtcodeHashes.back().bytes;
}

uint64_t evmGetCallDataSize(zen::runtime::EVMInstance *Instance) {
  const evmc_message *Msg = Instance->getCurrentMessage();
  ZEN_ASSERT(Msg && "No current message set in EVMInstance");
  return Msg->input_size;
}

uint64_t evmGetCodeSize(zen::runtime::EVMInstance *Instance) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module);
  return Module->CodeSize;
}

const uint8_t *evmGetBlockHash(zen::runtime::EVMInstance *Instance,
                               int64_t BlockNumber) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);

  evmc_tx_context TxContext = Module->Host->get_tx_context();
  const auto UpperBound = TxContext.block_number;
  const auto LowerBound = std::max(UpperBound - 256, decltype(UpperBound){0});

  auto &Cache = Instance->getMessageCache();
  auto It = Cache.BlockHashes.find(BlockNumber);
  if (It == Cache.BlockHashes.end()) {
    evmc::bytes32 Hash = (BlockNumber < UpperBound && BlockNumber >= LowerBound)
                             ? Module->Host->get_block_hash(BlockNumber)
                             : evmc::bytes32{};
    Cache.BlockHashes[BlockNumber] = Hash;
    return Cache.BlockHashes[BlockNumber].bytes;
  }
  return It->second.bytes;
}

const uint8_t *evmGetCoinBase(zen::runtime::EVMInstance *Instance) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);

  auto &Cache = Instance->getMessageCache();
  if (!Cache.TxContextCached) {
    Cache.TxContext = Module->Host->get_tx_context();
    Cache.TxContextCached = true;
  }
  return Cache.TxContext.block_coinbase.bytes;
}

const intx::uint256 *evmGetTimestamp(zen::runtime::EVMInstance *Instance) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);
  evmc_tx_context TxContext = Module->Host->get_tx_context();
  return storeUint256Result(intx::uint256(TxContext.block_timestamp));
}

const intx::uint256 *evmGetNumber(zen::runtime::EVMInstance *Instance) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);
  evmc_tx_context TxContext = Module->Host->get_tx_context();
  return storeUint256Result(intx::uint256(TxContext.block_number));
}

const uint8_t *evmGetPrevRandao(zen::runtime::EVMInstance *Instance) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);

  auto &Cache = Instance->getMessageCache();
  if (!Cache.TxContextCached) {
    Cache.TxContext = Module->Host->get_tx_context();
    Cache.TxContextCached = true;
  }
  return Cache.TxContext.block_prev_randao.bytes;
}

const intx::uint256 *evmGetGasLimit(zen::runtime::EVMInstance *Instance) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);
  evmc_tx_context TxContext = Module->Host->get_tx_context();
  return storeUint256Result(intx::uint256(TxContext.block_gas_limit));
}

const uint8_t *evmGetChainId(zen::runtime::EVMInstance *Instance) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);

  auto &Cache = Instance->getMessageCache();
  if (!Cache.TxContextCached) {
    Cache.TxContext = Module->Host->get_tx_context();
    Cache.TxContextCached = true;
  }
  return Cache.TxContext.chain_id.bytes;
}

const intx::uint256 *evmGetSelfBalance(zen::runtime::EVMInstance *Instance) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);
  const evmc_message *Msg = Instance->getCurrentMessage();
  ZEN_ASSERT(Msg && "No current message set in EVMInstance");
  evmc::bytes32 Balance = Module->Host->get_balance(Msg->recipient);
  return storeUint256Result(intx::be::load<intx::uint256>(Balance));
}

const intx::uint256 *evmGetBaseFee(zen::runtime::EVMInstance *Instance) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);
  evmc_tx_context TxContext = Module->Host->get_tx_context();
  return storeUint256Result(
      intx::be::load<intx::uint256>(TxContext.block_base_fee));
}

const uint8_t *evmGetBlobHash(zen::runtime::EVMInstance *Instance,
                              uint64_t Index) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);
  evmc_tx_context TxContext = Module->Host->get_tx_context();

  auto &Cache = Instance->getMessageCache();
  auto It = Cache.BlobHashes.find(Index);
  if (It == Cache.BlobHashes.end()) {
    evmc::bytes32 Hash;
    if (Index >= TxContext.blob_hashes_count) {
      Hash = evmc::bytes32{};
    } else {
      // TODO: havn't implemented in evmc
      // Hash = Module->Host->get_blob_hash(Index);
    }
    Cache.BlobHashes[Index] = Hash;
    return Cache.BlobHashes[Index].bytes;
  }
  return It->second.bytes;
}

const intx::uint256 *evmGetBlobBaseFee(zen::runtime::EVMInstance *Instance) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);
  evmc_tx_context TxContext = Module->Host->get_tx_context();
  return storeUint256Result(
      intx::be::load<intx::uint256>(TxContext.blob_base_fee));
}

uint64_t evmGetMSize(zen::runtime::EVMInstance *Instance) {
  return Instance->getMemorySize();
}
const intx::uint256 *evmGetMLoad(zen::runtime::EVMInstance *Instance,
                                 uint64_t Offset) {
  uint64_t RequiredSize = Offset + 32;
  Instance->expandMemory(RequiredSize);
  auto &Memory = Instance->getMemory();

  uint8_t ValueBytes[32];
  std::memcpy(ValueBytes, Memory.data() + Offset, 32);

  intx::uint256 Result = intx::be::load<intx::uint256>(ValueBytes);
  return storeUint256Result(Result);
}
void evmSetMStore(zen::runtime::EVMInstance *Instance, uint64_t Offset,
                  const intx::uint256 &Value) {
  uint64_t RequiredSize = Offset + 32;
  Instance->expandMemory(RequiredSize);

  auto &Memory = Instance->getMemory();
  uint8_t ValueBytes[32];
  intx::be::store(ValueBytes, Value);
  std::memcpy(Memory.data() + Offset, ValueBytes, sizeof(ValueBytes));
}

void evmSetMStore8(zen::runtime::EVMInstance *Instance, uint64_t Offset,
                   const intx::uint256 &Value) {
  uint64_t RequiredSize = Offset + 1;

  Instance->expandMemory(RequiredSize);

  auto &Memory = Instance->getMemory();
  uint8_t ByteValue = static_cast<uint8_t>(Value & intx::uint256{0xFF});
  Memory[Offset] = ByteValue;
}

void evmSetMCopy(zen::runtime::EVMInstance *Instance, uint64_t Dest,
                 uint64_t Src, uint64_t Len) {
  if (Len == 0) {
    return;
  }
  if (uint64_t CopyGas = calculateWordCopyGas(Len)) {
    Instance->chargeGas(CopyGas);
  }
  uint64_t RequiredSize = std::max(Dest + Len, Src + Len);

  Instance->expandMemory(RequiredSize);

  auto &Memory = Instance->getMemory();
  std::memmove(&Memory[Dest], &Memory[Src], Len);
}
void evmSetReturn(zen::runtime::EVMInstance *Instance, uint64_t Offset,
                  uint64_t Len) {
  Instance->expandMemory(Offset + Len);
  auto &Memory = Instance->getMemory();
  std::vector<uint8_t> ReturnData(Memory.begin() + Offset,
                                  Memory.begin() + Offset + Len);
  Instance->setReturnData(ReturnData);

  evmc::Result ExeResult(EVMC_SUCCESS, 0,
                         Instance ? Instance->getGasRefund() : 0,
                         ReturnData.data(), ReturnData.size());
  Instance->setExeResult(std::move(ExeResult));
  // Immediately terminate the execution and return the success code (0)
  Instance->exit(0);
}
void evmSetCallDataCopy(zen::runtime::EVMInstance *Instance,
                        uint64_t DestOffset, uint64_t Offset, uint64_t Size) {
  uint64_t RequiredSize = DestOffset + Size;
  Instance->expandMemory(RequiredSize);
  if (uint64_t CopyGas = calculateWordCopyGas(Size)) {
    Instance->chargeGas(CopyGas);
  }

  const evmc_message *Msg = Instance->getCurrentMessage();
  ZEN_ASSERT(Msg && "No current message set in EVMInstance");

  auto &Memory = Instance->getMemory();

  // Calculate actual source offset and copy size
  uint64_t ActualOffset =
      std::min(Offset, static_cast<uint64_t>(Msg->input_size));
  uint64_t CopySize =
      (ActualOffset < Msg->input_size)
          ? std::min<uint64_t>(Size, static_cast<uint64_t>(Msg->input_size) -
                                         ActualOffset)
          : 0;

  if (CopySize > 0) {
    std::memcpy(Memory.data() + DestOffset, Msg->input_data + ActualOffset,
                CopySize);
  }

  // Fill remaining bytes with zeros if needed
  if (Size > CopySize) {
    std::memset(Memory.data() + DestOffset + CopySize, 0, Size - CopySize);
  }
}

void evmSetExtCodeCopy(zen::runtime::EVMInstance *Instance,
                       const uint8_t *Address, uint64_t DestOffset,
                       uint64_t Offset, uint64_t Size) {
  uint64_t RequiredSize = DestOffset + Size;
  Instance->expandMemory(RequiredSize);
  if (uint64_t CopyGas = calculateWordCopyGas(Size)) {
    Instance->chargeGas(CopyGas);
  }

  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);
  evmc::address Addr;
  std::memcpy(Addr.bytes, Address, sizeof(Addr.bytes));

  auto &Memory = Instance->getMemory();
  size_t CodeSize = Module->Host->get_code_size(Addr);

  if (Offset >= CodeSize) {
    // If offset is beyond code size, fill with zeros
    std::memset(Memory.data() + DestOffset, 0, Size);
  } else {
    uint64_t CopySize =
        std::min<uint64_t>(Size, static_cast<uint64_t>(CodeSize) - Offset);
    size_t CopiedSize = Module->Host->copy_code(
        Addr, Offset, Memory.data() + DestOffset, CopySize);

    // Fill remaining bytes with zeros if needed
    if (Size > CopiedSize) {
      std::memset(Memory.data() + DestOffset + CopiedSize, 0,
                  Size - CopiedSize);
    }
  }
}

void evmSetReturnDataCopy(zen::runtime::EVMInstance *Instance,
                          uint64_t DestOffset, uint64_t Offset, uint64_t Size) {
  uint64_t RequiredSize = DestOffset + Size;
  Instance->expandMemory(RequiredSize);
  if (uint64_t CopyGas = calculateWordCopyGas(Size)) {
    Instance->chargeGas(CopyGas);
  }

  const auto &ReturnData = Instance->getReturnData();
  auto &Memory = Instance->getMemory();

  if (Offset >= ReturnData.size()) {
    std::memset(Memory.data() + DestOffset, 0, Size);
  } else {
    uint64_t CopySize = std::min<uint64_t>(
        Size, static_cast<uint64_t>(ReturnData.size()) - Offset);
    std::memcpy(Memory.data() + DestOffset, ReturnData.data() + Offset,
                CopySize);

    // Fill remaining bytes with zeros
    if (Size > CopySize) {
      std::memset(Memory.data() + DestOffset + CopySize, 0, Size - CopySize);
    }
  }
}

uint64_t evmGetReturnDataSize(zen::runtime::EVMInstance *Instance) {
  const auto &ReturnData = Instance->getReturnData();
  return ReturnData.size();
}

void evmEmitLog(zen::runtime::EVMInstance *Instance, uint64_t Offset,
                uint64_t Size, const uint8_t *Topic1, const uint8_t *Topic2,
                const uint8_t *Topic3, const uint8_t *Topic4) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);

  const evmc_message *Msg = Instance->getCurrentMessage();
  ZEN_ASSERT(Msg && "No current message set in EVMInstance");

  // Calculate required memory size and charge gas
  uint64_t RequiredSize = Offset + Size;
  Instance->expandMemory(RequiredSize);

  auto &Memory = Instance->getMemory();
  const uint8_t *Data = Memory.data() + Offset;

  // Build topic array - only include non-null topics
  evmc::bytes32 Topics[4] = {};
  size_t NumTopics = 0;

  if (Topic1) {
    std::memcpy(Topics[NumTopics].bytes, Topic1, 32);
    NumTopics++;
  }
  if (Topic2) {
    std::memcpy(Topics[NumTopics].bytes, Topic2, 32);
    NumTopics++;
  }
  if (Topic3) {
    std::memcpy(Topics[NumTopics].bytes, Topic3, 32);
    NumTopics++;
  }
  if (Topic4) {
    std::memcpy(Topics[NumTopics].bytes, Topic4, 32);
    NumTopics++;
  }

  Module->Host->emit_log(Msg->recipient, Data, Size, Topics, NumTopics);
}

const uint8_t *evmHandleCreateInternal(zen::runtime::EVMInstance *Instance,
                                       evmc_call_kind CallKind,
                                       intx::uint128 Value, uint64_t Offset,
                                       uint64_t Size,
                                       const uint8_t *Salt = nullptr) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);

  const evmc_message *Msg = Instance->getCurrentMessage();
  ZEN_ASSERT(Msg && "No current message set in EVMInstance");

  // Calculate required memory size and charge gas
  uint64_t RequiredSize = Offset + Size;
  Instance->expandMemory(RequiredSize);

  auto &Memory = Instance->getMemory();
  const uint8_t *InitCode = Memory.data() + Offset;

  // Create message for CREATE/CREATE2
  evmc_message CreateMsg = {};
  CreateMsg.kind = CallKind;
  CreateMsg.flags = Msg->flags;
  CreateMsg.depth = Msg->depth + 1;
  CreateMsg.gas = Msg->gas;
  CreateMsg.sender = Msg->recipient;
  std::memcpy(CreateMsg.value.bytes, &Value, 32);
  CreateMsg.input_data = InitCode;
  CreateMsg.input_size = Size;

  // Set salt for CREATE2
  if (CallKind == EVMC_CREATE2 && Salt != nullptr) {
    std::memcpy(CreateMsg.create2_salt.bytes, Salt, 32);
  }

  Instance->pushMessage(&CreateMsg);
  evmc::Result Result = Module->Host->call(CreateMsg);
  Instance->popMessage();

  // Store return data
  std::vector<uint8_t> ReturnData(Result.output_data,
                                  Result.output_data + Result.output_size);
  Instance->setReturnData(std::move(ReturnData));
  if (Result.status_code == EVMC_SUCCESS) {
    // Return created contract address
    static evmc::address CreatedAddr = Result.create_address;
    return CreatedAddr.bytes;
  } else {
    // Return zero address on failure
    static evmc::address ZeroAddr = {};
    return ZeroAddr.bytes;
  }
}

const uint8_t *evmHandleCreate(zen::runtime::EVMInstance *Instance,
                               intx::uint128 Value, uint64_t Offset,
                               uint64_t Size) {
  return evmHandleCreateInternal(Instance, EVMC_CREATE, Value, Offset, Size);
}

const uint8_t *evmHandleCreate2(zen::runtime::EVMInstance *Instance,
                                intx::uint128 Value, uint64_t Offset,
                                uint64_t Size, const uint8_t *Salt) {
  return evmHandleCreateInternal(Instance, EVMC_CREATE2, Value, Offset, Size,
                                 Salt);
}

// Helper function for all call types
static uint64_t evmHandleCallInternal(zen::runtime::EVMInstance *Instance,
                                      evmc_call_kind CallKind, uint64_t Gas,
                                      const uint8_t *ToAddr,
                                      intx::uint128 Value, uint64_t ArgsOffset,
                                      uint64_t ArgsSize, uint64_t RetOffset,
                                      uint64_t RetSize, bool ForceStatic) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);

  const evmc_message *CurrentMsg = Instance->getCurrentMessage();
  ZEN_ASSERT(CurrentMsg && "No current message set in EVMInstance");
  evmc::address TargetAddr{};
  if (ToAddr) {
    constexpr size_t AddrSize = sizeof(TargetAddr.bytes);
    for (size_t I = 0; I < AddrSize; ++I) {
      // Copy the low 20 bytes and reverse to produce the big-endian address.
      TargetAddr.bytes[I] = ToAddr[AddrSize - 1 - I];
    }
  }
  evmc_revision Rev = Instance->getRevision();
  if (Rev >= EVMC_BERLIN &&
      Module->Host->access_account(TargetAddr) == EVMC_ACCESS_COLD) {
    Instance->chargeGas(zen::evm::ADDITIONAL_COLD_ACCOUNT_ACCESS_COST);
  }

  const bool TransfersValue =
      (CallKind == EVMC_CALL || CallKind == EVMC_CALLCODE) && Value != 0;
  if (TransfersValue && Instance->isStaticMode()) {
    throw zen::common::getError(zen::common::ErrorCode::EVMStaticModeViolation);
  }

  bool HasEnoughBalance = true;
  if (TransfersValue) {
    const auto CallerBalance = Module->Host->get_balance(CurrentMsg->recipient);
    const intx::uint256 CallerValue =
        intx::be::load<intx::uint256>(CallerBalance);
    HasEnoughBalance = CallerValue >= intx::uint256(Value);
    uint64_t ValueCost = zen::evm::CALL_VALUE_COST;
    if (!HasEnoughBalance) {
      ValueCost -= zen::evm::CALL_GAS_STIPEND;
    }
    Instance->chargeGas(ValueCost);
    if (CallKind == EVMC_CALL && HasEnoughBalance &&
        !Module->Host->account_exists(TargetAddr)) {
      Instance->chargeGas(zen::evm::ACCOUNT_CREATION_COST);
    }
  }

  if (TransfersValue && !HasEnoughBalance) {
    Instance->setReturnData({});
    return 0;
  }

  // Calculate required memory sizes for input and output
  uint64_t InputRequiredSize = ArgsOffset + ArgsSize;
  uint64_t OutputRequiredSize = RetOffset + RetSize;
  uint64_t MaxRequiredSize = std::max(InputRequiredSize, OutputRequiredSize);

  // Expand memory and charge gas
  Instance->expandMemory(MaxRequiredSize);

  auto &Memory = Instance->getMemory();
  const uint8_t *InputData =
      (ArgsSize > 0) ? Memory.data() + ArgsOffset : nullptr;

  // Create message for call
  evmc_message CallMsg{
      .kind = CallKind,
      .flags = (CallKind == EVMC_CALL && ForceStatic) ? uint32_t{EVMC_STATIC}
                                                      : CurrentMsg->flags,
      .depth = CurrentMsg->depth + 1,
      .gas = static_cast<int64_t>(Gas),
      .recipient = (CallKind == EVMC_CALL || ForceStatic)
                       ? TargetAddr
                       : CurrentMsg->recipient,
      .sender = (CallKind == EVMC_DELEGATECALL) ? CurrentMsg->sender
                                                : CurrentMsg->recipient,
      .input_data = Memory.data() + ArgsOffset,
      .input_size = ArgsSize,
      .value = (CallKind == EVMC_DELEGATECALL)
                   ? CurrentMsg->value
                   : intx::be::store<evmc::bytes32>(intx::uint256{Value}),
      .create2_salt = {},
      .code_address = TargetAddr,
      .code = nullptr,
      .code_size = 0,
  };

  Instance->pushMessage(&CallMsg);
  evmc::Result Result = Module->Host->call(CallMsg);
  Instance->popMessage();

  // Charge the caller for the gas actually consumed by the callee.
  uint64_t CallGas = Gas;
  uint64_t GasLeft =
      Result.gas_left > 0 ? static_cast<uint64_t>(Result.gas_left) : 0;
  uint64_t GasUsed = CallGas > GasLeft ? CallGas - GasLeft : 0;
  if (GasUsed >= zen::evm::BASIC_EXECUTION_COST) {
    GasUsed -= zen::evm::BASIC_EXECUTION_COST;
  } else {
    GasUsed = 0;
  }
  if (GasUsed > 0) {
    Instance->chargeGas(GasUsed);
  }
  if (Result.gas_refund > 0) {
    Instance->addGasRefund(Result.gas_refund);
  }

  // Copy return data to memory if output area is specified
  if (RetSize > 0 && Result.output_size > 0) {
    size_t CopySize =
        std::min(static_cast<size_t>(RetSize), Result.output_size);
    std::memcpy(Memory.data() + RetOffset, Result.output_data, CopySize);

    // Zero out remaining output area if needed
    if (RetSize > CopySize) {
      std::memset(Memory.data() + RetOffset + CopySize, 0, RetSize - CopySize);
    }
  }

  // Store full return data for RETURNDATASIZE/RETURNDATACOPY
  std::vector<uint8_t> ReturnData(Result.output_data,
                                  Result.output_data + Result.output_size);
  Instance->setReturnData(std::move(ReturnData));

  // Determine success (1) or failure (0)
  uint64_t Success = (Result.status_code == EVMC_SUCCESS) ? 1 : 0;

  return Success;
}

uint64_t evmHandleCall(zen::runtime::EVMInstance *Instance, uint64_t Gas,
                       const uint8_t *ToAddr, intx::uint128 Value,
                       uint64_t ArgsOffset, uint64_t ArgsSize,
                       uint64_t RetOffset, uint64_t RetSize) {
  return evmHandleCallInternal(Instance, EVMC_CALL, Gas, ToAddr, Value,
                               ArgsOffset, ArgsSize, RetOffset, RetSize, false);
}

uint64_t evmHandleCallCode(zen::runtime::EVMInstance *Instance, uint64_t Gas,
                           const uint8_t *ToAddr, intx::uint128 Value,
                           uint64_t ArgsOffset, uint64_t ArgsSize,
                           uint64_t RetOffset, uint64_t RetSize) {
  return evmHandleCallInternal(Instance, EVMC_CALLCODE, Gas, ToAddr, Value,
                               ArgsOffset, ArgsSize, RetOffset, RetSize, false);
}

void evmHandleInvalid(zen::runtime::EVMInstance *Instance) {
  // Immediately terminate the execution and return the revert code (2)
  evmc::Result ExeResult(
      EVMC_INVALID_INSTRUCTION, 0, Instance ? Instance->getGasRefund() : 0,
      Instance->getReturnData().data(), Instance->getReturnData().size());
  Instance->setExeResult(std::move(ExeResult));
  Instance->exit(4);
}

uint64_t evmHandleDelegateCall(zen::runtime::EVMInstance *Instance,
                               uint64_t Gas, const uint8_t *ToAddr,
                               uint64_t ArgsOffset, uint64_t ArgsSize,
                               uint64_t RetOffset, uint64_t RetSize) {
  return evmHandleCallInternal(Instance, EVMC_DELEGATECALL, Gas, ToAddr,
                               intx::uint128{0}, ArgsOffset, ArgsSize,
                               RetOffset, RetSize, false);
}

uint64_t evmHandleStaticCall(zen::runtime::EVMInstance *Instance, uint64_t Gas,
                             const uint8_t *ToAddr, uint64_t ArgsOffset,
                             uint64_t ArgsSize, uint64_t RetOffset,
                             uint64_t RetSize) {
  return evmHandleCallInternal(Instance, EVMC_CALL, Gas, ToAddr,
                               intx::uint128{0}, ArgsOffset, ArgsSize,
                               RetOffset, RetSize, true);
}

void evmSetRevert(zen::runtime::EVMInstance *Instance, uint64_t Offset,
                  uint64_t Size) {
  auto &Memory = Instance->getMemory();
  std::vector<uint8_t> ReturnData(Memory.begin() + Offset,
                                  Memory.begin() + Offset + Size);
  Instance->setReturnData(std::move(ReturnData));
  // Immediately terminate the execution and return the revert code (2)
  evmc::Result ExeResult(
      EVMC_REVERT, 0, Instance ? Instance->getGasRefund() : 0,
      Instance->getReturnData().data(), Instance->getReturnData().size());
  Instance->setExeResult(std::move(ExeResult));
  Instance->exit(2);
}

void evmSetCodeCopy(zen::runtime::EVMInstance *Instance, uint64_t DestOffset,
                    uint64_t Offset, uint64_t Size) {
  uint64_t RequiredSize = DestOffset + Size;
  Instance->expandMemory(RequiredSize);
  if (uint64_t CopyGas = calculateWordCopyGas(Size)) {
    Instance->chargeGas(CopyGas);
  }

  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module);
  const zen::common::Byte *Code = Module->Code;
  size_t CodeSize = Module->CodeSize;

  auto &Memory = Instance->getMemory();

  if (Offset < CodeSize) {
    auto CopySize = std::min(Size, CodeSize - Offset);
    std::memcpy(Memory.data() + DestOffset, Code + Offset, CopySize);
    if (Size > CopySize) {
      std::memset(Memory.data() + DestOffset + CopySize, 0, Size - CopySize);
    }
  } else {
    if (Size > 0) {
      std::memset(Memory.data() + DestOffset, 0, Size);
    }
  }
}

const uint8_t *evmGetKeccak256(zen::runtime::EVMInstance *Instance,
                               uint64_t Offset, uint64_t Length) {
  uint64_t RequiredSize = Offset + Length;
  Instance->expandMemory(RequiredSize);

  auto &Memory = Instance->getMemory();
  const uint8_t *InputData = Memory.data() + Offset;

  auto &Cache = Instance->getMessageCache();
  evmc::bytes32 HashResult;
  zen::host::evm::crypto::keccak256(InputData, Length, HashResult.bytes);
  Cache.Keccak256Results.push_back(HashResult);

  return Cache.Keccak256Results.back().bytes;
}
const intx::uint256 *evmGetSLoad(zen::runtime::EVMInstance *Instance,
                                 const intx::uint256 &Index) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);
  const evmc_message *Msg = Instance->getCurrentMessage();
  evmc_revision Rev = Instance->getRevision();

  const auto Key = intx::be::store<evmc::bytes32>(Index);
  if (Rev >= EVMC_BERLIN &&
      Module->Host->access_storage(Msg->recipient, Key) == EVMC_ACCESS_COLD) {
    Instance->chargeGas(zen::evm::ADDITIONAL_COLD_ACCOUNT_ACCESS_COST);
  }
  const auto Value = Module->Host->get_storage(Msg->recipient, Key);
  return storeUint256Result(intx::be::load<intx::uint256>(Value));
}
void evmSetSStore(zen::runtime::EVMInstance *Instance,
                  const intx::uint256 &Index, const intx::uint256 &Value) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);
  if (Instance->isStaticMode()) {
    throw zen::common::getError(zen::common::ErrorCode::EVMStaticModeViolation);
  }
  const evmc_message *Msg = Instance->getCurrentMessage();
  evmc_revision Rev = Instance->getRevision();
  const auto Key = intx::be::store<evmc::bytes32>(Index);
  const auto Val = intx::be::store<evmc::bytes32>(Value);

  const auto GasCostCold =
      (Rev >= EVMC_BERLIN &&
       Module->Host->access_storage(Msg->recipient, Key) == EVMC_ACCESS_COLD)
          ? zen::evm::COLD_SLOAD_COST
          : 0;
  const auto Status = Module->Host->set_storage(Msg->recipient, Key, Val);

  const auto [GasCostWarm, GasReFund] = zen::evm::SSTORE_COSTS[Rev][Status];

  const auto GasCost = GasCostCold + GasCostWarm;
  Instance->chargeGas(GasCost);
  Instance->addGasRefund(GasReFund);
}

uint64_t evmGetGas(zen::runtime::EVMInstance *Instance) {
  return Instance->getGas();
}

const intx::uint256 *evmGetTLoad(zen::runtime::EVMInstance *Instance,
                                 const intx::uint256 &Index) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);
  const evmc_message *Msg = Instance->getCurrentMessage();
  const auto Key = intx::be::store<evmc::bytes32>(Index);
  const auto Value = Module->Host->get_transient_storage(Msg->recipient, Key);
  return storeUint256Result(intx::be::load<intx::uint256>(Value));
}
void evmSetTStore(zen::runtime::EVMInstance *Instance,
                  const intx::uint256 &Index, const intx::uint256 &Value) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);
  if (Instance->isStaticMode()) {
    throw zen::common::getError(zen::common::ErrorCode::EVMStaticModeViolation);
  }
  const evmc_message *Msg = Instance->getCurrentMessage();
  const auto Key = intx::be::store<evmc::bytes32>(Index);
  const auto Val = intx::be::store<evmc::bytes32>(Value);
  Module->Host->set_transient_storage(Msg->recipient, Key, Val);
}
void evmHandleSelfDestruct(zen::runtime::EVMInstance *Instance,
                           const uint8_t *Beneficiary) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);
  if (Instance->isStaticMode()) {
    throw zen::common::getError(zen::common::ErrorCode::EVMStaticModeViolation);
  }
  const evmc_message *Msg = Instance->getCurrentMessage();
  evmc_revision Rev = Instance->getRevision();

  evmc::address BenefAddr;
  std::memcpy(BenefAddr.bytes, Beneficiary, sizeof(BenefAddr.bytes));

  // EIP-161: if target account does not exist, charge account creation cost
  if (Rev >= EVMC_SPURIOUS_DRAGON && !Module->Host->account_exists(BenefAddr)) {
    Instance->chargeGas(zen::evm::ACCOUNT_CREATION_COST);
  }

  // EIP-2929: Charge cold account access cost if needed
  if (Rev >= EVMC_BERLIN &&
      Module->Host->access_account(BenefAddr) == EVMC_ACCESS_COLD) {
    Instance->chargeGas(zen::evm::ADDITIONAL_COLD_ACCOUNT_ACCESS_COST);
  }

  Module->Host->selfdestruct(Msg->recipient, BenefAddr);
  uint64_t RemainingGas = Msg->gas;
  Instance->popMessage();

  if (const evmc_message *Parent = Instance->getCurrentMessage()) {
    const_cast<evmc_message *>(Parent)->gas += RemainingGas;
  } else {
    evmc::Result ExeResult(
        EVMC_SUCCESS, 0, Instance ? Instance->getGasRefund() : 0,
        Instance->getReturnData().data(), Instance->getReturnData().size());
    Instance->setExeResult(std::move(ExeResult));
    Instance->exit(0);
  }
}

} // namespace COMPILER
