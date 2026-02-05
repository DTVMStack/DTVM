// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/evm_frontend/evm_imported.h"
#include "common/errors.h"
#include "evm/gas_storage_cost.h"
#include "host/evm/crypto.h"
#include "runtime/evm_instance.h"
#include "runtime/evm_module.h"
#include <cstdint>
#include <cstring>
#include <evmc/evmc.h>
#include <vector>

namespace COMPILER {

namespace {
thread_local intx::uint256 Uint256ReturnBuffer;

const intx::uint256 *storeUint256Result(const intx::uint256 &Value) {
  Uint256ReturnBuffer = Value;
  return &Uint256ReturnBuffer;
}

evmc::address loadAddressFromLE(const uint8_t *AddressLE) {
  evmc::address Addr{};
  constexpr size_t AddrSize = sizeof(Addr.bytes);
  for (size_t I = 0; I < AddrSize; ++I) {
    Addr.bytes[I] = AddressLE[AddrSize - 1 - I];
  }
  return Addr;
}
evmc::bytes32 loadBytes32FromLE(const uint8_t *BytesLE) {
  evmc::bytes32 Out{};
  constexpr size_t Size = sizeof(Out.bytes);
  for (size_t I = 0; I < Size; ++I) {
    Out.bytes[I] = BytesLE[Size - 1 - I];
  }
  return Out;
}
constexpr int64_t numWords(uint64_t Size) noexcept {
  /// The size of the EVM 256-bit word.
  constexpr auto WORD_SIZE = 32;
  return static_cast<int64_t>((Size + (WORD_SIZE - 1)) / WORD_SIZE);
}
inline uint64_t calculateWordCopyGas(uint64_t Size) {
  if (Size == 0) {
    return 0;
  }
  uint64_t Words = numWords(Size);
  return Words * static_cast<uint64_t>(zen::evm::WORD_COPY_COST);
}

inline void triggerStaticModeViolation(zen::runtime::EVMInstance *Instance) {
  Instance->setGas(0);
  zen::runtime::EVMInstance::triggerInstanceExceptionOnJIT(
      Instance, zen::common::ErrorCode::EVMStaticModeViolation);
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
      .GetSLoad = &evmGetSLoad,
      .SetSStore = &evmSetSStore,
      .GetGas = &evmGetGas,
      .GetTLoad = &evmGetTLoad,
      .SetTStore = &evmSetTStore,
      .SetCallDataCopy = &evmSetCallDataCopy,
      .SetExtCodeCopy = &evmSetExtCodeCopy,
      .SetReturnDataCopy = &evmSetReturnDataCopy,
      .ExpandMemoryNoGas = &evmExpandMemoryNoGas,
      .GetReturnDataSize = &evmGetReturnDataSize,
      .EmitLog0 = &evmEmitLog0,
      .EmitLog1 = &evmEmitLog1,
      .EmitLog2 = &evmEmitLog2,
      .EmitLog3 = &evmEmitLog3,
      .EmitLog4 = &evmEmitLog4,
      .HandleCreate = &evmHandleCreate,
      .HandleCreate2 = &evmHandleCreate2,
      .HandleCall = &evmHandleCall,
      .HandleCallCode = &evmHandleCallCode,
      .SetReturn = &evmSetReturn,
      .HandleDelegateCall = &evmHandleDelegateCall,
      .HandleStaticCall = &evmHandleStaticCall,
      .SetRevert = &evmSetRevert,
      .HandleInvalid = &evmHandleInvalid,
      .HandleUndefined = &evmHandleUndefined,
      .HandleSelfDestruct = &evmHandleSelfDestruct,
      .GetKeccak256 = &evmGetKeccak256,
      .GetClz = &evmGetClz};
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

  intx::uint256 Result = intx::sdivrem(Dividend, Divisor).rem;
  return storeUint256Result(Result);
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
  // EIP-160: 50 gas per byte of exponent (pre-Spurious Dragon is cheaper).
  const uint64_t ExponentByteSize = intx::count_significant_bytes(Exponent);
  const auto Rev = Instance->getRevision();
  const uint64_t GasPerByte = Rev < EVMC_SPURIOUS_DRAGON
                                  ? zen::evm::EXP_BYTE_GAS_PRE_SPURIOUS_DRAGON
                                  : zen::evm::EXP_BYTE_GAS;
  Instance->chargeGas(ExponentByteSize * GasPerByte);

  // EVM: (Base ^ Exponent) % (2^256)
  return storeUint256Result(intx::exp(Base, Exponent));
}

const uint8_t *evmGetAddress(zen::runtime::EVMInstance *Instance) {
  const evmc_message *Msg = Instance->getCurrentMessage();
  ZEN_ASSERT(Msg && "No current message set in EVMInstance");

  static thread_local uint8_t PaddedAddress[32] = {0};
  memcpy(PaddedAddress + 12, Msg->recipient.bytes, 20);
  return PaddedAddress;
}

const intx::uint256 *evmGetBalance(zen::runtime::EVMInstance *Instance,
                                   const uint8_t *Address) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);

  evmc::address Addr = loadAddressFromLE(Address);

  evmc_revision Rev = Instance->getRevision();
  if (Rev >= EVMC_BERLIN &&
      Module->Host->access_account(Addr) == EVMC_ACCESS_COLD) {
    Instance->chargeGas(zen::evm::ADDITIONAL_COLD_ACCOUNT_ACCESS_COST);
  }

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

  static thread_local uint8_t PaddedAddress[32] = {0};
  memcpy(PaddedAddress + 12, Cache.TxContext.tx_origin.bytes, 20);
  return PaddedAddress;
}

const uint8_t *evmGetCaller(zen::runtime::EVMInstance *Instance) {
  const evmc_message *Msg = Instance->getCurrentMessage();
  ZEN_ASSERT(Msg && "No current message set in EVMInstance");

  static thread_local uint8_t PaddedAddress[32] = {0};
  memcpy(PaddedAddress + 12, Msg->sender.bytes, 20);
  return PaddedAddress;
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

  evmc::address Addr = loadAddressFromLE(Address);

  evmc_revision Rev = Instance->getRevision();
  if (Rev >= EVMC_BERLIN &&
      Module->Host->access_account(Addr) == EVMC_ACCESS_COLD) {
    Instance->chargeGas(zen::evm::ADDITIONAL_COLD_ACCOUNT_ACCESS_COST);
  }

  uint64_t Size = Module->Host->get_code_size(Addr);
  return Size;
}

const uint8_t *evmGetExtCodeHash(zen::runtime::EVMInstance *Instance,
                                 const uint8_t *Address) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);

  evmc::address Addr = loadAddressFromLE(Address);

  evmc_revision Rev = Instance->getRevision();
  if (Rev >= EVMC_BERLIN &&
      Module->Host->access_account(Addr) == EVMC_ACCESS_COLD) {
    Instance->chargeGas(zen::evm::ADDITIONAL_COLD_ACCOUNT_ACCESS_COST);
  }

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

  static thread_local uint8_t PaddedAddress[32] = {0};
  memcpy(PaddedAddress + 12, Cache.TxContext.block_coinbase.bytes, 20);
  return PaddedAddress;
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
      Hash = Module->Host->get_tx_context().blob_hashes[Index];
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

void evmSetReturn(zen::runtime::EVMInstance *Instance, uint64_t Offset,
                  uint64_t Len) {
  std::vector<uint8_t> ReturnData;
  if (Len > 0) {
    if (!Instance->expandMemoryChecked(Offset, Len)) {
      return;
    }
    uint8_t *MemoryBase = Instance->getMemoryBase();
    ReturnData =
        std::vector<uint8_t>(MemoryBase + Offset, MemoryBase + Offset + Len);
  }
  Instance->setReturnData(ReturnData);

  const uint64_t RemainingGas = Instance->getGas();
  evmc::Result ExeResult(EVMC_SUCCESS, RemainingGas,
                         Instance ? Instance->getGasRefund() : 0,
                         ReturnData.data(), ReturnData.size());
  Instance->setExeResult(std::move(ExeResult));
  // Immediately terminate the execution and return the success code (0)
  Instance->exit(0);
}
void evmSetCallDataCopy(zen::runtime::EVMInstance *Instance,
                        uint64_t DestOffset, uint64_t Offset, uint64_t Size) {
  // When Size is 0, no memory operations are needed
  if (Size == 0) {
    return;
  }
  if (!Instance->expandMemoryChecked(DestOffset, Size)) {
    return;
  }
  if (uint64_t CopyGas = calculateWordCopyGas(Size)) {
    Instance->chargeGas(CopyGas);
  }

  const evmc_message *Msg = Instance->getCurrentMessage();
  ZEN_ASSERT(Msg && "No current message set in EVMInstance");

  uint8_t *MemoryBase = Instance->getMemoryBase();

  // Calculate actual source offset and copy size
  uint64_t ActualOffset =
      std::min(Offset, static_cast<uint64_t>(Msg->input_size));
  uint64_t CopySize =
      (ActualOffset < Msg->input_size)
          ? std::min<uint64_t>(Size, static_cast<uint64_t>(Msg->input_size) -
                                         ActualOffset)
          : 0;

  if (CopySize > 0) {
    std::memcpy(MemoryBase + DestOffset, Msg->input_data + ActualOffset,
                CopySize);
  }

  // Fill remaining bytes with zeros if needed
  if (Size > CopySize) {
    std::memset(MemoryBase + DestOffset + CopySize, 0, Size - CopySize);
  }
}

void evmSetExtCodeCopy(zen::runtime::EVMInstance *Instance,
                       const uint8_t *Address, uint64_t DestOffset,
                       uint64_t Offset, uint64_t Size) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);
  evmc::address Addr = loadAddressFromLE(Address);

  if (!Instance->expandMemoryChecked(DestOffset, Size)) {
    return;
  }

  if (uint64_t CopyGas = calculateWordCopyGas(Size)) {
    Instance->chargeGas(CopyGas);
  }

  evmc_revision Rev = Instance->getRevision();
  if (Rev >= EVMC_BERLIN &&
      Module->Host->access_account(Addr) == EVMC_ACCESS_COLD) {
    Instance->chargeGas(zen::evm::ADDITIONAL_COLD_ACCOUNT_ACCESS_COST);
  }

  // When Size is 0, no memory operations are needed
  if (Size == 0) {
    return;
  }

  uint8_t *MemoryBase = Instance->getMemoryBase();
  constexpr auto MaxBufferSize = std::numeric_limits<uint32_t>::max();
  Offset = (MaxBufferSize < Offset) ? MaxBufferSize : Offset;
  size_t CopiedSize =
      Module->Host->copy_code(Addr, Offset, MemoryBase + DestOffset, Size);

  // Fill remaining bytes with zeros if needed
  if (Size > CopiedSize) {
    std::memset(MemoryBase + DestOffset + CopiedSize, 0, Size - CopiedSize);
  }
}

void evmSetReturnDataCopy(zen::runtime::EVMInstance *Instance,
                          uint64_t DestOffset, uint64_t Offset, uint64_t Size) {
  const auto &ReturnData = Instance->getReturnData();
  // Additional checks for add overflow
  if (Offset > ReturnData.size() || Size > ReturnData.size() ||
      Offset + Size > ReturnData.size()) {
    Instance->setGas(0);
    zen::runtime::EVMInstance::triggerInstanceExceptionOnJIT(
        Instance, zen::common::ErrorCode::OutOfBoundsMemory);
  }

  // When Size is 0, no memory operations are needed
  if (Size == 0) {
    return;
  }
  if (!Instance->expandMemoryChecked(DestOffset, Size)) {
    return;
  }
  if (uint64_t CopyGas = calculateWordCopyGas(Size)) {
    Instance->chargeGas(CopyGas);
  }

  uint8_t *MemoryBase = Instance->getMemoryBase();

  uint64_t CopySize = std::min<uint64_t>(
      Size, static_cast<uint64_t>(ReturnData.size()) - Offset);
  std::memcpy(MemoryBase + DestOffset, ReturnData.data() + Offset, CopySize);
}

void evmExpandMemoryNoGas(zen::runtime::EVMInstance *Instance,
                          uint64_t RequiredSize) {
  Instance->expandMemoryNoGas(RequiredSize);
}

uint64_t evmGetReturnDataSize(zen::runtime::EVMInstance *Instance) {
  const auto &ReturnData = Instance->getReturnData();
  return ReturnData.size();
}

template <size_t MaxTopics>
static void evmEmitLogGeneric(zen::runtime::EVMInstance *Instance,
                              uint64_t Offset, uint64_t Size,
                              const uint8_t *TopicsData[]) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);

  const evmc_message *Msg = Instance->getCurrentMessage();
  ZEN_ASSERT(Msg && "No current message set in EVMInstance");
  if (Instance->isStaticMode()) {
    triggerStaticModeViolation(Instance);
    return;
  }

  // Only expand memory if we actually need to access it (Size > 0)
  const uint8_t *Data = nullptr;
  if (Size > 0) {
    if (!Instance->expandMemoryChecked(Offset, Size)) {
      return;
    }
    const uint64_t LogDataCost = 8 * Size;
    if (LogDataCost != 0) {
      Instance->chargeGas(LogDataCost);
    }
    uint8_t *MemoryBase = Instance->getMemoryBase();
    Data = MemoryBase + Offset;
  }

  // Build topic array - only include non-null topics
  evmc::bytes32 Topics[MaxTopics] = {};
  size_t ActualNumTopics = 0;

  for (size_t i = 0; i < MaxTopics; ++i) {
    if (TopicsData[i]) {
      Topics[ActualNumTopics] = loadBytes32FromLE(TopicsData[i]);
      ActualNumTopics++;
    }
  }

  Module->Host->emit_log(Msg->recipient, Data, Size,
                         ActualNumTopics > 0 ? Topics : nullptr,
                         ActualNumTopics);
}

void evmEmitLog0(zen::runtime::EVMInstance *Instance, uint64_t Offset,
                 uint64_t Size) {
  const uint8_t *Topics[0] = {};
  evmEmitLogGeneric<0>(Instance, Offset, Size, Topics);
}

void evmEmitLog1(zen::runtime::EVMInstance *Instance, uint64_t Offset,
                 uint64_t Size, const uint8_t *Topic1) {
  const uint8_t *Topics[1] = {Topic1};
  evmEmitLogGeneric<1>(Instance, Offset, Size, Topics);
}

void evmEmitLog2(zen::runtime::EVMInstance *Instance, uint64_t Offset,
                 uint64_t Size, const uint8_t *Topic1, const uint8_t *Topic2) {
  const uint8_t *Topics[2] = {Topic1, Topic2};
  evmEmitLogGeneric<2>(Instance, Offset, Size, Topics);
}

void evmEmitLog3(zen::runtime::EVMInstance *Instance, uint64_t Offset,
                 uint64_t Size, const uint8_t *Topic1, const uint8_t *Topic2,
                 const uint8_t *Topic3) {
  const uint8_t *Topics[3] = {Topic1, Topic2, Topic3};
  evmEmitLogGeneric<3>(Instance, Offset, Size, Topics);
}

void evmEmitLog4(zen::runtime::EVMInstance *Instance, uint64_t Offset,
                 uint64_t Size, const uint8_t *Topic1, const uint8_t *Topic2,
                 const uint8_t *Topic3, const uint8_t *Topic4) {
  const uint8_t *Topics[4] = {Topic1, Topic2, Topic3, Topic4};
  evmEmitLogGeneric<4>(Instance, Offset, Size, Topics);
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

  static thread_local uint8_t ZeroAddress[32] = {0};
  if (Instance->isStaticMode()) {
    triggerStaticModeViolation(Instance);
    return ZeroAddress;
  }

  // Calculate required memory size and charge gas
  const uint8_t *InitCode = nullptr;
  if (Size > 0) {
    if (!Instance->expandMemoryChecked(Offset, Size)) {
      Instance->setReturnData({});
      return ZeroAddress;
    }

    uint8_t *MemoryBase = Instance->getMemoryBase();
    InitCode = MemoryBase + Offset;
  }

  evmc_revision Rev = Instance->getRevision();
  if (Rev >= EVMC_SHANGHAI && Size > zen::evm::MAX_SIZE_OF_INITCODE) {
    Instance->chargeGas(Instance->getGas() + 1);
  }
  uint64_t InitCodeWordCost = 0;
  if (CallKind == EVMC_CREATE2) {
    InitCodeWordCost += 6;
  }
  if (Rev >= EVMC_SHANGHAI) {
    InitCodeWordCost += 2;
  }
  if (InitCodeWordCost != 0 && Size != 0) {
    uint64_t InitCodeWords = (Size + 31) / 32;
    uint64_t InitCodeCost = InitCodeWordCost * InitCodeWords;
    if (InitCodeCost != 0) {
      Instance->chargeGas(InitCodeCost);
    }
  }

  if (Msg->depth >= zen::evm::MAXSTACK) {
    Instance->setReturnData({});
    return ZeroAddress;
  }

  if (intx::be::load<intx::uint256>(Module->Host->get_balance(Msg->recipient)) <
      intx::uint256{Value}) {
    Instance->setReturnData({});
    return ZeroAddress;
  }

  // Create message for CREATE/CREATE2
  evmc_message CreateMsg = {};
  CreateMsg.kind = CallKind;
  CreateMsg.flags = Msg->flags;
  CreateMsg.depth = Msg->depth + 1;
  CreateMsg.gas = Msg->gas;
  if (Rev >= EVMC_TANGERINE_WHISTLE && CreateMsg.gas > 0) {
    int64_t Reduction = CreateMsg.gas / 64;
    CreateMsg.gas -= Reduction;
  }
  CreateMsg.sender = Msg->recipient;
  CreateMsg.value = intx::be::store<evmc::bytes32>(intx::uint256{Value});
  CreateMsg.input_data = InitCode;
  CreateMsg.input_size = Size;

  // Set salt for CREATE2
  if (CallKind == EVMC_CREATE2 && Salt != nullptr) {
    CreateMsg.create2_salt = loadBytes32FromLE(Salt);
  }

  Instance->pushMessage(&CreateMsg);
  evmc::Result Result = Module->Host->call(CreateMsg);
  Instance->popMessage();

  uint64_t ProvidedGas =
      CreateMsg.gas > 0 ? static_cast<uint64_t>(CreateMsg.gas) : 0;
  uint64_t GasLeft =
      Result.gas_left > 0 ? static_cast<uint64_t>(Result.gas_left) : 0;
  uint64_t GasUsed = ProvidedGas > GasLeft ? ProvidedGas - GasLeft : 0;
  if (GasUsed != 0) {
    Instance->chargeGas(GasUsed);
  }
  // Track subcall refund (may be negative)
  Instance->addGasRefund(Result.gas_refund);

  std::vector<uint8_t> ReturnData(Result.output_data,
                                  Result.output_data + Result.output_size);
  Instance->setReturnData(std::move(ReturnData));
  if (Result.status_code == EVMC_SUCCESS) {
    static thread_local uint8_t PaddedAddress[32] = {0};
    memcpy(PaddedAddress + 12, Result.create_address.bytes, 20);
    return PaddedAddress;
  }
  return ZeroAddress;
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
  evmc::address TargetAddr =
      ToAddr ? loadAddressFromLE(ToAddr) : evmc::address{};
  evmc_revision Rev = Instance->getRevision();
  if (Rev >= EVMC_BERLIN &&
      Module->Host->access_account(TargetAddr) == EVMC_ACCESS_COLD) {
    Instance->chargeGas(zen::evm::ADDITIONAL_COLD_ACCOUNT_ACCESS_COST);
  }

  const bool HasValueArgs = CallKind == EVMC_CALL || CallKind == EVMC_CALLCODE;
  const bool HasValue = Value != 0;

  if (CallKind == EVMC_CALL && HasValue && Instance->isStaticMode()) {
    triggerStaticModeViolation(Instance);
    return 0;
  }

  // Calculate required memory sizes for input and output
  // Only expand memory if we actually need to access it
  bool needArgsMemory = ArgsSize > 0;
  bool needRetMemory = RetSize > 0;
  if (needArgsMemory && needRetMemory) {
    if (!Instance->expandMemoryChecked(ArgsOffset, ArgsSize, RetOffset,
                                       RetSize)) {
      Instance->setReturnData({});
      return 0;
    }
  } else if (needArgsMemory) {
    if (!Instance->expandMemoryChecked(ArgsOffset, ArgsSize)) {
      Instance->setReturnData({});
      return 0;
    }
  } else if (needRetMemory) {
    if (!Instance->expandMemoryChecked(RetOffset, RetSize)) {
      Instance->setReturnData({});
      return 0;
    }
  }

  uint64_t CallGas = Gas;
  if (HasValueArgs) {
    std::optional<bool> AccountState;
    uint64_t GasCost = HasValue ? zen::evm::CALL_VALUE_COST : 0;
    if (CallKind == EVMC_CALL) {
      if (HasValue || Instance->getRevision() < EVMC_SPURIOUS_DRAGON) {
        AccountState = Module->Host->account_exists(TargetAddr);
        if (!AccountState.value()) {
          GasCost += zen::evm::ACCOUNT_CREATION_COST;
        }
      }
    }

    Instance->chargeGas(GasCost);
  }

  uint64_t GasLeft = Instance->getGas();
  if (Rev >= EVMC_TANGERINE_WHISTLE) {
    const uint64_t GasCap = GasLeft - GasLeft / 64;
    CallGas = std::min(CallGas, GasCap);
  } else if (CallGas > GasLeft) {
    zen::runtime::EVMInstance::triggerInstanceExceptionOnJIT(
        Instance, zen::common::ErrorCode::GasLimitExceeded);
  }

  if (HasValueArgs) {
    bool HasEnoughBalance = true;
    if (HasValue) {
      Instance->addGas(zen::evm::CALL_GAS_STIPEND);
      CallGas += zen::evm::CALL_GAS_STIPEND;

      const auto CallerBalance =
          Module->Host->get_balance(CurrentMsg->recipient);
      const intx::uint256 CallerValue =
          intx::be::load<intx::uint256>(CallerBalance);
      HasEnoughBalance = CallerValue >= intx::uint256(Value);

      if (!HasEnoughBalance) {
        Instance->setReturnData({});
        return 0;
      }
    }
  }

  uint8_t *MemoryBase = Instance->getMemoryBase();

  if (CurrentMsg->depth >= zen::evm::MAXSTACK) {
    Instance->setReturnData({});
    return 0;
  }

  // Create message for call
  evmc_message CallMsg{
      .kind = CallKind,
      .flags = (CallKind == EVMC_CALL && ForceStatic) ? uint32_t{EVMC_STATIC}
                                                      : CurrentMsg->flags,
      .depth = CurrentMsg->depth + 1,
      .gas = static_cast<int64_t>(CallGas),
      .recipient = (CallKind == EVMC_CALL || ForceStatic)
                       ? TargetAddr
                       : CurrentMsg->recipient,
      .sender = (CallKind == EVMC_DELEGATECALL) ? CurrentMsg->sender
                                                : CurrentMsg->recipient,
      .input_data = MemoryBase + ArgsOffset,
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
  CallGas = CallMsg.gas > 0 ? static_cast<uint64_t>(CallMsg.gas) : 0;
  GasLeft = Result.gas_left > 0 ? static_cast<uint64_t>(Result.gas_left) : 0;
  uint64_t GasUsed = CallGas > GasLeft ? CallGas - GasLeft : 0;
  if (GasUsed > 0) {
    Instance->chargeGas(GasUsed);
  }

  // Track subcall refund (may be negative)
  Instance->addGasRefund(Result.gas_refund);

  // Copy return data to memory if output area is specified.
  // Per EVM semantics, bytes beyond returned data length remain unchanged.
  if (RetSize > 0 && Result.output_size > 0) {
    size_t CopySize =
        std::min(static_cast<size_t>(RetSize), Result.output_size);
    std::memcpy(MemoryBase + RetOffset, Result.output_data, CopySize);
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
  // Immediately terminate the execution and return the invalid code (4)
  Instance->restoreGasRefundSnapshot();
  Instance->setReturnData({});
  evmc::Result ExeResult(
      EVMC_INVALID_INSTRUCTION, 0, Instance ? Instance->getGasRefund() : 0,
      Instance->getReturnData().data(), Instance->getReturnData().size());
  Instance->setGas(0);
  Instance->setExeResult(std::move(ExeResult));
  Instance->exit(4);
}

void evmHandleUndefined(zen::runtime::EVMInstance *Instance) {
  // Immediately terminate the execution and return the undefined code
  Instance->restoreGasRefundSnapshot();
  Instance->setReturnData({});
  evmc::Result ExeResult(
      EVMC_UNDEFINED_INSTRUCTION, 0, Instance ? Instance->getGasRefund() : 0,
      Instance->getReturnData().data(), Instance->getReturnData().size());
  Instance->setGas(0);
  Instance->setExeResult(std::move(ExeResult));
  Instance->exit(5);
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
  std::vector<uint8_t> ReturnData;
  if (Size > 0) {
    if (!Instance->expandMemoryChecked(Offset, Size)) {
      return;
    }
    uint8_t *MemoryBase = Instance->getMemoryBase();
    ReturnData =
        std::vector<uint8_t>(MemoryBase + Offset, MemoryBase + Offset + Size);
  }
  Instance->restoreGasRefundSnapshot();
  Instance->setReturnData(std::move(ReturnData));
  const int64_t GasLeft =
      Instance ? static_cast<int64_t>(Instance->getGas()) : 0;
  // Immediately terminate the execution and return the revert code (2)
  evmc::Result ExeResult(
      EVMC_REVERT, GasLeft, Instance ? Instance->getGasRefund() : 0,
      Instance->getReturnData().data(), Instance->getReturnData().size());
  Instance->setExeResult(std::move(ExeResult));
  Instance->exit(2);
}

void evmSetCodeCopy(zen::runtime::EVMInstance *Instance, uint64_t DestOffset,
                    uint64_t Offset, uint64_t Size) {
  // When Size is 0, no memory operations are needed
  if (Size == 0) {
    return;
  }
  if (!Instance->expandMemoryChecked(DestOffset, Size)) {
    return;
  }
  if (uint64_t CopyGas = calculateWordCopyGas(Size)) {
    Instance->chargeGas(CopyGas);
  }

  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module);
  const zen::common::Byte *Code = Module->Code;
  size_t CodeSize = Module->CodeSize;

  uint8_t *MemoryBase = Instance->getMemoryBase();

  if (Offset < CodeSize) {
    auto CopySize = std::min(Size, CodeSize - Offset);
    std::memcpy(MemoryBase + DestOffset, Code + Offset, CopySize);
    if (Size > CopySize) {
      std::memset(MemoryBase + DestOffset + CopySize, 0, Size - CopySize);
    }
  } else {
    if (Size > 0) {
      std::memset(MemoryBase + DestOffset, 0, Size);
    }
  }
}

const uint8_t *evmGetKeccak256(zen::runtime::EVMInstance *Instance,
                               uint64_t Offset, uint64_t Length) {
  const uint8_t *InputData = nullptr;
  if (Length > 0) {
    if (!Instance->expandMemoryChecked(Offset, Length)) {
      return nullptr;
    }
    const uint64_t ExtraGas =
        static_cast<uint64_t>(numWords(static_cast<uint64_t>(Length))) * 6;
    Instance->chargeGas(ExtraGas);
    uint8_t *MemoryBase = Instance->getMemoryBase();
    InputData = MemoryBase + Offset;
  }

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
    Instance->chargeGas(zen::evm::ADDITIONAL_COLD_SLOAD_COST);
  }
  const auto Value = Module->Host->get_storage(Msg->recipient, Key);
  return storeUint256Result(intx::be::load<intx::uint256>(Value));
}
void evmSetSStore(zen::runtime::EVMInstance *Instance,
                  const intx::uint256 &Index, const intx::uint256 &Value) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);
  if (Instance->isStaticMode()) {
    triggerStaticModeViolation(Instance);
    return;
  }
  const evmc_message *Msg = Instance->getCurrentMessage();
  const evmc_revision Rev = Instance->getRevision();
  if (Rev >= EVMC_ISTANBUL &&
      Instance->getGas() <= zen::evm::SSTORE_REQUIRED_ISTANBUL) {
    zen::runtime::EVMInstance::triggerInstanceExceptionOnJIT(
        Instance, zen::common::ErrorCode::GasLimitExceeded);
  }
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
    triggerStaticModeViolation(Instance);
    return;
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
    triggerStaticModeViolation(Instance);
    return;
  }
  const evmc_message *Msg = Instance->getCurrentMessage();
  evmc_revision Rev = Instance->getRevision();

  evmc::address BenefAddr = loadAddressFromLE(Beneficiary);

  // EIP-2929: charge cold account access cost if needed.
  if (Rev >= EVMC_BERLIN) {
    const bool IsCold =
        Module->Host->access_account(BenefAddr) == EVMC_ACCESS_COLD;
    if (IsCold) {
      Instance->chargeGas(zen::evm::COLD_ACCOUNT_ACCESS_COST);
    }
  }

  // EIP-161: charge account creation cost only if a new account is created.
  if (Rev >= EVMC_TANGERINE_WHISTLE) {
    if (Rev == EVMC_TANGERINE_WHISTLE ||
        Module->Host->get_balance(Msg->recipient)) {
      if (!Module->Host->account_exists(BenefAddr)) {
        Instance->chargeGas(zen::evm::ACCOUNT_CREATION_COST);
      }
    }
  }

  if (Module->Host->selfdestruct(Msg->recipient, BenefAddr)) {
    if (Rev < EVMC_LONDON) {
      Instance->addGasRefund(zen::evm::EXTRA_REFUND_BEFORE_LONDON);
    }
  }

  Instance->setReturnData({});
  uint64_t RemainingGas = Msg->gas;
  Instance->popMessage();

  if (const evmc_message *Parent = Instance->getCurrentMessage()) {
    auto *ParentMsg = const_cast<evmc_message *>(Parent);
    ParentMsg->gas += static_cast<int64_t>(RemainingGas);
    Instance->setGas(static_cast<uint64_t>(ParentMsg->gas));
  } else {
    Instance->setGas(RemainingGas);
    evmc::Result ExeResult(
        EVMC_SUCCESS, RemainingGas, Instance ? Instance->getGasRefund() : 0,
        Instance->getReturnData().data(), Instance->getReturnData().size());
    Instance->setExeResult(std::move(ExeResult));
    Instance->exit(0);
  }
}

const intx::uint256 *evmGetClz(zen::runtime::EVMInstance *Instance,
                               const intx::uint256 &Value) {
  uint64_t clzResult = intx::clz(Value);
  intx::uint256 result;
  result[0] = clzResult;
  return storeUint256Result(result);
}
} // namespace COMPILER
