// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/evm_frontend/evm_imported.h"
#include "common/errors.h"
#include "host/evm/crypto.h"
#include "runtime/evm_instance.h"
#include "runtime/evm_module.h"

namespace COMPILER {

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
      .GetTLoad = &evmGetTLoad,
      .SetTStore = &evmSetTStore,
      .SetMCopy = &evmSetMCopy,
      .SetCallDataCopy = &evmSetCallDataCopy,
      .SetExtCodeCopy = &evmSetExtCodeCopy,
      .SetReturnDataCopy = &evmSetReturnDataCopy,
      .GetReturnDataSize = &evmGetReturnDataSize,
      .SetReturn = &evmSetReturn,
      .HandleInvalid = &evmHandleInvalid,
      .HandleSelfDestruct = &evmHandleSelfDestruct,
      .GetKeccak256 = &evmGetKeccak256};
  return Table;
}

intx::uint256 evmGetMul(zen::runtime::EVMInstance *Instance,
                        intx::uint256 Multiplicand, intx::uint256 Multiplier) {
  // EVM: Multiplicand * Multiplier % (2^256)
  return Multiplicand * Multiplier;
}

intx::uint256 evmGetDiv(zen::runtime::EVMInstance *Instance,
                        intx::uint256 Dividend, intx::uint256 Divisor) {
  if (Divisor == 0) {
    return intx::uint256{0};
  }
  return Dividend / Divisor;
}

intx::uint256 evmGetSDiv(zen::runtime::EVMInstance *Instance,
                         intx::uint256 Dividend, intx::uint256 Divisor) {
  if (Divisor == 0) {
    return intx::uint256{0};
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

  return isResultNegative ? (~absResult + 1) : absResult;
}

intx::uint256 evmGetMod(zen::runtime::EVMInstance *Instance,
                        intx::uint256 Dividend, intx::uint256 Divisor) {
  if (Divisor == 0) {
    return intx::uint256{0};
  }
  return Dividend % Divisor;
}

intx::uint256 evmGetSMod(zen::runtime::EVMInstance *Instance,
                         intx::uint256 Dividend, intx::uint256 Divisor) {
  if (Divisor == 0) {
    return intx::uint256{0};
  }

  // Check if dividend is negative (MSB set)
  bool isDividendNegative = (Dividend >> 255) != 0;

  // Convert to absolute values
  intx::uint256 absDividend = isDividendNegative ? (~Dividend + 1) : Dividend;
  intx::uint256 absDivisor = Divisor; // Divisor sign doesn't affect modulo

  // Perform unsigned modulo
  intx::uint256 absResult = absDividend % absDivisor;

  // Apply sign: result has same sign as dividend
  return isDividendNegative ? (~absResult + 1) : absResult;
}

intx::uint256 evmGetAddMod(zen::runtime::EVMInstance *Instance,
                           intx::uint256 Augend, intx::uint256 Addend,
                           intx::uint256 Modulus) {
  // Handle edge case: modulo 0
  if (Modulus == 0) {
    return intx::uint256{0};
  }

  // (Augend + Addend) % Modulus
  // Use 512-bit intermediate to prevent overflow
  intx::uint512 Sum = intx::uint512(Augend) + intx::uint512(Addend);
  intx::uint256 Result = intx::uint256(Sum % Modulus);
  return Result;
}

intx::uint256 evmGetMulMod(zen::runtime::EVMInstance *Instance,
                           intx::uint256 Multiplicand, intx::uint256 Multiplier,
                           intx::uint256 Modulus) {
  // Handle edge case: modulo 0
  if (Modulus == 0) {
    return intx::uint256{0};
  }

  // (Multiplicand * Multiplier) % Modulus
  // Use 512-bit intermediate to prevent overflow
  intx::uint512 Product =
      intx::uint512(Multiplicand) * intx::uint512(Multiplier);
  intx::uint256 Result = intx::uint256(Product % Modulus);
  return Result;
}

intx::uint256 evmGetExp(zen::runtime::EVMInstance *Instance, intx::uint256 Base,
                        intx::uint256 Exponent) {
  // Handle edge cases
  if (Exponent == 0) {
    return intx::uint256{1};
  }
  if (Base == 0) {
    return intx::uint256{0};
  }
  if (Exponent == 1) {
    return Base;
  }

  // EVM: (Base ^ Exponent) % (2^256)
  intx::uint256 Result = 1;
  intx::uint256 CurrentBase = Base;

  while (Exponent > 0) {
    if (Exponent & 1) {
      Result *= CurrentBase;
    }
    CurrentBase *= CurrentBase;
    Exponent >>= 1;
  }

  return Result;
}

const uint8_t *evmGetAddress(zen::runtime::EVMInstance *Instance) {
  const evmc_message *Msg = Instance->getCurrentMessage();
  ZEN_ASSERT(Msg && "No current message set in EVMInstance");
  return Msg->recipient.bytes;
}

intx::uint256 evmGetBalance(zen::runtime::EVMInstance *Instance,
                            const uint8_t *Address) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);

  evmc::address Addr;
  std::memcpy(Addr.bytes, Address, sizeof(Addr.bytes));

  evmc::bytes32 BalanceBytes = Module->Host->get_balance(Addr);
  intx::uint256 Balance = intx::be::load<intx::uint256>(BalanceBytes);
  return Balance;
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

intx::uint256 evmGetGasPrice(zen::runtime::EVMInstance *Instance) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);
  evmc_tx_context TxContext = Module->Host->get_tx_context();
  return intx::be::load<intx::uint256>(TxContext.tx_gas_price);
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

intx::uint256 evmGetTimestamp(zen::runtime::EVMInstance *Instance) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);
  evmc_tx_context TxContext = Module->Host->get_tx_context();
  return intx::uint256(TxContext.block_timestamp);
}

intx::uint256 evmGetNumber(zen::runtime::EVMInstance *Instance) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);
  evmc_tx_context TxContext = Module->Host->get_tx_context();
  return intx::uint256(TxContext.block_number);
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

intx::uint256 evmGetGasLimit(zen::runtime::EVMInstance *Instance) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);
  evmc_tx_context TxContext = Module->Host->get_tx_context();
  return intx::uint256(TxContext.block_gas_limit);
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

intx::uint256 evmGetSelfBalance(zen::runtime::EVMInstance *Instance) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);
  const evmc_message *Msg = Instance->getCurrentMessage();
  ZEN_ASSERT(Msg && "No current message set in EVMInstance");
  evmc::bytes32 Balance = Module->Host->get_balance(Msg->recipient);
  return intx::be::load<intx::uint256>(Balance);
}

intx::uint256 evmGetBaseFee(zen::runtime::EVMInstance *Instance) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);
  evmc_tx_context TxContext = Module->Host->get_tx_context();
  return intx::be::load<intx::uint256>(TxContext.block_base_fee);
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

intx::uint256 evmGetBlobBaseFee(zen::runtime::EVMInstance *Instance) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);
  evmc_tx_context TxContext = Module->Host->get_tx_context();
  return intx::be::load<intx::uint256>(TxContext.blob_base_fee);
}

uint64_t evmGetMSize(zen::runtime::EVMInstance *Instance) {
  return Instance->getMemorySize();
}
intx::uint256 evmGetMLoad(zen::runtime::EVMInstance *Instance,
                          uint64_t Offset) {
  uint64_t RequiredSize = Offset + 32;
  Instance->consumeMemoryExpansionGas(RequiredSize);
  Instance->expandMemory(RequiredSize);
  auto &Memory = Instance->getMemory();

  uint8_t ValueBytes[32];
  std::memcpy(ValueBytes, Memory.data() + Offset, 32);

  intx::uint256 Result = intx::be::load<intx::uint256>(ValueBytes);
  return Result;
}
void evmSetMStore(zen::runtime::EVMInstance *Instance, uint64_t Offset,
                  intx::uint256 Value) {
  uint64_t RequiredSize = Offset + 32;
  Instance->consumeMemoryExpansionGas(RequiredSize);
  Instance->expandMemory(RequiredSize);

  auto &Memory = Instance->getMemory();
  uint8_t ValueBytes[32];
  intx::be::store(ValueBytes, Value);
  std::memcpy(&Memory[Offset], ValueBytes, 32);
}

void evmSetMStore8(zen::runtime::EVMInstance *Instance, uint64_t Offset,
                   intx::uint256 Value) {
  uint64_t RequiredSize = Offset + 1;

  Instance->consumeMemoryExpansionGas(RequiredSize);
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
  uint64_t RequiredSize = std::max(Dest + Len, Src + Len);

  Instance->consumeMemoryExpansionGas(RequiredSize);
  Instance->expandMemory(RequiredSize);

  auto &Memory = Instance->getMemory();
  std::memmove(&Memory[Dest], &Memory[Src], Len);
}
void evmSetReturn(zen::runtime::EVMInstance *Instance, uint64_t Offset,
                  uint64_t Len) {
  auto &Memory = Instance->getMemory();
  std::vector<uint8_t> ReturnData(Memory.begin() + Offset,
                                  Memory.begin() + Offset + Len);
  Instance->setReturnData(std::move(ReturnData));
  // Immediately terminate the execution and return the success code (0)
  Instance->exit(0);
}
void evmSetCallDataCopy(zen::runtime::EVMInstance *Instance,
                        uint64_t DestOffset, uint64_t Offset, uint64_t Size) {
  uint64_t RequiredSize = DestOffset + Size;
  Instance->consumeMemoryExpansionGas(RequiredSize);
  Instance->expandMemory(RequiredSize);

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
  Instance->consumeMemoryExpansionGas(RequiredSize);
  Instance->expandMemory(RequiredSize);

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
  Instance->consumeMemoryExpansionGas(RequiredSize);
  Instance->expandMemory(RequiredSize);

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

void evmHandleInvalid(zen::runtime::EVMInstance *Instance) {
  throw zen::common::getError(zen::common::ErrorCode::EVMInvalidInstruction);
}

void evmSetCodeCopy(zen::runtime::EVMInstance *Instance, uint64_t DestOffset,
                    uint64_t Offset, uint64_t Size) {
  uint64_t RequiredSize = DestOffset + Size;
  Instance->consumeMemoryExpansionGas(RequiredSize);
  Instance->expandMemory(RequiredSize);

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
  Instance->consumeMemoryExpansionGas(RequiredSize);
  Instance->expandMemory(RequiredSize);

  auto &Memory = Instance->getMemory();
  const uint8_t *InputData = Memory.data() + Offset;

  auto &Cache = Instance->getMessageCache();
  evmc::bytes32 HashResult;
  zen::host::evm::crypto::keccak256(InputData, Length, HashResult.bytes);
  Cache.Keccak256Results.push_back(HashResult);

  return Cache.Keccak256Results.back().bytes;
}
intx::uint256 evmGetSLoad(zen::runtime::EVMInstance *Instance,
                          intx::uint256 Index) {
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
  return intx::be::load<intx::uint256>(Value);
}
void evmSetSStore(zen::runtime::EVMInstance *Instance, intx::uint256 Index,
                  intx::uint256 Value) {
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
intx::uint256 evmGetTLoad(zen::runtime::EVMInstance *Instance,
                          intx::uint256 Index) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);
  const evmc_message *Msg = Instance->getCurrentMessage();
  const auto Key = intx::be::store<evmc::bytes32>(Index);
  const auto Value = Module->Host->get_transient_storage(Msg->recipient, Key);
  return intx::be::load<intx::uint256>(Value);
}
void evmSetTStore(zen::runtime::EVMInstance *Instance, intx::uint256 Index,
                  intx::uint256 Value) {
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
    Instance->exit(0);
  }
}

} // namespace COMPILER
