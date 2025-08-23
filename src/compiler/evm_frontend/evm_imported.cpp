// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/evm_frontend/evm_imported.h"
#include "common/errors.h"
#include "runtime/evm_instance.h"
#include "runtime/evm_module.h"

namespace COMPILER {

const RuntimeFunctions &getRuntimeFunctionTable() {
  static const RuntimeFunctions Table = {.GetAddress = &evmGetAddress,
                                         .GetBalance = &evmGetBalance,
                                         .GetOrigin = &evmGetOrigin,
                                         .GetCaller = &evmGetCaller,
                                         .GetCallValue = &evmGetCallValue,
                                         .GetCallDataLoad = &evmGetCallDataLoad,
                                         .GetCallDataSize = &evmGetCallDataSize,
                                         .GetCodeSize = &evmGetCodeSize,
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
                                         .GetBlobBaseFee = &evmGetBlobBaseFee};
  return Table;
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
    return Hash.bytes;
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
      Hash = Module->Host->get_blob_hash(Index);
    }
    Cache.BlobHashes[Index] = Hash;
    return Hash.bytes;
  }
  return It->second.bytes;
}

intx::uint256 evmGetBlobBaseFee(zen::runtime::EVMInstance *Instance) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);
  evmc_tx_context TxContext = Module->Host->get_tx_context();
  return intx::be::load<intx::uint256>(TxContext.blob_base_fee);
}

} // namespace COMPILER
