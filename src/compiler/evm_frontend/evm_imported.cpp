// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/evm_frontend/evm_imported.h"
#include "common/errors.h"
#include "runtime/evm_instance.h"
#include "runtime/evm_module.h"

namespace COMPILER {

const RuntimeFunctions &getRuntimeFunctionTable() {
  static const RuntimeFunctions Table = {.GetAddress = &evmGetAddress,
                                         .GetOrigin = &evmGetOrigin,
                                         .GetCaller = &evmGetCaller,
                                         .GetCallValue = &evmGetCallValue,
                                         .GetGasPrice = &evmGetGasPrice,
                                         .GetCallDataSize = &evmGetCallDataSize,
                                         .GetCodeSize = &evmGetCodeSize,
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

const uint8_t *evmGetOrigin(zen::runtime::EVMInstance *Instance) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);

  auto &cache = Instance->getMessageCache();
  if (!cache.tx_context_cached) {
    cache.tx_context = Module->Host->get_tx_context();
    cache.tx_context_cached = true;
  }
  return cache.tx_context.tx_origin.bytes;
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

intx::uint256 evmGetGasPrice(zen::runtime::EVMInstance *Instance) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);
  evmc_tx_context TxContext = Module->Host->get_tx_context();
  return intx::be::load<intx::uint256>(TxContext.tx_gas_price);
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

  auto &cache = Instance->getMessageCache();
  auto it = cache.block_hashes.find(BlockNumber);
  if (it == cache.block_hashes.end()) {
    evmc::bytes32 hash = (BlockNumber < UpperBound && BlockNumber >= LowerBound)
                             ? Module->Host->get_block_hash(BlockNumber)
                             : evmc::bytes32{};
    cache.block_hashes[BlockNumber] = hash;
    return hash.bytes;
  }
  return it->second.bytes;
}

const uint8_t *evmGetCoinBase(zen::runtime::EVMInstance *Instance) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);

  auto &cache = Instance->getMessageCache();
  if (!cache.tx_context_cached) {
    cache.tx_context = Module->Host->get_tx_context();
    cache.tx_context_cached = true;
  }
  return cache.tx_context.block_coinbase.bytes;
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

  auto &cache = Instance->getMessageCache();
  if (!cache.tx_context_cached) {
    cache.tx_context = Module->Host->get_tx_context();
    cache.tx_context_cached = true;
  }
  return cache.tx_context.block_prev_randao.bytes;
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

  auto &cache = Instance->getMessageCache();
  if (!cache.tx_context_cached) {
    cache.tx_context = Module->Host->get_tx_context();
    cache.tx_context_cached = true;
  }
  return cache.tx_context.chain_id.bytes;
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

  auto &cache = Instance->getMessageCache();
  auto it = cache.blob_hashes.find(Index);
  if (it == cache.blob_hashes.end()) {
    evmc::bytes32 hash;
    if (Index >= TxContext.blob_hashes_count) {
      hash = evmc::bytes32{};
    } else {
      hash = Module->Host->get_blob_hash(Index);
    }
    cache.blob_hashes[Index] = hash;
    return hash.bytes;
  }
  return it->second.bytes;
}

intx::uint256 evmGetBlobBaseFee(zen::runtime::EVMInstance *Instance) {
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);
  evmc_tx_context TxContext = Module->Host->get_tx_context();
  return intx::be::load<intx::uint256>(TxContext.blob_base_fee);
}

} // namespace COMPILER
