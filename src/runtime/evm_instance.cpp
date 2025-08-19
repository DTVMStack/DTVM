// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "runtime/evm_instance.h"

#include "action/instantiator.h"
#include "common/enums.h"
#include "common/errors.h"
#include "common/traphandler.h"
#include "entrypoint/entrypoint.h"
#include "runtime/config.h"
#include <algorithm>

namespace zen::runtime {

using namespace common;

EVMInstanceUniquePtr EVMInstance::newEVMInstance(Isolation &Iso,
                                                 const EVMModule &Mod,
                                                 uint64_t GasLimit) {

  Runtime *RT = Mod.getRuntime();
  void *Buf = RT->allocate(sizeof(EVMInstance), Alignment);
  ZEN_ASSERT(Buf);

  EVMInstanceUniquePtr Inst(new (Buf) EVMInstance(Mod, *RT));

  Inst->Iso = &Iso;

  Inst->setGas(GasLimit);

  return Inst;
}

EVMInstance::~EVMInstance() {}

const uint8_t *evmGetAddress(EVMInstance *Instance) {
  const evmc_message *Msg = Instance->getCurrentMessage();
  ZEN_ASSERT(Msg && "No current message set in EVMInstance");
  return Msg->recipient.bytes;
}

const uint8_t *evmGetOrigin(EVMInstance *Instance) {
  const EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);
  evmc_tx_context TxContext = Module->Host->get_tx_context();
  static thread_local evmc_tx_context CachedTxContext;
  CachedTxContext = TxContext;
  return CachedTxContext.tx_origin.bytes;
}

const uint8_t *evmGetCaller(EVMInstance *Instance) {
  const evmc_message *Msg = Instance->getCurrentMessage();
  ZEN_ASSERT(Msg && "No current message set in EVMInstance");
  return Msg->sender.bytes;
}

const uint8_t *evmGetCallValue(EVMInstance *Instance) {
  const evmc_message *Msg = Instance->getCurrentMessage();
  ZEN_ASSERT(Msg && "No current message set in EVMInstance");
  return Msg->value.bytes;
}

intx::uint256 evmGetGasPrice(EVMInstance *Instance) {
  const EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);
  evmc_tx_context TxContext = Module->Host->get_tx_context();
  return intx::be::load<intx::uint256>(TxContext.tx_gas_price);
}

uint64_t evmGetCallDataSize(EVMInstance *Instance) {
  const evmc_message *Msg = Instance->getCurrentMessage();
  ZEN_ASSERT(Msg && "No current message set in EVMInstance");
  return Msg->input_size;
}

uint64_t evmGetCodeSize(EVMInstance *Instance) {
  const EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module);
  return Module->CodeSize;
}

} // namespace zen::runtime
