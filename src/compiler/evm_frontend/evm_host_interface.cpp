// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/evm_frontend/evm_host_interface.h"
#include "common/defines.h"
#include "common/errors.h"
#include "evmc/evmc.hpp"
#include "runtime/evm_instance.h"

namespace COMPILER {

// ==================== Host Interface Implementation ====================

const EVMHostInterface::HostFunctions &EVMHostInterface::getFunctionTable() {
  static const HostFunctions Table = {
      .GetAddress = &EVMHostInterface::getAddressImpl,
      .GetOrigin = &EVMHostInterface::getOriginImpl,
      .GetCaller = &EVMHostInterface::getCallerImpl,
      .GetCallValue = &EVMHostInterface::getCallValueImpl,
      .GetGasPrice = &EVMHostInterface::getGasPriceImpl,
      .GetCallDataSize = &EVMHostInterface::getCallDataSizeImpl,
      .GetCodeSize = &EVMHostInterface::getCodeSizeImpl};
  return Table;
}

intx::uint256
EVMHostInterface::getAddressImpl(zen::runtime::EVMInstance *Instance) {
  ZEN_ASSERT(Instance);
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);

  evmc_tx_context TxContext = Module->Host->get_tx_context();
  return intx::be::load<intx::uint256>(TxContext.tx_origin);
}

intx::uint256
EVMHostInterface::getOriginImpl(zen::runtime::EVMInstance *Instance) {
  ZEN_ASSERT(Instance);
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);

  evmc_tx_context TxContext = Module->Host->get_tx_context();
  return intx::be::load<intx::uint256>(TxContext.tx_origin);
}

intx::uint256
EVMHostInterface::getCallerImpl(zen::runtime::EVMInstance *Instance) {
  ZEN_ASSERT(Instance);
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);

  const evmc_message *Msg = Instance->getCurrentMessage();
  ZEN_ASSERT(Msg && "No current message set in EVMInstance");
  return intx::be::load<intx::uint256>(Msg->sender);
}

intx::uint256
EVMHostInterface::getCallValueImpl(zen::runtime::EVMInstance *Instance) {
  ZEN_ASSERT(Instance);
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);

  const evmc_message *Msg = Instance->getCurrentMessage();
  ZEN_ASSERT(Msg && "No current message set in EVMInstance");
  return intx::be::load<intx::uint256>(Msg->value);
}

intx::uint256
EVMHostInterface::getGasPriceImpl(zen::runtime::EVMInstance *Instance) {
  ZEN_ASSERT(Instance);
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);

  evmc_tx_context TxContext = Module->Host->get_tx_context();
  return intx::be::load<intx::uint256>(TxContext.tx_gas_price);
}

uint64_t
EVMHostInterface::getCallDataSizeImpl(zen::runtime::EVMInstance *Instance) {
  ZEN_ASSERT(Instance);
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module && Module->Host);

  const evmc_message *Msg = Instance->getCurrentMessage();
  ZEN_ASSERT(Msg && "No current message set in EVMInstance");
  return Msg->input_size;
}

uint64_t
EVMHostInterface::getCodeSizeImpl(zen::runtime::EVMInstance *Instance) {
  ZEN_ASSERT(Instance);
  const zen::runtime::EVMModule *Module = Instance->getModule();
  ZEN_ASSERT(Module);

  return Module->CodeSize;
}

 
} // namespace COMPILER
