// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef EVM_FRONTEND_EVM_HOST_INTERFACE_H
#define EVM_FRONTEND_EVM_HOST_INTERFACE_H

#include "intx/intx.hpp"
#include <cstddef>
#include <cstdint>

namespace zen {
namespace runtime {
class EVMInstance;
} // namespace runtime
} // namespace zen

namespace evmc {
class Host;
} // namespace evmc

struct evmc_message;
struct evmc_tx_context;

namespace COMPILER {

class EVMHostInterface {
public:
  using AddressFn = intx::uint256 (*)(zen::runtime::EVMInstance *);
  using SizeFn = uint64_t (*)(zen::runtime::EVMInstance *);

  // Function dispatch table for JIT compilation
  struct HostFunctions {
    AddressFn GetAddress;
    AddressFn GetOrigin;
    AddressFn GetCaller;
    AddressFn GetCallValue;
    AddressFn GetGasPrice;
    SizeFn GetCallDataSize;
    SizeFn GetCodeSize;
  };

  // Get function addresses for JIT compilation
  static const HostFunctions &getFunctionTable();

  // Template-based function address getter
  template <typename FuncType>
  static uint64_t getFunctionAddress(FuncType Func) {
    return reinterpret_cast<uint64_t>(Func);
  }

private:
  static intx::uint256 getAddressImpl(zen::runtime::EVMInstance *Instance);
  static intx::uint256 getOriginImpl(zen::runtime::EVMInstance *Instance);
  static intx::uint256 getCallerImpl(zen::runtime::EVMInstance *Instance);
  static intx::uint256 getCallValueImpl(zen::runtime::EVMInstance *Instance);
  static intx::uint256 getGasPriceImpl(zen::runtime::EVMInstance *Instance);
  static uint64_t getCallDataSizeImpl(zen::runtime::EVMInstance *Instance);
  static uint64_t getCodeSizeImpl(zen::runtime::EVMInstance *Instance);
};

} // namespace COMPILER

#endif // EVM_FRONTEND_EVM_HOST_INTERFACE_H
