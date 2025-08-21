// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef EVM_FRONTEND_EVM_IMPORTED_H
#define EVM_FRONTEND_EVM_IMPORTED_H

#include "intx/intx.hpp"
#include <cstdint>

namespace zen::runtime {
class EVMInstance;
} // namespace zen::runtime

namespace COMPILER {

using U256Fn = intx::uint256 (*)(zen::runtime::EVMInstance *);
using Bytes32Fn = const uint8_t *(*)(zen::runtime::EVMInstance *);
using SizeFn = uint64_t (*)(zen::runtime::EVMInstance *);

struct RuntimeFunctions {
  Bytes32Fn GetAddress;
  Bytes32Fn GetOrigin;
  Bytes32Fn GetCaller;
  Bytes32Fn GetCallValue;
  U256Fn GetGasPrice;
  SizeFn GetCallDataSize;
  SizeFn GetCodeSize;
};

const RuntimeFunctions &getRuntimeFunctionTable();

template <typename FuncType> uint64_t getFunctionAddress(FuncType Func) {
  return reinterpret_cast<uint64_t>(Func);
}

const uint8_t *evmGetAddress(zen::runtime::EVMInstance *Instance);
const uint8_t *evmGetOrigin(zen::runtime::EVMInstance *Instance);
const uint8_t *evmGetCaller(zen::runtime::EVMInstance *Instance);
const uint8_t *evmGetCallValue(zen::runtime::EVMInstance *Instance);
intx::uint256 evmGetGasPrice(zen::runtime::EVMInstance *Instance);
uint64_t evmGetCallDataSize(zen::runtime::EVMInstance *Instance);
uint64_t evmGetCodeSize(zen::runtime::EVMInstance *Instance);

} // namespace COMPILER

#endif // EVM_FRONTEND_EVM_IMPORTED_H
