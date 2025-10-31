/*
 * Copyright (C) 2019 Intel Corporation.
 * Copyright (C) 2021-2023 the DTVM authors.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "entrypoint/entrypoint.h"
#include "common/errors.h"
#include "common/type.h"
#ifdef ZEN_ENABLE_EVM
#include "runtime/evm_instance.h"
#endif // ZEN_ENABLE_EVM
#include "runtime/instance.h"

namespace zen::entrypoint {

using namespace common;
using namespace runtime;

constexpr const uint32_t MaxIntRegs = 6;
constexpr const uint32_t MaxFloatRegs = 8;

void callNativeGeneral(Instance *Instance, GenericFunctionPointer FuncPtr,
                       const std::vector<TypedValue> &Args,
                       std::vector<TypedValue> &Results, SysMemPool *MPool,
                       bool SkipInstanceProcessing) {
  uint64_t ArgvBuf[32] = {0};
  uint64_t *ArgvNative = ArgvBuf;

  uint64_t ArgcNative = 1 + MaxFloatRegs * 2 + uint32_t(Args.size()) * 2;
  if (ArgcNative > sizeof(ArgvBuf) / sizeof(uint64_t)) {
    ArgvNative =
        static_cast<uint64_t *>(MPool->allocate(sizeof(uint64_t) * ArgcNative));
    ZEN_ASSERT(ArgvNative);
  }

  uint32_t NumIntArgs = 0;   // number of used integer registers
  uint32_t NumFpArgs = 0;    // number of used float registers
  uint32_t NumStackArgs = 0; // number of used stack cell

  V128 *Fps = (V128 *)ArgvNative;                    // store float registers
  uint64_t *Ints = (uint64_t *)(Fps + MaxFloatRegs); // store integer registers
  uint64_t *Stacks = Ints + MaxIntRegs; // store extra args in stack

  if (Instance) {
    Ints[NumIntArgs++] = (uint64_t)(uintptr_t)Instance;
  } else {
    SkipInstanceProcessing = true;
  }

  for (size_t I = 0; I < Args.size(); ++I) {
    const auto &Value = Args[I].Value;
    switch (Args[I].Type) {
    case WASMType::I32: {
      if (NumIntArgs < MaxIntRegs) {
        std::memcpy(Ints + NumIntArgs, &Value.I32, sizeof(int32_t));
        NumIntArgs++;
      } else {
        std::memcpy(Stacks + NumStackArgs, &Value.I32, sizeof(int32_t));
        NumStackArgs++;
      }
      break;
    }
    case WASMType::I64: {
      if (NumIntArgs < MaxIntRegs) {
        std::memcpy(Ints + NumIntArgs, &Value.I64, sizeof(int64_t));
        NumIntArgs++;
      } else {
        std::memcpy(Stacks + NumStackArgs, &Value.I64, sizeof(int64_t));
        NumStackArgs++;
      }
      break;
    }
    case WASMType::F32: {
      if (NumFpArgs < MaxFloatRegs) {
        std::memcpy(Fps + NumFpArgs, &Value.F32, sizeof(float));
        NumFpArgs++;
      } else {
        std::memcpy(Stacks + NumStackArgs, &Value.F32, sizeof(float));
        NumStackArgs++;
      }
      break;
    }
    case WASMType::F64: {
      if (NumFpArgs < MaxFloatRegs) {
        std::memcpy(Fps + NumFpArgs, &Value.F64, sizeof(double));
        NumFpArgs++;
      } else {
        std::memcpy(Stacks + NumStackArgs, &Value.F64, sizeof(double));
        NumStackArgs++;
      }
      break;
    }
    default:
      ZEN_ASSERT_TODO();
    }
  }

  if (Instance) {
    Instance->getRuntime()->startCPUTracing();
  }

  if (Results.empty()) {
    callNative_Void(FuncPtr, ArgvNative, NumStackArgs, SkipInstanceProcessing);
  } else {
    UntypedValue &Value = Results[0].Value;
    switch (Results[0].Type) {
    case WASMType::I32:
      Value.I32 = callNative_Int32(FuncPtr, ArgvNative, NumStackArgs,
                                   SkipInstanceProcessing);
      break;
    case WASMType::I64:
      Value.I64 = callNative_Int64(FuncPtr, ArgvNative, NumStackArgs,
                                   SkipInstanceProcessing);
      break;
    case WASMType::F32:
      Value.F32 = callNativeFloat32(FuncPtr, ArgvNative, NumStackArgs,
                                    SkipInstanceProcessing);
      break;
    case WASMType::F64:
      Value.F64 = callNativeFloat64(FuncPtr, ArgvNative, NumStackArgs,
                                    SkipInstanceProcessing);
      break;
    default:
      ZEN_ASSERT_TODO();
    }
  }

  if (Instance) {
    Instance->getRuntime()->endCPUTracing();
  }

  if (ArgcNative > sizeof(ArgvBuf) / sizeof(uint64_t)) {
    MPool->deallocate(ArgvNative);
  }
}

#ifdef ZEN_ENABLE_EVM
void callNativeGeneral(EVMInstance *Instance, GenericFunctionPointer FuncPtr,
                       SysMemPool *MPool, bool SkipInstanceProcessing) {

  uint64_t ArgvBuf[32] = {0};
  uint64_t *ArgvNative = ArgvBuf;

  uint64_t ArgcNative = 1 + MaxFloatRegs * 2;
  if (ArgcNative > sizeof(ArgvBuf) / sizeof(uint64_t)) {
    ArgvNative =
        static_cast<uint64_t *>(MPool->allocate(sizeof(uint64_t) * ArgcNative));
    ZEN_ASSERT(ArgvNative);
  }

  uint32_t NumIntArgs = 0;   // number of used integer registers
  uint32_t NumStackArgs = 0; // number of used stack cell

  V128 *Fps = (V128 *)ArgvNative;                    // store float registers
  uint64_t *Ints = (uint64_t *)(Fps + MaxFloatRegs); // store integer registers

  if (Instance) {
    Ints[NumIntArgs++] = (uint64_t)(uintptr_t)Instance;
  } else {
    SkipInstanceProcessing = true;
  }

  if (Instance) {
    Instance->getRuntime()->startCPUTracing();
  }
  callNative_Void(FuncPtr, ArgvNative, NumStackArgs, SkipInstanceProcessing);

  if (Instance) {
    Instance->getRuntime()->endCPUTracing();
  }

  if (ArgcNative > sizeof(ArgvBuf) / sizeof(uint64_t)) {
    MPool->deallocate(ArgvNative);
  }
}
#endif // ZEN_ENABLE_EVM

} // namespace zen::entrypoint
