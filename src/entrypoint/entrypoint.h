/*
 * Copyright (C) 2019 Intel Corporation.
 * Copyright (C) 2021-2023 the DTVM authors.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef ZEN_ENTRYPOINT_ENTRYPOINT_H
#define ZEN_ENTRYPOINT_ENTRYPOINT_H

#include "common/defines.h"
#include "common/mem_pool.h"
#include <vector>

extern "C" {
typedef void (*GenericFunctionPointer)();
void callNative(GenericFunctionPointer F, uint64_t *Args, uint64_t NumStackArgs,
                bool SkipInstanceProcessing);
void callNative_end();

typedef double (*Float64FuncPtr)(GenericFunctionPointer, uint64_t *, uint64_t,
                                 bool);
typedef float (*Float32FuncPtr)(GenericFunctionPointer, uint64_t *, uint64_t,
                                bool);
typedef int64_t (*Int64FuncPtr)(GenericFunctionPointer, uint64_t *, uint64_t,
                                bool);
typedef int32_t (*Int32FuncPtr)(GenericFunctionPointer, uint64_t *, uint64_t,
                                bool);
typedef void (*VoidFuncPtr)(GenericFunctionPointer, uint64_t *, uint64_t, bool);
}

static volatile Float64FuncPtr callNativeFloat64 =
    (Float64FuncPtr)(uintptr_t)callNative;
static volatile Float32FuncPtr callNativeFloat32 =
    (Float32FuncPtr)(uintptr_t)callNative;
static volatile Int64FuncPtr callNative_Int64 =
    (Int64FuncPtr)(uintptr_t)callNative;
static volatile Int32FuncPtr callNative_Int32 =
    (Int32FuncPtr)(uintptr_t)callNative;
static volatile VoidFuncPtr callNative_Void =
    (VoidFuncPtr)(uintptr_t)callNative;

namespace zen {

namespace common {
struct TypedValue;
} // namespace common

namespace runtime {
class Instance;
class EVMInstance;
} // namespace runtime

namespace entrypoint {

void callNativeGeneral(runtime::Instance *Instance,
                       GenericFunctionPointer FuncPtr,
                       const std::vector<common::TypedValue> &Args,
                       std::vector<common::TypedValue> &Results,
                       common::SysMemPool *MPool,
                       bool SkipInstProcessing = false);

void callNativeGeneral(runtime::EVMInstance *Instance,
                       GenericFunctionPointer FuncPtr,
                       common::SysMemPool *MPool,
                       bool SkipInstanceProcessing = false);

} // namespace entrypoint
} // namespace zen

#endif // ZEN_ENTRYPOINT_ENTRYPOINT_H
