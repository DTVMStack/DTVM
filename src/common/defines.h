// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_COMMON_DEFINES_H
#define ZEN_COMMON_DEFINES_H

#include "platform/platform.h"

#ifdef NDEBUG
#define ZEN_ABORT() abort()
#define ZEN_ASSERT(x)                                                          \
  if (!(x))                                                                    \
  ::abort()
#define ZEN_ASSERT_TODO() ::abort()
#define ZEN_STATIC_ASSERT(x) static_assert(x)
#define ZEN_UNREACHABLE() ::abort()
#else
#define ZEN_ABORT() assert(false)
#define ZEN_ASSERT(x) assert(x)
#define ZEN_ASSERT_TODO() assert(false && "not implemented yet")
#define ZEN_STATIC_ASSERT(x) static_assert(x)
#define ZEN_UNREACHABLE() assert(false)
#endif // NDEBUG

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

#if __has_builtin(__builtin_expect) || defined(__GNUC__)
#define ZEN_LIKELY(EXPR) __builtin_expect((bool)(EXPR), true)
#define ZEN_UNLIKELY(EXPR) __builtin_expect((bool)(EXPR), false)
#else
#define ZEN_LIKELY(EXPR) (EXPR)
#define ZEN_UNLIKELY(EXPR) (EXPR)
#endif

#define ZEN_ALIGN(VALUE, ALIGNMENT)                                            \
  ((VALUE + ALIGNMENT - 1) & (~(ALIGNMENT - 1)))

#define SELF (static_cast<T &>(*this))
#define SELF_CONST (static_cast<const T &>(*this))

#define MAX_TRACE_LENGTH 16
#define MAX_NATIVE_FUNC_SIZE 0x800
#define JIT_FUNCTION_NAME_PREFIX "function_"

#define NONCOPYABLE(C)                                                         \
  C(C const &) = delete;                                                       \
  C &operator=(C const &) = delete

#define NONASSIGNABLE(C) C &operator=(C const &) = delete
namespace zen {

using WASMSymbol = uint32_t;
using EVMSymbol = uint32_t;

namespace common {

/// \brief WebAssembly preset limit values
constexpr uint32_t DefaultBytesNumPerPage = 65536;
constexpr uint64_t MaxLinearMemSize = (0x1ull << 32);
constexpr uint32_t MaxLinearMemPageCount =
    (MaxLinearMemSize / DefaultBytesNumPerPage);
constexpr uint32_t DefaultTableMaxSize = 10240;

constexpr uint32_t WasmMagicNumber = 0x6d736100; // "\0asm"
constexpr uint32_t WasmVersion = 0x1;
// At most one memory is allowed in MVP
constexpr size_t PresetMaxNumMemories = 1;
// At most one table is allowed in MVP
constexpr size_t PresetMaxNumTables = 1;

// when protect stack overflow by cpu trap(no dwasm mode), leave guard memory in
// stack
constexpr int64_t StackGuardSize = 16384;

#ifdef ZEN_ENABLE_DWASM
constexpr size_t PresetMaxModuleSize = 16 * 1024 * 1024; // 16MB

constexpr size_t PresetMaxNumTypes = 10240;
constexpr size_t PresetMaxNumImports = 10240;
constexpr size_t PresetMaxNumFunctions = 10240;
constexpr size_t PresetMaxNumGlobals = 10240;
constexpr size_t PresetMaxNumExports = 1024;
constexpr size_t PresetMaxNumElemSegments = 10240;
constexpr size_t PresetMaxNumDataSegments = 1024;

constexpr size_t PresetMaxFunctionLocals = 10240;     // uint16_t
constexpr size_t PresetMaxFunctionLocalCells = 10240; // uint16_t
constexpr size_t PresetMaxTableSize = 10240;
constexpr size_t PresetMaxTotalDataSize = 1024 * 1024 * 1024; // 1GB
constexpr size_t PresetMaxNumOpcodesOfFunction = 102400;
constexpr size_t PresetMaxNumSameLevelBlocks = 1024;
constexpr size_t PresetMaxBlockDepth = 1024;
constexpr size_t PresetReservedStackSize = 8 * 1024 * 1024; // 8MB

#define DWASM_DEFAULT_MAX_VM_LINEAR_MEMORY_PAGES 256
#else
constexpr size_t PresetMaxModuleSize = 1024 * 1024 * 1024; // 1GB

constexpr size_t PresetMaxNumTypes = UINT16_MAX;
constexpr size_t PresetMaxNumImports = UINT16_MAX;
constexpr size_t PresetMaxNumFunctions = UINT16_MAX;
constexpr size_t PresetMaxNumGlobals = UINT16_MAX;
constexpr size_t PresetMaxNumExports = UINT16_MAX;
constexpr size_t PresetMaxNumElemSegments = UINT16_MAX;
constexpr size_t PresetMaxNumDataSegments = 1024 * 1024;

constexpr size_t PresetMaxFunctionLocals = UINT16_MAX;     // uint16_t
constexpr size_t PresetMaxFunctionLocalCells = UINT16_MAX; // uint16_t
constexpr size_t PresetMaxTableSize = 1024 * 1024;
constexpr size_t PresetMaxTotalDataSize = 1024 * 1024 * 1024; // 1GB
constexpr size_t PresetReservedStackSize = 4 * 1024 * 1024;   // 4MB
#endif

constexpr size_t PresetMaxSectionSize = 512 * 1024 * 1024; // 512MB
constexpr size_t PresetMaxNameLength = UINT16_MAX;
constexpr size_t PresetMaxNumParams = UINT16_MAX;     // uint16_t
constexpr size_t PresetMaxNumParamCells = UINT16_MAX; // uint16_t
// Multi-value support: allow multiple return values (WASI extension)
// MVP limit: PresetMaxNumReturns = 1
#ifdef ZEN_ENABLE_WASI_MULTI_VALUE
constexpr size_t PresetMaxNumReturns = UINT8_MAX; // uint8_t: 8 bits
#else
// At most one return value in MVP
constexpr size_t PresetMaxNumReturns = 1; // uint8_t: 2 bits
#endif
constexpr size_t PresetMaxNumReturnCells = (1u << 6) - 1; // uint8_t: 6 bits

constexpr size_t PresetMaxMemoryPages = 1u << 16;                // 65536 pages
constexpr size_t PresetMaxFunctionSize = 16 * 1024 * 1024;       // 16MB
constexpr size_t PresetMaxTotalFunctionSize = 512 * 1024 * 1024; // 512MB
constexpr size_t PresetMaxDataSegmentSize = 128 * 1024 * 1024;   // 128MB

} // namespace common

} // namespace zen

#endif // ZEN_COMMON_DEFINES_H
