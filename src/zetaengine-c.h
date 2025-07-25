// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_ZETAENGINE_C_H
#define ZEN_ZETAENGINE_C_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  ZenTypeI32 = 0,
  ZenTypeI64 = 1,
  ZenTypeF32 = 2,
  ZenTypeF64 = 3,
} ZenType;

typedef struct ZenValue {
  ZenType Type;
  union {
    int32_t I32;
    int64_t I64;
    float F32;
    double F64;
  } Value;
} ZenValue;

typedef enum {
  ZenModeInterp = 0,
  ZenModeSinglepass = 1,
  ZenModeMultipass = 2,
  ZenModeUnknown = 3,
} ZenRunMode;

typedef struct ZenRuntimeConfig {
  // Run mode
  ZenRunMode Mode;
  // Disable mmap to allocate wasm memory
  bool DisableWasmMemoryMap;
  // Disable WASI(only takes effect when ZEN_ENABLE_BUILTIN_WASI is ON)
  bool DisableWASI;
  // Open statistics(compilation time/execution time)
  bool EnableStatistics;
  // Enable cpu instruction tracer hook
  bool EnableGdbTracingHook;
} ZenRuntimeConfig;

typedef struct ZenRuntimeConfig *ZenRuntimeConfigRef;
typedef struct ZenOpaqueRuntime *ZenRuntimeRef;
typedef struct ZenOpaqueModule *ZenModuleRef;
typedef struct ZenOpaqueEVMModule *ZenEVMModuleRef;
typedef struct ZenOpaqueHostModuleDesc *ZenHostModuleDescRef;
typedef struct ZenOpaqueHostModule *ZenHostModuleRef;
typedef struct ZenOpaqueIsolation *ZenIsolationRef;
typedef struct ZenOpaqueInstance *ZenInstanceRef;
typedef struct ZenOpaqueEVMHost *ZenEVMHostRef;

// ==================== Runtime ====================

ZenRuntimeConfigRef ZenCreateRuntimeConfig(ZenRunMode Mode);

void ZenDeleteRuntimeConfig(ZenRuntimeConfigRef Config);

void ZenRuntimeConfigSetWasmMemoryMap(ZenRuntimeConfigRef Config, bool Enabled);

ZenRuntimeRef ZenCreateRuntime(ZenRuntimeConfig *Config);

ZenRuntimeRef ZenCreateEVMRuntime(ZenRuntimeConfig *Config,
                                  ZenEVMHostRef EVMHost);

void ZenDeleteRuntime(ZenRuntimeRef Runtime);

bool ZenCallWasmMainFunc(ZenRuntimeRef Runtime, ZenInstanceRef Instance,
                         ZenValue OutResults[], uint32_t *NumOutResults);

bool ZenCallWasmFuncByName(ZenRuntimeRef Runtime, ZenInstanceRef Instance,
                           const char *FuncName, const char *InArgs[],
                           uint32_t NumInArgs, ZenValue OutResults[],
                           uint32_t *NumOutResults);

bool ZenCallWasmFuncByIdx(ZenRuntimeRef Runtime, ZenInstanceRef Instance,
                          uint32_t FuncIdx, const ZenValue InArgs[],
                          uint32_t NumInArgs, ZenValue OutResults[],
                          uint32_t *NumOutResults);

// ==================== Host Module ====================

typedef struct ZenHostFuncDesc {
  const char *Name;
  uint32_t NumArgs;
  const ZenType *ArgTypes;
  uint32_t NumReturns;
  const ZenType *RetTypes;
  void *Ptr;
} ZenHostFuncDesc;

/// \warning not thread-safe
ZenHostModuleDescRef
ZenCreateHostModuleDesc(ZenRuntimeRef Runtime, const char *HostModName,
                        const ZenHostFuncDesc HostFuncDescs[],
                        uint32_t NumHostFunctions);

/// \warning not thread-safe
void ZenDeleteHostModuleDesc(ZenRuntimeRef Runtime,
                             ZenHostModuleDescRef HostModuleDesc);

/// \warning not thread-safe
ZenHostModuleRef ZenLoadHostModule(ZenRuntimeRef Runtime,
                                   ZenHostModuleDescRef HostModuleDesc);

/// \warning not thread-safe
bool ZenMergeHostModule(ZenRuntimeRef Runtime, ZenHostModuleRef HostModule,
                        ZenHostModuleDescRef OtherHostModuleDesc);

/// \warning not thread-safe
bool ZenDeleteHostModule(ZenRuntimeRef Runtime, ZenHostModuleRef HostModule);

/// \warning not thread-safe
bool ZenFilterHostFunctions(ZenHostModuleRef HostModule,
                            const char *FuncNames[], uint32_t NumFuncNames);

// ==================== Module ====================

/// \warning not thread-safe
ZenModuleRef ZenLoadModuleFromFile(ZenRuntimeRef Runtime, const char *Filename,
                                   char *ErrBuf, uint32_t ErrBufSize);

/// \warning not thread-safe
ZenModuleRef ZenLoadModuleFromBuffer(ZenRuntimeRef Runtime,
                                     const char *ModuleName,
                                     const uint8_t *Code, uint32_t CodeSize,
                                     char *ErrBuf, uint32_t ErrBufSize);

/// \warning not thread-safe
ZenEVMModuleRef ZenLoadEVMModuleFromBuffer(ZenRuntimeRef Runtime,
                                           const char *ModuleName,
                                           const uint8_t *Code,
                                           uint32_t CodeSize, char *ErrBuf,
                                           uint32_t ErrBufSize);

/// \warning not thread-safe
bool ZenDeleteModule(ZenRuntimeRef Runtime, ZenModuleRef Module);

bool ZenGetExportFunc(ZenModuleRef Module, const char *FuncName,
                      uint32_t *FuncIdx);

bool ZenGetImportFuncName(ZenModuleRef Module, uint32_t FuncIdx,
                          char *HostModuleNameOut,
                          uint32_t *HostModuleNameLenOut,
                          uint32_t HostModuleNameOutBufSize, char *FuncNameOut,
                          uint32_t *FuncNameLenOut,
                          uint32_t FuncNameOutBufSize);

uint32_t ZenGetNumImportFunctions(ZenModuleRef Module);

// ==================== Isolation ====================

ZenIsolationRef ZenCreateIsolation(ZenRuntimeRef Runtime);

bool ZenDeleteIsolation(ZenRuntimeRef Runtime, ZenIsolationRef Isolation);

// ==================== Instance ====================

ZenInstanceRef ZenCreateInstance(ZenIsolationRef Isolation, ZenModuleRef Module,
                                 char *ErrBuf, uint32_t ErrBufSize);

ZenInstanceRef ZenCreateInstanceWithGas(ZenIsolationRef Isolation,
                                        ZenModuleRef Module, uint64_t GasLimit,
                                        char *ErrBuf, uint32_t ErrBufSize);

bool ZenDeleteInstance(ZenIsolationRef Isolation, ZenInstanceRef Instance);

ZenRuntimeRef ZenGetRuntimeFromInstance(ZenInstanceRef Instance);

/// \return true if the instance has an error otherwise false
bool ZenGetInstanceError(ZenInstanceRef Instance, char *ErrBuf,
                         uint32_t ErrBufSize);

void ZenClearInstanceError(ZenInstanceRef Instance);

bool ZenValidateHostMemAddr(ZenInstanceRef Instance, void *HostAddr,
                            uint32_t Size);

bool ZenValidateAppMemAddr(ZenInstanceRef Instance, uint32_t Offset,
                           uint32_t Size);

void *ZenGetHostMemAddr(ZenInstanceRef Instance, uint32_t Offset);

uint32_t ZenGetAppMemOffset(ZenInstanceRef Instance, void *HostAddr);

void ZenSetInstanceCustomData(ZenInstanceRef Instance, void *CustomData);

void *ZenGetInstanceCustomData(ZenInstanceRef Instance);

uint64_t ZenGetInstanceGasLeft(ZenInstanceRef Instance);

void ZenSetInstanceGasLeft(ZenInstanceRef Instance, uint64_t NewGas);

// param ErrorCode: zen::common::ErrorCode
void ZenSetInstanceExceptionByHostapi(ZenInstanceRef Instance,
                                      uint32_t ErrorCode);

uint32_t ZenGetErrCodeEnvAbort();
uint32_t ZenGetErrCodeGasLimitExceeded();
uint32_t ZenGetErrCodeOutOfBoundsMemory();

void ZenInstanceExit(ZenInstanceRef Instance, int32_t ExitCode);
int32_t ZenGetInstanceExitCode(ZenInstanceRef Instance);

// wasm instance enabled by default
// but after call some child instance, the parent maybe not active
// need enable it again
void ZenInstanceProtectMemoryAgain(ZenInstanceRef Instance);

// ==================== Others ====================

// Warning: these two function can only be called for testing purpose, please
// don't use them in production.
void ZenEnableLogging();
void ZenDisableLogging();

#ifdef __cplusplus
} // extern "C"
#endif

#endif // ZEN_ZETAENGINE_C_H
