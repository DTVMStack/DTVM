// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "zetaengine-c.h"
#include "evmc/evmc.hpp"
#include "zetaengine.h"

static inline zen::common::WASMType getWASMType(ZenType Type) {
  using WASMType = zen::common::WASMType;
  switch (Type) {
  case ZenTypeI32:
    return WASMType::I32;
  case ZenTypeI64:
    return WASMType::I64;
  case ZenTypeF32:
    return WASMType::F32;
  case ZenTypeF64:
    return WASMType::F64;
  }
  ZEN_UNREACHABLE();
}

static inline ZenType getZenType(zen::common::WASMType Type) {
  using WASMType = zen::common::WASMType;
  switch (Type) {
  case WASMType::I32:
    return ZenTypeI32;
  case WASMType::I64:
    return ZenTypeI64;
  case WASMType::F32:
    return ZenTypeF32;
  case WASMType::F64:
    return ZenTypeF64;
  default:
    ZEN_UNREACHABLE();
  }
}

static void copyArgsIn(const ZenValue InArgs[], uint32_t NumInArgs,
                       std::vector<zen::common::TypedValue> &Args) {
  Args.resize(NumInArgs);

  for (uint32_t I = 0; I < NumInArgs; ++I) {
    const ZenValue &InArg = InArgs[I];
    zen::common::TypedValue &Arg = Args[I];
    Arg.Type = getWASMType(InArg.Type);
    switch (InArg.Type) {
    case ZenTypeI32:
      Arg.Value.I32 = InArg.Value.I32;
      break;
    case ZenTypeI64:
      Arg.Value.I64 = InArg.Value.I64;
      break;
    case ZenTypeF32:
      Arg.Value.F32 = InArg.Value.F32;
      break;
    case ZenTypeF64:
      Arg.Value.F64 = InArg.Value.F64;
      break;
    default:
      ZEN_UNREACHABLE();
    }
  }
}

static void copyResultsOut(const std::vector<zen::common::TypedValue> &Results,
                           ZenValue OutResults[], uint32_t *NumOutResults) {
  using WASMType = zen::common::WASMType;

  size_t NumResults = Results.size();
  ZEN_ASSERT(NumResults <= UINT32_MAX);
  *NumOutResults = static_cast<uint32_t>(NumResults);

  ZenValue *CurOutResult = OutResults;
  for (const zen::common::TypedValue &Result : Results) {
    CurOutResult->Type = getZenType(Result.Type);
    const zen::common::UntypedValue &ResultValue = Result.Value;
    switch (Result.Type) {
    case WASMType::I32:
      CurOutResult->Value.I32 = ResultValue.I32;
      break;
    case WASMType::I64:
      CurOutResult->Value.I64 = ResultValue.I64;
      break;
    case WASMType::F32:
      CurOutResult->Value.F32 = ResultValue.F32;
      break;
    case WASMType::F64:
      CurOutResult->Value.F64 = ResultValue.F64;
      break;
    default:
      ZEN_UNREACHABLE();
    }
    ++CurOutResult;
  }
}

static void setErrBuf(char *ErrBuf, uint32_t ErrBufSize, const char *Str) {
  if (ErrBuf) {
    snprintf(ErrBuf, ErrBufSize, "%s", Str);
  }
}

static void nop() {}

#define DEFINE_CONVERSION_FUNCTIONS(ty, ref)                                   \
  static inline ty *unwrap(ref P) { return reinterpret_cast<ty *>(P); }        \
                                                                               \
  static inline ref wrap(const ty *P) {                                        \
    return reinterpret_cast<ref>(const_cast<ty *>(P));                         \
  }

DEFINE_CONVERSION_FUNCTIONS(zen::runtime::Runtime, ZenRuntimeRef)
DEFINE_CONVERSION_FUNCTIONS(zen::runtime::Module, ZenModuleRef)
DEFINE_CONVERSION_FUNCTIONS(zen::runtime::EVMModule, ZenEVMModuleRef)
DEFINE_CONVERSION_FUNCTIONS(zen::runtime::HostModule, ZenHostModuleRef)
DEFINE_CONVERSION_FUNCTIONS(BuiltinModuleDesc, ZenHostModuleDescRef)
DEFINE_CONVERSION_FUNCTIONS(zen::runtime::Isolation, ZenIsolationRef)
DEFINE_CONVERSION_FUNCTIONS(zen::runtime::Instance, ZenInstanceRef)
DEFINE_CONVERSION_FUNCTIONS(evmc::Host, ZenEVMHostRef)

// ==================== Runtime ====================

ZenRuntimeConfigRef ZenCreateRuntimeConfig(ZenRunMode Mode) {
  auto *Config = reinterpret_cast<ZenRuntimeConfigRef>(
      std::malloc(sizeof(ZenRuntimeConfig)));
  if (!Config) {
    ZEN_ABORT();
  }
  std::memset(Config, 0x0, sizeof(ZenRuntimeConfig));
  Config->Mode = Mode;
  return Config;
}

void ZenDeleteRuntimeConfig(ZenRuntimeConfigRef Config) {
  ZEN_ASSERT(Config);
  std::free(Config);
}

void ZenRuntimeConfigSetWasmMemoryMap(ZenRuntimeConfigRef Config,
                                      bool Enabled) {
  ZEN_ASSERT(Config);
  Config->DisableWasmMemoryMap = !Enabled;
}

ZenRuntimeRef ZenCreateRuntime(ZenRuntimeConfig *Config) {
  zen::runtime::RuntimeConfig NewConfig;
  if (Config) {
    NewConfig.DisableWasmMemoryMap = Config->DisableWasmMemoryMap;
#ifdef ZEN_ENABLE_BUILTIN_WASI
    NewConfig.DisableWASI = Config->DisableWASI;
#endif
    NewConfig.EnableStatistics = Config->EnableStatistics;
    NewConfig.EnableGdbTracingHook = Config->EnableGdbTracingHook;
    using ZenRunModeCPP = zen::common::RunMode;
    switch (Config->Mode) {
    case ZenModeInterp:
      NewConfig.Mode = ZenRunModeCPP::InterpMode;
      break;
    case ZenModeSinglepass:
      NewConfig.Mode = ZenRunModeCPP::SinglepassMode;
      break;
    case ZenModeMultipass:
      NewConfig.Mode = ZenRunModeCPP::MultipassMode;
      break;
    case ZenModeUnknown:
      NewConfig.Mode = ZenRunModeCPP::UnknownMode;
      break;
    }
  }
  auto RT = zen::runtime::Runtime::newRuntime(NewConfig);
  return wrap(RT.release());
}

ZenRuntimeRef ZenCreateEVMRuntime(ZenRuntimeConfig *Config,
                                  ZenEVMHostRef EVMHost) {
  zen::runtime::RuntimeConfig NewConfig;
  if (Config) {
    NewConfig.DisableWasmMemoryMap = Config->DisableWasmMemoryMap;
#ifdef ZEN_ENABLE_BUILTIN_WASI
    NewConfig.DisableWASI = Config->DisableWASI;
#endif
    NewConfig.EnableStatistics = Config->EnableStatistics;
    NewConfig.EnableGdbTracingHook = Config->EnableGdbTracingHook;
    using ZenRunModeCPP = zen::common::RunMode;
    switch (Config->Mode) {
    case ZenModeInterp:
      NewConfig.Mode = ZenRunModeCPP::InterpMode;
      break;
    case ZenModeSinglepass:
      ZEN_ASSERT(false);
      break;
    case ZenModeMultipass:
      NewConfig.Mode = ZenRunModeCPP::MultipassMode;
      break;
    case ZenModeUnknown:
      NewConfig.Mode = ZenRunModeCPP::UnknownMode;
      break;
    }
  }
  auto RT = zen::runtime::Runtime::newEVMRuntime(NewConfig, unwrap(EVMHost));
  return wrap(RT.release());
}

void ZenDeleteRuntime(ZenRuntimeRef Runtime) {
  ZEN_ASSERT(Runtime);
  delete unwrap(Runtime);
}

bool ZenCallWasmMainFunc(ZenRuntimeRef Runtime, ZenInstanceRef Instance,
                         ZenValue OutResults[], uint32_t *NumOutResults) {
  ZEN_ASSERT(Runtime);
  ZEN_ASSERT(Instance);
  zen::runtime::Runtime *RT = unwrap(Runtime);
  zen::runtime::Instance *Inst = unwrap(Instance);

  std::vector<zen::common::TypedValue> Results;
  bool Ret = RT->callWasmMain(*Inst, Results);
  copyResultsOut(Results, OutResults, NumOutResults);
  return Ret;
}

bool ZenCallWasmFuncByName(ZenRuntimeRef Runtime, ZenInstanceRef Instance,
                           const char *FuncName, const char *InArgs[],
                           uint32_t NumInArgs, ZenValue OutResults[],
                           uint32_t *NumOutResults) {
  ZEN_ASSERT(Runtime);
  ZEN_ASSERT(Instance);
  zen::runtime::Runtime *RT = unwrap(Runtime);
  zen::runtime::Instance *Inst = unwrap(Instance);

  std::vector<std::string> Args;
  for (uint32_t I = 0; I < NumInArgs; ++I) {
    Args.emplace_back(InArgs[I]);
  }

  std::vector<zen::common::TypedValue> Results;
  bool Ret = RT->callWasmFunction(*Inst, FuncName, Args, Results);
  ZEN_ASSERT(NumOutResults);
  copyResultsOut(Results, OutResults, NumOutResults);
  return Ret;
}

bool ZenCallWasmFuncByIdx(ZenRuntimeRef Runtime, ZenInstanceRef Instance,
                          uint32_t FuncIdx, const ZenValue InArgs[],
                          uint32_t NumInArgs, ZenValue OutResults[],
                          uint32_t *NumOutResults) {
  ZEN_ASSERT(Runtime);
  ZEN_ASSERT(Instance);
  zen::runtime::Runtime *RT = unwrap(Runtime);
  zen::runtime::Instance *Inst = unwrap(Instance);

  std::vector<zen::common::TypedValue> Args;
  copyArgsIn(InArgs, NumInArgs, Args);

  std::vector<zen::common::TypedValue> Results;
  bool Ret = RT->callWasmFunction(*Inst, FuncIdx, Args, Results);
  ZEN_ASSERT(NumOutResults);
  copyResultsOut(Results, OutResults, NumOutResults);
  return Ret;
}

// ==================== Host Module ====================

ZenHostModuleDescRef
ZenCreateHostModuleDesc(ZenRuntimeRef Runtime, const char *HostModName,
                        const ZenHostFuncDesc HostFuncDescs[],
                        uint32_t NumHostFunctions) {
  ZEN_ASSERT(Runtime);
  zen::runtime::Runtime *RT = unwrap(Runtime);
  BuiltinModuleDesc *ModDesc = new BuiltinModuleDesc();
  ModDesc->_name = HostModName;
  ModDesc->NumFunctions = NumHostFunctions;
  ModDesc->_load_func = reinterpret_cast<decltype(ModDesc->_load_func)>(nop);
  ModDesc->_unload_func =
      reinterpret_cast<decltype(ModDesc->_unload_func)>(nop);
  ModDesc->_init_ctx_func =
      reinterpret_cast<decltype(ModDesc->_init_ctx_func)>(nop);
  ModDesc->_destroy_ctx_func =
      reinterpret_cast<decltype(ModDesc->_destroy_ctx_func)>(nop);
  ModDesc->Functions = reinterpret_cast<NativeFuncDesc *>(
      std::malloc(sizeof(NativeFuncDesc) * NumHostFunctions));
  if (!ModDesc->Functions) {
    ZEN_ABORT();
  }
  for (uint32_t I = 0; I < NumHostFunctions; ++I) {
    const ZenHostFuncDesc &HostFuncDesc = HostFuncDescs[I];
    NativeFuncDesc &FuncDesc = ModDesc->Functions[I];
    FuncDesc._name =
        RT->newSymbol(HostFuncDesc.Name, std::strlen(HostFuncDesc.Name));
    FuncDesc._ptr = HostFuncDesc.Ptr;
    FuncDesc._param_count = HostFuncDesc.NumArgs;
    FuncDesc._ret_count = HostFuncDesc.NumReturns;
    FuncDesc._func_type = reinterpret_cast<zen::common::WASMType *>(
        std::malloc(sizeof(zen::common::WASMType) * HostFuncDesc.NumArgs));
    if (!FuncDesc._func_type) {
      ZEN_ABORT();
    }
    for (uint32_t J = 0; J < HostFuncDesc.NumArgs; ++J) {
      FuncDesc._func_type[J] = getWASMType(HostFuncDesc.ArgTypes[J]);
    }
    for (uint32_t J = 0; J < HostFuncDesc.NumReturns; ++J) {
      FuncDesc._func_type[J + HostFuncDesc.NumArgs] =
          getWASMType(HostFuncDesc.RetTypes[J]);
    }
    FuncDesc._isReserved = false;
  }
  return wrap(ModDesc);
}

void ZenDeleteHostModuleDesc(ZenRuntimeRef Runtime,
                             ZenHostModuleDescRef HostModuleDesc) {
  ZEN_ASSERT(Runtime);
  ZEN_ASSERT(HostModuleDesc);
  zen::runtime::Runtime *RT = unwrap(Runtime);
  BuiltinModuleDesc *ModDesc = unwrap(HostModuleDesc);
  for (uint32_t I = 0; I < ModDesc->NumFunctions; ++I) {
    RT->freeSymbol(ModDesc->Functions[I]._name);
    std::free(ModDesc->Functions[I]._func_type);
  }
  std::free(ModDesc->Functions);
  delete ModDesc;
}

ZenHostModuleRef ZenLoadHostModule(ZenRuntimeRef Runtime,
                                   ZenHostModuleDescRef HostModuleDesc) {
  ZEN_ASSERT(Runtime);
  ZEN_ASSERT(HostModuleDesc);
  zen::runtime::Runtime *RT = unwrap(Runtime);
  BuiltinModuleDesc *Desc = unwrap(HostModuleDesc);
  zen::runtime::HostModule *HostMod = RT->loadHostModule(*Desc);
  if (!HostMod) {
    return nullptr;
  }
  return wrap(HostMod);
}

bool ZenMergeHostModule(ZenRuntimeRef Runtime, ZenHostModuleRef HostModule,
                        ZenHostModuleDescRef OtherHostModuleDesc) {
  ZEN_ASSERT(Runtime);
  ZEN_ASSERT(HostModule);
  ZEN_ASSERT(OtherHostModuleDesc);
  zen::runtime::Runtime *RT = unwrap(Runtime);
  zen::runtime::HostModule *HostMod = unwrap(HostModule);
  BuiltinModuleDesc *OtherDesc = unwrap(OtherHostModuleDesc);
  return RT->mergeHostModule(HostMod, *OtherDesc);
}

bool ZenDeleteHostModule(ZenRuntimeRef Runtime, ZenHostModuleRef HostModule) {
  ZEN_ASSERT(Runtime);
  ZEN_ASSERT(HostModule);
  zen::runtime::Runtime *RT = unwrap(Runtime);
  zen::runtime::HostModule *HostMod = unwrap(HostModule);
  return RT->unloadHostModule(HostMod);
}

bool ZenFilterHostFunctions(ZenHostModuleRef HostModule,
                            const char *FuncNames[], uint32_t NumFuncNames) {
  ZEN_ASSERT(HostModule);
  zen::runtime::HostModule *HostMod = unwrap(HostModule);
  std::vector<zen::common::StringView> NewFuncNames;
  for (uint32_t I = 0; I < NumFuncNames; ++I) {
    NewFuncNames.emplace_back(FuncNames[I]);
  }
  if (!HostMod->filterFunctions(NewFuncNames)) {
    return false;
  }
  return true;
}

// ==================== Module ====================

ZenModuleRef ZenLoadModuleFromFile(ZenRuntimeRef Runtime, const char *Filename,
                                   char *ErrBuf, uint32_t ErrBufSize) {
  ZEN_ASSERT(Runtime);
  zen::runtime::Runtime *RT = unwrap(Runtime);
  auto ModuleOrErr = RT->loadModule(Filename);
  if (!ModuleOrErr) {
    const std::string &ErrMsg = ModuleOrErr.getError().getFormattedMessage();
    setErrBuf(ErrBuf, ErrBufSize, ErrMsg.c_str());
    return nullptr;
  }
  return wrap(*ModuleOrErr);
}

ZenModuleRef ZenLoadModuleFromBuffer(ZenRuntimeRef Runtime,
                                     const char *ModuleName,
                                     const uint8_t *Code, uint32_t CodeSize,
                                     char *ErrBuf, uint32_t ErrBufSize) {
  ZEN_ASSERT(Runtime);
  zen::runtime::Runtime *RT = unwrap(Runtime);
  auto ModuleOrErr = RT->loadModule(ModuleName, Code, CodeSize);
  if (!ModuleOrErr) {
    const std::string &ErrMsg = ModuleOrErr.getError().getFormattedMessage();
    setErrBuf(ErrBuf, ErrBufSize, ErrMsg.c_str());
    return nullptr;
  }
  return wrap(*ModuleOrErr);
}

ZenEVMModuleRef ZenLoadEVMModuleFromBuffer(ZenRuntimeRef Runtime,
                                           const char *ModuleName,
                                           const uint8_t *Code,
                                           uint32_t CodeSize, char *ErrBuf,
                                           uint32_t ErrBufSize) {
  ZEN_ASSERT(Runtime);
  zen::runtime::Runtime *RT = unwrap(Runtime);
  auto ModuleOrErr = RT->loadEVMModule(ModuleName, Code, CodeSize);
  if (!ModuleOrErr) {
    const std::string &ErrMsg = ModuleOrErr.getError().getFormattedMessage();
    setErrBuf(ErrBuf, ErrBufSize, ErrMsg.c_str());
    return nullptr;
  }
  return wrap(*ModuleOrErr);
}

bool ZenDeleteModule(ZenRuntimeRef Runtime, ZenModuleRef Module) {
  ZEN_ASSERT(Runtime);
  ZEN_ASSERT(Module);
  zen::runtime::Runtime *RT = unwrap(Runtime);
  zen::runtime::Module *Mod = unwrap(Module);
  return RT->unloadModule(Mod);
}

bool ZenGetExportFunc(ZenModuleRef Module, const char *FuncName,
                      uint32_t *FuncIdx) {
  ZEN_ASSERT(Module);
  zen::runtime::Module *Mod = unwrap(Module);
  return Mod->getExportFunc(FuncName, *FuncIdx);
}

bool ZenGetImportFuncName(ZenModuleRef Module, uint32_t FuncIdx,
                          char *HostModuleNameOut,
                          uint32_t *HostModuleNameLenOut,
                          uint32_t HostModuleNameOutBufSize, char *FuncNameOut,
                          uint32_t *FuncNameLenOut,
                          uint32_t FuncNameOutBufSize) {
  ZEN_ASSERT(Module);
  zen::runtime::Module *Mod = unwrap(Module);
  if (FuncIdx >= Mod->getNumImportFunctions()) {
    return false;
  }
  auto StringToBuf = [](const char *Str, char *OutBuf, uint32_t *SizeOut,
                        uint32_t BufLimit) {
    if (!Str || !OutBuf || !SizeOut) {
      return false;
    }
    auto StrLen = std::strlen(Str);
    if (StrLen >= BufLimit) {
      return false;
    }
    std::memcpy(OutBuf, Str, StrLen);
    *SizeOut = static_cast<uint32_t>(StrLen);
    return true;
  };
  const auto &ImportFunc = Mod->getImportFunction(FuncIdx);
  auto HostModuleName =
      Mod->getRuntime()->dumpSymbolString(ImportFunc.ModuleName);
  if (!StringToBuf(HostModuleName, HostModuleNameOut, HostModuleNameLenOut,
                   HostModuleNameOutBufSize)) {
    return false;
  }

  auto HostFuncName = Mod->getRuntime()->dumpSymbolString(ImportFunc.FieldName);
  if (!StringToBuf(HostFuncName, FuncNameOut, FuncNameLenOut,
                   FuncNameOutBufSize)) {
    return false;
  }
  return true;
}

uint32_t ZenGetNumImportFunctions(ZenModuleRef Module) {
  ZEN_ASSERT(Module);
  zen::runtime::Module *Mod = unwrap(Module);
  return Mod->getNumImportFunctions();
}

// ==================== Isolation ====================

ZenIsolationRef ZenCreateIsolation(ZenRuntimeRef Runtime) {
  zen::runtime::Runtime *RT = unwrap(Runtime);
  zen::runtime::Isolation *Iso = RT->createManagedIsolation();
  return wrap(Iso);
}

bool ZenDeleteIsolation(ZenRuntimeRef Runtime, ZenIsolationRef Isolation) {
  ZEN_ASSERT(Runtime);
  ZEN_ASSERT(Isolation);
  zen::runtime::Runtime *RT = unwrap(Runtime);
  zen::runtime::Isolation *Iso = unwrap(Isolation);
  return RT->deleteManagedIsolation(Iso);
}

// ==================== Instance ====================

ZenInstanceRef ZenCreateInstance(ZenIsolationRef Isolation, ZenModuleRef Module,
                                 char *ErrBuf, uint32_t ErrBufSize) {
  ZEN_ASSERT(Isolation);
  ZEN_ASSERT(Module);
  zen::runtime::Isolation *Iso = unwrap(Isolation);
  zen::runtime::Module *Mod = unwrap(Module);
  auto InstOrErr = Iso->createInstance(*Mod);
  if (!InstOrErr) {
    const std::string &ErrMsg = InstOrErr.getError().getFormattedMessage();
    setErrBuf(ErrBuf, ErrBufSize, ErrMsg.c_str());
    return nullptr;
  }
  return wrap(*InstOrErr);
}

ZenInstanceRef ZenCreateInstanceWithGas(ZenIsolationRef Isolation,
                                        ZenModuleRef Module, uint64_t GasLimit,
                                        char *ErrBuf, uint32_t ErrBufSize) {
  ZEN_ASSERT(Isolation);
  ZEN_ASSERT(Module);
  zen::runtime::Isolation *Iso = unwrap(Isolation);
  zen::runtime::Module *Mod = unwrap(Module);
  auto InstOrErr = Iso->createInstance(*Mod, GasLimit);
  if (!InstOrErr) {
    const std::string &ErrMsg = InstOrErr.getError().getFormattedMessage();
    setErrBuf(ErrBuf, ErrBufSize, ErrMsg.c_str());
    return nullptr;
  }
  return wrap(*InstOrErr);
}

bool ZenDeleteInstance(ZenIsolationRef Isolation, ZenInstanceRef Instance) {
  ZEN_ASSERT(Isolation);
  ZEN_ASSERT(Instance);
  zen::runtime::Isolation *Iso = unwrap(Isolation);
  zen::runtime::Instance *Inst = unwrap(Instance);
  return Iso->deleteInstance(Inst);
}

ZenRuntimeRef ZenGetRuntimeFromInstance(ZenInstanceRef Instance) {
  ZEN_ASSERT(Instance);
  zen::runtime::Instance *Inst = unwrap(Instance);
  zen::runtime::Runtime *RT = Inst->getRuntime();
  return wrap(RT);
}

bool ZenGetInstanceError(ZenInstanceRef Instance, char *ErrBuf,
                         uint32_t ErrBufSize) {
  ZEN_ASSERT(Instance);
  zen::runtime::Instance *Inst = unwrap(Instance);
  if (!Inst->hasError()) {
    return false;
  }
  const std::string &ErrMsg = Inst->getError().getFormattedMessage();
  setErrBuf(ErrBuf, ErrBufSize, ErrMsg.c_str());
  return true;
}

void ZenClearInstanceError(ZenInstanceRef Instance) {
  ZEN_ASSERT(Instance);
  zen::runtime::Instance *Inst = unwrap(Instance);
  Inst->clearError();
}

bool ZenValidateHostMemAddr(ZenInstanceRef Instance, void *HostAddr,
                            uint32_t Size) {
  ZEN_ASSERT(Instance);
  zen::runtime::Instance *Inst = unwrap(Instance);
  return Inst->validatedNativeAddr(reinterpret_cast<uint8_t *>(HostAddr), Size);
}

bool ZenValidateAppMemAddr(ZenInstanceRef Instance, uint32_t Offset,
                           uint32_t Size) {
  ZEN_ASSERT(Instance);
  zen::runtime::Instance *Inst = unwrap(Instance);
  return Inst->validatedAppAddr(Offset, Size);
}

void *ZenGetHostMemAddr(ZenInstanceRef Instance, uint32_t Offset) {
  ZEN_ASSERT(Instance);
  zen::runtime::Instance *Inst = unwrap(Instance);
  return Inst->getNativeMemoryAddr(Offset);
}

uint32_t ZenGetAppMemOffset(ZenInstanceRef Instance, void *HostAddr) {
  ZEN_ASSERT(Instance);
  zen::runtime::Instance *Inst = unwrap(Instance);
  return Inst->getMemoryOffset(HostAddr);
}

void ZenSetInstanceCustomData(ZenInstanceRef Instance, void *CustomData) {
  ZEN_ASSERT(Instance);
  zen::runtime::Instance *Inst = unwrap(Instance);
  Inst->setCustomData(CustomData);
}

void *ZenGetInstanceCustomData(ZenInstanceRef Instance) {
  ZEN_ASSERT(Instance);
  zen::runtime::Instance *Inst = unwrap(Instance);
  return Inst->getCustomData();
}

uint64_t ZenGetInstanceGasLeft(ZenInstanceRef Instance) {
  ZEN_ASSERT(Instance);
  zen::runtime::Instance *Inst = unwrap(Instance);
  return Inst->getGas();
}

void ZenSetInstanceGasLeft(ZenInstanceRef Instance, uint64_t NewGas) {
  ZEN_ASSERT(Instance);
  zen::runtime::Instance *Inst = unwrap(Instance);
  Inst->setGas(NewGas);
}

void ZenSetInstanceExceptionByHostapi(ZenInstanceRef Instance,
                                      uint32_t ErrorCode) {
  ZEN_ASSERT(Instance);
  zen::runtime::Instance *Inst = unwrap(Instance);
  auto ErrOpt = zen::common::getErrorOrNone((zen::common::ErrorCode)ErrorCode);
  if (ErrOpt.has_value()) {
    Inst->setExceptionByHostapi(ErrOpt.value());
  } else {
    Inst->exit((int32_t)ErrorCode);
  }
}

uint32_t ZenGetErrCodeEnvAbort() {
  return (uint32_t)zen::common::ErrorCode::EnvAbort;
}
uint32_t ZenGetErrCodeGasLimitExceeded() {
  return (uint32_t)zen::common::ErrorCode::GasLimitExceeded;
}
uint32_t ZenGetErrCodeOutOfBoundsMemory() {
  return (uint32_t)zen::common::ErrorCode::OutOfBoundsMemory;
}

void ZenInstanceExit(ZenInstanceRef Instance, int32_t ExitCode) {
  ZEN_ASSERT(Instance);
  zen::runtime::Instance *Inst = unwrap(Instance);
  Inst->exit(ExitCode);
}

int32_t ZenGetInstanceExitCode(ZenInstanceRef Instance) {
  ZEN_ASSERT(Instance);
  zen::runtime::Instance *Inst = unwrap(Instance);
  return Inst->getExitCode();
}

void ZenInstanceProtectMemoryAgain(ZenInstanceRef Instance) {
  ZEN_ASSERT(Instance);
  zen::runtime::Instance *Inst = unwrap(Instance);
  Inst->protectMemoryAgain();
}

// ==================== Others ====================

void ZenEnableLogging() {
  static std::shared_ptr<zen::utils::ILogger> Logger =
      zen::utils::createConsoleLogger("zen_c_api_logger",
                                      zen::utils::LoggerLevel::Trace);
  zen::setGlobalLogger(Logger);
}

void ZenDisableLogging() { zen::setGlobalLogger(nullptr); }
