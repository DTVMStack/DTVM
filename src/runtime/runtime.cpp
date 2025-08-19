// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "runtime/runtime.h"

#ifdef ZEN_ENABLE_CPU_EXCEPTION
#include <csetjmp>
#include <csignal>
#include <pthread.h>
#endif // ZEN_ENABLE_CPU_EXCEPTION

#include "action/interpreter.h"
#include "common/type.h"
#include "entrypoint/entrypoint.h"
#include "evm/interpreter.h"
#include "runtime/codeholder.h"
#include "runtime/evm_instance.h"
#include "runtime/instance.h"
#include "runtime/isolation.h"
#include "runtime/module.h"
#include "runtime/symbol_wrapper.h"
#include "utils/logging.h"
#include "utils/others.h"
#include "utils/statistics.h"
#ifdef ZEN_ENABLE_VIRTUAL_STACK
#include "utils/virtual_stack.h"
#endif
#include <evmc/hex.hpp>
#include <fstream>
#include <string_view>
#include <unistd.h>

namespace zen::runtime {

using namespace common;
using namespace utils;

void Runtime::cleanRuntime() {

  Isolations.clear();

  HostModulePool.clear();

  ModulePool.clear();

  EVMModulePool.clear();

  SymbolPool.destroyPool();

#ifdef ZEN_ENABLE_BUILTIN_WASI
  if (_argv_buf)
    deallocate(_argv_buf);
  if (_argv_list)
    deallocate(_argv_list);
  if (_env_buf)
    deallocate(_env_buf);
  if (_env_list)
    deallocate(_env_list);
  if (_dirs_buf)
    deallocate(_dirs_buf);
  if (_dirs_list)
    deallocate(_dirs_list);
#endif
}

HostModule *Runtime::loadHostModule(BuiltinModuleDesc &ModDesc) noexcept {
  const char *ModName = ModDesc._name;
  if (!ModName || !std::strlen(ModName)) {
    ZEN_LOG_ERROR("empty host module name");
    return nullptr;
  }

  WASMSymbol Name = newSymbol(ModName, std::strlen(ModName));
  if (auto It = HostModulePool.find(Name); It != HostModulePool.end()) {
    return It->second.get();
  }

  if (HostModule *RawMod = resolveHostModule(Name); RawMod) {
    return RawMod;
  }

  HostModuleUniquePtr Mod;
  try {
    Mod = HostModule::newModule(*this, &ModDesc);
  } catch (const Error &Err) {
    const auto &ErrMsg = Err.getFormattedMessage();
    ZEN_LOG_ERROR(ErrMsg.c_str());
    return nullptr;
  }

  HostModule *RawMod = Mod.get();
  RawMod->setName(Name);

  auto EmplaceRet =
      HostModulePool.emplace(Name, std::forward<HostModuleUniquePtr>(Mod));
  if (EmplaceRet.second) {
    return EmplaceRet.first->second.get();
  }

  return nullptr;
}

bool Runtime::mergeHostModule(HostModule *HostMod,
                              BuiltinModuleDesc &OtherHostModDesc) noexcept {
  uint32_t NumHostFunctions = 0;
  const NativeFuncDesc *HostFuncDescs;

  // Judge if the host module is registered by C API
  if (OtherHostModDesc.Functions) {
    HostFuncDescs = OtherHostModDesc.Functions;
    NumHostFunctions = OtherHostModDesc.NumFunctions;
  } else {
    HostFuncDescs =
        OtherHostModDesc._load_func(HostMod->getVNMIEnv(), NumHostFunctions);
  }

  if (!HostFuncDescs) {
    ZEN_LOG_ERROR("failed to load host function array");
    return false;
  }

  try {
    HostMod->addFunctions(&OtherHostModDesc, HostFuncDescs, NumHostFunctions);
  } catch (const Error &Err) {
    OtherHostModDesc._unload_func(HostMod->getVNMIEnv(),
                                  const_cast<NativeFuncDesc *>(HostFuncDescs));
    const auto &ErrMsg = Err.getFormattedMessage();
    ZEN_LOG_ERROR(ErrMsg.c_str());
    return false;
  }

  return true;
}

bool Runtime::unloadHostModule(HostModule *HostMod) noexcept {
  ZEN_ASSERT(HostMod);
  const char *ModName = HostMod->getModuleDesc()->_name;
  WASMSymbol Name = probeSymbol(ModName, std::strlen(ModName));
  return HostModulePool.erase(Name) != 0;
}

HostModule *Runtime::resolveHostModule(WASMSymbol Name) const {
  if (Name == WASM_SYMBOL_wasi_unstable) {
    Name = WASM_SYMBOL_wasi_snapshot_preview1;
  }
  auto It = HostModulePool.find(Name);
  if (It != HostModulePool.end()) {
    return It->second.get();
  }

  return nullptr;
}

MayBe<Module *> Runtime::loadModule(const std::string &Filename,
                                    const std::string &EntryHint) noexcept {
  if (Filename.empty()) {
    return getError(ErrorCode::InvalidFilePath);
  }

  WASMSymbol Name = newSymbol(Filename.c_str(), Filename.size());
  if (auto It = ModulePool.find(Name); It != ModulePool.end()) {
    return It->second.get();
  }

  try {
    auto Code = CodeHolder::newFileCodeHolder(*this, Filename);
    return loadModule(Name, std::move(Code), EntryHint);
  } catch (const Error &Err) {
    Stats.clearAllTimers();
    freeSymbol(Name);
    return Err;
  }
}

MayBe<Module *> Runtime::loadModule(const std::string &ModName,
                                    const void *Data, size_t Size,
                                    const std::string &EntryHint) noexcept {
  if (ModName.empty() || !Data || !Size) {
    return getError(ErrorCode::InvalidRawData);
  }

  WASMSymbol Name = newSymbol(ModName.c_str(), ModName.size());
  if (auto It = ModulePool.find(Name); It != ModulePool.end()) {
    return It->second.get();
  }

  try {
    auto Code = CodeHolder::newRawDataCodeHolder(*this, Data, Size);
    return loadModule(Name, std::move(Code), EntryHint);
  } catch (const Error &Err) {
    Stats.clearAllTimers();
    freeSymbol(Name);
    return Err;
  }
}

// Before executing this function, it is necessary to ensure that name is unique
Module *Runtime::loadModule(WASMSymbol Name, CodeHolderUniquePtr CodeHolder,
                            const std::string &EntryHint) {
  ZEN_ASSERT(Name);
  ZEN_ASSERT(CodeHolder);

  ModuleUniquePtr Mod =
      Module::newModule(*this, std::move(CodeHolder), EntryHint);
  // All errors in Module::newModule are thrown as exceptions, so the return
  // value must be valid when the following line is executed
  ZEN_ASSERT(Mod);
  auto *ModulePtr = Mod.get();
  ModulePtr->setName(Name);

  // Ignore the return value, because the name is unique(checked in above)
  auto EmplaceRet =
      ModulePool.emplace(Name, std::forward<ModuleUniquePtr>(Mod));
  if (EmplaceRet.second) {
    return EmplaceRet.first->second.get();
  }

  return ModulePtr;
}

MayBe<EVMModule *>
Runtime::loadEVMModule(const std::string &Filename) noexcept {
  if (Filename.empty()) {
    return getError(ErrorCode::InvalidFilePath);
  }

  WASMSymbol Name = newSymbol(Filename.c_str(), Filename.size());
  if (auto It = EVMModulePool.find(Name); It != EVMModulePool.end()) {
    return It->second.get();
  }

  try {
    // Read hex content from file
    std::ifstream File(Filename);
    if (!File.is_open()) {
      return getError(ErrorCode::FileAccessFailed);
    }

    std::string HexContent((std::istreambuf_iterator<char>(File)),
                           std::istreambuf_iterator<char>());
    File.close();
    // trim HexContent
    utils::trimString(HexContent);

    // Decode hex string to bytes
    auto DecodedBytes = utils::fromHex(std::string_view(HexContent));
    if (!DecodedBytes.has_value()) {
      return getError(ErrorCode::InvalidRawData);
    }

    // Create CodeHolder with decoded bytes
    auto Code = CodeHolder::newRawDataCodeHolder(*this, DecodedBytes->data(),
                                                 DecodedBytes->size());
    return loadEVMModule(Name, std::move(Code));
  } catch (const Error &Err) {
    Stats.clearAllTimers();
    freeSymbol(Name);
    return Err;
  } catch (const std::exception &StdErr) {
    Stats.clearAllTimers();
    freeSymbol(Name);
    return getError(ErrorCode::FileAccessFailed);
  }
}

MayBe<EVMModule *> Runtime::loadEVMModule(const std::string &ModName,
                                          const void *Data,
                                          size_t Size) noexcept {
  if (ModName.empty() || !Data || !Size) {
    return getError(ErrorCode::InvalidRawData);
  }

  EVMSymbol Name = newSymbol(ModName.c_str(), ModName.size());
  if (auto It = EVMModulePool.find(Name); It != EVMModulePool.end()) {
    return It->second.get();
  }

  try {
    auto Code = CodeHolder::newRawDataCodeHolder(*this, Data, Size);
    return loadEVMModule(Name, std::move(Code));
  } catch (const Error &Err) {
    Stats.clearAllTimers();
    freeSymbol(Name);
    return Err;
  }
}

// Before executing this function, it is necessary to ensure that name is unique
EVMModule *Runtime::loadEVMModule(EVMSymbol Name,
                                  CodeHolderUniquePtr CodeHolder) {
  ZEN_ASSERT(Name);
  ZEN_ASSERT(CodeHolder);

  EVMModuleUniquePtr Mod =
      EVMModule::newEVMModule(*this, std::move(CodeHolder));
  // All errors in Module::newModule are thrown as exceptions, so the return
  // value must be valid when the following line is executed
  ZEN_ASSERT(Mod);
  auto *ModulePtr = Mod.get();
  ModulePtr->setName(Name);

  // Ignore the return value, because the name is unique(checked in above)
  auto EmplaceRet =
      EVMModulePool.emplace(Name, std::forward<EVMModuleUniquePtr>(Mod));
  if (EmplaceRet.second) {
    return EmplaceRet.first->second.get();
  }

  return ModulePtr;
}

bool Runtime::unloadModule(const Module *Mod) noexcept {
  WASMSymbol Name = Mod->getName();
  return ModulePool.erase(Name) != 0;
}

bool Runtime::unloadEVMModule(const EVMModule *Mod) noexcept {
  EVMSymbol Name = Mod->getName();
  return EVMModulePool.erase(Name) != 0;
}

Isolation *Runtime::createManagedIsolation() noexcept {
  IsolationUniquePtr Iso = createUnmanagedIsolation();
  if (!Iso) {
    return nullptr;
  }

  Isolation *RawIso = Iso.get();
  common::LockGuard<common::Mutex> Lock(Mtx);
  auto EmplaceRet =
      Isolations.emplace(RawIso, std::forward<IsolationUniquePtr>(Iso));
  if (!EmplaceRet.second) {
    return nullptr;
  }

  return EmplaceRet.first->second.get();
}

bool Runtime::deleteManagedIsolation(Isolation *Iso) noexcept {
  ZEN_ASSERT(Iso);
  common::LockGuard<common::Mutex> Lock(Mtx);
  return Isolations.erase(Iso) != 0;
}

IsolationUniquePtr Runtime::createUnmanagedIsolation() noexcept {
  return Isolation::newIsolation(*this);
}

static bool checkWASIStartFuncType(TypeEntry *Type) {
  return Type && Type->NumParams == 0 && Type->NumReturns == 0;
}

static bool checkMainFuncType(TypeEntry *Type) {
  if (!Type || !(Type->NumParams == 0 || Type->NumParams == 2) ||
      Type->NumReturns > 1) {
    return false;
  }
  const WASMType *ParamTypes = Type->getParamTypes();
  if (Type->NumParams == 2 &&
      !(ParamTypes[0] == WASMType::I32 && ParamTypes[1] == WASMType::I32)) {
    return false;
  }
  if (Type->NumReturns && Type->ReturnTypes[0] != WASMType::I32) {
    return false;
  }
  return true;
}

bool Runtime::callWasmMain(Instance &Inst, std::vector<TypedValue> &Results) {
  const Module *Mod = Inst.getModule();
  uint32_t FuncIdx;
  if (Mod->getExportFunc("_start", FuncIdx)) {
    TypeEntry *Type = Mod->getFunctionType(FuncIdx);
    if (!checkWASIStartFuncType(Type)) {
      Inst.setError(getErrorWithExtraMessage(ErrorCode::UnexpectedFuncType,
                                             "of wasi '_start' function"));
      ZEN_LOG_ERROR("invalid wasi _start function type");
      return false;
    }
    return callWasmFunction(Inst, FuncIdx, {}, Results);
  }
  if (Mod->getExportFunc("main", FuncIdx) ||
      Mod->getExportFunc("__main_argc_argv", FuncIdx) ||
      Mod->getExportFunc("_main", FuncIdx)) {
    TypeEntry *Type = Mod->getFunctionType(FuncIdx);
    if (!checkMainFuncType(Type)) {
      Inst.setError(getErrorWithExtraMessage(ErrorCode::UnexpectedFuncType,
                                             "of 'main' function"));
      ZEN_LOG_ERROR("invalid main function type");
      return false;
    }
    if (Type->NumParams == 2) {
      std::vector<TypedValue> MainFnArgs{
          TypedValue(0, WASMType::I32),
          TypedValue(0, WASMType::I32),
      };
      return callWasmFunction(Inst, FuncIdx, MainFnArgs, Results);
    }
    return callWasmFunction(Inst, FuncIdx, {}, Results);
  }
  Inst.setError(getErrorWithExtraMessage(ErrorCode::CannotFindFunction,
                                         "wasi '_start' or 'main'"));
  ZEN_LOG_ERROR("wasi '_start' or 'main' function not found");
  return false;
}

bool Runtime::callWasmFunction(Instance &Inst, const std::string &FuncName,
                               const std::vector<std::string> &Args,
                               std::vector<TypedValue> &Results) {
  const Module *Mod = Inst.getModule();

  uint32_t FuncIdx;

  if (!Mod->getExportFunc(FuncName, FuncIdx)) {
    Inst.setError(getErrorWithExtraMessage(ErrorCode::CannotFindFunction,
                                           '"' + FuncName + '"'));
    ZEN_LOG_ERROR("cannot find function '%s'", FuncName.c_str());
    return false;
  }

  FunctionInstance &Func = *Inst.getFunctionInst(FuncIdx);
  uint16_t NumParams = Func.NumParams;
  if (Args.size() != NumParams) {
    Inst.setError(common::getError(ErrorCode::UnexpectedNumArgs));
    ZEN_LOG_ERROR("unexpected number of function arguments");
    return false;
  }
  std::vector<TypedValue> NumericArgs(NumParams);
  for (uint32_t I = 0; I < NumParams; ++I) {
    WASMType Type = Func.getLocalType(I);
    NumericArgs[I].Type = Type;
    UntypedValue &Val = NumericArgs[I].Value;
    try {
      switch (Type) {
      case WASMType::I32: {
        int64_t I32 = static_cast<int64_t>(std::stoul(Args[I], nullptr, 0));
        if (I32 > UINT_MAX) {
          throw std::out_of_range("out of range");
        }
        Val.I32 = I32;
        break;
      }
      case WASMType::I64: {
        Val.I64 = static_cast<int64_t>(std::stoull(Args[I], nullptr, 0));
        break;
      }
      case WASMType::F32: {
        Val.F32 = std::stof(Args[I]);
        break;
      }
      case WASMType::F64: {
        Val.F64 = std::stod(Args[I]);
        break;
      }
      default:
        ZEN_ASSERT_TODO();
      }
    } catch (const std::invalid_argument &Exception) {
      Inst.setError(common::getError(ErrorCode::InvalidArgument));
      ZEN_LOG_ERROR("function arguments conversion failed");
      return false;
    } catch (const std::out_of_range &Exception) {
      Inst.setError(common::getError(ErrorCode::ArgOutOfRange));
      ZEN_LOG_ERROR("function arguments out of range");
      return false;
    }
  }

  return callWasmFunction(Inst, FuncIdx, NumericArgs, Results);
}

#ifdef ZEN_ENABLE_VIRTUAL_STACK
static void callWasmFuncFromVirtualStack(VirtualStackInfo *StackInfo) {
  // check stack once
  static uint8_t CheckDwasmStackResult = checkDwasmStackEnough();
  ZEN_ASSERT(CheckDwasmStackResult == 7);
  Instance *Inst = StackInfo->SavedInst;
  uint32_t FuncIdx = StackInfo->SavedFuncIdx;
  const std::vector<TypedValue> *Args = StackInfo->SavedArgs;
  std::vector<TypedValue> *Results = StackInfo->SavedResults;
  Inst->getRuntime()->callWasmFunctionOnPhysStack(*Inst, FuncIdx, *Args,
                                                  *Results);
}
#endif

void Runtime::callWasmFunctionOnPhysStack(
    Instance &Inst, uint32_t FuncIdx, const std::vector<TypedValue> &Args,
    std::vector<common::TypedValue> &Results) noexcept {
  if (getConfig().Mode == RunMode::InterpMode) {
    callWasmFunctionInInterpMode(Inst, FuncIdx, Args, Results);
  } else {
#ifdef ZEN_ENABLE_JIT
    callWasmFunctionInJITMode(Inst, FuncIdx, Args, Results);
#else
    ZEN_UNREACHABLE();
#endif
  }
}

bool Runtime::callWasmFunction(Instance &Inst, uint32_t FuncIdx,
                               const std::vector<TypedValue> &Args,
                               std::vector<TypedValue> &Results) {
#ifdef ZEN_ENABLE_DWASM
  // dwasm disabled hostapi to call wasm function
  // hostapi prolog in dwasm will mark the WasmInstance's in hostapi flag
  // and the hostapi epilog in dwasm will unmark the flag.
  // So Runtime::callWasmFunction just check the flag
  if (Inst.inHostAPI()) {
    ZEN_LOG_ERROR("hostapi can't call wasm function in DWASM spec\n");
    Inst.setExecutionError(
        common::getError(ErrorCode::DWasmInvalidHostApiCallWasm), 1);
    return false;
  }
#endif

  // Check if the function arguments match the expected types
  FunctionInstance *Func = Inst.getFunctionInst(FuncIdx);
  if (!Func) {
    Inst.setError(getErrorWithExtraMessage(ErrorCode::CannotFindFunction,
                                           std::to_string(FuncIdx)));
    ZEN_LOG_ERROR("cannot find function %u", FuncIdx);
    return false;
  }
  if (Args.size() != Func->NumParams) {
    Inst.setError(common::getError(ErrorCode::UnexpectedNumArgs));
    ZEN_LOG_ERROR("unexpected number of arguments for function %u", FuncIdx);
    return false;
  }
  for (uint32_t I = 0; I < Func->NumParams; ++I) {
    if (Args[I].Type != Func->getLocalType(I)) {
      Inst.setError(common::getError(ErrorCode::UnexpectedArgType));
      ZEN_LOG_ERROR("unexpected argument type for function %u", FuncIdx);
      return false;
    }
  }

  // Prepare slots to receive the return values.
  ZEN_ASSERT(Results.empty());
  uint32_t NumReturns = Func->NumReturns;
  Results.resize(NumReturns);
  for (uint32_t I = 0; I < NumReturns; ++I) {
    Results[I].Type = Func->ReturnTypes[I];
  }

  auto Timer = Stats.startRecord(utils::StatisticPhase::Execution);

  Inst.protectMemory();

#ifdef ZEN_ENABLE_VIRTUAL_STACK
  VirtualStackInfo StackInfo(&Inst, FuncIdx, &Args, &Results);
  StackInfo.runInVirtualStack(&callWasmFuncFromVirtualStack);
#else
  callWasmFunctionOnPhysStack(Inst, FuncIdx, Args, Results);
#endif // !ZEN_ENABLE_VIRTUAL_STACK

  Stats.stopRecord(Timer);

  const Error &Err = Inst.getError();
  ErrorCode ErrCode = Err.getCode();
  if (ErrCode != ErrorCode::NoError) {
    if (ErrCode == ErrorCode::InstanceExit) {
      Inst.clearError();
    } else {
#ifdef ZEN_ENABLE_DUMP_CALL_STACK
      if (Config.Mode == RunMode::SinglepassMode ||
          Config.Mode == RunMode::MultipassMode) {
        Inst.dumpCallStackOnJIT();
      }
#endif
      return false;
    }
  }

  return true;
}

void Runtime::callWasmFunctionInInterpMode(Instance &Inst, uint32_t FuncIdx,
                                           const std::vector<TypedValue> &Args,
                                           std::vector<TypedValue> &Results) {
  using namespace action;
  RuntimeObjectUniquePtr<InterpStack> Stack =
      InterpStack::newInterpStack(*this, PresetReservedStackSize);
  InterpreterExecContext Context(&Inst, Stack.get());
  uint8_t *Bottom = Stack->top();

  for (const TypedValue &Arg : Args) {
    const UntypedValue &Val = Arg.Value;
    switch (Arg.Type) {
    case WASMType::I32: {
      Stack->push<int32_t>(Val.I32);
      break;
    }
    case WASMType::I64: {
      Stack->push<int64_t>(Val.I64);
      break;
    }
    case WASMType::F32: {
      Stack->push<float>(Val.F32);
      break;
    }
    case WASMType::F64: {
      Stack->push<double>(Val.F64);
      break;
    }
    default:
      ZEN_ASSERT_TODO();
    }
  }

  BaseInterpreter Interpreter(Context);
  FunctionInstance *Func = Inst.getFunctionInst(FuncIdx);
  InterpFrame *Frame = Context.allocFrame(Func, (uint32_t *)Bottom);
  ZEN_ASSERT(Frame != nullptr);

  Inst.getRuntime()->startCPUTracing();
  try {
    Interpreter.interpret();
  } catch (const Error &Err) {
    Inst.getRuntime()->endCPUTracing();
    Inst.setError(Err);
    return;
  }
  Inst.getRuntime()->endCPUTracing();

  for (TypedValue &Result : Results) {
    UntypedValue &Val = Result.Value;
    switch (Result.Type) {
    case WASMType::I32: {
      Val.I32 = *(int32_t *)Bottom;
      Bottom += sizeof(int32_t);
      break;
    }
    case WASMType::I64: {
      Val.I64 = *(int64_t *)Bottom;
      Bottom += sizeof(int64_t);
      break;
    }
    case WASMType::F32: {
      Val.F32 = *(float *)Bottom;
      Bottom += sizeof(float);
      break;
    }
    case WASMType::F64: {
      Val.F64 = *(double *)Bottom;
      Bottom += sizeof(double);
      break;
    }
    default:
      ZEN_ASSERT_TODO();
    }
  }
}

void Runtime::callEVMInInterpMode(EVMInstance &Inst,
                                  std::vector<uint8_t> &Result) {
  evm::InterpreterExecContext Ctx(&Inst);
  evm::BaseInterpreter Interpreter(Ctx);
  evmc_message Msg = {
      .kind = EVMC_CALL,
      .flags = 0,
      .depth = 0,
      .gas = static_cast<int64_t>(Inst.getGas() >> 1), // to avoid overflow
  };
  Ctx.allocFrame(&Msg); // TODO: use the correct message
  Interpreter.interpret();
  Result = Ctx.getReturnData();
}

void Runtime::callEVMMain(EVMInstance &Inst, std::vector<uint8_t> &Result) {
  if (getConfig().Mode == RunMode::InterpMode) {
    callEVMInInterpMode(Inst, Result);
  } else {
#ifdef ZEN_ENABLE_JIT
    callEVMInJITMode(Inst, Result);
#else
    ZEN_UNREACHABLE();
#endif
  }
}

#ifdef ZEN_ENABLE_JIT
void Runtime::callWasmFunctionInJITMode(Instance &Inst, uint32_t FuncIdx,
                                        const std::vector<TypedValue> &Args,
                                        std::vector<TypedValue> &Results) {
  FunctionInstance *Func = Inst.getFunctionInst(FuncIdx);
  Inst.setJITStackSize(PresetReservedStackSize);
  bool IsImport = FuncIdx < Inst.getModule()->getNumImportFunctions();
  auto FuncPtr =
      GenericFunctionPointer(IsImport ? Func->CodePtr : Func->JITCodePtr);

#ifdef ZEN_ENABLE_CPU_EXCEPTION
  jmp_buf JmpBuf;
  common::traphandler::CallThreadState TLS(&Inst, &JmpBuf,
                                           __builtin_frame_address(0), nullptr);

  // longjmp with asan(in gcc-9) not works well, it affects the asan stack
  // malloc. so use wrapper func to recover the stack
  auto CallWasmFnWrapper = [&]() {
    int JmpSignum = ::setjmp(JmpBuf);
    if (JmpSignum == 0) {
      TLS.restartHandler();

#endif // ZEN_ENABLE_CPU_EXCEPTION

      entrypoint::callNativeGeneral(&Inst, FuncPtr, Args, Results,
                                    this->getMemAllocator());

#ifdef ZEN_ENABLE_CPU_EXCEPTION
    } else { // When cpu-exception
      // NoError means not need capture trap state
      ErrorCode CapturedTapErrCode = ErrorCode::NoError;
      switch (JmpSignum) {
      case SIGFPE: {
        // divide by zero signal
        CapturedTapErrCode = ErrorCode::IntegerDivByZero;
        break;
      }
      case SIGSEGV:
      case SIGBUS: {
        // out of bounds signal
        CapturedTapErrCode = ErrorCode::OutOfBoundsMemory;
#ifdef ZEN_ENABLE_STACK_CHECK_CPU
        // when the accessed address in virtual stack, raise CallStackExhausted
        auto *FaultingAddress =
            static_cast<uint8_t *>(TLS.getTrapState().FaultingAddress);
#ifdef ZEN_ENABLE_VIRTUAL_STACK
        auto *VirtualStack = Inst.currentVirtualStack();
        if (FaultingAddress != nullptr && VirtualStack) {
          if (FaultingAddress >= VirtualStack->AllInfo &&
              FaultingAddress < VirtualStack->StackMemoryTop) {
            CapturedTapErrCode = ErrorCode::CallStackExhausted;
          }
        }
#else

#ifdef ZEN_BUILD_PLATFORM_DARWIN
        // on darwin get stack info
        void *StackAddr = pthread_get_stackaddr_np(pthread_self());
        size_t StackSize = pthread_get_stacksize_np(pthread_self());
#else
        // on linux get stack info
        pthread_attr_t Attrs;
        pthread_getattr_np(pthread_self(), &Attrs);

        void *StackAddr;
        size_t StackSize;
        pthread_attr_getstack(&Attrs, &StackAddr, &StackSize);
#endif

        size_t GuardSize =
            common::StackGuardSize; // stack overflow guard, when overflow not
                                    // in dwasm, not greater then StackGuardSize
                                    // bytes
        if ((uintptr_t)FaultingAddress >= (uintptr_t)StackAddr - GuardSize &&
            (uintptr_t)FaultingAddress < ((uintptr_t)StackAddr + StackSize)) {
          CapturedTapErrCode = ErrorCode::CallStackExhausted;
        }
#ifndef ZEN_BUILD_PLATFORM_DARWIN
        pthread_attr_destroy(&Attrs);
#endif // ZEN_BUILD_PLATFORM_DARWIN

#endif // ZEN_ENABLE_VIRTUAL_STACK

#endif // ZEN_ENABLE_STACK_CHECK_CPU
        break;
      }
      default: {
        // SIGILL not process here. the traces set by Instance::setException
        break;
      }
      }
      if (Inst.getError().getCode() == ErrorCode::GasLimitExceeded) {
        Inst.setGas(0);
      } else if (Config.Mode == RunMode::SinglepassMode) {
        // restore gas left from register when trap in singlepass JIT mode
        Inst.setGas(TLS.getGasRegisterValue());
      }
      if (CapturedTapErrCode != ErrorCode::NoError) {
        const auto &TrapState = TLS.getTrapState();
        Inst.setExecutionError(common::getError(CapturedTapErrCode),
                               TrapState.NumIgnoredFrames, TrapState);
      }
    }
  };
  CallWasmFnWrapper();
#endif // ZEN_ENABLE_CPU_EXCEPTION
}

void Runtime::callEVMInJITMode(EVMInstance &Inst,
                               std::vector<uint8_t> &Result) {
  // TODO: Implement EVM JIT compilation and execution
  // For now, fallback to interpreter mode as placeholder
  callEVMInInterpMode(Inst, Result);
}
#endif // ZEN_ENABLE_JIT

void Runtime::startCPUTracing() {
  if (!Config.EnableGdbTracingHook) {
    return;
  }
  // tools/gdb_trace will add breakpoint in this line, when this file changed,
  // update gdb_trace.py
  constexpr char BeginCpuTracingHook[] = "__begin_cpu_tracing__\n";
  // use syscall write not printf, so in qemu log, we can direct capture the
  // correct position when executing wasm function
  if ((sizeof(BeginCpuTracingHook) - 1) !=
      os_write(1, BeginCpuTracingHook, sizeof(BeginCpuTracingHook) - 1)) {
    ZEN_ABORT();
  }
}

void Runtime::endCPUTracing() {
  if (!Config.EnableGdbTracingHook) {
    return;
  }
  constexpr char EndCpuTracingHook[] = "__end_cpu_tracing__\n";
  // use syscall write not printf, so in qemu log, we can direct capture the
  // correct position when executing wasm function
  if ((sizeof(EndCpuTracingHook) - 1) !=
      os_write(1, EndCpuTracingHook, sizeof(EndCpuTracingHook) - 1)) {
    ZEN_ABORT();
  }
  // end the wasm function execution directly, so the tracing log will not too
  // many
  ::_exit(0);
}

} // namespace zen::runtime
