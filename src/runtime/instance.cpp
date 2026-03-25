// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "runtime/instance.h"

#include "action/instantiator.h"
#include "common/enums.h"
#include "common/errors.h"
#include "common/traphandler.h"
#include "entrypoint/entrypoint.h"
#include "runtime/config.h"
#include <algorithm>

namespace zen::runtime {

using namespace common;

WasmMemoryData MemoryInstance::getWasmMemoryData() {
  return WasmMemoryData{
      .Type = Kind,
      .MemoryData = MemBase,
      .MemorySize = MemSize,
      .NeedMprotect =
          Kind == WasmMemoryDataType::WM_MEMORY_DATA_TYPE_SINGLE_MMAP ||
          Kind == WasmMemoryDataType::WM_MEMORY_DATA_TYPE_BUCKET_MMAP,
  };
}

// If you want to modify this function, please make sure that you have
// understood the alignment requirements
void Module::InstanceLayout::compute() {
  const uint32_t NumFunctions = Mod.getNumTotalFunctions();
  const uint32_t NumGlobals = Mod.getNumTotalGlobals();
  const uint32_t NumTables = Mod.getNumTotalTables();
  const uint32_t NumMemories = Mod.getNumTotalMemories();

  InstanceSize = ZEN_ALIGN(sizeof(Instance), Alignment);
  FuncInstancesSize =
      ZEN_ALIGN(sizeof(FunctionInstance) * NumFunctions, Alignment);
  GlobalInstancesSize =
      ZEN_ALIGN(sizeof(GlobalInstance) * NumGlobals, Alignment);
  GlobalVarSize = ZEN_ALIGN(Mod.GlobalVarSize, Alignment);
  TableInstancesSize = ZEN_ALIGN(sizeof(TableInstance) * NumTables, Alignment);
  TableElemsSize = 0;
  for (size_t I = 0; I < Mod.NumImportTables; ++I) {
    TableElemsSize += Mod.ImportTableTable[I].InitSize * sizeof(uint32_t);
  }
  for (size_t I = 0; I < Mod.NumInternalTables; ++I) {
    TableElemsSize += Mod.InternalTableTable[I].InitSize * sizeof(uint32_t);
  }
  TableElemsSize = ZEN_ALIGN(TableElemsSize, Alignment);
  // at least malloc one memory instance after Instance object
  // because callNative.S will visit Instance::MemoryInstance::_memory_base
  MemoryInstancesSize = ZEN_ALIGN(
      sizeof(MemoryInstance) * (NumMemories > 0 ? NumMemories : 1), Alignment);

  TotalSize = InstanceSize + FuncInstancesSize + GlobalInstancesSize +
              GlobalVarSize + TableInstancesSize + TableElemsSize +
              MemoryInstancesSize;

  GlobalVarBaseOffset = InstanceSize + FuncInstancesSize + GlobalInstancesSize;
  TableElemBaseOffset =
      GlobalVarBaseOffset + GlobalVarSize + TableInstancesSize;
  TableElemSizeOffset =
      GlobalVarBaseOffset + GlobalVarSize + offsetof(TableInstance, CurSize);

  size_t MemoryInstanceOffset = TableElemBaseOffset + TableElemsSize;
  MemoryBaseOffset = MemoryInstanceOffset + offsetof(MemoryInstance, MemBase);
  MemorySizeOffset = MemoryInstanceOffset + offsetof(MemoryInstance, MemSize);
  MemoryPagesOffset = MemoryInstanceOffset + offsetof(MemoryInstance, CurPages);

#ifdef ZEN_ENABLE_JIT
  FuncPtrsSize = ZEN_ALIGN(NumFunctions * sizeof(uintptr_t), Alignment);
  FuncTypeIndexesSize = ZEN_ALIGN(NumFunctions * sizeof(uint32_t), Alignment);
  TotalSize += FuncPtrsSize + FuncTypeIndexesSize;

  FuncPtrsBaseOffset =
      TableElemBaseOffset + TableElemsSize + MemoryInstancesSize;
  FuncTypeIndexesBaseOffset = FuncPtrsBaseOffset + FuncPtrsSize;

  StackBoundaryOffset = offsetof(Instance, JITStackBoundary);
#ifdef ZEN_ENABLE_DUMP_CALL_STACK
  TracesSize = ZEN_ALIGN(MAX_TRACE_LENGTH * sizeof(uint32_t), Alignment);
  TotalSize += TracesSize;
#endif // ZEN_ENABLE_DUMP_CALL_STACK
#endif // ZEN_ENABLE_JIT

  ExceptionOffset = offsetof(Instance, Err.ErrCode);
  GasOffset = offsetof(Instance, Gas);

#ifdef ZEN_ENABLE_DWASM
  StackCostOffset = offsetof(Instance, StackCost);
#endif
}

InstanceUniquePtr Instance::newInstance(Isolation &Iso, const Module &Mod,
                                        uint64_t GasLimit) {
#ifdef ZEN_ENABLE_CPU_EXCEPTION
  [[maybe_unused]] static bool _ =
      common::traphandler::initPlatformTrapHandler();
#endif // ZEN_ENABLE_CPU_EXCEPTION

  const auto &Layout = Mod.Layout;
  Runtime *RT = Mod.getRuntime();
  void *Buf = RT->allocate(Layout.TotalSize, Layout.Alignment);
  ZEN_ASSERT(Buf);

  InstanceUniquePtr Inst(new (Buf) Instance(Mod, *RT));

  Inst->Iso = &Iso;

  Inst->Functions = reinterpret_cast<FunctionInstance *>((uintptr_t)Buf +
                                                         Layout.InstanceSize);
  Inst->Globals = reinterpret_cast<GlobalInstance *>(
      (uintptr_t)Inst->Functions + Layout.FuncInstancesSize);
  Inst->GlobalVarData = reinterpret_cast<uint8_t *>((uintptr_t)Inst->Globals +
                                                    Layout.GlobalInstancesSize);
  Inst->Tables = reinterpret_cast<TableInstance *>(
      (uintptr_t)Inst->GlobalVarData + Layout.GlobalVarSize);
  Inst->Memories = reinterpret_cast<MemoryInstance *>(
      (uintptr_t)Inst->Tables + Layout.TableInstancesSize +
      Layout.TableElemsSize);

#ifdef ZEN_ENABLE_JIT
  Inst->JITFuncPtrs = reinterpret_cast<uintptr_t *>((uintptr_t)Inst->Memories +
                                                    Layout.MemoryInstancesSize);
  Inst->FuncTypeIdxs = reinterpret_cast<uint32_t *>(
      (uintptr_t)Inst->JITFuncPtrs + Layout.FuncPtrsSize);
#ifdef ZEN_ENABLE_DUMP_CALL_STACK
  Inst->Traces = reinterpret_cast<int32_t *>((uintptr_t)Inst->FuncTypeIdxs +
                                             Layout.FuncTypeIndexesSize);
#endif // ZEN_ENABLE_DUMP_CALL_STACK

#endif // ZEN_ENABLE_JIT

  Inst->setGas(GasLimit);

  action::Instantiator Instantiator;
  Instantiator.instantiate(*Inst);

  return Inst;
}

Instance::~Instance() {
#ifdef ZEN_ENABLE_BULK_MEMORY
  // Free dropped segment tracking arrays
  if (DroppedDataSegments) {
    deallocate(DroppedDataSegments);
    DroppedDataSegments = nullptr;
  }
  if (DroppedElemSegments) {
    deallocate(DroppedElemSegments);
    DroppedElemSegments = nullptr;
  }
#endif

  auto *MemAllocator = getWasmMemoryAllocator();
  for (uint32_t I = 0; I < NumTotalMemories; ++I) {
    if (Memories[I].MemBase) {
      MemAllocator->freeWasmMemory(Memories[I].getWasmMemoryData());
      Memories[I].MemBase = nullptr;
      Memories[I].MemEnd = nullptr;
      Memories[I].MemSize = 0;
    }
  }

#ifdef ZEN_ENABLE_BUILTIN_WASI
  // will move the following to other place soon.
  if (WASICtx) {
    Runtime *RT = getRuntime();
    HostModule *HostMod =
        RT->resolveHostModule(common::WASM_SYMBOL_wasi_snapshot_preview1);
    if (!HostMod) {
      return;
    }

    const BuiltinModuleDesc *ModDesc = HostMod->getModuleDesc();
    if (!ModDesc) {
      return;
    }

    ModDesc->_destroy_ctx_func(HostMod->getVNMIEnv(), WASICtx);

    WASICtx = nullptr;
  }
#endif
}

// ==================== Memory Accessing Methods ====================

WasmMemoryAllocator *Instance::getWasmMemoryAllocator() {
  return const_cast<Module *>(Mod)->getMemoryAllocator();
}

void Instance::protectMemory() {
  for (uint32_t MemIdx = 0; MemIdx < NumTotalMemories; ++MemIdx) {
    MemoryInstance *Mem = &Memories[MemIdx];
    if (!Mem->MemBase) {
      continue;
    }

#ifdef ZEN_ENABLE_CPU_EXCEPTION
    auto *TLS = common::traphandler::CallThreadState::current();
    // when not instance call instance, then the bucket is mprotect none
    // before.
    bool UnprotectBucket = TLS != nullptr && TLS->parent() != nullptr;
#else
    bool UnprotectBucket = true;
#endif // ZEN_ENABLE_CPU_EXCEPTION
    getWasmMemoryAllocator()->mprotectReadWriteWasmMemoryData(
        Mem->getWasmMemoryData(), UnprotectBucket);
  }
}

void Instance::protectMemoryAgain() { protectMemory(); }

bool Instance::growLinearMemory(uint32_t MemIdx, uint32_t GrowPagesDelta) {
  if (MemIdx >= NumTotalMemories) {
    return false;
  }

  if (!GrowPagesDelta) {
    return true;
  }

  MemoryInstance *Mem = &Memories[MemIdx];
  uint32_t NewMemPages = Mem->CurPages + GrowPagesDelta;
  if (NewMemPages < Mem->CurPages /* integer overflow */
      || NewMemPages > Mem->MaxPages) {
    return false;
  }

  uint64_t NewMemSize = uint64_t(NewMemPages) * common::DefaultBytesNumPerPage;
  if (NewMemSize >= UINT32_MAX) {
    return false;
  }

  auto *MemAllocator = getWasmMemoryAllocator();

  WasmMemoryData NewMemData = MemAllocator->enlargeWasmMemory(
      WasmMemoryData{
          .Type = Mem->Kind,
          .MemoryData = Mem->MemBase,
          .MemorySize = Mem->MemSize,
          .NeedMprotect = false,
      },
      NewMemSize);
  void *Buf = NewMemData.MemoryData;
  if (!Buf) {
    return false;
  }

  Mem->MemBase = reinterpret_cast<uint8_t *>(Buf);
  Mem->MemEnd = Mem->MemBase + NewMemSize;
  Mem->CurPages = NewMemPages;
  Mem->MemSize = NewMemSize;
  Mem->Kind = NewMemData.Type;

  return true;
}

void *Instance::getNativeMemoryAddr(uint32_t Offset) {
  if (Offset >= Memories[0].MemSize) {
    return nullptr;
  }
  return Memories[0].MemBase + Offset;
}

uint32_t Instance::getMemoryOffset(void *Addr) {
  if (Addr < Memories[0].MemBase ||
      Addr >= Memories[0].MemBase + Memories[0].MemSize) {
    return (uint32_t)-1;
  }
  return (uint8_t *)Addr - Memories[0].MemBase;
}

bool Instance::validatedAppAddr(uint32_t Offset, uint32_t Size) {
  bool Valid = Offset < Memories[0].MemSize && Size <= Memories[0].MemSize &&
               Offset <= Memories[0].MemSize - Size;
  if (!Valid) {
    setExecutionError(common::getError(ErrorCode::OutOfBoundsMemory), 1);
  }
  return Valid;
}

bool Instance::validatedNativeAddr(uint8_t *NativeAddr, uint32_t Size) {
  bool Valid = Memories[0].MemBase <= NativeAddr &&
               Size <= (uintptr_t)Memories[0].MemEnd &&
               NativeAddr <= Memories[0].MemEnd - Size;
  if (!Valid) {
    setExecutionError(common::getError(ErrorCode::OutOfBoundsMemory), 1);
  }
  return Valid;
}

// ==================== Error/Exception Methods ====================

void Instance::setExecutionError(const Error &NewErr, uint32_t IgnoredDepth,
                                 common::traphandler::TrapState TS) {
  ZEN_ASSERT(NewErr.getPhase() == common::ErrorPhase::Execution);

  setError(NewErr);

  if (NewErr.getCode() == ErrorCode::GasLimitExceeded) {
    setGas(0); // gas left
  }

#ifdef ZEN_ENABLE_DUMP_CALL_STACK
  auto Mode = getRuntime()->getConfig().Mode;
  using common::RunMode;
  if (Mode == RunMode::SinglepassMode || Mode == RunMode::MultipassMode) {
    if (NumTraces == 0 &&
        !(NewErr.isEmpty() || NewErr.getCode() == ErrorCode::InstanceExit)) {
      // // jit trace need only set once
      createCallStackOnJIT(IgnoredDepth + 1, TS);
    }
  }
#endif // ZEN_ENABLE_DUMP_CALL_STACK
}

void Instance::exit(int32_t ExitCode) {
  this->InstanceExitCode = ExitCode;
  setExceptionByHostapi(common::getError(ErrorCode::InstanceExit));
}

#ifdef ZEN_ENABLE_JIT

int32_t Instance::growInstanceMemoryOnJIT(Instance *Inst,
                                          uint32_t GrowPagesDelta) {
  uint32_t PrevNumPages = Inst->getDefaultMemoryInst().CurPages;
  ZEN_ASSERT(PrevNumPages < (1U << 31));
  if (Inst->growLinearMemory(0, GrowPagesDelta)) {
    return static_cast<int32_t>(PrevNumPages);
  }
  return -1;
}

void Instance::setInstanceExceptionOnJIT(Instance *Inst,
                                         common::ErrorCode ErrCode) {
  Inst->setExecutionError(common::getError(ErrCode), 1,
                          common::traphandler::TrapState{});
}

void Instance::throwInstanceExceptionOnJIT(Instance *Inst) {
#ifdef ZEN_ENABLE_CPU_EXCEPTION
  SAVE_HOSTAPI_FRAME_POINTER_TO_TLS

  utils::throwCpuIllegalInstructionTrap();
#endif // ZEN_ENABLE_CPU_EXCEPTION
}

void Instance::triggerInstanceExceptionOnJIT(Instance *Inst,
                                             common::ErrorCode ErrCode) {
  // Not use setInstanceExceptionOnJIT instead of the following code, because we
  // need correct `ignored_depth`
  Inst->setExecutionError(common::getError(ErrCode), 1,
                          common::traphandler::TrapState{});

  throwInstanceExceptionOnJIT(Inst);
}

#ifdef ZEN_ENABLE_DUMP_CALL_STACK
void Instance::createCallStackOnJIT(uint32_t IgnoredDepth,
                                    common::traphandler::TrapState TS) {
  void *FrameAddr = __builtin_frame_address(0);
  std::vector<void *> TraceAddrs;

  void *JITCode = Mod->JITCode;
  void *JITCodeEnd = static_cast<uint8_t *>(JITCode) + Mod->JITCodeSize;

  if (TS.Traces) {
    TraceAddrs = *TS.Traces;
  } else {
    TraceAddrs = utils::createBacktraceUntil(
        FrameAddr, nullptr, nullptr, IgnoredDepth,
        reinterpret_cast<void *>(callNative),
        reinterpret_cast<void *>(callNative_end), JITCode, JITCodeEnd);
  }

  for (size_t I = 0; I < TraceAddrs.size(); ++I) {
    void *RetAddr = TraceAddrs[I];
    // traces maybe from trap handler, so need check again
    if (RetAddr >= reinterpret_cast<void *>(callNative) &&
        RetAddr < reinterpret_cast<void *>(callNative_end)) {
      break;
    }
    int32_t FuncIdx = getFuncIndexByAddrOnJIT(RetAddr);
    Traces[NumTraces++] = FuncIdx;
  }
}

int32_t Instance::getFuncIndexByAddrOnJIT(void *Addr) {
  using common::RunMode;
  // find from internal functions
  RunMode Mode = getRuntime()->getConfig().Mode;
  void *JITCode = Mod->JITCode;
  void *JITCodeEnd = static_cast<uint8_t *>(JITCode) + Mod->JITCodeSize;
  if (Mode == RunMode::SinglepassMode) {
    if (Addr >= JITCode && Addr < JITCodeEnd) {
      uintptr_t *BoundStart = JITFuncPtrs + Mod->NumImportFunctions;
      uintptr_t *BoundEnd = JITFuncPtrs + NumTotalFunctions;
      auto It = std::upper_bound(
          BoundStart, BoundEnd, Addr, [](void *addr, uintptr_t FuncPtr) {
            return addr < reinterpret_cast<void *>(FuncPtr);
          });

      return It - JITFuncPtrs - 1;
    }
  } else if (Mode == RunMode::MultipassMode) {
    const auto &SortedJITFuncPtrs = Mod->getSortedJITFuncPtrs();
    if (Addr >= JITCode && Addr < JITCodeEnd) {
      auto It = std::upper_bound(
          SortedJITFuncPtrs.begin(), SortedJITFuncPtrs.end(), Addr,
          [](void *Addr, const auto &Item) { return Addr > Item.first; });
      if (It != SortedJITFuncPtrs.end()) {
        return static_cast<int32_t>(It->second);
      }
      // the last func_index in _jited_funcs_sort_by_code
      if (!SortedJITFuncPtrs.empty()) {
        return static_cast<int32_t>(
            SortedJITFuncPtrs[SortedJITFuncPtrs.size() - 1].second);
      }
    }
  } else {
    ZEN_ABORT();
  }

  // find from imported functions
  auto It =
      std::upper_bound(HostFuncPtrs.begin(), HostFuncPtrs.end(), Addr,
                       [](void *Addr, const auto &Item) {
                         return Addr < reinterpret_cast<void *>(Item.second);
                       });

  if (It != HostFuncPtrs.begin() && It != HostFuncPtrs.end()) {
    return std::prev(It)->first;
  }

  return -1;
}

void Instance::dumpCallStackOnJIT() {
  using common::WASM_SYMBOL_NULL;
  printf("\n");
  for (uint32_t I = 0; I < NumTraces; ++I) {
    int32_t FuncIdx = Traces[I];
    if (FuncIdx == -1) {
      printf("#%02u  <unknown>\n", I);
      continue;
    }

    char FuncIdxStr[64];
    snprintf(FuncIdxStr, sizeof(FuncIdxStr), "$f%02u", FuncIdx);

    WASMSymbol ModNameSym = WASM_SYMBOL_NULL;
    WASMSymbol FuncNameSym = WASM_SYMBOL_NULL;

    if (uint32_t(FuncIdx) >= Mod->NumImportFunctions) {
      uint32_t InternalFunIdx = FuncIdx - Mod->NumImportFunctions;
      FuncNameSym = Mod->getInternalFunction(InternalFunIdx).Name;
    } else {
      const auto &ImportFunc = Mod->getImportFunction(FuncIdx);
      FuncNameSym = ImportFunc.FieldName;
      ModNameSym = ImportFunc.ModuleName;
    }

    if (FuncNameSym != WASM_SYMBOL_NULL) {
      const char *FuncName = dumpSymbolString(FuncNameSym);
      if (ModNameSym != WASM_SYMBOL_NULL) {
        const char *ModName = dumpSymbolString(ModNameSym);
        printf("#%02u  %s  %s.%s\n", I, FuncIdxStr, ModName, FuncName);
      } else {
        printf("#%02u  %s  %s\n", I, FuncIdxStr, FuncName);
      }
    } else {
      printf("#%02u  %s\n", I, FuncIdxStr);
    }
  }
  printf("\n");
}

#endif // ZEN_ENABLE_DUMP_CALL_STACK

#endif // ZEN_ENABLE_JIT

} // namespace zen::runtime
