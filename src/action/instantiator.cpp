// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "action/instantiator.h"
#include "common/defines.h"
#include "common/enums.h"
#include "common/type.h"
#include "runtime/instance.h"
#include "utils/math.h"
#include <algorithm>

namespace zen::action {

using namespace common;
using namespace runtime;

void Instantiator::instantiateGlobals(Instance &Inst) {
  const Module &Mod = *Inst.Mod;
  Inst.NumTotalGlobals = Mod.getNumTotalGlobals();

  uint32_t Idx = 0;

  for (uint32_t I = 0; I < Mod.NumImportGlobals; ++I) {
    const auto &Global = Mod.ImportGlobalTable[I];
    uint32_t Offset = Global.Offset;
    // uint8_t *GlobalPtr = Inst.GlobalVarData + Offset;
    GlobalInstance &GlobalInst = Inst.Globals[Idx];
    GlobalInst.Offset = Offset;
    GlobalInst.Mutable = Global.Mutable;
    GlobalInst.Type = Global.Type;
    ++Idx;
  }

  size_t GlobalVarSize = Inst.getModule()->Layout.GlobalVarSize;
  if (GlobalVarSize > 0) {
    std::memset(Inst.GlobalVarData, 0, GlobalVarSize);
  }

  for (uint32_t I = 0; I < Mod.NumInternalGlobals; ++I) {
    const auto &Global = Mod.InternalGlobalTable[I];
    uint32_t Offset = Global.Offset;
    uint32_t Size = getWASMTypeSize(Global.Type);

    GlobalInstance &GlobalInst = Inst.Globals[Idx];
    GlobalInst.Offset = Offset;
    GlobalInst.Mutable = Global.Mutable;
    GlobalInst.Type = Global.Type;

    uint8_t *GlobalPtr = Inst.GlobalVarData + Offset;
    const auto &InitExpr = Global.InitExprVal;
    switch (Global.InitExprKind) {
    case GET_GLOBAL: {
      const auto &FromGlobalInst = Mod.InternalGlobalTable[InitExpr.GlobalIdx];
      // can move global validity to module validate session;
      ZEN_ASSERT(Size <= sizeof(FromGlobalInst.InitExprVal));
      std::memcpy(GlobalPtr, &FromGlobalInst.InitExprVal.I32, Size);
      break;
    }
    default:
      ZEN_ASSERT(Size <= sizeof(InitExpr));
      std::memcpy(GlobalPtr, &InitExpr.I32, Size);
      break;
    }
    ++Idx;
  }
}

void Instantiator::instantiateFunctions(Instance &Inst) {
#ifdef ZEN_ENABLE_DUMP_CALL_STACK
  auto &HostFuncPtrs = Inst.HostFuncPtrs;
#define INSERT_HOST_FUNC_PTR(FuncIdx, Ptr)                                     \
  HostFuncPtrs.emplace_back(FuncIdx, Ptr);
#define SORT_HOST_FUNC_PTRS                                                    \
  if (!HostFuncPtrs.empty()) {                                                 \
    uintptr_t HostFuncBoundEnd =                                               \
        HostFuncPtrs.back().second + MAX_NATIVE_FUNC_SIZE;                     \
    HostFuncPtrs.emplace_back(-1, HostFuncBoundEnd);                           \
  }                                                                            \
  std::sort(HostFuncPtrs.begin(), HostFuncPtrs.end(),                          \
            [](const auto &A, const auto &B) { return A.second < B.second; });
#else
#define INSERT_HOST_FUNC_PTR(...)
#define SORT_HOST_FUNC_PTRS
#endif

  const Module &Mod = *Inst.Mod;
  Inst.NumTotalFunctions = Mod.getNumTotalFunctions();

  uint32_t NumImportFunctions = Mod.getNumImportFunctions();
  if (NumImportFunctions > 0) {
    std::memset(Inst.Functions, 0,
                sizeof(FunctionInstance) * NumImportFunctions);
  }
  for (uint32_t I = 0; I < Inst.NumTotalFunctions; ++I) {
    FunctionInstance &FuncInst = Inst.Functions[I];

    bool IsImport = I < NumImportFunctions;
    // Ensure only used when I >= NumImportFunctions
    uint32_t InternalFuncIdx = I - NumImportFunctions;
    uint32_t TypeIdx = IsImport
                           ? Mod.getImportFunction(I).TypeIdx
                           : Mod.getInternalFunction(InternalFuncIdx).TypeIdx;

    TypeEntry &Type = Mod.TypeTable[TypeIdx];
    FuncInst.NumParams = Type.NumParams;
    FuncInst.NumParamCells = Type.NumParamCells;
    FuncInst.NumReturns = Type.NumReturns;
    FuncInst.NumReturnCells = Type.NumReturnCells;
    std::memcpy(FuncInst.ReturnTypes, Type.getReturnTypes(),
                sizeof(FuncInst.ReturnTypes));
    FuncInst.ParamTypes = Type.ParamTypes;
    FuncInst.FuncType = &Type;

    if (IsImport) {
      FuncInst.Kind = FunctionKind::Native;
      FuncInst.CodePtr =
          reinterpret_cast<const uint8_t *>(Mod.ImportFunctionTable[I].FuncPtr);
      INSERT_HOST_FUNC_PTR(I, uintptr_t(FuncInst.CodePtr))
    } else {
      FuncInst.Kind = FunctionKind::ByteCode;
      const CodeEntry &Code = Mod.CodeTable[InternalFuncIdx];
      FuncInst.NumLocals = Code.NumLocals;
      FuncInst.NumLocalCells = Code.NumLocalCells;
      FuncInst.LocalTypes = Code.LocalTypes;
      FuncInst.LocalOffsets = Code.LocalOffsets;
      FuncInst.MaxStackSize = Code.MaxStackSize;
      FuncInst.MaxBlockDepth = Code.MaxBlockDepth;
      FuncInst.CodePtr = Code.CodePtr;
#ifdef ZEN_ENABLE_JIT
      FuncInst.JITCodePtr = Code.JITCodePtr;
#endif
      FuncInst.CodeSize = Code.CodeSize;
    }

#ifdef ZEN_ENABLE_JIT
    Inst.FuncTypeIdxs[I] = TypeIdx;
    Inst.JITFuncPtrs[I] = reinterpret_cast<uintptr_t>(FuncInst.JITCodePtr);
#endif
  }

  SORT_HOST_FUNC_PTRS
}

void Instantiator::instantiateTables(Instance &Inst) {
  const Module &Mod = *Inst.Mod;
  Inst.NumTotalTables = Mod.getNumTotalTables();

  uint32_t *TableElemStart = reinterpret_cast<uint32_t *>(
      (uintptr_t)Inst.Tables + Inst.Mod->Layout.TableInstancesSize);

  for (uint32_t I = 0; I < Inst.NumTotalTables; ++I) {
    TableInstance &TableInst = Inst.Tables[I];
    if (I < Mod.NumImportTables) {
      const auto &Table = Mod.ImportTableTable[I];
      TableInst.CurSize = Table.InitSize;
      TableInst.MaxSize = Table.MaxSize;
    } else {
      const auto &Table = Mod.InternalTableTable[I - Mod.NumImportTables];
      TableInst.CurSize = Table.InitSize;
      TableInst.MaxSize = Table.MaxSize;
    }

    std::memset(TableElemStart, -1, TableInst.CurSize * sizeof(uint32_t));
    TableInst.Elements = TableElemStart;
  }

  for (uint32_t I = 0; I < Mod.NumElementSegments; ++I) {
    const auto &Element = Mod.ElementTable[I];
    TableInstance &TableInst = Inst.Tables[Element.TableIdx];
    uint32_t Offset = 0;
    if (Element.InitExprKind == GET_GLOBAL) {
      uint32_t GlobalIdx = Element.InitExprVal.GlobalIdx;
      Offset = Inst.Globals[GlobalIdx].Offset;
      Offset = *reinterpret_cast<uint32_t *>(Inst.GlobalVarData + Offset);
    } else {
      Offset = Element.InitExprVal.I32;
    }

    const uint32_t NumFuncIdxs = Element.NumFuncIdxs;
    if (Offset > TableInst.CurSize ||
        (Offset + NumFuncIdxs) > TableInst.CurSize) {
#ifdef ZEN_ENABLE_DWASM
      throw getError(ErrorCode::DWasmModuleFormatInvalid);
#else
      throw getError(ErrorCode::ElementsSegmentDoesNotFit);
#endif
    }

    std::memcpy(TableInst.Elements + Offset, Element.FuncIdxs,
                NumFuncIdxs * sizeof(uint32_t));
  }
}

static void checkAndUpdateMemPages(uint32_t VmMaxMemPages, uint32_t CurMemPages,
                                   uint32_t *MaxMemPages) {
  if (VmMaxMemPages > 0) {
    if (CurMemPages > VmMaxMemPages) {
      throw getErrorWithPhase(ErrorCode::MemorySizeTooLarge,
                              ErrorPhase::Instantiation);
    }
    *MaxMemPages = std::min(*MaxMemPages, VmMaxMemPages);
  }
}

void Instantiator::initMemoryByDataSegments(Instance &Inst) {
  if (Inst.DataSegsInited) {
    return;
  }
  const Module *Mod = Inst.Mod;
  for (uint32_t I = 0; I < Mod->NumDataSegments; ++I) {
    const auto &DataSeg = Mod->DataTable[I];
    uint32_t MemIdx = DataSeg.MemIdx;
    // should checked if MemIndex is valid in loader
    MemoryInstance &MemInst = Inst.Memories[MemIdx];

    uint32_t Offset = 0;

    if (DataSeg.InitExprKind == GET_GLOBAL) {
      uint32_t GlobalIdx = DataSeg.InitExprVal.GlobalIdx;
      auto *InitExprPtr = Inst.GlobalVarData + Inst.Globals[GlobalIdx].Offset;
      Offset = *reinterpret_cast<uint32_t *>(InitExprPtr);
    } else {
      Offset = DataSeg.InitExprVal.I32;
    }

    uint32_t DataBoundary;
    if (Offset > MemInst.MemSize ||
        utils::addOverflow(Offset, DataSeg.Size, DataBoundary) ||
        DataBoundary > MemInst.MemSize) {
      throw getError(ErrorCode::DataSegmentDoesNotFit);
    }

    if (MemInst.MemBase) {
      std::memcpy(MemInst.MemBase + Offset,
                  Mod->getWASMBytecode() + DataSeg.Offset, DataSeg.Size);
    }
  }
  Inst.DataSegsInited = true;
}

void Instantiator::instantiateMemories(Instance &Inst) {
  const Module &Mod = *Inst.Mod;
  Inst.NumTotalMemories = Mod.getNumTotalMemories();
  if (Inst.NumTotalMemories > 1) {
    throw getErrorWithPhase(ErrorCode::TooManyMemories,
                            ErrorPhase::Instantiation);
  }

  uint32_t VmMaxMemPages = Inst.getRuntime()->getVmMaxMemoryPages();

  for (uint32_t I = 0; I < Inst.NumTotalMemories; ++I) {
    MemoryInstance &MemInst = Inst.Memories[I];

    if (I < Mod.NumImportMemories) {
      const auto &ImportMem = Mod.ImportMemoryTable[I];
      uint32_t CurMemPages = ImportMem.InitPages;
      uint32_t MaxMemPages = ImportMem.MaxPages;
      checkAndUpdateMemPages(VmMaxMemPages, CurMemPages, &MaxMemPages);
      MemInst.CurPages = CurMemPages;
      MemInst.MaxPages = MaxMemPages;

      MemInst.MemBase = nullptr;
      MemInst.MemEnd = nullptr;
      MemInst.MemSize = 0;
      MemInst.Kind = WasmMemoryDataType::WM_MEMORY_DATA_TYPE_NO_DATA;
    } else {
      uint32_t InternalMemIdx = I - Mod.NumImportMemories;
      const auto &Mem = Mod.InternalMemoryTable[InternalMemIdx];
      uint32_t CurMemPages = Mem.InitSize;

      uint32_t MaxMemPages = 0;
      if (!Mem.MaxSize) {
        MaxMemPages = MemInst.CurPages;
      } else {
        MaxMemPages = Mem.MaxSize;
      }
      checkAndUpdateMemPages(VmMaxMemPages, CurMemPages, &MaxMemPages);
      MemInst.CurPages = CurMemPages;
      MemInst.MaxPages = MaxMemPages;

      if (!MemInst.CurPages) {
        MemInst.MemSize = 0;
        MemInst.MemBase = nullptr;
        MemInst.MemEnd = nullptr;
        MemInst.Kind = WasmMemoryDataType::WM_MEMORY_DATA_TYPE_NO_DATA;
      }
    }

    uint64_t TotalMemSize =
        MemInst.CurPages * uint64_t(common::DefaultBytesNumPerPage);
    ZEN_ASSERT(TotalMemSize <= UINT32_MAX);

    auto *MemAllocator = Inst.getWasmMemoryAllocator();
    bool DataSegsInited = false;

    WasmMemoryData NewMemDataStruct = MemAllocator->allocInitWasmMemory(
        (uint8_t *)reinterpret_cast<void *>(&MemInst), TotalMemSize, true,
        &DataSegsInited, nullptr, 0);
    if (!NewMemDataStruct.MemoryData && TotalMemSize > 0) {
      ZEN_ABORT();
    }
    Inst.DataSegsInited = DataSegsInited;

    MemInst.MemSize = TotalMemSize;
    MemInst.MemBase = reinterpret_cast<uint8_t *>(NewMemDataStruct.MemoryData);
    MemInst.Kind = NewMemDataStruct.Type;
    MemInst.MemEnd = MemInst.MemBase + TotalMemSize;
  }

  initMemoryByDataSegments(Inst);
}

#ifdef ZEN_ENABLE_BUILTIN_WASI
// will move the following to other place soon.
void Instantiator::instantiateWasi(Instance &Inst) {
  Runtime *RT = Inst.getRuntime();

  HostModule *HostMod =
      RT->resolveHostModule(WASM_SYMBOL_wasi_snapshot_preview1);
  ZEN_ASSERT(HostMod);

  const BuiltinModuleDesc *HostModDesc = HostMod->getModuleDesc();
  ZEN_ASSERT(HostModDesc);

  uint32_t Argc = 0, NumEnvs = 0, NumDirs = 0, ArgvBufSize = 0, EnvBufSize = 0;
  auto *ArgvList = RT->getWASIArgs(Argc);
  auto *ArgvBuf = RT->getWASIArgsBuf(ArgvBufSize);
  auto *EnvList = RT->getWASIEnvs(NumEnvs);
  auto *EnvBuf = RT->getWASIEnvsBuf(EnvBufSize);
  auto *DirList = RT->getWASIDirs(NumDirs);

  void *WASICtx = HostModDesc->_init_ctx_func(
      HostMod->getVNMIEnv(), DirList, NumDirs, EnvList, NumEnvs, EnvBuf,
      EnvBufSize, const_cast<char **>(ArgvList), Argc, ArgvBuf, ArgvBufSize);

  // temporally store wasi ctx into instance, will move to wni later.
  Inst.WASICtx = (host::WASIContext *)WASICtx;
}
#endif

void Instantiator::instantiate(Instance &Inst) {
  const Module &Mod = *Inst.Mod;

  instantiateGlobals(Inst);

  instantiateFunctions(Inst);

  instantiateTables(Inst);

  instantiateMemories(Inst);

#ifdef ZEN_ENABLE_BUILTIN_WASI
  if (!Inst.getRuntime()->getConfig().DisableWASI) {
    instantiateWasi(Inst);
  }
#endif

  uint32_t StartFuncIdx = Mod.getStartFuncIdx();
  if (StartFuncIdx != -1u) {
    Runtime *RT = Inst.getRuntime();
    std::vector<common::TypedValue> Results;
    if (!RT->callWasmFunction(Inst, StartFuncIdx, {}, Results)) {
      throw common::Error(Inst.getError());
    }
  }
}

} // namespace zen::action
