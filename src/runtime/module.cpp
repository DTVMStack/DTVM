// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "runtime/module.h"

#include "action/compiler.h"
#include "action/module_loader.h"
#include "common/enums.h"
#include "common/errors.h"
#include "runtime/codeholder.h"
#include "runtime/symbol_wrapper.h"
#include "utils/statistics.h"
#include "utils/wasm.h"
#include <algorithm>
#include <memory>
#include <string>
#ifdef ZEN_ENABLE_MULTIPASS_JIT
#include "compiler/compiler.h"
#endif

extern struct VNMInterface_ *vnmi_functions();

namespace zen::runtime {

using namespace common;
using namespace utils;

HostModule::HostModule(Runtime *RT, BuiltinModuleDesc *ModDesc)
    : BaseModule(RT, ModuleType::NATIVE), MainModDesc(ModDesc) {
  _vnmi_env._runtime = RT;
  _vnmi_env._env._functions = vnmi_functions();
};

HostModuleUniquePtr HostModule::newModule(Runtime &RT,
                                          BuiltinModuleDesc *ModDesc) {
  ZEN_ASSERT(ModDesc);

  void *ObjBuf = RT.allocate(sizeof(HostModule));
  ZEN_ASSERT(ObjBuf);

  auto *RawMod = new (ObjBuf) HostModule(&RT, ModDesc);
  HostModuleUniquePtr Mod(RawMod);

  action::HostModuleLoader Loader(*Mod);
  Loader.load();

  return Mod;
}

static bool compareHostFuncName(const NativeFuncDesc *LHS,
                                const NativeFuncDesc *RHS) {
  return LHS->_name < RHS->_name;
}

void HostModule::addFunctions(const BuiltinModuleDesc *HostModDesc,
                              const NativeFuncDesc *HostFuncDescs,
                              uint32_t NumFunctions) {
  ZEN_ASSERT(HostModDesc);
  ZEN_ASSERT(HostFuncDescs && NumFunctions > 0);
  if (HostModMap.find(HostModDesc) != HostModMap.end()) {
    throw getErrorWithExtraMessage(ErrorCode::DuplicateHostModule,
                                   std::string(": ") + HostModDesc->_name);
  }
  for (uint32_t I = 0; I < NumFunctions; ++I) {
    if (std::binary_search(HostFunctionList.begin(), HostFunctionList.end(),
                           &HostFuncDescs[I], compareHostFuncName)) {
      const char *FuncName =
          getSymbolPool()->dumpSymbolString(HostFuncDescs[I]._name);
      throw getErrorWithExtraMessage(ErrorCode::DuplicateHostFunction,
                                     std::string(": ") + FuncName);
    }
    HostFunctionList.push_back(&HostFuncDescs[I]);
  }
  HostModMap[HostModDesc] = HostFuncDescs;
}

bool HostModule::filterFunctions(
    const std::vector<common::StringView> &WhiteList) noexcept {
  std::unordered_set<WASMSymbol> WhiteListSymSet;
  for (const auto &Name : WhiteList) {
    WASMSymbol Sym = probeSymbol(Name.data(), Name.length());
    if (Sym == WASM_SYMBOL_NULL) {
      ZEN_LOG_ERROR("unknown import, '%s.%s' function not found",
                    MainModDesc->_name, Name.data());
      return false;
    }
    WhiteListSymSet.insert(Sym);
  }
  std::vector<const NativeFuncDesc *> NewHostFuncList;
  for (const NativeFuncDesc *HostFuncDesc : HostFunctionList) {
    if (WhiteListSymSet.find(HostFuncDesc->_name) != WhiteListSymSet.end()) {
      NewHostFuncList.push_back(HostFuncDesc);
    }
  }
  HostFunctionList = std::move(NewHostFuncList);
  return true;
}

SysMemPool *HostModule::getMemAllocator() {
  return getRuntime()->getMemAllocator();
}

ConstStringPool *HostModule::getSymbolPool() {
  return getRuntime()->getSymbolPool();
}

bool TypeEntry::isEqual(TypeEntry *Type1, TypeEntry *Type2) {
  ZEN_ASSERT(Type1 != nullptr && Type2 != nullptr);
  if (Type1->NumParams != Type2->NumParams ||
      Type1->NumReturns != Type2->NumReturns) {
    return false;
  }
  if (std::memcmp(Type1->getParamTypes(), Type2->getParamTypes(),
                  sizeof(WASMType) * Type1->NumParams) ||
      std::memcmp(Type1->getReturnTypes(), Type2->getReturnTypes(),
                  sizeof(WASMType) * Type1->NumReturns)) {
    return false;
  }
  return true;
}

std::pair<WASMType, size_t>
Module::InstanceLayout::getGlobalTypeAndOffset(uint32_t GlobalIdx) const {
  int32_t InternalIdx = int32_t(GlobalIdx) - Mod.getNumImportGlobals();
  ZEN_ASSERT(InternalIdx >= 0);
  const auto &Global = Mod.getInternalGlobal(InternalIdx);
  return {
      Global.Type,
      GlobalVarBaseOffset + Global.Offset,
  };
}

Module::Module(Runtime *RT) : BaseModule(RT, ModuleType::WASM), Layout(*this) {
  // when not SGX and the memory init size not too small, set use_mmap =
  // true
  MemAllocOptions.UseMmap = false;
#ifdef ZEN_ENABLE_CPU_EXCEPTION
  MemAllocOptions.UseMmap = !RT->getConfig().DisableWasmMemoryMap;
#endif // ZEN_ENABLE_CPU_EXCEPTION
  MemAllocOptions.MemoryIndex = 0;
  ThreadLocalMemAllocatorMap =
      new utils::ThreadSafeMap<int64_t, WasmMemoryAllocator *>();
}

Module::~Module() {
  releaseMemoryAllocatorCache();
  delete ThreadLocalMemAllocatorMap;

#ifdef ZEN_ENABLE_MULTIPASS_JIT
  if (LazyJITCompiler) {
    // Must release LazyJITCompiler before destroying the module elements
    auto &Stats = getRuntime()->getStatistics();
    auto Timer = Stats.startRecord(StatisticPhase::JITLazyReleaseDelay);
    LazyJITCompiler.reset();
    Stats.stopRecord(Timer);
  }
#endif

  destroyTypeTable();
  destroyImportTables();
  destroyFunctionTable();
  deallocate(InternalFunctionTable);
  deallocate(InternalTableTable);
  deallocate(InternalMemoryTable);
  deallocate(InternalGlobalTable);
  destroyExportTable();
  destroyElemTable();
  deallocate(DataTable);
  destroyCodeTable();
}

void Module::releaseMemoryAllocatorCache() {
  // clear cache resources
  if (ThreadLocalMemAllocatorMap) {
    ThreadLocalMemAllocatorMap->each([](auto K, auto V) { delete V; });
    ThreadLocalMemAllocatorMap->clear();
  }
}

ModuleUniquePtr Module::newModule(Runtime &RT, CodeHolderUniquePtr CodeHolder,
                                  const std::string &EntryHint) {
  void *ObjBuf = RT.allocate(sizeof(Module));
  ZEN_ASSERT(ObjBuf);

  auto *RawMod = new (ObjBuf) Module(&RT);
  ModuleUniquePtr Mod(RawMod);

#ifdef ZEN_ENABLE_MULTIPASS_JIT
  Mod->EntryHint = EntryHint;
#endif

  action::ModuleLoader Loader(*Mod,
                              static_cast<const Byte *>(CodeHolder->getData()),
                              CodeHolder->getSize());

  auto &Stats = RT.getStatistics();
  auto Timer = Stats.startRecord(utils::StatisticPhase::Load);

  Loader.load();

  Stats.stopRecord(Timer);

  Mod->Layout.compute();

  Mod->CodeHolder = std::move(CodeHolder);

  if (Mod->NumInternalFunctions > 0) {
    action::performJITCompile(*Mod);
  }

  Mod->getMemoryAllocator();

  return Mod;
}

// ==================== JIT Methods ====================
#ifdef ZEN_ENABLE_MULTIPASS_JIT
COMPILER::LazyJITCompiler *Module::newLazyJITCompiler() {
  LazyJITCompiler = std::make_unique<COMPILER::LazyJITCompiler>(this);
  return LazyJITCompiler.get();
}
#endif

// ==================== Metadata Methods ====================

const uint8_t *Module::getWASMBytecode() const {
  return static_cast<const uint8_t *>(CodeHolder->getData());
}

// ==================== Segment Accessing Methods ====================

uint32_t Module::getFunctionTypeIdx(uint32_t FuncIdx) const {
  if (FuncIdx < NumImportFunctions) {
    return getImportFunction(FuncIdx).TypeIdx;
  }
  uint32_t InternalFuncIdx = FuncIdx - NumImportFunctions;
  ZEN_ASSERT(InternalFuncIdx < NumInternalFunctions);
  return getInternalFunction(InternalFuncIdx).TypeIdx;
}

TypeEntry *Module::getFunctionType(uint32_t FuncIdx) const {
  return getDeclaredType(getFunctionTypeIdx(FuncIdx));
}

CodeEntry *Module::getCodeEntry(uint32_t FuncIdx) const {
  if (FuncIdx < NumImportFunctions) {
    return nullptr;
  }
  uint32_t InternalFuncIdx = FuncIdx - NumImportFunctions;
  ZEN_ASSERT(InternalFuncIdx < NumInternalFunctions);
  return CodeTable + InternalFuncIdx;
}

bool Module::getExportFunc(WASMSymbol Name, uint32_t &FuncIdx) const noexcept {
  // perhaps use a hashmap instead if there are too much export functions.
  for (uint32_t I = 0; I < NumExports; ++I) {
    if (ExportTable[I].Kind == ExportKind::EXPORT_FUNC &&
        Name == ExportTable[I].Name) {
      FuncIdx = ExportTable[I].ItemIdx;
      return true;
    }
  }

  return false;
}

bool Module::getExportFunc(const std::string &Name,
                           uint32_t &FuncIdx) const noexcept {
  WASMSymbol NameSym = probeSymbol(Name.c_str(), Name.length());
  if (NameSym == WASM_SYMBOL_NULL) {
    return false;
  }
  return getExportFunc(NameSym, FuncIdx);
}

// ==================== Platform Feature Methods ====================

WasmMemoryAllocator *Module::getMemoryAllocator() {
  auto ThreadId = utils::getThreadLocalUniqueId();
  if (!ThreadLocalMemAllocatorMap->containsKey(ThreadId)) {
    ThreadLocalMemAllocatorMap->put(
        ThreadId, new WasmMemoryAllocator(this, &MemAllocOptions));
  }
  return ThreadLocalMemAllocatorMap->get(ThreadId);
}

// ==================== Destroy Table Methods ====================

void Module::destroyTypeTable() {
  for (uint32_t I = 0; I < NumTypes; ++I) {
    if (TypeTable[I].NumParams > (__WORDSIZE / 8) && TypeTable[I].ParamTypes) {
      deallocate(TypeTable[I].ParamTypes);
    }
#ifdef ZEN_ENABLE_WASI_MULTI_VALUE
    // Free dynamically allocated return types array for multi-value
    if (TypeTable[I].NumReturns > 2 && TypeTable[I].ReturnTypesPtr) {
      deallocate(TypeTable[I].ReturnTypesPtr);
    }
#endif
  }
  deallocate(TypeTable);
}

void Module::destroyFunctionTable() {
  for (uint32_t I = 0; I < NumInternalFunctions; ++I) {
    freeSymbol(InternalFunctionTable[I].Name);
  }
}

void Module::destroyImportTables() {
  for (uint32_t I = 0; I < NumImportFunctions; ++I) {
    freeSymbol(ImportFunctionTable[I].ModuleName);
    freeSymbol(ImportFunctionTable[I].FieldName);
  }
  deallocate(ImportFunctionTable);

  for (uint32_t I = 0; I < NumImportTables; ++I) {
    freeSymbol(ImportTableTable[I].ModuleName);
    freeSymbol(ImportTableTable[I].FieldName);
  }
  deallocate(ImportTableTable);

  for (uint32_t I = 0; I < NumImportMemories; ++I) {
    freeSymbol(ImportMemoryTable[I].ModuleName);
    freeSymbol(ImportMemoryTable[I].FieldName);
  }
  deallocate(ImportMemoryTable);

  for (uint32_t I = 0; I < NumImportGlobals; ++I) {
    freeSymbol(ImportGlobalTable[I].ModuleName);
    freeSymbol(ImportGlobalTable[I].FieldName);
  }
  deallocate(ImportGlobalTable);
}

void Module::destroyExportTable() {
  for (uint32_t I = 0; I < NumExports; ++I) {
    freeSymbol(ExportTable[I].Name);
  }
  deallocate(ExportTable);
}

void Module::destroyElemTable() {
  for (uint32_t I = 0; I < NumElementSegments; ++I) {
    deallocate(ElementTable[I].FuncIdxs);
  }
  deallocate(ElementTable);
}

void Module::destroyCodeTable() {
  for (uint32_t I = 0; I < NumCodeSegments; ++I) {
    if (CodeTable[I].LocalTypes) {
      deallocate(CodeTable[I].LocalTypes);
    }
    if (CodeTable[I].LocalOffsets) {
      deallocate(CodeTable[I].LocalOffsets);
    }
  }
  deallocate(CodeTable);
}

} // namespace zen::runtime
