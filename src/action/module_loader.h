// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_ACTION_MODULE_LOADER_H
#define ZEN_ACTION_MODULE_LOADER_H

#include "action/loader_common.h"

namespace zen::action {

class HostModuleLoader {
public:
  HostModuleLoader(runtime::HostModule &M) : Mod(M) {}
  void load();

private:
  runtime::HostModule &Mod;
}; // class HostModuleLoader

class ModuleLoader final : public LoaderCommon {
  using SectionType = common::SectionType;
  using SymbolWrapperUniquePtr = runtime::SymbolWrapperUniquePtr;

  // {Min, Max?}
  typedef std::pair<uint32_t, common::Optional<uint32_t>> Limits;

  // {MinTableSize, MaxTableSize}
  typedef std::pair<uint32_t, uint32_t> TableType;
  // {MinMemPages, MaxMemPages}
  typedef std::pair<uint32_t, uint32_t> MemoryType;
  // {Type, Mutable}
  typedef std::pair<WASMType, bool> GlobalType;

public:
  explicit ModuleLoader(runtime::Module &M, const Byte *Data, size_t Size)
      // Set `End` to nullptr temporarily, and then formally set `End` when the
      // `load` method is called
      : ModuleLoader(M, Data, nullptr) {
    ModuleSize = Size;
  }

  void load();

private:
  ModuleLoader(runtime::Module &M, const Byte *PtrStart, const Byte *PtrEnd)
      : LoaderCommon(M, PtrStart, PtrEnd) {}

  WASMSymbol readName();
  Limits readLimits();
  TableType readTableType();
  MemoryType readMemoryType();
  GlobalType readGlobalType();

  std::pair<uint8_t, runtime::InitExpr> readConstExpr(WASMType Type);

  const void *resolveImportFunction(WASMSymbol ModuleName, WASMSymbol FieldName,
                                    const runtime::TypeEntry &ExpectedFuncType);

  std::pair<SectionType, uint32_t> loadSectionHeader() {
    SectionType SecType = static_cast<SectionType>(readByte());
    uint32_t SecSize = readU32();
    return {SecType, SecSize};
  }

  void loadModuleHeader();
  void loadModuleBody();
  void loadCustomSection();
  void loadTypeSection();
  void loadImportSection();
  void loadFunctionSection();
  void loadTableSection();
  void loadMemorySection();
  void loadGlobalSection();
  void loadExportSection();
  void loadStartSection();
  void loadElementSection();
  void loadDataCountSection();
  void loadCodeSection();
  void loadDataSection();

  void loadNameSection();

#ifdef ZEN_ENABLE_SPEC_TEST
  void patchForSpecTest();
#endif

  bool HasNameSection = false;
  size_t ModuleSize = 0;
}; // class ModuleLoader

} // namespace zen::action

#endif // ZEN_ACTION_MODULE_LOADER_H
