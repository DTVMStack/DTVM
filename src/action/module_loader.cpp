// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "action/module_loader.h"
#include "action/function_loader.h"
#include "runtime/symbol_wrapper.h"
#include "utils/unicode.h"
#include "utils/wasm.h"

#ifdef ZEN_ENABLE_CHECKED_ARITHMETIC
#include "action/hook.h"
#endif

namespace zen::action {

using namespace common;
using namespace runtime;
using namespace utils;

void HostModuleLoader::load() {
  ZEN_ASSERT(Mod.MainModDesc);
  const auto *MainModDesc = Mod.MainModDesc;
  uint32_t NumHostFunctions = 0;
  const NativeFuncDesc *HostFuntionList;

  // Judge if the host module is registered by C API
  if (MainModDesc->Functions) {
    HostFuntionList = MainModDesc->Functions;
    NumHostFunctions = MainModDesc->NumFunctions;
  } else {
    HostFuntionList = MainModDesc->_load_func(
        reinterpret_cast<VNMIEnv *>(&Mod._vnmi_env), NumHostFunctions);
  }

  if (!HostFuntionList) {
    throw getError(ErrorCode::HostFunctionArrayLoadFailed);
  }

  Mod.addFunctions(Mod.MainModDesc, HostFuntionList, NumHostFunctions);
}

void ModuleLoader::load() {
  if (!Start) {
    throw getError(ErrorCode::UnexpectedEnd);
  }

  // Set `End` if the module size is valid, otherwise throw error
  if (addOverflow(Start, ModuleSize, End)) {
    throw getError(ErrorCode::ModuleSizeTooLarge);
  }

  loadModuleHeader();

  loadModuleBody();

#ifdef ZEN_ENABLE_SPEC_TEST
  patchForSpecTest();
#endif
}

WASMSymbol ModuleLoader::readName() {
  uint32_t NameLen = readU32();
  Bytes NameBytes = readBytes(NameLen);
  if (NameLen > common::PresetMaxNameLength) {
    throw getError(ErrorCode::TooLongName);
  }
  const auto *StringPtr = reinterpret_cast<const uint8_t *>(NameBytes.data());
  if (!validateUTF8String(StringPtr, NameBytes.length())) {
    throw getError(ErrorCode::InvalidUTF8Encoding);
  }
  const char *Name = reinterpret_cast<const char *>(NameBytes.data());
  WASMSymbol NameSymbol = Mod.newSymbol(Name, NameLen);
  if (NameSymbol == WASM_SYMBOL_NULL) {
    throw getError(ErrorCode::SymbolAllocFailed);
  }
  return NameSymbol;
}

ModuleLoader::Limits ModuleLoader::readLimits() {
  Byte Flag = readByte();
  if (Flag > Byte(0x01)) {
    throw getError(ErrorCode::InvalidLimitsFlag);
  }

  uint32_t Min = readU32();
  common::Optional<uint32_t> Max;
  // If has maximum, read and check it
  if (Flag == Byte(0x01)) {
    Max = readU32();
    if (Min > Max.value()) {
      throw getError(ErrorCode::SizeMinimumGreaterThenMaximum);
    }
  }
  return {Min, Max};
}

ModuleLoader::TableType ModuleLoader::readTableType() {
  [[maybe_unused]] WASMType RefType = readRefType();
  const auto &[MinTableSize, OptMaxTableSize] = readLimits();
  uint32_t MaxTableSize = OptMaxTableSize.value_or(PresetMaxTableSize);
  if (MinTableSize > PresetMaxTableSize || MaxTableSize > PresetMaxTableSize) {
    throw getError(ErrorCode::TableSizeTooLarge);
  }
  return {MinTableSize, MaxTableSize};
}

ModuleLoader::MemoryType ModuleLoader::readMemoryType() {
  const auto &[MinMemPages, OptMaxMemPages] = readLimits();
  uint32_t MaxMemPages = OptMaxMemPages.value_or(PresetMaxMemoryPages);
  if (MinMemPages > PresetMaxMemoryPages ||
      MaxMemPages > PresetMaxMemoryPages) {
    throw getError(ErrorCode::MemorySizeTooLarge);
  }
  return {MinMemPages, MaxMemPages};
}

ModuleLoader::GlobalType ModuleLoader::readGlobalType() {
  WASMType Type = readValType();
  Byte MutableFlag = readByte();
  if (MutableFlag > Byte(0x01)) {
    throw getError(ErrorCode::InvalidMutability);
  }
  return {Type, MutableFlag == Byte(0x01)};
}

std::pair<uint8_t, runtime::InitExpr>
ModuleLoader::readConstExpr(WASMType Type) {
  uint8_t Opcode = to_underlying(readByte());
  WASMType ActualType;
  InitExpr ConstExpr;
  switch (Opcode) {
  case I32_CONST:
    ActualType = WASMType::I32;
    ConstExpr.I32 = readI32();
    break;
  case I64_CONST:
    ActualType = WASMType::I64;
    ConstExpr.I64 = readI64();
    break;
  case F32_CONST:
    ActualType = WASMType::F32;
    ConstExpr.F32 = readF32();
    break;
  case F64_CONST:
    ActualType = WASMType::F64;
    ConstExpr.F64 = readF64();
    break;
  case GET_GLOBAL: {
    uint32_t GlobalIdx = readU32();
    if (!Mod.isValidImportGlobal(GlobalIdx)) {
      throw getError(ErrorCode::UnknownGlobal);
    }
    const ImportGlobalEntry &Global = Mod.ImportGlobalTable[GlobalIdx];
    // Ensure the global is immutable
    if (Global.Mutable) {
      throw getError(ErrorCode::ConstExprRequired);
    }
    ActualType = Global.Type;
    ConstExpr.GlobalIdx = GlobalIdx;
    break;
  }
  default:
    // TODO: Use more specific error code
    throw getError(ErrorCode::TypeMismatchOrConstExprRequired);
  }

  if (ActualType != Type) {
    throw getError(ErrorCode::TypeMismatch);
  }

  // TODO: Use more specific error code
  if (to_underlying(readByte()) != END) {
    throw getError(ErrorCode::TypeMismatchOrConstExprRequired);
  }

  return {Opcode, ConstExpr};
}

const void *
ModuleLoader::resolveImportFunction(WASMSymbol ModuleName, WASMSymbol FieldName,
                                    const TypeEntry &ExpectedFuncType) {
  Runtime *RT = Mod.getRuntime();
  ZEN_ASSERT(RT);

  auto ThrowError = [=](ErrorCode ErrCode, const std::string &DetailMsg) {
    const char *ModuleNameStr = RT->dumpSymbolString(ModuleName);
    const char *FieldNameStr = RT->dumpSymbolString(FieldName);
    const auto &ErrMsg = std::string("\"") + ModuleNameStr + '.' +
                         FieldNameStr + "\", " + DetailMsg;
    throw getErrorWithExtraMessage(ErrCode, ErrMsg);
  };

  HostModule *HostMod = RT->resolveHostModule(ModuleName);
  if (!HostMod) {
    ThrowError(ErrorCode::UnknownImport, "module not found");
  }

  const auto &HostFuncs = HostMod->getHostFuntionList();
  const uint32_t NumHostFuncs = HostMod->getNumHostFunctions();
  uint32_t FoundIdx = NumHostFuncs;

  // Fast lookup, there is a precondition, which implies function order is
  // same with symbol order.
  if (FieldName >= HostFuncs[0]->_name &&
      FieldName <= HostFuncs[NumHostFuncs - 1]->_name) {
    uint32_t NameIdx = FieldName - HostFuncs[0]->_name;
    if (NameIdx < NumHostFuncs && HostFuncs[NameIdx]->_name == FieldName) {
      FoundIdx = NameIdx;
    }
  }

  // Normal lookup
  if (FoundIdx == NumHostFuncs) {
    for (uint32_t I = 0; I < NumHostFuncs; ++I) {
      if (HostFuncs[I]->_isReserved) {
        continue;
      }
      if (HostFuncs[I]->_name == FieldName) {
        FoundIdx = I;
        break;
      }
    }
  }

  if (FoundIdx == NumHostFuncs) {
    ThrowError(ErrorCode::UnknownImport, "function not found");
  }

  const NativeFuncDesc *TargetHostFunc = HostFuncs[FoundIdx];
  const WASMType *ActualFuncType = TargetHostFunc->_func_type;
  uint32_t ActualNumReturns = TargetHostFunc->_ret_count;
  uint32_t ActualNumParams = TargetHostFunc->_param_count;
  uint32_t ExpectedNumReturns = ExpectedFuncType.NumReturns;
  uint32_t ExpectedNumParams = ExpectedFuncType.NumParams;

  if (ExpectedNumReturns != ActualNumReturns) {
    std::string DetailErrMsg = "return count mismatch (expected ";
    DetailErrMsg += std::to_string(ActualNumReturns);
    DetailErrMsg += ", acutal ";
    DetailErrMsg += std::to_string(ExpectedNumReturns);
    DetailErrMsg += ')';
    ThrowError(ErrorCode::IncompatibleImportType, DetailErrMsg);
  }
  if (ExpectedNumParams != ActualNumParams) {
    std::string DetailErrMsg = "param count mismatch (expected ";
    DetailErrMsg += std::to_string(ExpectedNumParams);
    DetailErrMsg += ", acutal ";
    DetailErrMsg += std::to_string(ActualNumParams);
    DetailErrMsg += ')';
    ThrowError(ErrorCode::IncompatibleImportType, DetailErrMsg);
  }

  for (uint32_t I = 0; I < ExpectedNumReturns; ++I) {
    WASMType ExpectedType = ExpectedFuncType.ReturnTypes[I];
    WASMType ActualType = ActualFuncType[I + ActualNumParams];
    if (ExpectedType != ActualType) {
      std::string DetailErrMsg = "return type mismatch (expected ";
      DetailErrMsg += getWASMTypeString(ExpectedType);
      DetailErrMsg += ", acutal ";
      DetailErrMsg += getWASMTypeString(ActualType);
      DetailErrMsg += ')';
      ThrowError(ErrorCode::IncompatibleImportType, DetailErrMsg);
    }
  }

  const WASMType *ExpectedParamTypes = ExpectedFuncType.getParamTypes();
  for (uint32_t I = 0; I < ActualNumParams; ++I) {
    WASMType ExpectedType = ExpectedParamTypes[I];
    WASMType ActualType = ActualFuncType[I];
    if (ExpectedType != ActualType) {
      std::string DetailErrMsg = "param type mismatch (param index: ";
      DetailErrMsg += std::to_string(I);
      DetailErrMsg += ", expected ";
      DetailErrMsg += getWASMTypeString(ExpectedType);
      DetailErrMsg += ", acutal ";
      DetailErrMsg += getWASMTypeString(ActualType);
      DetailErrMsg += ')';
      ThrowError(ErrorCode::IncompatibleImportType, DetailErrMsg);
    }
  }

  return TargetHostFunc->_ptr;
}

void ModuleLoader::loadModuleHeader() {
  // Check magic number
  if (readPlainU32() != WasmMagicNumber) {
    throw getError(ErrorCode::MagicNotDetected);
  }

  // Check version
  if (readPlainU32() != WasmVersion) {
    throw getError(ErrorCode::UnknownBinaryVersion);
  }
}

void ModuleLoader::loadModuleBody() {
  SectionOrder LastSecOrder = SectionOrder::SEC_ORDER_CUSTOM;
  while (Ptr < End) {
    const auto [SecType, SecSize] = loadSectionHeader();

    if (SecType > SectionType::SEC_LAST) {
      throw getError(ErrorCode::InvalidSectionId);
    }
    // Ensure the order of sections
    if (SecType != SectionType::SEC_CUSTOM) {
      SectionOrder SecOrder = getSectionOrder(SecType);
      if (SecOrder <= LastSecOrder) {
        throw getError(ErrorCode::JunkAfterLastSection);
      }
      LastSecOrder = SecOrder;
    }
    if (HasNameSection && SecType != SectionType::SEC_CUSTOM) {
      throw getError(ErrorCode::InvalidNameSectionPosition);
    }

    const Byte *SecEnd;
    if (SecSize > PresetMaxSectionSize || addOverflow(Ptr, SecSize, SecEnd)) {
      throw getError(ErrorCode::SectionSizeTooLarge);
    }
    if (SecEnd > End) {
      throw getError(ErrorCode::UnexpectedEnd);
    }

    // Swap `SecEnd` and `End` and restore after loading current section
    std::swap(SecEnd, End);
    switch (SecType) {
    case SectionType::SEC_CUSTOM:
      loadCustomSection();
      break;
    case SectionType::SEC_TYPE:
      loadTypeSection();
      break;
    case SectionType::SEC_IMPORT:
      loadImportSection();
      break;
    case SectionType::SEC_FUNC:
      loadFunctionSection();
      break;
    case SectionType::SEC_TABLE:
      loadTableSection();
      break;
    case SectionType::SEC_MEMORY:
      loadMemorySection();
      break;
    case SectionType::SEC_GLOBAL:
      loadGlobalSection();
      break;
    case SectionType::SEC_EXPORT:
      loadExportSection();
      break;
    case SectionType::SEC_START:
      loadStartSection();
      break;
    case SectionType::SEC_ELEM:
      loadElementSection();
      break;
    case SectionType::SEC_DATACOUNT:
      loadDataCountSection();
      break;
    case SectionType::SEC_CODE:
      loadCodeSection();
      break;
    case SectionType::SEC_DATA:
      loadDataSection();
      break;
    default:
      ZEN_UNREACHABLE();
    }
    std::swap(SecEnd, End);

    if (Ptr != SecEnd) {
      throw getError(ErrorCode::SectionSizeMismath);
    }
  }

  // Check function number consistency
  if (Mod.NumInternalFunctions != Mod.NumCodeSegments) {
    throw getError(ErrorCode::FuncCodeInconsistent);
  }

  ZEN_ASSERT(Ptr == End);
}

void ModuleLoader::loadCustomSection() {
  SymbolWrapper Name(*Mod.getRuntime(), readName());
  switch (Name) {
  case WASM_SYMBOL_name:
    loadNameSection();
    break;
  case WASM_SYMBOL_dylink:
  default:
    // Skip unknown custom section
    Ptr = End;
    break;
  }
}

void ModuleLoader::loadTypeSection() {
  uint32_t NumTypes = readU32();
  if (NumTypes > PresetMaxNumTypes) {
    throw getError(ErrorCode::TooManyTypes);
  }

  TypeEntry *Entry = Mod.initTypeTable(NumTypes);
  for (uint32_t I = 0; I < NumTypes; ++I) {
    Byte Flag = readByte();
    if (Flag != Byte(0x60)) {
      throw getError(ErrorCode::InvalidFuncTypeFlag);
    }

    uint32_t NumParams = readU32();
    if (NumParams > PresetMaxNumParams) {
      throw getError(ErrorCode::TooManyParams);
    }

    uint32_t NumParamCells = 0;
    WASMType *ParamTypes = nullptr;
    if (NumParams > (__WORDSIZE / 8)) {
      ParamTypes = Entry->ParamTypes = Mod.initParamTypes(NumParams);
    } else {
      ParamTypes = Entry->ParamTypesVec;
    }
    for (uint32_t J = 0; J < NumParams; ++J) {
      WASMType Type = readValType();
      uint32_t NumCells = getWASMTypeCellNum(Type);
      if (addOverflow(NumParamCells, NumCells, NumParamCells)) {
        throw getError(ErrorCode::TooManyParams);
      }
      ParamTypes[J] = Type;
    }
    if (NumParamCells > PresetMaxNumParamCells) {
      throw getError(ErrorCode::TooManyParams);
    }

    uint32_t NumReturns = readU32();
    WASMType *ReturnTypes = Entry->ReturnTypes;
    if (NumReturns > PresetMaxNumReturns) {
      throw getError(ErrorCode::TooManyReturns);
    }
    uint32_t NumReturnCells = 0;
    for (uint32_t J = 0; J < NumReturns; ++J) {
      WASMType Type = readValType();
      uint32_t NumCells = getWASMTypeCellNum(Type);
      if (addOverflow(NumReturnCells, NumCells, NumReturnCells)) {
        throw getError(ErrorCode::TooManyReturns);
      }
      ReturnTypes[J] = Type;
    }
    if (NumReturnCells > PresetMaxNumReturnCells) {
      throw getError(ErrorCode::TooManyReturns);
    }

    Entry->NumParams = static_cast<uint16_t>(NumParams);
    Entry->NumParamCells = static_cast<uint16_t>(NumParamCells);
    Entry->NumReturns = static_cast<uint8_t>(NumReturns);
    Entry->NumReturnCells = static_cast<uint8_t>(NumReturnCells);
    Entry->SmallestTypeIdx = I;

    for (uint32_t J = 0; J < I; ++J) {
      TypeEntry *Type = Mod.getDeclaredType(J);
      if (TypeEntry::isEqual(Entry, Type)) {
        Entry->SmallestTypeIdx = J;
        break;
      }
    }

    ++Entry;
  }
}

void ModuleLoader::loadImportSection() {
  uint32_t NumImports = readU32();
  if (NumImports > PresetMaxNumImports) {
    throw getError(ErrorCode::TooManyImports);
  }

  std::vector<ImportFunctionEntry> ImportFunctionTable;
  std::vector<ImportTableEntry> ImportTableTable;
  std::vector<ImportMemoryEntry> ImportMemoryTable;
  std::vector<ImportGlobalEntry> ImportGlobalTable;
  // Eliminate reallocations
  ImportFunctionTable.reserve(16);

  uint32_t GlobalOffset = 0;
  // Free these symbols if throw an error in for-loop
  std::vector<SymbolWrapper> ImportSymbols;

  for (uint32_t I = 0; I < NumImports; ++I) {
    try {
      ImportSymbols.emplace_back(*Mod.getRuntime(), readName());
      WASMSymbol ModuleName = ImportSymbols.back().get();
      ImportSymbols.emplace_back(*Mod.getRuntime(), readName());
      WASMSymbol FieldName = ImportSymbols.back().get();

      uint8_t ImportKind = to_underlying(readByte());
      switch (ImportKind) {
      case IMPORT_FUNC: {
        uint32_t TypeIdx = readU32();
        if (!Mod.isValidType(TypeIdx)) {
          throw getError(ErrorCode::UnknownTypeIdx);
        }
        TypeEntry *Type = Mod.getDeclaredType(TypeIdx);
        if (!Type) {
          throw getError(ErrorCode::UnknownTypeIdx);
        }

        const void *FuncPtr = nullptr;
#ifdef ZEN_ENABLE_CHECKED_ARITHMETIC
        if (!resolveCheckedArithmeticFunction(
                &Mod, ModuleName, FieldName,
                static_cast<uint32_t>(ImportFunctionTable.size()))) {
#endif // ZEN_ENABLE_CHECKED_ARITHMETIC
          FuncPtr = resolveImportFunction(ModuleName, FieldName, *Type);
#ifdef ZEN_ENABLE_CHECKED_ARITHMETIC
        }
#endif // ZEN_ENABLE_CHECKED_ARITHMETIC
        ImportFunctionTable.emplace_back(ModuleName, FieldName,
                                         Type->SmallestTypeIdx, FuncPtr);
        break;
      }
#ifdef ZEN_ENABLE_SPEC_TEST
      case IMPORT_TABLE: {
        const auto [MinTableSize, MaxTableSize] = readTableType();
        ImportTableTable.emplace_back(ModuleName, FieldName, MinTableSize,
                                      MaxTableSize);
        break;
      }
      case IMPORT_MEMORY: {
        const auto [MinMemPages, MaxMemPages] = readMemoryType();
        ImportMemoryTable.emplace_back(ModuleName, FieldName, MinMemPages,
                                       MaxMemPages);
        break;
      }
      case IMPORT_GLOBAL: {
        const auto [Type, Mutable] = readGlobalType();
        if (Mutable) {
          throw getError(ErrorCode::InvalidMutability);
        }
        ImportGlobalTable.emplace_back(ModuleName, FieldName, Type, Mutable,
                                       GlobalOffset);
        uint32_t TypeSize = getWASMTypeSize(Type);
        if (addOverflow(ZEN_ALIGN(GlobalOffset, TypeSize), TypeSize,
                        GlobalOffset)) {
          throw getError(ErrorCode::TooManyGlobals);
        }
        break;
      }
#else
      case IMPORT_TABLE:
      case IMPORT_MEMORY:
      case IMPORT_GLOBAL:
        throw getError(ErrorCode::UnsupportedImport);
#endif
      default:
        throw getError(ErrorCode::InvalidImportKind);
      }
    } catch (const Error &Err) {
      throw Err;
    }
  }

  for (SymbolWrapper &Symbol : ImportSymbols) {
    Symbol.release();
  }

  Mod.GlobalVarSize = GlobalOffset;

  uint32_t NumImportFuncs = static_cast<uint32_t>(ImportFunctionTable.size());
  uint32_t NumImportTables = static_cast<uint32_t>(ImportTableTable.size());
  uint32_t NumImportMemories = static_cast<uint32_t>(ImportMemoryTable.size());
  uint32_t NumImportGlobals = static_cast<uint32_t>(ImportGlobalTable.size());

  if (NumImportFuncs > PresetMaxNumFunctions) {
    throw getError(ErrorCode::TooManyFunctions);
  }
  if (NumImportTables > PresetMaxNumTables) {
    throw getError(ErrorCode::TooManyTables);
  }
  if (NumImportMemories > PresetMaxNumMemories) {
    throw getError(ErrorCode::TooManyMemories);
  }
  if (NumImportGlobals > PresetMaxNumGlobals) {
    throw getError(ErrorCode::TooManyGlobals);
  }

  ImportFunctionEntry *FuncTable = Mod.initImportFuncTable(NumImportFuncs);
  ImportTableEntry *TableTable = Mod.initImportTableTable(NumImportTables);
  ImportMemoryEntry *MemTable = Mod.initImportMemoryTable(NumImportMemories);
  ImportGlobalEntry *GlobalTable = Mod.initImportGlobalTable(NumImportGlobals);

  std::memcpy(FuncTable, ImportFunctionTable.data(),
              sizeof(ImportFunctionEntry) * NumImportFuncs);
  std::memcpy(TableTable, ImportTableTable.data(),
              sizeof(ImportTableEntry) * NumImportTables);
  std::memcpy(MemTable, ImportMemoryTable.data(),
              sizeof(ImportMemoryEntry) * NumImportMemories);
  std::memcpy(GlobalTable, ImportGlobalTable.data(),
              sizeof(ImportGlobalEntry) * NumImportGlobals);

  Mod.NumImportFunctions = NumImportFuncs;
  Mod.NumImportTables = NumImportTables;
  Mod.NumImportMemories = NumImportMemories;
  Mod.NumImportGlobals = NumImportGlobals;
}

void ModuleLoader::loadFunctionSection() {
  uint32_t NumFunctions = readU32();
  uint32_t TotalNumFunctions;
  if (addOverflow(NumFunctions, Mod.NumImportFunctions, TotalNumFunctions)) {
    throw getError(ErrorCode::TooManyFunctions);
  }
  if (TotalNumFunctions > PresetMaxNumFunctions) {
    throw getError(ErrorCode::TooManyFunctions);
  }

  FuncEntry *Entry = Mod.initFuncTable(NumFunctions);
  for (uint32_t I = 0; I < NumFunctions; ++I) {
    uint32_t TypeIdx = readU32();
    if (!Mod.isValidType(TypeIdx)) {
      throw getError(ErrorCode::UnknownTypeIdx);
    }

    TypeEntry *Type = Mod.getDeclaredType(TypeIdx);
    if (!Type) {
      throw getError(ErrorCode::UnknownTypeIdx);
    }

    Entry->OriginTypeIdx = TypeIdx;
    Entry->TypeIdx = Type->SmallestTypeIdx;

    ++Entry;
  }
}

void ModuleLoader::loadTableSection() {
  uint32_t NumTables = readU32();
  uint32_t TotalNumTables;
  if (addOverflow(NumTables, Mod.NumImportTables, TotalNumTables) ||
      TotalNumTables > PresetMaxNumTables) {
    throw getError(ErrorCode::TooManyTables);
  }

  TableEntry *Entry = Mod.initTableTable(NumTables);
  for (uint32_t I = 0; I < NumTables; ++I) {
    const auto [MinTableSize, MaxTableSize] = readTableType();

    Entry->InitSize = MinTableSize;
    Entry->MaxSize = MaxTableSize;

    ++Entry;
  }
}

void ModuleLoader::loadMemorySection() {
  uint32_t NumMemories = readU32();
  uint32_t TotalNumMemories;
  if (addOverflow(NumMemories, Mod.NumImportMemories, TotalNumMemories) ||
      TotalNumMemories > PresetMaxNumMemories) {
    throw getError(ErrorCode::TooManyMemories);
  }

  MemoryEntry *Entry = Mod.initMemoryTable(NumMemories);
  for (uint32_t I = 0; I < NumMemories; ++I) {
    const auto [MinMemPages, MaxMemPages] = readMemoryType();

    Entry->InitSize = MinMemPages;
    Entry->MaxSize = MaxMemPages;

    ++Entry;
  }
}

void ModuleLoader::loadGlobalSection() {
  uint32_t NumGlobals = readU32();
  uint32_t TotalNumGlobals;
  if (addOverflow(NumGlobals, Mod.NumImportGlobals, TotalNumGlobals) ||
      TotalNumGlobals > PresetMaxNumGlobals) {
    throw getError(ErrorCode::TooManyGlobals);
  }

  GlobalEntry *Entry = Mod.initGlobalTable(NumGlobals);
  uint32_t GlobalOffset = Mod.GlobalVarSize;
  for (uint32_t I = 0; I < NumGlobals; ++I) {
    const auto [Type, Mutable] = readGlobalType();
    const auto [ExprKind, Expr] = readConstExpr(Type);

    Entry->Offset = GlobalOffset;
    Entry->InitExprKind = ExprKind;
    Entry->InitExprVal = Expr;
    Entry->Type = Type;
    Entry->Mutable = Mutable;

    uint32_t TypeSize = getWASMTypeSize(Type);
    if (addOverflow(ZEN_ALIGN(GlobalOffset, TypeSize), TypeSize,
                    GlobalOffset)) {
      throw getError(ErrorCode::TooManyGlobals);
    }

    ++Entry;
  }

  Mod.GlobalVarSize = GlobalOffset;
}

void ModuleLoader::loadExportSection() {
  uint32_t NumExports = readU32();
  if (NumExports > PresetMaxNumExports) {
    throw getError(ErrorCode::TooManyExports);
  }

#ifdef ZEN_ENABLE_MULTIPASS_JIT
  auto EntrySymPtr = SymbolWrapper::newSymbol(*Mod.getRuntime(), Mod.EntryHint);
  WASMSymbol EntrySym =
      EntrySymPtr ? EntrySymPtr->get() : WASMSymbol(WASM_SYMBOL_NULL);
  uint32_t EntryFuncIdx = -1u;
#endif

  ExportEntry *Entry = Mod.initExportTable(NumExports);
  for (uint32_t I = 0; I < NumExports; ++I) {
    WASMSymbol Name = readName();
    Entry->Name = Name;
    // Check if the name has already been used
    for (uint32_t J = 0; J < I; ++J) {
      if (Mod.ExportTable[J].Name == Name) {
        throw getError(ErrorCode::DuplicateExportName);
      }
    }

    uint8_t ExportKind = to_underlying(readByte());
    uint32_t ExportIdx = readU32();
    switch (ExportKind) {
    case EXPORT_FUNC:
      if (!Mod.isValidFunc(ExportIdx)) {
        throw getError(ErrorCode::UnknownFunction);
      }
      if (Name == WASM_SYMBOL_func_gas) {
        TypeEntry *GasFuncType = Mod.getFunctionType(ExportIdx);
        if (GasFuncType->NumParams == 1 && GasFuncType->NumReturns == 0 &&
            GasFuncType->getParamTypes()[0] == WASMType::I64) {
          Mod.GasFuncIdx = ExportIdx;
        } else {
          throw getError(ErrorCode::InvalidGasFuncType);
        }
      }
#ifdef ZEN_ENABLE_MULTIPASS_JIT
      if (ZEN_LIKELY(ExportIdx >= Mod.NumImportFunctions)) {
        if (Name == EntrySym) {
          EntryFuncIdx = ExportIdx;
        } else {
          Mod.ExportedFuncIdxs.push_back(ExportIdx);
        }
      }
#endif
      break;
    case EXPORT_TABLE:
      if (!Mod.isValidTable(ExportIdx)) {
        throw getError(ErrorCode::UnknownTable);
      }
      break;
    case EXPORT_MEMORY:
      if (!Mod.isValidMem(ExportIdx)) {
        throw getError(ErrorCode::UnknownMemory);
      }
      break;
    case EXPORT_GLOBAL:
      if (!Mod.isValidGlobal(ExportIdx)) {
        throw getError(ErrorCode::UnknownGlobal);
      }
      break;
    default:
      throw getError(ErrorCode::InvalidExportKind);
    }

    Entry->Kind = ExportKind;
    Entry->ItemIdx = ExportIdx;

    ++Entry;
  }

#ifdef ZEN_ENABLE_MULTIPASS_JIT
  // Push the entry function index to the end of `ExportedFuncIdxs`
  if (EntryFuncIdx != -1u) {
    Mod.ExportedFuncIdxs.push_back(EntryFuncIdx);
  }
#endif
}

void ModuleLoader::loadStartSection() {
  uint32_t StartFuncIdx = readU32();

  if (!Mod.isValidFunc(StartFuncIdx)) {
    throw getError(ErrorCode::UnknownFunction);
  }

  // The type of start function must be `[] -> []`
  TypeEntry *Type = Mod.getFunctionType(StartFuncIdx);
  if (!Type || Type->NumParams != 0 || Type->NumReturns != 0) {
    throw getError(ErrorCode::InvalidStartFuncType);
  }

  Mod.StartFuncIdx = StartFuncIdx;
}

void ModuleLoader::loadElementSection() {
  uint32_t NumElemSegments = readU32();
  if (NumElemSegments > PresetMaxNumElemSegments) {
    throw getError(ErrorCode::TooManyElemSegments);
  }

  ElemEntry *Entry = Mod.initElemTable(NumElemSegments);
  for (uint32_t I = 0; I < NumElemSegments; ++I) {
    uint32_t TableIdx = readU32();
    if (!Mod.isValidTable(TableIdx)) {
      throw getError(ErrorCode::UnknownTable);
    }

    const auto [ExprKind, Expr] = readConstExpr(WASMType::I32);

    uint32_t NumFuncIdxs = readU32();
    // Set the field `NumFuncIdxs` and `FuncIdxs` implicitly
    uint32_t *FuncIdxs = Mod.initFuncIdxTable(NumFuncIdxs, Entry);
    for (uint32_t J = 0; J < NumFuncIdxs; ++J) {
      uint32_t FuncIdx = readU32();
      if (!Mod.isValidFunc(FuncIdx)) {
        throw getError(ErrorCode::UnknownFunction);
      }
      FuncIdxs[J] = FuncIdx;
#ifdef ZEN_ENABLE_MULTIPASS_JIT
      if (ZEN_LIKELY(FuncIdx >= Mod.NumImportFunctions)) {
        uint32_t TypeIdx = Mod.getFunctionTypeIdx(FuncIdx);
        Mod.TypedFuncRefs[TypeIdx].push_back(FuncIdx);
      }
#endif
    }

    Entry->TableIdx = TableIdx;
    Entry->InitExprKind = ExprKind;
    Entry->InitExprVal = Expr;

    ++Entry;
  }
}

void ModuleLoader::loadDataCountSection() { Mod.DataCount = readU32(); }

void ModuleLoader::loadCodeSection() {
  uint32_t NumCodes = readU32();
  // Only check function number consistency, no need to check `NumCodes` range
  if (NumCodes != Mod.NumInternalFunctions) {
    throw getError(ErrorCode::FuncCodeInconsistent);
  }

  // Calculate the distance between callsite and callee in AArch64 singlepass
  uint32_t CodeOffset = 0;

  CodeEntry *Entry = Mod.initCodeTable(NumCodes);
  uint32_t NumImportFunctions = Mod.getNumImportFunctions();
  uint32_t NumTotalFunctions = NumImportFunctions + NumCodes;
  for (uint32_t I = NumImportFunctions; I < NumTotalFunctions; ++I) {
    uint32_t CodeSize = readU32();
    if (CodeSize > PresetMaxFunctionSize) {
      throw getError(ErrorCode::FunctionSizeTooLarge);
    }

    // Include `vec(locals) expr`
    const Byte *CodePtrStart = Ptr;
    uint32_t NumLocals = 0;
    uint32_t NumLocalCells = 0;
    uint32_t NumLocalVectors = readU32();
    const Byte *PrevPtr = Ptr;

    // First pass to get the total number and cells of locals
    for (uint32_t J = 0; J < NumLocalVectors; ++J) {
      // Number of same type locals
      uint32_t NumSameLocals = readU32();
      if (addOverflow(NumLocals, NumSameLocals, NumLocals)) {
        throw getError(ErrorCode::TooManyLocals);
      }

      WASMType Type = readValType();
      uint32_t NumCells = getWASMTypeCellNum(Type);

      uint32_t NumSameLocalCells;
      if (mulOverflow(NumSameLocals, NumCells, NumSameLocalCells) ||
          addOverflow(NumLocalCells, NumSameLocalCells, NumLocalCells)) {
        throw getError(ErrorCode::TooManyLocals);
      }
    }

    if (NumLocals > PresetMaxFunctionLocals ||
        NumLocalCells > PresetMaxFunctionLocalCells) {
      throw getError(ErrorCode::TooManyLocals);
    }

    WASMType *LocalTypes = Mod.initLocalTypes(NumLocals);
    WASMType *LocalTypesPtr = LocalTypes;
    Ptr = PrevPtr;

    // Second pass to set the local types
    for (uint32_t J = 0; J < NumLocalVectors; ++J) {
      uint32_t NumSameLocals = readU32();
      WASMType Type = readValType();
      std::memset(LocalTypesPtr, to_underlying(Type), NumSameLocals);
      if (addOverflow(LocalTypesPtr, NumSameLocals, LocalTypesPtr)) {
        throw getError(ErrorCode::TooManyLocals);
      }
    }

    TypeEntry *FuncType = Mod.getFunctionType(I);
    ZEN_ASSERT(FuncType);
    uint32_t NumParamsAndLocals;
    if (addOverflow(static_cast<uint32_t>(FuncType->NumParams), NumLocals,
                    NumParamsAndLocals)) {
      throw getError(ErrorCode::TooManyLocals);
    }
    size_t TotalLocalSize = NumParamsAndLocals * sizeof(uint32_t);
    if (TotalLocalSize > 0) {
      Entry->LocalOffsets = Mod.initLocalOffsets(TotalLocalSize);

      const WASMType *ParamTypes = FuncType->getParamTypes();
      uint32_t LocalOffset = 0;

      // Set the offsets of parameters
      for (uint32_t J = 0; J < FuncType->NumParams; ++J) {
        Entry->LocalOffsets[J] = LocalOffset;
        uint32_t ParamSize = getWASMTypeCellNum(ParamTypes[J]);
        if (addOverflow(LocalOffset, ParamSize, LocalOffset)) {
          throw getError(ErrorCode::TooManyParams);
        }
      }

      // Set the offsets of local variables
      for (uint32_t J = 0; J < NumLocals; ++J) {
        Entry->LocalOffsets[FuncType->NumParams + J] = LocalOffset;
        uint32_t LocalSize = getWASMTypeCellNum(LocalTypes[J]);
        if (addOverflow(LocalOffset, LocalSize, LocalOffset)) {
          throw getError(ErrorCode::TooManyLocals);
        }
      }

#if defined(ZEN_ENABLE_DWASM) && defined(ZEN_ENABLE_JIT)
      Entry->JITStackCost = (LocalOffset << 2) + 64;
#endif
    } else {
#if defined(ZEN_ENABLE_DWASM) && defined(ZEN_ENABLE_JIT)
      Entry->JITStackCost = 64;
#endif
    }

    // ActualCodeSize < CodeSize < PresetMaxFunctionSize < UINT32_MAX
    uint32_t ActualCodeSize = CodePtrStart + CodeSize - Ptr;

    Entry->NumLocals = static_cast<uint16_t>(NumLocals);
    Entry->NumLocalCells = static_cast<uint16_t>(NumLocalCells);
    Entry->LocalTypes = LocalTypes;
    Entry->CodePtr = reinterpret_cast<const uint8_t *>(Ptr);
    Entry->CodeSize = ActualCodeSize;
    Entry->CodeOffset = CodeOffset;
    Entry->Stats = Module::SF_none;

    const Byte *CodePtrEnd;
    if (addOverflow(Ptr, ActualCodeSize, CodePtrEnd) || CodePtrEnd > End) {
      throw getError(ErrorCode::UnexpectedEnd);
    }

    FunctionLoader FuncLoader(Mod, Ptr, CodePtrEnd, I, *FuncType, *Entry);
    FuncLoader.load();

    Ptr = CodePtrEnd;
    if (addOverflow(CodeOffset, ActualCodeSize, CodeOffset) ||
        CodeOffset > PresetMaxTotalFunctionSize) {
      throw getError(ErrorCode::CodeSectionTooLarge);
    }

    ++Entry;
  }
}

void ModuleLoader::loadDataSection() {
  uint32_t NumDataSegments = readU32();
  if (NumDataSegments > PresetMaxNumDataSegments) {
    throw getError(ErrorCode::TooManyDataSegments);
  }

  // If exist data count section, check the consistency
  if (Mod.DataCount != -1u && NumDataSegments != Mod.DataCount) {
    throw getError(ErrorCode::DataSegAndDataCountInconsistent);
  }

  uint32_t TotalDataSize = 0;
  DataEntry *Entry = Mod.initDataTable(NumDataSegments);
  for (uint32_t I = 0; I < NumDataSegments; ++I) {
    uint32_t MemIdx = readU32();
    if (!Mod.isValidMem(MemIdx)) {
      throw getError(ErrorCode::UnknownMemory);
    }

    const auto [ExprKind, Expr] = readConstExpr(WASMType::I32);

    uint32_t DataSegmentSize = readU32();
    if (DataSegmentSize > PresetMaxDataSegmentSize ||
        addOverflow(TotalDataSize, DataSegmentSize, TotalDataSize)) {
      throw getError(ErrorCode::DataSegmentTooLarge);
    }

    uint32_t DataPtrOffset = Ptr - Start;
    if (addOverflow(Ptr, DataSegmentSize, Ptr) || Ptr > End) {
      throw getError(ErrorCode::UnexpectedEnd);
    }

    Entry->MemIdx = MemIdx;
    Entry->Size = DataSegmentSize;
    Entry->Offset = DataPtrOffset;
    Entry->InitExprKind = ExprKind;
    Entry->InitExprVal = Expr;

    ++Entry;
  }

  if (TotalDataSize > PresetMaxTotalDataSize) {
    throw getError(ErrorCode::DataSectionTooLarge);
  }
}

void ModuleLoader::loadNameSection() {
  NameSectionType NoneSubSec = static_cast<NameSectionType>(-1u);
  NameSectionType LastSubSecType = NoneSubSec;

  while (Ptr < End) {
    NameSectionType SubSecType = static_cast<NameSectionType>(readByte());
    uint32_t SubSecSize = readU32();

    // Check subsection type
    if (LastSubSecType != NoneSubSec) {
      if (SubSecType < LastSubSecType) {
        throw getError(ErrorCode::OutOfOrderNameSubSection);
      }
      if (SubSecType == LastSubSecType) {
        throw getError(ErrorCode::DuplicateSubSection);
      }
      if (SubSecType > NameSectionType::NAMESEC_LAST) {
        throw getError(ErrorCode::InvalidNameSubSection);
      }
    }
    LastSubSecType = SubSecType;

    // Check subsection size
    const Byte *SubSecEnd;
    if (SubSecSize > PresetMaxSectionSize ||
        addOverflow(Ptr, SubSecSize, SubSecEnd)) {
      throw getError(ErrorCode::SectionSizeTooLarge);
    }
    if (SubSecEnd > End) {
      throw getError(ErrorCode::UnexpectedEnd);
    }

    // Swap `SubSecEnd` and `End` and restore after loading current subsection,
    // and the `End` has exchanged with `SecEnd` before this
    std::swap(SubSecEnd, End);
    switch (SubSecType) {
    case NameSectionType::NAMESEC_FUNCTION: {
      uint32_t NumFuncNames = readU32();
      if (NumFuncNames > Mod.getNumTotalFunctions()) {
        throw getError(ErrorCode::OutOfRangeFuncIdx);
      }

      uint32_t LastFuncIdx = -1u;
      for (uint32_t I = 0; I < NumFuncNames; ++I) {
        uint32_t FuncIdx = readU32();
        if (!Mod.isValidFunc(FuncIdx)) {
          throw getError(ErrorCode::UnknownFunction);
        }

        if (LastFuncIdx != -1u) {
          if (FuncIdx < LastFuncIdx) {
            throw getError(ErrorCode::OutOfOrderFuncIdx);
          }
          if (FuncIdx == LastFuncIdx) {
            throw getError(ErrorCode::DuplicateFuncName);
          }
        }
        LastFuncIdx = FuncIdx;

        SymbolWrapper FuncName(*Mod.getRuntime(), readName());
        uint32_t NumImportFuncs = Mod.getNumImportFunctions();
        if (FuncIdx >= NumImportFuncs) {
          FuncEntry &Func = Mod.InternalFunctionTable[FuncIdx - NumImportFuncs];
          Func.Name = FuncName.release();
        }
      }
      break;
    }
    case NameSectionType::NAMESEC_MODULE:
    case NameSectionType::NAMESEC_LOCAL:
    case NameSectionType::NAMESEC_LABEL:
    case NameSectionType::NAMESEC_TYPE:
    case NameSectionType::NAMESEC_TABLE:
    case NameSectionType::NAMESEC_MEMORY:
    case NameSectionType::NAMESEC_GLOBAL:
    case NameSectionType::NAMESEC_ELEMSEG:
    case NameSectionType::NAMESEC_DATASEG:
    case NameSectionType::NAMESEC_TAG:
    default:
      // Skip unsupported or unknown name subsection
      Ptr = End;
      break;
    }
    std::swap(SubSecEnd, End);

    if (Ptr != SubSecEnd) {
      throw getError(ErrorCode::SectionSizeMismath);
    }
  }

  HasNameSection = true;
}

#ifdef ZEN_ENABLE_SPEC_TEST
void ModuleLoader::patchForSpecTest() {
  ImportTableEntry *TablEntry = Mod.ImportTableTable;
  for (uint32_t I = 0; I < Mod.NumImportTables; ++I) {
    /* (table (export "table") 10 20 funcref) */
    if (TablEntry->ModuleName == WASM_SYMBOL_spectest) {
      TablEntry->InitSize = 10;
      TablEntry->MaxSize = 20;
    }
    TablEntry++;
  }

  ImportMemoryEntry *MemEntry = Mod.ImportMemoryTable;
  for (uint32_t I = 0; I < Mod.NumImportMemories; ++I) {
    /* (memory (export "memory") 1 2) */
    if (MemEntry->ModuleName == WASM_SYMBOL_spectest) {
      MemEntry->InitPages = 1;
      MemEntry->MaxPages = 2;
    }
    MemEntry++;
  }
}
#endif

} // namespace zen::action
