// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_RUNTIME_MODULE_H
#define ZEN_RUNTIME_MODULE_H

#include "common/const_string_pool.h"
#include "common/errors.h"
#include "runtime/memory.h"
#include "runtime/object.h"
#include "utils/safe_map.h"

#ifdef ZEN_ENABLE_MULTIPASS_JIT
namespace COMPILER {
class LazyJITCompiler;
}; // namespace COMPILER
#endif

namespace zen {

namespace action {
class HostModuleLoader;
class ModuleLoader;
class EVMModuleLoader;
class FunctionLoader;
class Instantiator;
} // namespace action

namespace runtime {

using common::WASMType;

enum class ModuleType {
  WASM,
  EVM,
  JIT,
  AOT,
  NATIVE,
};

template <typename T> class BaseModule : public RuntimeObject<T> {
public:
  ModuleType getType() const { return Type; }

  WASMSymbol getName() const { return Name; }

  void setName(WASMSymbol NewName) {
    if (Name) {
      this->freeSymbol(Name);
    }
    Name = NewName;
  }

protected:
  BaseModule(Runtime *RT, ModuleType Type)
      : RuntimeObject<T>(*RT), Type(Type) {}

  virtual ~BaseModule() { destroy(); }

  ModuleType Type;

  WASMSymbol Name = common::WASM_SYMBOL_NULL;

private:
  void destroy() {
    if (Name) {
      this->freeSymbol(Name);
      Name = common::WASM_SYMBOL_NULL;
    }
  }
};

class HostModule final : public BaseModule<HostModule> {
  using ConstStringPool = common::ConstStringPool;
  using SysMemPool = common::SysMemPool;

  friend class RuntimeObjectDestroyer;
  friend class action::HostModuleLoader;

public:
  HostModule() = delete;

  static HostModuleUniquePtr newModule(Runtime &RT, BuiltinModuleDesc *ModDesc);

  const std::vector<const NativeFuncDesc *> &getHostFuntionList() const {
    return HostFunctionList;
  }

  uint32_t getNumHostFunctions() {
    return static_cast<uint32_t>(HostFunctionList.size());
  }

  VNMIEnv *getVNMIEnv() { return reinterpret_cast<VNMIEnv *>(&_vnmi_env); }

  const BuiltinModuleDesc *getModuleDesc() { return MainModDesc; }

  void addFunctions(const BuiltinModuleDesc *HostModDesc,
                    const NativeFuncDesc *HostFuncDescs, uint32_t NumFunctions);

  bool
  filterFunctions(const std::vector<common::StringView> &WhiteList) noexcept;

  // temporally define them here
  SysMemPool *getMemAllocator();
  ConstStringPool *getSymbolPool();

private:
  HostModule(Runtime *RT, BuiltinModuleDesc *ModDesc);

  virtual ~HostModule() {
    for (const auto &[HostModDesc, HostFuncDescs] : HostModMap) {
      if (HostModDesc && HostModDesc->_unload_func) {
        HostModDesc->_unload_func(reinterpret_cast<VNMIEnv *>(&_vnmi_env),
                                  const_cast<NativeFuncDesc *>(HostFuncDescs));
      }
    }
  }

  VNMIEnvInternal _vnmi_env;
  const BuiltinModuleDesc *MainModDesc = nullptr;
  std::unordered_map<const BuiltinModuleDesc *, const NativeFuncDesc *>
      HostModMap;
  std::vector<const NativeFuncDesc *> HostFunctionList;
};

struct TypeEntry final {
  uint16_t NumParams;
  uint16_t NumParamCells;
  uint8_t NumReturns : 2;
  uint8_t NumReturnCells : 6;
  WASMType ReturnTypes[2];
  union {
    WASMType *ParamTypes;
    WASMType ParamTypesVec[__WORDSIZE / 8];
  };
  uint32_t SmallestTypeIdx;

  const WASMType *getParamTypes() const {
    if (NumParams > (__WORDSIZE / 8)) {
      return ParamTypes;
    }
    return ParamTypesVec;
  }

  WASMType getReturnType() const {
    ZEN_ASSERT(NumReturns <= 1);
    return NumReturns > 0 ? ReturnTypes[0] : WASMType::VOID;
  }

  static bool isEqual(TypeEntry *Type1, TypeEntry *Type2);
};

struct ImportEntryBase {
  WASMSymbol ModuleName;
  WASMSymbol FieldName;
};

struct ImportFunctionEntry final : ImportEntryBase {
  uint32_t TypeIdx;
  const void *FuncPtr;
  /// \note constructor is required to initialize under C++14
  ImportFunctionEntry(WASMSymbol ModuleName, WASMSymbol FieldName,
                      uint32_t TypeIdx, const void *FuncPtr)
      : ImportEntryBase{ModuleName, FieldName}, TypeIdx(TypeIdx),
        FuncPtr(FuncPtr) {}
};

struct ImportTableEntry final : ImportEntryBase {
  uint32_t InitSize;
  uint32_t MaxSize;
  /// \note constructor is required to initialize under C++14
  ImportTableEntry(WASMSymbol ModuleName, WASMSymbol FieldName,
                   uint32_t InitSize, uint32_t MaxSize)
      : ImportEntryBase{ModuleName, FieldName}, InitSize(InitSize),
        MaxSize(MaxSize) {}
};

struct ImportMemoryEntry final : ImportEntryBase {
  uint32_t InitPages;
  uint32_t MaxPages;
  /// \note constructor is required to initialize under C++14
  ImportMemoryEntry(WASMSymbol ModuleName, WASMSymbol FieldName,
                    uint32_t InitPages, uint32_t MaxPages)
      : ImportEntryBase{ModuleName, FieldName}, InitPages(InitPages),
        MaxPages(MaxPages) {}
};

struct ImportGlobalEntry final : ImportEntryBase {
  WASMType Type;
  bool Mutable;
  uint32_t Offset;
  /// \note constructor is required to initialize under C++14
  ImportGlobalEntry(WASMSymbol ModuleName, WASMSymbol FieldName, WASMType Type,
                    bool Mutable, uint32_t Offset)
      : ImportEntryBase{ModuleName, FieldName}, Type(Type), Mutable(Mutable),
        Offset(Offset) {}
};

struct FuncEntry final {
  WASMSymbol Name;
  uint32_t TypeIdx;
  uint32_t OriginTypeIdx;
};

struct TableEntry final {
  uint32_t InitSize;
  uint32_t MaxSize;
};

struct MemoryEntry final {
  uint32_t InitSize;
  uint32_t MaxSize;
};

union InitExpr final {
  uint32_t GlobalIdx;
  int32_t I32;
  int64_t I64;
  float F32;
  double F64;
};

struct GlobalEntry final {
  WASMType Type;
  uint8_t Mutable;
  uint8_t InitExprKind;
  InitExpr InitExprVal;
  uint32_t Offset;
};

struct ExportEntry {
  WASMSymbol Name;
  uint8_t Kind;
  uint32_t ItemIdx;
};

struct ElemEntry {
  uint32_t TableIdx;
  uint8_t InitExprKind;
  InitExpr InitExprVal;
  uint32_t NumFuncIdxs;
  uint32_t *FuncIdxs;
#ifdef ZEN_ENABLE_BULK_MEMORY
  uint8_t Mode; // 0=active, 1=passive, 2=declarative
#endif
};

struct CodeEntry {
  const uint8_t *CodePtr;
#ifdef ZEN_ENABLE_JIT
  const uint8_t *JITCodePtr;
#endif
  uint32_t CodeSize;
  uint32_t MaxStackSize;
  uint32_t MaxBlockDepth;
  uint16_t NumLocals;
  uint16_t NumLocalCells;
  WASMType *LocalTypes;
  uint32_t *LocalOffsets;
  uint32_t Stats;
  // indicate the approximate offset of current function in wasm bytecode
  uint32_t CodeOffset;
#if defined(ZEN_ENABLE_DWASM) && defined(ZEN_ENABLE_JIT)
  uint32_t JITStackCost;
#endif
};

struct DataEntry {
  uint32_t MemIdx;
  uint32_t Size;
  uint32_t Offset;
  uint8_t InitExprKind;
  InitExpr InitExprVal;
#ifdef ZEN_ENABLE_BULK_MEMORY
  uint8_t Mode; // 0=active, 1=passive
#endif
};

class Module final : public BaseModule<Module> {
  struct InstanceLayout {
    InstanceLayout(Module &M) : Mod(M) {}

    InstanceLayout(const InstanceLayout &Other) = delete;
    InstanceLayout &operator=(const InstanceLayout &Other) = delete;

    static constexpr size_t Alignment = 8;

    Module &Mod;

    size_t InstanceSize = 0;

    size_t FuncInstancesSize = 0;

    size_t GlobalInstancesSize = 0;
    size_t GlobalVarBaseOffset = 0;
    size_t GlobalVarSize = 0;

    size_t TableInstancesSize = 0;
    size_t TableElemBaseOffset = 0;
    size_t TableElemSizeOffset = 0;
    size_t TableElemsSize = 0;

    size_t MemoryInstancesSize = 0;
    // Differs from TableElemBaseOffset, you must load memory base pointer
    // through MemoryBaseOffset before accessing memory data.
    size_t MemoryBaseOffset = 0;
    size_t MemorySizeOffset = 0;
    size_t MemoryPagesOffset = 0;

#ifdef ZEN_ENABLE_JIT
    size_t FuncPtrsBaseOffset = 0;
    size_t FuncPtrsSize = 0;

    size_t FuncTypeIndexesBaseOffset = 0;
    size_t FuncTypeIndexesSize = 0;

    size_t StackBoundaryOffset = 0;
#ifdef ZEN_ENABLE_DUMP_CALL_STACK
    size_t TracesSize = 0;
#endif // ZEN_ENABLE_DUMP_CALL_STACK
#endif // ZEN_ENABLE_JIT

    size_t ExceptionOffset = 0;

#ifdef ZEN_ENABLE_DWASM
    size_t StackCostOffset = 0;
#endif

    uint64_t GasOffset = 0;
    size_t TotalSize = 0;

    void compute();

    std::pair<WASMType, size_t>
    getGlobalTypeAndOffset(uint32_t GlobalIdx) const;
  };

  friend class RuntimeObjectDestroyer;
  friend class action::ModuleLoader;
  friend class action::FunctionLoader;
  friend class Instance;
  friend class action::Instantiator;

public:
  enum StatsFlags : uint32_t {
    SF_none = 0,
    SF_global = 1 << 0, // Access global variables
    SF_memory = 1 << 1, // Access linear memory
    SF_table = 1 << 2,  // Access table
  };

  static ModuleUniquePtr newModule(Runtime &RT, CodeHolderUniquePtr CodeHolder,
                                   const std::string &EntryHint = "");

  void releaseMemoryAllocatorCache();

  // ==================== Metadata Methods ====================

  const uint8_t *getWASMBytecode() const;

  // ==================== Number Methods ====================

  uint32_t getNumImportFunctions() const { return NumImportFunctions; }

  uint32_t getNumInternalFunctions() const { return NumInternalFunctions; }

  uint32_t getNumTotalFunctions() const {
    return NumImportFunctions + NumInternalFunctions;
  }

  uint32_t getNumTotalTables() const {
    return NumImportTables + NumInternalTables;
  }

  uint32_t getNumInternalMemories() const { return NumInternalMemories; }

  uint32_t getNumTotalMemories() const {
    return NumImportMemories + NumInternalMemories;
  }

  uint32_t getNumImportGlobals() const { return NumImportGlobals; }

  uint32_t getNumInternalGlobals() const { return NumInternalGlobals; }

  uint32_t getNumTotalGlobals() const {
    return NumImportGlobals + NumInternalGlobals;
  }

  uint32_t getNumDataSegments() const { return NumDataSegments; }

  uint32_t getNumElementSegments() const { return NumElementSegments; }

  // ==================== Validating Methods ====================

  bool isValidType(uint32_t TypeIdx) const { return TypeIdx < NumTypes; }

  bool isValidFunc(uint32_t FuncIdx) const {
    return FuncIdx < getNumTotalFunctions();
  }

  bool isValidTable(uint32_t TableIdx) const {
    return TableIdx < getNumTotalTables();
  }

  bool isValidMem(uint32_t MemIdx) const {
    return MemIdx < getNumTotalMemories();
  }

  bool isValidImportGlobal(uint32_t GlobalIdx) const {
    return GlobalIdx < NumImportGlobals;
  }

  bool isValidGlobal(uint32_t GlobalIdx) const {
    return GlobalIdx < getNumTotalGlobals();
  }

  bool isValidDataSegment(uint32_t DataIdx) const {
    // During code validation, NumDataSegments may not be set yet
    // (Data section comes after Code section), so use DataCount if available
    uint32_t Count = (DataCount != -1u) ? DataCount : NumDataSegments;
    return DataIdx < Count;
  }

  bool isValidElemSegment(uint32_t ElemIdx) const {
    return ElemIdx < NumElementSegments;
  }

  // ==================== Segment Accessing Methods ====================

  TypeEntry *getDeclaredType(uint32_t TypeIdx) const {
    ZEN_ASSERT(isValidType(TypeIdx));
    return TypeTable + TypeIdx;
  }

  const ImportFunctionEntry &getImportFunction(uint32_t FuncIdx) const {
    ZEN_ASSERT(FuncIdx < NumImportFunctions);
    return ImportFunctionTable[FuncIdx];
  }

  const FuncEntry &getInternalFunction(uint32_t InternalFuncIdx) const {
    ZEN_ASSERT(InternalFuncIdx < NumInternalFunctions);
    return InternalFunctionTable[InternalFuncIdx];
  }

  uint32_t getFunctionTypeIdx(uint32_t FuncIdx) const;

  TypeEntry *getFunctionType(uint32_t FuncIdx) const;

  ImportGlobalEntry *getImportGlobal(uint32_t GlobalIdx) const {
    ZEN_ASSERT(GlobalIdx < NumImportGlobals);
    return ImportGlobalTable + GlobalIdx;
  }

  const GlobalEntry &getInternalGlobal(uint32_t InternalGlobalIdx) const {
    ZEN_ASSERT(InternalGlobalIdx < NumInternalGlobals);
    return InternalGlobalTable[InternalGlobalIdx];
  }

  WASMType getGlobalType(uint32_t GlobalIdx) const {
    if (GlobalIdx < NumImportGlobals) {
      return getImportGlobal(GlobalIdx)->Type;
    }
    uint32_t InternalGlobalIdx = GlobalIdx - NumImportGlobals;
    return getInternalGlobal(InternalGlobalIdx).Type;
  }

  const MemoryEntry &getDefaultMemoryEntry() const {
    ZEN_ASSERT(NumInternalMemories == 1);
    return InternalMemoryTable[0];
  }

  bool getExportFunc(WASMSymbol Name, uint32_t &FuncIdx) const noexcept;

  bool getExportFunc(const std::string &Name, uint32_t &FuncIdx) const noexcept;

  uint32_t getStartFuncIdx() const { return StartFuncIdx; };

  CodeEntry *getCodeEntry(uint32_t FuncIdx) const;

  DataEntry *getDataEntry(uint32_t DataSegIdx) const {
    ZEN_ASSERT(DataSegIdx < NumDataSegments);
    return DataTable + DataSegIdx;
  }

  ElemEntry *getElemEntry(uint32_t ElemSegIdx) const {
    ZEN_ASSERT(ElemSegIdx < NumElementSegments);
    return ElementTable + ElemSegIdx;
  }

  // ==================== Layout Methods ====================

  const InstanceLayout &getLayout() const { return Layout; }

  // ==================== Platform Feature Methods ====================

  uint32_t getGasFuncIdx() const { return GasFuncIdx; }

  WasmMemoryAllocator *getMemoryAllocator();

  bool checkUseSoftLinearMemoryCheck() const {
#ifdef ZEN_ENABLE_CPU_EXCEPTION
    return false;
#else
    return true;
#endif
  }

  // ==================== JIT Methods ====================

#ifdef ZEN_ENABLE_JIT
  common::CodeMemPool &getJITCodeMemPool() { return JITCodeMemPool; }

  void *getJITCode() const { return JITCode; }

  size_t getJITCodeSize() const { return JITCodeSize; }

  void setJITCodeAndSize(void *Code, size_t Size) {
    JITCode = Code;
    JITCodeSize = Size;
  }

#ifdef ZEN_ENABLE_DUMP_CALL_STACK
  auto &getSortedJITFuncPtrs() { return SortedJITFuncPtrs; }

  const auto &getSortedJITFuncPtrs() const { return SortedJITFuncPtrs; }
#endif // ZEN_ENABLE_DUMP_CALL_STACK

#ifdef ZEN_ENABLE_MULTIPASS_JIT
  COMPILER::LazyJITCompiler *newLazyJITCompiler();

  COMPILER::LazyJITCompiler *getLazyJITCompiler() const {
    ZEN_ASSERT(LazyJITCompiler);
    return LazyJITCompiler.get();
  }

  const auto &getExportedFuncIdxs() const { return ExportedFuncIdxs; }

  const auto &getCallSeqMap() const { return CallSeqMap; }
#endif // ZEN_ENABLE_MULTIPASS_JIT

#endif // ZEN_ENABLE_JIT

  // ==================== Utilities ====================

#ifdef ZEN_ENABLE_LINUX_PERF
  std::string getWasmFuncDebugName(uint32_t FuncIdx) {
    ZEN_ASSERT(FuncIdx >= NumImportFunctions);
    const FuncEntry &Func = getInternalFunction(FuncIdx - NumImportFunctions);
    if (Func.Name != common::WASM_SYMBOL_NULL) {
      const char *FuncName = dumpSymbolString(Func.Name);
      if (FuncName) {
        return FuncName;
      }
    }
    return "jitfunc_" + std::to_string(FuncIdx);
  }
#endif

#ifdef ZEN_ENABLE_CHECKED_ARITHMETIC
#define DEFINE_ARITH_FIELD(field) uint32_t field##_func = -1u;
#include "common/arithmetic.def"
#undef DEFINE_ARITH_FIELD
#endif // ZEN_ENABLE_CHECKED_ARITHMETIC

private:
  Module(Runtime *RT);
  Module(const Module &Other) = delete;
  Module &operator=(const Module &Other) = delete;

  virtual ~Module();

  // ==================== Init Table Methods ====================

  template <typename EntryType>
  EntryType *initItemTable(EntryType *&ItemTable, uint32_t &NumItems,
                           uint32_t InitNumItems) {
    size_t Size = sizeof(EntryType) * InitNumItems;
    if (Size > UINT32_MAX) {
      throw common::getError(common::ErrorCode::TooManyItems);
    }
    EntryType *Entry = Size ? (EntryType *)allocateZeros(Size) : nullptr;
    NumItems = InitNumItems;
    ItemTable = Entry;
    return Entry;
  }

  TypeEntry *initTypeTable(uint32_t N) {
    return initItemTable(TypeTable, NumTypes, N);
  }

  ImportFunctionEntry *initImportFuncTable(uint32_t N) {
    return initItemTable(ImportFunctionTable, NumImportFunctions, N);
  }

  ImportTableEntry *initImportTableTable(uint32_t N) {
    return initItemTable(ImportTableTable, NumImportTables, N);
  }

  ImportMemoryEntry *initImportMemoryTable(uint32_t N) {
    return initItemTable(ImportMemoryTable, NumImportMemories, N);
  }

  ImportGlobalEntry *initImportGlobalTable(uint32_t N) {
    return initItemTable(ImportGlobalTable, NumImportGlobals, N);
  }

  WASMType *initParamTypes(uint32_t N) {
    return N > 0 ? (WASMType *)allocate(sizeof(WASMType) * N) : nullptr;
  }

  WASMType *initLocalTypes(uint32_t N) {
    return N > 0 ? (WASMType *)allocate(sizeof(WASMType) * N) : nullptr;
  }

  uint32_t *initLocalOffsets(uint64_t TotalLocalSize) {
    return TotalLocalSize > 0 ? (uint32_t *)allocate(TotalLocalSize) : nullptr;
  }

  FuncEntry *initFuncTable(uint32_t N) {
    return initItemTable(InternalFunctionTable, NumInternalFunctions, N);
  }

  TableEntry *initTableTable(uint32_t N) {
    return initItemTable(InternalTableTable, NumInternalTables, N);
  }

  MemoryEntry *initMemoryTable(uint32_t N) {
    return initItemTable(InternalMemoryTable, NumInternalMemories, N);
  }

  GlobalEntry *initGlobalTable(uint32_t N) {
    return initItemTable(InternalGlobalTable, NumInternalGlobals, N);
  }

  ExportEntry *initExportTable(uint32_t N) {
    return initItemTable(ExportTable, NumExports, N);
  }

  ElemEntry *initElemTable(uint32_t N) {
    return initItemTable(ElementTable, NumElementSegments, N);
  }

  CodeEntry *initCodeTable(uint32_t N) {
    return initItemTable(CodeTable, NumCodeSegments, N);
  }

  DataEntry *initDataTable(uint32_t N) {
    return initItemTable(DataTable, NumDataSegments, N);
  }

  uint32_t *initFuncIdxTable(uint32_t N, ElemEntry *Entry) {
    return initItemTable(Entry->FuncIdxs, Entry->NumFuncIdxs, N);
  }

  // ==================== Destroy Table Methods ====================

  void destroyTypeTable();
  void destroyImportTables();
  void destroyExportTable();
  void destroyFunctionTable();
  void destroyElemTable();
  void destroyCodeTable();

  // ==================== Metadata Members ====================

  CodeHolderUniquePtr CodeHolder;

  // ==================== Number Members ====================

  uint32_t NumTypes = 0;
  uint32_t NumImportFunctions = 0;
  uint32_t NumImportTables = 0;
  uint32_t NumImportMemories = 0;
  uint32_t NumImportGlobals = 0;
  uint32_t NumInternalFunctions = 0;
  uint32_t NumInternalTables = 0;
  uint32_t NumInternalMemories = 0;
  uint32_t NumInternalGlobals = 0;
  uint32_t NumExports = 0;
  uint32_t StartFuncIdx = -1u;
  uint32_t NumElementSegments = 0;
  uint32_t NumCodeSegments = 0;
  uint32_t NumDataSegments = 0;
  uint32_t DataCount = -1u; // -1 means not exist data count section

  // ==================== Entry Table Members ====================

  TypeEntry *TypeTable = nullptr;
  ImportFunctionEntry *ImportFunctionTable = nullptr;
  ImportTableEntry *ImportTableTable = nullptr;
  ImportMemoryEntry *ImportMemoryTable = nullptr;
  ImportGlobalEntry *ImportGlobalTable = nullptr;
  FuncEntry *InternalFunctionTable = nullptr;
  TableEntry *InternalTableTable = nullptr;
  MemoryEntry *InternalMemoryTable = nullptr;
  GlobalEntry *InternalGlobalTable = nullptr;
  ExportEntry *ExportTable = nullptr;
  ElemEntry *ElementTable = nullptr;
  CodeEntry *CodeTable = nullptr;
  DataEntry *DataTable = nullptr;

  // ==================== Layout Members ====================

  uint32_t GlobalVarSize = 0;
  InstanceLayout Layout;

  // ==================== Platform Feature Members ====================

  uint32_t GasFuncIdx = -1u;

  WasmMemoryAllocatorOptions MemAllocOptions;

  // thread_id => WasmMemoryAllocator*
  // WasmMemoryAllocator will only run in one thread(needn't lock)
  typedef utils::ThreadSafeMap<int64_t, WasmMemoryAllocator *> ThreadSafeMap;
  ThreadSafeMap *ThreadLocalMemAllocatorMap = nullptr;

  // ==================== JIT Members ====================

#ifdef ZEN_ENABLE_JIT
  common::CodeMemPool JITCodeMemPool;
  void *JITCode = nullptr;
  size_t JITCodeSize = 0;

#ifdef ZEN_ENABLE_DUMP_CALL_STACK
  // Only used in mutlipass mode, save all functions jited_codes
  // vector of (jited_code_ptr, func_index) ordered by jited_code desc
  std::vector<std::pair<void *, uint32_t>> SortedJITFuncPtrs;
#endif // ZEN_ENABLE_DUMP_CALL_STACK

// All function indexes in the following macro are global function index
#ifdef ZEN_ENABLE_MULTIPASS_JIT
  std::string EntryHint;
  std::unique_ptr<COMPILER::LazyJITCompiler> LazyJITCompiler;
  // All exported function indexes excluding import functions
  std::vector<uint32_t> ExportedFuncIdxs;
  std::unordered_map<uint32_t, std::vector<uint32_t>> TypedFuncRefs;
  // Call Graph excluding import functions
  std::unordered_map<uint32_t, std::vector<uint32_t>> CallSeqMap;
#endif // ZEN_ENABLE_MULTIPASS_JIT

#endif // ZEN_ENABLE_JIT
};

} // namespace runtime
} // namespace zen

#endif // ZEN_RUNTIME_MODULE_H
