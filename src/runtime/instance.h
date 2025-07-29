// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_RUNTIME_INSTANCE_H
#define ZEN_RUNTIME_INSTANCE_H

#include "common/errors.h"
#include "common/traphandler.h"
#include "runtime/module.h"
#include "utils/backtrace.h"
#ifdef ZEN_ENABLE_VIRTUAL_STACK
#include "utils/virtual_stack.h"
#include <queue>
#endif

#ifdef ZEN_ENABLE_CPU_EXCEPTION
#include <csetjmp>
#include <csignal>
#endif // ZEN_ENABLE_CPU_EXCEPTION

#ifdef ZEN_ENABLE_BUILTIN_WASI
#include "host/wasi/wasi.h"
#endif

namespace zen {

namespace action {
class Instantiator;
} // namespace action

namespace singlepass {
class JITCompiler;
template <typename ConcreteCodeGen, typename ConcreteCodeGenAttrs>
class OnePassCodeGen;
} // namespace singlepass

namespace runtime {

enum FunctionKind {
  ByteCode = 0,
  Jit,
  Aot,
  Native,
};

struct FunctionInstance final {
  uint16_t NumParams;
  uint16_t NumParamCells;
  uint16_t NumLocals;
  uint16_t NumLocalCells;

  uint32_t MaxStackSize;
  uint32_t MaxBlockDepth;
  uint32_t CodeSize;

  FunctionKind Kind : 2;
  uint8_t NumReturns : 2;
  uint8_t NumReturnCells : 4;
  WASMType ReturnTypes[2];

  union {
    WASMType *ParamTypes;
    WASMType ParamTypesVec[__WORDSIZE / 8];
  };
  TypeEntry *FuncType;
  WASMType *LocalTypes;
  uint32_t *LocalOffsets;
  const uint8_t *CodePtr;
#ifdef ZEN_ENABLE_JIT
  const uint8_t *JITCodePtr;
#endif

  WASMType *getParamTypes() {
    return NumParams > (__WORDSIZE / 8) ? ParamTypes : ParamTypesVec;
  }

  WASMType getLocalType(uint32_t LocalIdx) {
    ZEN_ASSERT(LocalIdx < (NumParams + NumLocals));
    if (LocalIdx < NumParams) {
      return getParamTypes()[LocalIdx];
    }
    return LocalTypes[LocalIdx - NumParams];
  }

  uint32_t getLocalOffset(uint32_t LocalIdx) {
    ZEN_ASSERT(LocalIdx < (NumParams + NumLocals));
    return LocalOffsets[LocalIdx];
  }
};

struct TableInstance final {
  uint32_t CurSize;
  uint32_t MaxSize;
  uint32_t *Elements;
};

struct MemoryInstance final {
  uint32_t CurPages;
  uint32_t MaxPages;
  uint64_t MemSize;
  uint8_t *MemBase;
  uint8_t *MemEnd;
  WasmMemoryDataType Kind;

  WasmMemoryData getWasmMemoryData();
};

struct GlobalInstance final {
  common::WASMType Type;
  bool Mutable;
  uint32_t Offset;
};

/// \warning: not support multi-threading
class Instance final : public RuntimeObject<Instance> {
  using Error = common::Error;
  using ErrorCode = common::ErrorCode;

  friend class Runtime;
  friend class Isolation;
  friend class RuntimeObjectDestroyer;
  friend struct Module::InstanceLayout;
  friend class action::Instantiator;
  friend class singlepass::JITCompiler;
  template <typename ConcreteCodeGen, typename ConcreteCodeGenAttrs>
  friend class singlepass::OnePassCodeGen;

public:
  // ==================== Module Accessing Methods ====================

  const Module *getModule() const { return Mod; }

  // ==================== Function  Methods ====================

  FunctionInstance *getFunctionInst(uint32_t FuncIdx) {
    return Functions + FuncIdx;
  }

  // ==================== Table Accessing Methods ====================

  TableInstance *getTableInst(uint32_t TableIdx) {
    ZEN_ASSERT(NumTotalTables > TableIdx);
    return Tables + TableIdx;
  }

  // ==================== Memory Accessing Methods ====================

  bool hasMemory() const { return NumTotalMemories > 0; }

  MemoryInstance &getDefaultMemoryInst() {
    ZEN_ASSERT(hasMemory());
    return Memories[0];
  }

  const MemoryInstance &getDefaultMemoryInst() const {
    ZEN_ASSERT(hasMemory());
    return Memories[0];
  }

  bool growLinearMemory(uint32_t MemIdx, uint32_t GrowPagesDelta);

  void *reallocLinearMemory(void *Ptr, uint32_t OldSize, uint32_t NewSize) {
    return reallocate(Ptr, OldSize, NewSize);
  }

  void *getNativeMemoryAddr(uint32_t Offset);

  uint32_t getMemoryOffset(void *Addr);

  bool __attribute__((noinline))
  validatedAppAddr(uint32_t Offset, uint32_t Size);

  bool __attribute__((noinline))
  validatedNativeAddr(uint8_t *NativeAddr, uint32_t Size);

  // ==================== Global Accessing Methods ====================

  uint8_t *getGlobalAddr(uint32_t GlobalIdx) {
    ZEN_ASSERT(GlobalIdx < NumTotalGlobals);
    GlobalInstance *Global = Globals + GlobalIdx;
    return GlobalVarData + Global->Offset;
  }

  WASMType getGlobalType(uint32_t GlobalIdx) const {
    ZEN_ASSERT(GlobalIdx < NumTotalGlobals);
    return Globals[GlobalIdx].Type;
  }

  // ==================== Error/Exception Methods ====================

  void setError(const Error &NewErr) { Err = NewErr; }

  const Error &getError() const { return Err; }

  bool hasError() const { return !Err.isEmpty(); }

  void clearError() { Err = ErrorCode::NoError; }

  // can only called by hostapi directly
  // setExceptionByHostapi must be inline to capture the hostapi's frame
  // pointer
  void __attribute__((always_inline))
  setExceptionByHostapi(const Error &NewErr) {
    setExecutionError(NewErr, 1, {});
  }

  // ignored_depth: the distance from the setExecutionError to the top of
  // expected call stack
  void __attribute__((noinline))
  setExecutionError(const Error &NewErr, uint32_t IgnoredDepth = 0,
                    common::traphandler::TrapState TS = {});

  uint32_t getNumTraces() const {
#ifdef ZEN_ENABLE_DUMP_CALL_STACK
    return NumTraces;
#else
    return 0;
#endif
  }

  // ==================== JIT Methods ====================

#ifdef ZEN_ENABLE_JIT
  static int32_t growInstanceMemoryOnJIT(Instance *Inst,
                                         uint32_t GrowPagesDelta);

  void setJITStackSize(uint64_t NewStackSize) { JITStackSize = NewStackSize; }

  static void __attribute__((noinline))
  setInstanceExceptionOnJIT(Instance *Inst, ErrorCode ErrCode);
  static void __attribute__((noinline))
  throwInstanceExceptionOnJIT(Instance *Inst);
  // trigger = set + throw
  static void __attribute__((noinline))
  triggerInstanceExceptionOnJIT(Instance *Inst, ErrorCode ErrCode);

#ifdef ZEN_ENABLE_DUMP_CALL_STACK
  void createCallStackOnJIT(uint32_t IgnoredDepth,
                            common::traphandler::TrapState TS = {});

  int32_t getFuncIndexByAddrOnJIT(void *Addr);

  void dumpCallStackOnJIT();
#endif // ZEN_ENABLE_DUMP_CALL_STACK

#endif // ZEN_ENABLE_JIT

  // ==================== WASI Methods ====================

#ifdef ZEN_ENABLE_BUILTIN_WASI
  host::WASIContext *getWASIContext() const { return WASICtx; }
#endif

  void exit(int32_t ExitCode);

  int32_t getExitCode() const { return InstanceExitCode; }

  // ==================== Platform Feature Methods ====================

  uint64_t getGas() const { return Gas; }
  void setGas(uint64_t NewGas) { Gas = NewGas; }

  void *getCustomData() { return CustomData; }
  void setCustomData(void *NewCustomData) { CustomData = NewCustomData; }

  // wasm instance enabled by default
  // but after call some child instance, the parent maybe not active
  // need enable it again
  void protectMemoryAgain();

#ifdef ZEN_ENABLE_VIRTUAL_STACK
  void pushVirtualStack(utils::VirtualStackInfo *VirtualStack) {
    VirtualStacks.push(VirtualStack);
  }
  void popVirtualStack() { VirtualStacks.pop(); }

  utils::VirtualStackInfo *currentVirtualStack() const {
    return VirtualStacks.empty() ? nullptr : VirtualStacks.back();
  }
#endif

#ifdef ZEN_ENABLE_DWASM
  uint32_t getStackCost() const { return StackCost; }

  void updateStackCost(int32_t Delta) {
    ZEN_ASSERT(Delta >= 0 || StackCost >= (uint32_t)(-Delta));
    StackCost = (uint32_t)((int32_t)StackCost + Delta);
  }

  bool inHostAPI() const { return InHostAPI != 0; }
  void setInHostAPI(bool V) { InHostAPI = (V ? 1 : 0); }
#endif

private:
  Instance(const Module &M, Runtime &RT)
      : RuntimeObject<Instance>(RT), Mod(&M) {}

  virtual ~Instance();

  /* Make an instance and define its memory layout */
  static InstanceUniquePtr newInstance(Isolation &Iso, const Module &Mod,
                                       uint64_t GasLimit = 0);

  WasmMemoryAllocator *getWasmMemoryAllocator();

  void protectMemory();

  Isolation *Iso = nullptr;
  const Module *Mod = nullptr;

  uint32_t NumTotalGlobals = 0;
  uint32_t NumTotalMemories = 0;
  uint32_t NumTotalTables = 0;
  uint32_t NumTotalFunctions = 0;

  FunctionInstance *Functions = nullptr;
  GlobalInstance *Globals = nullptr;
  uint8_t *GlobalVarData = nullptr;
  TableInstance *Tables = nullptr;
  MemoryInstance *Memories = nullptr; // at least 1 memory instance exists.

#ifdef ZEN_ENABLE_JIT
  uintptr_t *JITFuncPtrs = nullptr;
  uint32_t *FuncTypeIdxs = nullptr;
  uint64_t JITStackSize = 0;
  uint8_t *JITStackBoundary = nullptr;
#endif

  Error Err = ErrorCode::NoError;

  uint64_t Gas = 0;

  // exit code set by Instance.exit(ExitCode)
  int32_t InstanceExitCode = 0;

#ifdef ZEN_ENABLE_BUILTIN_WASI
  host::WASIContext *WASICtx = nullptr;
#endif

#ifdef ZEN_ENABLE_DUMP_CALL_STACK
  int32_t *Traces;
  uint32_t NumTraces = 0;
  std::vector<std::pair<int32_t, uintptr_t>> HostFuncPtrs;
#endif

#ifdef ZEN_ENABLE_DWASM
  // Used to check stack exhaustion
  uint32_t StackCost = 0;

  // struct offsets used, so _wasm_error can only be added after jit fields
  int8_t InHostAPI = 0; // flag. use i8 to update by jit
#endif

  void *CustomData = nullptr;

  WasmMemoryDataType MemDataKind =
      WasmMemoryDataType::WM_MEMORY_DATA_TYPE_MALLOC;

  bool DataSegsInited = false;

#ifdef ZEN_ENABLE_VIRTUAL_STACK
  // one instance maybe called by hostapi( instanceA -> hostapi -> instanceA )
  std::queue<utils::VirtualStackInfo *> VirtualStacks;
#endif
};

} // namespace runtime
} // namespace zen

#endif // ZEN_RUNTIME_INSTANCE_H
