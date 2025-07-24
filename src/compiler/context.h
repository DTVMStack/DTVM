// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef ZEN_COMPILER_CONTEXT_H
#define ZEN_COMPILER_CONTEXT_H

#include "compiler/common/common_defs.h"
#include "compiler/mir/constants.h"
#include "compiler/mir/type.h"
#include "llvm/ADT/APFloat.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/Twine.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCSymbol.h"
#include "llvm/Target/TargetMachine.h"

namespace COMPILER {

class MModule;
class MFunctionType;
class MPointerType;
class MConstantInt;
class MConstantFloat;
class LLVMWorkaround;
struct FunctionTypeKeyInfo;
struct PointerTypeKeyInfo;
struct DenseMapAPFloatKeyInfo;
class X86MCLowering;

class CompileContext {
  using FunctionTypeSet = llvm::DenseSet<MFunctionType *, FunctionTypeKeyInfo>;
  using PointerTypeSet = llvm::DenseSet<MPointerType *, PointerTypeKeyInfo>;
  using DenseMapAPIntKeyInfo = llvm::DenseMapInfo<llvm::APInt>;
  using IntMapTy =
      llvm::DenseMap<llvm::APInt, MConstantInt *, DenseMapAPIntKeyInfo>;
  using FPMapTy =
      llvm::DenseMap<llvm::APFloat, MConstantFloat *, DenseMapAPFloatKeyInfo>;
  struct ExternRelocations {
    uint64_t Offset;
    int64_t Addend;
    uint32_t CalleeFuncIdx;
    ExternRelocations(uint64_t Offset, int64_t Addend, uint32_t CalleeFuncIdx)
        : Offset(Offset), Addend(Addend), CalleeFuncIdx(CalleeFuncIdx) {}
  };

public:
  CompileContext();

  virtual ~CompileContext();

  CompileContext(const CompileContext &OtherCtx);

  CompileContext &operator=(const CompileContext &OtherCtx) = delete;

  CompileContext(CompileContext &&OtherCtx) = delete;

  CompileContext &operator=(CompileContext &&OtherCtx) = delete;

  void initialize();

  void finalize();

  /// \warning only used for lazy compilation
  void reinitialize();

  llvm::SmallVectorImpl<char> &getObjBuffer() { return ObjBuffer; }

  X86MCLowering &getMCLowering() const { return *MCL; }

  LLVMWorkaround &getLLVMWorkaround() const { return *Workaround; }

  llvm::LLVMTargetMachine &getTargetMachine() const { return *TM; }

  const llvm::TargetSubtargetInfo &getSubtargetInfo() const { return *STI; }

  llvm::MCContext &getMCContext() const { return *MCCtx; }

  llvm::MCSymbol *getOrCreateFuncMCSymbol(uint32_t FuncIdx) {
    const auto &FuncName = JIT_FUNCTION_NAME_PREFIX + std::to_string(FuncIdx);
    return MCCtx->getOrCreateSymbol(FuncName);
  }

  llvm::MCSymbol *getOrCreateMCSymbol(const llvm::Twine &SymName) {
    return MCCtx->getOrCreateSymbol(SymName);
  }

  static inline MType I8Type = MType::I8;
  static inline MType I16Type = MType::I16;
  static inline MType I32Type = MType::I32;
  static inline MType I64Type = MType::I64;
  static inline MType F32Type = MType::F32;
  static inline MType F64Type = MType::F64;
  static inline MType VoidType = MType::VOID;

  bool Inited = false;
  bool Lazy = false;

  /// ================ MemPool Related ================

  // Lifecycle of the memory pool aligns with that of the compilation thread
  CompileMemPool ThreadMemPool;
  // Need to be replaced with a new one after the current thread compiles the
  // previous function
  CompileMemPool MemPool;
  common::CodeMemPool *CodeMPool = nullptr;

  /// ================ MIR Related ================

  FunctionTypeSet FuncTypeSet;
  PointerTypeSet PtrTypeSet;
  IntMapTy IntConstants;
  FPMapTy FPConstants;

  /// ================ Linking Related ================

  uint8_t *CodePtr = nullptr;
  uint64_t CodeSize = 0;
  uint64_t CodeOffset = 0;
  CompileUnorderedMap<uint32_t, uint64_t> FuncOffsetMap{ThreadMemPool};
#ifdef ZEN_ENABLE_LINUX_PERF
  // Only for perf
  CompileUnorderedMap<uint32_t, uint64_t> FuncSizeMap{ThreadMemPool};
#endif
  CompileVector<ExternRelocations> ExternRelocs{ThreadMemPool};

private:
  void initializeTargetMachine();
  void initializeMC();

  /// ================ LLVM Related ================

  LLVMWorkaround *Workaround = nullptr;
  std::unique_ptr<llvm::LLVMTargetMachine> TM;
  llvm::TargetSubtargetInfo *STI = nullptr;

  /// ================ MC Related ================

  llvm::SmallVector<char, 4096> ObjBuffer;
  llvm::MCContext *MCCtx = nullptr;
  X86MCLowering *MCL = nullptr;
};

class ContextObject : public NonCopyable {
public:
  virtual ~ContextObject() = default;

  CompileContext &getContext() const { return Ctx; }

protected:
  ContextObject(CompileContext &Context) : Ctx(Context) {}

  template <typename T, typename... Arguments>
  T *newObject(Arguments &&...Args) {
    return Ctx.MemPool.newObject<T>(std::forward<Arguments>(Args)...);
  }

  template <typename T> void deleteObject(T *Ptr) {
    Ctx.MemPool.deleteObject(Ptr);
  }

  CompileContext &Ctx;
};

struct FunctionTypeKeyInfo {
  struct KeyTy {
    const MType *Result;
    llvm::ArrayRef<MType *> Parameters;

    KeyTy(const MType *Res, const llvm::ArrayRef<MType *> &Params)
        : Result(Res), Parameters(Params) {}
    KeyTy(const MFunctionType *FuncTypes);

    bool operator==(const KeyTy &Other) const {
      if (Result != Other.Result)
        return false;
      if (Parameters != Other.Parameters)
        return false;
      return true;
    }
    bool operator!=(const KeyTy &Other) const {
      return !this->operator==(Other);
    }
  };

  static inline MFunctionType *getEmptyKey() {
    return llvm::DenseMapInfo<MFunctionType *>::getEmptyKey();
  }
  static inline MFunctionType *getTombstoneKey() {
    return llvm::DenseMapInfo<MFunctionType *>::getTombstoneKey();
  }

  static unsigned getHashValue(const KeyTy &Key) {
    return hash_combine(
        Key.Result,
        llvm::hash_combine_range(Key.Parameters.begin(), Key.Parameters.end()));
  }

  static unsigned getHashValue(const MFunctionType *FuncType) {
    return getHashValue(KeyTy(FuncType));
  }
  static bool isEqual(const KeyTy &LHS, const MFunctionType *RHS) {
    if (RHS == getEmptyKey() || RHS == getTombstoneKey())
      return false;
    return LHS == KeyTy(RHS);
  }
  static bool isEqual(const MFunctionType *LHS, const MFunctionType *RHS) {
    return LHS == RHS;
  }
};

struct PointerTypeKeyInfo {
  struct KeyTy {
    const MType *ElemType;
    const unsigned int AddressSpace;

    KeyTy(const MType *ElemTy, const unsigned int AddrSpace)
        : ElemType(ElemTy), AddressSpace(AddrSpace) {}

    KeyTy(const MPointerType *PtrType);

    bool operator==(const KeyTy &Other) const {
      if (ElemType != Other.ElemType)
        return false;
      if (AddressSpace != Other.AddressSpace)
        return false;
      return true;
    }
    bool operator!=(const KeyTy &Other) const {
      return !this->operator==(Other);
    }
  };

  static inline MPointerType *getEmptyKey() {
    return llvm::DenseMapInfo<MPointerType *>::getEmptyKey();
  }
  static inline MPointerType *getTombstoneKey() {
    return llvm::DenseMapInfo<MPointerType *>::getTombstoneKey();
  }

  static unsigned getHashValue(const KeyTy &Key) {
    return llvm::hash_combine(Key.ElemType, Key.AddressSpace);
  }

  static unsigned getHashValue(const MPointerType *PtrType) {
    return getHashValue(KeyTy(PtrType));
  }
  static bool isEqual(const KeyTy &LHS, const MPointerType *RHS) {
    if (RHS == getEmptyKey() || RHS == getTombstoneKey())
      return false;
    return LHS == KeyTy(RHS);
  }
  static bool isEqual(const MPointerType *LHS, const MPointerType *RHS) {
    return LHS == RHS;
  }
};

struct DenseMapAPFloatKeyInfo {
  static inline llvm::APFloat getEmptyKey() {
    return llvm::APFloat(llvm::APFloat::Bogus(), 1);
  }
  static inline llvm::APFloat getTombstoneKey() {
    return llvm::APFloat(llvm::APFloat::Bogus(), 2);
  }

  static unsigned getHashValue(const llvm::APFloat &Key) {
    return static_cast<unsigned>(hash_value(Key));
  }

  static bool isEqual(const llvm::APFloat &LHS, const llvm::APFloat &RHS) {
    return LHS.bitwiseIsEqual(RHS);
  }
};

} // namespace COMPILER

#endif // ZEN_COMPILER_CONTEXT_H
