// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef COMPILER_IR_FUNCTION_H
#define COMPILER_IR_FUNCTION_H

#include "compiler/common/common_defs.h"
#include "compiler/mir/basic_block.h"
#include "compiler/mir/instruction.h"
#include "compiler/mir/type.h"
#include "compiler/mir/variable.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/DenseMapInfo.h"
#include <list>
#include <stdio.h>

namespace COMPILER {

class CompileContext;

class MFunctionType : public MType, public NonCopyable {
public:
  void print(llvm::raw_ostream &OS) const;
  // hide super class dump
  void dump() const;

  static MFunctionType *create(CompileContext &Context, MType &RetType,
                               llvm::ArrayRef<MType *> ParamTypes);

private:
  MFunctionType(MType &RetType, llvm::ArrayRef<MType *> ParamTypes);

  MType *const *getSubTypes() const {
    return reinterpret_cast<MType *const *>(this + 1);
  }

  MType **getSubTypes() { return reinterpret_cast<MType **>(this + 1); }

public:
  using ParamIterator = MType::SubTypeIterator;
  uint32_t getNumParams() const { return _subClassData; }
  ParamIterator param_begin() const { return getSubTypes() + 1; }
  ParamIterator param_end() const { return param_begin() + getNumParams(); }
  MType *getReturnType() const { return getSubTypes()[0]; }
  llvm::ArrayRef<MType *> getParamTypes() const {
    return llvm::makeArrayRef(param_begin(), param_end());
  }
};

class MFunction : public ContextObject {
public:
  MFunction(CompileContext &Context, uint32_t FuncIndex)
      : ContextObject(Context), FuncIdx(FuncIndex), Variables(Context.MemPool),
        BasicBlocks(Context.MemPool), Instructions(Context.MemPool),
        ExceptionSetBBs(Context.MemPool) {}

  ~MFunction() override { clearMFunction(); }

  auto begin() { return BasicBlocks.begin(); }

  auto end() { return BasicBlocks.end(); }

  void print(llvm::raw_ostream &OS) const;
#if !defined(NDEBUG) || defined(LLVM_ENABLE_DUMP)
  void dump() const;
#endif

  MFunctionType *getFunctionType() const { return FuncType; }

  void setFunctionType(MFunctionType *FType) { FuncType = FType; }

  void clearMFunction() {
    clearMBasicBlocks();
    clearVariables();
    clearInstructions();
  }

  // Only create basic block but not insert it into function
  MBasicBlock *createBasicBlock() { return newObject<MBasicBlock>(*this); }

  // Insert basic block into the end of function
  void appendBlock(MBasicBlock *BB) {
    BB->setIdx(BasicBlocks.size());
    BasicBlocks.emplace_back(BB);
  }

  MBasicBlock *getBasicBlock(uint32_t BBIdx) const {
    ZEN_ASSERT(BBIdx < BasicBlocks.size());
    return BasicBlocks[BBIdx];
  }

  MBasicBlock *getEntryBasicBlock() const {
    ZEN_ASSERT(!BasicBlocks.empty());
    return BasicBlocks.front();
  }

  uint32_t getNumBasicBlocks() const { return BasicBlocks.size(); }

  // for BumpPtrAllocator, ignore this
  void deleteMBasicBlock(MBasicBlock *BB) {
    ZEN_ASSERT(BB);
    if (ExceptionHandlingBB == BB) {
      ExceptionHandlingBB = nullptr;
    }
    if (ExceptionReturnBB == BB) {
      ExceptionReturnBB = nullptr;
    }
    deleteObject(BB);
  }

  void clearMBasicBlocks() {
    for (auto *BB : BasicBlocks) {
      deleteMBasicBlock(BB);
    }
    BasicBlocks.clear();
  }

  uint32_t getNumParams() const {
    ZEN_ASSERT(FuncType);
    return FuncType->getNumParams();
  }

  uint32_t getNumVariables() const { return getNumParams() + Variables.size(); }

  Variable *createVariable(MType *Type) {
    VariableIdx VarIdx = getNumVariables();
    Variable *Var = newObject<Variable>(VarIdx, Type);
    Variables.emplace_back(Var);
    return Var;
  }

  // for BumpPtrAllocator, ignore this
  void deleteVariable(Variable *Var) {
    ZEN_ASSERT(Var);
    deleteObject(Var);
  }

  void clearVariables() {
    for (Variable *Var : Variables) {
      deleteVariable(Var);
    }
    Variables.clear();
  }

  MType *getVariableType(uint32_t VarIdx) {
    ZEN_ASSERT(VarIdx < getNumVariables());
    if (VarIdx < getNumParams()) {
      return FuncType->getParamTypes()[VarIdx];
    }
    return Variables[VarIdx - getNumParams()]->getType();
  }

  uint32_t getNumInstructions() const { return Instructions.size(); }

  template <class T, typename... Arguments>
  T *createInstruction(bool IsStmt, MBasicBlock &BB, Arguments &&...Args) {
    T *Inst = T::create(Ctx.MemPool, std::forward<Arguments>(Args)...);
    Instructions.emplace_back(Inst);

    if (IsStmt) {
      BB.addStatement(Inst);
    }

    return Inst;
  }

  void freeInstruction(MInstruction *Inst) {
    Inst->~MInstruction();
    MInstruction::freeMem(Ctx.MemPool, Inst);
  }

  void deleteInstruction(MInstruction *Inst) {
    auto It = std::find(Instructions.begin(), Instructions.end(), Inst);
    if (It != Instructions.end()) {
      Instructions.erase(It);
    }
    freeInstruction(Inst);
  }

  void clearInstructions() {
    for (MInstruction *Inst : Instructions) {
      freeInstruction(Inst);
    }
    Instructions.clear();
  }

  auto getFuncIdx() const { return FuncIdx; }

  MBasicBlock *getOrCreateExceptionSetBB(ErrorCode ErrCode) {
    auto It = ExceptionSetBBs.lower_bound(ErrCode);
    if (It == ExceptionSetBBs.end() || It->first != ErrCode) {
      It = ExceptionSetBBs.emplace_hint(It, ErrCode, createBasicBlock());
    }
    return It->second;
  }

  const auto &getExceptionSetBBs() const { return ExceptionSetBBs; }

  MBasicBlock *createExceptionHandlingBB() {
    ZEN_ASSERT(!ExceptionHandlingBB);
    ExceptionHandlingBB = createBasicBlock();
    return ExceptionHandlingBB;
  }

  MBasicBlock *getExceptionHandlingBB() const { return ExceptionHandlingBB; }

  void clearExceptionHandlingBB() { ExceptionHandlingBB = nullptr; }

  MBasicBlock *createExceptionReturnBB() {
    ZEN_ASSERT(!ExceptionReturnBB);
    ExceptionReturnBB = createBasicBlock();
    return ExceptionReturnBB;
  }

  MBasicBlock *getExceptionReturnBB() const { return ExceptionReturnBB; }

private:
  uint32_t FuncIdx = 0;
  MFunctionType *FuncType = nullptr;
  CompileVector<Variable *> Variables;
  CompileVector<MBasicBlock *> BasicBlocks;
  CompileVector<MInstruction *> Instructions;
  CompileMap<ErrorCode, MBasicBlock *> ExceptionSetBBs;
  MBasicBlock *ExceptionHandlingBB = nullptr;
  MBasicBlock *ExceptionReturnBB = nullptr;
};

} // namespace COMPILER

#endif // COMPILER_IR_FUNCTION_H
