// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "compiler/wasm_frontend/wasm_mir_compiler.h"
#include "action/bytecode_visitor.h"
#include "compiler/mir/module.h"
#include "compiler/mir/pointer.h"
#include <unordered_map>
#include <unordered_set>

namespace COMPILER {

WasmFrontendContext::WasmFrontendContext(runtime::Module &WasmMod)
    : UseSoftMemCheck(WasmMod.checkUseSoftLinearMemoryCheck()),
      WasmMod(WasmMod) {}

WasmFrontendContext::WasmFrontendContext(const WasmFrontendContext &OtherCtx)
    : CompileContext(OtherCtx),
      UseSoftMemCheck(OtherCtx.WasmMod.checkUseSoftLinearMemoryCheck()),
      WasmMod(OtherCtx.WasmMod) {}

MType *WasmFrontendContext::getMIRTypeFromWASMType(WASMType Type) {
  switch (Type) {
  case WASMType::I8:
    return &I8Type;
  case WASMType::I16:
    return &I16Type;
  case WASMType::I32:
    return &I32Type;
  case WASMType::I64:
    return &I64Type;
  case WASMType::F32:
    return &F32Type;
  case WASMType::F64:
    return &F64Type;
  case WASMType::VOID:
    return &VoidType;
  default:
    throw getErrorWithPhase(ErrorCode::UnexpectedType, ErrorPhase::Compilation,
                            ErrorSubphase::MIREmission);
  }
}

WASMType WasmFrontendContext::getWASMTypeFromMIRType(MType *Type) {
  switch (Type->getKind()) {
  case MType::Kind::I8:
    return WASMType::I8;
  case MType::Kind::I16:
    return WASMType::I16;
  case MType::Kind::I32:
    return WASMType::I32;
  case MType::Kind::I64:
    return WASMType::I64;
  case MType::Kind::F32:
    return WASMType::F32;
  case MType::Kind::F64:
    return WASMType::F64;
  case MType::Kind::VOID:
    return WASMType::VOID;
  default:
    throw getErrorWithPhase(ErrorCode::UnexpectedType, ErrorPhase::Compilation,
                            ErrorSubphase::MIREmission);
  }
}

void buildAllMIRFuncTypes(WasmFrontendContext &Context, MModule &MMod,
                          const runtime::Module &WasmMod) {
  uint32_t NumImportFunctions = WasmMod.getNumImportFunctions();
  uint32_t NumInternalFunctions = WasmMod.getNumInternalFunctions();

  for (uint32_t I = 0; I < NumInternalFunctions; ++I) {
    TypeEntry *FuncType = WasmMod.getFunctionType(I + NumImportFunctions);
    CompileVector<MType *> MParamTypes(FuncType->NumParams + 1,
                                       Context.ThreadMemPool);
    MParamTypes[0] = MPointerType::create(Context, Context.VoidType);
    const WASMType *ParamTypes = FuncType->getParamTypes();
    for (uint32_t J = 0; J < FuncType->NumParams; ++J) {
      MParamTypes[J + 1] = Context.getMIRTypeFromWASMType(ParamTypes[J]);
    }
    MType *MRetType = Context.getMIRTypeFromWASMType(
        FuncType->NumReturns > 0 ? FuncType->getReturnTypes()[0]
                                 : WASMType::VOID);
    MMod.addFuncType(MFunctionType::create(Context, *MRetType, MParamTypes));
  }
}

FunctionMirBuilder::FunctionMirBuilder(CompilerContext &Context,
                                       MFunction &MFunc)
    : Ctx(Context), ControlStack(Context.MemPool), CurFunc(&MFunc) {}

bool FunctionMirBuilder::compile([[maybe_unused]] CompilerContext *Context) {
  zen::action::WASMByteCodeVisitor<FunctionMirBuilder> Visitor(*this, &Ctx);
  return Visitor.compile();
}

void FunctionMirBuilder::initFunction(
    [[maybe_unused]] CompilerContext *Context) {
  const runtime::TypeEntry &Type = Ctx.getWasmFuncType();
  const runtime::CodeEntry &Code = Ctx.getWasmFuncCode();
  WASMType RetType = Type.getReturnType();

  // Create and enter the entry basic block
  setInsertBlock(createBasicBlock());

  for (uint32_t I = 0; I < Code.NumLocals; ++I) {
    WASMType Type = (WASMType)Code.LocalTypes[I];
    MType *MTy = Ctx.getMIRTypeFromWASMType(Type);

    Variable *Var = CurFunc->createVariable(MTy);

    MConstant *Constant = nullptr;
    if (Type == WASMType::I32 || Type == WASMType::I64) {
      Constant = MConstantInt::get(Ctx, *MTy, 0);
    } else if (Type == WASMType::F32) {
      Constant = MConstantFloat::get(Ctx, *MTy, float(0));
    } else if (Type == WASMType::F64) {
      Constant = MConstantFloat::get(Ctx, *MTy, double(0));
    } else {
      throw getErrorWithPhase(ErrorCode::UnexpectedType,
                              ErrorPhase::Compilation,
                              ErrorSubphase::MIREmission);
    }

    MInstruction *ConstInst =
        createInstruction<ConstantInstruction>(false, MTy, *Constant);
    createInstruction<DassignInstruction>(true, &Ctx.VoidType, ConstInst,
                                          Var->getVarIdx());
  }

  MBasicBlock *ReturnBB = createBasicBlock();
#ifdef ZEN_ENABLE_WASI_MULTI_VALUE
  // Handle multi-value function returns
  if (Type.NumReturns > 1) {
    std::vector<Operand> Results;
    Results.reserve(Type.NumReturns);
    const WASMType *RetTypes = Type.getReturnTypes();
    for (uint32_t I = 0; I < Type.NumReturns; ++I) {
      Results.push_back(createTempStackOperand(RetTypes[I]));
    }
    ControlStack.emplace_back(CtrlBlockKind::FUNC_ENTRY, std::move(Results),
                              &Type, 0, ReturnBB, nullptr, nullptr);
  } else
#endif
  {
    enterBlock(CtrlBlockKind::FUNC_ENTRY, RetType, 0, ReturnBB);
  }

  loadWASMInstanceAttr();
}

void FunctionMirBuilder::loadWASMInstanceAttr() {
  InstanceAddr = createInstruction<ConversionInstruction>(
      false, OP_ptrtoint, &Ctx.I64Type,
      createInstruction<DreadInstruction>(false, createVoidPtrType(), 0));

  ExceptionReturnBB = CurFunc->createExceptionReturnBB();

  const auto &Layout = Ctx.getWasmMod().getLayout();

#ifdef ZEN_ENABLE_DWASM
  MBasicBlock *CallStackExhaustedBB =
      getOrCreateExceptionSetBB(ErrorCode::CallStackExhausted);
  MInstruction *StackCost =
      getInstanceElement(&Ctx.I32Type, Layout.StackCostOffset);
  MInstruction *CurFuncStackCost = createIntConstInstruction(
      &Ctx.I32Type, Ctx.getWasmFuncCode().JITStackCost);
  MInstruction *NewStackCost = createInstruction<BinaryInstruction>(
      false, OP_add, &Ctx.I32Type, StackCost, CurFuncStackCost);
  MInstruction *ResuableNewStackCost =
      makeReusableValue(NewStackCost, &Ctx.I32Type);
  setInstanceElement(&Ctx.I32Type, ResuableNewStackCost,
                     Layout.StackCostOffset);

  MInstruction *StackCostLimit =
      createIntConstInstruction(&Ctx.I32Type, common::PresetReservedStackSize);
  MInstruction *IsExhausted = createInstruction<CmpInstruction>(
      false, CmpInstruction::ICMP_UGT, &Ctx.I8Type, ResuableNewStackCost,
      StackCostLimit);
  createInstruction<BrIfInstruction>(true, Ctx, IsExhausted,
                                     CallStackExhaustedBB);
  addUniqueSuccessor(CallStackExhaustedBB);
#elif defined(ZEN_ENABLE_STACK_CHECK_CPU)
  // visit sp-StackGuardSize to check stack overflow before has not stack to
  // call sig handler StackGuardSize is guard space for sig handler
  createInstruction<WasmVisitStackGuardInstruction>(true, Ctx);
#else
  MBasicBlock *CallStackExhaustedBB =
      getOrCreateExceptionSetBB(ErrorCode::CallStackExhausted);
  MInstruction *StackBoundary =
      getInstanceElement(&Ctx.I64Type, Layout.StackBoundaryOffset);
  createInstruction<WasmCheckStackBoundaryInstruction>(true, Ctx,
                                                       StackBoundary);
  addUniqueSuccessor(CallStackExhaustedBB);
#endif

  using StatsFlags = Module::StatsFlags;
  const uint32_t Stats = Ctx.getWasmFuncCode().Stats;
  if (Stats == StatsFlags::SF_none) {
    return;
  }

  // Load the memories address and memory base ptr if needed
  if (Stats & StatsFlags::SF_memory) {
    /**
     *  $_memory_base_idx = load (
     *    base = instance,
     *    offset = MemoryBaseOffset
     *  )
     */
    Variable *MemoryBaseVar = CurFunc->createVariable(&Ctx.I64Type);
    MemoryBaseIdx = MemoryBaseVar->getVarIdx();
    MInstruction *MemoryBase = getMemoryBase();
    createInstruction<DassignInstruction>(true, &Ctx.VoidType, MemoryBase,
                                          MemoryBaseIdx);

    /**
     *  $_memory_size_idx = load (
     *    base = instance,
     *    offset = MemorySizeOffset
     *  )
     */
    if (Ctx.UseSoftMemCheck) {
      Variable *MemorySizeVar = CurFunc->createVariable(&Ctx.I32Type);
      MemorySizeIdx = MemorySizeVar->getVarIdx();
      MInstruction *MemorySize = getMemorySize();
      createInstruction<DassignInstruction>(true, &Ctx.VoidType, MemorySize,
                                            MemorySizeIdx);
    }
  }
}

void FunctionMirBuilder::finalizeFunctionBase() {
  const auto &ExceptionSetBBs = CurFunc->getExceptionSetBBs();

  VariableIdx ExceptionIDIdx =
      CurFunc->createVariable(&Ctx.I32Type)->getVarIdx();
  // when use cpu-trap to process wasm error, _exception_handling_bb means to
  // exit wasm function to wasm caller when use soft check to process wasm
  // error, _exception_handling_bb means to exit to parent wasm function
  MBasicBlock *ExceptionHandlingBB = CurFunc->createExceptionHandlingBB();

  auto GenExceptionSetBBs = [&]() {
    for (const auto [ErrCode, ExceptionSetBB] : ExceptionSetBBs) {
      setInsertBlock(ExceptionSetBB);
      createInstruction<DassignInstruction>(
          true, &Ctx.VoidType,
          createIntConstInstruction(&Ctx.I32Type,
                                    common::to_underlying(ErrCode)),
          ExceptionIDIdx);
      createInstruction<BrInstruction>(true, Ctx, ExceptionHandlingBB);
      addSuccessor(ExceptionHandlingBB);
    }
  };

  auto HandleException = [&](uintptr_t ExceptionHandlerAddr) {
    MInstruction *HandlerAddr =
        createIntConstInstruction(&Ctx.I64Type, ExceptionHandlerAddr);

    CompileVector<MInstruction *> SetExceptionArgs{
        {
            InstanceAddr,
            createInstruction<DreadInstruction>(false, &Ctx.I32Type,
                                                ExceptionIDIdx),
        },
        Ctx.MemPool,
    };
    createInstruction<ICallInstruction>(true, &Ctx.VoidType, HandlerAddr,
                                        SetExceptionArgs);

    createInstruction<BrInstruction>(true, Ctx, ExceptionReturnBB);
    addSuccessor(ExceptionReturnBB);
  };

  auto ReturnZero = [&]() {
    Operand Ret;
    const auto &Type = Ctx.getWasmFuncType();
    if (Type.NumReturns == 0) {
      handleReturn(Ret);
      return;
    }
    WASMType WType = Type.getReturnType();
    switch (WType) {
    case WASMType::I32:
      Ret = handleConst<WASMType::I32>(0);
      break;
    case WASMType::I64:
      Ret = handleConst<WASMType::I64>(0);
      break;
    case WASMType::F32:
      Ret = handleConst<WASMType::F32>(0.0f);
      break;
    case WASMType::F64:
      Ret = handleConst<WASMType::F64>(0.0);
      break;
    default:
      ZEN_ABORT();
    }
    handleReturn(Ret);
  };

#if defined(ZEN_ENABLE_CPU_EXCEPTION) && !defined(ZEN_ENABLE_DWASM)
  // When check call exception after call_indirect or call hostapi, just
  // throw, no need set args again
  auto ThrowException = [&] {
    MInstruction *ThrowExceptionAddr = createIntConstInstruction(
        &Ctx.I64Type, uintptr_t(Instance::throwInstanceExceptionOnJIT));

    CompileVector<MInstruction *> ThrowExceptionArgs{
        {InstanceAddr},
        Ctx.MemPool,
    };
    createInstruction<ICallInstruction>(true, &Ctx.VoidType, ThrowExceptionAddr,
                                        ThrowExceptionArgs);
  };
  // Has exceptions that cannot be checked by cpu-hardware
  // No need to worry about underflow
  bool HasPureSoftException =
      ExceptionSetBBs.size() -
          ExceptionSetBBs.count(ErrorCode::IntegerDivByZero) -
          ExceptionSetBBs.count(ErrorCode::OutOfBoundsMemory) >
      0;

  if (HasPureSoftException) {
    GenExceptionSetBBs();
    setInsertBlock(ExceptionHandlingBB);
    HandleException(uintptr_t(Instance::setInstanceExceptionOnJIT));
    setInsertBlock(ExceptionReturnBB);
    ThrowException();
    ReturnZero();
  } else if (UseExceptionReturnAfterCall) {
    setInsertBlock(ExceptionReturnBB);
    ThrowException();
    ReturnZero();
    CurFunc->deleteMBasicBlock(ExceptionHandlingBB);
  } else {
    CurFunc->deleteMBasicBlock(ExceptionHandlingBB);
    CurFunc->deleteMBasicBlock(ExceptionReturnBB);
  }
#else
  GenExceptionSetBBs();
  setInsertBlock(ExceptionHandlingBB);
  HandleException(uintptr_t(Instance::triggerInstanceExceptionOnJIT));
  setInsertBlock(ExceptionReturnBB);
  ReturnZero();
#endif
}

// ==================== Block and Operand Methods ====================

const FunctionMirBuilder::BlockInfo &
FunctionMirBuilder::getBlockInfo(uint32_t Level) {
  ZEN_ASSERT(Level < ControlStack.size());
  return ControlStack[ControlStack.size() - Level - 1];
}

FunctionMirBuilder::BlockInfo &FunctionMirBuilder::getCurrentBlockInfo() {
  ZEN_ASSERT(!ControlStack.empty());
  return ControlStack.back();
}

void FunctionMirBuilder::makeAssignment(WASMType Type, const Operand &LHS,
                                        const Operand &RHS) {
  ZEN_ASSERT(Type == LHS.getType());
  ZEN_ASSERT(Type == RHS.getType());
  Variable *Var = LHS.getVar();
  ZEN_ASSERT(Var);
  MInstruction *Val = extractOperand(RHS);
  createInstruction<DassignInstruction>(true, &(Ctx.VoidType), Val,
                                        Var->getVarIdx());
}

MInstruction *FunctionMirBuilder::extractOperand(const Operand &Opnd) {
  if (Opnd.isEmpty()) {
    return nullptr;
  }
  if (Opnd.getInstr()) {
    return Opnd.getInstr();
  }
  Variable *Var = Opnd.getVar();
  ZEN_ASSERT(Var);
  MInstruction *Result = createInstruction<DreadInstruction>(
      false, Var->getType(), Var->getVarIdx());
  return Result;
}

// ==================== Control Instruction Handlers ====================

void FunctionMirBuilder::handleUnreachable() {
  /**
   * br @unreachable
   */
  MBasicBlock *UnreachableBB =
      getOrCreateExceptionSetBB(ErrorCode::Unreachable);
  createInstruction<BrInstruction>(true, Ctx, UnreachableBB);
  addUniqueSuccessor(UnreachableBB);
}

void FunctionMirBuilder::handleBlock(WASMType Type, uint32_t StackSize) {
  MBasicBlock *EndBlock = createBasicBlock();
  enterBlock(CtrlBlockKind::BLOCK, Type, StackSize, EndBlock);
}

void FunctionMirBuilder::handleLoop(WASMType Type, uint32_t StackSize) {
  MBasicBlock *LoopBlock = createBasicBlock();
  MBasicBlock *EndBlock = createBasicBlock();
  createInstruction<BrInstruction>(true, Ctx, LoopBlock);
  addSuccessor(LoopBlock);

  enterBlock(CtrlBlockKind::LOOP, Type, StackSize, LoopBlock, EndBlock);
  setInsertBlock(LoopBlock);
}

void FunctionMirBuilder::handleIf(Operand CondOp, WASMType Type,
                                  uint32_t StackSize) {
  MInstruction *Condition = extractOperand(CondOp);
  MBasicBlock *ThenBlock = createBasicBlock();
  MBasicBlock *EndBlock = createBasicBlock();
  auto BranchInst = createInstruction<BrIfInstruction>(true, Ctx, Condition,
                                                       ThenBlock, EndBlock);
  addSuccessor(ThenBlock);
  addSuccessor(EndBlock);

  enterBlock(CtrlBlockKind::IF, Type, StackSize, EndBlock, nullptr, BranchInst);
  setInsertBlock(ThenBlock);
}

#ifdef ZEN_ENABLE_WASI_MULTI_VALUE
void FunctionMirBuilder::handleBlockMultiValue(const TypeEntry *Type,
                                               uint32_t StackSize) {
  MBasicBlock *EndBlock = createBasicBlock();
  std::vector<Operand> Results;
  if (Type->NumReturns > 0) {
    Results.reserve(Type->NumReturns);
    const WASMType *RetTypes = Type->getReturnTypes();
    for (uint32_t I = 0; I < Type->NumReturns; ++I) {
      Results.push_back(createTempStackOperand(RetTypes[I]));
    }
  }
  ControlStack.emplace_back(CtrlBlockKind::BLOCK, std::move(Results), Type,
                            StackSize, EndBlock, nullptr, nullptr);
}

void FunctionMirBuilder::handleLoopMultiValue(const TypeEntry *Type,
                                              uint32_t StackSize) {
  MBasicBlock *LoopBlock = createBasicBlock();
  MBasicBlock *EndBlock = createBasicBlock();
  createInstruction<BrInstruction>(true, Ctx, LoopBlock);
  addSuccessor(LoopBlock);

  std::vector<Operand> Results;
  if (Type->NumReturns > 0) {
    Results.reserve(Type->NumReturns);
    const WASMType *RetTypes = Type->getReturnTypes();
    for (uint32_t I = 0; I < Type->NumReturns; ++I) {
      Results.push_back(createTempStackOperand(RetTypes[I]));
    }
  }
  ControlStack.emplace_back(CtrlBlockKind::LOOP, std::move(Results), Type,
                            StackSize, LoopBlock, EndBlock, nullptr);
  setInsertBlock(LoopBlock);
}

void FunctionMirBuilder::handleIfMultiValue(Operand CondOp,
                                            const TypeEntry *Type,
                                            uint32_t StackSize) {
  MInstruction *Condition = extractOperand(CondOp);
  MBasicBlock *ThenBlock = createBasicBlock();
  MBasicBlock *EndBlock = createBasicBlock();
  auto BranchInst = createInstruction<BrIfInstruction>(true, Ctx, Condition,
                                                       ThenBlock, EndBlock);
  addSuccessor(ThenBlock);
  addSuccessor(EndBlock);

  std::vector<Operand> Results;
  if (Type->NumReturns > 0) {
    Results.reserve(Type->NumReturns);
    const WASMType *RetTypes = Type->getReturnTypes();
    for (uint32_t I = 0; I < Type->NumReturns; ++I) {
      Results.push_back(createTempStackOperand(RetTypes[I]));
    }
  }
  ControlStack.emplace_back(CtrlBlockKind::IF, std::move(Results), Type,
                            StackSize, EndBlock, nullptr, BranchInst);
  setInsertBlock(ThenBlock);
}
#endif

void FunctionMirBuilder::handleElse(const BlockInfo &Info) {
  MBasicBlock *EndBlock = Info.getJumpBlock();
  if (Info.reachable()) {
    createInstruction<BrInstruction>(true, Ctx, EndBlock);
    addSuccessor(EndBlock);
  }

  // Patch the else branch for if-else instruction
  MBasicBlock *ElseBlock = createBasicBlock();
  BrIfInstruction *BranchInst = Info.getBranchInstr();
  BranchInst->setFalseBlock(ElseBlock);
  MBasicBlock *PrevBlock = BranchInst->getBasicBlock();
  PrevBlock->replaceSuccessor(EndBlock, ElseBlock);

  setInsertBlock(ElseBlock);
}

void FunctionMirBuilder::handleEnd(const BlockInfo &Info) {
  ControlStack.pop_back();
  MBasicBlock *NextBlock = Info.getNextBlock();
  if (!NextBlock) {
    NextBlock = Info.getJumpBlock();
  }

  if (Info.reachable()) {
    createInstruction<BrInstruction>(true, Ctx, NextBlock);
    addSuccessor(NextBlock);
  }

  setInsertBlock(NextBlock);
}

void FunctionMirBuilder::handleBranch(uint32_t Level, const BlockInfo &Info) {
  MBasicBlock *JumpBlock = Info.getJumpBlock();
  createInstruction<BrInstruction>(true, Ctx, JumpBlock);
  addSuccessor(JumpBlock);
}

void FunctionMirBuilder::handleBranchIf(Operand CondOp, uint32_t Level,
                                        const BlockInfo &Info) {
  MInstruction *Condition = extractOperand(CondOp);
  MBasicBlock *JumpBlock = Info.getJumpBlock();
  MBasicBlock *NextBlock = createBasicBlock();
  createInstruction<BrIfInstruction>(true, Ctx, Condition, JumpBlock,
                                     NextBlock);
  addSuccessor(JumpBlock);
  addSuccessor(NextBlock);

  setInsertBlock(NextBlock);
}

void FunctionMirBuilder::handleBranchTable(
    Operand Index, Operand StackTop, const std::vector<uint32_t> &Levels) {
  // Remove duplicate levels and create target basic blocks for them
  CompileUnorderedSet<uint32_t> LevelsSet(Levels.begin(), Levels.end(),
                                          Levels.size(), Ctx.MemPool);
  CompileVector<uint32_t> NewLevels(LevelsSet.begin(), LevelsSet.end(),
                                    Ctx.MemPool);
  CompileUnorderedMap<uint32_t, MBasicBlock *> BlockMap(Ctx.MemPool);
  for (const uint32_t Level : NewLevels) {
    BlockMap.emplace(Level, createBasicBlock());
  }

  // Save stack top value into the variable
  MInstruction *StackTopVarInstr = nullptr;
  if (!StackTop.isEmpty()) {
    MType *StackTopType = Ctx.getMIRTypeFromWASMType(StackTop.getType());
    Variable *StackTopVar = CurFunc->createVariable(StackTopType);
    MInstruction *RawStackTop = extractOperand(StackTop);
    createInstruction<DassignInstruction>(true, &(Ctx.VoidType), RawStackTop,
                                          StackTopVar->getVarIdx());
    StackTopVarInstr = createInstruction<DreadInstruction>(
        false, StackTopType, StackTopVar->getVarIdx());
  }

  uint32_t TableSize = Levels.size() - 1;
  MBasicBlock *DefaultBlock = BlockMap[Levels[TableSize]];
  CompileSet<MBasicBlock *> SwitchSuccessors(Ctx.MemPool);
  SwitchSuccessors.insert(DefaultBlock);

  if (TableSize == 0) {
    createInstruction<BrInstruction>(true, Ctx, DefaultBlock);
  } else {
    MInstruction *Condition = extractOperand(Index);
    CompileVector<std::pair<ConstantInstruction *, MBasicBlock *>> Cases(
        TableSize, Ctx.MemPool);
    for (uint32_t I = 0; I < TableSize; I++) {
      Cases[I].first = createIntConstInstruction(&Ctx.I32Type, I);
      MBasicBlock *Block = BlockMap[Levels[I]];
      Cases[I].second = Block;
      SwitchSuccessors.insert(Block);
    }
    createInstruction<SwitchInstruction>(true, Ctx, Condition, DefaultBlock,
                                         Cases);
  }

  // Add successors without duplicate
  for (MBasicBlock *Succ : SwitchSuccessors) {
    addSuccessor(Succ);
  }

  for (const uint32_t Level : NewLevels) {
    setInsertBlock(BlockMap[Level]);
    const auto &Info = getBlockInfo(Level);
    if (Info.getType() != WASMType::VOID &&
        Info.getKind() != CtrlBlockKind::LOOP) {
      makeAssignment(Info.getType(), Info.getResult(),
                     Operand(StackTopVarInstr, StackTop.getType()));
    }
    handleBranch(Level, Info);
  }
}

void FunctionMirBuilder::handleReturn(Operand Opnd) {
#ifdef ZEN_ENABLE_DWASM
  const auto &Layout = Ctx.getWasmMod().getLayout();
  MInstruction *StackCost =
      getInstanceElement(&Ctx.I32Type, Layout.StackCostOffset);
  MInstruction *CurFuncStackCost = createIntConstInstruction(
      &Ctx.I32Type, Ctx.getWasmFuncCode().JITStackCost);
  MInstruction *NewStackCost = createInstruction<BinaryInstruction>(
      false, OP_sub, &Ctx.I32Type, StackCost, CurFuncStackCost);
  setInstanceElement(&Ctx.I32Type, NewStackCost, Layout.StackCostOffset);
#endif

  MInstruction *Ret = extractOperand(Opnd);
  MType *Type = Ret ? Ret->getType() : &Ctx.VoidType;
  createInstruction<ReturnInstruction>(true, Type, Ret);
}

#ifdef ZEN_ENABLE_WASI_MULTI_VALUE
void FunctionMirBuilder::handleReturnMultiValue(
    const std::vector<Operand> &Opnds) {
#ifdef ZEN_ENABLE_DWASM
  const auto &Layout = Ctx.getWasmMod().getLayout();
  MInstruction *StackCost =
      getInstanceElement(&Ctx.I32Type, Layout.StackCostOffset);
  MInstruction *CurFuncStackCost = createIntConstInstruction(
      &Ctx.I32Type, Ctx.getWasmFuncCode().JITStackCost);
  MInstruction *NewStackCost = createInstruction<BinaryInstruction>(
      false, OP_sub, &Ctx.I32Type, StackCost, CurFuncStackCost);
  setInstanceElement(&Ctx.I32Type, NewStackCost, Layout.StackCostOffset);
#endif

  // For multi-value returns, we need to handle multiple operands
  // Currently we just use the first operand for the return instruction
  // Full multi-value return requires extending ReturnInstruction
  if (Opnds.empty()) {
    createInstruction<ReturnInstruction>(true, &Ctx.VoidType, nullptr);
  } else {
    // Use first operand for now
    // TODO: Extend ReturnInstruction to support multiple operands
    MInstruction *Ret = extractOperand(Opnds[0]);
    MType *Type = Ret ? Ret->getType() : &Ctx.VoidType;
    createInstruction<ReturnInstruction>(true, Type, Ret);
  }
}
#endif

FunctionMirBuilder::Operand FunctionMirBuilder::handleCall(
    uint32_t FuncIdx, uintptr_t Target, bool IsImport, bool FarCall,
    const ArgumentInfo &ArgInfo, const std::vector<Operand> &Args) {

  if (IsImport) {
    MInstruction *FuncAddr = createIntConstInstruction(&Ctx.I64Type, Target);
    return handleCallBase<ICallInstruction>(FuncAddr, ArgInfo, Args, true);
  } else {
    ZEN_ASSERT(Target == 0);
    // exclude import functions
    FuncIdx -= Ctx.getWasmMod().getNumImportFunctions();
    return handleCallBase<CallInstruction>(FuncIdx, ArgInfo, Args, false);
  }
}

FunctionMirBuilder::Operand FunctionMirBuilder::handleCallIndirect(
    uint32_t TypeIdx, Operand IndirectFuncIdxOp, uint32_t TblIdx,
    const ArgumentInfo &ArgInfo, const std::vector<Operand> &Args) {

  MInstruction *IndirectFuncIdx = extractOperand(IndirectFuncIdxOp);
  MInstruction *ResuableIndirectFuncIdx =
      makeReusableValue(IndirectFuncIdx, &Ctx.I32Type);

  /**
   *  br_if cmp iuge ($indirect_func_idx, table_size), @undefined_element
   */

  MInstruction *TableSize = getInstanceElement(
      &Ctx.I32Type, Ctx.getWasmMod().getLayout().TableElemSizeOffset);
  MInstruction *IsUndefined = createInstruction<CmpInstruction>(
      false, CmpInstruction::ICMP_UGE, &Ctx.I8Type, ResuableIndirectFuncIdx,
      TableSize);

  MBasicBlock *UndefinedElementBB =
      getOrCreateExceptionSetBB(ErrorCode::UndefinedElement);
  createInstruction<BrIfInstruction>(true, Ctx, IsUndefined,
                                     UndefinedElementBB);
  addUniqueSuccessor(UndefinedElementBB);

  /**
   *  $func_idx = load (
   *    base = instance,
   *    scale = 4,
   *    index = $indirect_func_idx,
   *    offset = TableElemBaseOffset
   *  )
   */

  MInstruction *FuncIdx = getInstanceElement(
      &Ctx.I32Type, sizeof(uint32_t), ResuableIndirectFuncIdx,
      Ctx.getWasmMod().getLayout().TableElemBaseOffset);
  MInstruction *ReusableFuncIdx = makeReusableValue(FuncIdx, &Ctx.I32Type);

  /**
   *  br_if cmp ieq ($func_idx, -1), @uninitialized_element
   */

  MInstruction *IsUninitialized = createInstruction<CmpInstruction>(
      false, CmpInstruction::ICMP_EQ, &Ctx.I8Type, ReusableFuncIdx,
      createIntConstInstruction(&Ctx.I32Type, -1));

  MBasicBlock *UninitializedElementBB =
      getOrCreateExceptionSetBB(ErrorCode::UninitializedElement);
  createInstruction<BrIfInstruction>(true, Ctx, IsUninitialized,
                                     UninitializedElementBB);
  addUniqueSuccessor(UninitializedElementBB);

  /**
   *  $actual_type_idx = load (
   *    base = instance,
   *    scale = 4,
   *    index = $func_idx,
   *    offset = FuncTypeIndexesBaseOffset
   *  )
   *  br_if cmp ine ($actual_type_idx, type_idx), @indirect_call_type_mismatch
   */

  MInstruction *ActualTypeIdx = getInstanceElement(
      &Ctx.I32Type, sizeof(uint32_t), ReusableFuncIdx,
      Ctx.getWasmMod().getLayout().FuncTypeIndexesBaseOffset);

  MInstruction *IsTypeMismatch = createInstruction<CmpInstruction>(
      false, CmpInstruction::ICMP_NE, &Ctx.I8Type, ActualTypeIdx,
      createIntConstInstruction(&Ctx.I32Type, TypeIdx));

  MBasicBlock *IndirectCallTypeMismatchBB =
      getOrCreateExceptionSetBB(ErrorCode::IndirectCallTypeMismatch);
  createInstruction<BrIfInstruction>(true, Ctx, IsTypeMismatch,
                                     IndirectCallTypeMismatchBB);
  addUniqueSuccessor(IndirectCallTypeMismatchBB);

  /**
   *  $func_addr = load (
   *    base = instance,
   *    scale = 8,
   *    index = $func_idx,
   *    offset = FuncPtrsBaseOffset
   *  )
   */

  MInstruction *FuncAddr =
      getInstanceElement(&Ctx.I64Type, sizeof(uintptr_t), ReusableFuncIdx,
                         Ctx.getWasmMod().getLayout().FuncPtrsBaseOffset);
  return handleCallBase<ICallInstruction>(FuncAddr, ArgInfo, Args, true);
}

#ifdef ZEN_ENABLE_WASI_MULTI_VALUE
// Multi-value call implementation
std::vector<FunctionMirBuilder::Operand>
FunctionMirBuilder::handleCallMultiValue(uint32_t FuncIdx, uintptr_t Target,
                                         bool IsImport, bool FarCall,
                                         const ArgumentInfo &ArgInfo,
                                         const std::vector<Operand> &Args) {
  // First, get the single result from the actual call
  // The calling convention only supports single return value
  Operand SingleResult =
      handleCall(FuncIdx, Target, IsImport, FarCall, ArgInfo, Args);

  // For multi-value returns, we need to create temp operands for each return
  // The first return value comes from the actual call result
  // Additional return values would require extending the calling convention
  std::vector<Operand> Results;
  uint32_t NumReturns = ArgInfo.getNumReturns();
  if (NumReturns > 0) {
    Results.reserve(NumReturns);
    // First result is from the actual call
    Results.push_back(SingleResult);
    // For additional return values, create properly defined operands
    // Note: This is a limitation - the calling convention only supports
    // single return value, so additional values are initialized to 0
    // Full multi-value support requires extending the calling convention
    const WASMType *RetTypes = ArgInfo.getReturnTypes();
    for (uint32_t I = 1; I < NumReturns; ++I) {
      MType *Mtype = Ctx.getMIRTypeFromWASMType(RetTypes[I]);
      MInstruction *ConstVal;
      if (RetTypes[I] == WASMType::F32) {
        ConstVal = createInstruction<ConstantInstruction>(
            false, Mtype, *MConstantFloat::get(Ctx, *Mtype, 0.0f));
      } else if (RetTypes[I] == WASMType::F64) {
        ConstVal = createInstruction<ConstantInstruction>(
            false, Mtype, *MConstantFloat::get(Ctx, *Mtype, 0.0));
      } else {
        ConstVal = createIntConstInstruction(Mtype, 0);
      }
      MInstruction *DefinedVal = makeReusableValue(ConstVal, Mtype);
      Results.push_back(Operand(DefinedVal, RetTypes[I]));
    }
  }
  return Results;
}

std::vector<FunctionMirBuilder::Operand>
FunctionMirBuilder::handleCallIndirectMultiValue(
    uint32_t TypeIdx, Operand IndirectFuncIdx, uint32_t TblIdx,
    const ArgumentInfo &ArgInfo, const std::vector<Operand> &Args) {
  // First, get the single result from the actual call
  Operand SingleResult =
      handleCallIndirect(TypeIdx, IndirectFuncIdx, TblIdx, ArgInfo, Args);

  // For multi-value returns, create properly defined operands
  std::vector<Operand> Results;
  uint32_t NumReturns = ArgInfo.getNumReturns();
  if (NumReturns > 0) {
    Results.reserve(NumReturns);
    // First result is from the actual call
    Results.push_back(SingleResult);
    // For additional return values, create properly defined operands
    // Note: This is a limitation - the calling convention only supports
    // single return value, so additional values are initialized to 0
    const WASMType *RetTypes = ArgInfo.getReturnTypes();
    for (uint32_t I = 1; I < NumReturns; ++I) {
      MType *Mtype = Ctx.getMIRTypeFromWASMType(RetTypes[I]);
      MInstruction *ConstVal;
      if (RetTypes[I] == WASMType::F32) {
        ConstVal = createInstruction<ConstantInstruction>(
            false, Mtype, *MConstantFloat::get(Ctx, *Mtype, 0.0f));
      } else if (RetTypes[I] == WASMType::F64) {
        ConstVal = createInstruction<ConstantInstruction>(
            false, Mtype, *MConstantFloat::get(Ctx, *Mtype, 0.0));
      } else {
        ConstVal = createIntConstInstruction(Mtype, 0);
      }
      MInstruction *DefinedVal = makeReusableValue(ConstVal, Mtype);
      Results.push_back(Operand(DefinedVal, RetTypes[I]));
    }
  }
  return Results;
}
#endif

void FunctionMirBuilder::checkCallException(bool IsImportOrIndirect) {
#ifdef ZEN_ENABLE_CPU_EXCEPTION
  if (IsImportOrIndirect) {
#endif
    MInstruction *Exception = getInstanceElement(
        &Ctx.I32Type, Ctx.getWasmMod().getLayout().ExceptionOffset);
    MInstruction *HasException = createInstruction<CmpInstruction>(
        false, CmpInstruction::ICMP_NE, &Ctx.I8Type, Exception,
        createIntConstInstruction(&Ctx.I32Type, 0));

    createInstruction<BrIfInstruction>(true, Ctx, HasException,
                                       ExceptionReturnBB);
    addUniqueSuccessor(ExceptionReturnBB);
    UseExceptionReturnAfterCall = true;
#ifdef ZEN_ENABLE_CPU_EXCEPTION
  }
#endif // ZEN_ENABLE_CPU_EXCEPTION
}

// ==================== Parametric Instruction Handlers ====================

FunctionMirBuilder::Operand
FunctionMirBuilder::handleSelect(Operand CondOp, Operand LHSOp, Operand RHSOp) {
  WASMType Wtype = LHSOp.getType();
  MType *MTy = Ctx.getMIRTypeFromWASMType(Wtype);

  MInstruction *Cond = extractOperand(CondOp);
  MInstruction *LHS = extractOperand(LHSOp);
  MInstruction *RHS = extractOperand(RHSOp);

  MInstruction *SelectInst =
      createInstruction<SelectInstruction>(false, MTy, Cond, LHS, RHS);
  return Operand(SelectInst, Wtype);
}

// ==================== Variable Instruction Handlers ====================

FunctionMirBuilder::Operand
FunctionMirBuilder::handleGetLocal(uint32_t LocalIdx) {
  // skip instance
  LocalIdx++;
  ZEN_ASSERT(LocalIdx < CurFunc->getNumVariables());
  MType *MTy = CurFunc->getVariableType(LocalIdx);
  WASMType Wtype = Ctx.getWASMTypeFromMIRType(MTy);
  MInstruction *LocalVal =
      createInstruction<DreadInstruction>(false, MTy, LocalIdx);
  MInstruction *SafeLocalVal = protectUnsafeValue(LocalVal, MTy);
  return Operand(SafeLocalVal, Wtype);
}

void FunctionMirBuilder::handleSetLocal(uint32_t LocalIdx, Operand Val) {
  // skip instance
  LocalIdx++;
  ZEN_ASSERT(LocalIdx < CurFunc->getNumVariables());

  createInstruction<DassignInstruction>(true, &(Ctx.VoidType),
                                        extractOperand(Val), LocalIdx);
}

FunctionMirBuilder::Operand
FunctionMirBuilder::handleGetGlobal(uint32_t GlobalIdx) {
  const auto [WType, Offset] =
      Ctx.getWasmMod().getLayout().getGlobalTypeAndOffset(GlobalIdx);
  MType *ValType = Ctx.getMIRTypeFromWASMType(WType);
  MInstruction *GlobalVal = getInstanceElement(ValType, Offset);
  MInstruction *SafeGlobalVal = protectUnsafeValue(GlobalVal, ValType);
  return Operand(SafeGlobalVal, WType);
}

void FunctionMirBuilder::handleSetGlobal(uint32_t GlobalIdx, Operand Val) {
  const auto [WType, Offset] =
      Ctx.getWasmMod().getLayout().getGlobalTypeAndOffset(GlobalIdx);
  MType *ValType = Ctx.getMIRTypeFromWASMType(WType);
  MInstruction *Value = extractOperand(Val);
  setInstanceElement(ValType, Value, Offset);
}

// ==================== Memory Instruction Handlers ====================

FunctionMirBuilder::Operand FunctionMirBuilder::handleMemorySize() {
  MInstruction *MemorySize = getInstanceElement(
      &Ctx.I32Type, Ctx.getWasmMod().getLayout().MemoryPagesOffset);
  MInstruction *SafeMemorySize = protectUnsafeValue(MemorySize, &Ctx.I32Type);
  return Operand(SafeMemorySize, WASMType::I32);
}

FunctionMirBuilder::Operand FunctionMirBuilder::handleMemoryGrow(Operand Opnd) {
  CompileVector<MInstruction *> MemoryGrowArgs{
      {
          InstanceAddr,
          extractOperand(Opnd),
      },
      Ctx.MemPool,
  };

  MType *MTy = &Ctx.I32Type;

  MInstruction *MemoryGrowAddr = createIntConstInstruction(
      &Ctx.I64Type, uint64_t(Instance::growInstanceMemoryOnJIT));

  MInstruction *MemoryGrowResult = createInstruction<ICallInstruction>(
      false, &Ctx.I32Type, MemoryGrowAddr, MemoryGrowArgs);

  Variable *PrevNumPagesVar = CurFunc->createVariable(MTy);
  createInstruction<DassignInstruction>(true, &(Ctx.VoidType), MemoryGrowResult,
                                        PrevNumPagesVar->getVarIdx());

  updateMemoryBaseAndSize();

  MInstruction *PrevNumPages = createInstruction<DreadInstruction>(
      false, MTy, PrevNumPagesVar->getVarIdx());
  return Operand(PrevNumPages, WASMType::I32);
}

std::tuple<MInstruction *, MInstruction *, int32_t>
FunctionMirBuilder::getMemoryLocation(MInstruction *Base, uint32_t Offset,
                                      MType *Type) {
  ZEN_ASSERT(MemoryBaseIdx != (VariableIdx)-1);

  bool IsConstBase = Base->getKind() == MInstruction::Kind::CONSTANT;
  MInstruction *CheckBase =
      IsConstBase ? nullptr : makeReusableValue(Base, Base->getType());
  uint64_t CheckOffset = Offset;
  MInstruction *AccessBase = CheckBase;
  uint32_t AccessOffset = Offset;
  if (IsConstBase) {
    const auto *ConstBase = static_cast<ConstantInstruction *>(Base);
    const MConstant &ConstValue = ConstBase->getConstant();
    ZEN_ASSERT(ConstValue.getType().isI32());
    const auto &IntConst = llvm::cast<MConstantInt>(ConstValue);
    auto BaseOffset = IntConst.getValue().getZExtValue();
    CheckOffset = BaseOffset + uint64_t(AccessOffset);
    if (CheckOffset <= INT32_MAX) {
      AccessOffset = CheckOffset;
    } else {
      AccessBase = makeReusableValue(Base, Base->getType());
    }
  }

  if (Ctx.UseSoftMemCheck) {
    ZEN_ASSERT(MemorySizeIdx != (VariableIdx)-1);
    MInstruction *MemorySize =
        createInstruction<DreadInstruction>(false, &Ctx.I32Type, MemorySizeIdx);
    createInstruction<WasmCheckMemoryAccessInstruction>(
        true, Ctx, CheckBase, CheckOffset, Type->getNumBytes(), MemorySize);
    MBasicBlock *OutOfBoundsMemoryBB =
        getOrCreateExceptionSetBB(ErrorCode::OutOfBoundsMemory);
    addUniqueSuccessor(OutOfBoundsMemoryBB);
  }

  MInstruction *MemoryBaseAddr =
      createInstruction<DreadInstruction>(false, &Ctx.I64Type, MemoryBaseIdx);

  // x86_64 address mode only supports int32 offset(displacement), so we need to
  // split the offset into two parts, one is added into the base address, the
  // other is the displacement
  if (AccessOffset > INT32_MAX) {
    // 0x80000000
    constexpr uint64_t Delta = uint64_t(INT32_MAX) + 1;
    MInstruction *BaseDelta = createIntConstInstruction(&Ctx.I64Type, Delta);
    MemoryBaseAddr = createInstruction<BinaryInstruction>(
        false, OP_add, &Ctx.I64Type, MemoryBaseAddr, BaseDelta);
    AccessOffset -= Delta;
  }

  MPointerType *ValuePtrType = MPointerType::create(Ctx, *Type);

  MInstruction *MemoryBasePtr = createInstruction<ConversionInstruction>(
      false, OP_inttoptr, ValuePtrType, MemoryBaseAddr);

  return {MemoryBasePtr, AccessBase, AccessOffset};
}

/**
 * Get the memory base in form of i64
 *
 * load (base = InstPtr, offset = MemoryBaseOffset)
 */
MInstruction *FunctionMirBuilder::getMemoryBase() {
  return getInstanceElement(&Ctx.I64Type,
                            Ctx.getWasmMod().getLayout().MemoryBaseOffset);
}

/**
 * Get the memory size in form of i32
 *
 * load (base = InstPtr, offset = MemorySizeOffset)
 */
MInstruction *FunctionMirBuilder::getMemorySize() {
  return getInstanceElement(&Ctx.I32Type,
                            Ctx.getWasmMod().getLayout().MemorySizeOffset);
}

void FunctionMirBuilder::updateMemoryBaseAndSize() {
  if (MemoryBaseIdx != VariableIdx(-1)) {
    MInstruction *MemoryBase = getMemoryBase();
    createInstruction<DassignInstruction>(true, &Ctx.VoidType, MemoryBase,
                                          MemoryBaseIdx);
    // MemorySizeIdx can only be valid if MemoryBaseIdx is valid
    if (MemorySizeIdx != VariableIdx(-1)) {
      MInstruction *MemorySize = getMemorySize();
      createInstruction<DassignInstruction>(true, &Ctx.VoidType, MemorySize,
                                            MemorySizeIdx);
    }
  }
}

// ==================== Platform Feature Methods ====================

void FunctionMirBuilder::handleGasCall(Operand Delta) {
  // if instance.gas_left < 0 error; instance.gas_left -= delta;
  const auto &Layout = Ctx.getWasmMod().getLayout();
  MBasicBlock *GasExceedBB =
      getOrCreateExceptionSetBB(ErrorCode::GasLimitExceeded);
  MInstruction *GasLeft = getInstanceElement(&Ctx.I64Type, Layout.GasOffset);
  MInstruction *DeltaValue = extractOperand(Delta);
  MInstruction *ReusableDeltaValue =
      makeReusableValue(DeltaValue, &Ctx.I64Type);

  MInstruction *IsExhausted = createInstruction<CmpInstruction>(
      false, CmpInstruction::ICMP_ULT, &Ctx.I8Type, GasLeft,
      ReusableDeltaValue);
  createInstruction<BrIfInstruction>(true, Ctx, IsExhausted, GasExceedBB);
  addUniqueSuccessor(GasExceedBB);

  MInstruction *NewGasLeft = createInstruction<BinaryInstruction>(
      false, OP_sub, &Ctx.I64Type, GasLeft, DeltaValue);
  setInstanceElement(&Ctx.I64Type, NewGasLeft, Layout.GasOffset);
}

// ==================== MIR Opcode Methods ====================

Opcode FunctionMirBuilder::getBinOpcode(BinaryOperator BinOpr) {
  switch (BinOpr) {
  case BinaryOperator::BO_ADD:
    return OP_add;
  case BinaryOperator::BO_SUB:
    return OP_sub;
  case BinaryOperator::BO_MUL:
    return OP_mul;
  case BinaryOperator::BO_DIV:
    return OP_fpdiv;
  case BinaryOperator::BO_DIV_S:
    return OP_sdiv;
  case BinaryOperator::BO_DIV_U:
    return OP_udiv;
  case BinaryOperator::BO_REM_S:
    return OP_srem;
  case BinaryOperator::BO_REM_U:
    return OP_urem;
  case BinaryOperator::BO_OR:
    return OP_or;
  case BinaryOperator::BO_AND:
    return OP_and;
  case BinaryOperator::BO_XOR:
    return OP_xor;
  case BinaryOperator::BO_MIN:
    return OP_fpmin;
  case BinaryOperator::BO_MAX:
    return OP_fpmax;
  case BinaryOperator::BO_COPYSIGN:
    return OP_fpcopysign;
  case BinaryOperator::BO_SHL:
    return OP_shl;
  case BinaryOperator::BO_SHR_S:
    return OP_sshr;
  case BinaryOperator::BO_SHR_U:
    return OP_ushr;
  case BinaryOperator::BO_ROTL:
    return OP_rotl;
  case BinaryOperator::BO_ROTR:
    return OP_rotr;
  default:
    ZEN_ASSERT_TODO();
    return OP_unknown;
  }
};

Opcode FunctionMirBuilder::getUnaryOpcode(UnaryOperator UnOpr) {
  switch (UnOpr) {
  case UnaryOperator::UO_CLZ:
    return OP_clz;
  case UnaryOperator::UO_CTZ:
    return OP_ctz;
  case UnaryOperator::UO_POPCNT:
    return OP_popcnt;
  case UnaryOperator::UO_ABS:
    return OP_fpabs;
  case UnaryOperator::UO_NEG:
    return OP_fpneg;
  case UnaryOperator::UO_SQRT:
    return OP_fpsqrt;
  case UnaryOperator::UO_CEIL:
    return OP_fpround_ceil;
  case UnaryOperator::UO_FLOOR:
    return OP_fpround_floor;
  case UnaryOperator::UO_TRUNC:
    return OP_fpround_trunc;
  case UnaryOperator::UO_NEAREST:
    return OP_fpround_nearest;
  default:
    ZEN_ASSERT_TODO();
    return OP_unknown;
  }
}

} // namespace COMPILER
