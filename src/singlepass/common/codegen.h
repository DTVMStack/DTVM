// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_SINGLEPASS_COMMON_CODEGEN_H
#define ZEN_SINGLEPASS_COMMON_CODEGEN_H

// ============================================================================
// codegen.h
//
// define common code generator base classes for all one pass jit compilers
//
// ============================================================================

#include "singlepass/common/definitions.h"

namespace zen::singlepass {

template <typename ConcreteArgumentInfo, typename ConcreteArgumentInfoAttrs>
class ArgumentInfo {
public:
  typedef typename ConcreteArgumentInfoAttrs::DataType DataType;
  typedef typename ConcreteArgumentInfoAttrs::RegNum RegNumType;
  typedef typename ConcreteArgumentInfoAttrs::OnePassABI OnePassABI;
  typedef typename ConcreteArgumentInfoAttrs::ArchABI ArchABI;

  template <DataType Type>
  using TypeAttr = typename ConcreteArgumentInfoAttrs::template TypeAttr<Type>;

  class Argument {
  private:
    WASMType Type : 8;  // formal type
    RegNumType Reg : 8; // argument if passed by register
    uint16_t Offset;    // offset on stack if passed by stack

  public:
    Argument(WASMType Type, RegNumType Reg, uint32_t Offset)
        : Type(Type), Reg(Reg), Offset(Offset) {
      ZEN_ASSERT((Offset >> 16) == 0);
    }

    WASMType getType() const { return Type; }
    RegNumType getRegNum() const { return Reg; }
    bool inReg() const { return Reg != OnePassABI::InvalidParamReg; }
    uint32_t getOffset() const { return Offset; }
  };

  ArgumentInfo(TypeEntry *Type) {
    ZEN_ASSERT(Type);
    ZEN_ASSERT(Type->NumReturns <= 1);
    uint32_t ArgNum = Type->NumParams;
    RetType = Type->getReturnType();
    uint32_t GpNum = 0;
    uint32_t FpNum = 0;
    uint32_t StkSize = OnePassABI::ActualStackOffset;
    Arguments.reserve(ArgNum + 1); // reserve 1 more for instance

    // instance
    layoutArgument<WASMType::I64>(GpNum, StkSize);

    if (ArgNum == 0) {
      NumGpRegs = GpNum;
      NumFpRegs = 0;
      StackSize = StkSize;
      return;
    }

    const WASMType *ParamTypes = Type->getParamTypes();
    for (uint32_t I = 0; I < ArgNum; ++I) {
      switch (ParamTypes[I]) {
      case WASMType::I32:
        layoutArgument<WASMType::I32>(GpNum, StkSize);
        break;
      case WASMType::I64:
        layoutArgument<WASMType::I64>(GpNum, StkSize);
        break;
      case WASMType::F32:
        layoutArgument<WASMType::F32>(FpNum, StkSize);
        break;
      case WASMType::F64:
        layoutArgument<WASMType::F64>(FpNum, StkSize);
        break;
      case WASMType::V128:
        layoutArgument<WASMType::V128>(FpNum, StkSize);
        break;
      default:
        ZEN_ABORT();
      }
    }
    NumGpRegs = GpNum;
    NumFpRegs = FpNum;
    StkSize = ZEN_ALIGN(StkSize, ArchABI::FpRegWidth);
    StackSize = StkSize;
  }

  WASMType getReturnType() const { return RetType; }
  uint32_t getStackSize() const { return StackSize; }

  typedef typename std::vector<Argument>::const_reverse_iterator
      ConstReverseIterator;
  typedef typename std::vector<Argument>::const_iterator ConstIterator;

  ConstIterator cbegin() const { return Arguments.cbegin(); }
  ConstIterator cend() const { return Arguments.cend(); }
  ConstReverseIterator crbegin() const { return Arguments.crbegin(); }
  ConstReverseIterator crend() const { return Arguments.crend(); }
  uint32_t size() const { return Arguments.size(); }
  const Argument &front() const { return Arguments.front(); }
  const Argument &at(uint32_t Index) const { return Arguments[Index]; }

private:
  ConcreteArgumentInfo &self() {
    return static_cast<ConcreteArgumentInfo &>(*this);
  }

  template <WASMType Type>
  void layoutArgument(uint32_t &RegNum, uint32_t &StkSize) {
    constexpr DataType DataType =
        ConcreteArgumentInfo::getDataTypeFromWASMType(Type);

    if (RegNum < OnePassABI::template getNumParamRegs<DataType>()) {
      // in register
      auto Reg = OnePassABI::template getParamRegNum<DataType>(RegNum);
      ++RegNum;
      Arguments.emplace_back(Type, Reg, 1);
    } else {
      constexpr uint32_t Align = TypeAttr<DataType>::StackAlign;
      ZEN_STATIC_ASSERT((Align & (Align - 1)) == 0);
      StkSize = ZEN_ALIGN(StkSize, Align);
      Arguments.emplace_back(Type, OnePassABI::InvalidParamReg, StkSize);
      StkSize += Align;
    }
  }

  std::vector<Argument> Arguments;
  uint8_t NumGpRegs;
  uint8_t NumFpRegs;
  uint16_t StackSize;
  WASMType RetType : 8;
};

constexpr uint32_t InvalidLabelId = asmjit::Globals::kInvalidId;

struct FunctionState {
  // when process wasm trap by software,
  // _exception_exit_label means block label to return current wasm func to
  // parent when process wasm trap by CPU-trap, _exception_exit_label means
  // block label to use cpu trap to exit current wasm function
  uint32_t ExceptionExitLabel = InvalidLabelId;
  std::map<ErrorCode, asmjit::Label> ExceptLabels;

  int32_t FrameSizePatchOffset = -1;
  int32_t GasCheckPatchOffset = -1;
};

#define _ ASM.Assembler().

template <typename ConcreteCodeGen, typename ConcreteCodeGenAttrs>
class OnePassCodeGen {
public:
  typedef JITCompilerContext CompilerContext;
  typedef typename ConcreteCodeGenAttrs::ArgumentInfo ArgumentInfo;
  typedef typename ConcreteCodeGenAttrs::Operand Operand;
  typedef typename ConcreteCodeGenAttrs::VMState VMState;
  typedef typename ConcreteCodeGenAttrs::Assembler Assembler;
  typedef typename ConcreteCodeGenAttrs::OnePassDataLayout OnePassDataLayout;
  typedef typename ConcreteCodeGenAttrs::CodePatcher CodePatcher;
  typedef typename ConcreteCodeGenAttrs::OnePassABI OnePassABI;
  typedef typename ConcreteCodeGenAttrs::ArchABI ArchABI;
  typedef typename ConcreteCodeGenAttrs::RegNum RegNum;
  typedef typename ConcreteCodeGenAttrs::GP GP;
  typedef typename ConcreteCodeGenAttrs::FP FP;
  typedef typename ConcreteCodeGenAttrs::DataType DataType;
  typedef typename ConcreteCodeGenAttrs::Mem Mem;
  typedef typename ConcreteCodeGenAttrs::RegClass RegClass;

  template <DataType Type>
  using TypeAttr = typename ConcreteCodeGenAttrs::template TypeAttr<Type>;

  static constexpr DataType I32 = ConcreteCodeGenAttrs::I32;
  static constexpr DataType F32 = ConcreteCodeGenAttrs::F32;
  static constexpr DataType I64 = ConcreteCodeGenAttrs::I64;
  static constexpr DataType F64 = ConcreteCodeGenAttrs::F64;
  static constexpr DataType V128 = ConcreteCodeGenAttrs::V128;

  static constexpr uint32_t GlobalBaseOffset =
      offsetof(Instance, GlobalVarData);
  static constexpr uint32_t MemoriesOffset = offsetof(Instance, Memories);
  static constexpr uint32_t MemoryBaseOffset =
      offsetof(MemoryInstance, MemBase);
  static constexpr uint32_t MemorySizeOffset =
      offsetof(MemoryInstance, MemSize);
  static constexpr uint32_t MemoryPagesOffset =
      offsetof(MemoryInstance, CurPages);
  static constexpr uint32_t TablesOffset = offsetof(Instance, Tables);
  static constexpr uint32_t TableSizeOffset = offsetof(TableInstance, CurSize);
  static constexpr uint32_t TableBaseOffset = offsetof(TableInstance, Elements);
  static constexpr uint32_t FunctionTypesOffset =
      offsetof(Instance, FuncTypeIdxs);
  static constexpr uint32_t FunctionPointersOffset =
      offsetof(Instance, JITFuncPtrs);
  static constexpr uint32_t ExceptionOffset = offsetof(Instance, Err.ErrCode);
  static constexpr uint32_t StackBoundaryOffset =
      offsetof(Instance, JITStackBoundary);
  static constexpr uint32_t GasLeftOffset = offsetof(Instance, Gas);
#ifdef ZEN_ENABLE_DWASM
  static constexpr uint32_t InHostApiOffset = offsetof(Instance, InHostAPI);
  static constexpr uint32_t InHostApiSize = sizeof(Instance::InHostAPI);
#endif

  // for control instructions
  enum class CtrlBlockKind : uint8_t { FUNC_ENTRY, BLOCK, LOOP, IF };

  // Record each nested block
  class BlockInfo {
  public:
    BlockInfo(CtrlBlockKind Kind, Operand Result, uint32_t Label,
              uint32_t StackSize)
        : Kind(Kind), Result(Result), Label(Label), StackSize(StackSize) {}

    // Get block kind
    CtrlBlockKind getKind() const { return Kind; }

    Operand getResult() const { return Result; }

    // Get block WASM type
    WASMType getType() const { return Result.getType(); }

    // Get label associated with the block
    uint32_t getLabel() const { return Label; }

    // Get native stack size associated with the block
    uint32_t getStackSize() const { return StackSize; }

    // Get label associated with the else block of an if-block
    uint32_t getElseLabel() const {
      ZEN_ASSERT(Kind == CtrlBlockKind::IF);
      return Label + 1;
    }

    void setHasElseLabel() { HasElseLabel = true; }

    bool hasElseLabel() const { return HasElseLabel; }

    void setReachable(bool V) { Reachable = V; }

    bool reachable() const { return Reachable; }

  private:
    CtrlBlockKind Kind;
    Operand Result;
    uint32_t Label;
    uint32_t StackSize;

    bool HasElseLabel = false;
    bool Reachable = true;
  };

  OnePassCodeGen(asmjit::CodeHolder *Code, OnePassDataLayout &Layout,
                 CodePatcher &Patcher, JITCompilerContext *Ctx)
      : ASM(Code), Layout(Layout), Patcher(Patcher), ABI(Layout.getABI()),
        Ctx(Ctx) {
    Stack.reserve(16);
  }

  // Initialize before handle the function
  void initFunction(JITCompilerContext *Ctx) {
    TypeEntry *Type = Ctx->FuncType;
    // Initialize function state
    CurFuncState = FunctionState();

    // Initialize stack layout
    Patcher.initFunction(Ctx->Func, Ctx->InternalFuncIdx);

    // Initialize stack layout
    Layout.initFunction(Ctx);

    // Call impl's initFunction at first
    self().emitProlog(Ctx);

    // Save parameters in reg to stack
    saveParamReg(Type->NumParams);

    ZEN_ASSERT(Stack.size() == 0);

    WASMType RetType = Type->getReturnType();
    // Use stack operand instead of register operand, as return values of
    // function/block have relatively long lifetime and may hold registers
    // for too long.
    auto Res =
        (RetType == WASMType::VOID) ? Operand() : getTempStackOperand(RetType);
    Stack.emplace_back(CtrlBlockKind::FUNC_ENTRY, Res, createLabel(), 0);
  }

  // finalize after handle the function
  void finalizeFunctionBase() {
    ZEN_ASSERT(Stack.size() == 0);

    uint32_t GotExcept = InvalidLabelId;
    for (const auto &P : CurFuncState.ExceptLabels) {
      _ bind(P.second);
      movImm<I32>(ABI.template getParamRegNum<I32, 1>(),
                  static_cast<uint32_t>(P.first));
      if (P.first == ErrorCode::GasLimitExceeded) {
        movImm<I64>(ABI.getGasRegNum(), 0); // clear remaining gas
      }

      if (GotExcept == InvalidLabelId) {
        GotExcept = createLabel();
      }
      self().branch(GotExcept);
    }

    if (GotExcept != InvalidLabelId) {
      bindLabel(GotExcept);
      mov<I64>(ABI.template getParamRegNum<I64, 0>(), ABI.getModuleInst());
      self().callAbsolute(uintptr_t(Instance::triggerInstanceExceptionOnJIT));

      if (CurFuncState.ExceptionExitLabel == InvalidLabelId) {
        CurFuncState.ExceptionExitLabel = createLabel();
      }
      self().branch(CurFuncState.ExceptionExitLabel);
    }

    if (CurFuncState.ExceptionExitLabel != InvalidLabelId) {
      bindLabel(CurFuncState.ExceptionExitLabel);

      self().setException();
#ifdef ZEN_ENABLE_CPU_EXCEPTION
      mov<I64>(ABI.template getParamRegNum<I64, 0>(), ABI.getModuleInst());
      self().callAbsolute(uintptr_t(Instance::throwInstanceExceptionOnJIT));
#else
      if (Layout.getNumReturns() > 0) {
        self().emitEpilog(getReturnRegOperand(Layout.getReturnType(0)));
      } else {
        self().emitEpilog(Operand());
      }
#endif // ZEN_ENABLE_CPU_EXCEPTION
    }

    self().finalizeFunction();

    // clear stack layout
    Layout.finalizeFunction();
  }

  // release operand and make the register/stack space available for reuse
  void releaseOperand(Operand Opnd) {
    if (!Opnd.isTempReg() && !Opnd.isTempMem()) {
      return;
    }
    Layout.releaseOperand(Opnd);
  }

  template <uint32_t TempRegIndex = ScopedTempReg0>
  void makeAssignment(WASMType Type, Operand LHS, Operand RHS) {
    ZEN_ASSERT(LHS.getType() == Type);
    ZEN_ASSERT(RHS.getType() == Type);
    ZEN_ASSERT(LHS.isReg() || LHS.isMem());
    switch (Type) {
    case WASMType::I32:
      mov<I32, TempRegIndex>(LHS, RHS);
      break;
    case WASMType::I64:
      mov<I64, TempRegIndex>(LHS, RHS);
      break;
    case WASMType::F32:
      mov<F32, TempRegIndex>(LHS, RHS);
      break;
    case WASMType::F64:
      mov<F64, TempRegIndex>(LHS, RHS);
      break;
    default:
      // ZEN_ASSERT_TODO();
      throw getError(ErrorCode::TypeMismatch);
    }
  }

  // ==================== Block Methods ====================

  const BlockInfo &getBlockInfo(uint32_t Level) {
    ZEN_ASSERT(Level < Stack.size());
    return Stack[Stack.size() - Level - 1];
  }

  BlockInfo &getCurrentBlockInfo() {
    ZEN_ASSERT(!Stack.empty());
    return Stack.back();
  }

  // ==================== Control Instruction Handlers ====================

  void handleUnreachable() { self().handleUnreachableImpl(); }

  void handleBlock(WASMType Type, uint32_t Estack) {
    uint32_t Label = createLabel();
    auto Res = (Type == WASMType::VOID) ? Operand() : getTempStackOperand(Type);
    Stack.push_back(BlockInfo(CtrlBlockKind::BLOCK, Res, Label, Estack));
  }

  void handleLoop(WASMType Type, uint32_t Estack) {
    uint32_t Label = createLabel();
    auto Res = (Type == WASMType::VOID) ? Operand() : getTempStackOperand(Type);
    Stack.push_back(BlockInfo(CtrlBlockKind::LOOP, Res, Label, Estack));
    bindLabel(Label);
  }

  void handleIf(Operand Op, WASMType Type, uint32_t Estack) {
    uint32_t Label = createLabel();
    uint32_t ElseLabel = createLabel();
    ZEN_ASSERT(ElseLabel == Label + 1);
    auto Res = (Type == WASMType::VOID) ? Operand() : getTempStackOperand(Type);
    Stack.push_back(BlockInfo(CtrlBlockKind::IF, Res, Label, Estack));
    self().branchFalse(Op, ElseLabel);
  }

  // else block in if-block
  // if (!cond) goto else_label;
  //    ...
  //    goto label;
  // else_label:
  //    ...
  // label:
  void handleElse(const BlockInfo &Info) {
    ZEN_ASSERT(Stack.size() > 0);
    ZEN_ASSERT(&Info == &Stack.back());
    ZEN_ASSERT(Info.getKind() == CtrlBlockKind::IF);
    ZEN_ASSERT(Info.getElseLabel() != 0);
    // jump from end of then block to end of if
    self().branch(Info.getLabel());
    // bind else label
    bindLabel(Info.getElseLabel());
    // set else label emitted
    Stack.back().setHasElseLabel();
  }

  void handleEnd(const BlockInfo &Info) {
    ZEN_ASSERT(Stack.size() > 0);
    ZEN_ASSERT(&Info == &Stack.back());
    CtrlBlockKind Kind = Info.getKind();
    // bind else label for IF if no else block
    if (Kind == CtrlBlockKind::IF && !Info.hasElseLabel()) {
      bindLabel(Info.getElseLabel());
    }
    // bind label to end of block for BLOCK/IF/FUNC
    if (Kind != CtrlBlockKind::LOOP) {
      bindLabel(Info.getLabel());
    }
    Stack.pop_back();
  }

  void handleBranch(uint32_t Level, const BlockInfo &Info) {
    ZEN_ASSERT(Level < Stack.size());
    ZEN_ASSERT(&Info == &Stack[Stack.size() - Level - 1]);
    self().branch(Info.getLabel());
  }

  void handleBranchIf(Operand Op, uint32_t Level, const BlockInfo &Info) {
    ZEN_ASSERT(Level < Stack.size());
    ZEN_ASSERT(&Info == &Stack[Stack.size() - Level - 1]);
    // if (opnd) goto label;
    self().branchTrue(Op, Info.getLabel());
  }

  void handleBranchTable(Operand Index, Operand StackTop,
                         const std::vector<uint32_t> &Levels) {
    std::vector<uint32_t> Labels;
    Labels.reserve(Levels.size());
    std::generate_n(std::back_inserter(Labels), Levels.size(),
                    [this] { return createLabel(); });

    self().handleBranchTableImpl(Index, Labels);

    // TODO: no need to emit extra jumps if there's no result value
    for (size_t I = 0; I < Levels.size(); ++I) {
      bindLabel(Labels[I]);
      const auto &Info = Stack.at(Stack.size() - Levels[I] - 1);
      if (Info.getType() != WASMType::VOID &&
          Info.getKind() != CtrlBlockKind::LOOP) {
        makeAssignment<ScopedTempReg0>(Info.getType(), Info.getResult(),
                                       StackTop);
      }
      self().branch(Info.getLabel());
    }
  }

  void handleReturn(Operand Opnd) { self().handleReturnImpl(Opnd); }

  Operand handleCall(uint32_t FuncIdx, uintptr_t Target, bool IsImport,
                     bool FarCall, const ArgumentInfo &ArgInfo,
                     const std::vector<Operand> &Arg) {
    return self().handleCallImpl(FuncIdx, Target, IsImport, FarCall, ArgInfo,
                                 Arg);
  }

  Operand handleCallIndirect(uint32_t TypeIdx, Operand Callee, uint32_t TblIdx,
                             const ArgumentInfo &ArgInfo,
                             const std::vector<Operand> &Arg) {
    return self().handleCallIndirectImpl(TypeIdx, Callee, TblIdx, ArgInfo, Arg);
  }

  // ==================== Parametric Instruction Handlers ====================

  Operand handleSelect(Operand Cond, Operand LHS, Operand RHS) {
    return self().handleSelectImpl(Cond, LHS, RHS);
  }

  // ==================== Variable Instruction Handlers ====================

  Operand handleGetLocal(uint32_t LocalIdx) {
    auto Val = Layout.getLocal(LocalIdx);
    auto Ret = getTempOperand(Val.getType());
    makeAssignment<ScopedTempReg0>(Val.getType(), Ret, Val);
    return Ret;
  }

  void handleSetLocal(uint32_t LocalIdx, Operand Val) {
    auto Local = Layout.getLocal(LocalIdx);
    ZEN_ASSERT(Local.getType() == Val.getType());
    makeAssignment<ScopedTempReg0>(Local.getType(), Local, Val);
  }

  Operand handleGetGlobal(uint32_t GlobalIdx) {
    auto Val = Layout.getGlobal(ABI.getGlobalDataBase(), GlobalIdx);
    auto Ret = getTempOperand(Val.getType());
    makeAssignment<ScopedTempReg0>(Val.getType(), Ret, Val);
    return Ret;
  }

  void handleSetGlobal(uint32_t GlobalIdx, Operand Val) {
    auto Local = Layout.getGlobal(ABI.getGlobalDataBase(), GlobalIdx);
    ZEN_ASSERT(Local.getType() == Val.getType());
    makeAssignment<ScopedTempReg0>(Local.getType(), Local, Val);
  }

  // ==================== Memory Instruction Handlers ====================

  // Load from memory in SrcType and extend to DestType
  template <WASMType DestType, WASMType SrcType, bool Sext>
  Operand handleLoad(Operand Base, uint32_t Offset, uint32_t Align) {
    return self().template handleLoadImpl<DestType, SrcType, Sext>(Base, Offset,
                                                                   Align);
  }

  // Store to memory in DestType
  template <WASMType DestType>
  void handleStore(Operand Value, Operand Base, uint32_t Offset,
                   uint32_t Align) {
    self().template handleStoreImpl<DestType>(Value, Base, Offset, Align);
  }

  Operand handleMemorySize() { return self().handleMemorySizeImpl(); }

  Operand handleMemoryGrow(Operand Op) {
    return self().handleMemoryGrowImpl(Op);
  }

  // ==================== Numeric Instruction Handlers ====================

  template <WASMType Ty>
  Operand handleConst(typename WASMTypeAttr<Ty>::Type Val) {
    return self().template handleConstImpl<Ty>(Val);
  }

  // compare operator
  template <WASMType Type, CompareOperator Opr>
  Operand handleCompareOp(Operand LHS, Operand RHS) {
    return self().template handleCompareOpImpl<Type, Opr>(LHS, RHS);
  }

  template <WASMType CondType, CompareOperator Opr>
  void handleFusedCompareIfa(Operand LHS, Operand RHS, WASMType Type,
                             uint32_t Estack) {
    uint32_t Label = createLabel();
    uint32_t ElseLabel = createLabel();
    ZEN_ASSERT(ElseLabel == Label + 1);
    auto Res = (Type == WASMType::VOID) ? Operand() : getTempStackOperand(Type);
    Stack.push_back(BlockInfo(CtrlBlockKind::IF, Res, Label, Estack));
    self().template handleFusedCompareBranchImpl<CondType, Opr, false>(
        LHS, RHS, ElseLabel);
  }

  template <WASMType CondType, CompareOperator Opr>
  void handleFusedCompareBranchIf(Operand LHS, Operand RHS, uint32_t Level,
                                  const BlockInfo &Info) {
    ZEN_ASSERT(Level < Stack.size());
    ZEN_ASSERT(&Info == &Stack[Stack.size() - Level - 1]);
    self().template handleFusedCompareBranchImpl<CondType, Opr, true>(
        LHS, RHS, Info.getLabel());
  }

  // fused compare and select
  template <WASMType Type, CompareOperator Opr>
  Operand handleFusedCompareSelect(Operand CmpLHS, Operand CmpRHS,
                                   Operand SelLHS, Operand SelRHS) {
    return self().template handleFusedCompareSelectImpl<Type, Opr>(
        CmpLHS, CmpRHS, SelLHS, SelRHS);
  }

  template <WASMType Type, UnaryOperator Opr>
  Operand handleBitCountOp(Operand Op) {
    return self().template handleBitCountOpImpl<Type, Opr>(Op);
  }

  template <WASMType Type, BinaryOperator Opr>
  Operand handleBinaryOp(Operand LHS, Operand RHS) {
    return self().template handleBinaryOpImpl<Type, Opr>(LHS, RHS);
  }

  template <WASMType Type, BinaryOperator Opr>
  Operand handleIDiv(Operand LHS, Operand RHS) {
    return self().template handleIDivOpImpl<Type, Opr>(LHS, RHS);
  }

  template <WASMType Type, BinaryOperator Opr>
  Operand handleShift(Operand LHS, Operand RHS) {
    return self().template handleShiftOpImpl<Type, Opr>(LHS, RHS);
  }

  template <WASMType Type, UnaryOperator Opr>
  Operand handleUnaryOp(Operand Op) {
    return self().template handleUnaryOpImpl<Type, Opr>(Op);
  }

  template <WASMType Type, BinaryOperator Opr>
  Operand handleFDiv(Operand LHS, Operand RHS) {
    return self().template handleFDivOpImpl<Type, Opr>(LHS, RHS);
  }

  template <WASMType Type, BinaryOperator Opr>
  Operand handleFloatMinMax(Operand LHS, Operand RHS) {
    return self().template handleFloatMinMaxImpl<Type, Opr>(LHS, RHS);
  }

  template <WASMType Type>
  Operand handleFloatCopysign(Operand LHS, Operand RHS) {
    return self().template handleFloatCopysignImpl<Type>(LHS, RHS);
  }

  Operand handleIntTrunc(Operand Op) { return self().handleIntTruncImpl(Op); }

  template <WASMType DestType, WASMType SrcType, bool Sext>
  Operand handleFloatToInt(Operand Op) {
    return self().template handleFloatToIntImpl<DestType, SrcType, Sext>(Op);
  }

  // Extend from SrcType (smaller) to DestType (larger) with the same type kind
  template <WASMType DestType, WASMType SrcType, bool Sext>
  Operand handleIntExtend(Operand Op) {
    return self().template handleIntExtendImpl<DestType, SrcType, Sext>(Op);
  }

  // Convert from SrcType to dtype between integer and floating-point
  template <WASMType DestType, WASMType SrcType, bool Sext>
  Operand handleConvert(Operand Op) {
    return self().template handleConvertImpl<DestType, SrcType, Sext>(Op);
  }

  // Reinterpret value from stype to dtype between integer and floating-point
  template <WASMType DestType, WASMType Srctype>
  Operand handleBitcast(Operand Op) {
    constexpr auto DType = ArgumentInfo::getDataTypeFromWASMType(DestType);
    constexpr auto SType = ArgumentInfo::getDataTypeFromWASMType(Srctype);

    auto Src = self().template toReg<SType, ScopedTempReg0>(Op);
    auto Dest = Layout.template getScopedTemp<DType, ScopedTempReg0>();
    ASM.fmov(RegClass::template getRegRef<DType>(Dest),
             RegClass::template getRegRef<SType>(Src));

    auto Ret = getTempOperand(DestType);
    mov<DType>(Ret, Dest);
    return Ret;
  }

  // ==================== Platform Feature Methods ====================

  void handleGasCall(Operand Delta) {
    self().subGasVal(Delta);
    self().branchLTU(getExceptLabel(ErrorCode::GasLimitExceeded).id());
  }

  template <bool Sign, WASMType Type, BinaryOperator Opr>
  Operand handleCheckedArithmetic(Operand LHS, Operand RHS) {
    return self().template checkedArithmetic<Sign, Type, Opr>(LHS, RHS);
  }
  template <bool Sign, BinaryOperator Opr>
  Operand handleCheckedI128Arithmetic(Operand LHSLow, Operand LHSHigh,
                                      Operand RHSLow, Operand RHSHigh) {
    return self().template checkedI128Arithmetic<Sign, Opr>(LHSLow, LHSHigh,
                                                            RHSLow, RHSHigh);
  }

protected:
  // ==================== Move Methods ====================

  template <DataType Type, uint32_t TempRegIndex>
  void mov(Operand LHS, Operand RHS) {
    ZEN_ASSERT(LHS.isReg() || LHS.isMem());

    if (LHS.isReg()) {
      mov<Type>(LHS.getReg(), RHS);
    } else {
      mov<Type, TempRegIndex>(LHS.template getMem<Type>(), RHS);
    }
  }

  template <DataType Type, bool AllowRemove = true>
  void mov(Operand LHS, RegNum RHS) {
    ZEN_ASSERT(LHS.isReg() || LHS.isMem());

    if (LHS.isReg()) {
      auto LHSReg = LHS.getReg();
      //  when LHS == RHS and Type is 64bit, no need to mov
      if (LHSReg != RHS) {
        mov<Type>(LHSReg, RHS);
      } else if (!AllowRemove && Type == DataType::I32) {
        // some mov reg32, reg32 used to clear first 32bit
        mov<Type>(LHSReg, RHS);
      }
    } else {
      self().template storeRegToMem<Type>(RHS, LHS.template getMem<Type>());
    }
  }

  // store value to memory
  template <DataType Type, uint32_t TempRegIndex>
  void mov(const Mem &Mem, Operand Val) {
    if (Val.isReg()) {
      self().template storeRegToMem<Type>(Val.getReg(), Mem);
      return;
    }
    constexpr DataType WidenType = TypeAttr<Type>::WidenType;
    if (Val.isImm()) {
      self().template storeImmToMem<Type, TempRegIndex>(Val.getImm(), Mem);
    } else if (Val.isMem()) {
      auto TempReg = Layout.template getScopedTemp<Type, TempRegIndex>();
      self().template loadRegFromMem<WidenType, Type, false>(
          TempReg, Val.template getMem<Type>());
      self().template storeRegToMem<Type>(TempReg, Mem);
    } else {
      ZEN_ABORT();
    }
  }

  // move value from rhs (reg, mem, imm) to lhs (reg only)
  template <DataType Type> void mov(RegNum LHS, Operand RHS) {
    if (RHS.isReg()) {
      ASM.template mov<Type>(RegClass::template getRegRef<Type>(LHS),
                             RHS.template getRegRef<Type>());
    } else if (RHS.isMem()) {
      self().template loadRegFromMem<Type>(LHS, RHS.template getMem<Type>());
    } else {
      ASM.template mov<Type>(RegClass::template getRegRef<Type>(LHS),
                             RHS.getImm());
    }
  }

  template <DataType Type> void mov(RegNum LHS, RegNum RHS) {
    ASM.template mov<Type>(RegClass::template getRegRef<Type>(LHS),
                           RegClass::template getRegRef<Type>(RHS));
  }

  // only used for Gp
  template <DataType Type> void movImm(RegNum LHS, int64_t RHS) {
    ASM.template mov<Type>(RegClass::template getRegRef<Type>(LHS), RHS);
  }

  template <DataType Type, uint32_t TempRegIndex>
  void movImm(const Mem &Mem, int64_t RHS) {
    auto TempReg = Layout.template getScopedTemp<Type, TempRegIndex>();
    ASM.template mov<Type>(RegClass::template getRegRef<Type>(TempReg), RHS);
    self().template storeRegToMem<Type>(TempReg, Mem);
  }

  template <DataType Type, uint32_t TempRegIndex>
  void movImm(Operand LHS, int64_t RHS) {
    ZEN_ASSERT(LHS.isReg() || LHS.isMem());
    if (LHS.isReg()) {
      movImm<Type>(LHS.getReg(), RHS);
    } else {
      movImm<Type, TempRegIndex>(LHS.template getMem<Type>(), RHS);
    }
  }

  // ==================== Operand Methods ====================

  // Get a temporary operand either in temp register or stack
  Operand getTempOperand(WASMType Type) {
    const auto [kind, size] = getWASMTypeKindAndSize(Type);
    if (kind == WASMTypeKind::INTEGER) {
      GP RegNum;
      if (Layout.template hasAvailTempReg<I64>(RegNum)) {
        Layout.template clearAvailReg<I64>(RegNum);
        return Operand(Type, RegNum, Operand::FLAG_TEMP_REG);
      }
    } else {
      FP RegNum;
      if (Layout.template hasAvailTempReg<F64>(RegNum)) {
        Layout.template clearAvailReg<F64>(RegNum);
        return Operand(Type, RegNum, Operand::FLAG_TEMP_REG);
      }
    }
    return getTempStackOperand(Type, size);
  }

  // get a temporary space on stack
  Operand getTempStackOperand(WASMType Type, uint32_t Size) {
    ZEN_ASSERT(getWASMTypeSize(Type) == Size);
    auto Ret = Layout.getTempStackOperand(Type, Size);
    ZEN_ASSERT(Ret.isMem());
    return Ret;
  }

  Operand getTempStackOperand(WASMType Type) {
    return getTempStackOperand(Type, getWASMTypeSize(Type));
  }

  // Get return register operand
  Operand getReturnRegOperand(WASMType Type) {
    RegNum Reg;
    if (Type == WASMType::I32 || Type == WASMType::I64) {
      Reg = ABI.template getRetRegNum<I64>();
    } else if (Type == WASMType::F32 || Type == WASMType::F64 ||
               Type == WASMType::V128) {
      Reg = ABI.template getRetRegNum<F64>();
    } else {
      ZEN_ABORT();
    }
    return Operand(Type, Reg, Operand::FLAG_NONE);
  }

  // ==================== Label Methods ====================

  // Bind label to current pc
  void bindLabel(uint32_t Id) { ASM.bind(Id); }

  // Create a label
  uint32_t createLabel() { return ASM.newLabel(); }

  asmjit::Label getExceptLabel(ErrorCode Id) {
    auto It = CurFuncState.ExceptLabels.lower_bound(Id);
    if (It == CurFuncState.ExceptLabels.end() || It->first != Id) {
      It = CurFuncState.ExceptLabels.emplace_hint(It, Id, _ newLabel());
    }
    return It->second;
  }

  void embedLabel(uint32_t Id) { _ embedLabel(asmjit::Label(Id)); }

  void emitJumpTable(uint32_t Table, const std::vector<uint32_t> &Targets) {
    // align code to pointer boundary
    _ align(asmjit::AlignMode::kCode, sizeof(uintptr_t));
    bindLabel(Table);
    for (uint32_t Target : Targets) {
      embedLabel(Target);
    }
  }

  template <typename PrepareCallFn, typename GenerateCallFn,
            typename PostCallFn>
  Operand emitCall(const ArgumentInfo &ArgInfo, const std::vector<Operand> &Arg,
                   PrepareCallFn PreCall, GenerateCallFn GenCall,
                   PostCallFn PostCall) {
    constexpr uint32_t GpRegNum = OnePassABI::template getNumTempRegs<I64>();
    constexpr uint32_t FpRegNum = OnePassABI::template getNumTempRegs<F64>();
    // save temp gp register
    uint32_t GpMask = Layout.template getAvailRegMask<I64>();
    uint32_t FpMask = Layout.template getAvailRegMask<F64>();
    uint32_t GpRegToSave = GpRegNum;
    if (GpMask) {
      GpRegToSave -= __builtin_popcount(GpMask);
    }
    uint32_t FpRegToSave = FpRegNum;
    if (FpMask) {
      FpRegToSave -= __builtin_popcount(FpMask);
    }
    // align gp_reg_to_save to 16 byte
    uint32_t StkSize = (GpRegToSave + (GpRegToSave & 1)) * ArchABI::GpRegWidth +
                       FpRegToSave * ArchABI::FpRegWidth +
                       ArgInfo.getStackSize();
    // allocate stack for function call
    self().subStackPointer(StkSize);

    // save temporary gp to stack
    uint32_t StackOffset = StkSize;
    if (GpRegToSave) {
      saveRestoreTempReg<I64, true>(GpMask, StackOffset);
      if (GpRegToSave & 1) {
        StackOffset -= ArchABI::GpRegWidth;
      }
      ZEN_ASSERT(StackOffset ==
                 FpRegToSave * ArchABI::FpRegWidth + ArgInfo.getStackSize());
    }

    // save temporary fp to stack
    if (FpRegToSave) {
      saveRestoreTempReg<V128, true>(FpMask, StackOffset);
      ZEN_ASSERT(StackOffset == ArgInfo.getStackSize());
    }

    // prepare call
    PreCall();

    // layout argument
    ZEN_ASSERT(ArgInfo.size() == Arg.size() + 1);

    std::vector<uint32_t> NeedSortedMovs;
    uint32_t GpRegUsed = 0;
    uint32_t FpRegUsed = 0;
    for (uint32_t I = 1; I < ArgInfo.size(); ++I) {
      const auto &Info = ArgInfo.at(I);
      if (Info.inReg()) {
        NeedSortedMovs.push_back(I);
        continue;
      }

      Operand Op = Arg[I - 1];
      ZEN_ASSERT(Op.getType() == Info.getType());
      copyParam(Info, Op, GpRegUsed, FpRegUsed, StackOffset);
    }

    // sort movs
    for (uint32_t I = 0; I < NeedSortedMovs.size(); ++I) {
      for (uint32_t J = I + 1; J < NeedSortedMovs.size(); ++J) {
        // should not take this sentence out, because need_sorted_movs
        // may change
        const auto &Info = ArgInfo.at(NeedSortedMovs[I]);
        Operand Op = Arg[NeedSortedMovs[J] - 1];
        if (Op.isReg() && Op.getReg() == Info.getRegNum()) {
          std::swap(NeedSortedMovs[I], NeedSortedMovs[J]);
        }
      }
    }

    // copy sorted movs
    for (uint32_t I : NeedSortedMovs) {
      const auto &Info = ArgInfo.at(I);
      Operand Op = Arg[I - 1];
      ZEN_ASSERT(Op.getType() == Info.getType());
      copyParam(Info, Op, GpRegUsed, FpRegUsed, StackOffset);
    }

    // place instance
    mov<I64>(ABI.template getParamRegNum<I64, 0>(), ABI.getModuleInst());

    // generare call
    GenCall();

    // copy return value if exist
    Operand RetVal;
    WASMType Type = ArgInfo.getReturnType();
    if (Type != WASMType::VOID) {
      RetVal = getTempOperand(Type);
      makeAssignment<ScopedTempReg1>(Type, RetVal, getReturnRegOperand(Type));
    }

    // restore temporary gp from stack
    StackOffset = StkSize;
    if (GpRegToSave) {
      saveRestoreTempReg<I64, false>(GpMask, StackOffset);
      if (GpRegToSave & 1) {
        StackOffset -= ArchABI::GpRegWidth;
      }
      ZEN_ASSERT(StackOffset ==
                 FpRegToSave * ArchABI::FpRegWidth + ArgInfo.getStackSize());
    }

    // restore temporary fp from stack
    if (FpRegToSave) {
      saveRestoreTempReg<V128, false>(FpMask, StackOffset);
      ZEN_ASSERT(StackOffset == ArgInfo.getStackSize());
    }

    // restore stack after function call
    self().addStackPointer(StkSize);

    PostCall();

    return RetVal;
  }

  // Use vector because branch may refer random parent block
  typedef std::vector<BlockInfo> BlockStack;
  BlockStack Stack; // manage nested block
  Assembler ASM;
  OnePassDataLayout &Layout;
  CodePatcher &Patcher;
  const OnePassABI &ABI;
  JITCompilerContext *Ctx;
  FunctionState CurFuncState;

private:
  ConcreteCodeGen &self() { return static_cast<ConcreteCodeGen &>(*this); }

  // save parameters in register to stack
  void saveParamReg(uint32_t ParamCnt) {
    uint32_t GpAvailMask = 0;
    uint32_t FpAvailMask = 0;
    for (uint32_t I = 0; I < ParamCnt; ++I) {
      auto Info = Layout.getLocalInfo(I);
      if (Info.inReg()) {
        Mem Addr(ABI.getFrameBaseReg(), Info.getOffset());
        switch (Info.getType()) {
        case WASMType::I32:
          GpAvailMask |= (1 << Info.getReg());
          self().template storeRegToMem<I32>(Info.getReg(), Addr);
          break;
        case WASMType::I64:
          GpAvailMask |= (1 << Info.getReg());
          self().template storeRegToMem<I64>(Info.getReg(), Addr);
          break;
        case WASMType::F32:
          FpAvailMask |= (1 << Info.getReg());
          self().template storeRegToMem<F32>(Info.getReg(), Addr);
          break;
        case WASMType::F64:
          FpAvailMask |= (1 << Info.getReg());
          self().template storeRegToMem<F64>(Info.getReg(), Addr);
          break;
        case WASMType::V128:
          FpAvailMask |= (1 << Info.getReg());
          self().template storeRegToMem<V128>(Info.getReg(), Addr);
          break;
        default:
          // ZEN_ASSERT_TODO();
          throw getError(ErrorCode::TypeMismatch);
        }
        // set local not in register
        Layout.clearLocalInRegister(I);
      }
    }
    if (GpAvailMask) {
      Layout.template markAvailRegMask<I64>(GpAvailMask &
                                            ABI.template getTempRegMask<I64>());
    }
    if (FpAvailMask) {
      Layout.template markAvailRegMask<F64>(FpAvailMask &
                                            ABI.template getTempRegMask<F64>());
    }
    // set all param on stack
    Layout.clearParamInReg();
  }

  // save/restore tempoorary registers for call
  template <DataType Type, bool Save>
  void saveRestoreTempReg(uint32_t Mask, uint32_t &StackOffset) {
    // TODO: optimization with ldp/stp
    constexpr uint32_t RegisterNum =
        OnePassABI::template getNumTempRegs<Type>();
    for (uint32_t I = 0; I < RegisterNum; ++I) {
      RegNum Reg = OnePassABI::template getTempRegNum<Type>(I);
      if ((Mask & (1 << Reg)) == 0) {
        StackOffset -= TypeAttr<Type>::Size;
        Mem Addr(ABI.getStackPointerReg(), StackOffset);
        if (Save) {
          self().template storeRegToMem<Type>(Reg, Addr);
        } else {
          self().template loadRegFromMem<Type>(Reg, Addr);
        }
      }
    }
  }

  void copyParam(const typename ArgumentInfo::Argument &Info, Operand Opnd,
                 uint32_t &GpRegUsed, uint32_t &FpRegUsed,
                 uint32_t StackOffset) {
    WASMTypeKind Kind = getWASMTypeKind(Opnd.getType());
    if (Kind == WASMTypeKind::INTEGER) {
      ZEN_ASSERT(!Opnd.isReg() || (GpRegUsed & (1 << Opnd.getReg())) == 0);
    } else {
      ZEN_ASSERT(!Opnd.isReg() || (FpRegUsed & (1 << Opnd.getReg())) == 0);
    }

    if (Info.inReg()) {
      RegNum Reg = Info.getRegNum();
      makeAssignment<ScopedTempReg1>(
          Info.getType(), Operand(Info.getType(), Reg, Operand::FLAG_NONE),
          Opnd);
      if (Kind == WASMTypeKind::INTEGER) {
        ZEN_ASSERT(GpRegUsed |= (1 << Reg));
      } else {
        ZEN_ASSERT(FpRegUsed |= (1 << Reg));
      }
    } else {
      ZEN_ASSERT(Info.getOffset() < StackOffset);
      Operand Dst(Info.getType(), ABI.getStackPointer(), Info.getOffset(),
                  Operand::FLAG_NONE);

      makeAssignment<ScopedTempReg1>(Info.getType(), Dst, Opnd);
    }
  }
};

#undef _

} // namespace zen::singlepass

#endif // ZEN_SINGLEPASS_COMMON_CODEGEN_H
