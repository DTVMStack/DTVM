// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef WASM_FRONTEND_WASM_MIR_COMPILER_H
#define WASM_FRONTEND_WASM_MIR_COMPILER_H

#include "compiler/context.h"
#include "compiler/mir/constants.h"
#include "compiler/mir/function.h"
#include "compiler/mir/instructions.h"
#include "compiler/mir/opcode.h"
#include "compiler/mir/pointer.h"

namespace COMPILER {

class Variable;

class WasmFrontendContext final : public CompileContext {
public:
  WasmFrontendContext(runtime::Module &WasmMod);

  ~WasmFrontendContext() override = default;

  WasmFrontendContext(const WasmFrontendContext &OtherCtx);

  WasmFrontendContext &operator=(const WasmFrontendContext &OtherCtx) = delete;

  WasmFrontendContext(WasmFrontendContext &&OtherCtx) = delete;

  WasmFrontendContext &operator=(WasmFrontendContext &&OtherCtx) = delete;

  static MType *getMIRTypeFromWASMType(WASMType Type);

  static WASMType getWASMTypeFromMIRType(MType *Type);

  runtime::Module &getWasmMod() { return WasmMod; }

  const runtime::Module &getWasmMod() const { return WasmMod; }

  void setCurFunc(uint32_t FuncIdx, runtime::TypeEntry *FuncType,
                  runtime::CodeEntry *FuncCode) {
    CurFuncIdx = FuncIdx;
    WasmFuncType = FuncType;
    WasmFuncCode = FuncCode;
  }

  uint32_t getCurFuncIdx() const { return CurFuncIdx; }

  const runtime::TypeEntry &getWasmFuncType() const { return *WasmFuncType; }

  const runtime::CodeEntry &getWasmFuncCode() const { return *WasmFuncCode; }

  const bool UseSoftMemCheck;

private:
  runtime::Module &WasmMod;
  uint32_t CurFuncIdx = -1; // exclude imported functions
  runtime::TypeEntry *WasmFuncType = nullptr;
  runtime::CodeEntry *WasmFuncCode = nullptr;
};

void buildAllMIRFuncTypes(WasmFrontendContext &Context, MModule &MMod,
                          const runtime::Module &WasmMod);

class FunctionMirBuilder final {
public:
  typedef WasmFrontendContext CompilerContext;

  FunctionMirBuilder(CompilerContext &Context, MFunction &MFunc);

  class Operand {
  public:
    Operand() = default;

    Operand(MInstruction *Instr, WASMType Type) : Instr(Instr), Type(Type) {}

    Operand(Variable *Var, WASMType Type) : Var(Var), Type(Type) {}

    MInstruction *getInstr() const { return Instr; }

    Variable *getVar() const { return Var; }

    WASMType getType() const { return Type; }

    bool isEmpty() const { return !Instr && !Var && Type == WASMType::VOID; }

    /* Do nothing, only used to match WASMByteVisitor */
    constexpr bool isReg() const { return false; }
    constexpr bool isMem() const { return false; }
    constexpr bool isTempReg() const { return true; }
    constexpr int getKind() const { return 0; }
    constexpr uint8_t getRawOpKind() const { return 0; }

  private:
    MInstruction *Instr = nullptr;
    Variable *Var = nullptr;
    WASMType Type = WASMType::VOID;
  };

  enum class CtrlBlockKind : uint8_t { FUNC_ENTRY, BLOCK, LOOP, IF };

  // Record each nested block
  class BlockInfo {
  public:
    BlockInfo(CtrlBlockKind Kind, Operand Result, uint32_t StackSize,
              MBasicBlock *JumpBlock, MBasicBlock *NextBlock,
              BrIfInstruction *BranchInst)
        : Kind(Kind), Result(Result), StackSize(StackSize),
          JumpBlock(JumpBlock), NextBlock(NextBlock), BranchInstr(BranchInst)
#ifdef ZEN_ENABLE_WASI_MULTI_VALUE
          ,
          IsMultiValue(false)
#endif
    {
    }

#ifdef ZEN_ENABLE_WASI_MULTI_VALUE
    // Constructor for multi-value blocks
    BlockInfo(CtrlBlockKind Kind, std::vector<Operand> Results,
              const TypeEntry *BlockType, uint32_t StackSize,
              MBasicBlock *JumpBlock, MBasicBlock *NextBlock,
              BrIfInstruction *BranchInst)
        : Kind(Kind), Results(std::move(Results)), BlockType(BlockType),
          StackSize(StackSize), JumpBlock(JumpBlock), NextBlock(NextBlock),
          BranchInstr(BranchInst), IsMultiValue(true) {
      Result = this->Results.empty() ? Operand() : this->Results[0];
    }
#endif

    CtrlBlockKind getKind() const { return Kind; }

    Operand getResult() const { return Result; }

    WASMType getType() const { return Result.getType(); }

#ifdef ZEN_ENABLE_WASI_MULTI_VALUE
    bool isMultiValue() const { return IsMultiValue; }
    uint32_t getNumResults() const {
      return IsMultiValue ? Results.size()
                          : (Result.getType() == WASMType::VOID ? 0 : 1);
    }
    const std::vector<Operand> &getResults() const { return Results; }
    const TypeEntry *getBlockType() const { return BlockType; }
#endif

    uint32_t getStackSize() const { return StackSize; }

    void setReachable(bool V) { Reachable = V; }

    bool reachable() const { return Reachable; }

    MBasicBlock *getJumpBlock() const { return JumpBlock; }

    MBasicBlock *getNextBlock() const { return NextBlock; }

    BrIfInstruction *getBranchInstr() const {
      ZEN_ASSERT(Kind == CtrlBlockKind::IF);
      return BranchInstr;
    }

  private:
    CtrlBlockKind Kind;
    Operand Result;
#ifdef ZEN_ENABLE_WASI_MULTI_VALUE
    std::vector<Operand> Results;
    const TypeEntry *BlockType = nullptr;
#endif
    uint32_t StackSize;
    MBasicBlock *JumpBlock = nullptr;
    MBasicBlock *NextBlock = nullptr;
    BrIfInstruction *BranchInstr = nullptr;
    bool Reachable = true;
#ifdef ZEN_ENABLE_WASI_MULTI_VALUE
    bool IsMultiValue = false;
#endif
  };

  class ArgumentInfo {
  public:
    ArgumentInfo(const TypeEntry *Type) {
      ZEN_ASSERT(Type);
#ifdef ZEN_ENABLE_WASI_MULTI_VALUE
      // Multi-value support: store all return types
      NumReturns = Type->NumReturns;
      if (NumReturns > 0) {
        ReturnTypes.resize(NumReturns);
        std::memcpy(ReturnTypes.data(), Type->getReturnTypes(),
                    NumReturns * sizeof(WASMType));
        RetType = ReturnTypes[0]; // Primary return type for backward compat
      } else {
        RetType = WASMType::VOID;
      }
#else
      RetType = Type->getReturnType();
#endif
      uint32_t NumParams = Type->NumParams;
      // Reserve 1 slot for instance
      ArgTypes.resize(NumParams + 1);
      ArgTypes[0] = WASMType::I64;
      std::memcpy(ArgTypes.data() + 1, Type->getParamTypes(),
                  NumParams * sizeof(WASMType));
    }

    WASMType getReturnType() const { return RetType; }

#ifdef ZEN_ENABLE_WASI_MULTI_VALUE
    uint32_t getNumReturns() const { return NumReturns; }
    const WASMType *getReturnTypes() const {
      return NumReturns > 0 ? ReturnTypes.data() : nullptr;
    }
#endif

  private:
    std::vector<WASMType> ArgTypes;
    WASMType RetType;
#ifdef ZEN_ENABLE_WASI_MULTI_VALUE
    uint32_t NumReturns = 0;
    std::vector<WASMType> ReturnTypes;
#endif
  };

  bool compile(CompilerContext *Context);

  void initFunction(CompilerContext *Context);

  void finalizeFunctionBase();

  // ==================== Block and Operand Methods ====================

  // Let `LHS = RHS`(Assign RHS to LHS)
  void makeAssignment(WASMType Type, const Operand &LHS, const Operand &RHS);

  /* Do nothing, only used to match WASMByteVisitor */
  void releaseOperand(Operand Opnd) {}

  const BlockInfo &getBlockInfo(uint32_t Level);

  BlockInfo &getCurrentBlockInfo();

  // ==================== Control Instruction Handlers ====================

  void handleUnreachable();

  void handleBlock(WASMType Type, uint32_t Estack);

#ifdef ZEN_ENABLE_WASI_MULTI_VALUE
  void handleBlockMultiValue(const TypeEntry *Type, uint32_t Estack);
#endif

  void handleLoop(WASMType Type, uint32_t Estack);

#ifdef ZEN_ENABLE_WASI_MULTI_VALUE
  void handleLoopMultiValue(const TypeEntry *Type, uint32_t Estack);
#endif

  void handleIf(Operand CondOp, WASMType Type, uint32_t Estack);

#ifdef ZEN_ENABLE_WASI_MULTI_VALUE
  void handleIfMultiValue(Operand CondOp, const TypeEntry *Type,
                          uint32_t Estack);
#endif

  void handleElse(const BlockInfo &Info);

  void handleEnd(const BlockInfo &Info);

  void handleBranch(uint32_t Level, const BlockInfo &Info);

  void handleBranchIf(Operand CondOp, uint32_t Level, const BlockInfo &Info);

  void handleBranchTable(Operand Index, Operand StackTop,
                         const std::vector<uint32_t> &Levels);

  void handleReturn(Operand Opnd);

#ifdef ZEN_ENABLE_WASI_MULTI_VALUE
  void handleReturnMultiValue(const std::vector<Operand> &Opnds);
#endif

  Operand handleCall(uint32_t FuncIdx, uintptr_t TarGet, bool IsImport,
                     bool FarCall, const ArgumentInfo &ArgInfo,
                     const std::vector<Operand> &Args);

#ifdef ZEN_ENABLE_WASI_MULTI_VALUE
  std::vector<Operand> handleCallMultiValue(uint32_t FuncIdx, uintptr_t TarGet,
                                            bool IsImport, bool FarCall,
                                            const ArgumentInfo &ArgInfo,
                                            const std::vector<Operand> &Args);
#endif

  Operand handleCallIndirect(uint32_t TypeIdx, Operand IndirectFuncIdx,
                             uint32_t TblIdx, const ArgumentInfo &ArgInfo,
                             const std::vector<Operand> &Args);

#ifdef ZEN_ENABLE_WASI_MULTI_VALUE
  std::vector<Operand>
  handleCallIndirectMultiValue(uint32_t TypeIdx, Operand IndirectFuncIdx,
                               uint32_t TblIdx, const ArgumentInfo &ArgInfo,
                               const std::vector<Operand> &Args);
#endif

  // ==================== Parametric Instruction Handlers ====================

  Operand handleSelect(Operand CondOp, Operand LHSOp, Operand RHSOp);

  // ==================== Variable Instruction Handlers ====================

  Operand handleGetLocal(uint32_t LocalIdx);

  void handleSetLocal(uint32_t LocalIdx, Operand Val);

  Operand handleGetGlobal(uint32_t GlobalIdx);

  void handleSetGlobal(uint32_t GlobalIdx, Operand Val);

  // ==================== Memory Instruction Handlers ====================

  // Load from memory in SrcType and extend to DestType
  template <WASMType DestType, WASMType SrcType, bool Sext>
  Operand handleLoad(Operand Base, uint32_t Offset, uint32_t Align) {
    ZEN_ASSERT(DestType >= SrcType);
    MType *SrcMTy = Ctx.getMIRTypeFromWASMType(SrcType);
    MType *DestMTy = Ctx.getMIRTypeFromWASMType(DestType);
    MInstruction *BaseInst = extractOperand(Base);
    const auto [MemoryBase, MemoryIndex, MemoryOffset] =
        getMemoryLocation(BaseInst, Offset, SrcMTy);
    MInstruction *Value = createInstruction<LoadInstruction>(
        false, DestMTy, SrcMTy, MemoryBase, 1, MemoryIndex, MemoryOffset, Sext);
    MInstruction *SafeValue = protectUnsafeValue(Value, DestMTy);
    return Operand(SafeValue, DestType);
  }

  // Store to memory in DestType
  template <WASMType DestType>
  void handleStore(Operand Value, Operand Base, uint32_t Offset,
                   uint32_t Align) {
    MType *MTy = Ctx.getMIRTypeFromWASMType(DestType);
    MInstruction *ValueInst = extractOperand(Value);
    if (Value.getType() > DestType) {
      ValueInst = createInstruction<ConversionInstruction>(false, OP_trunc, MTy,
                                                           ValueInst);
    }

    MInstruction *BaseInst = extractOperand(Base);
    const auto [MemoryBase, MemoryIndex, MemoryOffset] =
        getMemoryLocation(BaseInst, Offset, MTy);

    createInstruction<StoreInstruction>(true, &Ctx.VoidType, ValueInst,
                                        MemoryBase, 1, MemoryIndex,
                                        MemoryOffset);
  }

  Operand handleMemorySize();

  Operand handleMemoryGrow(Operand Opnd);

  // ==================== Numeric Instruction Handlers ====================

  template <WASMType Ty>
  Operand handleConst(typename WASMTypeAttr<Ty>::Type Value) {
    MType &MTy = *Ctx.getMIRTypeFromWASMType(Ty);
    MConstant *Constant = nullptr;
    if constexpr (isWASMTypeInteger<Ty>()) {
      Constant = MConstantInt::get(Ctx, MTy, Value);
    } else {
      Constant = MConstantFloat::get(Ctx, MTy, Value);
    }

    MInstruction *Ret =
        createInstruction<ConstantInstruction>(false, &MTy, *Constant);
    return Operand(Ret, Ty);
  }

  template <WASMType Type, CompareOperator Opeator>
  Operand handleCompareOp(Operand LHSOp, Operand RHSOp) {
    MInstruction *Ret =
        handleCompareImpl<Type, Opeator>(LHSOp, RHSOp, &Ctx.I32Type);
    return Operand(Ret, WASMType::I32);
  }

  template <WASMType Type, CompareOperator Opeator>
  void handleFusedCompareIfa(Operand LHSOp, Operand RHSOp, WASMType VType,
                             uint32_t StackSize) {
    MInstruction *Condition =
        handleCompareImpl<Type, Opeator>(LHSOp, RHSOp, &Ctx.I8Type);
    handleIf(Operand(Condition, WASMType::I8), VType, StackSize);
  }

  template <WASMType Type, CompareOperator Opeator>
  void handleFusedCompareBranchIf(Operand LHSOp, Operand RHSOp, uint32_t Level,
                                  const BlockInfo &Info) {
    MInstruction *Condition =
        handleCompareImpl<Type, Opeator>(LHSOp, RHSOp, &Ctx.I8Type);
    handleBranchIf(Operand(Condition, WASMType::I8), Level, Info);
  }

  template <WASMType Type, CompareOperator Opeator>
  Operand handleFusedCompareSelect(Operand CmpLHSOp, Operand CmpRHSOp,
                                   Operand SelLHSOp, Operand SelRHSOp) {
    MInstruction *Condition =
        handleCompareImpl<Type, Opeator>(CmpLHSOp, CmpRHSOp, &Ctx.I8Type);
    return handleSelect(Operand(Condition, WASMType::I8), SelLHSOp, SelRHSOp);
  }

  template <WASMType Type, UnaryOperator Opeator>
  Operand handleBitCountOp(Operand Opnd) {
    MInstruction *Ret = createInstruction<UnaryInstruction>(
        false, getUnaryOpcode(Opeator), Ctx.getMIRTypeFromWASMType(Type),
        extractOperand(Opnd));
    return Operand(Ret, Type);
  }

  template <WASMType Type, BinaryOperator Opeator>
  Operand handleBinaryOp(Operand LHSOp, Operand RHSOp) {
    MInstruction *LHS = extractOperand(LHSOp);
    MInstruction *RHS = extractOperand(RHSOp);
    MInstruction *Ret = createInstruction<BinaryInstruction>(
        false, getBinOpcode(Opeator), Ctx.getMIRTypeFromWASMType(Type), LHS,
        RHS);
    return Operand(Ret, Type);
  }

  template <WASMType Type, BinaryOperator Opeator>
  Operand handleIDiv(Operand LHSOp, Operand RHSOp) {
    MType *Mtype = Ctx.getMIRTypeFromWASMType(Type);

    MInstruction *LHS = makeReusableValue(extractOperand(LHSOp), Mtype);
    MInstruction *RHS = makeReusableValue(extractOperand(RHSOp), Mtype);

#if !defined(ZEN_BUILD_TARGET_X86_64) or !defined(ZEN_ENABLE_CPU_EXCEPTION)
    MInstruction *DivByZero = createInstruction<CmpInstruction>(
        false, CmpInstruction::ICMP_EQ, &Ctx.I8Type, RHS,
        createIntConstInstruction(Mtype, 0));

    // when in x86-64, /0 will cause SIGFPE cpu trap
    MBasicBlock *IntDivByZeroBB =
        getOrCreateExceptionSetBB(ErrorCode::IntegerDivByZero);
    createInstruction<BrIfInstruction>(true, Ctx, DivByZero, IntDivByZeroBB);
    addUniqueSuccessor(IntDivByZeroBB);
#endif // !ZEN_BUILD_TARGET_X86_64 or !ZEN_ENABLE_CPU_EXCEPTION

    Variable *ResultVar = CurFunc->createVariable(Mtype);
    VariableIdx ResultVarIdx = ResultVar->getVarIdx();
    MBasicBlock *ExitBB = nullptr; // Only used for BO_REM_S

    if constexpr (Opeator == BinaryOperator::BO_DIV_S ||
                  Opeator == BinaryOperator::BO_REM_S) {
      uint64_t IntMin = Mtype->is32Bits() ? INT32_MIN : INT64_MIN;
      MInstruction *LHSIsNotMin = createInstruction<CmpInstruction>(
          false, CmpInstruction::ICMP_NE, &Ctx.I8Type, LHS,
          createIntConstInstruction(Mtype, IntMin));
      MBasicBlock *NormalBB = createBasicBlock();
      createInstruction<BrIfInstruction>(true, Ctx, LHSIsNotMin, NormalBB);
      addSuccessor(NormalBB);

      uint64_t NegOne = Mtype->is32Bits() ? uint32_t(-1) : uint64_t(-1);
      MInstruction *RHSIsNegOne = createInstruction<CmpInstruction>(
          false, CmpInstruction::ICMP_EQ, &Ctx.I8Type, RHS,
          createIntConstInstruction(Mtype, NegOne));
      if constexpr (Opeator == BinaryOperator::BO_DIV_S) {
        MBasicBlock *IntOverflowBB =
            getOrCreateExceptionSetBB(ErrorCode::IntegerOverflow);
        createInstruction<BrIfInstruction>(true, Ctx, RHSIsNegOne,
                                           IntOverflowBB, NormalBB);
        addUniqueSuccessor(IntOverflowBB);
      } else { // BO_REM_S
        MInstruction *Zero = createIntConstInstruction(Mtype, 0);
        createInstruction<DassignInstruction>(true, &(Ctx.VoidType), Zero,
                                              ResultVarIdx);
        ExitBB = createBasicBlock();
        ZEN_ASSERT(ExitBB);
        createInstruction<BrIfInstruction>(true, Ctx, RHSIsNegOne, ExitBB,
                                           NormalBB);
        addSuccessor(ExitBB);
      }
      addUniqueSuccessor(NormalBB);
      setInsertBlock(NormalBB);
    }

    MInstruction *NormalResult = createInstruction<BinaryInstruction>(
        false, getBinOpcode(Opeator), Mtype, LHS, RHS);
    // Prevent `(drop (i32.div xxx xxx))` discarding DivideByZeroException in
    // the sdiv instruction
    createInstruction<DassignInstruction>(true, &(Ctx.VoidType), NormalResult,
                                          ResultVarIdx);
    if (ExitBB) {
      createInstruction<BrInstruction>(true, Ctx, ExitBB);
      setInsertBlock(ExitBB);
    }
    MInstruction *Ret =
        createInstruction<DreadInstruction>(false, Mtype, ResultVarIdx);
    return Operand(Ret, Type);
  }

  template <WASMType Type, BinaryOperator Opeator>
  Operand handleShift(Operand LHSOp, Operand RHSOp) {
    MInstruction *LHS = extractOperand(LHSOp);
    MInstruction *RHS = extractOperand(RHSOp);
    MInstruction *Ret = createInstruction<BinaryInstruction>(
        false, getBinOpcode(Opeator), Ctx.getMIRTypeFromWASMType(Type), LHS,
        RHS);
    return Operand(Ret, Type);
  }

  template <WASMType Type, UnaryOperator Opeator>
  Operand handleUnaryOp(Operand Opnd) {
    MInstruction *Ret = createInstruction<UnaryInstruction>(
        false, getUnaryOpcode(Opeator), Ctx.getMIRTypeFromWASMType(Type),
        extractOperand(Opnd));
    return Operand(Ret, Type);
  }

  template <WASMType Type, BinaryOperator Opeator>
  Operand handleFDiv(Operand LHSOp, Operand RHSOp) {
    MInstruction *LHS = extractOperand(LHSOp);
    MInstruction *RHS = extractOperand(RHSOp);
    auto *Ret = createInstruction<BinaryInstruction>(
        false, getBinOpcode(Opeator), Ctx.getMIRTypeFromWASMType(Type), LHS,
        RHS);
    return Operand(Ret, Type);
  }

  template <WASMType Type, BinaryOperator opr>
  Operand handleFloatMinMax(Operand LHSOp, Operand RHSOp) {
    MInstruction *LHS = extractOperand(LHSOp);
    MInstruction *RHS = extractOperand(RHSOp);
    auto Ret = createInstruction<BinaryInstruction>(
        false, getBinOpcode(opr), Ctx.getMIRTypeFromWASMType(Type), LHS, RHS);
    return Operand(Ret, Type);
  }

  template <WASMType Type>
  Operand handleFloatCopysign(Operand LHSOp, Operand RHSOp) {
    MInstruction *LHS = extractOperand(LHSOp);
    MInstruction *RHS = extractOperand(RHSOp);
    auto Ret = createInstruction<BinaryInstruction>(
        false, OP_fpcopysign, Ctx.getMIRTypeFromWASMType(Type), LHS, RHS);
    return Operand(Ret, Type);
  }

  Operand handleIntTrunc(Operand Opnd) {
    MInstruction *Ret = createInstruction<ConversionInstruction>(
        false, OP_trunc, &Ctx.I32Type, extractOperand(Opnd));
    return Operand(Ret, WASMType::I32);
  }

  template <WASMType DestType, WASMType SrcType, bool Sext>
  Operand handleFloatToInt(Operand Opnd) {
    constexpr Opcode CVTOpc = Sext ? OP_wasm_fptosi : OP_wasm_fptoui;
    MType *DestMType = Ctx.getMIRTypeFromWASMType(DestType);
    MInstruction *OpndInstr = extractOperand(Opnd);
    MInstruction *CVTRet = createInstruction<ConversionInstruction>(
        false, CVTOpc, DestMType, OpndInstr);
    MBasicBlock *NaNBB =
        getOrCreateExceptionSetBB(ErrorCode::InvalidConversionToInteger);
    MBasicBlock *IntOverflowBB =
        getOrCreateExceptionSetBB(ErrorCode::IntegerOverflow);
    addUniqueSuccessor(NaNBB);
    addUniqueSuccessor(IntOverflowBB);
    MInstruction *Ret = makeReusableValue(CVTRet, DestMType);
    return Operand(Ret, DestType);
  }

  template <WASMType DestType, WASMType SrcType, bool Sext>
  Operand handleIntExtend(Operand Opnd) {
    MInstruction *OpndInstr = extractOperand(Opnd);
    if (Opnd.getType() > SrcType) {
      OpndInstr = createInstruction<ConversionInstruction>(
          false, OP_trunc, Ctx.getMIRTypeFromWASMType(SrcType), OpndInstr);
    }
    constexpr Opcode ConverOpcode = Sext ? OP_sext : OP_uext;
    MInstruction *Ret = createInstruction<ConversionInstruction>(
        false, ConverOpcode, Ctx.getMIRTypeFromWASMType(DestType), OpndInstr);
    return Operand(Ret, DestType);
  }

  template <WASMType DestType, WASMType SrcType, bool Sext>
  Operand handleConvert(Operand Opnd) {
    Opcode Opc;
    // F32_DEMOTE_F64
    if constexpr (DestType == WASMType::F32 && SrcType == WASMType::F64) {
      Opc = OP_fptrunc;
    }
    // F64_PROMOTE_F32
    else if constexpr (DestType == WASMType::F64 && SrcType == WASMType::F32) {
      Opc = OP_fpext;
    } else {
      Opc = Sext ? OP_sitofp : OP_uitofp;
    }
    MInstruction *Ret = createInstruction<ConversionInstruction>(
        false, Opc, Ctx.getMIRTypeFromWASMType(DestType), extractOperand(Opnd));
    return Operand(Ret, DestType);
  }

  template <WASMType DestType, WASMType SrcType>
  Operand handleBitcast(Operand Opnd) {
    MInstruction *Ret = createInstruction<ConversionInstruction>(
        false, OP_bitcast, Ctx.getMIRTypeFromWASMType(DestType),
        extractOperand(Opnd));
    return Operand(Ret, DestType);
  }

  // ==================== Platform Feature Methods ====================

  void handleGasCall(Operand Delta);

  template <bool Sign, WASMType Type, BinaryOperator Opr>
  Operand handleCheckedArithmetic(Operand LHSOp, Operand RHSOp) {
    Opcode Opc;
    switch (Opr) {
    case BinaryOperator::BO_ADD:
      Opc = Sign ? OP_wasm_sadd_overflow : OP_wasm_uadd_overflow;
      break;
    case BinaryOperator::BO_SUB:
      Opc = Sign ? OP_wasm_ssub_overflow : OP_wasm_usub_overflow;
      break;
    case BinaryOperator::BO_MUL:
      Opc = Sign ? OP_wasm_smul_overflow : OP_wasm_umul_overflow;
      break;
    default:
      ZEN_UNREACHABLE();
    }

    constexpr bool IsSmallType = Type == WASMType::I8 || Type == WASMType::I16;
    MType *Mtype = Ctx.getMIRTypeFromWASMType(Type);
    MInstruction *LHS = extractOperand(LHSOp);
    MInstruction *RHS = extractOperand(RHSOp);

    if (IsSmallType) {
      LHS =
          createInstruction<ConversionInstruction>(false, OP_trunc, Mtype, LHS);
      RHS =
          createInstruction<ConversionInstruction>(false, OP_trunc, Mtype, RHS);
    }

    MInstruction *Ret =
        createInstruction<BinaryInstruction>(false, Opc, Mtype, LHS, RHS);
    MBasicBlock *IntOverflowBB =
        getOrCreateExceptionSetBB(ErrorCode::IntegerOverflow);
    addUniqueSuccessor(IntOverflowBB);

    if (IsSmallType) {
      return handleIntExtend<WASMType::I32, Type, Sign>(Operand(Ret, Type));
    }
    return Operand(Ret, Type);
  }

  template <bool Sign, BinaryOperator Opr>
  Operand handleCheckedI128Arithmetic(Operand LHSLoOp, Operand LHSHiOp,
                                      Operand RHSLoOp, Operand RHSHiOp) {
    Opcode Opc;
    switch (Opr) {
    case BinaryOperator::BO_ADD:
      Opc = Sign ? OP_wasm_sadd128_overflow : OP_wasm_uadd128_overflow;
      break;
    case BinaryOperator::BO_SUB:
      Opc = Sign ? OP_wasm_ssub128_overflow : OP_wasm_usub128_overflow;
      break;
    default:
      ZEN_UNREACHABLE();
    }

    MInstruction *LHSLo = extractOperand(LHSLoOp);
    MInstruction *LHSHi = extractOperand(LHSHiOp);
    MInstruction *RHSLo = extractOperand(RHSLoOp);
    MInstruction *RHSHi = extractOperand(RHSHiOp);
    MInstruction *Ret = createInstruction<WasmOverflowI128BinaryInstruction>(
        false, &Ctx.I64Type, Opc, LHSLo, LHSHi, RHSLo, RHSHi);

    MBasicBlock *IntOverflowBB =
        getOrCreateExceptionSetBB(ErrorCode::IntegerOverflow);
    addUniqueSuccessor(IntOverflowBB);

    return Operand(Ret, WASMType::I64);
  }

private:
  // ==================== Operand Methods ====================

  MInstruction *extractOperand(const Operand &Opnd);

  Operand createTempStackOperand(WASMType Type) {
    MType *Mtype = Ctx.getMIRTypeFromWASMType(Type);
    Variable *TempVar = CurFunc->createVariable(Mtype);
    ZEN_ASSERT(TempVar->getVarIdx() < CurFunc->getNumVariables());
    return Operand(TempVar, Type);
  }

  // ==================== WASM Instance Util Methods ====================

  void loadWASMInstanceAttr();

  LoadInstruction *getInstanceElement(MType *ValueType, uint32_t Scale,
                                      MInstruction *Index, uint64_t Offset) {
    MPointerType *ValuePtrType = MPointerType::create(Ctx, *ValueType);
    MInstruction *InstancePtr =
        createInstruction<DreadInstruction>(false, ValuePtrType, 0);
    return createInstruction<LoadInstruction>(false, ValueType, InstancePtr,
                                              Scale, Index, Offset);
  }

  LoadInstruction *getInstanceElement(MType *ValueType, uint64_t Offset) {
    return getInstanceElement(ValueType, 1, nullptr, Offset);
  }

  StoreInstruction *setInstanceElement(MType *ValueType, MInstruction *Value,
                                       uint64_t Offset) {
    MPointerType *ValuePtrType = MPointerType::create(Ctx, *ValueType);
    MInstruction *InstancePtr =
        createInstruction<DreadInstruction>(false, ValuePtrType, 0);
    return createInstruction<StoreInstruction>(true, &Ctx.VoidType, Value,
                                               InstancePtr, Offset);
  }

  // ==================== Handler Util Methods ====================

  void enterBlock(CtrlBlockKind Kind, WASMType Type, uint32_t StackSize,
                  MBasicBlock *JumpBlock, MBasicBlock *NextBlock = nullptr,
                  BrIfInstruction *BranchInst = nullptr) {
    auto BlockResult =
        (Type == WASMType::VOID) ? Operand() : createTempStackOperand(Type);
    ControlStack.emplace_back(Kind, BlockResult, StackSize, JumpBlock,
                              NextBlock, BranchInst);
  }

  template <typename CallInst, typename Callee>
  Operand handleCallBase(Callee FuncInstr, const ArgumentInfo &ArgInfo,
                         const std::vector<Operand> &Args,
                         bool IsImportOrIndirect) {
    // ensure the first argument is the instance pointer
    CompileVector<MInstruction *> MIRArgs(Args.size() + 1, Ctx.MemPool);
    MIRArgs[0] =
        createInstruction<DreadInstruction>(false, createVoidPtrType(), 0);
    for (size_t I = 0, E = Args.size(); I < E; ++I) {
      MIRArgs[I + 1] = extractOperand(Args[I]);
    }
    WASMType Wtype = ArgInfo.getReturnType();
    MType *Mtype = Ctx.getMIRTypeFromWASMType(Wtype);
    /// There are only two forms of CallInstructions in MIR
    /// 1. $2 = call %0 ($0, $1) when function %0 returns a value, in which
    /// the CallInstruction is the operand of the DassignInstruction.
    /// 2. call %0 ($0, $1) when function %0 returns void, in which
    /// the CallInstruction is a statement.
    bool IsStmt = Wtype == WASMType::VOID;
    MInstruction *CallResult =
        createInstruction<CallInst>(IsStmt, Mtype, FuncInstr, MIRArgs);

    Variable *ReturnVar = nullptr;
    if (!IsStmt) {
      ReturnVar = CurFunc->createVariable(Mtype);
      createInstruction<DassignInstruction>(true, &(Ctx.VoidType), CallResult,
                                            ReturnVar->getVarIdx());
    }

    checkCallException(IsImportOrIndirect);
    updateMemoryBaseAndSize();

    if (IsStmt) {
      return Operand();
    }

    ZEN_ASSERT(ReturnVar != nullptr);
    MInstruction *ReturnVal = createInstruction<DreadInstruction>(
        false, Mtype, ReturnVar->getVarIdx());
    return Operand(ReturnVal, Wtype);
  }

  void checkCallException(bool IsImportOrIndirect);

  // Assign feature values(from local.get/global.get/load/memory.size) to a
  // temp variable, considering that the corresponding set
  // instruction(local.set/global.set/store/memory.grow) may modify these
  // values on the instance
  MInstruction *protectUnsafeValue(MInstruction *Value, MType *Type) {
    return makeReusableValue(Value, Type);
  }

  // Return {MemoryBase, Index(Scale = 1), Offset}
  std::tuple<MInstruction *, MInstruction *, int32_t>
  getMemoryLocation(MInstruction *Base, uint32_t Offset, MType *Type);

  MInstruction *getMemoryBase();
  MInstruction *getMemorySize();

  // Update memory base and size after growing memory or calling a function
  void updateMemoryBaseAndSize();

  template <WASMType Type, CompareOperator Opeator>
  CmpInstruction *handleCompareImpl(Operand LHSOp,
                                    [[maybe_unused]] Operand RHSOp,
                                    MType *Mtype) {
    ZEN_ASSERT(Mtype == &Ctx.I8Type || Mtype == &Ctx.I32Type);
    MInstruction *LHS = extractOperand(LHSOp);
    MInstruction *RHS = nullptr;
    if constexpr (Opeator == CompareOperator::CO_EQZ) {
      ZEN_ASSERT(LHS && isWASMTypeInteger<Type>());
      RHS = createIntConstInstruction(LHS->getType(), 0);
    } else {
      RHS = extractOperand(RHSOp);
    }
    ZEN_ASSERT(LHS && RHS);
    constexpr auto Predicate = getCmpPredicate<Type, Opeator>();
    return createInstruction<CmpInstruction>(false, Predicate, Mtype, LHS, RHS);
  }

  // ==================== MIR Util Methods ====================

  MPointerType *createVoidPtrType() const {
    return MPointerType::create(Ctx, Ctx.VoidType);
  }

  template <class T, typename... Arguments>
  T *createInstruction(bool IsStmt, Arguments &&...Args) {
    ZEN_ASSERT(CurFunc);
    ZEN_ASSERT(CurBB);
    return CurFunc->createInstruction<T>(IsStmt, *CurBB,
                                         std::forward<Arguments>(Args)...);
  }

  ConstantInstruction *createIntConstInstruction(MType *Type, uint64_t V) {
    return createInstruction<ConstantInstruction>(
        false, Type, *MConstantInt::get(Ctx, *Type, V));
  }

  MInstruction *makeReusableValue(MInstruction *Value, MType *Type) {
    Variable *ReusableVar = CurFunc->createVariable(Type);
    VariableIdx ReusableVarIdx = ReusableVar->getVarIdx();
    createInstruction<DassignInstruction>(true, &(Ctx.VoidType), Value,
                                          ReusableVarIdx);
    return createInstruction<DreadInstruction>(false, Type, ReusableVarIdx);
  }

  MBasicBlock *createBasicBlock() { return CurFunc->createBasicBlock(); }

  void setInsertBlock(MBasicBlock *BB) {
    CurBB = BB;
    CurFunc->appendBlock(BB);
  }

  void addSuccessor(MBasicBlock *Succ) { CurBB->addSuccessor(Succ); }

  void addUniqueSuccessor(MBasicBlock *Succ) {
    auto E = CurBB->successors().end();
    auto It = std::find(CurBB->successors().begin(), E, Succ);
    if (It == E) {
      CurBB->addSuccessor(Succ);
    }
  }

  MBasicBlock *getOrCreateExceptionSetBB(ErrorCode ErrCode) {
    return CurFunc->getOrCreateExceptionSetBB(ErrCode);
  }

  // ==================== MIR Opcode Methods ====================

  static Opcode getBinOpcode(BinaryOperator BinOpr);

  static Opcode getUnaryOpcode(UnaryOperator UnOpr);

  template <WASMType Type, CompareOperator Opeator>
  static constexpr CmpInstruction::Predicate getCmpPredicate() {
    using Predicate = CmpInstruction::Predicate;
    if (isWASMTypeFloat<Type>()) {
      switch (Opeator) {
      case CompareOperator::CO_EQ:
        return Predicate::FCMP_OEQ;
      case CompareOperator::CO_NE:
        return Predicate::FCMP_UNE;
      case CompareOperator::CO_LT:
        return Predicate::FCMP_OLT;
      case CompareOperator::CO_GT:
        return Predicate::FCMP_OGT;
      case CompareOperator::CO_LE:
        return Predicate::FCMP_OLE;
      case CompareOperator::CO_GE:
        return Predicate::FCMP_OGE;
      default:
        ZEN_UNREACHABLE();
      }
    } else {
      switch (Opeator) {
      case CompareOperator::CO_EQZ:
      case CompareOperator::CO_EQ:
        return Predicate::ICMP_EQ;
      case CompareOperator::CO_NE:
        return Predicate::ICMP_NE;
      case CompareOperator::CO_LT_S:
        return Predicate::ICMP_SLT;
      case CompareOperator::CO_LT_U:
        return Predicate::ICMP_ULT;
      case CompareOperator::CO_GT_S:
        return Predicate::ICMP_SGT;
      case CompareOperator::CO_GT_U:
        return Predicate::ICMP_UGT;
      case CompareOperator::CO_LE_S:
        return Predicate::ICMP_SLE;
      case CompareOperator::CO_LE_U:
        return Predicate::ICMP_ULE;
      case CompareOperator::CO_GE_S:
        return Predicate::ICMP_SGE;
      case CompareOperator::CO_GE_U:
        return Predicate::ICMP_UGE;
      default:
        ZEN_UNREACHABLE();
      }
    }
  }

  CompilerContext &Ctx;
  CompileVector<BlockInfo> ControlStack; // manage nested block
  MFunction *CurFunc = nullptr;
  MBasicBlock *CurBB = nullptr;

  MInstruction *InstanceAddr = nullptr;
  // exit wasm func when has exception
  MBasicBlock *ExceptionReturnBB = nullptr;
  bool UseExceptionReturnAfterCall = false;

  VariableIdx MemoryBaseIdx = (VariableIdx)-1;
  VariableIdx MemorySizeIdx = (VariableIdx)-1;
};

} // namespace COMPILER

#endif // WASM_FRONTEND_WASM_MIR_COMPILER_H
