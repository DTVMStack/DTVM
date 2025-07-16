// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_SINGLEPASS_A64_CODEGEN_H
#define ZEN_SINGLEPASS_A64_CODEGEN_H

// ============================================================================
// a64/codegen.h
//
// code generator for a64 one pass jit compiler
//
// ============================================================================

#include "common/operators.h"
#include "singlepass/a64/asm/assembler.h"
#include "singlepass/a64/asm/register.h"
#include "singlepass/a64/assembler.h"
#include "singlepass/a64/codepatch.h"
#include "singlepass/a64/datalayout.h"
#include "singlepass/a64/machine.h"
#include "singlepass/a64/operand.h"
#include "singlepass/common/codegen.h"
#include "singlepass/common/definitions.h"
#include "singlepass/common/valtype.h"

namespace zen::singlepass {

// ============================================================================
// A64ArgumentInfo
// manage argument for function call
// ============================================================================

class A64ArgumentInfoAttrs {
public:
  typedef A64::Type DataType;
  typedef A64::RegNum RegNum;
  typedef A64OnePassABI OnePassABI;
  typedef AArch64ABI ArchABI;

  template <A64::Type type> using TypeAttr = A64TypeAttr<type>;
};

class A64ArgumentInfo
    : public ArgumentInfo<A64ArgumentInfo, A64ArgumentInfoAttrs> {
public:
  A64ArgumentInfo(TypeEntry *Type) : ArgumentInfo(Type) {}

  static constexpr A64::Type getDataTypeFromWASMType(WASMType Type) {
    return getA64TypeFromWASMType(Type);
  }
};

// make a short rep for real assembler
#define _ ASM.Assembler().

class A64OnePassCodeGenAttrs {
public:
  typedef A64ArgumentInfo ArgumentInfo;
  typedef A64InstOperand Operand;
  typedef A64MachineState VMState;
  typedef A64Assembler Assembler;
  typedef A64OnePassDataLayout OnePassDataLayout;
  typedef A64CodePatcher CodePatcher;
  typedef A64OnePassABI OnePassABI;
  typedef AArch64ABI ArchABI;
  typedef A64::RegNum RegNum;
  typedef A64::GP GP;
  typedef A64::FP FP;
  typedef A64::Type DataType;
  typedef asmjit::a64::Mem Mem;
  typedef A64Reg RegClass;

  template <A64::Type type> using TypeAttr = A64TypeAttr<type>;

  static constexpr DataType I32 = A64::I32;
  static constexpr DataType F32 = A64::F32;
  static constexpr DataType I64 = A64::I64;
  static constexpr DataType F64 = A64::F64;
  static constexpr DataType V128 = A64::V128;
};

// ============================================================================
// A64OnePassCodeGenImpl
// code generator implementation for a64 onepass JIT compiler
// ============================================================================
class A64OnePassCodeGenImpl
    : public OnePassCodeGen<A64OnePassCodeGenImpl, A64OnePassCodeGenAttrs> {
public:
  friend OnePassCodeGen;

  typedef A64ArgumentInfo ArgumentInfo;
  typedef A64InstOperand Operand;
  typedef A64MachineState VMState;
  typedef A64Assembler Assembler;

public:
  // constructor
  A64OnePassCodeGenImpl(A64OnePassDataLayout &Layout, A64CodePatcher &Patcher,
                        asmjit::CodeHolder *Code, JITCompilerContext *Ctx)
      : OnePassCodeGen(Code, Layout, Patcher, Ctx) {}

  void addStackPointer(uint32_t StackSize) {
    if (!isArithImmValid(StackSize)) {
      auto StackSizeReg = ABI.getScratchReg();
      _ mov(StackSizeReg, StackSize);
      _ add(ABI.getStackPointerReg(), ABI.getStackPointerReg(), StackSizeReg);
    } else if (ZEN_LIKELY(StackSize > 0)) {
      // The immediate value in the add/sub instruction is 12-bit
      _ add(ABI.getStackPointerReg(), ABI.getStackPointerReg(), StackSize);
    }
  }

  void subStackPointer(uint32_t StackSize) {
    if (!isArithImmValid(StackSize)) {
      auto StackSizeReg = ABI.getScratchReg();
      _ mov(StackSizeReg, StackSize);
      _ sub(ABI.getStackPointerReg(), ABI.getStackPointerReg(), StackSizeReg);
    } else if (ZEN_LIKELY(StackSize > 0)) {
      // The immediate value in the add/sub instruction is 12-bit
      _ sub(ABI.getStackPointerReg(), ABI.getStackPointerReg(), StackSize);
    }
  }

private:
  //
  // prolog and epilog
  //

  // prolog
  void emitProlog(JITCompilerContext *Ctx) {
    // setup stack
    _ stp(ABI.getFrameBaseReg(), ABI.getLinkAddressReg(),
          asmjit::a64::ptr_pre(ABI.getStackPointerReg(), -16));

    // save stack pointer to frame base
    _ mov(ABI.getFrameBaseReg(), ABI.getStackPointerReg());

    // allocate stack frame
    CurFuncState.FrameSizePatchOffset = _ offset();
    auto FrameSize = ABI.getCallTargetReg();
    _ mov(FrameSize, 0); // to be patched later
    _ nop();             // in case frame size exceeds 64KB
    _ sub(ABI.getStackPointerReg(), ABI.getStackPointerReg(), FrameSize);

#ifdef ZEN_ENABLE_DWASM
    auto NotOverflow = createLabel();
    // update stack cost
    auto StackCostAddr = asmjit::a64::ptr(
        ABI.getModuleInstReg(), Ctx->Mod->getLayout().StackCostOffset);
    auto StackCostReg = Layout.getScopedTempReg<A64::I32, ScopedTempReg0>();
    _ ldr(StackCostReg, StackCostAddr);
    uint32_t StackCost = Ctx->Func->JITStackCost;
    if (!isArithImmValid(StackCost)) {
      auto CurFuncStackCostReg =
          A64Reg::getRegRef<A64::I32>(ABI.getScratchRegNum());
      _ mov(CurFuncStackCostReg, StackCost);
      _ add(StackCostReg, StackCostReg, CurFuncStackCostReg);
    } else if (ZEN_LIKELY(StackCost > 0)) {
      _ add(StackCostReg, StackCostReg, StackCost);
    }
    _ str(StackCostReg, StackCostAddr);
    _ cmp(StackCostReg, common::PresetReservedStackSize);
    _ b_ls(asmjit::Label(NotOverflow));

    emitRuntimeError(ErrorCode::CallStackExhausted);
    bindLabel(NotOverflow);
#elif defined(ZEN_ENABLE_STACK_CHECK_CPU)
    // visit sp-StackGuardSize to check stack overflow before has not stack to
    // call sig handler StackGuardSize is guard space for sig handler
    auto StackVisitGuardReg =
        Layout.getScopedTempReg<A64::I64, ScopedTempReg0>();
    // StackGuardSize > ldr imm limit, so use two instructions
    _ sub(StackVisitGuardReg, ABI.getStackPointerReg(), common::StackGuardSize);
    _ ldr(StackVisitGuardReg, asmjit::a64::ptr(StackVisitGuardReg, 0));
#else
    auto NotOverflow = createLabel();
    auto StackBoundAddr =
        asmjit::a64::ptr(ABI.getModuleInstReg(), StackBoundaryOffset);
    auto StackBound = ABI.getScratchReg();
    _ ldr(StackBound, StackBoundAddr);
    _ cmp(ABI.getStackPointerReg(), StackBound);
    _ b_hi(asmjit::Label(NotOverflow));

    emitRuntimeError(ErrorCode::CallStackExhausted);
    bindLabel(NotOverflow);
#endif

    // save preserved registers
    uint32_t PresSaveSize = 0;
    uint32_t IntPresMask = 0;
    for (uint32_t I = 0; I < Layout.getIntPresSavedCount(); ++I) {
      const A64::GP Reg = ABI.getPresRegNum<A64::I64>(I);
      _ str(A64Reg::getRegRef<A64::I64>(Reg),
            asmjit::a64::ptr(ABI.getFrameBaseReg(), -(I + 1) * ABI.GpRegWidth));
      PresSaveSize += ABI.GpRegWidth;
      IntPresMask |= (1 << Reg);
    }
    Layout.markAvailRegMask<A64::I64>(IntPresMask);
    ZEN_ASSERT(PresSaveSize == Layout.getIntPresSavedCount() * ABI.GpRegWidth);

    // initialize all locals to zero
    for (uint32_t I = 0; I < Ctx->Func->NumLocals; ++I) {
      auto Local = Layout.getLocal(I + Ctx->FuncType->NumParams);
      ZEN_ASSERT(Local.isMem());
      if (Local.getType() == WASMType::I32 ||
          Local.getType() == WASMType::F32) {
        storeRegToMem<A64::I32>(GP::XZR, Local.getMem<A64::I32>());
      } else {
        storeRegToMem<A64::I64>(GP::XZR, Local.getMem<A64::I64>());
      }
    }

    // TODO: maybe we could move this to `invokeNative`
    loadGasVal();
  } // EmitProlog

  // epilog
  void emitEpilog(Operand Op) {
    saveGasVal();

#ifdef ZEN_ENABLE_DWASM
    // update stack cost
    auto StackCostAddr = asmjit::a64::ptr(
        ABI.getModuleInstReg(), Ctx->Mod->getLayout().StackCostOffset);
    auto StackCostReg = Layout.getScopedTempReg<A64::I32, ScopedTempReg0>();
    _ ldr(StackCostReg, StackCostAddr);
    uint32_t StackCost = Ctx->Func->JITStackCost;
    if (!isArithImmValid(StackCost)) {
      auto CurFuncStackCostReg =
          A64Reg::getRegRef<A64::I32>(ABI.getScratchRegNum());
      _ mov(CurFuncStackCostReg, StackCost);
      _ sub(StackCostReg, StackCostReg, CurFuncStackCostReg);
    } else if (ZEN_LIKELY(StackCost > 0)) {
      _ sub(StackCostReg, StackCostReg, Ctx->Func->JITStackCost);
    }
    _ str(StackCostReg, StackCostAddr);
#endif

    if (Layout.getNumReturns() > 0) {
      ZEN_ASSERT(Layout.getNumReturns() == 1);
      ZEN_ASSERT(Layout.getReturnType(0) == Op.getType());
      switch (Op.getType()) {
      case WASMType::I32:
        mov<A64::I32>(ABI.getRetRegNum<A64::I32>(), Op);
        break;
      case WASMType::I64:
        mov<A64::I64>(ABI.getRetRegNum<A64::I64>(), Op);
        break;
      case WASMType::F32:
        mov<A64::F32>(ABI.getRetRegNum<A64::F32>(), Op);
        break;
      case WASMType::F64:
        mov<A64::F64>(ABI.getRetRegNum<A64::F64>(), Op);
        break;
      default:
        ZEN_ABORT();
      }
    }

    // restore preserved registers
    for (uint32_t I = 0; I < Layout.getIntPresSavedCount(); ++I) {
      const A64::GP Reg = ABI.getPresRegNum<A64::I64>(I);
      _ ldr(A64Reg::getRegRef<A64::I64>(Reg),
            asmjit::a64::ptr(ABI.getFrameBaseReg(), -(I + 1) * ABI.GpRegWidth));
    }
    // restore stack pointer from frame base
    _ mov(ABI.getStackPointerReg(), ABI.getFrameBaseReg());
    // restore stack
    _ ldp(ABI.getFrameBaseReg(), ABI.getLinkAddressReg(),
          asmjit::a64::ptr_post(ABI.getStackPointerReg(), 16));
    _ ret(ABI.getLinkAddressReg());
  } // EmitEpilog

  template <uint32_t AddrRegIndex, uint32_t SizeRegIndex, uint32_t CmpRegIndex>
  void emitGetTableAddress(uint32_t TblIdx, Operand EntryIdx) {
    ZEN_ASSERT(EntryIdx.getType() == WASMType::I32);
    // load table address into ScopedTempReg1
    asmjit::a64::Mem TableAddr(ABI.getModuleInstReg(),
                               TablesOffset + sizeof(TableInstance) * TblIdx);
    auto AddrReg = Layout.getScopedTempReg<A64::I64, AddrRegIndex>();
    _ ldr(AddrReg, TableAddr);
    // load table size into ScopedTempReg0 for oob check
    auto SizeReg = Layout.getScopedTempReg<A64::I32, SizeRegIndex>();
    ZEN_STATIC_ASSERT(sizeof(TableInstance::CurSize) == sizeof(uint32_t));
    asmjit::a64::Mem SizeAddr(AddrReg, TableSizeOffset);
    _ ldr(SizeReg, SizeAddr);
    // compare entry_idx with sizeReg

    bool Exchanged;
    cmp<A64::I32, CmpRegIndex, CmpRegIndex>(
        Operand(WASMType::I32, Layout.getScopedTemp<A64::I32, SizeRegIndex>(),
                Operand::FLAG_NONE),
        EntryIdx, Exchanged);
    uint32_t ChkOk = createLabel();
    jmpcc<CompareOperator::CO_GT_U, true>(ChkOk);
    emitRuntimeError(ErrorCode::UndefinedElement);
    bindLabel(ChkOk);
  }

  void emitTableGet(uint32_t TblIdx, Operand Elem, A64::GP ResRegNum) {
    // place table[TblIdx] to ScopedTempReg1
    emitGetTableAddress<ScopedTempReg1, ScopedTempReg0, ScopedTempReg2>(TblIdx,
                                                                        Elem);
    auto AddrReg = Layout.getScopedTempReg<A64::I64, ScopedTempReg1>();
    // reuse addrReg(ScopedTempReg1) to load element start addr
    _ ldr(AddrReg, asmjit::a64::ptr(AddrReg, TableBaseOffset));
    auto ResReg = A64Reg::getRegRef<A64::I32>(ResRegNum);
    constexpr uint32_t Shift = 2;
    // load table[TblIdx].functions[Elem] into register
    if (Elem.isReg()) {
      _ ldr(ResReg, asmjit::a64::ptr(AddrReg, Elem.getRegRef<A64::I32>(),
                                     asmjit::a64::lsl(Shift)));
    } else if (Elem.isMem()) {
      // Elem  is on stack, load it and save to ScopedTempReg0
      auto ElemRegNum = Layout.getScopedTemp<A64::I32, ScopedTempReg0>();
      auto ElemReg = A64Reg::getRegRef<A64::I32>(ElemRegNum);
      loadRegFromMem<A64::I32>(ElemRegNum, Elem.getMem<A64::I32>());
      _ ldr(ResReg,
            asmjit::a64::ptr(AddrReg, ElemReg, asmjit::a64::lsl(Shift)));
    } else if (Elem.isImm()) {
      auto Offset = Elem.getImm() * sizeof(uint32_t);
      loadRegFromMem<A64::I32>(ResRegNum, asmjit::a64::ptr(AddrReg, Offset));
    }
  }

  void emitRuntimeError(ErrorCode Id) { _ b(getExceptLabel(Id)); };

public:
  //
  // initialization and finalization
  //

  // finalization after compiling a function
  void finalizeFunction() {
    // patch up frame size in prolog
    ZEN_ASSERT(CurFuncState.FrameSizePatchOffset >= 0);
    auto CurrOffset = _ offset();
    _ setOffset(CurFuncState.FrameSizePatchOffset);
    _ mov(ABI.getCallTargetReg(), Layout.getStackBudget());
    _ setOffset(CurrOffset);
  }

public:
  //
  // templated method to handle operations
  //

  // in alphabetical order
  // binary operator
  template <WASMType Type, BinaryOperator Opr>
  Operand handleBinaryOpImpl(Operand LHS, Operand RHS) {
    constexpr A64::Type A64Type = getA64TypeFromWASMType<Type>();
    typedef typename A64TypeAttr<A64Type>::RegNum RegNum;
    RegNum LHSRegNum;
    RegNum RHSRegNum;
    RegNum ResRegNum = Layout.getScopedTemp<A64Type, ScopedTempReg1>();

    // check lhs is reg and try reuse lhs for result
    if (!LHS.isReg()) {
      LHSRegNum = Layout.getScopedTemp<A64Type, ScopedTempReg1>();
      mov<A64Type>((A64::RegNum)LHSRegNum, LHS);
    } else {
      ZEN_ASSERT(LHS.isTempReg());
      ResRegNum = LHSRegNum = (RegNum)LHS.getReg();
    }

    // check RHS is reg and try reuse RHS for result if lhs isn't reg
    if (!RHS.isReg()) {
      RHSRegNum = Layout.getScopedTemp<A64Type, ScopedTempReg2>();
      mov<A64Type>((A64::RegNum)RHSRegNum, RHS);
    } else {
      ZEN_ASSERT(RHS.isTempReg());
      RHSRegNum = (RegNum)RHS.getReg();
      if (ResRegNum == Layout.getScopedTemp<A64Type, ScopedTempReg1>()) {
        ResRegNum = RHSRegNum;
      }
    }

    BinaryOperatorImpl<A64Type, Opr>::emit(
        ASM, A64Reg::getRegRef<A64Type>(ResRegNum),
        A64Reg::getRegRef<A64Type>(LHSRegNum),
        A64Reg::getRegRef<A64Type>(RHSRegNum));

    if (ResRegNum != Layout.getScopedTemp<A64Type, ScopedTempReg1>()) {
      Layout.clearAvailReg<A64Type>(ResRegNum);
      return Operand(Type, ResRegNum, Operand::FLAG_TEMP_REG);
    }

    Operand Ret = getTempOperand(Type);
    mov<A64Type>(Ret, ResRegNum);
    return Ret;
  }

  // TODO: avoid redundant mov
  template <WASMType Type, UnaryOperator Opr>
  Operand handleBitCountOpImpl(Operand Op) {
    constexpr auto A64Type = getA64TypeFromWASMType<Type>();

    auto Ret = getTempOperand(Type);
    A64::RegNum RegNum =
        Ret.isReg()
            ? (A64::RegNum)Ret.getReg()
            : (A64::RegNum)Layout.getScopedTemp<A64Type, ScopedTempReg0>();

    if (Opr == UnaryOperator::UO_POPCNT) {
      auto IRegRef = A64Reg::getRegRef<A64Type>(RegNum);
      constexpr A64::Type FType = getIntTypeFromFloatType<A64Type>();
      A64::RegNum VReg = Layout.getScopedTemp<FType, ScopedTempReg1>();
      auto VRegRef = A64Reg::getRegRef<FType>(VReg);
      _ fmov(VRegRef, IRegRef);
      _ cnt(VRegRef.v(), VRegRef.v());
      _ uaddlv(VRegRef.h(), VRegRef.b8());
      _ fmov(IRegRef, VRegRef);
    } else {
      mov<A64Type>(RegNum, Op);
      auto Reg = A64Reg::getRegRef<A64Type>(RegNum);
      UnaryOperatorImpl<A64Type, Opr>::emit(ASM, Reg, Reg);
    }

    if (!Ret.isReg()) {
      mov<A64Type>(Ret, RegNum);
    }
    return Ret;
  }

  // compare operator
  template <WASMType Type, CompareOperator Opr>
  Operand handleCompareOpImpl(Operand LHS, Operand RHS) {
    constexpr A64::Type A64Type = getA64TypeFromWASMType<Type>();
    ZEN_ASSERT(LHS.getType() == Type);

    // make comparison
    bool Exchanged = false;
    if (Opr == CompareOperator::CO_EQZ) {
      ZEN_ASSERT(RHS.getType() == WASMType::VOID);
      ZEN_ASSERT(RHS.getKind() == OK_None);
      RHS = Operand(Type, A64::XZR, Operand::FLAG_NONE);
    }

    cmp<A64Type, ScopedTempReg0, ScopedTempReg1>(LHS, RHS, Exchanged);

    A64::RegNum RegNum;
    Operand Ret = getTempOperand(WASMType::I32);
    if (Ret.isReg()) {
      RegNum = Ret.getReg();
    } else {
      RegNum = Layout.getScopedTemp<A64::I32, ScopedTempReg2>();
    }

    // setcc to resulta
    if (!Exchanged) {
      setcc<A64::I32, Opr, true>(RegNum);
    } else {
      constexpr CompareOperator ExchangedOpr =
          getExchangedCompareOperator<Opr>();
      setcc<A64::I32, ExchangedOpr, true>(RegNum);
    }

    // handle NaN operands
    if (getWASMTypeKind(Type) == WASMTypeKind::FLOAT) {
      auto NotNaN = createLabel();
      _ b_vc(asmjit::Label(NotNaN));
      mov<A64::I32>(RegNum, Operand(WASMType::I32,
                                    Opr == CompareOperator::CO_NE ? 1 : 0));
      bindLabel(NotNaN);
    }

    if (!Ret.isReg()) {
      mov<A64::I32>(Ret, RegNum);
    }

    return Ret;
  }

  // constant
  template <WASMType Ty>
  Operand handleConstImpl(typename WASMTypeAttr<Ty>::Type Val) {
    // 32 bit
    if (Ty == WASMType::I32) {
      return Operand(Ty, Val);
    }

    constexpr A64::Type A64Type = getA64TypeFromWASMType<Ty>();
    Operand Ret = getTempOperand(Ty);
    if (Ty == WASMType::I64) {
      movImm<A64Type, ScopedTempReg0>(Ret, (int64_t)Val);
      return Ret;
    }

    constexpr A64::Type IntType = (Ty == WASMType::F32) ? A64::I32 : A64::I64;

    A64::RegNum Reg = Layout.getScopedTemp<IntType, ScopedTempReg0>();
    movImm<IntType>(Reg, utils::bitCast<int64_t>(Val));
    if (Ty == WASMType::F32) {
      fmovFromGp<A64::F32, IntType, ScopedTempReg1>(Ret, Reg);
    } else {
      fmovFromGp<A64::F64, IntType, ScopedTempReg1>(Ret, Reg);
    }

    return Ret;
  }

  // convert from SrcType to DestType (between integer and float-point)
  template <WASMType DestType, WASMType SrcType, bool Sext>
  Operand handleConvertImpl(Operand Op) {
    constexpr auto A64SrcType = getA64TypeFromWASMType<SrcType>();
    constexpr auto A64DestType = getA64TypeFromWASMType<DestType>();

    auto SrcReg = toReg<A64SrcType, ScopedTempReg0>(Op);
    auto DstReg = Layout.getScopedTemp<A64DestType, ScopedTempReg0>();
    ConvertOpImpl<A64DestType, A64SrcType, Sext>::emit(
        ASM, A64Reg::getRegRef<A64DestType>(DstReg),
        A64Reg::getRegRef<A64SrcType>(SrcReg));

    auto Ret = getTempOperand(DestType);
    mov<A64DestType>(Ret, DstReg);
    return Ret;
  }

  // float div
  template <WASMType Type, BinaryOperator Opr>
  Operand handleFDivOpImpl(Operand LHS, Operand RHS) {
    return handleBinaryOpImpl<Type, Opr>(LHS, RHS);
  }

  template <WASMType Type>
  Operand handleFloatCopysignImpl(Operand LHS, Operand RHS) {
    constexpr auto A64Type = getA64TypeFromWASMType<Type>();
    auto LHSReg = toReg<A64Type, ScopedTempReg0>(LHS);
    auto RHSReg = toReg<A64Type, ScopedTempReg1>(RHS);

    auto Shift = getWASMTypeSize(Type) * CHAR_BIT - 1;
    // XXX: somehow f32 and f64 need different operand notations
    if (Type == WASMType::F32) {
      auto LHSRegRef = A64Reg::getRegRef<A64::V128>(LHSReg).s2();
      auto RHSRegRef = A64Reg::getRegRef<A64::V128>(RHSReg).s2();
      _ ushr(RHSRegRef, RHSRegRef, Shift);
      _ sli(LHSRegRef, RHSRegRef, Shift);
    } else {
      auto LHSRegRef = A64Reg::getRegRef<A64Type>(LHSReg);
      auto RHSRegRef = A64Reg::getRegRef<A64Type>(RHSReg);
      _ ushr(RHSRegRef, RHSRegRef, Shift);
      _ sli(LHSRegRef, RHSRegRef, Shift);
    }

    auto Ret = getTempOperand(Type);
    mov<A64Type>(Ret, LHSReg);
    return Ret;
  }

  template <WASMType Type, BinaryOperator Opr>
  Operand handleFloatMinMaxImpl(Operand LHS, Operand RHS) {
    return handleBinaryOpImpl<Type, Opr>(LHS, RHS);
  }

  // integer div
  template <WASMType Type, BinaryOperator Opr>
  Operand handleIDivOpImpl(Operand LHS, Operand RHS) {
    ZEN_ASSERT(LHS.getType() == Type);
    ZEN_ASSERT(RHS.getType() == Type);
    ZEN_ASSERT(Type == WASMType::I32 || Type == WASMType::I64);

    constexpr A64::Type A64Type = getA64TypeFromWASMType<Type>();

    constexpr bool IsUnsigned =
        (Opr == BinaryOperator::BO_DIV_U || Opr == BinaryOperator::BO_REM_U);
    constexpr bool IsRem =
        (Opr == BinaryOperator::BO_REM_U || Opr == BinaryOperator::BO_REM_S);

    uint32_t NormalPathLabel = 0;
    uint32_t EndLabel = 0;

    bool Exchanged = false;

    Operand Ret;
    if (IsRem) {
      Ret = getTempOperand(Type);
    }

    // rem_s
    if (!IsUnsigned) {
      NormalPathLabel = createLabel();
      EndLabel = createLabel();

      Operand CmpOpnd;
      if (A64Type == A64::I32) {
        CmpOpnd = Operand(Type, 0x80000000U);
      } else {
        auto RegNum = Layout.getScopedTemp<A64Type, ScopedTempReg0>();
        movImm<A64::I64>(RegNum, 0x8000000000000000ULL);
        CmpOpnd = Operand(Type, RegNum, Operand::FLAG_NONE);
      }

      cmp<A64Type, ScopedTempReg1, ScopedTempReg2>(LHS, CmpOpnd, Exchanged);
      jne(NormalPathLabel);

      if (A64Type == A64::I32) {
        CmpOpnd = Operand(Type, 0xffffffffU);
      } else {
        auto RegNum = Layout.getScopedTemp<A64Type, ScopedTempReg0>();
        movImm<A64::I64>(RegNum, 0xffffffffffffffffULL);
        CmpOpnd = Operand(Type, RegNum, Operand::FLAG_NONE);
      }

      cmp<A64Type, ScopedTempReg1, ScopedTempReg2>(RHS, CmpOpnd, Exchanged);
      jne(NormalPathLabel);

      if (IsRem) {
        mov<A64Type, ScopedTempReg0>(Ret, Operand(Type, 0));
        branch(EndLabel);
      } else {
        emitRuntimeError(ErrorCode::IntegerOverflow);
      }

      bindLabel(NormalPathLabel);
    }

    NormalPathLabel = createLabel();
    // SIGFPE not always work on aarch64
    cmp<A64Type, ScopedTempReg1, ScopedTempReg2>(RHS, Operand(Type, 0),
                                                 Exchanged);
    jne(NormalPathLabel);
    emitRuntimeError(ErrorCode::IntegerDivByZero);
    bindLabel(NormalPathLabel);

    if (!IsRem) {
      return handleBinaryOpImpl<Type, Opr>(LHS, RHS);
    }

    // rem
    A64::RegNum LHSRegNum = toReg<A64Type, ScopedTempReg0>(LHS);
    A64::RegNum RHSRegNum = toReg<A64Type, ScopedTempReg1>(RHS);
    A64::RegNum ResRegNum = Layout.getScopedTemp<A64Type, ScopedTempReg2>();

    if (Opr == BinaryOperator::BO_REM_S) {
      BinaryOperatorImpl<A64Type, BinaryOperator::BO_DIV_S>::emit(
          ASM, A64Reg::getRegRef<A64Type>(ResRegNum),
          A64Reg::getRegRef<A64Type>(LHSRegNum),
          A64Reg::getRegRef<A64Type>(RHSRegNum));
    } else {
      BinaryOperatorImpl<A64Type, BinaryOperator::BO_DIV_U>::emit(
          ASM, A64Reg::getRegRef<A64Type>(ResRegNum),
          A64Reg::getRegRef<A64Type>(LHSRegNum),
          A64Reg::getRegRef<A64Type>(RHSRegNum));
    }

    _ msub(A64Reg::getRegRef<A64Type>(ResRegNum),
           A64Reg::getRegRef<A64Type>(ResRegNum),
           A64Reg::getRegRef<A64Type>(RHSRegNum),
           A64Reg::getRegRef<A64Type>(LHSRegNum));

    mov<A64Type>(Ret, ResRegNum);

    // rem_s
    if (!IsUnsigned) {
      bindLabel(EndLabel);
    }

    return Ret;
  }

  template <WASMType DestType, WASMType SrcType, bool Sext>
  Operand handleFloatToIntImpl(Operand Op) {
    constexpr auto A64DstType = getA64TypeFromWASMType<DestType>();
    constexpr auto A64SrcType = getA64TypeFromWASMType<SrcType>();

    auto SrcRegNum = toReg<A64SrcType, ScopedTempReg0>(Op);
    auto SrcReg = A64Reg::getRegRef<A64SrcType>(SrcRegNum);

    // check NaN
    auto NotNaN = createLabel();
    _ fcmp(SrcReg, SrcReg);
    _ b_vc(asmjit::Label(NotNaN));
    emitRuntimeError(ErrorCode::InvalidConversionToInteger);
    bindLabel(NotNaN);

    constexpr auto IntSType =
        getA64TypeFromWASMType<FloatAttr<SrcType>::IntType>();
    auto TmpIReg = Layout.getScopedTempReg<IntSType, ScopedTempReg0>();
    auto TmpFReg = Layout.getScopedTempReg<A64SrcType, ScopedTempReg1>();

    // check underflow
    auto NotUnderflow = createLabel();
    auto IntMin = Sext ? FloatAttr<SrcType>::template int_min<DestType>()
                       : FloatAttr<SrcType>::template uint_min<DestType>();
    _ mov(TmpIReg, IntMin);
    _ fmov(TmpFReg, TmpIReg);
    _ fcmp(SrcReg, TmpFReg);
    _ b_gt(asmjit::Label(NotUnderflow));
    emitRuntimeError(ErrorCode::IntegerOverflow);
    bindLabel(NotUnderflow);

    // check overflow
    auto NotOverflow = createLabel();
    auto IntMax = Sext ? FloatAttr<SrcType>::template int_max<DestType>()
                       : FloatAttr<SrcType>::template uint_max<DestType>();
    _ mov(TmpIReg, IntMax);
    _ fmov(TmpFReg, TmpIReg);
    _ fcmp(SrcReg, TmpFReg);
    _ b_mi(asmjit::Label(NotOverflow));
    emitRuntimeError(ErrorCode::IntegerOverflow);
    bindLabel(NotOverflow);

    auto DstRegNum = Layout.getScopedTemp<A64DstType, ScopedTempReg1>();
    auto DstReg = A64Reg::getRegRef<A64DstType>(DstRegNum);
    ConvertOpImpl<A64DstType, A64SrcType, Sext>::emit(ASM, DstReg, SrcReg);

    auto Ret = getTempOperand(DestType);
    mov<A64DstType>(Ret, DstRegNum);
    return Ret;
  }

  // extend from SrcType to DestType in same type kind (integer or
  // floating-point)
  template <WASMType DestType, WASMType SrcType, bool Sext>
  Operand handleIntExtendImpl(Operand Op) {
    constexpr auto A64DestType = getA64TypeFromWASMType<DestType>();
    constexpr auto A64SrcType = getA64TypeFromWASMType<SrcType>();
    A64::RegNum DestRegNum =
        Layout.getScopedTemp<A64DestType, ScopedTempReg0>();
    A64::RegNum SrcRegNum;
    if (Op.isReg()) {
      SrcRegNum = Op.getReg();
    } else {
      SrcRegNum = Layout.getScopedTemp<A64DestType, ScopedTempReg0>();
      mov<A64DestType>(SrcRegNum, Op);
    }

    ConvertOpImpl<A64DestType, A64SrcType, Sext>::emit(
        ASM, A64Reg::getRegRef<A64DestType>(DestRegNum),
        A64Reg::getRegRef<A64SrcType>(SrcRegNum));

    auto Ret = getTempOperand(DestType);
    mov<A64DestType>(Ret, DestRegNum);
    return Ret;
  }

  // fused compare and branch
  template <WASMType Type, CompareOperator Opr, bool TrueBr>
  void handleFusedCompareBranchImpl(Operand CmpLHS, Operand CmpRHS,
                                    uint32_t LabelIdx) {
    constexpr A64::Type A64CType = getA64TypeFromWASMType<Type>();
    ZEN_ASSERT(CmpLHS.getType() == Type);

    // make comparison
    bool Exchanged = false;
    if (Opr == CompareOperator::CO_EQZ) {
      CmpRHS = Operand(Type, A64::XZR, Operand::FLAG_NONE);
    }

    cmp<A64CType, ScopedTempReg1, ScopedTempReg2>(CmpLHS, CmpRHS, Exchanged);

    auto Fallthrough = createLabel();
    if (!Exchanged) {
      jmpcc<Opr, !TrueBr>(Fallthrough);
    } else {
      constexpr CompareOperator ExchangedOpr =
          getExchangedCompareOperator<Opr>();
      jmpcc<ExchangedOpr, !TrueBr>(Fallthrough);
    }
    branch(LabelIdx);
    bindLabel(Fallthrough);
  }

  // fused compare and select
  template <WASMType Type, CompareOperator Opr>
  Operand handleFusedCompareSelectImpl(Operand CmpLHS, Operand CmpRHS,
                                       Operand LHS, Operand RHS) {
    constexpr auto A64CType = getA64TypeFromWASMType<Type>();
    ZEN_ASSERT(CmpLHS.getType() == Type);

    if (Opr == CompareOperator::CO_EQZ) {
      ZEN_ASSERT(CmpRHS.getType() == WASMType::VOID);
      ZEN_ASSERT(CmpRHS.getKind() == OK_None);
      CmpRHS = Operand(Type, A64::XZR, Operand::FLAG_NONE);
    }

    bool Xchg = false;
    cmp<A64CType, ScopedTempReg0, ScopedTempReg1>(CmpLHS, CmpRHS, Xchg);

    ZEN_ASSERT(LHS.getType() == RHS.getType());
    switch (LHS.getType()) {
    case WASMType::I32:
      return fusedCompareSelectWithIf<WASMType::I32, Opr>(LHS, RHS, Xchg);
    case WASMType::I64:
      return fusedCompareSelectWithIf<WASMType::I64, Opr>(LHS, RHS, Xchg);
    case WASMType::F32:
      return fusedCompareSelectWithIf<WASMType::F32, Opr>(LHS, RHS, Xchg);
    case WASMType::F64:
      return fusedCompareSelectWithIf<WASMType::F64, Opr>(LHS, RHS, Xchg);
    default:
      ZEN_ABORT();
    }
  }

  // load from memory in SrcType and return in DestType
  template <WASMType DestType, WASMType SrcType, bool Sext>
  Operand handleLoadImpl(Operand Base, uint32_t Offset, uint32_t Align) {
    constexpr A64::Type A64DestType = getA64TypeFromWASMType<DestType>();
    constexpr A64::Type A64SrcType = getA64TypeFromWASMType<SrcType>();
    ZEN_ASSERT(Base.getType() == A64OnePassABI::WASMAddrType);

    // handle base which is offset in linear memory
    auto BaseReg = toReg<A64::I32, ScopedTempReg1>(Base);
    // extend `base` from i32 to i64 to avoid overflow
    auto Reg = A64Reg::getRegRef<A64::I64>(BaseReg);
    if (!isArithImmValid(Offset)) {
      auto Tmp = Layout.getScopedTempReg<A64::I64, ScopedTempReg2>();
      _ mov(Tmp, Offset);
      _ add(Reg, Reg, Tmp);
    } else if (ZEN_LIKELY(Offset > 0)) {
      _ add(Reg, Reg, Offset);
    }
    auto Addr = asmjit::a64::ptr(ABI.getMemoryBaseReg(), Reg);

    checkMemoryOverflow<SrcType, ScopedTempReg2>(Reg);

    typename A64TypeAttr<A64DestType>::RegNum ValRegNum;
    bool HasTempReg = Layout.hasAvailTempReg<A64DestType>(ValRegNum);
    if (!HasTempReg) {
      ValRegNum = Layout.getScopedTemp<A64DestType, ScopedTempReg0>();
    }

    loadRegFromMem<A64DestType, A64SrcType, Sext>(ValRegNum, Addr);

    if (HasTempReg) {
      Layout.clearAvailReg<A64DestType>(ValRegNum);
      return Operand(DestType, ValRegNum, Operand::FLAG_TEMP_REG);
    }
    Operand Ret = getTempStackOperand(DestType);
    storeRegToMem<A64DestType>(ValRegNum, Ret.getMem<A64DestType>());
    return Ret;
  }

  // shift
  template <WASMType Type, BinaryOperator Opr>
  Operand handleShiftOpImpl(Operand LHS, Operand RHS) {
    if (Opr == BinaryOperator::BO_ROTL) {
      constexpr A64::Type A64Type = getA64TypeFromWASMType<Type>();
      A64::RegNum ResReg = Layout.getScopedTemp<A64Type, ScopedTempReg0>();
      if (Type == WASMType::I32) {
        mov<A64Type>(ResReg, Operand(WASMType::I32, 32));
      } else {
        ZEN_ASSERT(Type == WASMType::I64);
        mov<A64Type>(ResReg, Operand(WASMType::I32, 64));
      }

      A64::RegNum RHSReg;
      if (RHS.isReg())
        RHSReg = RHS.getReg();
      else {
        RHSReg = Layout.getScopedTemp<A64Type, ScopedTempReg1>();
        mov<A64Type>(RHSReg, RHS);
      }
      BinaryOperatorImpl<A64Type, BinaryOperator::BO_SUB>::emit(
          ASM, A64Reg::getRegRef<A64Type>(ResReg),
          A64Reg::getRegRef<A64Type>(ResReg),
          A64Reg::getRegRef<A64Type>(RHSReg));

      A64::RegNum LHSReg;
      if (LHS.isReg())
        LHSReg = LHS.getReg();
      else {
        LHSReg = Layout.getScopedTemp<A64Type, ScopedTempReg1>();
        mov<A64Type>(LHSReg, LHS);
      }
      BinaryOperatorImpl<A64Type, BinaryOperator::BO_ROTR>::emit(
          ASM, A64Reg::getRegRef<A64Type>(ResReg),
          A64Reg::getRegRef<A64Type>(LHSReg),
          A64Reg::getRegRef<A64Type>(ResReg));
      Operand Ret = getTempOperand(Type);
      mov<A64Type>(Ret, ResReg);
      return Ret;
    }
    return handleBinaryOpImpl<Type, Opr>(LHS, RHS);
  }

  // store value to memory in Type
  template <WASMType Type>
  void handleStoreImpl(Operand Value, Operand Base, uint32_t Offset,
                       uint32_t Align) {
    constexpr A64::Type A64Type = getA64TypeFromWASMType<Type>();
    ZEN_ASSERT(Base.getType() == A64OnePassABI::WASMAddrType);

    // handle base which is offset in linear memory
    auto BaseReg = toReg<A64::I32, ScopedTempReg0>(Base);
    // extend `base` from i32 to i64 to avoid overflow
    auto Reg = A64Reg::getRegRef<A64::I64>(BaseReg);
    if (!isArithImmValid(Offset)) {
      auto Tmp = Layout.getScopedTempReg<A64::I64, ScopedTempReg1>();
      _ mov(Tmp, Offset);
      _ add(Reg, Reg, Tmp);
    } else if (ZEN_LIKELY(Offset > 0)) {
      _ add(Reg, Reg, Offset);
    }
    auto Addr = asmjit::a64::ptr(ABI.getMemoryBaseReg(), Reg);

    checkMemoryOverflow<Type, ScopedTempReg1>(Reg);

    mov<A64Type, ScopedTempReg2>(Addr, Value);
  }

  Operand handleIntTruncImpl(Operand Op) {
    auto Src = toReg<A64::I64, ScopedTempReg0>(Op);
    auto Dst = getTempOperand(WASMType::I32);
    mov<A64::I32, false>(Dst, Src);
    return Dst;
  }

  // floating-point unary operators
  template <WASMType Type, UnaryOperator Opr>
  Operand handleUnaryOpImpl(Operand Op) {
    constexpr auto A64Type = getA64TypeFromWASMType<Type>();
    auto SrcReg = toReg<A64Type, ScopedTempReg0>(Op);

    auto Ret = getTempOperand(Type);
    auto DstReg =
        Ret.isReg()
            ? (A64::RegNum)Ret.getReg()
            : (A64::RegNum)Layout.getScopedTemp<A64Type, ScopedTempReg1>();
    UnaryOperatorImpl<A64Type, Opr>::emit(ASM,
                                          A64Reg::getRegRef<A64Type>(DstReg),
                                          A64Reg::getRegRef<A64Type>(SrcReg));

    if (!Ret.isReg()) {
      mov<A64Type>(Ret, DstReg);
    }
    return Ret;
  }

public:
  //
  // branch, call and return instructions
  //

  // in alphabetical order
  // branch to given label
  void branch(uint32_t LabelIdx) {
    asmjit::Label L(LabelIdx);
    _ b(L);
  }

  void branchLTU(uint32_t LabelIdx) { _ b_lo(asmjit::Label(LabelIdx)); }

  // branch to label if cond is false
  void branchFalse(Operand Cond, uint32_t LabelIdx) {
    ZEN_ASSERT(Cond.getType() == WASMType::I32 ||
               Cond.getType() == WASMType::I64);
    if (Cond.getType() == WASMType::I32) {
      compareBranch<A64::I32, true, ScopedTempReg1>(Cond, LabelIdx);
    } else if (Cond.getType() == WASMType::I64) {
      compareBranch<A64::I64, true, ScopedTempReg1>(Cond, LabelIdx);
    } else {
      ZEN_ABORT();
    }
  }

  // branch to label if cond is true
  void branchTrue(Operand Cond, uint32_t LabelIdx) {
    ZEN_ASSERT(Cond.getType() == WASMType::I32 ||
               Cond.getType() == WASMType::I64);
    if (Cond.getType() == WASMType::I32) {
      compareBranch<A64::I32, false, ScopedTempReg1>(Cond, LabelIdx);
    } else if (Cond.getType() == WASMType::I64) {
      compareBranch<A64::I64, false, ScopedTempReg1>(Cond, LabelIdx);
    } else {
      ZEN_ABORT();
    }
  }

  // branch to table index
  void handleBranchTableImpl(Operand Index,
                             const std::vector<uint32_t> &LabelIdxs) {
    ZEN_ASSERT(Index.getType() == WASMType::I32);
    ZEN_ASSERT(LabelIdxs.size() >= 1);
    uint32_t Bound = LabelIdxs.size() - 1; // last item is default
    // compare index with bound
    if (Index.isImm()) {
      uint32_t IndexImm =
          ((uint32_t)Index.getImm() < Bound) ? Index.getImm() : Bound;
      branch(LabelIdxs[IndexImm]);
      return;
    }

    // load index into register if necessary
    A64::RegNum IndexRegNum = toReg<A64::I32, ScopedTempReg1>(Index);
    // compare index with bound
    Operand IndexRegOp =
        Operand(WASMType::I32, IndexRegNum, Operand::FLAG_NONE);
    bool Exchanged;
    cmp<A64::I32, ScopedTempReg2, ScopedTempReg2>(
        IndexRegOp, Operand(WASMType::I32, Bound), Exchanged);
    // jump to default label if index >= bound
    jmpcc<CompareOperator::CO_GE_U, true>(LabelIdxs[Bound]);

    // for small tables, generate if (index == i) goto i;
    switch (Bound) {
    case 4:
      cmp<A64::I32, ScopedTempReg2, ScopedTempReg2>(
          IndexRegOp, Operand(WASMType::I32, 3), Exchanged);
      jmpcc<CompareOperator::CO_EQ, true>(LabelIdxs[3]);
      // fall through
    case 3:
      cmp<A64::I32, ScopedTempReg2, ScopedTempReg2>(
          IndexRegOp, Operand(WASMType::I32, 2), Exchanged);
      jmpcc<CompareOperator::CO_EQ, true>(LabelIdxs[2]);
      // fall through
    case 2:
      cmp<A64::I32, ScopedTempReg2, ScopedTempReg2>(
          IndexRegOp, Operand(WASMType::I32, 1), Exchanged);
      jmpcc<CompareOperator::CO_EQ, true>(LabelIdxs[1]);
      // fall through
    case 1:
      cmp<A64::I32, ScopedTempReg2, ScopedTempReg2>(
          IndexRegOp, Operand(WASMType::I32, 0), Exchanged);
      jmpcc<CompareOperator::CO_EQ, true>(LabelIdxs[0]);
      return;
    default:
      break;
    }

    // jump to entry in jump table
    uint32_t Table = createLabel();
    auto JmpReg = Layout.getScopedTempReg<A64::I64, ScopedTempReg2>();
    _ adr(JmpReg, asmjit::Label(Table));
    asmjit::a64::Mem JmpAddr(JmpReg, A64Reg::getRegRef<A64::I32>(IndexRegNum),
                             asmjit::a64::lsl(sizeof(uintptr_t) == 4 ? 2 : 3));
    _ ldr(JmpReg, JmpAddr);
    _ br(JmpReg);
    emitJumpTable(Table, LabelIdxs);
  }

  // call
  Operand handleCallImpl(uint32_t FuncIdx, uintptr_t Target, bool IsImport,
                         bool FarCall, const ArgumentInfo &ArgInfo,
                         const std::vector<Operand> &Args) {
    return emitCall(
        ArgInfo, Args,
        [this, IsImport] {
          saveGasVal();
#ifdef ZEN_ENABLE_DWASM
          // if IsImport, update WasmInstance::is_host_api
          if (IsImport) {
            auto in_host_api_flag_addr =
                asmjit::a64::ptr(ABI.getModuleInstReg(), InHostApiOffset);
            movImm<A64::I8, ScopedTempReg0>(in_host_api_flag_addr, 1);
          }
#endif
        },
        [&]() {
          // generate call, emit call or record relocation for patching
          if (Target) {
            callAbsolute(Target);
          } else {
            size_t Offset = _ offset();
            _ nop();
            if (FarCall) {
              _ nop();
              _ nop();
              _ nop();
              ZEN_ASSERT(_ offset() - Offset == 16);
            } else {
              ZEN_ASSERT(_ offset() - Offset == 4);
            }
            Patcher.addCallEntry(Offset, _ offset() - Offset, FuncIdx);
          }
        },
        [this, IsImport] {
#ifdef ZEN_ENABLE_DWASM
          // if IsImport, update WasmInstance::is_host_api
          if (IsImport) {
            auto InHostAPIFlagAddr =
                asmjit::a64::ptr(ABI.getModuleInstReg(), InHostApiOffset);
            movImm<A64::I8, ScopedTempReg0>(InHostAPIFlagAddr, 0);
          }
#endif
          loadGasVal();
          checkCallException(IsImport);
        });
  }

  Operand handleCallIndirectImpl(uint32_t TypeIdx, Operand Callee,
                                 uint32_t TblIdx, const ArgumentInfo &ArgInfo,
                                 const std::vector<Operand> &Args) {
    uint32_t NumHostAPIs = Ctx->Mod->getNumImportFunctions();
    return emitCall(
        ArgInfo, Args,
        // prepare call, check and load Callee address into %r11
        [this, NumHostAPIs, TypeIdx, Callee, TblIdx]() {
          saveGasVal();

          auto FuncIdxReg = Layout.getScopedTemp<A64::I32, ScopedTempReg0>();
          emitTableGet(TblIdx, Callee, FuncIdxReg);
          auto FuncIdx = A64Reg::getRegRef<A64::I32>(FuncIdxReg);
          auto InstReg = ABI.getModuleInstReg();
          uint32_t CheckFuncType = createLabel();
          bool Exchanged;
          cmp<A64::I32, ScopedTempReg2, ScopedTempReg2>(
              Operand(WASMType::I32, FuncIdxReg, Operand::FLAG_NONE),
              Operand(WASMType::I32, -1), Exchanged);
          jmpcc<CompareOperator::CO_NE, true>(CheckFuncType);
          emitRuntimeError(ErrorCode::UninitializedElement);

          bindLabel(CheckFuncType);
          auto TypeIdxs = Layout.getScopedTempReg<A64::I64, ScopedTempReg2>();
          asmjit::a64::Mem TypeIdxsAddr(InstReg, FunctionTypesOffset);
          _ ldr(TypeIdxs, TypeIdxsAddr);

          asmjit::a64::Mem TypeIdxAddr(TypeIdxs, FuncIdx, asmjit::a64::lsl(2));
          auto ActualTypeIdx =
              Layout.getScopedTempReg<A64::I32, ScopedTempReg2>();
          _ ldr(ActualTypeIdx, TypeIdxAddr);

          uint32_t CheckSucc = createLabel();
          _ cmp(ActualTypeIdx, TypeIdx);
          jmpcc<CompareOperator::CO_EQ, true>(CheckSucc);
          emitRuntimeError(ErrorCode::IndirectCallTypeMismatch);
          bindLabel(CheckSucc);

#ifdef ZEN_ENABLE_DWASM
          // check FuncIdx < import_funcs_count (is_import)
          // if is_import, update WasmInstance::is_host_api
          auto UpdateFlagLabel = createLabel();
          auto EndUpdateFlagLabel = createLabel();
          // The immediate value in the cmp instruction is 12-bit
          if (ZEN_LIKELY(isArithImmValid(NumHostAPIs))) {
            _ cmp(FuncIdx, NumHostAPIs);
          } else {
            auto NumHostAPIsReg =
                Layout.getScopedTempReg<A64::I32, ScopedTempReg1>();
            _ mov(NumHostAPIsReg, NumHostAPIs);
            _ cmp(FuncIdx, NumHostAPIsReg);
          }

          branchLTU(UpdateFlagLabel);
          branch(EndUpdateFlagLabel);

          bindLabel(UpdateFlagLabel);
          auto InHostAPIFlagAddr =
              asmjit::a64::ptr(ABI.getModuleInstReg(), InHostApiOffset);
          movImm<A64::I8, ScopedTempReg0>(InHostAPIFlagAddr, 1);
          branch(EndUpdateFlagLabel);

          bindLabel(EndUpdateFlagLabel);
#endif

          auto FuncPtrs = Layout.getScopedTempReg<A64::I64, ScopedTempReg2>();
          asmjit::a64::Mem FuncPtrsAddr(InstReg, FunctionPointersOffset);
          _ ldr(FuncPtrs, FuncPtrsAddr);

          auto FuncPtr = ABI.getCallTargetReg();
          constexpr uint32_t Shift = sizeof(void *) == 4 ? 2 : 3;
          asmjit::a64::Mem FuncPtrAddr(FuncPtrs, FuncIdx,
                                       asmjit::a64::lsl(Shift));
          _ ldr(FuncPtr, FuncPtrAddr);
        },
        // generate call
        [&]() { _ blr(ABI.getCallTargetReg()); },
        [this] {
#ifdef ZEN_ENABLE_DWASM
          // because FuncIdx reg not available in post_call
          // so just update the flag directly now(have performance cost)
          auto InHostAPIFlagAddr =
              asmjit::a64::ptr(ABI.getModuleInstReg(), InHostApiOffset);
          movImm<A64::I8, ScopedTempReg0>(InHostAPIFlagAddr,
                                          0); // update flag back
#endif
          loadGasVal();
          checkCallIndirectException();
        });
  }

  // branch to label if ZF is 0
  void je(uint32_t LabelIdx) {
    asmjit::Label L(LabelIdx);
    _ b_eq(L);
  }

  // branch to label if ZF is 1
  void jne(uint32_t LabelIdx) {
    asmjit::Label L(LabelIdx);
    _ b_ne(L);
  }

  // return
  void handleReturnImpl(Operand Op) { emitEpilog(Op); }

  // unreachable
  void handleUnreachableImpl() { emitRuntimeError(ErrorCode::Unreachable); }

public:
  //
  // non-templated method to handle other individual opcode
  //

  // in alphabetical order

  // memory grow
  Operand handleMemoryGrowImpl(Operand Op) {
    static TypeEntry SigBuf = {
        .NumParams = 1,
        .NumParamCells = 1,
        .NumReturns = 1,
        .NumReturnCells = 1,
        .ReturnTypes = {WASMType::I32},
        {
            .ParamTypesVec = {WASMType::I32},
        },
        .SmallestTypeIdx = uint32_t(-1),
    };
    ArgumentInfo ArgInfo(&SigBuf);
    std::vector<Operand> Args = {Op};
    auto GenCall = [this] {
      callAbsolute(uintptr_t(Instance::growInstanceMemoryOnJIT));

      auto InstReg = ABI.getModuleInstReg();
      auto MemReg = ABI.getMemoryBaseReg();

      auto MemsPtr = asmjit::a64::ptr(InstReg, MemoriesOffset);
      _ ldr(MemReg, MemsPtr);

      auto MemSizePtr = asmjit::a64::ptr(MemReg, MemorySizeOffset);
      _ ldr(ABI.getMemorySizeReg(), MemSizePtr);

      auto MemBasePtr = asmjit::a64::ptr(MemReg, MemoryBaseOffset);
      _ ldr(MemReg, MemBasePtr);
    };
    return emitCall(
        ArgInfo, Args, [] {}, GenCall, [] {});
  }

  // memory size
  Operand handleMemorySizeImpl() {
    // convert bytes to pages
    auto TmpReg = Layout.getScopedTemp<A64::I32, ScopedTempReg0>();
    _ lsr(A64Reg::getRegRef<A64::I64>(TmpReg), ABI.getMemorySizeReg(), 16);

    auto Ret = getTempOperand(WASMType::I32);
    mov<A64::I32>(Ret, TmpReg);
    return Ret;
  }

  // select
  Operand handleSelectImpl(Operand Cond, Operand LHS, Operand RHS) {
    ZEN_ASSERT(LHS.getType() == RHS.getType());
    ZEN_ASSERT(Cond.getType() == WASMType::I32 ||
               Cond.getType() == WASMType::I64);
    switch (LHS.getType()) {
    case WASMType::I32:
      return selectWithIf<WASMType::I32>(Cond, LHS, RHS);
    case WASMType::I64:
      return selectWithIf<WASMType::I64>(Cond, LHS, RHS);
    case WASMType::F32:
      return selectWithIf<WASMType::F32>(Cond, LHS, RHS);
    case WASMType::F64:
      return selectWithIf<WASMType::F64>(Cond, LHS, RHS);
    default:
      ZEN_ABORT();
    }
  }

  void subGasVal(Operand Delta) {
    if (Delta.isImm() && isArithImmValid(Delta.getImm())) {
      _ subs(ABI.getGasReg(), ABI.getGasReg(), Delta.getImm());
    } else {
      auto DeltaRegNum = toReg<A64::I64, ScopedTempReg0>(Delta);
      auto DeltaReg = A64Reg::getRegRef<A64::I64>(DeltaRegNum);
      _ subs(ABI.getGasReg(), ABI.getGasReg(), DeltaReg);
    }
  }

  void loadGasVal() {
    auto GasPtr = asmjit::a64::ptr(ABI.getModuleInstReg(), GasLeftOffset);
    _ ldr(ABI.getGasReg(), GasPtr);
  }

  void saveGasVal() {
    auto GasPtr = asmjit::a64::ptr(ABI.getModuleInstReg(), GasLeftOffset);
    _ str(ABI.getGasReg(), GasPtr);
  }

  template <A64::Type Ty, BinaryOperator Opr>
  void handleBinaryOpWithOverflowFlags(const A64::RegNum ResRegNum,
                                       const A64::RegNum LHSRegNum,
                                       const A64::RegNum RHSRegNum) {
    if (Opr == BinaryOperator::BO_ADD) {
      if (Ty == A64::I64) {
        _ adds(A64Reg::getRegRef<A64::I64>(ResRegNum),
               A64Reg::getRegRef<A64::I64>(LHSRegNum),
               A64Reg::getRegRef<A64::I64>(RHSRegNum));
      } else {
        _ adds(A64Reg::getRegRef<A64::I32>(ResRegNum),
               A64Reg::getRegRef<A64::I32>(LHSRegNum),
               A64Reg::getRegRef<A64::I32>(RHSRegNum));
      }
    } else if (Opr == BinaryOperator::BO_SUB) {
      if (Ty == A64::I64) {
        _ subs(A64Reg::getRegRef<A64::I64>(ResRegNum),
               A64Reg::getRegRef<A64::I64>(LHSRegNum),
               A64Reg::getRegRef<A64::I64>(RHSRegNum));
      } else {
        _ subs(A64Reg::getRegRef<A64::I32>(ResRegNum),
               A64Reg::getRegRef<A64::I32>(LHSRegNum),
               A64Reg::getRegRef<A64::I32>(RHSRegNum));
      }
    } else {
      ZEN_ASSERT(false);
    }
  }
  template <bool Sign, BinaryOperator Opr>
  Operand checkedI128Arithmetic(Operand LHSLo, Operand LHSHi, Operand RHSLo,
                                Operand RHSHi) {
    auto OverflowLabel = getExceptLabel(ErrorCode::IntegerOverflow);
    A64::RegNum ResRegNum = Layout.getScopedTemp<A64::I64, ScopedTempReg2>();
    auto LHSLoRegNum = toReg<A64::I64, ScopedTempReg0>(LHSLo);
    auto RHSLoRegNum = toReg<A64::I64, ScopedTempReg1>(RHSLo);
    auto Tmp1RegNum =
        Layout.getScopedTemp<A64::I64,
                             ScopedTempReg0>(); // tmp1 reg used after
                                                // LHSLo not used again
    handleBinaryOpWithOverflowFlags<A64::I64, Opr>(
        Tmp1RegNum, LHSLoRegNum,
        RHSLoRegNum); // ScopedTempReg0 need used after
    // use tmp reg 2(res reg num) as rhsHiRegI64 one one instruction
    auto LHSHiRegNum = toReg<A64::I64, ScopedTempReg1>(LHSHi);
    auto RHSHiRegNum = toReg<A64::I64, ScopedTempReg2>(RHSHi);
    if (Opr == BinaryOperator::BO_ADD) {
      _ adcs(A64Reg::getRegRef<I64>(ResRegNum),
             A64Reg::getRegRef<I64>(LHSHiRegNum),
             A64Reg::getRegRef<I64>(
                 RHSHiRegNum)); // ScopedTempReg2 amd 0 need used after
    } else if (Opr == BinaryOperator::BO_SUB) {
      _ sbcs(A64Reg::getRegRef<I64>(ResRegNum),
             A64Reg::getRegRef<I64>(LHSHiRegNum),
             A64Reg::getRegRef<I64>(
                 RHSHiRegNum)); // ScopedTempReg2 amd 0 need used after
    } else {
      ZEN_ASSERT(false);
    }
    if (!Sign && Opr == BinaryOperator::BO_ADD) { // u128 add
      _ b_cs(OverflowLabel);
    } else if (!Sign && Opr == BinaryOperator::BO_SUB) { // u128 sub
      _ b_cc(OverflowLabel);
    } else { // i128
      _ b_vs(OverflowLabel);
    }

    auto Ret = getTempOperand(WASMType::I64);
    mov<A64::I64>(Ret, ResRegNum);
    return Ret;
  }
  /**
   * multiply high
   */
  template <bool Sign>
  void mulh(A64::RegNum Dest, A64::RegNum A, A64::RegNum B) {
    if (Sign) {
      _ smulh(A64Reg::getRegRef<A64::I64>(Dest), A64Reg::getRegRef<A64::I64>(A),
              A64Reg::getRegRef<A64::I64>(B));
    } else {
      _ umulh(A64Reg::getRegRef<A64::I64>(Dest), A64Reg::getRegRef<A64::I64>(A),
              A64Reg::getRegRef<A64::I64>(B));
    }
  }
  /**
   * multiply low
   */
  template <bool Sign>
  void mull(A64::RegNum Dest, A64::RegNum A, A64::RegNum B) {
    if (Sign) {
      _ smull(A64Reg::getRegRef<A64::I64>(Dest), A64Reg::getRegRef<A64::I32>(A),
              A64Reg::getRegRef<A64::I32>(B));
    } else {
      _ umull(A64Reg::getRegRef<A64::I64>(Dest), A64Reg::getRegRef<A64::I32>(A),
              A64Reg::getRegRef<A64::I32>(B));
    }
  }
  template <bool Sign, A64::Type A64Type>
  void extendTo32Bits(A64::RegNum Dest, A64::RegNum N) {
    if (!Sign) {
      const int32_t BitUnsignedMax =
          (A64Type == A64::I8 ? 0xff : 0xffff); // u8: 0xff, u16: 0xffff
      _ and_(A64Reg::getRegRef<A64::I32>(Dest), A64Reg::getRegRef<A64::I32>(N),
             BitUnsignedMax);
      return;
    }
    if (A64Type == A64::I8) {
      _ sxtb(A64Reg::getRegRef<A64::I32>(Dest), A64Reg::getRegRef<A64::I32>(N));
    } else if (A64Type == A64::I16) {
      _ sxth(A64Reg::getRegRef<A64::I32>(Dest), A64Reg::getRegRef<A64::I32>(N));
    } else {
      ZEN_ASSERT(false);
    }
  }
  template <bool Sign, WASMType Type, BinaryOperator Opr>
  Operand checkedMulArithmetic(Operand LHS, Operand RHS) {
    constexpr auto A64Type = getA64TypeFromWASMType<Type>();
    auto OverflowLabel = getExceptLabel(ErrorCode::IntegerOverflow);
    A64::RegNum ResRegNum = Layout.getScopedTemp<A64Type, ScopedTempReg2>();
    auto LHSRegNum = toReg<A64Type, ScopedTempReg0>(LHS);
    auto RHSRegNum = toReg<A64Type, ScopedTempReg1>(RHS);
    A64::RegNum Tmp1RegNum =
        Layout.getScopedTemp<A64::I64,
                             ScopedTempReg0>(); // only can used after
                                                // lhsReg not used again
    auto ResRegI64 = A64Reg::getRegRef<A64::I64>(ResRegNum);
    auto ResRegI32 = A64Reg::getRegRef<A64::I32>(ResRegNum);
    auto LHSRegI64 = A64Reg::getRegRef<A64::I64>(LHSRegNum);
    auto RHSRegI64 = A64Reg::getRegRef<A64::I64>(RHSRegNum);
    auto Tmp1RegI64 = A64Reg::getRegRef<A64::I64>(Tmp1RegNum);
    auto Tmp1RegI32 = A64Reg::getRegRef<A64::I32>(Tmp1RegNum);
    if (A64Type == A64::I64) { // i64 mul || u64 mul
      _ mul(ResRegI64, LHSRegI64, RHSRegI64);
      mulh<Sign>(Tmp1RegNum, LHSRegNum, RHSRegNum);
      if (Sign) {
        _ cmp(Tmp1RegI64, ResRegI64, asmjit::arm::asr(63));
      } else {
        _ cmp(A64Reg::getRegRef<A64::I64>(A64::XZR), Tmp1RegI64);
      }
      _ b_ne(OverflowLabel);
    } else if (A64Type == A64::I32) { // i32 mul || u32 mul
      mull<Sign>(ResRegNum, LHSRegNum, RHSRegNum);
      if (Sign) {
        _ lsr(Tmp1RegI64, ResRegI64, 32);
        _ cmp(Tmp1RegI32, ResRegI32, asmjit::arm::asr(31));
      } else {
        _ cmp(A64Reg::getRegRef<A64::I64>(A64::XZR), ResRegI64,
              asmjit::arm::lsr(32));
      }
      _ b_ne(OverflowLabel);
    } else if (A64Type == A64::I8 || A64Type == A64::I16) { // 8bit and 16bit
      extendTo32Bits<Sign, A64Type>(ResRegNum, RHSRegNum);
      extendTo32Bits<Sign, A64Type>(Tmp1RegNum, LHSRegNum);
      _ mul(ResRegI32, Tmp1RegI32, ResRegI32);
      if (Sign) { // i8 and i16
        extendTo32Bits<Sign, A64Type>(Tmp1RegNum, ResRegNum);
        _ cmp(Tmp1RegI32, ResRegI32);
      } else if (A64Type == A64::I8 && !Sign) { // u8
        _ tst(ResRegI32, 0xff00);
      } else if (A64Type == A64::I16 && !Sign) { // u16
        _ tst(ResRegI32, 0xffff0000);
      } else {
        ZEN_ASSERT(false);
      }
      _ b_ne(OverflowLabel);
    } else {
      ZEN_ASSERT(false);
    }
    auto ResType = (getWASMTypeSize<Type>() < 4) ? WASMType::I32 : Type;
    auto Ret = getTempOperand(ResType);
    mov<A64Type>(Ret, ResRegNum);
    return Ret;
  }
  template <bool Sign, WASMType Type, BinaryOperator Opr>
  Operand checkedArithmetic(Operand LHS, Operand RHS) {
    if (Opr == BinaryOperator::BO_MUL) {
      return checkedMulArithmetic<Sign, Type, Opr>(LHS, RHS);
    }
    constexpr auto A64Type = getA64TypeFromWASMType<Type>();
    auto OverflowLabel = getExceptLabel(ErrorCode::IntegerOverflow);
    A64::RegNum ResRegNum = Layout.getScopedTemp<A64Type, ScopedTempReg2>();
    A64::RegNum LHSRegNum = toReg<A64Type, ScopedTempReg0>(LHS);
    A64::RegNum RHSRegNum = toReg<A64Type, ScopedTempReg1>(RHS);
    // tmp1 only can be used after lhsReg not used again
    A64::RegNum Tmp1RegNum = Layout.getScopedTemp<A64::I64, ScopedTempReg0>();
    auto ResRegI32 = A64Reg::getRegRef<A64::I32>(ResRegNum);
    auto RHSRegI32 = A64Reg::getRegRef<A64::I32>(RHSRegNum);
    auto Tmp1RegI32 = A64Reg::getRegRef<A64::I32>(Tmp1RegNum);
    if (A64Type == A64::I8 || A64Type == A64::I16) { // 8bit or 16bit add/sub
      // extend to 32bit
      extendTo32Bits<Sign, A64Type>(ResRegNum, LHSRegNum);
      asmjit::arm::Shift OprShift;
      if (Sign && A64Type == A64::I8) { // i8
        OprShift = asmjit::arm::sxtb(0);
      } else if (Sign && A64Type == A64::I16) { // i16
        OprShift = asmjit::arm::sxth(0);
      } else if (!Sign && A64Type == A64::I8) { // u8
        OprShift = asmjit::arm::uxtb(0);
      } else if (!Sign && A64Type == A64::I16) { // u16
        OprShift = asmjit::arm::uxth(0);
      } else {
        ZEN_ASSERT(false);
      }
      if (Opr == BinaryOperator::BO_ADD) {
        _ add(ResRegI32, ResRegI32, RHSRegI32, OprShift);
      } else if (Opr == BinaryOperator::BO_SUB) {
        _ sub(ResRegI32, ResRegI32, RHSRegI32, OprShift);
      } else {
        ZEN_ASSERT(false);
      }
      extendTo32Bits<Sign, A64Type>(Tmp1RegNum, ResRegNum);
      _ cmp(Tmp1RegI32, ResRegI32);
      _ b_ne(OverflowLabel);
    }
    handleBinaryOpWithOverflowFlags<A64Type, Opr>(ResRegNum, LHSRegNum,
                                                  RHSRegNum);
    if (!Sign && Opr == BinaryOperator::BO_ADD) // u32.add
      _ b_cs(OverflowLabel);
    else if (!Sign && Opr == BinaryOperator::BO_SUB) // u32.sub
      _ b_cc(OverflowLabel);
    else
      _ b_vs(OverflowLabel);
    auto ResType = (getWASMTypeSize<Type>() < 4) ? WASMType::I32 : Type;
    auto Ret = getTempOperand(ResType);
    mov<A64Type>(Ret, ResRegNum);
    return Ret;
  }

private:
  template <WASMType Type>
  Operand selectWithIf(Operand Cond, Operand LHS, Operand RHS) {
    auto Ret = getTempOperand(Type);
    constexpr auto A64Type = getA64TypeFromWASMType<Type>();
    auto RegNum = Layout.getScopedTemp<A64Type, ScopedTempReg0>();

    auto Label = createLabel();
    mov<A64Type>(RegNum, LHS);
    if (Cond.getType() == WASMType::I32) {
      compareBranch<A64::I32, false, ScopedTempReg1>(Cond, Label);
    } else if (Cond.getType() == WASMType::I64) {
      compareBranch<A64::I64, false, ScopedTempReg1>(Cond, Label);
    } else {
      ZEN_ABORT();
    }
    mov<A64Type>(RegNum, RHS);
    bindLabel(Label);

    mov<A64Type>(Ret, RegNum);

    return Ret;
  }

  template <WASMType Type, CompareOperator Opr>
  Operand fusedCompareSelectWithIf(Operand LHS, Operand RHS, bool Exchanged) {
    constexpr auto A64Type = getA64TypeFromWASMType<Type>();
    auto RegNum = Layout.getScopedTemp<A64Type, ScopedTempReg0>();

    auto Label = createLabel();
    mov<A64Type>(RegNum, LHS);

    if (Exchanged) {
      constexpr auto ExchangedOpr = getExchangedCompareOperator<Opr>();
      jmpcc<ExchangedOpr, true>(Label);
    } else {
      jmpcc<Opr, true>(Label);
    }

    mov<A64Type>(RegNum, RHS);
    bindLabel(Label);

    auto Ret = getTempOperand(Type);
    ZEN_ASSERT(!Ret.isImm());
    mov<A64Type>(Ret, RegNum);
    return Ret;
  }

private:
  //
  // helper functions, move to op_assembler_a64.h?
  //

  void callAbsolute(uintptr_t Addr) {
    auto Target = ABI.getCallTargetReg();
    _ mov(Target, Addr);
    _ blr(Target);
  }

  void setException() {
    BinaryOperatorImpl<A64::I64, BinaryOperator::BO_OR>::emit(
        ASM, ABI.getGlobalDataBaseReg(), ABI.getGlobalDataBaseReg(), 1);
  }

  void checkCallException(bool IsImport) {
#ifdef ZEN_ENABLE_CPU_EXCEPTION
    if (IsImport) {
      if (CurFuncState.ExceptionExitLabel == InvalidLabelId) {
        CurFuncState.ExceptionExitLabel = createLabel();
      }
      ZEN_ASSERT((Layout.getScopedTemp<A64::I64, ScopedTempReg0>() == A64::X0));
      asmjit::a64::Mem ExceptAddr(ABI.getModuleInstReg(), ExceptionOffset);
      auto Except = A64Reg::getRegRef<A64::I32>(ABI.getScratchRegNum());
      _ ldr(Except, ExceptAddr);
      _ cmp(Except, 0);

      // As `ExceptionExitLabel` could be far from here, and exceeds
      // conditiontal branch's range, we use an unconditional branch
      // instead.
      auto NoExcept = createLabel();
      je(NoExcept);
      branch(CurFuncState.ExceptionExitLabel);
      bindLabel(NoExcept);
    }
#else
    if (CurFuncState.ExceptionExitLabel == InvalidLabelId) {
      CurFuncState.ExceptionExitLabel = createLabel();
    }
    if (!IsImport) {
      _ tst(ABI.getGlobalDataBaseReg(),
            1); // has exception, reuse r14
    } else {
      ZEN_ASSERT((Layout.getScopedTemp<A64::I64, ScopedTempReg0>() == A64::X0));
      asmjit::a64::Mem ExceptAddr(ABI.getModuleInstReg(), ExceptionOffset);
      auto Except = A64Reg::getRegRef<A64::I32>(ABI.getScratchRegNum());
      _ ldr(Except, ExceptAddr);
      _ cmp(Except, 0);
    }
    // As `ExceptionExitLabel` could be far from here, and exceeds
    // conditiontal branch's range, we use an unconditional branch
    // instead.
    auto NoExcept = createLabel();
    je(NoExcept);
    branch(CurFuncState.ExceptionExitLabel);
    bindLabel(NoExcept);
#endif // ZEN_ENABLE_CPU_EXCEPTION
  }

  void checkCallIndirectException() { checkCallException(true); }

  template <WASMType Type, uint32_t TmpRegIdx>
  void checkMemoryOverflow(asmjit::a64::GpX Offset) {
    if (Ctx->UseSoftMemCheck) {
      auto Bound = Layout.getScopedTempReg<A64::I64, TmpRegIdx>();
      auto Size = getWASMTypeSize<Type>();
      _ add(Bound, Offset, Size);

      auto InBounds = createLabel();
      _ cmp(Bound, ABI.getMemorySizeReg());
      _ b_ls(asmjit::Label(InBounds));
      emitRuntimeError(ErrorCode::OutOfBoundsMemory);
      bindLabel(InBounds);
    }
  }

  // compare and branch on zero or non-zero
  template <A64::Type Ty, bool Zero, uint32_t TempRegIndex>
  void compareBranch(Operand Op, uint32_t LabelIdx) {
    ZEN_ASSERT(Op.getType() == getWASMTypeFromA64Type<Ty>());
    asmjit::Label L(LabelIdx);
    if (Op.isImm()) {
      if (Zero && !Op.getImm()) {
        _ b(L);
      } else if (!Zero && Op.getImm()) {
        _ b(L);
      }
      return;
    }

    typedef typename A64TypeAttr<Ty>::RegNum RegNum;
    RegNum RegisterNum;
    if (Op.isReg()) {
      RegisterNum = (RegNum)Op.getReg();
    } else if (Op.isMem()) {
      RegisterNum = Layout.getScopedTemp<Ty, TempRegIndex>();
      mov<Ty>((A64::RegNum)RegisterNum, Op);
    } else {
      ZEN_ABORT();
    }
    auto Reg = A64Reg::getRegRef<Ty>(RegisterNum);
    auto Fallthrough = _ newLabel();
    Zero ? _ cbnz(Reg, Fallthrough) : _ cbz(Reg, Fallthrough);
    _ b(L);
    _ bind(Fallthrough);
  }

  // get an operand in register, using a scoped temp if necessary
  template <A64::Type Ty, uint32_t Temp> A64::RegNum toReg(Operand Op) {
    if (Op.isReg()) {
      return Op.getReg();
    }
    auto TmpReg = Layout.getScopedTemp<Ty, Temp>();
    mov<Ty>(TmpReg, Op);
    return TmpReg;
  }

  template <A64::Type Ty, uint32_t Temp> A64RegType<Ty> toRegRef(Operand Op) {
    return A64Reg::getRegRef<Ty>(toReg<Ty, Temp>(Op));
  }

  template <A64::Type Ty, A64::Type IntType, uint32_t TempRegIndex>
  void fmovFromGp(Operand LHS, A64::RegNum RHS) {
    ZEN_ASSERT(LHS.isReg() || LHS.isMem());
    ZEN_STATIC_ASSERT(Ty == A64::F32 || Ty == A64::F64);

    if (LHS.isReg()) {
      _ fmov(A64Reg::getRegRef<Ty>(LHS.getReg()),
             A64Reg::getRegRef<IntType>(RHS));
    } else {
      A64::RegNum RegNum = Layout.getScopedTemp<Ty, TempRegIndex>();
      _ fmov(A64Reg::getRegRef<Ty>(RegNum), A64Reg::getRegRef<IntType>(RHS));
      storeRegToMem<Ty>(RegNum, LHS.getMem<Ty>());
    }
  }

  // load value from memory
  template <A64::Type DestType, A64::Type SrcType = DestType, bool Sext = false>
  void loadRegFromMem(A64::RegNum Val, asmjit::a64::Mem Memory) {
    if (Memory.hasOffset() && !isMemOffsetValid<DestType>(Memory.offset())) {
      auto OffsetReg = ABI.getScratchReg();
      _ mov(OffsetReg, Memory.offset());
      Memory =
          asmjit::a64::ptr(Memory.baseReg().as<asmjit::a64::GpX>(), OffsetReg);
    }
    LoadOperatorImpl<DestType, SrcType, Sext>::emit(ASM, Val, Memory);
  }

  // store value to memory
  template <A64::Type Ty, uint32_t TempRegIndex>
  void storeImmToMem(uint32_t Val, asmjit::a64::Mem Memory) {
    auto TempReg = Layout.getScopedTemp<Ty, TempRegIndex>();
    ASM.mov<Ty>(RegClass::template getRegRef<Ty>(TempReg), Val);
    storeRegToMem<Ty>(TempReg, Memory);
    return;
  }

  // store value to memory
  template <A64::Type Ty>
  void storeRegToMem(A64::RegNum Val, asmjit::a64::Mem Memory) {
    if (Memory.hasOffset() && !isMemOffsetValid<Ty>(Memory.offset())) {
      auto OffsetReg = ABI.getScratchReg();
      _ mov(OffsetReg, Memory.offset());
      Memory =
          asmjit::a64::ptr(Memory.baseReg().as<asmjit::a64::GpX>(), OffsetReg);
    }
    StoreOperatorImpl<Ty>::emit(ASM, Val, Memory);
  }

  // compare value
  template <A64::Type Ty, uint32_t TempRegIndex, uint32_t TempRegIndex2>
  void cmp(Operand LHS, Operand RHS, bool &Exchanged) {
    // floating-point constants are stored on stack
    ZEN_ASSERT(Ty == A64::I32 || Ty == A64::I64 ||
               (!LHS.isImm() && !RHS.isImm()));

    // TODO: currently some callers assume `Exchanged` is always false, so
    // we cannot safely do this optimization before fixing those callers
    Exchanged = false;

    auto LHSReg = toRegRef<Ty, TempRegIndex>(LHS);
    if (RHS.isImm() && isArithImmValid(RHS.getImm())) {
      ASM.cmp<Ty>(LHSReg, RHS.getImm());
    } else {
      auto RHSReg = toRegRef<Ty, TempRegIndex2>(RHS);
      ASM.cmp<Ty>(LHSReg, RHSReg);
    }
  }

  // Jmpcc
  template <CompareOperator Opr, bool Cond> void jmpcc(uint32_t LabelIdx) {
    constexpr JmpccOperator JmpccOpr = getJmpccOperator<Opr>();
    JmpccOperatorImpl<JmpccOpr, Cond>::emit(ASM, LabelIdx);
  }

  // Setcc
  template <A64::Type Ty, CompareOperator Opr, bool Cond>
  void setcc(A64::RegNum RegNum) {
    constexpr SetccOperator SetccOpr = getSetccOperator<Opr>();
    SetccOperatorImpl<Ty, SetccOpr, Cond>::emit(ASM,
                                                A64Reg::getRegRef<Ty>(RegNum));
  }
}; // A64OnePassCodeGenImpl

// undefine abbr for assembler
#undef _

} // namespace zen::singlepass

#endif // ZEN_SINGLEPASS_A64_CODEGEN_H
