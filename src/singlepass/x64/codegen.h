// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_SINGLEPASS_X64_CODEGEN_H
#define ZEN_SINGLEPASS_X64_CODEGEN_H

// ============================================================================
// x64/codegen.h
//
// code generator for x64 one pass jit compiler
//
// ============================================================================

#include "singlepass/common/codegen.h"
#include "singlepass/common/definitions.h"
#include "singlepass/common/valtype.h"
#include "singlepass/x64/asm/assembler.h"
#include "singlepass/x64/asm/register.h"
#include "singlepass/x64/assembler.h"
#include "singlepass/x64/codepatch.h"
#include "singlepass/x64/datalayout.h"
#include "singlepass/x64/machine.h"
#include "singlepass/x64/operand.h"

namespace zen::singlepass {

class X64ArgumentInfoAttrs {
public:
  typedef X64::Type DataType;
  typedef X64::RegNum RegNum;
  typedef X64OnePassABI OnePassABI;
  typedef X64SysVABI ArchABI;

  template <X64::Type Ty> using TypeAttr = X64TypeAttr<Ty>;
};

// ============================================================================
// X64ArgumentInfo
// manage argument for function call
// ============================================================================
class X64ArgumentInfo
    : public ArgumentInfo<X64ArgumentInfo, X64ArgumentInfoAttrs> {
public:
  X64ArgumentInfo(TypeEntry *Type) : ArgumentInfo(Type) {}

  static constexpr X64::Type getDataTypeFromWASMType(WASMType Type) {
    return getX64TypeFromWASMType(Type);
  }
};

// make a short rep for real assembler
#define _ ASM.Assembler().

class X64OnePassCodeGenAttrs {
public:
  typedef X64ArgumentInfo ArgumentInfo;
  typedef X64InstOperand Operand;
  typedef X64MachineState VMState;
  typedef X64Assembler Assembler;
  typedef X64OnePassDataLayout OnePassDataLayout;
  typedef X64CodePatcher CodePatcher;
  typedef X64OnePassABI OnePassABI;
  typedef X64SysVABI ArchABI;
  typedef X64::RegNum RegNum;
  typedef X64::GP GP;
  typedef X64::FP FP;
  typedef X64::Type DataType;
  typedef asmjit::x86::Mem Mem;
  typedef X64Reg RegClass;

  template <X64::Type Ty> using TypeAttr = X64TypeAttr<Ty>;

  static constexpr DataType I32 = X64::I32;
  static constexpr DataType F32 = X64::F32;
  static constexpr DataType I64 = X64::I64;
  static constexpr DataType F64 = X64::F64;
  static constexpr DataType V128 = X64::V128;
};

// ============================================================================
// X64OnePassCodeGenImpl
// code generator implementation for x64 onepass JIT compiler
// ============================================================================
class X64OnePassCodeGenImpl
    : public OnePassCodeGen<X64OnePassCodeGenImpl, X64OnePassCodeGenAttrs> {
public:
  friend class OnePassCodeGen;

  typedef X64ArgumentInfo ArgumentInfo;
  typedef X64InstOperand Operand;
  typedef X64MachineState VMState;
  typedef X64Assembler Assembler;

public:
  // constructor
  X64OnePassCodeGenImpl(X64OnePassDataLayout &Layout, X64CodePatcher &Patcher,
                        asmjit::CodeHolder *Code, JITCompilerContext *Ctx)
      : OnePassCodeGen(Code, Layout, Patcher, Ctx) {}

  void addStackPointer(uint32_t StackSize) {
    if (StackSize) {
      _ add(ABI.getStackPointerReg(), StackSize);
    }
  }

  void subStackPointer(uint32_t StackSize) {
    if (StackSize) {
      _ sub(ABI.getStackPointerReg(), StackSize);
    }
  }

private:
  //
  // prolog and epilog
  //

  // prolog
  void emitProlog(JITCompilerContext *Ctx) {
    // setup stack
    _ push(ABI.getFrameBaseReg());
    _ mov(ABI.getFrameBaseReg(), ABI.getStackPointerReg());
    CurFuncState.FrameSizePatchOffset = _ offset();
    _ long_().sub(ABI.getStackPointerReg(), 0); // to be patched later

#ifdef ZEN_ENABLE_DWASM
    // update stack cost
    auto StackCostAddr = asmjit::x86::ptr(ABI.getModuleInstReg(),
                                          Ctx->Mod->getLayout().StackCostOffset,
                                          sizeof(uint32_t));
    auto TmpReg = Layout.getScopedTempReg<X64::I32, ScopedTempReg0>();
    _ mov(TmpReg, StackCostAddr);
    _ add(TmpReg, Ctx->Func->JITStackCost);
    _ mov(StackCostAddr, TmpReg);
    _ cmp(TmpReg, common::PresetReservedStackSize);
    // jump to exception if exceed max stack size
    _ ja(getExceptLabel(ErrorCode::CallStackExhausted));
#elif defined(ZEN_ENABLE_STACK_CHECK_CPU)
    // visit sp-StackGuardSize to check stack overflow before has not stack to
    // call sig handler StackGuardSize is guard space for sig handler
    _ mov(asmjit::x86::rax,
          asmjit::x86::ptr(ABI.getStackPointerReg(), -common::StackGuardSize));
#else
    // check stack overflow
    auto StackBoundAddr =
        asmjit::x86::ptr(ABI.getModuleInstReg(), StackBoundaryOffset);
    _ cmp(ABI.getStackPointerReg(), StackBoundAddr);
    _ jbe(getExceptLabel(ErrorCode::CallStackExhausted));
#endif

    // save preserved registers
    uint32_t PresSaveSize = 0;
    uint32_t IntPresMask = 0;
    for (uint32_t I = 0; I < Layout.getIntPresSavedCount(); ++I) {
      const X64::GP Reg = ABI.getPresRegNum<X64::I64>(I);
      _ mov(asmjit::x86::Mem(ABI.getFrameBaseReg(), -(I + 1) * ABI.GpRegWidth),
            X64Reg::getRegRef<X64::I64>(Reg));
      PresSaveSize += ABI.GpRegWidth;
      IntPresMask |= (1 << Reg);
    }
    Layout.markAvailRegMask<X64::I64>(IntPresMask);
    ZEN_ASSERT(PresSaveSize == Layout.getIntPresSavedCount() * ABI.GpRegWidth);

    // initialize all locals to zero
    for (uint32_t I = 0; I < Ctx->Func->NumLocals; ++I) {
      auto Local = Layout.getLocal(I + Ctx->FuncType->NumParams);
      if (Local.isReg()) {
        if (Local.getType() == WASMType::I32 ||
            Local.getType() == WASMType::I64) {
          auto Reg = X64Reg::getRegRef<X64::I64>(Local.getReg());
          _ xor_(Reg, Reg);
        } else {
          auto Reg = X64Reg::getRegRef<X64::F64>(Local.getReg());
          _ xorpd(Reg, Reg);
        }
      } else {
        if (Local.getType() == WASMType::I32 ||
            Local.getType() == WASMType::F32) {
          _ mov(Local.getMem<X64::I32>(), 0);
        } else {
          _ mov(Local.getMem<X64::I64>(), 0);
        }
      }
    }

    loadGasVal();
  } // EmitProlog

  // epilog
  void emitEpilog(Operand Op) {
    saveGasVal();

#ifdef ZEN_ENABLE_DWASM
    // update stack cost
    auto StackCostAddr = asmjit::x86::ptr(ABI.getModuleInstReg(),
                                          Ctx->Mod->getLayout().StackCostOffset,
                                          sizeof(uint32_t));
    _ sub(StackCostAddr, Ctx->Func->JITStackCost);
#endif

    if (Layout.getNumReturns() > 0) {
      ZEN_ASSERT(Layout.getNumReturns() == 1);
      ZEN_ASSERT(Layout.getReturnType(0) == Op.getType());
      switch (Op.getType()) {
      case WASMType::I32:
        mov<X64::I32>(ABI.getRetRegNum<X64::I32>(), Op);
        break;
      case WASMType::I64:
        mov<X64::I64>(ABI.getRetRegNum<X64::I64>(), Op);
        break;
      case WASMType::F32:
        mov<X64::F32>(ABI.getRetRegNum<X64::F32>(), Op);
        break;
      case WASMType::F64:
        mov<X64::F64>(ABI.getRetRegNum<X64::F64>(), Op);
        break;
      default:
        ZEN_ASSERT(false);
      }
    }
    for (uint32_t I = 0; I < Layout.getIntPresSavedCount(); ++I) {
      const X64::GP Reg = ABI.getPresRegNum<X64::I64>(I);
      _ mov(X64Reg::getRegRef<X64::I64>(Reg),
            asmjit::x86::Mem(ABI.getFrameBaseReg(), -(I + 1) * ABI.GpRegWidth));
    }
    _ mov(ABI.getStackPointerReg(), ABI.getFrameBaseReg());
    _ pop(ABI.getFrameBaseReg());
    _ ret();
  } // EmitEpilog

  template <uint32_t SizeRegIndex>
  void emitTableSize(uint32_t TblIdx, Operand EntryIdx) {
    ZEN_ASSERT(EntryIdx.getType() == WASMType::I32);

    ZEN_STATIC_ASSERT(sizeof(TableInstance::CurSize) == sizeof(uint32_t));
    uint32_t SizeOffset = Ctx->Mod->getLayout().TableElemSizeOffset;
    asmjit::x86::Mem SizeAddr(ABI.getModuleInstReg(), SizeOffset,
                              sizeof(SizeOffset));
    // compare entry_idx with sizeReg
    if (EntryIdx.isReg()) {
      ZEN_ASSERT(EntryIdx.isTempReg());
      _ cmp(SizeAddr, EntryIdx.getRegRef<X64::I32>());
    } else if (EntryIdx.isMem()) {
      ZEN_ASSERT(EntryIdx.isTempMem());
      auto SizeReg = Layout.getScopedTempReg<X64::I32, SizeRegIndex>();
      _ mov(SizeReg, SizeAddr);
      _ cmp(SizeReg, EntryIdx.getMem<X64::I32>());
    } else if (EntryIdx.isImm()) {
      _ cmp(SizeAddr, EntryIdx.getImm());
    } else {
      ZEN_ABORT();
    }
    _ jbe(getExceptLabel(ErrorCode::UndefinedElement));
  }

  void emitTableGet(uint32_t TblIdx, Operand Elem, X64::GP ResRegNum) {
    // place table[tbl_idx] to ScopedTempReg1
    emitTableSize<ScopedTempReg0>(TblIdx, Elem);
    auto InstReg = ABI.getModuleInstReg();
    auto ResReg = X64Reg::getRegRef<X64::I32>(ResRegNum);
    constexpr uint32_t Shift = 2;
    uint32_t BaseOffset = Ctx->Mod->getLayout().TableElemBaseOffset;
    // load table[tbl_idx].functions[elem] into register
    if (Elem.isReg()) {
      // elem is in reg, reuse this reg
      _ mov(ResReg, asmjit::x86::ptr(InstReg, Elem.getRegRef<X64::I32>(), Shift,
                                     BaseOffset));
    } else if (Elem.isMem()) {
      // elem  is on stack, load it and save to ScopedTempReg0
      auto ElemReg = Layout.getScopedTempReg<X64::I32, ScopedTempReg0>();
      _ mov(ElemReg, Elem.getMem<X64::I32>());
      _ mov(ResReg, asmjit::x86::ptr(InstReg, ElemReg, Shift, BaseOffset));
    } else if (Elem.isImm()) {
      _ mov(ResReg, asmjit::x86::Mem(InstReg, Elem.getImm() * sizeof(uint32_t) +
                                                  BaseOffset));
    }
  }

public:
  //
  // initialization and finalization
  //

  // finalization after compiling a function
  void finalizeFunction() {
    // update RSP adjustment in prolog with the actual frame size
    ZEN_ASSERT(CurFuncState.FrameSizePatchOffset >= 0);
    auto CurrOffset = _ offset();
    _ setOffset(CurFuncState.FrameSizePatchOffset);
    _ long_().sub(ABI.getStackPointerReg(), Layout.getStackBudget());
    _ setOffset(CurrOffset);
  }

public:
  //
  // temporary, stack and vm state management
  //

  void callAbsolute(uintptr_t Addr) { _ call(Addr); }

  void setException() { _ or_(ABI.getGlobalDataBaseReg(), 1); }

  void checkCallException(bool IsImport) {
#ifdef ZEN_ENABLE_CPU_EXCEPTION
    if (IsImport) {
      if (CurFuncState.ExceptionExitLabel == InvalidLabelId) {
        CurFuncState.ExceptionExitLabel = createLabel();
      }
      auto Inst = ABI.getModuleInstReg();
      asmjit::x86::Mem ExceptAddr(Inst, ExceptionOffset, 4);
      _ cmp(ExceptAddr, 0);
      jne(CurFuncState.ExceptionExitLabel);
    }
#else
    if (CurFuncState.ExceptionExitLabel == InvalidLabelId) {
      CurFuncState.ExceptionExitLabel = createLabel();
    }

    if (!IsImport) {
      // has exception, reuse r14
      _ test(ABI.getGlobalDataBaseReg(), 1);
      jne(CurFuncState.ExceptionExitLabel);
    } else {
      auto Inst = ABI.getModuleInstReg();
      asmjit::x86::Mem ExceptAddr(Inst, ExceptionOffset, 4);
      _ cmp(ExceptAddr, 0);

      jne(CurFuncState.ExceptionExitLabel);
    }
#endif // ZEN_ENABLE_CPU_EXCEPTION
  }

  void checkCallIndirectException() { checkCallException(true); }

  template <WASMType Type>
  void checkMemoryOverflow(Operand Base, uint32_t Offset) {
    if (Ctx->UseSoftMemCheck) {
      constexpr uint32_t Size = getWASMTypeSize<Type>();
      Offset += Size;
      // check (offset + size) overflow
      if (Offset < Size) {
        _ jmp(getExceptLabel(ErrorCode::OutOfBoundsMemory));
      }

      auto BaseRegNum = Layout.getScopedTemp<X64::I32, ScopedTempReg0>();
      auto BaseReg = X64Reg::getRegRef<X64::I32>(BaseRegNum);
      mov<X64::I32>(BaseRegNum, Base);
      _ add(BaseReg, Offset);
      _ jc(getExceptLabel(ErrorCode::OutOfBoundsMemory));
      _ cmp(BaseReg, X64Reg::getRegRef<X64::I32>(ABI.getMemorySize()));
      _ ja(getExceptLabel(ErrorCode::OutOfBoundsMemory));
    }
  }

public:
  //
  // templated method to handle operations
  //

  // in alphabetical order
  // binary operator
  template <WASMType Type, BinaryOperator Opr>
  Operand handleBinaryOpImpl(Operand LHS, Operand RHS) {
    constexpr X64::Type X64Type = getX64TypeFromWASMType<Type>();

    auto ResReg = toReg<X64Type, ScopedTempReg0>(LHS);

    BinaryOperatorImpl<X64Type, Opr>::emit(
        ASM, X64Reg::getRegRef<X64Type>(ResReg), RHS);

    auto Ret = getTempOperand(Type);
    mov<X64Type>(Ret, ResReg);
    return Ret;
  }

  // TODO: avoid redundant mov
  template <WASMType Type, UnaryOperator Opr>
  Operand handleBitCountOpImpl(Operand Op) {
    constexpr auto X64Type = getX64TypeFromWASMType<Type>();

    auto Ret = getTempOperand(Type);
    auto RegNum = Ret.isReg()
                      ? Ret.getReg()
                      : static_cast<X64::RegNum>(
                            Layout.getScopedTemp<X64Type, ScopedTempReg0>());

    mov<X64Type>(RegNum, Op);
    UnaryOperatorImpl<X64Type, Opr>::emit(ASM,
                                          X64Reg::getRegRef<X64Type>(RegNum));

    if (!Ret.isReg()) {
      mov<X64Type, ScopedTempReg0>(Ret,
                                   Operand(Type, RegNum, Operand::FLAG_NONE));
    }
    return Ret;
  }

  // compare operator
  template <WASMType Type, CompareOperator Opr>
  Operand handleCompareOpImpl(Operand LHS, Operand RHS) {
    constexpr X64::Type X64Type = getX64TypeFromWASMType<Type>();
    ZEN_ASSERT(LHS.getType() == Type);

    // make comparison
    bool Exchanged = false;
    if (Opr == CompareOperator::CO_EQZ) {
      ZEN_ASSERT(RHS.getType() == WASMType::VOID);
      ZEN_ASSERT(RHS.getKind() == OK_None);
      test<X64Type, ScopedTempReg1>(LHS);
    } else {
      cmp<X64Type, ScopedTempReg1>(LHS, RHS, Exchanged);
    }

    // allocate result register
    typename X64TypeAttr<X64::I32>::RegNum RegNum;
    bool HasTempReg = Layout.hasAvailTempReg<X64::I32>(RegNum);
    if (!HasTempReg) {
      RegNum = Layout.getScopedTemp<X64::I32, ScopedTempReg0>();
    } else {
      Layout.clearAvailReg<X64::I32>(RegNum);
    }
    // setcc to resulta
    if (!Exchanged) {
      setcc<Opr, true>(RegNum);
    } else {
      constexpr CompareOperator ExchangedOpr =
          getExchangedCompareOperator<Opr>();
      setcc<ExchangedOpr, true>(RegNum);
    }
    // make a sign-extension
    _ movsx(X64Reg::getRegRef<X64::I32>(RegNum),
            X64Reg::getRegRef<X64::I8>(RegNum));

    // handle NaN operands
    if (Type == WASMType::F32 || Type == WASMType::F64) {
      auto TmpReg = Layout.getScopedTempReg<X64::I32, ScopedTempReg1>();
      if (Opr == CompareOperator::CO_NE) {
        _ mov(TmpReg, 1);
      } else {
        _ mov(TmpReg, 0);
      }
      _ cmovp(X64Reg::getRegRef<X64::I32>(RegNum), TmpReg);
    }

    if (HasTempReg) {
      return Operand(WASMType::I32, RegNum, Operand::FLAG_TEMP_REG);
    }

    // store to stack
    Operand Ret = getTempStackOperand(WASMType::I32);
    ASM.mov<X64::I32>(Ret.getMem<X64::I32>(),
                      X64Reg::getRegRef<X64::I32>(RegNum));
    return Ret;
  }

  // constant
  template <WASMType Ty>
  Operand handleConstImpl(typename WASMTypeAttr<Ty>::Type Val) {
    if (Ty == WASMType::I32) {
      return X64InstOperand(WASMType::I32, Val);
    }
    if (Ty == WASMType::I64) {
      if (Val >= INT32_MIN && Val <= INT32_MAX) {
        return X64InstOperand(WASMType::I64, (int32_t)Val);
      }
      typename X64TypeAttr<X64::I64>::RegNum RegNum;
      bool HasTempReg = Layout.hasAvailTempReg<X64::I64>(RegNum);
      if (!HasTempReg) {
        RegNum = Layout.getScopedTemp<X64::I64, ScopedTempReg0>();
      } else {
        Layout.clearAvailReg<X64::I64>(RegNum);
      }
      _ movabs(X64Reg::getRegRef<X64::I64>(RegNum), Val);
      if (HasTempReg) {
        return Operand(WASMType::I64, RegNum, Operand::FLAG_TEMP_REG);
      }
      // store to stack
      Operand Ret = getTempStackOperand(WASMType::I64);
      ASM.mov<X64::I64>(Ret.getMem<X64::I64>(),
                        X64Reg::getRegRef<X64::I64>(RegNum));
      return Ret;
    }
    // allocate memory on stack and fill stack/return Mem on stack
    Operand Ret = getTempStackOperand(Ty);
    ZEN_ASSERT(Ret.isMem() && Ret.getBase() == ABI.getFrameBase());
    int32_t Offset = Ret.getOffset();
    if (sizeof(Val) == 4) {
      int32_t I32;
      memcpy(&I32, &Val, sizeof(int32_t));
      _ mov(asmjit::x86::Mem(ABI.getFrameBaseReg(), Offset, 4), I32);
    } else if (sizeof(Val) == 8) {
      int64_t I64;
      memcpy(&I64, &Val, sizeof(int64_t));
      _ mov(asmjit::x86::Mem(ABI.getFrameBaseReg(), Offset, 4), (int32_t)I64);
      _ mov(asmjit::x86::Mem(ABI.getFrameBaseReg(), Offset + 4, 4),
            (int32_t)(I64 >> 32));
    } else {
      ZEN_ASSERT_TODO();
    }
    return Ret;
  }

  // convert from SrcType to DestType (between integer and float-point)
  // TODO: error-handling and conversion to/from unsigned i64
  template <WASMType DestType, WASMType SrcType, bool Sext>
  Operand handleConvertImpl(Operand Op) {
    if (SrcType == WASMType::I64 && !Sext) {
      return convertFromU64<DestType>(Op);
    }

    constexpr auto X64DestType = getX64TypeFromWASMType<DestType>();
    constexpr auto X64SrcType = getX64TypeFromWASMType<SrcType>();

    auto Ret = getTempOperand(DestType);
    auto RetReg = Ret.isReg()
                      ? Ret.getRegRef<X64DestType>()
                      : Layout.getScopedTempReg<X64DestType, ScopedTempReg0>();
    if (!Op.isReg()) {
      auto RegNum = Layout.getScopedTemp<X64SrcType, ScopedTempReg1>();
      mov<X64SrcType>(RegNum, Op);
      Op = Operand(SrcType, RegNum, Operand::FLAG_NONE);
    }

    ConvertOpImpl<X64DestType, X64SrcType, Sext>::emit(
        ASM, RetReg, Op.getRegRef<X64SrcType>());

    if (!Ret.isReg()) {
      ASM.mov<X64DestType>(Ret.getMem<X64DestType>(), RetReg);
    }
    return Ret;
  }

  template <WASMType DestType> Operand convertFromU64(Operand Op) {
    ZEN_STATIC_ASSERT(isWASMTypeFloat<DestType>());
    constexpr auto X64DestType = getX64TypeFromWASMType<DestType>();

    if (!Op.isReg()) {
      auto RegNum = Layout.getScopedTemp<X64::I64, ScopedTempReg0>();
      mov<X64::I64>(RegNum, Op);
      Op = Operand(WASMType::I64, RegNum, Operand::FLAG_NONE);
    }
    auto OpReg = Op.getRegRef<X64::I64>();

    auto TmpReg = Layout.getScopedTempReg<X64::I64, ScopedTempReg1>();
    _ mov(TmpReg, OpReg);
    _ shr(TmpReg, 1);

    auto TmpReg2 = Layout.getScopedTempReg<X64::I64, ScopedTempReg2>();
    _ mov(TmpReg2, OpReg);
    _ and_(TmpReg2, 0x1);
    _ or_(TmpReg, TmpReg2);

    auto ResReg = Layout.getScopedTempReg<X64DestType, ScopedTempReg0>();
    auto ResRegNum = Layout.getScopedTemp<X64DestType, ScopedTempReg0>();
    ConvertOpImpl<X64DestType, X64::I64, false>::emit(ASM, ResReg, TmpReg);
    ASM.add<X64DestType>(ResReg, ResReg);

    auto Label = _ newLabel();
    _ test(OpReg, OpReg);
    _ js(Label);

    ConvertOpImpl<X64DestType, X64::I64, false>::emit(ASM, ResReg, OpReg);
    _ bind(Label);

    auto Ret = getTempOperand(DestType);
    mov<X64DestType, ScopedTempReg0>(
        Ret, Operand(DestType, ResRegNum, Operand::FLAG_NONE));
    return Ret;
  }

  // float div
  template <WASMType Type, BinaryOperator Opr>
  Operand handleFDivOpImpl(Operand LHS, Operand RHS) {
    ZEN_ASSERT(LHS.getType() == Type);
    ZEN_ASSERT(RHS.getType() == Type);
    ZEN_ASSERT(Type == WASMType::F32 || Type == WASMType::F64);

    constexpr X64::Type X64Type = getX64TypeFromWASMType<Type>();

    typedef typename X64TypeAttr<X64Type>::RegNum RegNum;

    bool LHSIsReg = true;
    if (!LHS.isReg()) {
      LHSIsReg = false;
      RegNum LHSReg = Layout.getScopedTemp<X64Type, ScopedTempReg0>();
      mov<X64Type>(LHSReg, LHS);
      LHS = Operand(Type, LHSReg, Operand::FLAG_NONE);
    } else {
      Layout.clearAvailReg<X64Type>((RegNum)LHS.getReg());
    }

    if (RHS.isImm()) {
      RegNum RHSReg = Layout.getScopedTemp<X64Type, ScopedTempReg1>();
      mov<X64Type>(RHSReg, RHS);
      RHS = Operand(Type, RHSReg, Operand::FLAG_NONE);
    }

    BinaryOperatorImpl<X64Type, Opr>::emit(ASM, LHS, RHS);

    if (LHSIsReg) {
      return LHS;
    }

    Operand Ret = getTempOperand(Type);
    mov<X64Type, ScopedTempReg0>(Ret, LHS);
    return Ret;
  }

  template <WASMType Type>
  Operand handleFloatCopysignImpl(Operand LHS, Operand RHS) {
    constexpr auto X64Type = getX64TypeFromWASMType<Type>();
    auto LHSRegNum = toReg<X64Type, ScopedTempReg0>(LHS);
    auto LHSReg = X64Reg::getRegRef<X64Type>(LHSRegNum);
    auto RHSRegNum = toReg<X64Type, ScopedTempReg1>(RHS);
    auto RHSReg = X64Reg::getRegRef<X64Type>(RHSRegNum);

    constexpr auto X64IntType =
        getX64TypeFromWASMType<FloatAttr<Type>::IntType>();
    auto ImmReg = Layout.getScopedTempReg<X64Type, ScopedTempReg2>();
    auto MaskReg = Layout.getScopedTempReg<X64IntType, ScopedTempReg0>();
    auto SignMask = FloatAttr<Type>::SignMask;

    _ mov(MaskReg, ~SignMask);
    ASM.fmov(ImmReg, MaskReg);
    ASM.and_<X64Type>(LHSReg, ImmReg);

    _ mov(MaskReg, SignMask);
    ASM.fmov(ImmReg, MaskReg);
    ASM.and_<X64Type>(RHSReg, ImmReg);

    ASM.or_<X64Type>(LHSReg, RHSReg);

    auto Ret = getTempOperand(Type);
    mov<X64Type>(Ret, LHSRegNum);
    return Ret;
  }

  template <WASMType Type, BinaryOperator Opr>
  Operand handleFloatMinMaxImpl(Operand LHS, Operand RHS) {
    ZEN_STATIC_ASSERT(isWASMTypeFloat<Type>());
    constexpr auto X64Type = getX64TypeFromWASMType<Type>();

    auto TmpReg = Layout.getScopedTempReg<X64Type, ScopedTempReg0>();
    auto TmpRegNum = Layout.getScopedTemp<X64Type, ScopedTempReg0>();
    auto TmpReg2 = Layout.getScopedTempReg<X64Type, ScopedTempReg2>();
    auto TmpRegNum2 = Layout.getScopedTemp<X64Type, ScopedTempReg2>();

    mov<X64Type>(TmpRegNum, LHS);
    BinaryOperatorImpl<X64Type, Opr>::emit(ASM, TmpReg, RHS);

    bool Exchanged = false;
    cmp<X64Type, ScopedTempReg1>(LHS, RHS, Exchanged);
    auto HandleNaN = _ newLabel();
    auto Finish = _ newLabel();
    _ jp(HandleNaN);
    _ jne(Finish);

    constexpr auto X64IntType =
        getX64TypeFromWASMType<FloatAttr<Type>::IntType>();
    auto IntReg = Layout.getScopedTempReg<X64IntType, ScopedTempReg0>();
    auto IntReg2 = Layout.getScopedTempReg<X64IntType, ScopedTempReg1>();

    // handle 0.0 vs -0.0
    mov<X64Type>(TmpRegNum2, LHS);
    _ mov(IntReg, Opr == BinaryOperator::BO_MIN ? FloatAttr<Type>::NegZero : 0);
    ASM.fmov(IntReg2, TmpReg2);
    _ cmp(IntReg, IntReg2);
    _ jne(Finish);
    mov<X64Type>(TmpRegNum, LHS);
    _ jmp(Finish);

    _ bind(HandleNaN);
    auto CanonicalNaN = FloatAttr<Type>::CanonicalNan;
    _ mov(IntReg, CanonicalNaN);
    ASM.fmov(TmpReg, IntReg);

    _ bind(Finish);
    auto Ret = getTempOperand(Type);
    mov<X64Type, ScopedTempReg0>(Ret,
                                 Operand(Type, TmpRegNum, Operand::FLAG_NONE));
    return Ret;
  }

  // integer div
  template <WASMType Type, BinaryOperator Opr>
  Operand handleIDivOpImpl(Operand LHS, Operand RHS) {
    ZEN_ASSERT(LHS.getType() == Type);
    ZEN_ASSERT(RHS.getType() == Type);
    ZEN_ASSERT(Type == WASMType::I32 || Type == WASMType::I64);

    constexpr X64::Type X64Type = getX64TypeFromWASMType<Type>();

    constexpr bool IsUnsigned =
        (Opr == BinaryOperator::BO_DIV_U || Opr == BinaryOperator::BO_REM_U);
    constexpr bool IsRem =
        (Opr == BinaryOperator::BO_REM_U || Opr == BinaryOperator::BO_REM_S);

    uint32_t NormalPathLabel = 0;
    uint32_t EndLabel = 0;

    Operand Ret = getTempOperand(Type);
    bool Exchanged = false;

    // rem_s
    if (!IsUnsigned) {
      NormalPathLabel = createLabel();
      EndLabel = createLabel();

      Operand CmpOpnd;
      if (X64Type == X64::I32) {
        CmpOpnd = Operand(Type, 0x80000000U);
      } else {
        auto RegNum = Layout.getScopedTemp<X64Type, ScopedTempReg0>();
        _ movabs(X64Reg::getRegRef<X64::I64>(RegNum), 0x8000000000000000ULL);
        CmpOpnd = Operand(Type, RegNum, Operand::FLAG_NONE);
      }

      cmp<X64Type, ScopedTempReg1>(LHS, CmpOpnd, Exchanged);
      jne(NormalPathLabel);

      if (X64Type == X64::I32) {
        CmpOpnd = Operand(Type, 0xffffffffU);
      } else {
        auto RegNum = Layout.getScopedTemp<X64Type, ScopedTempReg0>();
        _ movabs(X64Reg::getRegRef<X64::I64>(RegNum), 0xffffffffffffffffULL);
        CmpOpnd = Operand(Type, RegNum, Operand::FLAG_NONE);
      }

      cmp<X64Type, ScopedTempReg1>(RHS, CmpOpnd, Exchanged);
      jne(NormalPathLabel);

      if (IsRem) {
        mov<X64Type, ScopedTempReg0>(Ret, Operand(Type, 0));
        branch(EndLabel);
      } else {
        _ jmp(getExceptLabel(ErrorCode::IntegerOverflow));
      }

      bindLabel(NormalPathLabel);
    }

#ifndef ZEN_ENABLE_CPU_EXCEPTION
    cmp<X64Type, ScopedTempReg1>(RHS, Operand(Type, 0), Exchanged);
    _ je(getExceptLabel(ErrorCode::IntegerDivByZero));
#endif // ZEN_ENABLE_CPU_EXCEPTION

    mov<X64Type>(X64::RAX, LHS);
    if (IsUnsigned) {
      auto RDXReg = X64Reg::getRegRef<X64Type>(X64::GP::RDX);
      ASM.xor_<X64Type>(RDXReg, RDXReg);
    } else if (X64Type == X64::I32) {
      ASM.cdq();
    } else if (X64Type == X64::I64) {
      ASM.cqo();
    }

    if (!RHS.isReg()) {
      mov<X64Type>(X64::RCX, RHS);
      RHS = Operand(Type, X64::RCX, Operand::FLAG_NONE);
    }

    BinaryOperatorImpl<X64Type, Opr>::emit(ASM, RHS, RHS);

    if (IsRem) {
      mov<X64Type, ScopedTempReg0>(Ret,
                                   Operand(Type, X64::RDX, Operand::FLAG_NONE));
    } else {
      mov<X64Type, ScopedTempReg0>(Ret,
                                   Operand(Type, X64::RAX, Operand::FLAG_NONE));
    }

    // rem_s
    if (!IsUnsigned && IsRem) {
      bindLabel(EndLabel);
    }

    return Ret;
  }

  template <WASMType DestType, WASMType SrcType, bool Sext>
  Operand handleFloatToIntImpl(Operand Op) {
    // tag dispatch
    return handleFloatToIntImpl<DestType, SrcType>(
        Op, std::integral_constant<bool, Sext>());
  }

  // extend from stype to dtype in same type kind (integer or floating-point)
  template <WASMType DestType, WASMType SrcType, bool Sext>
  Operand handleIntExtendImpl(Operand Op) {
    constexpr auto X64DestType = getX64TypeFromWASMType<DestType>();
    constexpr auto X64SrcType = getX64TypeFromWASMType<SrcType>();

    auto Ret = getTempOperand(DestType);
    auto RegNum = Layout.getScopedTemp<X64DestType, ScopedTempReg0>();
    auto RetReg = Ret.isReg() ? Ret.getRegRef<X64DestType>()
                              : X64Reg::getRegRef<X64DestType>(RegNum);

    using ExtendOp = ExtendOperatorImpl<X64DestType, X64SrcType, Sext>;
    if (Op.isImm()) {
      auto RegNum2 = Layout.getScopedTemp<X64SrcType, ScopedTempReg1>();
      auto TmpReg = X64Reg::getRegRef<X64SrcType>(RegNum2);
      _ mov(TmpReg, Op.getImm());
      ExtendOp::emit(ASM, RetReg, TmpReg);
    } else if (Op.isReg()) {
      ExtendOp::emit(ASM, RetReg, Op.getRegRef<X64SrcType>());
    } else {
      ExtendOp::emit(ASM, RetReg, Op.getMem<X64SrcType>());
    }

    if (Ret.isMem()) {
      _ mov(Ret.getMem<X64DestType>(), RetReg);
    }
    return Ret;
  }

  // fused compare and branch
  template <WASMType CondType, CompareOperator Opr, bool TrueBr>
  void handleFusedCompareBranchImpl(Operand CmpLHS, Operand CmpRHS,
                                    uint32_t Label) {
    constexpr X64::Type X64CondType = getX64TypeFromWASMType<CondType>();
    ZEN_ASSERT(CmpLHS.getType() == CondType);

    // make comparison
    bool Exchanged = false;
    if (Opr == CompareOperator::CO_EQZ) {
      ZEN_ASSERT(CmpRHS.getType() == WASMType::VOID);
      ZEN_ASSERT(CmpRHS.getKind() == OK_None);
      test<X64CondType, ScopedTempReg1>(CmpLHS);
    } else {
      cmp<X64CondType, ScopedTempReg1>(CmpLHS, CmpRHS, Exchanged);
    }

    if (!Exchanged) {
      jmpcc<Opr, TrueBr>(Label);
    } else {
      constexpr CompareOperator ExchangedOpr =
          getExchangedCompareOperator<Opr>();
      jmpcc<ExchangedOpr, TrueBr>(Label);
    }
  }

  // fused compare and select
  template <WASMType CondType, CompareOperator Opr>
  Operand handleFusedCompareSelectImpl(Operand CmpLHS, Operand CmpRHS,
                                       Operand LHS, Operand RHS) {
    constexpr X64::Type X64CondType = getX64TypeFromWASMType<CondType>();
    ZEN_ASSERT(CmpLHS.getType() == CondType);

    // make comparison
    bool Exchanged = false;
    if (Opr == CompareOperator::CO_EQZ) {
      ZEN_ASSERT(CmpRHS.getType() == WASMType::VOID);
      ZEN_ASSERT(CmpRHS.getKind() == OK_None);
      test<X64CondType, ScopedTempReg1>(CmpLHS);
    } else {
      cmp<X64CondType, ScopedTempReg1>(CmpLHS, CmpRHS, Exchanged);
    }

    ZEN_ASSERT(LHS.getType() == RHS.getType());
    switch (LHS.getType()) {
    // TODO: use cmov for integer type
    case WASMType::I32:
      return fusedCompareSelectWithIf<WASMType::I32, Opr>(LHS, RHS, Exchanged);
    case WASMType::I64:
      return fusedCompareSelectWithIf<WASMType::I64, Opr>(LHS, RHS, Exchanged);
    case WASMType::F32:
      return fusedCompareSelectWithIf<WASMType::F32, Opr>(LHS, RHS, Exchanged);
    case WASMType::F64:
      return fusedCompareSelectWithIf<WASMType::F64, Opr>(LHS, RHS, Exchanged);
    default:
      ZEN_ABORT();
    }
  }

  // load value from memory
  template <X64::Type DestType, X64::Type SrcType = DestType, bool Sext = false>
  void loadRegFromMem(X64::RegNum Val, asmjit::x86::Mem Mem) {
    LoadOperatorImpl<DestType, SrcType, Sext>::emit(ASM, Val, Mem);
  }

  // store value to memory
  template <X64::Type Ty>
  void storeRegToMem(X64::RegNum Val, asmjit::x86::Mem Mem) {
    ASM.mov<Ty>(Mem, X64Reg::getRegRef<Ty>(Val));
  }

  // store value to memory
  template <X64::Type Ty, uint32_t TempRegIndex>
  void storeImmToMem(uint32_t Val, asmjit::x86::Mem Mem) {
    ASM.mov<Ty>(Mem, Val);
  }

  // load from memory in SrcType and return in DestType
  template <WASMType DestType, WASMType SrcType, bool Sext>
  Operand handleLoadImpl(Operand Base, uint32_t Offset, uint32_t Align) {
    constexpr X64::Type X64DestType = getX64TypeFromWASMType<DestType>();
    constexpr X64::Type X64SrcType = getX64TypeFromWASMType<SrcType>();
    constexpr X64::Type AddrType =
        getX64TypeFromWASMType<X64OnePassABI::WASMAddrType>();
    ZEN_ASSERT(Base.getType() == X64OnePassABI::WASMAddrType);

    checkMemoryOverflow<SrcType>(Base, Offset);

    typename X64TypeAttr<AddrType>::RegNum BaseReg =
        X64::RAX; // the initial value only used to suppress compiler error

    asmjit::x86::Mem Addr;
    if (Base.isReg()) {
      BaseReg = (typename X64TypeAttr<AddrType>::RegNum)Base.getReg();
    } else if (Base.isMem()) {
      BaseReg = Layout.getScopedTemp<AddrType, ScopedTempReg1>();
      ASM.mov<AddrType>(X64Reg::getRegRef<AddrType>(BaseReg),
                        Base.getMem<AddrType>());
    } else if (Base.isImm()) {
      uint64_t Offset64 = (uint64_t)Offset;
      Offset64 += (uint32_t)Base.getImm();
      if (Offset64 > INT32_MAX) {
        Offset = INT32_MAX; // invalid addr
      } else {
        Offset = (uint32_t)Offset64;
      }
    } else {
      ZEN_ABORT();
    }

    typename X64TypeAttr<X64DestType>::RegNum ValReg;
    bool HasTempReg = Layout.hasAvailTempReg<X64DestType>(ValReg);
    if (!HasTempReg) {
      ValReg = Layout.getScopedTemp<X64DestType, ScopedTempReg0>();
    }

    Addr = Base.isImm()
               ? asmjit::x86::Mem(ABI.getMemoryBaseReg(), Offset,
                                  getWASMTypeSize<SrcType>())
               : asmjit::x86::Mem(ABI.getMemoryBaseReg(),
                                  X64Reg::getRegRef<X64::I32>(BaseReg), 0,
                                  Offset, getWASMTypeSize<SrcType>());

#ifdef ZEN_ENABLE_CPU_EXCEPTION
    if (!Base.isImm() && (Offset >= INT32_MAX)) {
      // when offset >= INT32_MAX, then will cause inst like mov edi, dword
      // ptr[r13+edi-1].
      auto MemAddrReg = Layout.getScopedTemp<AddrType, ScopedTempReg2>();
      _ mov(X64Reg::getRegRef<X64::I32>(MemAddrReg), Offset);
      _ add(X64Reg::getRegRef<X64::I64>(MemAddrReg),
            X64Reg::getRegRef<X64::I64>(BaseReg));
      _ add(X64Reg::getRegRef<X64::I64>(MemAddrReg), ABI.getMemoryBaseReg());
      Addr = asmjit::x86::Mem(X64Reg::getRegRef<X64::I64>(MemAddrReg), 0,
                              getWASMTypeSize(SrcType));
    }
#endif // ZEN_ENABLE_CPU_EXCEPTION

    LoadOperatorImpl<X64DestType, X64SrcType, Sext>::emit(
        ASM, X64Reg::getRegRef<X64DestType>(ValReg), Addr);
    if (HasTempReg) {
      Layout.clearAvailReg<X64DestType>(ValReg);
      return Operand(DestType, ValReg, Operand::FLAG_TEMP_REG);
    }
    Operand Ret = getTempStackOperand(DestType);
    ASM.mov<X64DestType>(Ret.getMem<X64DestType>(),
                         X64Reg::getRegRef<X64DestType>(ValReg));
    return Ret;
  }

  // shift
  template <WASMType Type, BinaryOperator Opr>
  Operand handleShiftOpImpl(Operand LHS, Operand RHS) {
    ZEN_ASSERT(LHS.getType() == Type);
    ZEN_ASSERT(RHS.getType() == Type);
    constexpr X64::Type X64Type = getX64TypeFromWASMType<Type>();

    auto ResReg = toReg<X64Type, ScopedTempReg0>(LHS);

    if (RHS.isMem() || RHS.isReg()) {
      mov<X64Type>(X64::RCX, RHS);
      RHS = Operand(Type, X64::RCX, Operand::FLAG_NONE);
    }

    BinaryOperatorImpl<X64Type, Opr>::emit(
        ASM, X64Reg::getRegRef<X64Type>(ResReg), RHS);

    auto Ret = getTempOperand(Type);
    mov<X64Type>(Ret, ResReg);

    return Ret;
  }

  // store value to memory in Type
  template <WASMType Type>
  void handleStoreImpl(Operand Value, Operand Base, uint32_t Offset,
                       uint32_t Align) {
    constexpr X64::Type X64Type = getX64TypeFromWASMType<Type>();
    constexpr X64::Type AddrType =
        getX64TypeFromWASMType<X64OnePassABI::WASMAddrType>();
    ZEN_ASSERT(Base.getType() == X64OnePassABI::WASMAddrType);

    checkMemoryOverflow<Type>(Base, Offset);

    X64::RegNum RegNum = 0;
    if (Base.isReg()) {
      RegNum = Base.getReg();
    } else if (Base.isMem()) {
      RegNum = Layout.getScopedTemp<AddrType, ScopedTempReg1>();
      ASM.mov<AddrType>(X64Reg::getRegRef<AddrType>(RegNum),
                        Base.getMem<AddrType>());
    } else if (Base.isImm()) {
      uint64_t Offset64 = (uint64_t)Offset;
      Offset64 += (uint32_t)Base.getImm();
      if (Offset64 > INT32_MAX) {
        Offset = INT32_MAX; // invalid addr
      } else {
        Offset = (uint32_t)Offset64;
      }
    } else {
      ZEN_ABORT();
    }

    // Addr = memoryBase + (in64) offset, so when offset < 0,
    // the result i32 Addr works like add (2**32 + offset)
    asmjit::x86::Mem Addr =
        Base.isImm() ? asmjit::x86::Mem(ABI.getMemoryBaseReg(), Offset,
                                        getWASMTypeSize<Type>())
                     : asmjit::x86::Mem(ABI.getMemoryBaseReg(),
                                        X64Reg::getRegRef<X64::I32>(RegNum), 0,
                                        Offset, getWASMTypeSize<Type>());

    mov<X64Type, ScopedTempReg0>(Addr, Value);
  }

  Operand handleIntTruncImpl(Operand Op) {
    auto Src = toReg<X64::I64, ScopedTempReg0>(Op);
    auto Dest = getTempOperand(WASMType::I32);
    mov<X64::I32, false>(Dest, Src);
    return Dest;
  }

  // floating-point unary operators
  template <WASMType Type, UnaryOperator Opr>
  Operand handleUnaryOpImpl(Operand Op) {
    ZEN_STATIC_ASSERT(Type == WASMType::F32 || Type == WASMType::F64);
    switch (Opr) {
    case UnaryOperator::UO_ABS:
      return floatAbs<Type>(Op);
    case UnaryOperator::UO_NEG:
      return floatNeg<Type>(Op);
    case UnaryOperator::UO_SQRT:
      return floatSqrt<Type>(Op);
    case UnaryOperator::UO_CEIL:
    case UnaryOperator::UO_FLOOR:
    case UnaryOperator::UO_NEAREST:
    case UnaryOperator::UO_TRUNC:
      return floatRound<Type, Opr>(Op);
    default:
      ZEN_ABORT();
    }
  }

public:
  //
  // branch, call and return instructions
  //

  // in alphabetical order
  // branch to given label
  void branch(uint32_t LabelIdx) {
    asmjit::Label L(LabelIdx);
    _ jmp(L);
  }

  void branchLTU(uint32_t LabelIdx) { _ jb(asmjit::Label(LabelIdx)); }

  // branch to label if cond is false
  void branchFalse(Operand Cond, uint32_t LabelIdx) {
    ZEN_ASSERT(Cond.getType() == WASMType::I32 ||
               Cond.getType() == WASMType::I64);
    asmjit::Label L(LabelIdx);
    if (!Cond.isImm()) {
      test<ScopedTempReg1>(Cond);
      _ je(L);
    } else if (!Cond.getImm()) {
      _ jmp(L);
    }
  }

  // branch to label if cond is true
  void branchTrue(Operand Cond, uint32_t LabelIdx) {
    ZEN_ASSERT(Cond.getType() == WASMType::I32 ||
               Cond.getType() == WASMType::I64);
    asmjit::Label L(LabelIdx);
    if (!Cond.isImm()) {
      test<ScopedTempReg1>(Cond);
      _ jne(L);
    } else if (Cond.getImm()) {
      _ jmp(L);
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
      asmjit::Label L(LabelIdxs[IndexImm]);
      _ jmp(L);
      return;
    }

    // load index into register if necessary
    auto IndexReg = Index.isReg()
                        ? Index.getRegRef<X64::I32>()
                        : Layout.getScopedTempReg<X64::I32, ScopedTempReg1>();
    if (!Index.isReg()) {
      _ mov(IndexReg, Index.getMem<X64::I32>());
    }
    // compare index with bound
    _ cmp(IndexReg, Bound);
    // jump to default label if index >= bound
    _ jae(asmjit::Label(LabelIdxs[Bound]));

    // for small tables, generate if (index == i) goto i;
    switch (Bound) {
    case 4:
      _ cmp(IndexReg, 3);
      _ je(asmjit::Label(LabelIdxs[3]));
      // fall through
    case 3:
      _ cmp(IndexReg, 2);
      _ je(asmjit::Label(LabelIdxs[2]));
      // fall through
    case 2:
      _ cmp(IndexReg, 1);
      _ je(asmjit::Label(LabelIdxs[1]));
      // fall through
    case 1:
      _ cmp(IndexReg, 0);
      _ je(asmjit::Label(LabelIdxs[0]));
      return;
    default:
      break;
    }

    // jump to entry in jump table
    uint32_t Table = createLabel();
    auto JmpReg = Layout.getScopedTempReg<X64::I64, ScopedTempReg2>();
    _ lea(JmpReg, asmjit::x86::ptr(asmjit::Label(Table)));
    _ jmp(
        asmjit::x86::Mem(JmpReg, IndexReg, sizeof(uintptr_t) == 4 ? 2 : 3, 0));
    emitJumpTable(Table, LabelIdxs);
  }

  // call

  Operand handleCallImpl(uint32_t FuncIdx, uintptr_t Target, bool IsImport,
                         bool FarCall, const ArgumentInfo &ArgInfo,
                         const std::vector<Operand> &Args) {
    return emitCall(
        ArgInfo, Args, [this] { saveGasVal(); },
        [&]() {

#ifdef ZEN_ENABLE_DWASM
          // if is_import, update WasmInstance::is_host_api
          if (IsImport) {
            auto InHostAPIFlagAddr = asmjit::x86::ptr(
                ABI.getModuleInstReg(), InHostApiOffset, InHostApiSize);
            _ mov(InHostAPIFlagAddr, 1);
          }
#endif

          // generate call, emit call or record relocation for patching
          if (Target) {
            _ call(Target);
          } else {
            size_t Offset = _ offset();
            _ dw(0);
            _ dd(0); // reserve 6 bytes
            ZEN_ASSERT(_ offset() - Offset == 6);
            Patcher.addCallEntry(Offset, _ offset() - Offset, FuncIdx);
          }
        },
        [this, IsImport]() {
          loadGasVal();
          checkCallException(IsImport);

#ifdef ZEN_ENABLE_DWASM
          // if is_import, update WasmInstance::is_host_api
          if (IsImport) {
            auto InHostAPIFlagAddr = asmjit::x86::ptr(
                ABI.getModuleInstReg(), InHostApiOffset, InHostApiSize);
            _ mov(InHostAPIFlagAddr, 0);
          }
#endif
        });
  }

  // call indirect
  Operand handleCallIndirectImpl(uint32_t TypeIdx, Operand Callee,
                                 uint32_t TblIdx, const ArgumentInfo &ArgInfo,
                                 const std::vector<Operand> &Arg) {
    uint32_t NumHostAPIs = Ctx->Mod->getNumImportFunctions();
    return emitCall(
        ArgInfo, Arg,
        // prepare call, check and load callee address into %rax (return
        // reg)
        [this, NumHostAPIs, TypeIdx, Callee, TblIdx]() {
          saveGasVal();

          auto FuncIdxReg = Layout.getScopedTemp<X64::I32, ScopedTempReg0>();

          auto FuncIdx = X64Reg::getRegRef<X64::I32>(FuncIdxReg);

          emitTableGet(TblIdx, Callee, FuncIdxReg);

          auto InstReg = ABI.getModuleInstReg();

          _ cmp(FuncIdx, -1);
          _ je(getExceptLabel(ErrorCode::UninitializedElement));

          constexpr uint32_t Shift0 = 2;
          auto IndexesBaseOffset =
              Ctx->Mod->getLayout().FuncTypeIndexesBaseOffset;
          asmjit::x86::Mem TypeIdxAddr(InstReg, FuncIdx, Shift0,
                                       IndexesBaseOffset, sizeof(TypeIdx));

          _ cmp(TypeIdxAddr, TypeIdx);
          _ jne(getExceptLabel(ErrorCode::IndirectCallTypeMismatch));

#ifdef ZEN_ENABLE_DWASM
          // check func_idx < import_funcs_count (is_import)
          // if is_import, update WasmInstance::is_host_api
          auto UpdateFlagLabel = createLabel();
          auto EndUpdateFlagLabel = createLabel();

          _ cmp(FuncIdx, NumHostAPIs);
          branchLTU(UpdateFlagLabel);
          branch(EndUpdateFlagLabel);

          bindLabel(UpdateFlagLabel);
          auto InHostAPIFlagAddr = asmjit::x86::ptr(
              ABI.getModuleInstReg(), InHostApiOffset, InHostApiSize);
          _ mov(InHostAPIFlagAddr, 1);

          bindLabel(EndUpdateFlagLabel);
#endif

          auto FuncPtr = ABI.getCallTargetReg();
          constexpr uint32_t Shift = sizeof(void *) == 4 ? 2 : 3;
          asmjit::x86::Mem FuncPtrAddr(
              InstReg, FuncIdx, Shift,
              Ctx->Mod->getLayout().FuncPtrsBaseOffset);

          _ mov(FuncPtr, FuncPtrAddr);
        },
        // generate call
        [&]() { _ call(ABI.getCallTargetReg()); },
        [this]() {
          loadGasVal();
          checkCallIndirectException();

#ifdef ZEN_ENABLE_DWASM
          // because func_idx reg not available in post_call
          // so just update the flag directly now(have performance cost)
          auto InHostAPIFlagAddr = asmjit::x86::ptr(
              ABI.getModuleInstReg(), InHostApiOffset, InHostApiSize);
          _ mov(InHostAPIFlagAddr, 0); // update flag back
#endif
        });
  }

  // branch to label if ZF is set
  void je(uint32_t LabelIdx) {
    asmjit::Label L(LabelIdx);
    _ je(L);
  }

  // branch to label if ZF is 1
  void jne(uint32_t LabelIdx) {
    asmjit::Label L(LabelIdx);
    _ jne(L);
  }

  // return
  void handleReturnImpl(Operand Op) { emitEpilog(Op); }

  // unreachable
  void handleUnreachableImpl() {
    _ jmp(getExceptLabel(ErrorCode::Unreachable));
  }

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

    X64ArgumentInfo ArgInfo(&SigBuf);
    std::vector<Operand> Args({Op});
    return emitCall(
        ArgInfo, Args,
        []() {
          // prepare call, no nothing
        },
        [this]() {
          // generate call, emit call to wasm_enlarge_memory_wrapper
          _ call(uintptr_t(Instance::growInstanceMemoryOnJIT));
          asmjit::Label CallFail = _ newLabel();
          _ cmp(ABI.getRetReg<X64::I32>(), 0);
          _ jl(CallFail); // less than 0, jump to call fail
          // call success, update r13 for mem base, r12 for mem size
          auto InstReg = ABI.getModuleInstReg();
          _ mov(ABI.getMemorySizeReg(),
                asmjit::x86::Mem(InstReg,
                                 Ctx->Mod->getLayout().MemorySizeOffset));
          _ mov(ABI.getMemoryBaseReg(),
                asmjit::x86::Mem(InstReg,
                                 Ctx->Mod->getLayout().MemoryBaseOffset));
          _ bind(CallFail);
        },
        [] {});
  }

  // memory size
  Operand handleMemorySizeImpl() {
    Operand Ret = getTempOperand(WASMType::I32);
    const auto &RetReg =
        Ret.isReg() ? Ret.getRegRef<X64::I32>()
                    : Layout.getScopedTempReg<X64::I32, ScopedTempReg1>();
    // Mov r12 to retReg and shift 16 (64KB)
    _ mov(RetReg, X64Reg::getRegRef<X64::I32>(ABI.getMemorySize()));
    _ shr(RetReg, 16);
    if (Ret.isMem()) {
      // mov retReg to return memory
      _ mov(Ret.getMem<X64::I32>(), RetReg);
    }
    return Ret;
  }

  // select
  Operand handleSelectImpl(Operand Cond, Operand LHS, Operand RHS) {
    ZEN_ASSERT(LHS.getType() == RHS.getType());
    ZEN_ASSERT(Cond.getType() == WASMType::I32 ||
               Cond.getType() == WASMType::I64);
    switch (LHS.getType()) {
    case WASMType::I32:
      return selectWithCMov<WASMType::I32>(Cond, LHS, RHS);
    case WASMType::I64:
      return selectWithCMov<WASMType::I64>(Cond, LHS, RHS);
    case WASMType::F32:
      return selectWithIf<WASMType::F32>(Cond, LHS, RHS);
    case WASMType::F64:
      return selectWithIf<WASMType::F64>(Cond, LHS, RHS);
    default:
      ZEN_ABORT();
    }
  }

private:
  // select, return value in type
  // test   cond
  // mov    rhs, res
  // cmovne lhs, rhs
  template <WASMType Type>
  Operand selectWithCMov(Operand Cond, Operand LHS, Operand RHS) {
    // handle condition
    test<ScopedTempReg1>(Cond);

    constexpr X64::Type X64Type = getX64TypeFromWASMType<Type>();
    typename X64TypeAttr<X64Type>::RegNum ResReg;
    bool Exchanged = false;
    if (LHS.isReg() && LHS.isTempReg()) {
      // reuse lhs as return value
      ResReg = (typename X64TypeAttr<X64Type>::RegNum)LHS.getReg();
      Layout.clearAvailReg<X64Type>(ResReg);
    } else if (RHS.isReg() && RHS.isTempReg()) {
      // reuse rhs as return value
      ResReg = (typename X64TypeAttr<X64Type>::RegNum)RHS.getReg();
      Layout.clearAvailReg<X64Type>(ResReg);
      Exchanged = true;
    } else if (LHS.isImm()) {
      // need a scoped temp for result, load lhs to temp at first
      ResReg = Layout.getScopedTemp<X64Type, ScopedTempReg0>();
      mov<X64Type>(ResReg, LHS);
    } else {
      // need a scoped temp for result, load rhs to temp at first
      ResReg = Layout.getScopedTemp<X64Type, ScopedTempReg0>();
      mov<X64Type>(ResReg, RHS);
      Exchanged = true;
    }

    // cmov rhs to lhsReg
    Exchanged ? cmovne<X64Type, ScopedTempReg1>(ResReg, LHS)
              : cmove<X64Type, ScopedTempReg1>(ResReg, RHS);

    if (ResReg != Layout.getScopedTemp<X64Type, ScopedTempReg0>()) {
      return Exchanged ? RHS : LHS;
    }

    // store lhsReg to return operand
    typename X64TypeAttr<X64Type>::RegNum RetReg;
    Operand Ret;
    if (Layout.hasAvailTempReg<X64Type>(RetReg)) {
      Ret = Operand(Type, RetReg, Operand::FLAG_TEMP_REG);
      Layout.clearAvailReg<X64Type>(RetReg);
      ASM.mov<X64Type>(X64Reg::getRegRef<X64Type>(RetReg),
                       X64Reg::getRegRef<X64Type>(ResReg));
    } else {
      Ret = getTempStackOperand(Type);
      ASM.mov<X64Type>(Ret.getMem<X64Type>(),
                       X64Reg::getRegRef<X64Type>(ResReg));
    }
    return Ret;
  }

  template <WASMType Type>
  Operand selectWithIf(Operand Cond, Operand LHS, Operand RHS) {
    auto Ret = getTempOperand(Type);
    constexpr auto X64Type = getX64TypeFromWASMType<Type>();
    auto RegNum = Layout.getScopedTemp<X64Type, ScopedTempReg0>();

    auto Label = createLabel();
    mov<X64Type>(RegNum, LHS);
    test<ScopedTempReg1>(Cond);
    jne(Label);
    mov<X64Type>(RegNum, RHS);
    bindLabel(Label);

    ZEN_ASSERT(!Ret.isImm());
    mov<X64Type, ScopedTempReg0>(Ret,
                                 Operand(Type, RegNum, Operand::FLAG_NONE));
    return Ret;
  }

  template <WASMType Type, CompareOperator Opr>
  Operand fusedCompareSelectWithIf(Operand LHS, Operand RHS, bool Exchanged) {
    auto Ret = getTempOperand(Type);
    constexpr auto X64Type = getX64TypeFromWASMType<Type>();
    auto RegNum = Layout.getScopedTemp<X64Type, ScopedTempReg0>();

    auto Label = createLabel();
    mov<X64Type>(RegNum, LHS);

    if (Exchanged) {
      constexpr auto ExchangedOpr = getExchangedCompareOperator<Opr>();
      jmpcc<ExchangedOpr, true>(Label);
    } else {
      jmpcc<Opr, true>(Label);
    }

    mov<X64Type>(RegNum, RHS);
    bindLabel(Label);

    ZEN_ASSERT(!Ret.isImm());
    mov<X64Type, ScopedTempReg0>(Ret,
                                 Operand(Type, RegNum, Operand::FLAG_NONE));
    return Ret;
  }

private:
  //
  // helper functions, move to op_assembler_x64.h?
  //

  // conditional move value from rhs (reg, mem, imm to lhs (reg only)
  template <X64::Type Ty, uint32_t TempRegIndex>
  void cmove(X64::RegNum LHS, Operand RHS) {
    typedef typename X64TypeAttr<Ty>::Type RegType;
    const RegType &LHSReg = X64Reg::getRegRef<Ty>(LHS);
    if (RHS.isReg()) {
      _ cmove(LHSReg, RHS.getRegRef<Ty>());
    } else if (RHS.isMem()) {
      _ cmove(LHSReg, RHS.getMem<Ty>());
    } else if (RHS.isImm()) {
      auto Tmp = Layout.getScopedTempReg<Ty, TempRegIndex>();
      ASM.mov<Ty>(Tmp, RHS.getImm());
      _ cmove(LHSReg, Tmp);
    } else {
      ZEN_ABORT();
    }
  }

  // conditional move value from rhs (reg, mem, imm to lhs (reg only)
  template <X64::Type Ty, uint32_t TempRegIndex>
  void cmovne(X64::RegNum LHS, Operand RHS) {
    typedef typename X64TypeAttr<Ty>::Type RegType;
    const RegType &LHSReg = X64Reg::getRegRef<Ty>(LHS);
    if (RHS.isReg()) {
      _ cmovne(LHSReg, RHS.getRegRef<Ty>());
    } else if (RHS.isMem()) {
      _ cmovne(LHSReg, RHS.getMem<Ty>());
    } else if (RHS.isImm()) {
      auto Tmp = Layout.getScopedTempReg<Ty, TempRegIndex>();
      ASM.mov<Ty>(Tmp, RHS.getImm());
      _ cmovne(LHSReg, Tmp);
    } else {
      ZEN_ABORT();
    }
  }

  // get an operand in register, using a scoped temp if necessary
  template <X64::Type Ty, uint32_t Temp> X64::RegNum toReg(Operand Op) {
    if (Op.isReg()) {
      return Op.getReg();
    }
    auto TmpReg = Layout.getScopedTemp<Ty, Temp>();
    mov<Ty>(TmpReg, Op);
    return TmpReg;
  }

  // compare value
  template <X64::Type Ty, uint32_t TempRegIndex>
  void cmp(Operand LHS, Operand RHS, bool &Exchanged) {
    // floating-point constants are stored on stack
    ZEN_ASSERT(Ty == X64::I32 || Ty == X64::I64 ||
               (!LHS.isImm() && !RHS.isImm()));

    // in case the caller forgets to initialize this parameter
    Exchanged = false;

    if (LHS.isReg()) {
      if (RHS.isReg()) {
        ASM.cmp<Ty>(LHS.getRegRef<Ty>(), RHS.getRegRef<Ty>());
      } else if (RHS.isMem()) {
        ASM.cmp<Ty>(LHS.getRegRef<Ty>(), RHS.getMem<Ty>());
      } else {
        ASM.cmp<Ty>(LHS.getRegRef<Ty>(), RHS.getImm());
      }
    } else if (LHS.isMem()) {
      if (RHS.isReg()) {
        Exchanged = true;
        ASM.cmp<Ty>(RHS.getRegRef<Ty>(), LHS.getMem<Ty>());
      } else if (RHS.isMem()) {
        auto Reg = Layout.getScopedTempReg<Ty, TempRegIndex>();
        ASM.mov<Ty>(Reg, LHS.getMem<Ty>());
        ASM.cmp<Ty>(Reg, RHS.getMem<Ty>());
      } else {
        ASM.cmp<Ty>(LHS.getMem<Ty>(), RHS.getImm());
      }
    } else {
      if (RHS.isReg()) {
        Exchanged = true;
        ASM.cmp<Ty>(RHS.getRegRef<Ty>(), LHS.getImm());
      } else if (RHS.isMem()) {
        Exchanged = true;
        ASM.cmp<Ty>(RHS.getMem<Ty>(), LHS.getImm());
      } else {
        auto Reg = Layout.getScopedTempReg<Ty, TempRegIndex>();
        ASM.mov<Ty>(Reg, LHS.getImm());
        ASM.cmp<Ty>(Reg, RHS.getImm());
      }
    }
  }

  // test single value with 0
  template <X64::Type Ty, uint32_t TempRegIndex> void test(Operand Op) {
    if (Op.isReg()) {
      auto Reg = Op.getRegRef<Ty>();
      ASM.test<Ty>(Reg, Reg);
    } else if (Op.isMem()) {
      auto Reg = Layout.getScopedTempReg<Ty, TempRegIndex>();
      ASM.mov<Ty>(Reg, Op.getMem<Ty>());
      ASM.test<Ty>(Reg, Reg);
    } else {
      auto Reg = Layout.getScopedTempReg<Ty, TempRegIndex>();
      ASM.mov<Ty>(Reg, Op.getImm());
      ASM.test<Ty>(Reg, Reg);
    }
  }

  // test single value with 0
  template <uint32_t TempRegIndex> void test(Operand Op) {
    if (Op.getType() == WASMType::I32) {
      test<X64::I32, TempRegIndex>(Op);
    } else if (Op.getType() == WASMType::I64) {
      test<X64::I64, TempRegIndex>(Op);
    } else {
      ZEN_ABORT();
    }
  }

  // Jmpcc
  template <CompareOperator Opr, bool Cond> void jmpcc(uint32_t LabelIdx) {
    constexpr JmpccOperator JmpccOpr = getJmpccOperator<Opr>();
    JmpccOperatorImpl<JmpccOpr, Cond>::emit(ASM, LabelIdx);
  }

  // Setcc
  template <CompareOperator Opr, bool Cond> void setcc(X64::RegNum RegNum) {
    constexpr SetccOperator SetccOpr = getSetccOperator<Opr>();
    SetccOperatorImpl<SetccOpr, Cond>::emit(ASM,
                                            X64Reg::getRegRef<X64::I8>(RegNum));
  }

  template <WASMType Type> Operand floatNeg(Operand Op) {
    constexpr auto X64Type = getX64TypeFromWASMType<Type>();
    constexpr auto X64IntType =
        getX64TypeFromWASMType<FloatAttr<Type>::IntType>();

    auto Ret = getTempOperand(Type);
    auto RegNum = Ret.isReg()
                      ? Ret.getReg()
                      : static_cast<X64::RegNum>(
                            Layout.getScopedTemp<X64Type, ScopedTempReg0>());
    mov<X64Type>(RegNum, Op);

    auto ImmReg = Layout.getScopedTempReg<X64Type, ScopedTempReg1>();
    auto ImmReg2 = Layout.getScopedTempReg<X64IntType, ScopedTempReg0>();

    auto SignMask = FloatAttr<Type>::SignMask;
    _ mov(ImmReg2, SignMask);
    ASM.fmov(ImmReg, ImmReg2);
    ASM.xor_<X64Type>(X64Reg::getRegRef<X64Type>(RegNum), ImmReg);

    if (!Ret.isReg()) {
      mov<X64Type, ScopedTempReg0>(Ret,
                                   Operand(Type, RegNum, Operand::FLAG_NONE));
    }
    return Ret;
  }

  template <WASMType Type> Operand floatAbs(Operand Op) {
    constexpr auto X64Type = getX64TypeFromWASMType<Type>();
    constexpr auto X64IntType =
        getX64TypeFromWASMType<FloatAttr<Type>::IntType>();

    auto TmpReg = Layout.getScopedTempReg<X64Type, ScopedTempReg0>();
    auto TmpRegNum = Layout.getScopedTemp<X64Type, ScopedTempReg0>();
    auto TmpIntReg = Layout.getScopedTempReg<X64IntType, ScopedTempReg0>();

    auto Mask = ~FloatAttr<Type>::SignMask;
    _ mov(TmpIntReg, Mask);
    ASM.fmov(TmpReg, TmpIntReg);

    if (Op.isReg()) {
      ASM.and_<X64Type>(TmpReg, Op.getRegRef<X64Type>());
    } else if (Op.isMem()) {
      auto TmpReg2 = Layout.getScopedTemp<X64Type, ScopedTempReg1>();
      mov<X64Type>(TmpReg2, Op);
      ASM.and_<X64Type>(TmpReg, X64Reg::getRegRef<X64Type>(TmpReg2));
    } else {
      ZEN_ABORT();
    }

    auto Ret = getTempOperand(Type);
    mov<X64Type, ScopedTempReg0>(Ret,
                                 Operand(Type, TmpRegNum, Operand::FLAG_NONE));
    return Ret;
  }

  template <WASMType Type> Operand floatSqrt(Operand Op) {
    constexpr auto X64Type = getX64TypeFromWASMType<Type>();
    auto TmpReg = Layout.getScopedTempReg<X64Type, ScopedTempReg0>();
    auto TmpRegNum = Layout.getScopedTemp<X64Type, ScopedTempReg0>();

    if (Op.isReg()) {
      ASM.sqrt<X64Type>(TmpReg, Op.getRegRef<X64Type>());
    } else if (Op.isMem()) {
      auto TmpReg2 = Layout.getScopedTemp<X64Type, ScopedTempReg1>();
      mov<X64Type>(TmpReg2, Op);
      ASM.sqrt<X64Type>(TmpReg, X64Reg::getRegRef<X64Type>(TmpReg2));
    } else {
      ZEN_ABORT();
    }

    auto Ret = getTempOperand(Type);
    mov<X64Type, ScopedTempReg0>(Ret,
                                 Operand(Type, TmpRegNum, Operand::FLAG_NONE));
    return Ret;
  }

  template <WASMType Type, UnaryOperator Opr> Operand floatRound(Operand Op) {
    constexpr auto X64Type = getX64TypeFromWASMType<Type>();
    auto TmpReg = Layout.getScopedTempReg<X64Type, ScopedTempReg0>();
    auto TmpRegNum = Layout.getScopedTemp<X64Type, ScopedTempReg0>();

    uint8_t Mode = [] {
      switch (Opr) {
      case UnaryOperator::UO_CEIL:
        return 2;
      case UnaryOperator::UO_FLOOR:
        return 1;
      case UnaryOperator::UO_NEAREST:
        return 0;
      case UnaryOperator::UO_TRUNC:
        return 3;
      default:
        ZEN_ABORT();
      }
    }();

    if (Op.isReg()) {
      if (Type == WASMType::F32) {
        _ roundss(TmpReg, Op.getRegRef<X64Type>(), Mode);
      } else {
        _ roundsd(TmpReg, Op.getRegRef<X64Type>(), Mode);
      }
    } else if (Op.isMem()) {
      auto TmpReg2 = Layout.getScopedTemp<X64Type, ScopedTempReg1>();
      mov<X64Type>(TmpReg2, Op);
      if (Type == WASMType::F32) {
        _ roundss(TmpReg, X64Reg::getRegRef<X64Type>(TmpReg2), Mode);
      } else {
        _ roundsd(TmpReg, X64Reg::getRegRef<X64Type>(TmpReg2), Mode);
      }
    } else {
      ZEN_ABORT();
    }

    auto Ret = getTempOperand(Type);
    mov<X64Type, ScopedTempReg0>(Ret,
                                 Operand(Type, TmpRegNum, Operand::FLAG_NONE));
    return Ret;
  }

  // truncate float to signed integer
  template <WASMType DestType, WASMType SrcType>
  Operand handleFloatToIntImpl(Operand Opnd, std::true_type) {
    constexpr auto X64DestType = getX64TypeFromWASMType<DestType>();
    constexpr auto X64SrcType = getX64TypeFromWASMType<SrcType>();

    auto Ret = getTempOperand(DestType);
    auto RetReg = Ret.isReg()
                      ? Ret.getRegRef<X64DestType>()
                      : Layout.getScopedTempReg<X64DestType, ScopedTempReg0>();
    if (!Opnd.isReg()) {
      auto RegNum = Layout.getScopedTemp<X64SrcType, ScopedTempReg0>();
      mov<X64SrcType>(RegNum, Opnd);
      Opnd = Operand(SrcType, RegNum, Operand::FLAG_NONE);
    }
    auto OpndReg = Opnd.getRegRef<X64SrcType>();

    ConvertOpImpl<X64DestType, X64SrcType, true>::emit(ASM, RetReg, OpndReg);

    auto Finish = _ newLabel();
    _ cmp(RetReg, 1);
    _ jno(Finish);

    ASM.cmp<X64SrcType>(OpndReg, OpndReg);
    _ jp(getExceptLabel(ErrorCode::InvalidConversionToInteger));

    constexpr auto X64IntSrcType =
        getX64TypeFromWASMType<FloatAttr<SrcType>::IntType>();
    auto TmpFReg = Layout.getScopedTempReg<X64SrcType, ScopedTempReg1>();
    auto TmpIReg = Layout.getScopedTempReg<X64IntSrcType, ScopedTempReg1>();

    auto IntMin = FloatAttr<SrcType>::template int_min<DestType>();
    _ mov(TmpIReg, IntMin);
    ASM.fmov(TmpFReg, TmpIReg);

    ASM.cmp<X64SrcType>(OpndReg, TmpFReg);
    _ jbe(getExceptLabel(ErrorCode::IntegerOverflow));

    ASM.xor_<X64SrcType>(TmpFReg, TmpFReg);
    ASM.cmp<X64SrcType>(TmpFReg, OpndReg);
    _ jb(getExceptLabel(ErrorCode::IntegerOverflow));

    _ bind(Finish);
    if (Ret.isMem()) {
      ASM.mov<X64DestType>(Ret.getMem<X64DestType>(), RetReg);
    }
    return Ret;
  }

  // truncate float to unsigned integer
  template <WASMType DestType, WASMType SrcType>
  Operand handleFloatToIntImpl(Operand Op, std::false_type) {
    constexpr auto X64DestType = getX64TypeFromWASMType<DestType>();
    constexpr auto X64SrcType = getX64TypeFromWASMType<SrcType>();

    auto Ret = getTempOperand(DestType);
    auto RetReg = Ret.isReg()
                      ? Ret.getRegRef<X64DestType>()
                      : Layout.getScopedTempReg<X64DestType, ScopedTempReg0>();
    if (!Op.isReg()) {
      auto RegNum = Layout.getScopedTemp<X64SrcType, ScopedTempReg0>();
      mov<X64SrcType>(RegNum, Op);
      Op = Operand(SrcType, RegNum, Operand::FLAG_NONE);
    }
    auto OpndReg = Op.getRegRef<X64SrcType>();

    constexpr auto X64IntSrcType =
        getX64TypeFromWASMType<FloatAttr<SrcType>::IntType>();
    auto TmpFReg = Layout.getScopedTempReg<X64SrcType, ScopedTempReg1>();
    auto TmpIReg = Layout.getScopedTempReg<X64IntSrcType, ScopedTempReg1>();

    auto IntMax = FloatAttr<SrcType>::template int_max<DestType>();
    _ mov(TmpIReg, IntMax);
    ASM.fmov(TmpFReg, TmpIReg);

    auto AboveIntMax = _ newLabel();
    ASM.cmp<X64SrcType>(OpndReg, TmpFReg);
    _ jae(AboveIntMax);
    _ jp(getExceptLabel(ErrorCode::InvalidConversionToInteger));

    ConvertOpImpl<X64DestType, X64SrcType, false>::emit(ASM, RetReg, OpndReg);

    auto Finish = _ newLabel();
    _ cmp(RetReg, 0);
    _ jge(Finish);
    _ jmp(getExceptLabel(ErrorCode::IntegerOverflow));

    _ bind(AboveIntMax);
    ASM.sub<X64SrcType>(OpndReg, TmpFReg);
    ConvertOpImpl<X64DestType, X64SrcType, false>::emit(ASM, RetReg, OpndReg);

    _ cmp(RetReg, 0);
    _ jl(getExceptLabel(ErrorCode::IntegerOverflow));

    auto TmpIReg2 = Layout.getScopedTempReg<X64DestType, ScopedTempReg2>();
    _ mov(TmpIReg2, 1UL << (getWASMTypeSize<DestType>() * CHAR_BIT - 1));
    _ add(RetReg, TmpIReg2);

    _ bind(Finish);
    if (!Ret.isReg()) {
      ASM.mov<X64DestType>(Ret.getMem<X64DestType>(), RetReg);
    }
    return Ret;
  }

  // load gas value from 'module_inst' to register
  void loadGasVal() {
    auto InstReg = ABI.getModuleInstReg();
    auto GasAddr = asmjit::x86::ptr(InstReg, GasLeftOffset);
    _ mov(ABI.getGasReg(), GasAddr);
  }

  // save gas value from register to 'module_inst'
  void saveGasVal() {
    auto InstReg = ABI.getModuleInstReg();
    auto GasAddr = asmjit::x86::ptr(InstReg, GasLeftOffset);
    _ mov(GasAddr, ABI.getGasReg());
  }

public:
  void subGasVal(Operand Delta) {
    Operand GasReg(WASMType::I64, ABI.getGasRegNum(), Operand::FLAG_NONE);
    BinaryOperatorImpl<X64::I64, BinaryOperator::BO_SUB>::emit(ASM, GasReg,
                                                               Delta);
  }

  template <bool Sign, WASMType Type, BinaryOperator Opr>
  Operand checkedArithmetic(Operand LHS, Operand RHS) {
    constexpr auto X64Type = getX64TypeFromWASMType<Type>();
    auto OverflowLabel = getExceptLabel(ErrorCode::IntegerOverflow);
    X64::RegNum LHSRegNum = -1;
    if (Opr == BinaryOperator::BO_MUL) {
      LHSRegNum = X64::RAX;
      mov<X64Type>(LHSRegNum, LHS);
      auto RhsRegNum = toReg<X64Type, ScopedTempReg1>(RHS); // avoid RAX
      auto RhsReg = X64Reg::getRegRef<X64Type>(RhsRegNum);
      if (Sign)
        _ imul(RhsReg);
      else
        _ mul(RhsReg);
      _ jo(OverflowLabel);
    } else {
      LHSRegNum = toReg<X64Type, ScopedTempReg0>(LHS);
      auto LhsReg = X64Reg::getRegRef<X64Type>(LHSRegNum);
      BinaryOperatorImpl<X64Type, Opr>::emit(ASM, LhsReg, RHS);
      if (Sign)
        _ jo(OverflowLabel);
      else
        _ jb(OverflowLabel);
    }
    // sign/zero extension
    constexpr bool IsSmallType = (getWASMTypeSize<Type>() < 4);
    if (IsSmallType) {
      auto Dest = X64Reg::getRegRef<I32>(LHSRegNum);
      auto Src = X64Reg::getRegRef<X64Type>(LHSRegNum);
      if (Sign)
        _ movsx(Dest, Src);
      else
        _ movzx(Dest, Src);
    }
    constexpr auto ResType = IsSmallType ? WASMType::I32 : Type;
    constexpr auto X64ResType = getX64TypeFromWASMType<ResType>();
    auto Ret = getTempOperand(ResType);
    mov<X64ResType>(Ret, LHSRegNum);
    return Ret;
  }
  template <bool Sign, BinaryOperator Opr>
  Operand checkedI128Arithmetic(Operand LHSLo, Operand LHSHi, Operand RHSLo,
                                Operand RHSHi) {
    auto LHSLoRegNum = toReg<I64, ScopedTempReg0>(LHSLo);
    auto LHSHiRegNum = toReg<I64, ScopedTempReg1>(LHSHi);
    auto LHSLoReg = X64Reg::getRegRef<I64>(LHSLoRegNum);
    auto LHSHiReg = X64Reg::getRegRef<I64>(LHSHiRegNum);
    // NOTE: 'ScopedTempReg2' will be reused subsequently
    auto RHSLoRegNum = toReg<I64, ScopedTempReg2>(RHSLo);
    auto RHSLoReg = X64Reg::getRegRef<I64>(RHSLoRegNum);
    if (Opr == BinaryOperator::BO_ADD)
      _ add(LHSLoReg, RHSLoReg);
    else
      _ sub(LHSLoReg, RHSLoReg);
    auto RHSHiRegNum = toReg<I64, ScopedTempReg2>(RHSHi);
    auto RHSHiReg = X64Reg::getRegRef<I64>(RHSHiRegNum);
    if (Opr == BinaryOperator::BO_ADD)
      _ adc(LHSHiReg, RHSHiReg);
    else
      _ sbb(LHSHiReg, RHSHiReg);
    auto OverflowLabel = getExceptLabel(ErrorCode::IntegerOverflow);
    if (Sign)
      _ jo(OverflowLabel);
    else
      _ jb(OverflowLabel);
    auto Ret = getTempOperand(WASMType::I64);
    mov<I64>(Ret, LHSHiRegNum);
    return Ret;
  }
}; // X64OnePassCodeGenImpl

// undefine abbr for assembler
#undef _

} // namespace zen::singlepass

#endif // ZEN_SINGLEPASS_X64_CODEGEN_H
