// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_SINGLEPASS_X64_DATALAYOUT_H
#define ZEN_SINGLEPASS_X64_DATALAYOUT_H

// ============================================================================
// x64/datalayout.h
//
// data layout for x64 one pass jit compiler.
//
// ============================================================================

#include "singlepass/common/datalayout.h"
#include "singlepass/common/definitions.h"
#include "singlepass/x64/abi.h"
#include "singlepass/x64/asm/register.h"
#include "singlepass/x64/machine.h"
#include "singlepass/x64/operand.h"

namespace zen::singlepass {

// ============================================================================
// X64DataLayout
//
// layout stack, heap and temporary space for x86-64 one pass jit compiler
//
// ============================================================================

class X64OnePassDataLayout : public OnePassDataLayout<X64OnePassABI> {
protected:
  // VM state to track register/stack status
  X64MachineState VmState;

  // each time stack increase 32-byte
  constexpr static uint32_t StackIncrement = 32;

public:
  X64OnePassDataLayout(X64OnePassABI &ABI)
      : OnePassDataLayout<X64OnePassABI>(ABI) {}

private:
  template <WASMType Type>
  void layoutParam(uint32_t &Index, uint32_t &StkSize, uint32_t &UpStkOfst) {
    constexpr X64::Type X64Type = getX64TypeFromWASMType<Type>();
    uint32_t ArgRegIndex = Index;
    if ((X64TypeAttr<X64Type>::Kind == X64::GPR)) {
      ArgRegIndex = Index + 1; // instance in 1st reg
    }
    if (ArgRegIndex < Abi.getNumParamRegs<X64Type>()) {
      // in register
      auto Reg = Abi.getParamRegNum<X64Type>(ArgRegIndex);
      VmState.clearAvailReg<X64Type>(Reg);
      VmState.markParamInReg<X64Type>(Index);
      ++Index;
      constexpr uint32_t Align = X64TypeAttr<X64Type>::Size;
      ZEN_STATIC_ASSERT((Align & (Align - 1)) == 0);
      StkSize = ZEN_ALIGN(StkSize, Align);
      StkSize += Align;
      Locals.push_back(LocalInfo(Type, Reg, -StkSize));
    } else {
      // on prev frame
      constexpr uint32_t Align = X64TypeAttr<X64Type>::StackAlign;
      ZEN_STATIC_ASSERT((Align & (Align - 1)) == 0);
      UpStkOfst = ZEN_ALIGN(UpStkOfst, Align);
      Locals.push_back(LocalInfo(Type, UpStkOfst));
      UpStkOfst += Align;
    }
  }

  template <WASMType Type> void layoutLocal(uint32_t &StkSize) {
    constexpr X64::Type X64Type = getX64TypeFromWASMType<Type>();
    constexpr uint32_t Align = X64TypeAttr<X64Type>::Size;
    ZEN_STATIC_ASSERT((Align & (Align - 1)) == 0);
    StkSize = ZEN_ALIGN(StkSize, Align);
    StkSize += Align;
    Locals.push_back(LocalInfo(Type, -StkSize));
  }

public:
  void initFunction(JITCompilerContext *Ctx) {
    auto *FuncType = Ctx->FuncType;
    auto *Func = Ctx->Func;
    VmState.initFunction();
    OnePassDataLayout<X64OnePassABI>::initFunction(Ctx);

    ZEN_ASSERT(Locals.empty());
    Locals.reserve(FuncType->NumParams + Func->NumLocals);

    uint32_t IntParamCnt = 0;
    uint32_t FpParamCnt = 0;
    uint32_t UpStackOffset = X64OnePassABI::FormalStackOffset;
    uint32_t StackTop = GpPresSavedArea + FpPresSavedArea;
    const auto *ParamTypes = FuncType->getParamTypes();
    for (uint32_t I = 0; I < FuncType->NumParams; ++I) {
      switch (ParamTypes[I]) {
      case WASMType::I32:
        layoutParam<WASMType::I32>(IntParamCnt, StackTop, UpStackOffset);
        break;
      case WASMType::I64:
        layoutParam<WASMType::I64>(IntParamCnt, StackTop, UpStackOffset);
        break;
      case WASMType::F32:
        layoutParam<WASMType::F32>(FpParamCnt, StackTop, UpStackOffset);
        break;
      case WASMType::F64:
        layoutParam<WASMType::F64>(FpParamCnt, StackTop, UpStackOffset);
        break;
      default:
        ZEN_ABORT();
      }
    } // for (...)

    // layout rest locals
    for (uint32_t I = 0; I < Func->NumLocals; ++I) {
      switch (Func->LocalTypes[I]) {
      case WASMType::I32:
        layoutLocal<WASMType::I32>(StackTop);
        break;
      case WASMType::I64:
        layoutLocal<WASMType::I64>(StackTop);
        break;
      case WASMType::F32:
        layoutLocal<WASMType::F32>(StackTop);
        break;
      case WASMType::F64:
        layoutLocal<WASMType::F64>(StackTop);
        break;
      default:
        ZEN_ABORT();
      }
    } // for (...)

    // set _stack_used and _stack_budget
    StackUsed = ((StackTop + 15) / 16) * 16;
    StackBudget = StackUsed + StackIncrement;
    // set param in register
    if (FuncType->NumParams) {
      ParamInRegister = true;
    }
  }

  void finalizeFunction() {
    // check _vm_state
    OnePassDataLayout<X64OnePassABI>::finalizeFunction();
    VmState.finalizeFunction();
  }

public:
  template <X64::Type Ty>
  void markAvailReg(typename X64TypeAttr<Ty>::RegNum Reg) {
    VmState.markAvailReg<Ty>(Reg);
  }

  template <X64::Type Ty> void markAvailRegMask(uint32_t Mask) {
    VmState.markAvailRegMask<Ty>(Mask);
  }

  template <X64::Type Ty>
  void clearAvailReg(typename X64TypeAttr<Ty>::RegNum Reg) {
    VmState.clearAvailReg<Ty>(Reg);
  }

  template <X64::Type Ty> uint32_t getAvailRegMask() const {
    return VmState.getAvailRegMask<Ty>();
  }

  void clearParamInReg() { VmState.clearParamInReg(); }

public:
  X64InstOperand getGlobal(X64::GP Base, uint32_t GlobalIdx) {
    ZEN_ASSERT(GlobalIdx < Globals.size());
    GlobalInfo Info = Globals[GlobalIdx];
    return X64InstOperand(Info.getType(), Base, Info.getOffset(),
                          X64InstOperand::FLAG_NONE);
  }

  X64InstOperand getLocal(uint32_t LocalIdx) {
    ZEN_ASSERT(LocalIdx < Locals.size());
    LocalInfo Info = Locals[LocalIdx];
    if (Info.inReg()) {
      // in register
      return X64InstOperand(Info.getType(), (X64::RegNum)Info.getReg(),
                            X64InstOperand::FLAG_NONE);
    }
    // on stack
    return X64InstOperand(Info.getType(), Abi.getFrameBase(), Info.getOffset(),
                          X64InstOperand::FLAG_NONE);
  }

public:
  // fully manual scoped temporary register management
  // get scoped temporary register number
  template <X64::Type Ty, uint32_t Index>
  constexpr typename X64TypeAttr<Ty>::RegNum getScopedTemp() {
    ZEN_STATIC_ASSERT(Ty >= X64::I8 && Ty <= X64::V128);
    ZEN_STATIC_ASSERT(Index < 3);
    return X64OnePassABI::getScopedTempRegNum<Ty, Index>();
  }

  // get scoped temporary register reference
  template <X64::Type Ty, uint32_t Index>
  constexpr typename X64TypeAttr<Ty>::Type getScopedTempReg() {
    ZEN_STATIC_ASSERT(Ty >= X64::I8 && Ty <= X64::V128);
    ZEN_STATIC_ASSERT(Index < 3);
    return X64OnePassABI::getScopedTempReg<Ty, Index>();
  }

public:
  template <X64::Type Ty>
  bool hasAvailTempReg(typename X64TypeAttr<Ty>::RegNum &Reg) {
    return VmState.hasAvailReg<Ty>(Reg);
  }

  template <WASMType Ty> X64InstOperand getTempRegOperand() {
    constexpr X64::Type X64Type = getX64TypeFromWASMType<Ty>();
    typename X64TypeAttr<X64Type>::RegNum Reg;
    if (VmState.hasAvailReg<X64Type>(Reg)) {
      return X64InstOperand(Ty, Reg, X64InstOperand::FLAG_TEMP_REG);
    }
    ZEN_UNREACHABLE();
  }

  X64InstOperand getTempStackOperand(WASMType Type, uint32_t Size) {
    ZEN_ASSERT(getWASMTypeSize(Type) == Size);
    ZEN_ASSERT((Size & (Size - 1)) == 0);
    StackUsed = ZEN_ALIGN(StackUsed, Size);
    StackUsed += Size;
    // check if need to grow the stack
    if (StackUsed > StackBudget) {
      StackBudget += StackIncrement;
    }
    return X64InstOperand(Type, X64OnePassABI::getFrameBase(),
                          -(int32_t)StackUsed, X64InstOperand::FLAG_TEMP_MEM);
  }

  X64MachineState getVMState() const { return VmState; }

  void releaseOperand(X64InstOperand Op) {
    ZEN_ASSERT(Op.isTempReg() || Op.isTempMem());
    if (Op.isTempReg()) {
      X64::RegNum Reg = Op.isReg() ? Op.getReg() : Op.getBase();
      switch (Op.getType()) {
      case WASMType::I32:
      case WASMType::I64:
        ZEN_ASSERT(X64OnePassABI::isTempReg<X64::I32>(Reg));
        VmState.markAvailReg<X64::I32>((X64::GP)Reg);
        break;
      case WASMType::F32:
      case WASMType::F64:
        ZEN_ASSERT(X64OnePassABI::isTempReg<X64::F32>(Reg));
        VmState.markAvailReg<X64::F32>((X64::FP)Reg);
        break;
      default:
        ZEN_ASSERT_TODO();
      }
    }
    if (Op.isTempMem()) {
      ZEN_ASSERT(Op.isMem());
      ZEN_ASSERT(Op.getOffset() < 0 && (-Op.getOffset() <= StackUsed));
      ZEN_ASSERT(-Op.getOffset() <= StackUsed);
      StackUsed = (-Op.getOffset() -
                   getWASMTypeSize(Op.getType())); // if stack aligned when
                                                   // getTempStackOperand,
                                                   // some stack space lost;
    }
  }
};
} // namespace zen::singlepass

#endif // ZEN_SINGLEPASS_X64_DATALAYOUT_H
