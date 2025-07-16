// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_SINGLEPASS_A64_DATALAYOUT_H
#define ZEN_SINGLEPASS_A64_DATALAYOUT_H

// ============================================================================
// a64/datalayout.h
//
// data layout for a64 one pass jit compiler.
//
// ============================================================================

#include "singlepass/a64/abi.h"
#include "singlepass/a64/asm/register.h"
#include "singlepass/a64/machine.h"
#include "singlepass/a64/operand.h"
#include "singlepass/common/datalayout.h"
#include "singlepass/common/definitions.h"

namespace zen::singlepass {

// ============================================================================
// A64DataLayout
//
// layout stack, heap and temporary space for a64-64 one pass jit compiler
//
// ============================================================================

class A64OnePassDataLayout : public OnePassDataLayout<A64OnePassABI> {
protected:
  // VM state to track register/stack status
  A64MachineState VmState;

  // each time stack increase 32-byte
  constexpr static uint32_t StackIncrement = 32;

public:
  A64OnePassDataLayout(A64OnePassABI &Abi)
      : OnePassDataLayout<A64OnePassABI>(Abi) {}

private:
  template <WASMType Type>
  void layoutParam(uint32_t &Index, uint32_t &StkSize, uint32_t &UpStkOffset) {
    constexpr A64::Type A64Type = getA64TypeFromWASMType<Type>();
    uint32_t ArgRegIndex = Index;
    if ((A64TypeAttr<A64Type>::Kind == A64::GPR)) {
      ArgRegIndex = Index + 1; // exec_env in 1st reg
    }
    if (ArgRegIndex < Abi.getNumParamRegs<A64Type>()) {
      // in register
      auto Reg = Abi.getParamRegNum<A64Type>(ArgRegIndex);
      VmState.clearAvailReg<A64Type>(Reg);
      VmState.markParamInReg<A64Type>(Index);
      ++Index;
      constexpr uint32_t Align = A64TypeAttr<A64Type>::Size;
      ZEN_STATIC_ASSERT((Align & (Align - 1)) == 0);
      StkSize = ZEN_ALIGN(StkSize, Align);
      StkSize += Align;
      Locals.push_back(LocalInfo(Type, Reg, -StkSize));
    } else {
      // on prev frame
      constexpr uint32_t Align = A64TypeAttr<A64Type>::StackAlign;
      ZEN_STATIC_ASSERT((Align & (Align - 1)) == 0);
      UpStkOffset = ZEN_ALIGN(UpStkOffset, Align);
      Locals.push_back(LocalInfo(Type, UpStkOffset));
      UpStkOffset += Align;
    }
  }

  template <WASMType Type> void layoutLocal(uint32_t &StkSize) {
    constexpr A64::Type A64Type = getA64TypeFromWASMType<Type>();
    constexpr uint32_t Align = A64TypeAttr<A64Type>::Size;
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
    OnePassDataLayout<A64OnePassABI>::initFunction(Ctx);

    ZEN_ASSERT(Locals.empty());
    Locals.reserve(FuncType->NumParams + Func->NumLocals);

    uint32_t IntParamCnt = 0;
    uint32_t FpParamCnt = 0;
    uint32_t UpStackOffset = A64OnePassABI::FormalStackOffset;
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

    // set StackUsed and _stack_budget
    StackUsed = ((StackTop + 15) / 16) * 16;
    StackBudget = StackUsed + StackIncrement;
    // set param in register
    if (FuncType->NumParams) {
      ParamInRegister = true;
    }
  }

  void finalizeFunction() {
    // check _vm_state
    OnePassDataLayout<A64OnePassABI>::finalizeFunction();
    VmState.finalizeFunction();
  }

public:
  template <A64::Type Ty>
  void markAvailReg(typename A64TypeAttr<Ty>::RegNum Reg) {
    VmState.markAvailReg<Ty>(Reg);
  }

  template <A64::Type Ty> void markAvailRegMask(uint32_t Mask) {
    VmState.markAvailRegMask<Ty>(Mask);
  }

  template <A64::Type Ty>
  void clearAvailReg(typename A64TypeAttr<Ty>::RegNum Reg) {
    VmState.clearAvailReg<Ty>(Reg);
  }

  template <A64::Type Ty> uint32_t getAvailRegMask() const {
    return VmState.getAvailRegMask<Ty>();
  }

  void clearParamInReg() { VmState.clearParamInReg(); }

public:
  A64InstOperand getGlobal(A64::GP Base, uint32_t GlobalIdx) {
    ZEN_ASSERT(GlobalIdx < Globals.size());
    GlobalInfo Info = Globals[GlobalIdx];
    return A64InstOperand(Info.getType(), Base, Info.getOffset(),
                          A64InstOperand::FLAG_NONE);
  }

  A64InstOperand getLocal(uint32_t LocalIdx) {
    ZEN_ASSERT(LocalIdx < Locals.size());
    LocalInfo Info = Locals[LocalIdx];
    if (Info.inReg()) {
      // in register
      return A64InstOperand(Info.getType(), (A64::RegNum)Info.getReg(),
                            A64InstOperand::FLAG_NONE);
    }
    // on stack, ofst is based on frame base, change to stack pointer
    return A64InstOperand(Info.getType(), Abi.getFrameBase(), Info.getOffset(),
                          A64InstOperand::FLAG_NONE);
  }

public:
  // fully manual scoped temporary register management
  // get scoped temporary register number
  template <A64::Type Ty, uint32_t Index>
  constexpr typename A64TypeAttr<Ty>::RegNum getScopedTemp() {
    ZEN_STATIC_ASSERT(Ty >= A64::I8 && Ty <= A64::V128);
    ZEN_STATIC_ASSERT(Index < 3);
    return A64OnePassABI::getScopedTempRegNum<Ty, Index>();
  }

  // get scoped temporary register reference
  template <A64::Type Ty, uint32_t Index>
  constexpr typename A64TypeAttr<Ty>::Type getScopedTempReg() {
    ZEN_STATIC_ASSERT(Ty >= A64::I8 && Ty <= A64::V128);
    ZEN_STATIC_ASSERT(Index < 3);
    return A64OnePassABI::getScopedTempReg<Ty, Index>();
  }

public:
  template <A64::Type Ty>
  bool hasAvailTempReg(typename A64TypeAttr<Ty>::RegNum &Reg) {
    return VmState.hasAvailReg<Ty>(Reg);
  }

  template <WASMType type> A64InstOperand getTempRegOperand() {
    constexpr A64::Type A64Type = getA64TypeFromWASMType<type>();
    typename A64TypeAttr<A64Type>::RegNum Reg;
    if (VmState.hasAvailReg<A64Type>(Reg)) {
      return A64InstOperand(type, Reg, A64InstOperand::FLAG_TEMP_REG);
    }
    ZEN_UNREACHABLE();
  }

  A64InstOperand getTempStackOperand(WASMType Type, uint32_t Size) {
    ZEN_ASSERT(getWASMTypeSize(Type) == Size);
    ZEN_ASSERT((Size & (Size - 1)) == 0);
    StackUsed = ZEN_ALIGN(StackUsed, Size);
    StackUsed += Size;
    // check if need to grow the stack
    if (StackUsed > StackBudget) {
      StackBudget += StackIncrement;
    }
    return A64InstOperand(Type, A64OnePassABI::getFrameBase(),
                          -(int32_t)StackUsed, A64InstOperand::FLAG_TEMP_MEM);
  }

  A64MachineState getVMState() const { return VmState; }

  void releaseOperand(A64InstOperand Opnd) {
    ZEN_ASSERT(Opnd.isTempReg() || Opnd.isTempMem());
    if (Opnd.isTempReg()) {
      A64::RegNum Reg = Opnd.isReg() ? Opnd.getReg() : Opnd.getBase();
      switch (Opnd.getType()) {
      case WASMType::I32:
      case WASMType::I64:
        ZEN_ASSERT(A64OnePassABI::isTempReg<A64::I32>(Reg));
        VmState.markAvailReg<A64::I32>((A64::GP)Reg);
        break;
      case WASMType::F32:
      case WASMType::F64:
        ZEN_ASSERT(A64OnePassABI::isTempReg<A64::F32>(Reg));
        VmState.markAvailReg<A64::F32>((A64::FP)Reg);
        break;
      default:
        ZEN_ABORT();
        break;
      }
    }
    if (Opnd.isTempMem()) {
      ZEN_ASSERT(Opnd.isMem());
      ZEN_ASSERT(Opnd.getOffset() < 0 && (-Opnd.getOffset() <= StackUsed));
      ZEN_ASSERT(-Opnd.getOffset() <= StackUsed);
      StackUsed = (-Opnd.getOffset() -
                   getWASMTypeSize(Opnd.getType())); // if stack aligned when
                                                     // getTempStackOperand,
                                                     // some stack space lost;
    }
  }
};

} // namespace zen::singlepass

#endif // ZEN_SINGLEPASS_A64_DATALAYOUT_H
