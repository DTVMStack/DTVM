// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "compiler/mir/basic_block.h"
#include "compiler/mir/function.h"
#include "compiler/mir/instruction.h"
#include "compiler/mir/instructions.h"
#include "compiler/mir/module.h"

namespace COMPILER {

class MVisitor {
public:
  MVisitor(MModule &M, MFunction &F) : Module(M), CurFunc(&F) {}

  virtual void visit() {
    for (MBasicBlock *BB : *CurFunc) {
      visitBasicBlock(*BB);
    }
  }

  virtual void visitBasicBlock(MBasicBlock &BB) {
    CurBB = &BB;
    for (MInstruction *I : BB) {
      visitInstruction(*I);
    }
  }

  virtual void visitInstruction(MInstruction &I) {
    switch (I.getKind()) {
    case MInstruction::DREAD:
      visitDreadInstruction(static_cast<DreadInstruction &>(I));
      break;
    case MInstruction::UNARY:
      visitUnaryInstruction(static_cast<UnaryInstruction &>(I));
      break;
    case MInstruction::BINARY:
      visitBinaryInstruction(static_cast<BinaryInstruction &>(I));
      break;
    case MInstruction::ADC:
      visitAdcInstruction(static_cast<AdcInstruction &>(I));
      break;
    case MInstruction::OVERFLOW_I128_BINARY:
      visitWasmOverflowI128BinaryInstruction(
          static_cast<WasmOverflowI128BinaryInstruction &>(I));
      break;
    case MInstruction::EVM_UMUL128:
      visitEvmUmul128Instruction(static_cast<EvmUmul128Instruction &>(I));
      break;
    case MInstruction::EVM_UMUL128_HI:
      visitEvmUmul128HiInstruction(static_cast<EvmUmul128HiInstruction &>(I));
      break;
    case MInstruction::CMP:
      visitCmpInstruction(static_cast<CmpInstruction &>(I));
      break;
    case MInstruction::SELECT:
      visitSelectInstruction(static_cast<SelectInstruction &>(I));
      break;
    case MInstruction::DASSIGN:
      visitDassignInstruction(static_cast<DassignInstruction &>(I));
      break;
    case MInstruction::LOAD:
      visitLoadInstruction(static_cast<LoadInstruction &>(I));
      break;
    case MInstruction::STORE:
      visitStoreInstruction(static_cast<StoreInstruction &>(I));
      break;
    case MInstruction::CONSTANT:
      visitConstantInstruction(static_cast<ConstantInstruction &>(I));
      break;
    case MInstruction::BR:
      visitBrInstruction(static_cast<BrInstruction &>(I));
      break;
    case MInstruction::BR_IF:
      visitBrIfInstruction(static_cast<BrIfInstruction &>(I));
      break;
    case MInstruction::SWITCH:
      visitSwitchInstruction(static_cast<SwitchInstruction &>(I));
      break;
    case MInstruction::CALL:
      if (I.getOpcode() == OP_call) {
        visitCallInstruction(static_cast<CallInstruction &>(I));
      } else {
        visitICallInstruction(static_cast<ICallInstruction &>(I));
      }
      break;
    case MInstruction::RETURN:
      visitReturnInstruction(static_cast<ReturnInstruction &>(I));
      break;
    case MInstruction::CONVERSION:
      visitConversionInstruction(static_cast<ConversionInstruction &>(I));
      break;
    case MInstruction::WASM_CHECK:
      switch (I.getOpcode()) {
      case OP_wasm_check_memory_access:
        visitWasmCheckMemoryAccessInstruction(
            static_cast<WasmCheckMemoryAccessInstruction &>(I));
        break;
      case OP_wasm_check_stack_boundary:
        visitWasmCheckStackBoundaryInstruction(
            static_cast<WasmCheckStackBoundaryInstruction &>(I));
        break;
      case OP_wasm_visit_stack_guard:
        visitWasmVisitStackGuardInstruction(
            static_cast<WasmVisitStackGuardInstruction &>(I));
        break;
      default:
        ZEN_ASSERT_TODO();
      }
      break;
    default:
      ZEN_ASSERT_TODO();
    }
  }

#define VISIT_OPERAND_1 visitInstruction(*I.getOperand<0>());
#define VISIT_OPERAND_2                                                        \
  visitInstruction(*I.getOperand<0>());                                        \
  visitInstruction(*I.getOperand<1>());
#define VISIT_OPERAND_3                                                        \
  visitInstruction(*I.getOperand<0>());                                        \
  visitInstruction(*I.getOperand<1>());                                        \
  visitInstruction(*I.getOperand<2>());
#define VISIT_OPERANDS                                                         \
  for (uint32_t i = 0, e = I.getNumOperands(); i != e; ++i) {                  \
    visitInstruction(*I.getOperand(i));                                        \
  }

  virtual void visitDreadInstruction(DreadInstruction &I) {}
  virtual void visitUnaryInstruction(UnaryInstruction &I) { VISIT_OPERAND_1 }
  virtual void visitBinaryInstruction(BinaryInstruction &I) { VISIT_OPERAND_2 }
  virtual void visitCmpInstruction(CmpInstruction &I) { VISIT_OPERAND_2 }
  virtual void visitAdcInstruction(AdcInstruction &I) { VISIT_OPERAND_3 }
  virtual void visitSelectInstruction(SelectInstruction &I) { VISIT_OPERAND_3 }
  virtual void visitDassignInstruction(DassignInstruction &I) {
    VISIT_OPERAND_1
  }
  virtual void visitLoadInstruction(LoadInstruction &I) { VISIT_OPERAND_1 }
  virtual void visitStoreInstruction(StoreInstruction &I) { VISIT_OPERAND_2 }
  virtual void visitConstantInstruction(ConstantInstruction &I) {}
  virtual void visitBrInstruction(BrInstruction &I) {}
  virtual void visitBrIfInstruction(BrIfInstruction &I) { VISIT_OPERAND_1 }
  virtual void visitSwitchInstruction(SwitchInstruction &I) { VISIT_OPERANDS }
  virtual void visitCallInstructionBase(CallInstructionBase &I) {
    VISIT_OPERANDS
  }
  virtual void visitCallInstruction(CallInstruction &I) {
    visitCallInstructionBase(I);
  }
  virtual void visitICallInstruction(ICallInstruction &I) {
    visitInstruction(*I.getCalleeAddr());
    visitCallInstructionBase(I);
  }
  virtual void visitReturnInstruction(ReturnInstruction &I) {
    if (I.getNumOperands() > 0) {
      VISIT_OPERAND_1
    }
  }
  virtual void visitConversionInstruction(ConversionInstruction &I) {
    VISIT_OPERAND_1
  }
  virtual void
  visitWasmCheckMemoryAccessInstruction(WasmCheckMemoryAccessInstruction &I) {
    VISIT_OPERAND_1
  }

  virtual void
  visitWasmCheckStackBoundaryInstruction(WasmCheckStackBoundaryInstruction &I) {
    VISIT_OPERAND_1
  }
  virtual void
  visitWasmVisitStackGuardInstruction(WasmVisitStackGuardInstruction &I) {}
  virtual void
  visitWasmOverflowI128BinaryInstruction(WasmOverflowI128BinaryInstruction &I) {
    VISIT_OPERANDS
  }
  virtual void visitEvmUmul128Instruction(EvmUmul128Instruction &I) {
    VISIT_OPERAND_2
  }
  virtual void visitEvmUmul128HiInstruction(EvmUmul128HiInstruction &I) {
    VISIT_OPERAND_1
  }

protected:
  MModule &Module;
  MFunction *CurFunc = nullptr;
  MBasicBlock *CurBB = nullptr;
};

} // namespace COMPILER
