// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "compiler/mir/pass/verifier.h"
#include "compiler/mir/pointer.h"
#include <sstream>
using namespace COMPILER;

void MVerifier::visitUnaryInstruction(UnaryInstruction &I) {
  MType *OperandType = I.getOperand<0>()->getType();
  Opcode Opc = I.getOpcode();
  switch (Opc) {
  case OP_clz:
  case OP_ctz:
  case OP_not:
  case OP_popcnt:
  case OP_bswap:
    CHECK(OperandType->isInteger(),
          "The type of " + getOpcodeString(Opc) + " operand must be integer");
    break;
  case OP_fpabs:
  case OP_fpneg:
  case OP_fpsqrt:
  case OP_fpround_ceil:
  case OP_fpround_floor:
  case OP_fpround_trunc:
  case OP_fpround_nearest:
    CHECK(OperandType->isFloat(), "The type of " + getOpcodeString(Opc) +
                                      " operand must be float-point");
    break;
  default:
    ZEN_ASSERT_TODO();
  }
  MVisitor::visitUnaryInstruction(I);
}

void MVerifier::visitBinaryInstruction(BinaryInstruction &I) {
  MType *LHSType = I.getOperand<0>()->getType();
  MType *RHSType = I.getOperand<1>()->getType();
  CHECK(LHSType->getKind() == RHSType->getKind(),
        "The operands of binary expession must be of the same type");

  Opcode Opc = I.getOpcode();
  switch (Opc) {
  case OP_add:
  case OP_sub:
  case OP_mul:
    // Both support integer and float-point operands
    break;
  case OP_and:
  case OP_or:
  case OP_xor:
  case OP_shl:
  case OP_sshr:
  case OP_ushr:
  case OP_rotl:
  case OP_rotr:
  case OP_sdiv:
  case OP_udiv:
  case OP_srem:
  case OP_urem:
  case OP_wasm_sadd_overflow:
  case OP_wasm_uadd_overflow:
  case OP_wasm_ssub_overflow:
  case OP_wasm_usub_overflow:
  case OP_wasm_smul_overflow:
  case OP_wasm_umul_overflow:
    CHECK(LHSType->isInteger(),
          "The type of " + getOpcodeString(Opc) + " operands must be integer");
    break;
  case OP_fpdiv:
  case OP_fpmin:
  case OP_fpmax:
  case OP_fpcopysign:
    CHECK(LHSType->isFloat(), "The type of " + getOpcodeString(Opc) +
                                  " operands must be float-point");
    break;
  default:
    ZEN_ASSERT_TODO();
  }
  MVisitor::visitBinaryInstruction(I);
}

void MVerifier::visitWasmOverflowI128BinaryInstruction(
    WasmOverflowI128BinaryInstruction &Instr) {
  Opcode Opc = Instr.getOpcode();
  switch (Opc) {
  case OP_wasm_sadd128_overflow:
  case OP_wasm_uadd128_overflow:
  case OP_wasm_ssub128_overflow:
  case OP_wasm_usub128_overflow:
    break;
  default:
    CHECK(false,
          "The opcode of wasm_overflow_i128_binary instruction must be one of "
          "wasm_sadd128_overflow/wasm_uadd128_overflow/wasm_ssub128_overflow/"
          "wasm_usub128_overflow");
  }
  for (uint32_t I = 0; I < Instr.getNumOperands(); ++I) {
    MType *OperandType = Instr.getOperand(I)->getType();
    CHECK(OperandType->isI64(),
          "The type of wasm_overflow_i128_binary operands must be i64");
  }
  CHECK(Instr.getType()->isI64(),
        "The type of wasm_overflow_i128_binary result must be i64");
  MVisitor::visitWasmOverflowI128BinaryInstruction(Instr);
}

void MVerifier::visitAdcInstruction(AdcInstruction &I) {
  MType *Operand1Type = I.getOperand<0>()->getType();
  MType *Operand2Type = I.getOperand<1>()->getType();
  MType *CarryType = I.getOperand<2>()->getType();

  CHECK(Operand1Type->getKind() == Operand2Type->getKind(),
        "The first two operands of adc instruction must be of the same type");
  CHECK(CarryType->isInteger(),
        "The carry operand of adc instruction must be integer");
  CHECK(Operand1Type->isInteger(),
        "The first two operands of adc instruction must be integer");

  MVisitor::visitAdcInstruction(I);
}

void MVerifier::visitCmpInstruction(CmpInstruction &I) {
  MType *Type = I.getType();
  CHECK(Type->isI8() || Type->isI32() || Type->isI64(),
        "The type of cmp instruction result must be i8/i32/i64");

  MType *LHSType = I.getOperand<0>()->getType();
  MType *RHSType = I.getOperand<1>()->getType();
  CHECK(LHSType->getKind() == RHSType->getKind(),
        "The operands of cmp instructions must have same type");

  CmpInstruction::Predicate predicate = I.getPredicate();
  CHECK(LHSType->isInteger() ? predicate >= CmpInstruction::ICMP_EQ &&
                                   predicate <= CmpInstruction::ICMP_SLE
                             : predicate >= CmpInstruction::FCMP_FALSE &&
                                   predicate <= CmpInstruction::FCMP_TRUE,
        "Illegal predicate in cmp instruction");
  MVisitor::visitCmpInstruction(I);
}

void MVerifier::visitSelectInstruction(SelectInstruction &I) {
  MType *CondType = I.getOperand<0>()->getType();
  MType *LHSType = I.getOperand<1>()->getType();
  MType *RHSType = I.getOperand<2>()->getType();
  CHECK(CondType->isI8() || CondType->isI32() || CondType->isI64(),
        "The type of select instruction condition must be i8/i32");
  CHECK(LHSType->getKind() == RHSType->getKind(),
        "The select left operand must have same type as select right operand");
  MVisitor::visitSelectInstruction(I);
}

void MVerifier::visitDassignInstruction(DassignInstruction &I) {
  MType *Type = I.getType();
  CHECK(
      Type->isVoid(),
      "The type of dassign instruction must be void, because it's a statement");
  MType *VarType = CurFunc->getVariableType(I.getVarIdx());
  MType *OperandType = I.getOperand<0>()->getType();
  CHECK(VarType->getKind() == OperandType->getKind(),
        "The variable and operand of dassign instruction must be of the same "
        "type");
  MVisitor::visitDassignInstruction(I);
}

void MVerifier::visitLoadInstruction(LoadInstruction &I) {
  MType *SrcType = I.getSrcType();
  MType *DestType = I.getDestType();
  if (SrcType->isInteger()) {
    CHECK(DestType->isI32() || DestType->isI64(),
          "The destination type of integer load must be i32 or i64");
    CHECK(DestType->getNumBytes() >= SrcType->getNumBytes(),
          "The destination of integer load must be wider than the source");
  } else {
    CHECK(SrcType->getKind() == DestType->getKind(),
          "The destination and source of floating-point load must be the same "
          "width");
  }

  MType *AddrType = I.getBase()->getType();
  CHECK(AddrType->isPointer(),
        "The address of load instruction must be pointer");
  MPointerType *PtrType = static_cast<MPointerType *>(AddrType);
  const MType *ElemType = PtrType->getElemType();
  if (!ElemType->isVoid()) {
    CHECK(SrcType->getKind() == ElemType->getKind(),
          "The type of load instruction source must be the same as the "
          "element type of the pointer");
  }
  const MInstruction *Index = I.getIndex();
  if (Index) {
    uint32_t Scale = I.getScale();
    CHECK(Scale == 1 || Scale == 2 || Scale == 4 || Scale == 8,
          "The scale of load instruction must be 1/2/4/8");
    MType *IndexType = Index->getType();
    CHECK(IndexType->isI32() || IndexType->isI64(),
          "The index of load instruction must be i32 or i64");
    MVisitor::visitInstruction(*const_cast<MInstruction *>(Index));
  }
  MVisitor::visitLoadInstruction(I);
}

void MVerifier::visitStoreInstruction(StoreInstruction &I) {
  MType *AddrType = I.getBase()->getType();
  CHECK(AddrType->isPointer(),
        "The target address of store instruction must be pointer");
  MPointerType *PtrType = static_cast<MPointerType *>(AddrType);
  const MType *ElemType = PtrType->getElemType();
  if (!ElemType->isVoid()) {
    CHECK(I.getValue()->getType()->getKind() == ElemType->getKind(),
          "The type of value in store instruction must be the same as the "
          "element type of the pointer");
  }
  const MInstruction *Index = I.getIndex();
  if (Index) {
    uint32_t Scale = I.getScale();
    CHECK(Scale == 1 || Scale == 2 || Scale == 4 || Scale == 8,
          "The scale of load instruction must be 1/2/4/8");
    MType *IndexType = Index->getType();
    CHECK(IndexType->isI32() || IndexType->isI64(),
          "The index of load instruction must be i32 or i64");
    MVisitor::visitInstruction(*const_cast<MInstruction *>(Index));
  }
  MVisitor::visitStoreInstruction(I);
}

void MVerifier::visitConstantInstruction(ConstantInstruction &I) {
  CHECK(I.getType()->getKind() == I.getConstant().getType().getKind(),
        "The type of constant instruction result must be the same as the "
        "constant type");
  MVisitor::visitConstantInstruction(I);
}

void MVerifier::visitBrInstruction(BrInstruction &I) {
  CHECK(I.getTargetBlock()->getIdx() < CurFunc->getNumBasicBlocks(),
        "The target index of br instruction must be less than number of "
        "basic blocks");
  MVisitor::visitBrInstruction(I);
}

void MVerifier::visitBrIfInstruction(BrIfInstruction &I) {
  MType *CondType = I.getOperand<0>()->getType();
  CHECK(CondType->isI8() || CondType->isI32() || CondType->isI64(),
        "The condition type of br_if instruction must be i8/i32/i64");

  CHECK(I.getTrueBlock(), "The br_if instruction must have true target");
  uint32_t NumBasicBlocks = CurFunc->getNumBasicBlocks();
  CHECK(I.getTrueBlock()->getIdx() < NumBasicBlocks,
        "The br_if true target index must be less than number of basic blocks");
  if (I.hasFalseBlock()) {
    CHECK(I.getFalseBlock()->getIdx() < NumBasicBlocks,
          "The br_if false target index must be less than number of basic "
          "blocks");
  }
  MVisitor::visitBrIfInstruction(I);
}

void MVerifier::visitSwitchInstruction(SwitchInstruction &I) {
  uint32_t NumBasicBlocks = CurFunc->getNumBasicBlocks();

  MType *CondType = I.getOperand<0>()->getType();
  CHECK(CondType->isInteger(),
        "The condition type of switch instruction must be integer");

  uint32_t NumCases = I.getNumCases();
  CHECK(I.getDefaultBlock()->getIdx() < NumBasicBlocks,
        "The default block index of switch instruction must be less than "
        "number of basic blocks");

  for (uint32_t i = 0; i < NumCases; i++) {
    CHECK(CondType->getKind() == I.getCaseValue(i)->getType()->getKind(),
          "The type of switch instruction condition must be the same as the "
          "case value type");
    CHECK(I.getCaseBlock(i)->getIdx() < NumBasicBlocks,
          "The case block index of switch instruction must be less than "
          "number of basic blocks");
  }

  MVisitor::visitSwitchInstruction(I);
}

void MVerifier::visitCallInstructionBase(CallInstructionBase &I) {
  if (!I.isStatement()) {
    CHECK(llvm::isa<DassignInstruction>(I.getParentInst()),
          "The call/icall instruction must be the right operand of the "
          "dassign instruction if it isn't a statement");
  }

  MVisitor::visitCallInstructionBase(I);
}

void MVerifier::visitCallInstruction(CallInstruction &Inst) {
  uint32_t CalleeIdx = Inst.getCalleeIdx();
  CHECK(CalleeIdx < Module.getNumFunctions(),
        "The callee index must be less than number of functions");

  uint32_t NumArgs = Inst.getNumOperands();
  MFunctionType *CalleeFuncType = Module.getFuncType(CalleeIdx);
  CHECK(NumArgs == CalleeFuncType->getNumParams(),
        "The number of arguments must be equal to number of parameters");

  llvm::ArrayRef<MType *> ParamTypes = CalleeFuncType->getParamTypes();
  for (uint32_t I = 0; I < NumArgs; ++I) {
    MType *ArgType = Inst.getOperand(I)->getType();
    CHECK(ArgType->getKind() == ParamTypes[I]->getKind(),
          "The types of arguments must be same as types of parameters");
  }

  MVisitor::visitCallInstruction(Inst);
}

void MVerifier::visitReturnInstruction(ReturnInstruction &I) {
  MType *ReturnType = CurFunc->getFunctionType()->getReturnType();
  if (ReturnType->isVoid()) {
    CHECK(I.getNumOperands() == 0,
          "The return instruction cannot have operands")
  } else {
    CHECK(I.getNumOperands() > 0, "The return instruction must have operands")
    const MInstruction *Operand = I.getOperand<0>();
    CHECK(Operand->getType()->getKind() == ReturnType->getKind(),
          "The type of return instruction operand must be same as function "
          "return type");
  }
  MVisitor::visitReturnInstruction(I);
}

void MVerifier::visitConversionInstruction(ConversionInstruction &I) {
  MType *OperandType = I.getOperand<0>()->getType();
  MType *ResultType = I.getType();

  switch (I.getOpcode()) {
  case OP_inttoptr:
    CHECK(OperandType->isI64(),
          "The operand of inttoptr instruction must be i64");
    CHECK(ResultType->isPointer(),
          "The result of inttoptr instruction must be pointer");
    break;
  case OP_ptrtoint:
    CHECK(OperandType->isPointer(),
          "The operand of ptrtoint instruction must be pointer");
    CHECK(ResultType->isI64(),
          "The result of ptrtoint instruction must be i64");
    break;
  case OP_uext:
  case OP_sext:
    visitIntExtInstruction(OperandType, ResultType);
    break;
  case OP_fpext:
    CHECK(OperandType->isF32() && ResultType->isF64(),
          "The type pair of fpext instruction is invalid");
    break;
  case OP_trunc:
    visitTruncInstruction(OperandType, ResultType);
    break;
  case OP_fptrunc:
    CHECK(OperandType->isF64() && ResultType->isF32(),
          "The type pair of fptrunc instruction is invalid");
    break;
  case OP_wasm_fptosi:
  case OP_wasm_fptoui:
    CHECK(OperandType->isFloat(),
          "The operand of wasm_fptosi/wasm_fptoui instruction must be float");
    CHECK(
        ResultType->isI32() || ResultType->isI64(),
        "The result of wasm_fptosi/wasm_fptoui instruction must be i32 or i64");
    break;
  case OP_uitofp:
  case OP_sitofp:
    CHECK(OperandType->isI32() || OperandType->isI64(),
          "The operand of uitofp/sitofp instruction must be i32 or i64");
    CHECK(ResultType->isFloat(),
          "The result of uitofp/sitofp instruction must be "
          "float");
    break;
  case OP_bitcast:
    visitBitcastInstruction(OperandType, ResultType);
    break;
  default:
    ZEN_ASSERT_TODO();
  }

  MVisitor::visitConversionInstruction(I);
}

void MVerifier::visitIntExtInstruction(MType *OperandType, MType *ResultType) {
  bool Valid = false;
  switch (OperandType->getKind()) {
  case MType::I8:
  case MType::I16:
    switch (ResultType->getKind()) {
    case MType::I32:
    case MType::I64:
      Valid = true;
      break;
    default:
      break;
    }
    break;
  case MType::I32:
    switch (ResultType->getKind()) {
    case MType::I64:
      Valid = true;
      break;
    default:
      break;
    }
    break;
  default:
    break;
  }
  CHECK(Valid, "The type pair of uext/sext instruction is invalid");
}

void MVerifier::visitTruncInstruction(MType *OperandType, MType *ResultType) {
  bool Valid = false;
  switch (OperandType->getKind()) {
  case MType::I32:
    switch (ResultType->getKind()) {
    case MType::I8:
    case MType::I16:
      Valid = true;
      break;
    default:
      break;
    }
    break;
  case MType::I64:
    switch (ResultType->getKind()) {
    case MType::I8:
    case MType::I16:
    case MType::I32:
      Valid = true;
      break;
    default:
      break;
    }
    break;
  default:
    break;
  }
  CHECK(Valid, "The type pair of trunc instruction is invalid");
}

void MVerifier::visitBitcastInstruction(MType *OperandType, MType *ResultType) {
  bool Valid = false;
  switch (OperandType->getKind()) {
  case MType::I32:
    Valid = ResultType->isF32();
    break;
  case MType::I64:
    Valid = ResultType->isF64();
    break;
  case MType::F32:
    Valid = ResultType->isI32();
    break;
  case MType::F64:
    Valid = ResultType->isI64();
    break;
  default:
    break;
  }
  CHECK(Valid, "The type pair of bitcast instruction is invalid");
}

void MVerifier::visitWasmCheckMemoryAccessInstruction(
    WasmCheckMemoryAccessInstruction &I) {
  const MInstruction *Base = I.getBase();
  if (Base) {
    MType *FromType = Base->getType();
    CHECK(FromType->isI32(), "The from type of wasm_check_memory_access "
                             "instruction result must be i32");
    MVisitor::visitInstruction(*const_cast<MInstruction *>(Base));
  }

  MType *BoundaryType = I.getBoundary()->getType();
  CHECK(BoundaryType->isI32(),
        "The boundary type of wasm_check_memory_access instruction result "
        "must be i32");
  MVisitor::visitWasmCheckMemoryAccessInstruction(I);
}

void MVerifier::visitWasmCheckStackBoundaryInstruction(
    WasmCheckStackBoundaryInstruction &I) {
  MType *BoundaryType = I.getOperand<0>()->getType();
  CHECK(BoundaryType->isI64(), "The boundary type of wasm_check_stack_boundary "
                               "instruction result must be i64");
  MVisitor::visitWasmCheckStackBoundaryInstruction(I);
}

void MVerifier::visitWasmVisitStackGuardInstruction(
    WasmVisitStackGuardInstruction &I) {
  MVisitor::visitWasmVisitStackGuardInstruction(I);
}
