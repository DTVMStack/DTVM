// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "compiler/mir/instructions.h"
#include "compiler/common/consts.h"
#include "compiler/mir/instruction.h"
#include "compiler/mir/opcode.h"
#include "llvm/Support/Casting.h"
#include <cstdio>

using namespace COMPILER;

std::string CmpInstruction::getPredicateName() const {
  switch (_predicate) {
#define CONDCODE(TEXT, PREDICATE, VALUE)                                       \
  case PREDICATE:                                                              \
    return #TEXT;
#include "compiler/mir/cond_codes.def"
#undef CONDCODE
  default:
    ZEN_ASSERT(false);
  }
}

bool MInstruction::isTerminator() const {
  switch (_kind) {
  case BR:
  case SWITCH:
  case RETURN:
    return true;
  case BR_IF: {
    const BrIfInstruction *BrIfInstr = llvm::cast<BrIfInstruction>(this);
    return BrIfInstr->hasFalseBlock();
  }
  default:
    return false;
  }
}

// TODO, optimize implementation
void MInstruction::print(llvm::raw_ostream &OS) const {
  switch (_kind) {
  case DREAD: {
    auto *var = llvm::cast<DreadInstruction>(this);
    OS << '$' << var->getVarIdx();
    break;
  }
  case UNARY: {
    ZEN_ASSERT(_opcode >= OP_UNARY_EXPR_START && _opcode <= OP_UNARY_EXPR_END);
    OS << getOpcodeString(_opcode) << " (" << getOperand<0>() << ')';
    break;
  }
  case BINARY: {
    ZEN_ASSERT(_opcode >= OP_BIN_EXPR_START && _opcode <= OP_BIN_EXPR_END);
    OS << getOpcodeString(_opcode) << " (" << getOperand<0>() << ", "
       << getOperand<1>() << ')';
    break;
  }
  case OVERFLOW_I128_BINARY:
    OS << getOpcodeString(_opcode) << " (" << getOperand<0>() << ", "
       << getOperand<1>() << ", " << getOperand<2>() << ", " << getOperand<3>()
       << ')';
    break;
  case DASSIGN: {
    auto *assign = llvm::cast<DassignInstruction>(this);
    OS << '$' << assign->getVarIdx() << " = " << getOperand<0>() << "\n";
    break;
  }
  case CMP: {
    auto *cmp_inst = llvm::cast<CmpInstruction>(this);
    OS << "cmp " << cmp_inst->getPredicateName() << " (" << getOperand<0>()
       << ", " << getOperand<1>() << ')';
    break;
  }
  case CONSTANT: {
    auto *const_inst = llvm::cast<ConstantInstruction>(this);
    OS << "const." << const_inst->getType() << ' ' << const_inst->getConstant();
    break;
  }
  case SELECT: {
    OS << "select (cond = " << getOperand<0>() << ", lhs = " << getOperand<1>()
       << ", rhs = " << getOperand<2>() << ')';
    break;
  }
  case ADC: {
    OS << "adc (" << getOperand<0>() << ", " << getOperand<1>() << ", "
       << getOperand<2>() << ')';
    break;
  }
  case BR: {
    auto *br = llvm::cast<BrInstruction>(this);
    OS << "br @" << br->getTargetBlock()->getIdx() << '\n';
    break;
  }
  case BR_IF: {
    auto *br_if = llvm::cast<BrIfInstruction>(this);
    OS << "br_if " << getOperand<0>();
    OS << ", @" << br_if->getTrueBlock()->getIdx();
    if (br_if->hasFalseBlock()) {
      OS << ", @" << br_if->getFalseBlock()->getIdx();
    }
    OS << '\n';
    break;
  }
  case SWITCH: {
    auto *sw = llvm::cast<SwitchInstruction>(this);
    OS << "switch " << getOperand<0>() << ", @"
       << sw->getDefaultBlock()->getIdx() << " [\n";
    uint32_t num_cases = sw->getNumCases();
    for (uint32_t i = 0; i < num_cases; i++) {
      auto &case_value =
          llvm::cast<MConstantInt>(sw->getCaseValue(i)->getConstant());
      OS << kDumpIndent4 << case_value << " -> @"
         << sw->getCaseBlock(i)->getIdx();
      if (i == num_cases - 1) {
        OS << '\n';
      } else {
        OS << ",\n";
      }
    }
    OS << kDumpIndent << "]\n";
    break;
  }
  case CALL: {
    if (auto *icall = llvm::dyn_cast<ICallInstruction>(this)) {
      OS << "icall " << icall->getType()
         << " (target = " << icall->getCalleeAddr() << ", ";
    } else {
      auto *dcall = llvm::cast<CallInstruction>(this);
      OS << "call %" << dcall->getCalleeIdx() << " (";
    }
    for (OperandNum i = 0; i < getNumOperands(); ++i) {
      OS << getOperand(i);
      if (i != getNumOperands() - 1) {
        OS << ", ";
      }
    }
    OS << ')';
    if (getType()->isVoid()) {
      OS << '\n';
    }
    break;
  }
  case RETURN: {
    auto *ret = llvm::cast<ReturnInstruction>(this);
    OS << "return";
    if (ret->getNumOperands() != 0) {
      OS << " " << getOperand<0>();
    }
    OS << "\n";
    break;
  }
  case LOAD: {
    const LoadInstruction *LoadInstr = llvm::cast<LoadInstruction>(this);
    OS << "load (base = " << LoadInstr->getBase();
    const MInstruction *Index = LoadInstr->getIndex();
    if (Index) {
      uint32_t Scale = LoadInstr->getScale();
      OS << ", scale = " << Scale << ", index = " << Index;
    }
    int32_t Offset = LoadInstr->getOffset();
    if (Offset) {
      OS << ", offset = " << Offset;
    }
    OS << ')';
    break;
  }
  case STORE: {
    const StoreInstruction *StoreInstr = llvm::cast<StoreInstruction>(this);
    OS << "store (value = " << StoreInstr->getValue();
    OS << ", base = " << StoreInstr->getBase();
    const MInstruction *Index = StoreInstr->getIndex();
    if (Index) {
      uint32_t Scale = StoreInstr->getScale();
      OS << ", scale = " << Scale << ", index = " << Index;
    }
    int32_t Offset = StoreInstr->getOffset();
    if (Offset) {
      OS << ", offset = " << Offset;
    }
    OS << ")\n";
    break;
  }
  case CONVERSION: {
    ZEN_ASSERT(_opcode >= OP_CONV_EXPR_START && _opcode <= OP_CONV_EXPR_END);
    OS << getOpcodeString(_opcode) << " (" << getOperand<0>() << ", "
       << getType() << ")";
    break;
  }
  case WASM_CHECK: {
    OS << getOpcodeString(_opcode) << " (";
    switch (_opcode) {
    case OP_wasm_check_memory_access: {
      auto *check_inst = llvm::cast<WasmCheckMemoryAccessInstruction>(this);
      const MInstruction *Base = check_inst->getBase();
      if (Base) {
        OS << "base = " << Base << ", ";
      }
      OS << "offset = " << check_inst->getOffset()
         << ", size = " << check_inst->getSize()
         << ", boundary = " << check_inst->getBoundary();
      break;
    }
    case OP_wasm_check_stack_boundary: {
      auto *check_inst = llvm::cast<WasmCheckStackBoundaryInstruction>(this);
      OS << "boundary = " << getOperand<0>();
      break;
    }
    case OP_wasm_visit_stack_guard: {
      auto *check_inst = llvm::cast<WasmVisitStackGuardInstruction>(this);
      OS << "visit_stack_guard";
      break;
    }
    default:
      ZEN_ASSERT_TODO();
    }
    OS << ")\n";
    break;
  }
  default:
    ZEN_ASSERT_TODO();
  }
}
#if !defined(NDEBUG) || defined(LLVM_ENABLE_DUMP)
void MInstruction::dump() const { print(llvm::dbgs()); }
#endif
