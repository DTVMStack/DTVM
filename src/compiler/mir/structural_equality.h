// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "compiler/mir/constants.h"
#include "compiler/mir/instructions.h"
#include "compiler/mir/opcode.h"
#include <llvm/Support/Casting.h>

namespace COMPILER {

// Structural equality on MInstruction trees. Used by both DMirRewritePass
// (production peephole, dmir_rewrite.h) and the Phase 2 shadow audit
// matcher (dmir_shadow_runtime.cpp variable-rebind path). Pointer-identical
// nodes return true immediately; otherwise opcode/kind/type/operand-count
// must agree, plus opcode-specific payload checks for OP_const, OP_dread,
// OP_cmp, OP_load, and the U256 add/sub result variants.
inline bool structurallyEqualMInstruction(const MInstruction &LHS,
                                          const MInstruction &RHS) {
  if (&LHS == &RHS) {
    return true;
  }
  if (LHS.getOpcode() != RHS.getOpcode() || LHS.getKind() != RHS.getKind() ||
      LHS.getType() != RHS.getType() ||
      LHS.getNumOperands() != RHS.getNumOperands()) {
    return false;
  }

  switch (LHS.getOpcode()) {
  case OP_const: {
    const auto &LHSConst = llvm::cast<ConstantInstruction>(LHS).getConstant();
    const auto &RHSConst = llvm::cast<ConstantInstruction>(RHS).getConstant();
    if (!LHSConst.getType().isInteger() || !RHSConst.getType().isInteger()) {
      return false;
    }
    return llvm::cast<MConstantInt>(&LHSConst)->getValue() ==
           llvm::cast<MConstantInt>(&RHSConst)->getValue();
  }
  case OP_dread:
    return llvm::cast<DreadInstruction>(LHS).getVarIdx() ==
           llvm::cast<DreadInstruction>(RHS).getVarIdx();
  case OP_cmp:
    if (llvm::cast<CmpInstruction>(LHS).getPredicate() !=
        llvm::cast<CmpInstruction>(RHS).getPredicate()) {
      return false;
    }
    break;
  case OP_load: {
    // NOTE: Load instructions are compared structurally (by address
    // computation parameters). This assumes no intervening stores between
    // the two loads. In the current EVM frontend, each load comes from
    // extractU256Operand and produces a unique instruction, so pointer
    // equality catches all real cases. If the frontend evolves to produce
    // aliased loads, this must be revisited.
    const auto &LHSLoad = llvm::cast<LoadInstruction>(LHS);
    const auto &RHSLoad = llvm::cast<LoadInstruction>(RHS);
    if (LHSLoad.getScale() != RHSLoad.getScale() ||
        LHSLoad.getOffset() != RHSLoad.getOffset() ||
        LHSLoad.getSrcType() != RHSLoad.getSrcType() ||
        LHSLoad.getDestType() != RHSLoad.getDestType() ||
        LHSLoad.getSext() != RHSLoad.getSext()) {
      return false;
    }
    const MInstruction *LHSIndex = LHSLoad.getIndex();
    const MInstruction *RHSIndex = RHSLoad.getIndex();
    if (LHSIndex == nullptr || RHSIndex == nullptr) {
      if (LHSIndex != RHSIndex) {
        return false;
      }
      break;
    }
    if (!structurallyEqualMInstruction(*LHSIndex, *RHSIndex)) {
      return false;
    }
    break;
  }
  case OP_evm_u256_add_result: {
    const auto &LHSRes = llvm::cast<EvmU256AddResultInstruction>(LHS);
    const auto &RHSRes = llvm::cast<EvmU256AddResultInstruction>(RHS);
    if (LHSRes.getResultIdx() != RHSRes.getResultIdx()) {
      return false;
    }
    break;
  }
  case OP_evm_u256_sub_result: {
    const auto &LHSRes = llvm::cast<EvmU256SubResultInstruction>(LHS);
    const auto &RHSRes = llvm::cast<EvmU256SubResultInstruction>(RHS);
    if (LHSRes.getResultIdx() != RHSRes.getResultIdx()) {
      return false;
    }
    break;
  }
  default:
    break;
  }

  for (uint32_t OperandIdx = 0; OperandIdx < LHS.getNumOperands();
       ++OperandIdx) {
    if (!structurallyEqualMInstruction(*LHS.getOperand(OperandIdx),
                                       *RHS.getOperand(OperandIdx))) {
      return false;
    }
  }
  return true;
}

} // namespace COMPILER
