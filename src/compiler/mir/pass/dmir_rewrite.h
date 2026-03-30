// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "compiler/mir/constants.h"
#include "compiler/mir/function.h"
#include "compiler/mir/instructions.h"
#include "llvm/Support/Casting.h"

namespace COMPILER {

class DMirRewritePass {
public:
  bool runOnMFunction(MFunction &F) {
    Func = &F;
    Changed = false;

    for (MBasicBlock *BB : F) {
      runOnBasicBlock(*BB);
    }

#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
    if (Changed) {
      llvm::dbgs() << "\n########## MIR Dump After dMIR Rewrite ##########\n\n";
      F.dump();
    }
#endif
    return Changed;
  }

private:
  void runOnBasicBlock(MBasicBlock &BB) {
    for (MInstruction *Inst : BB) {
      rewriteOperands(*Inst, BB);
    }
  }

  void rewriteOperands(MInstruction &Inst, MBasicBlock &BB) {
    for (uint32_t OperandIdx = 0; OperandIdx < Inst.getNumOperands();
         ++OperandIdx) {
      MInstruction *Operand = Inst.getOperand(OperandIdx);
      MInstruction *Rewritten = rewriteExprTree(Operand, BB);
      if (Rewritten != Operand) {
        Inst.setOperand(OperandIdx, Rewritten);
        Changed = true;
      }
    }
  }

  MInstruction *rewriteExprTree(MInstruction *Inst, MBasicBlock &BB) {
    for (uint32_t OperandIdx = 0; OperandIdx < Inst->getNumOperands();
         ++OperandIdx) {
      MInstruction *Operand = Inst->getOperand(OperandIdx);
      MInstruction *Rewritten = rewriteExprTree(Operand, BB);
      if (Rewritten != Operand) {
        Inst->setOperand(OperandIdx, Rewritten);
        Changed = true;
      }
    }

    if (MInstruction *Replacement = tryRewrite(*Inst, BB)) {
      if (Replacement != Inst) {
        Changed = true;
        return rewriteExprTree(Replacement, BB);
      }
      return Replacement;
    }
    return Inst;
  }

  MInstruction *tryRewrite(MInstruction &Inst, MBasicBlock &BB) {
    switch (Inst.getOpcode()) {
    case OP_add:
      return rewriteAdd(llvm::cast<BinaryInstruction>(Inst));
    case OP_sub:
      return rewriteSub(llvm::cast<BinaryInstruction>(Inst), BB);
    case OP_and:
      return rewriteAnd(llvm::cast<BinaryInstruction>(Inst), BB);
    case OP_or:
      return rewriteOr(llvm::cast<BinaryInstruction>(Inst), BB);
    case OP_xor:
      return rewriteXor(llvm::cast<BinaryInstruction>(Inst), BB);
    case OP_mul:
      return rewriteMul(llvm::cast<BinaryInstruction>(Inst), BB);
    case OP_shl:
    case OP_sshr:
    case OP_ushr:
      return rewriteShift(llvm::cast<BinaryInstruction>(Inst));
    case OP_not:
      return rewriteNot(llvm::cast<NotInstruction>(Inst));
    case OP_select:
      return rewriteSelect(llvm::cast<SelectInstruction>(Inst));
    default:
      return nullptr;
    }
  }

  MInstruction *rewriteAdd(BinaryInstruction &Inst) const {
    MInstruction *LHS = Inst.getOperand<0>();
    MInstruction *RHS = Inst.getOperand<1>();
    if (isZeroConst(*RHS)) {
      return LHS;
    }
    if (isZeroConst(*LHS)) {
      return RHS;
    }
    return nullptr;
  }

  MInstruction *rewriteSub(BinaryInstruction &Inst, MBasicBlock &BB) {
    MInstruction *LHS = Inst.getOperand<0>();
    MInstruction *RHS = Inst.getOperand<1>();
    if (isZeroConst(*RHS)) {
      return LHS;
    }
    if (structurallyEqual(*LHS, *RHS)) {
      return createZeroConstant(*Inst.getType(), BB);
    }
    return nullptr;
  }

  MInstruction *rewriteAnd(BinaryInstruction &Inst, MBasicBlock &BB) {
    MInstruction *LHS = Inst.getOperand<0>();
    MInstruction *RHS = Inst.getOperand<1>();
    if (isZeroConst(*LHS) || isZeroConst(*RHS)) {
      return createZeroConstant(*Inst.getType(), BB);
    }
    if (isAllOnesConst(*LHS)) {
      return RHS;
    }
    if (isAllOnesConst(*RHS)) {
      return LHS;
    }
    if (structurallyEqual(*LHS, *RHS)) {
      return LHS;
    }
    if (isNotOf(*LHS, *RHS) || isNotOf(*RHS, *LHS)) {
      return createZeroConstant(*Inst.getType(), BB);
    }
    if (MInstruction *Replacement = rewriteAndWithNestedAnd(*LHS, *RHS, BB)) {
      return Replacement;
    }
    if (MInstruction *Replacement = rewriteAndWithNestedAnd(*RHS, *LHS, BB)) {
      return Replacement;
    }
    if (MInstruction *Replacement = rewriteAndWithNestedOr(*LHS, *RHS)) {
      return Replacement;
    }
    if (MInstruction *Replacement = rewriteAndWithNestedOr(*RHS, *LHS)) {
      return Replacement;
    }
    if (MInstruction *Replacement = rewriteAndWithNestedNot(*LHS, *RHS, BB)) {
      return Replacement;
    }
    if (MInstruction *Replacement = rewriteAndWithNestedNot(*RHS, *LHS, BB)) {
      return Replacement;
    }
    return nullptr;
  }

  MInstruction *rewriteOr(BinaryInstruction &Inst, MBasicBlock &BB) {
    MInstruction *LHS = Inst.getOperand<0>();
    MInstruction *RHS = Inst.getOperand<1>();
    if (isZeroConst(*LHS)) {
      return RHS;
    }
    if (isZeroConst(*RHS)) {
      return LHS;
    }
    if (isAllOnesConst(*LHS) || isAllOnesConst(*RHS) || isNotOf(*LHS, *RHS) ||
        isNotOf(*RHS, *LHS)) {
      return createAllOnesConstant(*Inst.getType(), BB);
    }
    if (structurallyEqual(*LHS, *RHS)) {
      return LHS;
    }
    if (MInstruction *Replacement = rewriteOrWithNestedAnd(*LHS, *RHS, BB)) {
      return Replacement;
    }
    if (MInstruction *Replacement = rewriteOrWithNestedAnd(*RHS, *LHS, BB)) {
      return Replacement;
    }
    if (MInstruction *Replacement = rewriteOrWithNestedOr(*LHS, *RHS)) {
      return Replacement;
    }
    if (MInstruction *Replacement = rewriteOrWithNestedOr(*RHS, *LHS)) {
      return Replacement;
    }
    if (MInstruction *Replacement = rewriteOrWithNestedXor(*LHS, *RHS, BB)) {
      return Replacement;
    }
    if (MInstruction *Replacement = rewriteOrWithNestedXor(*RHS, *LHS, BB)) {
      return Replacement;
    }
    if (MInstruction *Replacement = rewriteOrWithNestedNot(*LHS, *RHS, BB)) {
      return Replacement;
    }
    if (MInstruction *Replacement = rewriteOrWithNestedNot(*RHS, *LHS, BB)) {
      return Replacement;
    }
    return nullptr;
  }

  MInstruction *rewriteXor(BinaryInstruction &Inst, MBasicBlock &BB) {
    MInstruction *LHS = Inst.getOperand<0>();
    MInstruction *RHS = Inst.getOperand<1>();
    if (isZeroConst(*LHS)) {
      return RHS;
    }
    if (isZeroConst(*RHS)) {
      return LHS;
    }
    if (structurallyEqual(*LHS, *RHS)) {
      return createZeroConstant(*Inst.getType(), BB);
    }
    if (isNotOf(*LHS, *RHS) || isNotOf(*RHS, *LHS)) {
      return createAllOnesConstant(*Inst.getType(), BB);
    }
    if (MInstruction *Replacement = rewriteXorWithNestedXor(*LHS, *RHS)) {
      return Replacement;
    }
    if (MInstruction *Replacement = rewriteXorWithNestedXor(*RHS, *LHS)) {
      return Replacement;
    }
    if (MInstruction *Replacement =
            rewriteXorWithNestedNotAndAllOnes(*LHS, *RHS)) {
      return Replacement;
    }
    if (MInstruction *Replacement =
            rewriteXorWithNestedNotAndAllOnes(*RHS, *LHS)) {
      return Replacement;
    }
    if (MInstruction *Replacement = rewriteXorWithNestedNot(*LHS, *RHS, BB)) {
      return Replacement;
    }
    if (MInstruction *Replacement = rewriteXorWithNestedNot(*RHS, *LHS, BB)) {
      return Replacement;
    }
    if (MInstruction *Replacement = rewriteXorWithTwoNots(*LHS, *RHS, BB)) {
      return Replacement;
    }
    if (MInstruction *Replacement = rewriteXorWithNestedAnd(*LHS, *RHS, BB)) {
      return Replacement;
    }
    if (MInstruction *Replacement = rewriteXorWithNestedAnd(*RHS, *LHS, BB)) {
      return Replacement;
    }
    if (MInstruction *Replacement = rewriteXorWithNestedOr(*LHS, *RHS, BB)) {
      return Replacement;
    }
    if (MInstruction *Replacement = rewriteXorWithNestedOr(*RHS, *LHS, BB)) {
      return Replacement;
    }
    return nullptr;
  }

  MInstruction *rewriteMul(BinaryInstruction &Inst, MBasicBlock &BB) {
    MInstruction *LHS = Inst.getOperand<0>();
    MInstruction *RHS = Inst.getOperand<1>();
    if (isZeroConst(*LHS) || isZeroConst(*RHS)) {
      return createZeroConstant(*Inst.getType(), BB);
    }
    if (isOneConst(*LHS)) {
      return RHS;
    }
    if (isOneConst(*RHS)) {
      return LHS;
    }
    return nullptr;
  }

  MInstruction *rewriteShift(BinaryInstruction &Inst) const {
    if (isZeroConst(*Inst.getOperand<1>())) {
      return Inst.getOperand<0>();
    }
    return nullptr;
  }

  MInstruction *rewriteNot(NotInstruction &Inst) const {
    MInstruction *Operand = Inst.getOperand<0>();
    if (Operand->getOpcode() == OP_not) {
      return Operand->getOperand<0>();
    }
    return nullptr;
  }

  MInstruction *rewriteSelect(SelectInstruction &Inst) const {
    MInstruction *TrueValue = Inst.getOperand<1>();
    MInstruction *FalseValue = Inst.getOperand<2>();
    if (structurallyEqual(*TrueValue, *FalseValue)) {
      return TrueValue;
    }
    return nullptr;
  }

  MInstruction *rewriteAndWithNestedAnd(MInstruction &NestedCandidate,
                                        MInstruction &Other, MBasicBlock &BB) {
    const BinaryInstruction *NestedAnd =
        getBinaryWithOpcode(NestedCandidate, OP_and);
    if (NestedAnd == nullptr) {
      return nullptr;
    }

    if (structurallyContains(*NestedAnd, Other)) {
      return const_cast<BinaryInstruction *>(NestedAnd);
    }
    if (isNotOf(Other, *NestedAnd->getOperand<0>()) ||
        isNotOf(Other, *NestedAnd->getOperand<1>())) {
      return createZeroConstant(*NestedAnd->getType(), BB);
    }

    const BinaryInstruction *OtherOr = getBinaryWithOpcode(Other, OP_or);
    if (OtherOr != nullptr && hasSameUnorderedOperands(*NestedAnd, *OtherOr)) {
      return const_cast<BinaryInstruction *>(NestedAnd);
    }

    const BinaryInstruction *OtherXor = getBinaryWithOpcode(Other, OP_xor);
    if (OtherXor != nullptr &&
        hasSameUnorderedOperands(*NestedAnd, *OtherXor)) {
      return createZeroConstant(*NestedAnd->getType(), BB);
    }

    return nullptr;
  }

  MInstruction *rewriteAndWithNestedOr(MInstruction &NestedCandidate,
                                       MInstruction &Other) const {
    const BinaryInstruction *NestedOr =
        getBinaryWithOpcode(NestedCandidate, OP_or);
    if (NestedOr == nullptr) {
      return nullptr;
    }

    if (structurallyContains(*NestedOr, Other)) {
      return &Other;
    }

    const BinaryInstruction *OtherXor = getBinaryWithOpcode(Other, OP_xor);
    if (OtherXor != nullptr && hasSameUnorderedOperands(*NestedOr, *OtherXor)) {
      return const_cast<BinaryInstruction *>(OtherXor);
    }

    return nullptr;
  }

  MInstruction *rewriteAndWithNestedNot(MInstruction &NestedCandidate,
                                        MInstruction &Other, MBasicBlock &BB) {
    if (NestedCandidate.getOpcode() != OP_not) {
      return nullptr;
    }

    const BinaryInstruction *OtherOr = getBinaryWithOpcode(Other, OP_or);
    if (OtherOr != nullptr) {
      if (MInstruction *OtherValue = getOtherBinaryOperand(
              *OtherOr, *NestedCandidate.getOperand<0>())) {
        return createBinaryInstruction(OP_and, *OtherOr->getType(),
                                       &NestedCandidate, OtherValue, BB);
      }
    }

    const BinaryInstruction *OtherXor = getBinaryWithOpcode(Other, OP_xor);
    if (OtherXor != nullptr) {
      if (MInstruction *OtherValue = getOtherBinaryOperand(
              *OtherXor, *NestedCandidate.getOperand<0>())) {
        return createBinaryInstruction(OP_and, *OtherXor->getType(),
                                       &NestedCandidate, OtherValue, BB);
      }
    }

    return nullptr;
  }

  MInstruction *rewriteOrWithNestedAnd(MInstruction &NestedCandidate,
                                       MInstruction &Other, MBasicBlock &BB) {
    const BinaryInstruction *NestedAnd =
        getBinaryWithOpcode(NestedCandidate, OP_and);
    if (NestedAnd == nullptr) {
      return nullptr;
    }

    if (structurallyContains(*NestedAnd, Other)) {
      return &Other;
    }

    const BinaryInstruction *OtherOr = getBinaryWithOpcode(Other, OP_or);
    if (OtherOr != nullptr && hasSameUnorderedOperands(*NestedAnd, *OtherOr)) {
      return const_cast<BinaryInstruction *>(OtherOr);
    }

    const BinaryInstruction *OtherXor = getBinaryWithOpcode(Other, OP_xor);
    if (OtherXor != nullptr &&
        hasSameUnorderedOperands(*NestedAnd, *OtherXor)) {
      return createBinaryInstruction(OP_or, *NestedAnd->getType(),
                                     NestedAnd->getOperand<0>(),
                                     NestedAnd->getOperand<1>(), BB);
    }

    if (Other.getOpcode() == OP_not) {
      if (MInstruction *OtherValue =
              getOtherBinaryOperand(*NestedAnd, *Other.getOperand<0>())) {
        return createBinaryInstruction(OP_or, *NestedAnd->getType(), &Other,
                                       OtherValue, BB);
      }
    }

    return nullptr;
  }

  MInstruction *rewriteOrWithNestedOr(MInstruction &NestedCandidate,
                                      MInstruction &Other) const {
    const BinaryInstruction *NestedOr =
        getBinaryWithOpcode(NestedCandidate, OP_or);
    if (NestedOr == nullptr) {
      return nullptr;
    }

    if (structurallyContains(*NestedOr, Other)) {
      return const_cast<BinaryInstruction *>(NestedOr);
    }

    const BinaryInstruction *OtherXor = getBinaryWithOpcode(Other, OP_xor);
    if (OtherXor != nullptr && hasSameUnorderedOperands(*NestedOr, *OtherXor)) {
      return const_cast<BinaryInstruction *>(NestedOr);
    }

    return nullptr;
  }

  MInstruction *rewriteOrWithNestedXor(MInstruction &NestedCandidate,
                                       MInstruction &Other, MBasicBlock &BB) {
    const BinaryInstruction *NestedXor =
        getBinaryWithOpcode(NestedCandidate, OP_xor);
    if (NestedXor == nullptr) {
      return nullptr;
    }

    if (structurallyContains(*NestedXor, Other)) {
      return createBinaryInstruction(OP_or, *NestedXor->getType(),
                                     NestedXor->getOperand<0>(),
                                     NestedXor->getOperand<1>(), BB);
    }

    return nullptr;
  }

  MInstruction *rewriteOrWithNestedNot(MInstruction &NestedCandidate,
                                       MInstruction &Other, MBasicBlock &BB) {
    if (NestedCandidate.getOpcode() != OP_not) {
      return nullptr;
    }

    const BinaryInstruction *OtherOr = getBinaryWithOpcode(Other, OP_or);
    if (OtherOr == nullptr) {
      return nullptr;
    }

    if (structurallyContains(*OtherOr, *NestedCandidate.getOperand<0>())) {
      return createAllOnesConstant(*OtherOr->getType(), BB);
    }
    return nullptr;
  }

  MInstruction *rewriteXorWithNestedXor(MInstruction &NestedCandidate,
                                        MInstruction &Other) const {
    const BinaryInstruction *NestedXor =
        getBinaryWithOpcode(NestedCandidate, OP_xor);
    if (NestedXor == nullptr) {
      return nullptr;
    }

    if (structurallyEqual(*NestedXor->getOperand<0>(), Other)) {
      return const_cast<MInstruction *>(NestedXor->getOperand<1>());
    }
    if (structurallyEqual(*NestedXor->getOperand<1>(), Other)) {
      return const_cast<MInstruction *>(NestedXor->getOperand<0>());
    }
    return nullptr;
  }

  MInstruction *rewriteXorWithNestedNotAndAllOnes(MInstruction &NestedCandidate,
                                                  MInstruction &Other) const {
    if (!isAllOnesConst(Other) || NestedCandidate.getOpcode() != OP_not) {
      return nullptr;
    }
    return NestedCandidate.getOperand<0>();
  }

  MInstruction *rewriteXorWithNestedNot(MInstruction &NestedCandidate,
                                        MInstruction &Other, MBasicBlock &BB) {
    if (NestedCandidate.getOpcode() != OP_not) {
      return nullptr;
    }

    const BinaryInstruction *OtherXor = getBinaryWithOpcode(Other, OP_xor);
    if (OtherXor != nullptr) {
      if (MInstruction *OtherValue = getOtherBinaryOperand(
              *OtherXor, *NestedCandidate.getOperand<0>())) {
        return createNotInstruction(*OtherXor->getType(), OtherValue, BB);
      }
    }

    const BinaryInstruction *OtherOr = getBinaryWithOpcode(Other, OP_or);
    if (OtherOr != nullptr) {
      if (MInstruction *OtherValue = getOtherBinaryOperand(
              *OtherOr, *NestedCandidate.getOperand<0>())) {
        return createBinaryInstruction(
            OP_or, *OtherOr->getType(),
            createNotInstruction(*OtherOr->getType(), OtherValue, BB),
            OtherOr->getOperand(0) == OtherValue ? OtherOr->getOperand(1)
                                                 : OtherOr->getOperand(0),
            BB);
      }
    }

    return nullptr;
  }

  MInstruction *rewriteXorWithTwoNots(MInstruction &LHS, MInstruction &RHS,
                                      MBasicBlock &BB) {
    if (LHS.getOpcode() != OP_not || RHS.getOpcode() != OP_not) {
      return nullptr;
    }
    return createBinaryInstruction(OP_xor, *LHS.getType(), LHS.getOperand<0>(),
                                   RHS.getOperand<0>(), BB);
  }

  MInstruction *rewriteXorWithNestedAnd(MInstruction &NestedCandidate,
                                        MInstruction &Other, MBasicBlock &BB) {
    const BinaryInstruction *NestedAnd =
        getBinaryWithOpcode(NestedCandidate, OP_and);
    if (NestedAnd == nullptr) {
      return nullptr;
    }

    const BinaryInstruction *OtherOr = getBinaryWithOpcode(Other, OP_or);
    if (OtherOr != nullptr && hasSameUnorderedOperands(*NestedAnd, *OtherOr)) {
      return createBinaryInstruction(OP_xor, *NestedAnd->getType(),
                                     NestedAnd->getOperand<0>(),
                                     NestedAnd->getOperand<1>(), BB);
    }

    const BinaryInstruction *OtherXor = getBinaryWithOpcode(Other, OP_xor);
    if (OtherXor != nullptr &&
        hasSameUnorderedOperands(*NestedAnd, *OtherXor)) {
      return createBinaryInstruction(OP_or, *NestedAnd->getType(),
                                     NestedAnd->getOperand<0>(),
                                     NestedAnd->getOperand<1>(), BB);
    }

    if (Other.getOpcode() == OP_not) {
      if (MInstruction *OtherValue =
              getOtherBinaryOperand(*NestedAnd, *Other.getOperand<0>())) {
        return createBinaryInstruction(OP_or, *NestedAnd->getType(), &Other,
                                       OtherValue, BB);
      }
    }

    return nullptr;
  }

  MInstruction *rewriteXorWithNestedOr(MInstruction &NestedCandidate,
                                       MInstruction &Other, MBasicBlock &BB) {
    const BinaryInstruction *NestedOr =
        getBinaryWithOpcode(NestedCandidate, OP_or);
    if (NestedOr == nullptr) {
      return nullptr;
    }

    const BinaryInstruction *OtherXor = getBinaryWithOpcode(Other, OP_xor);
    if (OtherXor != nullptr && hasSameUnorderedOperands(*NestedOr, *OtherXor)) {
      return createBinaryInstruction(OP_and, *NestedOr->getType(),
                                     NestedOr->getOperand<0>(),
                                     NestedOr->getOperand<1>(), BB);
    }

    return nullptr;
  }

  bool structurallyEqual(const MInstruction &LHS,
                         const MInstruction &RHS) const {
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
      if (!structurallyEqual(*LHSIndex, *RHSIndex)) {
        return false;
      }
      break;
    }
    default:
      break;
    }

    for (uint32_t OperandIdx = 0; OperandIdx < LHS.getNumOperands();
         ++OperandIdx) {
      if (!structurallyEqual(*LHS.getOperand(OperandIdx),
                             *RHS.getOperand(OperandIdx))) {
        return false;
      }
    }
    return true;
  }

  bool isNotOf(const MInstruction &MaybeNot, const MInstruction &Value) const {
    return MaybeNot.getOpcode() == OP_not &&
           structurallyEqual(*MaybeNot.getOperand<0>(), Value);
  }

  const BinaryInstruction *getBinaryWithOpcode(const MInstruction &Inst,
                                               Opcode Opc) const {
    if (Inst.getKind() != MInstruction::BINARY || Inst.getOpcode() != Opc) {
      return nullptr;
    }
    return static_cast<const BinaryInstruction *>(&Inst);
  }

  bool structurallyContains(const BinaryInstruction &Inst,
                            const MInstruction &Value) const {
    return structurallyEqual(*Inst.getOperand<0>(), Value) ||
           structurallyEqual(*Inst.getOperand<1>(), Value);
  }

  MInstruction *getOtherBinaryOperand(const BinaryInstruction &Inst,
                                      const MInstruction &Value) const {
    if (structurallyEqual(*Inst.getOperand<0>(), Value)) {
      return const_cast<MInstruction *>(Inst.getOperand<1>());
    }
    if (structurallyEqual(*Inst.getOperand<1>(), Value)) {
      return const_cast<MInstruction *>(Inst.getOperand<0>());
    }
    return nullptr;
  }

  bool hasSameUnorderedOperands(const BinaryInstruction &LHS,
                                const BinaryInstruction &RHS) const {
    return (structurallyEqual(*LHS.getOperand<0>(), *RHS.getOperand<0>()) &&
            structurallyEqual(*LHS.getOperand<1>(), *RHS.getOperand<1>())) ||
           (structurallyEqual(*LHS.getOperand<0>(), *RHS.getOperand<1>()) &&
            structurallyEqual(*LHS.getOperand<1>(), *RHS.getOperand<0>()));
  }

  static bool isIntegerConst(const MInstruction &Inst) {
    return Inst.getOpcode() == OP_const && Inst.getType()->isInteger();
  }

  static bool isZeroConst(const MInstruction &Inst) {
    if (!isIntegerConst(Inst)) {
      return false;
    }
    return llvm::cast<MConstantInt>(
               &llvm::cast<ConstantInstruction>(Inst).getConstant())
        ->getValue()
        .isZero();
  }

  static bool isOneConst(const MInstruction &Inst) {
    if (!isIntegerConst(Inst)) {
      return false;
    }
    return llvm::cast<MConstantInt>(
               &llvm::cast<ConstantInstruction>(Inst).getConstant())
        ->getValue()
        .isOne();
  }

  static bool isAllOnesConst(const MInstruction &Inst) {
    if (!isIntegerConst(Inst)) {
      return false;
    }
    return llvm::cast<MConstantInt>(
               &llvm::cast<ConstantInstruction>(Inst).getConstant())
        ->getValue()
        .isAllOnes();
  }

  MInstruction *createZeroConstant(MType &Type, MBasicBlock &BB) {
    return createIntegerConstant(Type, llvm::APInt(Type.getBitWidth(), 0), BB);
  }

  MInstruction *createAllOnesConstant(MType &Type, MBasicBlock &BB) {
    return createIntegerConstant(
        Type, llvm::APInt::getAllOnes(Type.getBitWidth()), BB);
  }

  MInstruction *createIntegerConstant(MType &Type, llvm::APInt Value,
                                      MBasicBlock &BB) {
    return Func->createInstruction<ConstantInstruction>(
        false, BB, &Type, *MConstantInt::get(Func->getContext(), Type, Value));
  }

  MInstruction *createNotInstruction(MType &Type, const MInstruction *Operand,
                                     MBasicBlock &BB) {
    return Func->createInstruction<NotInstruction>(
        false, BB, &Type, const_cast<MInstruction *>(Operand));
  }

  MInstruction *createBinaryInstruction(Opcode Opc, MType &Type,
                                        const MInstruction *LHS,
                                        const MInstruction *RHS,
                                        MBasicBlock &BB) {
    return Func->createInstruction<BinaryInstruction>(
        false, BB, Opc, &Type, const_cast<MInstruction *>(LHS),
        const_cast<MInstruction *>(RHS));
  }

  MFunction *Func = nullptr;
  bool Changed = false;
};

} // namespace COMPILER
