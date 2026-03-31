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
      return rewriteAdd(llvm::cast<BinaryInstruction>(Inst), BB);
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
    case OP_adc:
      return rewriteAdc(llvm::cast<AdcInstruction>(Inst), BB);
    case OP_sbb:
      return rewriteSbb(llvm::cast<SbbInstruction>(Inst), BB);
    default:
      return nullptr;
    }
  }

  MInstruction *rewriteAdd(BinaryInstruction &Inst, MBasicBlock &BB) {
    MInstruction *LHS = Inst.getOperand<0>();
    MInstruction *RHS = Inst.getOperand<1>();
    if (isZeroConst(*RHS)) {
      return LHS;
    }
    if (isZeroConst(*LHS)) {
      return RHS;
    }
    // (add x x) -> (shl x 1): doubling is a left shift by one
    if (structurallyEqual(*LHS, *RHS)) {
      return createBinaryInstruction(OP_shl, *Inst.getType(), LHS,
                                     createOneConstant(*Inst.getType(), BB),
                                     BB);
    }
    // (add (sub 0 x) y) -> (sub y x): negation folding
    if (isNeg(*LHS)) {
      return createBinaryInstruction(OP_sub, *Inst.getType(), RHS,
                                     getNegOperand(*LHS), BB);
    }
    if (isNeg(*RHS)) {
      return createBinaryInstruction(OP_sub, *Inst.getType(), LHS,
                                     getNegOperand(*RHS), BB);
    }
    // (add (and x y) (xor x y)) -> (or x y)
    if (const auto *AndInst =
            matchBinaryOperandPair(*LHS, *RHS, OP_and, OP_xor)) {
      return createBinaryInstruction(OP_or, *Inst.getType(),
                                     AndInst->getOperand<0>(),
                                     AndInst->getOperand<1>(), BB);
    }
    // (add (and x y) (or x y)) -> (add x y)
    if (const auto *AndInst =
            matchBinaryOperandPair(*LHS, *RHS, OP_and, OP_or)) {
      return createBinaryInstruction(OP_add, *Inst.getType(),
                                     AndInst->getOperand<0>(),
                                     AndInst->getOperand<1>(), BB);
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
    // (sub (and x y) (or x y)) -> (sub 0 (xor x y))
    if (const auto *AndInst =
            matchBinaryOperandPair(*LHS, *RHS, OP_and, OP_or)) {
      MInstruction *XorInst = createBinaryInstruction(
          OP_xor, *Inst.getType(), AndInst->getOperand<0>(),
          AndInst->getOperand<1>(), BB);
      return createBinaryInstruction(OP_sub, *Inst.getType(),
                                     createZeroConstant(*Inst.getType(), BB),
                                     XorInst, BB);
    }
    // (sub (or x y) (and x y)) -> (xor x y)
    if (const auto *OrInst =
            matchBinaryOperandPair(*LHS, *RHS, OP_or, OP_and)) {
      return createBinaryInstruction(OP_xor, *Inst.getType(),
                                     OrInst->getOperand<0>(),
                                     OrInst->getOperand<1>(), BB);
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
    // mul(x, 2^k) -> shl(x, k) for i64 types when k >= 1
    if (Inst.getType()->isInteger() && Inst.getType()->getBitWidth() == 64 &&
        isIntegerConst(*RHS)) {
      uint64_t C = llvm::cast<MConstantInt>(
                       &llvm::cast<ConstantInstruction>(RHS)->getConstant())
                       ->getValue()
                       .getZExtValue();
      if (C > 1 && (C & (C - 1)) == 0) {
        uint64_t K = static_cast<uint64_t>(__builtin_ctzll(C));
        return createBinaryInstruction(
            OP_shl, *Inst.getType(), LHS,
            createIntegerConstant(*Inst.getType(), llvm::APInt(64, K), BB), BB);
      }
    }
    return nullptr;
  }

  /// Carry-dead analysis: returns true when the carry/borrow output of the
  /// instruction that feeds this ADC/SBB is provably zero.
  ///
  /// Currently handles:
  ///   - const(0) operand (legacy placeholder or genuine chain-head zero)
  ///   - add(x, 0) / add(0, x): x + 0 never overflows, carry = 0
  ///   - adc(x, 0, prev) where isCarryDead(prev): x + 0 + 0 never overflows
  bool isCarryDead(const MInstruction &CarryProducer) const {
    // A const(0) carry operand means "no incoming carry" (chain head).
    if (isZeroConst(CarryProducer)) {
      return true;
    }
    // add(x, 0) or add(0, x): adding zero never produces a carry.
    if (CarryProducer.getOpcode() == OP_add &&
        CarryProducer.getKind() == MInstruction::BINARY) {
      const auto &Add = llvm::cast<BinaryInstruction>(CarryProducer);
      if (isZeroConst(*Add.getOperand<0>()) ||
          isZeroConst(*Add.getOperand<1>())) {
        return true;
      }
    }
    // adc(x, 0, prev) where prev's carry is also dead: recursive chain.
    if (CarryProducer.getOpcode() == OP_adc) {
      const auto &Adc = llvm::cast<AdcInstruction>(CarryProducer);
      if ((isZeroConst(*Adc.getOperand<0>()) ||
           isZeroConst(*Adc.getOperand<1>())) &&
          isCarryDead(*Adc.getOperand<2>())) {
        return true;
      }
    }
    // sub(x, 0): subtracting zero never borrows.
    if (CarryProducer.getOpcode() == OP_sub &&
        CarryProducer.getKind() == MInstruction::BINARY) {
      const auto &Sub = llvm::cast<BinaryInstruction>(CarryProducer);
      if (isZeroConst(*Sub.getOperand<1>())) {
        return true;
      }
    }
    // sbb(x, 0, prev) where prev's borrow is dead: recursive chain.
    if (CarryProducer.getOpcode() == OP_sbb) {
      const auto &Sbb = llvm::cast<SbbInstruction>(CarryProducer);
      if (isZeroConst(*Sbb.getOperand<1>()) &&
          isCarryDead(*Sbb.getOperand<2>())) {
        return true;
      }
    }
    // zext(icmp(ULT, x, 0)): no unsigned value is less than 0, always false.
    if (CarryProducer.getOpcode() == OP_uext &&
        CarryProducer.getKind() == MInstruction::UNARY) {
      const MInstruction *Inner = CarryProducer.getOperand<0>();
      if (Inner->getOpcode() == OP_cmp &&
          llvm::cast<CmpInstruction>(Inner)->getPredicate() ==
              CmpInstruction::ICMP_ULT) {
        if (isZeroConst(*Inner->getOperand<1>())) {
          return true;
        }
      }
    }
    return false;
  }

  MInstruction *rewriteAdc(AdcInstruction &Inst, MBasicBlock &BB) {
    MInstruction *LHS = Inst.getOperand<0>();
    MInstruction *RHS = Inst.getOperand<1>();
    MInstruction *CarryIn = Inst.getOperand<2>();
    if (!isCarryDead(*CarryIn)) {
      return nullptr;
    }
    // Carry is provably zero: adc(x, y, dead) → add(x, y)
    if (isZeroConst(*RHS)) {
      return LHS; // adc(x, 0, dead) → x
    }
    if (isZeroConst(*LHS)) {
      return RHS; // adc(0, y, dead) → y
    }
    return createBinaryInstruction(OP_add, *Inst.getType(), LHS, RHS, BB);
  }

  MInstruction *rewriteSbb(SbbInstruction &Inst, MBasicBlock &BB) {
    MInstruction *LHS = Inst.getOperand<0>();
    MInstruction *RHS = Inst.getOperand<1>();
    MInstruction *BorrowIn = Inst.getOperand<2>();
    if (!isCarryDead(*BorrowIn)) {
      return nullptr;
    }
    // Borrow is provably zero: sbb(x, y, dead) → sub(x, y)
    if (isZeroConst(*RHS)) {
      return LHS; // sbb(x, 0, dead) → x
    }
    if (structurallyEqual(*LHS, *RHS)) {
      return createZeroConstant(*Inst.getType(), BB); // sbb(x, x, dead) → 0
    }
    return createBinaryInstruction(OP_sub, *Inst.getType(), LHS, RHS, BB);
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
    MInstruction *Cond = Inst.getOperand<0>();
    MInstruction *TrueValue = Inst.getOperand<1>();
    MInstruction *FalseValue = Inst.getOperand<2>();
    // select(0, t, f) -> f: condition is always false
    if (isZeroConst(*Cond)) {
      return FalseValue;
    }
    // select(nonzero, t, f) -> t: condition is always true
    if (isNonZeroIntConst(*Cond)) {
      return TrueValue;
    }
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

  // Match a pair of binary operands where one has opcode OpcA and the other
  // has opcode OpcB, and both share the same unordered operand set.
  // Returns the OpcA instruction on success, nullptr otherwise.
  const BinaryInstruction *matchBinaryOperandPair(const MInstruction &LHS,
                                                  const MInstruction &RHS,
                                                  Opcode OpcA,
                                                  Opcode OpcB) const {
    if (const auto *A = getBinaryWithOpcode(LHS, OpcA))
      if (const auto *B = getBinaryWithOpcode(RHS, OpcB))
        if (hasSameUnorderedOperands(*A, *B))
          return A;
    if (const auto *A = getBinaryWithOpcode(RHS, OpcA))
      if (const auto *B = getBinaryWithOpcode(LHS, OpcB))
        if (hasSameUnorderedOperands(*A, *B))
          return A;
    return nullptr;
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

  static bool isNonZeroIntConst(const MInstruction &Inst) {
    if (!isIntegerConst(Inst)) {
      return false;
    }
    return !llvm::cast<MConstantInt>(
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

  MInstruction *createOneConstant(MType &Type, MBasicBlock &BB) {
    return createIntegerConstant(Type, llvm::APInt(Type.getBitWidth(), 1), BB);
  }

  // Returns true if Inst is (sub 0 x), i.e. a negation of x.
  static bool isNeg(const MInstruction &Inst) {
    if (Inst.getOpcode() != OP_sub) {
      return false;
    }
    return isZeroConst(*Inst.getOperand<0>());
  }

  // Returns the negated operand x from (sub 0 x). Caller must check isNeg.
  static MInstruction *getNegOperand(MInstruction &Inst) {
    return Inst.getOperand<1>();
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
