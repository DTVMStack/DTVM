// Copyright (C) 2021-2026 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/mir/pass/peephole.h"
#include "compiler/context.h"
#include "compiler/mir/basic_block.h"
#include "compiler/mir/constants.h"
#include "compiler/mir/instruction.h"
#include "compiler/mir/instructions.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/Casting.h"

using namespace COMPILER;

void MIRPeephole::runOnMFunction(MFunction &Func) {
  F = &Func;
  for (MBasicBlock *BB : Func) {
    rewriteBlock(*BB);
  }

#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  llvm::dbgs() << "\n########## MIR Dump After MIR Peephole ##########\n\n";
  Func.dump();
#endif
}

void MIRPeephole::rewriteBlock(MBasicBlock &BB) {
  CurBB = &BB;
  // Snapshot on the host heap. A CompileVector here shares the LLVM
  // bump slab with IR and can read ASan red zones on growth.
  llvm::SmallVector<MInstruction *, 16> Stmts;
  llvm::SmallPtrSet<MInstruction *, 32> InBlock;
  for (MInstruction *Inst : BB) {
    Stmts.push_back(Inst);
    InBlock.insert(Inst);
  }
  for (MInstruction *Inst : Stmts) {
    if (!InBlock.contains(Inst)) {
      continue;
    }
    for (OperandNum I = 0, E = Inst->getNumOperands(); I != E; ++I) {
      MInstruction *Op = Inst->getOperand(I);
      if (Op == nullptr) {
        continue;
      }
      MInstruction *NewOp = rewriteExpr(Op);
      if (NewOp != Op) {
        Inst->setOperand(I, NewOp);
      }
    }
    if (auto *BrIf = llvm::dyn_cast<BrIfInstruction>(Inst)) {
      if (foldConstBrIf(BB, *BrIf)) {
        InBlock.erase(BrIf);
        InBlock.clear();
        for (MInstruction *Cur : BB) {
          InBlock.insert(Cur);
        }
      }
    }
  }
}

MInstruction *MIRPeephole::rewriteExpr(MInstruction *Inst) {
  ZEN_ASSERT(Inst);
  for (OperandNum I = 0, E = Inst->getNumOperands(); I != E; ++I) {
    MInstruction *Op = Inst->getOperand(I);
    if (Op == nullptr) {
      continue;
    }
    MInstruction *NewOp = rewriteExpr(Op);
    if (NewOp != Op) {
      Inst->setOperand(I, NewOp);
    }
  }
  return foldExpr(Inst);
}

MInstruction *MIRPeephole::foldExpr(MInstruction *Inst) {
  if (MInstruction *New = foldBitCountEqZero(Inst)) {
    return New;
  }
  if (MInstruction *New = foldSelectICmp(Inst)) {
    return New;
  }
  if (MInstruction *New = foldSelectConstCond(Inst)) {
    return New;
  }
  if (MInstruction *New = foldConstCmp(Inst)) {
    return New;
  }
  if (MInstruction *New = foldAlgebra(Inst)) {
    return New;
  }
  return Inst;
}

MInstruction *MIRPeephole::foldBitCountEqZero(MInstruction *Inst) {
  auto *Cmp = llvm::dyn_cast<CmpInstruction>(Inst);
  if (!Cmp) {
    return nullptr;
  }
  const CmpInstruction::Predicate Pred = Cmp->getPredicate();
  if (Pred != CmpInstruction::ICMP_EQ && Pred != CmpInstruction::ICMP_NE) {
    return nullptr;
  }

  MInstruction *LHS = Cmp->getOperand<0>();
  MInstruction *RHS = Cmp->getOperand<1>();
  MInstruction *BitCount = nullptr;
  if (isIntZero(RHS) && LHS &&
      (LHS->getOpcode() == OP_ctz || LHS->getOpcode() == OP_clz)) {
    BitCount = LHS;
  } else if (isIntZero(LHS) && RHS &&
             (RHS->getOpcode() == OP_ctz || RHS->getOpcode() == OP_clz)) {
    BitCount = RHS;
  } else {
    return nullptr;
  }

  MInstruction *X = BitCount->getOperand<0>();
  MType *XTy = X->getType();
  if (!XTy->isInteger()) {
    return nullptr;
  }

  const bool WantEq = Pred == CmpInstruction::ICMP_EQ;
  if (BitCount->getOpcode() == OP_ctz) {
    // ctz(x)==0  <=>  (x & 1) != 0
    // ctz(x)!=0  <=>  (x & 1) == 0
    MInstruction *One = makeIntConst(XTy, 1);
    MInstruction *Masked = makeAnd(XTy, X, One);
    MInstruction *Zero = makeIntConst(XTy, 0);
    return makeICmp(WantEq ? CmpInstruction::ICMP_NE : CmpInstruction::ICMP_EQ,
                    Cmp->getType(), Masked, Zero);
  }

  // clz(x)==0  <=>  sign bit set  <=>  x < 0 (signed)
  // clz(x)!=0  <=>  x >= 0
  MInstruction *Zero = makeIntConst(XTy, 0);
  return makeICmp(WantEq ? CmpInstruction::ICMP_SLT : CmpInstruction::ICMP_SGE,
                  Cmp->getType(), X, Zero);
}

MInstruction *MIRPeephole::foldSelectICmp(MInstruction *Inst) {
  auto *Cmp = llvm::dyn_cast<CmpInstruction>(Inst);
  if (!Cmp) {
    return nullptr;
  }
  const CmpInstruction::Predicate Pred = Cmp->getPredicate();
  if (Pred != CmpInstruction::ICMP_EQ && Pred != CmpInstruction::ICMP_NE) {
    return nullptr;
  }

  MInstruction *LHS = Cmp->getOperand<0>();
  MInstruction *RHS = Cmp->getOperand<1>();
  SelectInstruction *Sel = nullptr;
  MInstruction *Key = nullptr;
  if (auto *S = llvm::dyn_cast<SelectInstruction>(LHS)) {
    Sel = S;
    Key = RHS;
  } else if (auto *S = llvm::dyn_cast<SelectInstruction>(RHS)) {
    Sel = S;
    Key = LHS;
  } else {
    return nullptr;
  }

  llvm::APInt TrueVal, FalseVal, KeyVal;
  if (!matchIntConst(Sel->getOperand<1>(), TrueVal) ||
      !matchIntConst(Sel->getOperand<2>(), FalseVal) ||
      !matchIntConst(Key, KeyVal)) {
    return nullptr;
  }

  MInstruction *Cond = Sel->getOperand<0>();
  if (TrueVal == FalseVal) {
    if (!isPureExpr(Sel)) {
      return nullptr;
    }
    const bool Eq = TrueVal == KeyVal;
    const bool Result = Pred == CmpInstruction::ICMP_EQ ? Eq : !Eq;
    return makeIntConst(Cmp->getType(), Result ? 1 : 0);
  }
  if (KeyVal != TrueVal && KeyVal != FalseVal) {
    if (!isPureExpr(Sel)) {
      return nullptr;
    }
    return makeIntConst(Cmp->getType(),
                        Pred == CmpInstruction::ICMP_EQ ? 0 : 1);
  }

  const bool CmpToTrueArm = KeyVal == TrueVal;
  const bool TrueWhenCondTrue =
      Pred == CmpInstruction::ICMP_EQ ? CmpToTrueArm : !CmpToTrueArm;
  MInstruction *Zero = makeIntConst(Cond->getType(), 0);
  return makeICmp(TrueWhenCondTrue ? CmpInstruction::ICMP_NE
                                   : CmpInstruction::ICMP_EQ,
                  Cmp->getType(), Cond, Zero);
}

MInstruction *MIRPeephole::foldSelectConstCond(MInstruction *Inst) {
  auto *Sel = llvm::dyn_cast<SelectInstruction>(Inst);
  if (!Sel) {
    return nullptr;
  }
  MInstruction *Cond = Sel->getOperand<0>();
  MInstruction *TrueV = Sel->getOperand<1>();
  MInstruction *FalseV = Sel->getOperand<2>();
  if (TrueV == FalseV) {
    // Dropping Cond is only safe if it has no effects.
    return isPureExpr(Cond) ? TrueV : nullptr;
  }
  llvm::APInt CondVal;
  if (!matchIntConst(Cond, CondVal)) {
    return nullptr;
  }
  MInstruction *Keep = CondVal.isZero() ? FalseV : TrueV;
  MInstruction *Drop = CondVal.isZero() ? TrueV : FalseV;
  if (!isPureExpr(Drop)) {
    return nullptr;
  }
  return Keep;
}

MInstruction *MIRPeephole::foldConstCmp(MInstruction *Inst) {
  auto *Cmp = llvm::dyn_cast<CmpInstruction>(Inst);
  if (!Cmp) {
    return nullptr;
  }
  MInstruction *LHS = Cmp->getOperand<0>();
  MInstruction *RHS = Cmp->getOperand<1>();
  if (LHS == RHS && LHS->getType()->isInteger() && isPureExpr(LHS)) {
    switch (Cmp->getPredicate()) {
    case CmpInstruction::ICMP_EQ:
    case CmpInstruction::ICMP_UGE:
    case CmpInstruction::ICMP_ULE:
    case CmpInstruction::ICMP_SGE:
    case CmpInstruction::ICMP_SLE:
      return makeIntConst(Cmp->getType(), 1);
    case CmpInstruction::ICMP_NE:
    case CmpInstruction::ICMP_UGT:
    case CmpInstruction::ICMP_ULT:
    case CmpInstruction::ICMP_SGT:
    case CmpInstruction::ICMP_SLT:
      return makeIntConst(Cmp->getType(), 0);
    default:
      break;
    }
  }

  llvm::APInt LV, RV;
  if (!LHS->getType()->isInteger() || !matchIntConst(LHS, LV) ||
      !matchIntConst(RHS, RV)) {
    return nullptr;
  }
  if (LV.getBitWidth() != RV.getBitWidth()) {
    return nullptr;
  }
  return makeIntConst(Cmp->getType(),
                      evalICmp(Cmp->getPredicate(), LV, RV) ? 1 : 0);
}

MInstruction *MIRPeephole::foldAlgebra(MInstruction *Inst) {
  if (Inst->getOpcode() == OP_not) {
    MInstruction *Op = Inst->getOperand<0>();
    if (Op->getOpcode() == OP_not) {
      return Op->getOperand<0>();
    }
    llvm::APInt CV;
    if (matchIntConst(Op, CV)) {
      return makeIntConst(Inst->getType(), (~CV).getZExtValue());
    }
    return nullptr;
  }

  if (Inst->getKind() != MInstruction::BINARY) {
    return nullptr;
  }
  if (!Inst->getType()->isInteger()) {
    return nullptr;
  }

  MInstruction *LHS = Inst->getOperand<0>();
  MInstruction *RHS = Inst->getOperand<1>();
  const Opcode Opc = Inst->getOpcode();
  MType *Ty = Inst->getType();

  llvm::APInt LV, RV;
  const bool LConst = matchIntConst(LHS, LV);
  const bool RConst = matchIntConst(RHS, RV);

  if (LConst && RConst && LV.getBitWidth() == RV.getBitWidth()) {
    const unsigned Width = LV.getBitWidth();
    const unsigned ShiftMask = Width - 1;
    switch (Opc) {
    case OP_add:
      return makeIntConst(Ty, (LV + RV).getZExtValue());
    case OP_sub:
      return makeIntConst(Ty, (LV - RV).getZExtValue());
    case OP_mul:
      return makeIntConst(Ty, (LV * RV).getZExtValue());
    case OP_and:
      return makeIntConst(Ty, (LV & RV).getZExtValue());
    case OP_or:
      return makeIntConst(Ty, (LV | RV).getZExtValue());
    case OP_xor:
      return makeIntConst(Ty, (LV ^ RV).getZExtValue());
    case OP_shl:
      return makeIntConst(Ty,
                          LV.shl(RV.getZExtValue() & ShiftMask).getZExtValue());
    case OP_ushr:
      return makeIntConst(
          Ty, LV.lshr(RV.getZExtValue() & ShiftMask).getZExtValue());
    case OP_sshr:
      return makeIntConst(
          Ty, LV.ashr(RV.getZExtValue() & ShiftMask).getZExtValue());
    default:
      break;
    }
  }

  auto same = [&](MInstruction *A, MInstruction *B) { return A == B; };

  // Folds that return a constant or one operand discard the other
  // subtree. Refuse that unless the discarded tree is pure (no load /
  // call / wasm-check). Frontend nesting currently avoids this, but the
  // pass must not rely on that discipline.
  switch (Opc) {
  case OP_add:
    if (isIntZero(RHS) && isPureExpr(RHS)) {
      return LHS;
    }
    if (isIntZero(LHS) && isPureExpr(LHS)) {
      return RHS;
    }
    break;
  case OP_sub:
    if (isIntZero(RHS) && isPureExpr(RHS)) {
      return LHS;
    }
    if (same(LHS, RHS) && isPureExpr(LHS)) {
      return makeIntConst(Ty, 0);
    }
    break;
  case OP_mul:
    if (isIntZero(LHS) && isPureExpr(RHS)) {
      return makeIntConst(Ty, 0);
    }
    if (isIntZero(RHS) && isPureExpr(LHS)) {
      return makeIntConst(Ty, 0);
    }
    if (isIntOne(RHS) && isPureExpr(RHS)) {
      return LHS;
    }
    if (isIntOne(LHS) && isPureExpr(LHS)) {
      return RHS;
    }
    break;
  case OP_and:
    if (isIntZero(LHS) && isPureExpr(RHS)) {
      return makeIntConst(Ty, 0);
    }
    if (isIntZero(RHS) && isPureExpr(LHS)) {
      return makeIntConst(Ty, 0);
    }
    if (isIntAllOnes(RHS) && isPureExpr(RHS)) {
      return LHS;
    }
    if (isIntAllOnes(LHS) && isPureExpr(LHS)) {
      return RHS;
    }
    if (same(LHS, RHS)) {
      return LHS;
    }
    // x & (x | y) -> x ; (x | y) & x -> x
    if (RHS->getOpcode() == OP_or &&
        (RHS->getOperand<0>() == LHS || RHS->getOperand<1>() == LHS) &&
        isPureExpr(RHS)) {
      return LHS;
    }
    if (LHS->getOpcode() == OP_or &&
        (LHS->getOperand<0>() == RHS || LHS->getOperand<1>() == RHS) &&
        isPureExpr(LHS)) {
      return RHS;
    }
    // (x & y) & y -> x & y
    if (LHS->getOpcode() == OP_and &&
        (LHS->getOperand<0>() == RHS || LHS->getOperand<1>() == RHS) &&
        isPureExpr(RHS)) {
      return LHS;
    }
    break;
  case OP_or:
    if (isIntZero(RHS) && isPureExpr(RHS)) {
      return LHS;
    }
    if (isIntZero(LHS) && isPureExpr(LHS)) {
      return RHS;
    }
    if (isIntAllOnes(LHS) && isPureExpr(RHS)) {
      return makeIntConst(
          Ty, llvm::APInt::getAllOnes(Ty->getBitWidth()).getZExtValue());
    }
    if (isIntAllOnes(RHS) && isPureExpr(LHS)) {
      return makeIntConst(
          Ty, llvm::APInt::getAllOnes(Ty->getBitWidth()).getZExtValue());
    }
    if (same(LHS, RHS)) {
      return LHS;
    }
    // x | (x & y) -> x
    if (RHS->getOpcode() == OP_and &&
        (RHS->getOperand<0>() == LHS || RHS->getOperand<1>() == LHS) &&
        isPureExpr(RHS)) {
      return LHS;
    }
    if (LHS->getOpcode() == OP_and &&
        (LHS->getOperand<0>() == RHS || LHS->getOperand<1>() == RHS) &&
        isPureExpr(LHS)) {
      return RHS;
    }
    if (LHS->getOpcode() == OP_or &&
        (LHS->getOperand<0>() == RHS || LHS->getOperand<1>() == RHS) &&
        isPureExpr(RHS)) {
      return LHS;
    }
    break;
  case OP_xor:
    if (isIntZero(RHS) && isPureExpr(RHS)) {
      return LHS;
    }
    if (isIntZero(LHS) && isPureExpr(LHS)) {
      return RHS;
    }
    if (same(LHS, RHS) && isPureExpr(LHS)) {
      return makeIntConst(Ty, 0);
    }
    break;
  case OP_shl:
  case OP_ushr:
  case OP_sshr:
  case OP_rotl:
  case OP_rotr:
    if (isIntZero(RHS)) {
      return LHS;
    }
    break;
  default:
    break;
  }
  return nullptr;
}

void MIRPeephole::removeEdgeAndPhiIncomings(MBasicBlock &From,
                                            MBasicBlock *To) {
  if (To == nullptr) {
    return;
  }
  bool IsSucc = false;
  for (MBasicBlock *Succ : From.successors()) {
    if (Succ == To) {
      IsSucc = true;
      break;
    }
  }
  if (!IsSucc) {
    return;
  }
  From.removeSuccessor(To);
  // Drop may stay reachable via other preds (shared EVM JUMPDEST).
  // Strip this edge's phi incomings so pred-count == incoming-count.
  for (MInstruction *Inst : To->phis()) {
    auto *Phi = llvm::dyn_cast<PhiInstruction>(Inst);
    if (!Phi) {
      continue;
    }
    for (int J = static_cast<int>(Phi->getNumIncoming()) - 1; J >= 0; --J) {
      if (Phi->getIncomingBlock(static_cast<size_t>(J)) == &From) {
        Phi->removeIncoming(static_cast<size_t>(J));
      }
    }
  }
}

bool MIRPeephole::foldConstBrIf(MBasicBlock &BB, BrIfInstruction &BrIf) {
  llvm::APInt CondVal;
  if (!matchIntConst(BrIf.getOperand<0>(), CondVal)) {
    return false;
  }

  MBasicBlock *TrueBB = BrIf.getTrueBlock();
  MBasicBlock *FalseBB = BrIf.hasFalseBlock() ? BrIf.getFalseBlock() : nullptr;
  const bool Taken = !CondVal.isZero();
  MBasicBlock *Keep = Taken ? TrueBB : FalseBB;
  MBasicBlock *Drop = Taken ? FalseBB : TrueBB;

  if (Keep == nullptr) {
    // br_if 0, T (no false) → fall through to the next statement.
    if (Drop) {
      removeEdgeAndPhiIncomings(BB, Drop);
    }
    BB.eraseStatement(&BrIf);
    return true;
  }

  if (Drop && Drop != Keep) {
    removeEdgeAndPhiIncomings(BB, Drop);
  }

  BrInstruction *NewBr =
      F->createInstruction<BrInstruction>(false, BB, F->getContext(), Keep);
  BB.replaceStatement(&BrIf, NewBr);
  return true;
}

MInstruction *MIRPeephole::makeIntConst(MType *Ty, uint64_t Val) {
  ZEN_ASSERT(F && CurBB && Ty);
  MConstantInt *C = MConstantInt::get(F->getContext(), *Ty, Val);
  return F->createInstruction<ConstantInstruction>(false, *CurBB, Ty, *C);
}

MInstruction *MIRPeephole::makeICmp(CmpInstruction::Predicate Pred, MType *Ty,
                                    MInstruction *LHS, MInstruction *RHS) {
  return F->createInstruction<CmpInstruction>(false, *CurBB, Pred, Ty, LHS,
                                              RHS);
}

MInstruction *MIRPeephole::makeAnd(MType *Ty, MInstruction *LHS,
                                   MInstruction *RHS) {
  return F->createInstruction<BinaryInstruction>(false, *CurBB, OP_and, Ty, LHS,
                                                 RHS);
}

bool MIRPeephole::matchIntConst(const MInstruction *Inst, llvm::APInt &Val) {
  const auto *C = llvm::dyn_cast<ConstantInstruction>(Inst);
  if (!C) {
    return false;
  }
  const auto *CI = llvm::dyn_cast<MConstantInt>(&C->getConstant());
  if (!CI) {
    return false;
  }
  Val = CI->getValue();
  return true;
}

bool MIRPeephole::isIntZero(const MInstruction *Inst) {
  llvm::APInt V;
  return matchIntConst(Inst, V) && V.isZero();
}

bool MIRPeephole::isIntOne(const MInstruction *Inst) {
  llvm::APInt V;
  return matchIntConst(Inst, V) && V.isOne();
}

bool MIRPeephole::isIntAllOnes(const MInstruction *Inst) {
  llvm::APInt V;
  return matchIntConst(Inst, V) && V.isAllOnes();
}

bool MIRPeephole::isPureExpr(const MInstruction *Inst) {
  if (Inst == nullptr) {
    return true;
  }
  switch (Inst->getKind()) {
  case MInstruction::LOAD:
  case MInstruction::STORE:
  case MInstruction::CALL:
  case MInstruction::WASM_CHECK:
  case MInstruction::PHI:
    return false;
  default:
    break;
  }
  for (OperandNum I = 0, E = Inst->getNumOperands(); I != E; ++I) {
    if (!isPureExpr(Inst->getOperand(I))) {
      return false;
    }
  }
  return true;
}

bool MIRPeephole::evalICmp(CmpInstruction::Predicate Pred,
                           const llvm::APInt &LHS, const llvm::APInt &RHS) {
  switch (Pred) {
  case CmpInstruction::ICMP_EQ:
    return LHS == RHS;
  case CmpInstruction::ICMP_NE:
    return LHS != RHS;
  case CmpInstruction::ICMP_UGT:
    return LHS.ugt(RHS);
  case CmpInstruction::ICMP_UGE:
    return LHS.uge(RHS);
  case CmpInstruction::ICMP_ULT:
    return LHS.ult(RHS);
  case CmpInstruction::ICMP_ULE:
    return LHS.ule(RHS);
  case CmpInstruction::ICMP_SGT:
    return LHS.sgt(RHS);
  case CmpInstruction::ICMP_SGE:
    return LHS.sge(RHS);
  case CmpInstruction::ICMP_SLT:
    return LHS.slt(RHS);
  case CmpInstruction::ICMP_SLE:
    return LHS.sle(RHS);
  default:
    ZEN_ASSERT(false && "evalICmp: non-integer predicate");
    return false;
  }
}
