// Copyright (C) 2021-2026 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "compiler/mir/function.h"
#include "compiler/mir/instructions.h"
#include "llvm/ADT/APInt.h"

namespace COMPILER {

/// Local algebraic / terminator peepholes on dMIR trees (Wasmtime-inspired).
/// Function-local, deterministic, no shared mutable state.
class MIRPeephole {
public:
  void runOnMFunction(MFunction &F);

private:
  MFunction *F = nullptr;
  MBasicBlock *CurBB = nullptr;

  void rewriteBlock(MBasicBlock &BB);
  MInstruction *rewriteExpr(MInstruction *Inst);
  MInstruction *foldExpr(MInstruction *Inst);

  MInstruction *foldBitCountEqZero(MInstruction *Inst);
  MInstruction *foldSelectICmp(MInstruction *Inst);
  MInstruction *foldAlgebra(MInstruction *Inst);
  MInstruction *foldConstCmp(MInstruction *Inst);
  MInstruction *foldSelectConstCond(MInstruction *Inst);
  bool foldConstBrIf(MBasicBlock &BB, BrIfInstruction &BrIf);

  MInstruction *makeIntConst(MType *Ty, uint64_t Val);
  MInstruction *makeICmp(CmpInstruction::Predicate Pred, MType *Ty,
                         MInstruction *LHS, MInstruction *RHS);
  MInstruction *makeAnd(MType *Ty, MInstruction *LHS, MInstruction *RHS);

  static bool matchIntConst(const MInstruction *Inst, llvm::APInt &Val);
  static bool isIntZero(const MInstruction *Inst);
  static bool isIntOne(const MInstruction *Inst);
  static bool isIntAllOnes(const MInstruction *Inst);
  static bool evalICmp(CmpInstruction::Predicate Pred, const llvm::APInt &LHS,
                       const llvm::APInt &RHS);
  // Loads / calls / wasm-checks are expressions; discarding them can
  // drop gas, bounds, or instance accesses. Only discard proven-pure trees.
  static bool isPureExpr(const MInstruction *Inst);
  static void removeEdgeAndPhiIncomings(MBasicBlock &From, MBasicBlock *To);
};

} // namespace COMPILER
