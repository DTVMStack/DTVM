// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "compiler/mir/pass/visitor.h"

namespace COMPILER {

class MVerifier final : public MVisitor {

#define CHECK(C, MSG)                                                          \
  if (!(C)) {                                                                  \
    CheckFailed(MSG);                                                          \
    return;                                                                    \
  }

public:
  MVerifier(MModule &M, MFunction &F, llvm::raw_ostream &OS)
      : MVisitor(M, F), OS(OS) {}

  bool verify() {
    Broken = false;
    visit();
    return !Broken;
  }

  void visitBasicBlock(MBasicBlock &BB) override {
    if (BB.empty()) {
      return;
    }
    const MInstruction *LastInst = *std::prev(BB.end());
    CHECK(LastInst->isTerminator(), "The last instruction in BB @" +
                                        std::to_string(BB.getIdx()) +
                                        " must be terminator");
    if (LastInst->getKind() == MInstruction::BR_IF) {
      const BrIfInstruction *BrIf = llvm::cast<BrIfInstruction>(LastInst);
      CHECK(BrIf->hasFalseBlock(), "The br_if instruction at the end of BB @" +
                                       std::to_string(BB.getIdx()) +
                                       "must have false target");
    }
    MVisitor::visitBasicBlock(BB);
  }

  void visitUnaryInstruction(UnaryInstruction &I) override;
  void visitBinaryInstruction(BinaryInstruction &I) override;
  void visitAdcInstruction(AdcInstruction &I) override;
  void visitCmpInstruction(CmpInstruction &I) override;
  void visitSelectInstruction(SelectInstruction &I) override;
  void visitDassignInstruction(DassignInstruction &I) override;
  void visitLoadInstruction(LoadInstruction &I) override;
  void visitStoreInstruction(StoreInstruction &I) override;
  void visitConstantInstruction(ConstantInstruction &I) override;
  void visitBrInstruction(BrInstruction &I) override;
  void visitBrIfInstruction(BrIfInstruction &I) override;
  void visitSwitchInstruction(SwitchInstruction &I) override;
  void visitCallInstructionBase(CallInstructionBase &I) override;
  void visitCallInstruction(CallInstruction &I) override;
  void visitReturnInstruction(ReturnInstruction &I) override;
  void visitConversionInstruction(ConversionInstruction &I) override;
  void visitWasmCheckMemoryAccessInstruction(
      WasmCheckMemoryAccessInstruction &I) override;
  void visitWasmCheckStackBoundaryInstruction(
      WasmCheckStackBoundaryInstruction &I) override;
  void visitWasmVisitStackGuardInstruction(
      WasmVisitStackGuardInstruction &I) override;
  void visitWasmOverflowI128BinaryInstruction(
      WasmOverflowI128BinaryInstruction &I) override;

private:
  void visitIntExtInstruction(MType *OperandType, MType *ResultType);
  void visitTruncInstruction(MType *OperandType, MType *ResultType);
  void visitBitcastInstruction(MType *OperandType, MType *ResultType);
  void CheckFailed(const llvm::Twine &Message) {
    OS << "[Verifying Error:" << FailedCount++ << "] " << Message << '\n';
    Broken = true;
  }

  bool Broken = false;
  llvm::raw_ostream &OS;
  uint32_t FailedCount = 0;
};

} // namespace COMPILER
