// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "compiler/cgir/pass/phi_elimination.h"
#include "compiler/cgir/cg_basic_block.h"
#include "compiler/cgir/cg_function.h"
#include "compiler/cgir/pass/cg_register_info.h"
#include "compiler/llvm-prebuild/Target/X86/X86InstrInfo.h"
#include <algorithm>
#include <unordered_map>
#include <vector>

using namespace COMPILER;

namespace {

struct CopyEdge {
  CgRegister Dst;
  CgRegister Src;
};

class PhiEliminationImpl {
public:
  void runOnCgFunction(CgFunction &MF) {
    this->MF = &MF;
    MRI = &MF.getRegInfo();
    TII = &MF.getTargetInstrInfo();

    std::vector<CgBasicBlock *> Blocks;
    Blocks.reserve(MF.size());
    for (CgBasicBlock *BB : MF) {
      Blocks.push_back(BB);
    }

    for (CgBasicBlock *BB : Blocks) {
      eliminateBlockPhis(*BB);
    }
  }

private:
  void eliminateBlockPhis(CgBasicBlock &BB) {
    std::vector<CgInstruction *> Phis;
    for (CgInstruction &MI : BB) {
      if (!MI.isPHI()) {
        break;
      }
      Phis.push_back(&MI);
    }
    if (Phis.empty()) {
      return;
    }

    std::unordered_map<CgBasicBlock *, std::vector<CopyEdge>> EdgeCopies;
    EdgeCopies.reserve(BB.pred_size());

    for (CgInstruction *Phi : Phis) {
      ZEN_ASSERT(Phi->getNumOperands() >= 3 &&
                 (Phi->getNumOperands() % 2) == 1 && "invalid lowered PHI");

      const CgRegister DstReg = Phi->getOperand(0).getReg();
      for (unsigned OpIdx = 1; OpIdx < Phi->getNumOperands(); OpIdx += 2) {
        CgOperand &SrcOp = Phi->getOperand(OpIdx);
        CgOperand &PredOp = Phi->getOperand(OpIdx + 1);
        ZEN_ASSERT(SrcOp.isReg() && PredOp.isMBB() &&
                   "invalid lowered PHI incoming");
        EdgeCopies[PredOp.getMBB()].push_back(CopyEdge{DstReg, SrcOp.getReg()});
      }
    }

    for (auto &[Pred, Copies] : EdgeCopies) {
      eraseIdentityCopies(Copies);
      if (Copies.empty()) {
        continue;
      }

      if (Pred->succ_size() == 1) {
        emitParallelCopies(*Pred, Pred->getFirstTerminator(), Copies);
        continue;
      }

      CgBasicBlock *SplitBB = createSplitEdgeBlock(*Pred, BB);
      emitParallelCopies(*SplitBB, SplitBB->end(), Copies);
      addUnconditionalBranch(*SplitBB, BB);
    }

    for (CgInstruction *Phi : Phis) {
      Phi->eraseFromParent();
    }
  }

  static void eraseIdentityCopies(std::vector<CopyEdge> &Copies) {
    Copies.erase(std::remove_if(
                     Copies.begin(), Copies.end(),
                     [](const CopyEdge &Copy) { return Copy.Dst == Copy.Src; }),
                 Copies.end());
  }

  bool rewriteExplicitBranchTarget(CgBasicBlock &Pred, CgBasicBlock &OldSucc,
                                   CgBasicBlock &NewSucc) {
    bool Rewritten = false;
    for (CgInstruction &MI : Pred.terminators()) {
      if (!MI.isBranch()) {
        continue;
      }
      for (CgOperand &MO : MI.operands()) {
        if (!MO.isMBB() || MO.getMBB() != &OldSucc) {
          continue;
        }
        MO.setMBB(&NewSucc);
        Rewritten = true;
      }
    }
    return Rewritten;
  }

  CgBasicBlock *createSplitEdgeBlock(CgBasicBlock &Pred, CgBasicBlock &Succ) {
    CgBasicBlock *SplitBB = MF->createCgBasicBlock();

    const bool Rewritten = rewriteExplicitBranchTarget(Pred, Succ, *SplitBB);
    if (Rewritten) {
      MF->appendCgBasicBlock(SplitBB);
    } else {
      ZEN_ASSERT(Pred.isLayoutSuccessor(&Succ) &&
                 "critical edge without explicit branch must be fallthrough");
      MF->insertCgBasicBlockAfter(&Pred, SplitBB);
    }

    Pred.replaceSuccessor(&Succ, SplitBB);
    SplitBB->addSuccessorWithoutProb(&Succ);
    return SplitBB;
  }

  const llvm::TargetRegisterClass *getCopyRegClass(const CopyEdge &Copy) const {
    if (Copy.Dst.isVirtual()) {
      return MRI->getRegClass(Copy.Dst);
    }
    if (Copy.Src.isVirtual()) {
      return MRI->getRegClass(Copy.Src);
    }
    ZEN_ASSERT(false && "expected at least one virtual register in PHI copy");
    return nullptr;
  }

  void addCopy(CgBasicBlock &BB, CgBasicBlock::iterator InsertPt,
               CgRegister Dst, CgRegister Src) {
    std::vector<CgOperand> Operands = {
        CgOperand::createRegOperand(Dst, true),
        CgOperand::createRegOperand(Src, false),
    };
    llvm::MutableArrayRef<CgOperand> OperandRef(Operands);
    MF->createCgInstruction(BB, InsertPt, TII->get(llvm::TargetOpcode::COPY),
                            OperandRef);
  }

  void emitParallelCopies(CgBasicBlock &BB, CgBasicBlock::iterator InsertPt,
                          std::vector<CopyEdge> Copies) {
    while (!Copies.empty()) {
      bool Progress = false;
      for (size_t Index = 0; Index < Copies.size(); ++Index) {
        const CopyEdge &Copy = Copies[Index];
        const bool DstStillUsedAsSource =
            std::any_of(Copies.begin(), Copies.end(),
                        [&](const CopyEdge &It) { return It.Src == Copy.Dst; });
        if (DstStillUsedAsSource) {
          continue;
        }
        addCopy(BB, InsertPt, Copy.Dst, Copy.Src);
        Copies.erase(Copies.begin() + Index);
        Progress = true;
        break;
      }
      if (Progress) {
        continue;
      }

      CopyEdge &CycleCopy = Copies.front();
      const llvm::TargetRegisterClass *RegClass = getCopyRegClass(CycleCopy);
      CgRegister TempReg = MRI->createVirtualRegister(RegClass);
      addCopy(BB, InsertPt, TempReg, CycleCopy.Dst);
      for (CopyEdge &Copy : Copies) {
        if (Copy.Src == CycleCopy.Dst) {
          Copy.Src = TempReg;
        }
      }
    }
  }

  void addUnconditionalBranch(CgBasicBlock &BB, CgBasicBlock &TargetBB) {
    std::vector<CgOperand> Operands = {
        CgOperand::createMBB(&TargetBB),
    };
    llvm::MutableArrayRef<CgOperand> OperandRef(Operands);
    MF->createCgInstruction(BB, TII->get(X86::JMP_1), OperandRef);
  }

  CgFunction *MF = nullptr;
  CgRegisterInfo *MRI = nullptr;
  const llvm::TargetInstrInfo *TII = nullptr;
};

} // namespace

void CgPhiElimination::runOnCgFunction(CgFunction &MF) {
  PhiEliminationImpl Impl;
  Impl.runOnCgFunction(MF);
}
