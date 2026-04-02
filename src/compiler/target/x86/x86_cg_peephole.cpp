// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/target/x86/x86_cg_peephole.h"
#include "compiler/cgir/pass/cg_register_info.h"
#include "compiler/llvm-prebuild/Target/X86/X86Subtarget.h"
#include "compiler/target/x86/x86_constants.h"

using namespace llvm;

namespace COMPILER {
void X86CgPeephole::peepholeOptimizeBB(CgBasicBlock &MBB) {
  if (MBB.empty()) {
    return;
  }

  CgInstruction &LastMI = MBB.back();
  if (LastMI.isUnconditionalBranch()) {
    optimizeBranchInBlockEnd(MBB, LastMI);
  }
}

void X86CgPeephole::peepholeOptimize(CgBasicBlock &MBB,
                                     CgBasicBlock::iterator &MII) {
  auto &Inst = *MII;
  if (Inst.isCompare()) {
    optimizeCmp(MBB, MII);
  }
}
void X86CgPeephole::optimizeCmp(CgBasicBlock &MBB,
                                CgBasicBlock::iterator &MII) {
  auto MIE = MBB.end();
  // cmp/test -> setcc cond -> [movzx] -> test -> jne
  // optimized to: cmp/test -> jcc cond
  auto LocalMII = MII;
  LocalMII++;
  if (LocalMII == MIE)
    return;
  auto &Inst1 = *LocalMII;
  if (Inst1.getOpcode() != X86::SETCCr)
    return;
  const auto &Op1 = Inst1.getOperand(0);
  if (!Op1.isReg())
    return;
  auto CC = Inst1.getOperand(1).getImm();
  unsigned TestReg = Op1.getReg();
  CgInstruction *MovzxInst = nullptr;

  LocalMII++;
  if (LocalMII == MIE)
    return;
  auto &Inst2 = *LocalMII;
  if (Inst2.getOpcode() == X86::MOVZX32rr8) {
    const auto &MovzxDst = Inst2.getOperand(0);
    const auto &MovzxSrc = Inst2.getOperand(1);
    if (!MovzxDst.isReg() || !MovzxSrc.isReg() ||
        MovzxSrc.getReg() != Op1.getReg())
      return;
    TestReg = MovzxDst.getReg();
    MovzxInst = &Inst2;
    LocalMII++;
    if (LocalMII == MIE)
      return;
  }

  auto &TestInst = *LocalMII;
  switch (TestInst.getOpcode()) {
  case X86::TEST8rr:
  case X86::TEST16rr:
  case X86::TEST32rr:
  case X86::TEST64rr:
    break;
  default:
    return;
  }
  const auto &TestOp0 = TestInst.getOperand(0);
  const auto &TestOp1 = TestInst.getOperand(1);
  if (!TestOp0.isReg() || !TestOp1.isReg() || TestOp0.getReg() != TestReg ||
      TestOp1.getReg() != TestReg)
    return;

  LocalMII++;
  if (LocalMII == MIE)
    return;
  auto &Inst3 = *LocalMII;
  if (Inst3.getOpcode() != X86::JCC_1)
    return;
  if (Inst3.getOperand(1).getImm() != X86::CondCode::COND_NE)
    return; // TODO, other optimization, use opposite condition code

  // Ensure the SETCC/MOVZX registers have no uses beyond this chain.
  // The lowering cache (_expr_reg_map) may share these virtual registers
  // with other consumers; erasing them would leave dangling references.
  const auto &RegInfo = MBB.getParent()->getRegInfo();
  if (!RegInfo.hasOneNonDBGUse(Op1.getReg()))
    return;
  if (MovzxInst != nullptr && !RegInfo.hasOneNonDBGUse(TestReg))
    return;

  Inst1.eraseFromParent();
  if (MovzxInst != nullptr) {
    MovzxInst->eraseFromParent();
  }
  TestInst.eraseFromParent();
  Inst3.getOperand(1).setImm(CC);
}
} // namespace COMPILER

void X86CgPeephole::optimizeBranchInBlockEnd(CgBasicBlock &MBB,
                                             CgInstruction &MI) {
  ZEN_ASSERT(MI.getNumOperands() > 0);
  CgOperand &MO = MI.getOperand(0);
  ZEN_ASSERT(MO.isMBB());
  CgBasicBlock *TargetMBB = MO.getMBB();
  if (TargetMBB->getNumber() == MBB.getNumber() + 1) {
    // remove the unconditional branch
    MI.eraseFromParent();
  }
}
