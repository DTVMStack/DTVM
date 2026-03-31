// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/target/x86/x86_cg_peephole.h"
#include "compiler/llvm-prebuild/Target/X86/X86Subtarget.h"

using namespace llvm;

namespace COMPILER {

#include "target/x86/x86_cg_peephole_generated.inc"

// Fold MOVZX32rr8 + SUBREG_TO_REG(0, GR32, sub_32bit) -> MOVZX64rr8.
// On x86-64, writing a 32-bit register implicitly zeroes the upper 32 bits,
// so SUBREG_TO_REG is a pure register-class annotation and can be eliminated.
static bool tryFoldMovzxSubregToReg(CgBasicBlock &MBB,
                                    CgBasicBlock::iterator &MII) {
  CgInstruction &Movzx = *MII;
  if (Movzx.getOpcode() != X86::MOVZX32rr8)
    return false;

  auto NextMII = MII;
  ++NextMII;
  if (NextMII == MBB.end())
    return false;

  CgInstruction &Subreg = *NextMII;
  if (!Subreg.isSubregToReg())
    return false;

  // SUBREG_TO_REG layout: op0=def(GR64), op1=imm(0), op2=src(GR32), op3=idx
  if (Subreg.getNumOperands() < 4)
    return false;
  if (!Subreg.getOperand(1).isImm() || Subreg.getOperand(1).getImm() != 0)
    return false;
  if (!Subreg.getOperand(2).isReg())
    return false;
  if (!Subreg.getOperand(3).isImm() ||
      Subreg.getOperand(3).getImm() != X86::sub_32bit)
    return false;

  // The src of SUBREG_TO_REG must be the def of MOVZX32rr8.
  CgRegister Movzx32Def = Movzx.getOperand(0).getReg();
  if (Subreg.getOperand(2).getReg() != Movzx32Def)
    return false;

  auto AfterSubreg = NextMII;
  ++AfterSubreg;

  // Rewrite: change MOVZX32rr8's def to the GR64 def from SUBREG_TO_REG and
  // change the opcode to MOVZX64rr8, then erase SUBREG_TO_REG.
  CgRegister SubregDef = Subreg.getOperand(0).getReg();
  Movzx.getOperand(0).setReg(SubregDef);

  const auto &TII = MBB.getParent()->getTargetInstrInfo();
  Movzx.setDesc(TII.get(X86::MOVZX64rr8));

  Subreg.eraseFromParent();
  MII = AfterSubreg;
  return true;
}

void X86CgPeephole::peepholeOptimizeBB(CgBasicBlock &MBB) {
  (void)tryGeneratedBlockEndRules(MBB);
}

bool X86CgPeephole::peepholeOptimize(CgBasicBlock &MBB,
                                     CgBasicBlock::iterator &MII) {
  if (tryFoldMovzxSubregToReg(MBB, MII))
    return true;
  return tryGeneratedInstructionRules(MBB, MII) ==
         GeneratedInstructionRuleResult::Advanced;
}

} // namespace COMPILER
