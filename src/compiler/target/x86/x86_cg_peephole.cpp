// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/target/x86/x86_cg_peephole.h"
#include "compiler/llvm-prebuild/Target/X86/X86Subtarget.h"

using namespace llvm;

namespace COMPILER {

#include "target/x86/x86_cg_peephole_generated.inc"

void X86CgPeephole::peepholeOptimizeBB(CgBasicBlock &MBB) {
  (void)tryGeneratedBlockEndRules(MBB);
}

bool X86CgPeephole::peepholeOptimize(CgBasicBlock &MBB,
                                     CgBasicBlock::iterator &MII) {
  return tryGeneratedInstructionRules(MBB, MII) ==
         GeneratedInstructionRuleResult::Advanced;
}

} // namespace COMPILER
