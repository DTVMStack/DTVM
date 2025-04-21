// Copyright (C) 2021-2023 Ant Group Co., Ltd. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "compiler/cgir/cg_basic_block.h"
#include "compiler/cgir/pass/peephole.h"

namespace COMPILER {
class X86CgPeephole : public CgPeephole<X86CgPeephole> {
public:
  using CgPeephole::CgPeephole;
  void peepholeOptimizeBB(CgBasicBlock &MBB);
  // after this function, MII should be the processed instruction
  void peepholeOptimize(CgBasicBlock &MBB, CgBasicBlock::iterator &MII);

private:
  void optimizeCmp(CgBasicBlock &MBB, CgBasicBlock::iterator &MII);
  void optimizeBranchInBlockEnd(CgBasicBlock &MBB, CgInstruction &MI);
};

} // namespace COMPILER
