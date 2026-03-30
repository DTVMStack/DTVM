// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "compiler/cgir/cg_basic_block.h"
#include "compiler/cgir/pass/peephole.h"

namespace COMPILER {
class X86CgPeephole : public CgPeephole<X86CgPeephole> {
public:
  using CgPeephole::CgPeephole;
  void peepholeOptimizeBB(CgBasicBlock &MBB);
  // Returns true when the matcher has already advanced MII.
  bool peepholeOptimize(CgBasicBlock &MBB, CgBasicBlock::iterator &MII);
};

} // namespace COMPILER
