/*
 * Copyright (C) 2021-2023 the DTVM authors.
 */
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "compiler/cgir/cg_function.h"
#include "compiler/common/common_defs.h"

namespace COMPILER {

template <typename T> class CgPeephole : public NonCopyable {
public:
  CgPeephole(CgFunction &MF) : MF(MF) {
    for (auto *MBB : MF) {
      for (CgBasicBlock::iterator MII = MBB->begin(), MIE = MBB->end();
           MII != MIE;) {
        // When the matcher erases the current instruction, it must advance
        // MII itself and return true to avoid incrementing an invalid iterator.
        if (!SELF.peepholeOptimize(*MBB, MII)) {
          MII++;
        }
      }
      // Block-end rewrites (e.g. remove-fallthrough-jcc) erase terminators
      // that instruction-level rules (e.g. fold-setcc-test-jne-to-jcc) need
      // as part of a longer match window. Run instruction-level pass first.
      SELF.peepholeOptimizeBB(*MBB);
    }
  }

private:
  CgFunction &MF;
};
} // end namespace COMPILER
