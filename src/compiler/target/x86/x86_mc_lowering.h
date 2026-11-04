/**
 * Copyright (C) 2021-2023 the DTVM authors
 */
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "compiler/cgir/mc_lowering.h"
#include "compiler/target/x86/x86_mc_inst_lower.h"

namespace COMPILER {

class X86MCLowering final : public MCLowering<X86MCLowering> {
public:
  using MCLowering::MCLowering;
  void emitInstruction(CgInstruction *MI) {
    llvm::MCInst TmpInst;
    X86MCInstLower MCInstLowering(*MF);
    MCInstLowering.lower(MI, TmpInst);
    // Legacy scalar GPR-to-XMM conversions preserve upper destination lanes.
    // They define a fresh scalar, so those lanes are dead, but CPUs may still
    // depend on the previous destination (e.g. the last iteration's DIVSD).
    // Break that false dependency after RA, using the allocated destination.
    // XORPS preserves EFLAGS and cannot alias the integer source register.
    switch (TmpInst.getOpcode()) {
    case llvm::X86::CVTSI2SSrr:
    case llvm::X86::CVTSI2SDrr:
    case llvm::X86::CVTSI642SSrr:
    case llvm::X86::CVTSI642SDrr: {
      llvm::MCInst Zero;
      Zero.setOpcode(llvm::X86::XORPSrr);
      for (unsigned I = 0; I < 3; ++I) {
        Zero.addOperand(TmpInst.getOperand(0));
      }
      Streamer->emitInstruction(Zero, *STI);
      break;
    }
    default:
      break;
    }
    Streamer->emitInstruction(TmpInst, *STI);
  }
};

} // namespace COMPILER