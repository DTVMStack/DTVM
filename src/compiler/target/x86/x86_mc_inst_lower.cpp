/**
 * Copyright (C) 2021-2023 the DTVM authors
 */
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "compiler/target/x86/x86_mc_inst_lower.h"
#include "compiler/cgir/cg_function.h"
#include "compiler/target/x86/x86_mc_lowering.h"

using namespace COMPILER;
using namespace llvm;

X86MCInstLower::X86MCInstLower(CgFunction &MF)
    : Ctx(MF.getMCContext()), MF(MF) {}

llvm::MCOperand X86MCInstLower::lowerSymbolOperand(const CgOperand &MO,
                                                   llvm::MCSymbol *Sym) const {
  const MCExpr *Expr =
      MCSymbolRefExpr::create(Sym, MCSymbolRefExpr::VK_None, Ctx);
  return MCOperand::createExpr(Expr);
}

llvm::MCSymbol *
X86MCInstLower::getSymbolFromOperand(const CgOperand &MO) const {
  ZEN_ASSERT(MO.isFunc() || MO.isMBB());

  llvm::MCSymbol *Sym = nullptr;

  if (MO.isFunc()) {
    Sym = MF.getContext().getOrCreateFuncMCSymbol(MO.getFunc());
  } else if (MO.isMBB()) {
    Sym = MO.getMBB()->getSymbol();
  } else {
    ZEN_ASSERT_TODO();
  }
  return Sym;
}

llvm::Optional<llvm::MCOperand>
X86MCInstLower::lowerMachineOperand(const CgOperand &MO) const {
  switch (MO.getType()) {
  case CgOperand::REGISTER:
    if (MO.isImplicit())
      return llvm::None;
    return llvm::MCOperand::createReg(MO.getReg());
  case CgOperand::IMMEDIATE:
    return llvm::MCOperand::createImm(MO.getImm());
  case CgOperand::FUNCTION:
  case CgOperand::BASIC_BLOCK:
    return lowerSymbolOperand(MO, getSymbolFromOperand(MO));
  case CgOperand::JUMP_TABLE_INDEX:
    return lowerSymbolOperand(MO, MF.getJTISymbol(MO.getIndex()));
  case CgOperand::REGISTER_MASK:
    return None;
  default:
    ZEN_ASSERT_TODO();
  }
}

/// Simplify FOO $imm, %{al,ax,eax,rax} to FOO $imm, for instruction with
/// a short fixed-register form.
static void SimplifyShortImmForm(MCInst &Inst, unsigned Opcode) {
  unsigned ImmOp = Inst.getNumOperands() - 1;
  ZEN_ASSERT(
      Inst.getOperand(0).isReg() &&
      (Inst.getOperand(ImmOp).isImm() || Inst.getOperand(ImmOp).isExpr()) &&
      ((Inst.getNumOperands() == 3 && Inst.getOperand(1).isReg() &&
        Inst.getOperand(0).getReg() == Inst.getOperand(1).getReg()) ||
       Inst.getNumOperands() == 2) &&
      "Unexpected instruction!");

  // Check whether the destination register can be fixed.
  unsigned Reg = Inst.getOperand(0).getReg();
  if (Reg != X86::AL && Reg != X86::AX && Reg != X86::EAX && Reg != X86::RAX)
    return;

  // If so, rewrite the instruction.
  MCOperand Saved = Inst.getOperand(ImmOp);
  Inst = MCInst();
  Inst.setOpcode(Opcode);
  Inst.addOperand(Saved);
}

/// If a movsx instruction has a shorter encoding for the used register
/// simplify the instruction to use it instead.
static void SimplifyMOVSX(MCInst &Inst) {
  unsigned NewOpcode = 0;
  unsigned Op0 = Inst.getOperand(0).getReg(), Op1 = Inst.getOperand(1).getReg();
  switch (Inst.getOpcode()) {
  default:
    llvm_unreachable("Unexpected instruction!");
  case X86::MOVSX16rr8: // movsbw %al, %ax   --> cbtw
    if (Op0 == X86::AX && Op1 == X86::AL)
      NewOpcode = X86::CBW;
    break;
  case X86::MOVSX32rr16: // movswl %ax, %eax  --> cwtl
    if (Op0 == X86::EAX && Op1 == X86::AX)
      NewOpcode = X86::CWDE;
    break;
  case X86::MOVSX64rr32: // movslq %eax, %rax --> cltq
    if (Op0 == X86::RAX && Op1 == X86::EAX)
      NewOpcode = X86::CDQE;
    break;
  }

  if (NewOpcode != 0) {
    Inst = MCInst();
    Inst.setOpcode(NewOpcode);
  }
}

void X86MCInstLower::lower(CgInstruction *MI, llvm::MCInst &OutMI) {
  OutMI.setOpcode(MI->getOpcode());
  for (const CgOperand &MO : *MI) {
    if (auto MaybeMCOp = lowerMachineOperand(MO)) {
      OutMI.addOperand(*MaybeMCOp);
    }
  }

  // Handle a few special cases to eliminate operand modifiers.
  switch (OutMI.getOpcode()) {
  case X86::LEA64_32r:
  case X86::LEA64r:
  case X86::LEA16r:
  case X86::LEA32r:
    // LEA should have a segment register, but it must be empty.
    ZEN_ASSERT(OutMI.getNumOperands() == 1 + X86::AddrNumOperands &&
               "Unexpected # of LEA operands");
    ZEN_ASSERT(OutMI.getOperand(1 + X86::AddrSegmentReg).getReg() == 0 &&
               "LEA has segment specified!");
    break;

  // Commute operands to get a smaller encoding by using VEX.R instead of
  // VEX.B if one of the registers is extended, but other isn't.
  case X86::VMOVZPQILo2PQIrr:
  case X86::VMOVAPDrr:
  case X86::VMOVAPDYrr:
  case X86::VMOVAPSrr:
  case X86::VMOVAPSYrr:
  case X86::VMOVDQArr:
  case X86::VMOVDQAYrr:
  case X86::VMOVDQUrr:
  case X86::VMOVDQUYrr:
  case X86::VMOVUPDrr:
  case X86::VMOVUPDYrr:
  case X86::VMOVUPSrr:
  case X86::VMOVUPSYrr: {
    if (!X86II::isX86_64ExtendedReg(OutMI.getOperand(0).getReg()) &&
        X86II::isX86_64ExtendedReg(OutMI.getOperand(1).getReg())) {
      unsigned NewOpc;
      switch (OutMI.getOpcode()) {
      default:
        llvm_unreachable("Invalid opcode");
      case X86::VMOVZPQILo2PQIrr:
        NewOpc = X86::VMOVPQI2QIrr;
        break;
      case X86::VMOVAPDrr:
        NewOpc = X86::VMOVAPDrr_REV;
        break;
      case X86::VMOVAPDYrr:
        NewOpc = X86::VMOVAPDYrr_REV;
        break;
      case X86::VMOVAPSrr:
        NewOpc = X86::VMOVAPSrr_REV;
        break;
      case X86::VMOVAPSYrr:
        NewOpc = X86::VMOVAPSYrr_REV;
        break;
      case X86::VMOVDQArr:
        NewOpc = X86::VMOVDQArr_REV;
        break;
      case X86::VMOVDQAYrr:
        NewOpc = X86::VMOVDQAYrr_REV;
        break;
      case X86::VMOVDQUrr:
        NewOpc = X86::VMOVDQUrr_REV;
        break;
      case X86::VMOVDQUYrr:
        NewOpc = X86::VMOVDQUYrr_REV;
        break;
      case X86::VMOVUPDrr:
        NewOpc = X86::VMOVUPDrr_REV;
        break;
      case X86::VMOVUPDYrr:
        NewOpc = X86::VMOVUPDYrr_REV;
        break;
      case X86::VMOVUPSrr:
        NewOpc = X86::VMOVUPSrr_REV;
        break;
      case X86::VMOVUPSYrr:
        NewOpc = X86::VMOVUPSYrr_REV;
        break;
      }
      OutMI.setOpcode(NewOpc);
    }
    break;
  }
  case X86::VMOVSDrr:
  case X86::VMOVSSrr: {
    if (!X86II::isX86_64ExtendedReg(OutMI.getOperand(0).getReg()) &&
        X86II::isX86_64ExtendedReg(OutMI.getOperand(2).getReg())) {
      unsigned NewOpc;
      switch (OutMI.getOpcode()) {
      default:
        llvm_unreachable("Invalid opcode");
      case X86::VMOVSDrr:
        NewOpc = X86::VMOVSDrr_REV;
        break;
      case X86::VMOVSSrr:
        NewOpc = X86::VMOVSSrr_REV;
        break;
      }
      OutMI.setOpcode(NewOpc);
    }
    break;
  }

  // CALL64r, CALL64pcrel32 - These instructions used to have register
  // inputs modeled as normal uses instead of implicit uses. As such, they
  // we used to truncate off all but the first operand (the callee). This
  // issue seems to have been fixed at some point. This assert verifies
  // that.
  case X86::CALL64r:
  case X86::CALL64pcrel32:
    ZEN_ASSERT(OutMI.getNumOperands() == 1 && "Unexpected number of operands!");
    break;

  // TAILJMPr64 is a pseudo-instruction; lower it to a real JMP64r.
  case X86::TAILJMPr64:
    OutMI.setOpcode(X86::JMP64r);
    break;

  case X86::ADC8ri:
  case X86::ADC16ri:
  case X86::ADC32ri:
  case X86::ADC64ri32:
  case X86::ADD8ri:
  case X86::ADD16ri:
  case X86::ADD32ri:
  case X86::ADD64ri32:
  case X86::AND8ri:
  case X86::AND16ri:
  case X86::AND32ri:
  case X86::AND64ri32:
  case X86::CMP8ri:
  case X86::CMP16ri:
  case X86::CMP32ri:
  case X86::CMP64ri32:
  case X86::OR8ri:
  case X86::OR16ri:
  case X86::OR32ri:
  case X86::OR64ri32:
  case X86::SBB8ri:
  case X86::SBB16ri:
  case X86::SBB32ri:
  case X86::SBB64ri32:
  case X86::SUB8ri:
  case X86::SUB16ri:
  case X86::SUB32ri:
  case X86::SUB64ri32:
  case X86::TEST8ri:
  case X86::TEST16ri:
  case X86::TEST32ri:
  case X86::TEST64ri32:
  case X86::XOR8ri:
  case X86::XOR16ri:
  case X86::XOR32ri:
  case X86::XOR64ri32: {
    unsigned NewOpc;
    switch (OutMI.getOpcode()) {
    default:
      llvm_unreachable("Invalid opcode");
    case X86::ADC8ri:
      NewOpc = X86::ADC8i8;
      break;
    case X86::ADC16ri:
      NewOpc = X86::ADC16i16;
      break;
    case X86::ADC32ri:
      NewOpc = X86::ADC32i32;
      break;
    case X86::ADC64ri32:
      NewOpc = X86::ADC64i32;
      break;
    case X86::ADD8ri:
      NewOpc = X86::ADD8i8;
      break;
    case X86::ADD16ri:
      NewOpc = X86::ADD16i16;
      break;
    case X86::ADD32ri:
      NewOpc = X86::ADD32i32;
      break;
    case X86::ADD64ri32:
      NewOpc = X86::ADD64i32;
      break;
    case X86::AND8ri:
      NewOpc = X86::AND8i8;
      break;
    case X86::AND16ri:
      NewOpc = X86::AND16i16;
      break;
    case X86::AND32ri:
      NewOpc = X86::AND32i32;
      break;
    case X86::AND64ri32:
      NewOpc = X86::AND64i32;
      break;
    case X86::CMP8ri:
      NewOpc = X86::CMP8i8;
      break;
    case X86::CMP16ri:
      NewOpc = X86::CMP16i16;
      break;
    case X86::CMP32ri:
      NewOpc = X86::CMP32i32;
      break;
    case X86::CMP64ri32:
      NewOpc = X86::CMP64i32;
      break;
    case X86::OR8ri:
      NewOpc = X86::OR8i8;
      break;
    case X86::OR16ri:
      NewOpc = X86::OR16i16;
      break;
    case X86::OR32ri:
      NewOpc = X86::OR32i32;
      break;
    case X86::OR64ri32:
      NewOpc = X86::OR64i32;
      break;
    case X86::SBB8ri:
      NewOpc = X86::SBB8i8;
      break;
    case X86::SBB16ri:
      NewOpc = X86::SBB16i16;
      break;
    case X86::SBB32ri:
      NewOpc = X86::SBB32i32;
      break;
    case X86::SBB64ri32:
      NewOpc = X86::SBB64i32;
      break;
    case X86::SUB8ri:
      NewOpc = X86::SUB8i8;
      break;
    case X86::SUB16ri:
      NewOpc = X86::SUB16i16;
      break;
    case X86::SUB32ri:
      NewOpc = X86::SUB32i32;
      break;
    case X86::SUB64ri32:
      NewOpc = X86::SUB64i32;
      break;
    case X86::TEST8ri:
      NewOpc = X86::TEST8i8;
      break;
    case X86::TEST16ri:
      NewOpc = X86::TEST16i16;
      break;
    case X86::TEST32ri:
      NewOpc = X86::TEST32i32;
      break;
    case X86::TEST64ri32:
      NewOpc = X86::TEST64i32;
      break;
    case X86::XOR8ri:
      NewOpc = X86::XOR8i8;
      break;
    case X86::XOR16ri:
      NewOpc = X86::XOR16i16;
      break;
    case X86::XOR32ri:
      NewOpc = X86::XOR32i32;
      break;
    case X86::XOR64ri32:
      NewOpc = X86::XOR64i32;
      break;
    }
    SimplifyShortImmForm(OutMI, NewOpc);
    break;
  }

  // Try to shrink some forms of movsx.
  case X86::MOVSX16rr8:
  case X86::MOVSX32rr16:
  case X86::MOVSX64rr32:
    SimplifyMOVSX(OutMI);
    break;

  case X86::VCMPPDrri:
  case X86::VCMPPDYrri:
  case X86::VCMPPSrri:
  case X86::VCMPPSYrri:
  case X86::VCMPSDrr:
  case X86::VCMPSSrr: {
    // Swap the operands if it will enable a 2 byte VEX encoding.
    // FIXME: Change the immediate to improve opportunities?
    if (!X86II::isX86_64ExtendedReg(OutMI.getOperand(1).getReg()) &&
        X86II::isX86_64ExtendedReg(OutMI.getOperand(2).getReg())) {
      unsigned Imm = MI->getOperand(3).getImm() & 0x7;
      switch (Imm) {
      default:
        break;
      case 0x00: // EQUAL
      case 0x03: // UNORDERED
      case 0x04: // NOT EQUAL
      case 0x07: // ORDERED
        std::swap(OutMI.getOperand(1), OutMI.getOperand(2));
        break;
      }
    }
    break;
  }

  default: {
    // If the instruction is a commutable arithmetic instruction we
    // might be able to commute the operands to get a 2 byte VEX prefix.
    uint64_t TSFlags = MI->getDesc().TSFlags;
    if (MI->getDesc().isCommutable() &&
        (TSFlags & X86II::EncodingMask) == X86II::VEX &&
        (TSFlags & X86II::OpMapMask) == X86II::TB &&
        (TSFlags & X86II::FormMask) == X86II::MRMSrcReg &&
        !(TSFlags & X86II::VEX_W) && (TSFlags & X86II::VEX_4V) &&
        OutMI.getNumOperands() == 3) {
      if (!X86II::isX86_64ExtendedReg(OutMI.getOperand(1).getReg()) &&
          X86II::isX86_64ExtendedReg(OutMI.getOperand(2).getReg()))
        std::swap(OutMI.getOperand(1), OutMI.getOperand(2));
    }
    break;
  }
  }
}