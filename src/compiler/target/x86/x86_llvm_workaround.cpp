// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "compiler/target/x86/x86_llvm_workaround.h"
#include "compiler/cgir/cg_function.h"
#include "compiler/cgir/pass/cg_frame_info.h"
#include "compiler/cgir/pass/cg_shape.h"
#include "compiler/context.h"
#include "compiler/llvm-prebuild/Target/X86/X86Subtarget.h"
#include "compiler/llvm-prebuild/Target/X86/X86TargetMachine.h"
#include "llvm/ADT/SmallString.h"
#include <array>

using namespace COMPILER;

//===----------------------------------------------------------------------===//
//
// TargetInstrInfo
//
//===----------------------------------------------------------------------===//

static bool isFrameLoadOpcode(int Opcode, unsigned &MemBytes) {
  switch (Opcode) {
  default:
    return false;
  case X86::MOV8rm:
  case X86::KMOVBkm:
    MemBytes = 1;
    return true;
  case X86::MOV16rm:
  case X86::KMOVWkm:
  case X86::VMOVSHZrm:
  case X86::VMOVSHZrm_alt:
    MemBytes = 2;
    return true;
  case X86::MOV32rm:
  case X86::MOVSSrm:
  case X86::MOVSSrm_alt:
  case X86::VMOVSSrm:
  case X86::VMOVSSrm_alt:
  case X86::VMOVSSZrm:
  case X86::VMOVSSZrm_alt:
  case X86::KMOVDkm:
    MemBytes = 4;
    return true;
  case X86::MOV64rm:
  case X86::LD_Fp64m:
  case X86::MOVSDrm:
  case X86::MOVSDrm_alt:
  case X86::VMOVSDrm:
  case X86::VMOVSDrm_alt:
  case X86::VMOVSDZrm:
  case X86::VMOVSDZrm_alt:
  case X86::MMX_MOVD64rm:
  case X86::MMX_MOVQ64rm:
  case X86::KMOVQkm:
    MemBytes = 8;
    return true;
  case X86::MOVAPSrm:
  case X86::MOVUPSrm:
  case X86::MOVAPDrm:
  case X86::MOVUPDrm:
  case X86::MOVDQArm:
  case X86::MOVDQUrm:
  case X86::VMOVAPSrm:
  case X86::VMOVUPSrm:
  case X86::VMOVAPDrm:
  case X86::VMOVUPDrm:
  case X86::VMOVDQArm:
  case X86::VMOVDQUrm:
  case X86::VMOVAPSZ128rm:
  case X86::VMOVUPSZ128rm:
  case X86::VMOVAPSZ128rm_NOVLX:
  case X86::VMOVUPSZ128rm_NOVLX:
  case X86::VMOVAPDZ128rm:
  case X86::VMOVUPDZ128rm:
  case X86::VMOVDQU8Z128rm:
  case X86::VMOVDQU16Z128rm:
  case X86::VMOVDQA32Z128rm:
  case X86::VMOVDQU32Z128rm:
  case X86::VMOVDQA64Z128rm:
  case X86::VMOVDQU64Z128rm:
    MemBytes = 16;
    return true;
  case X86::VMOVAPSYrm:
  case X86::VMOVUPSYrm:
  case X86::VMOVAPDYrm:
  case X86::VMOVUPDYrm:
  case X86::VMOVDQAYrm:
  case X86::VMOVDQUYrm:
  case X86::VMOVAPSZ256rm:
  case X86::VMOVUPSZ256rm:
  case X86::VMOVAPSZ256rm_NOVLX:
  case X86::VMOVUPSZ256rm_NOVLX:
  case X86::VMOVAPDZ256rm:
  case X86::VMOVUPDZ256rm:
  case X86::VMOVDQU8Z256rm:
  case X86::VMOVDQU16Z256rm:
  case X86::VMOVDQA32Z256rm:
  case X86::VMOVDQU32Z256rm:
  case X86::VMOVDQA64Z256rm:
  case X86::VMOVDQU64Z256rm:
    MemBytes = 32;
    return true;
  case X86::VMOVAPSZrm:
  case X86::VMOVUPSZrm:
  case X86::VMOVAPDZrm:
  case X86::VMOVUPDZrm:
  case X86::VMOVDQU8Zrm:
  case X86::VMOVDQU16Zrm:
  case X86::VMOVDQA32Zrm:
  case X86::VMOVDQU32Zrm:
  case X86::VMOVDQA64Zrm:
  case X86::VMOVDQU64Zrm:
    MemBytes = 64;
    return true;
  }
}

static std::array<CgOperand, 5> getFrameReferenceOpnds(int FI, int Offset = 0) {
  auto frame_idx = CgOperand::createFI(FI);

  return {frame_idx, CgOperand::createImmOperand(1),
          CgOperand::createRegOperand(0, false),
          CgOperand::createImmOperand(Offset),
          CgOperand::createRegOperand(0, false)};
#if 0
  CgInstruction *MI = MIB;
  CgFunction &MF = *MI->getParent()->getParent();
  CgFrameInfo &MFI = MF.getFrameInfo();
  const MCInstrDesc &MCID = MI->getDesc();
  auto Flags = MachineMemOperand::MONone;
  if (MCID.mayLoad())
    Flags |= MachineMemOperand::MOLoad;
  if (MCID.mayStore())
    Flags |= MachineMemOperand::MOStore;
  return addOffset(MIB.addFrameIndex(FI), Offset)
            .addMemOperand(MMO);
#endif
}

static bool isHReg(unsigned Reg) {
  return X86::GR8_ABCD_HRegClass.contains(Reg);
}

static unsigned getLoadStoreRegOpcode(const X86InstrInfo &TII, Register Reg,
                                      const TargetRegisterClass *RC,
                                      bool IsStackAligned,
                                      const X86Subtarget &STI, bool load) {
  bool HasAVX = STI.hasAVX();
  bool HasAVX512 = STI.hasAVX512();
  bool HasVLX = STI.hasVLX();

  switch (STI.getRegisterInfo()->getSpillSize(*RC)) {
  default:
    llvm_unreachable("Unknown spill size");
  case 1:
    assert(X86::GR8RegClass.hasSubClassEq(RC) && "Unknown 1-byte regclass");
    if (STI.is64Bit())
      // Copying to or from a physical H register on x86-64 requires a
      // NOREX move.  Otherwise use a normal move.
      if (isHReg(Reg) || X86::GR8_ABCD_HRegClass.hasSubClassEq(RC))
        return load ? X86::MOV8rm_NOREX : X86::MOV8mr_NOREX;
    return load ? X86::MOV8rm : X86::MOV8mr;
  case 2:
    if (X86::VK16RegClass.hasSubClassEq(RC))
      return load ? X86::KMOVWkm : X86::KMOVWmk;
    assert(X86::GR16RegClass.hasSubClassEq(RC) && "Unknown 2-byte regclass");
    return load ? X86::MOV16rm : X86::MOV16mr;
  case 4:
    if (X86::GR32RegClass.hasSubClassEq(RC))
      return load ? X86::MOV32rm : X86::MOV32mr;
    if (X86::FR32XRegClass.hasSubClassEq(RC))
      return load ? (HasAVX512 ? X86::VMOVSSZrm_alt
                     : HasAVX  ? X86::VMOVSSrm_alt
                               : X86::MOVSSrm_alt)
                  : (HasAVX512 ? X86::VMOVSSZmr
                     : HasAVX  ? X86::VMOVSSmr
                               : X86::MOVSSmr);
    if (X86::RFP32RegClass.hasSubClassEq(RC))
      return load ? X86::LD_Fp32m : X86::ST_Fp32m;
    if (X86::VK32RegClass.hasSubClassEq(RC)) {
      assert(STI.hasBWI() && "KMOVD requires BWI");
      return load ? X86::KMOVDkm : X86::KMOVDmk;
    }
    // All of these mask pair classes have the same spill size, the same
    // kind of kmov instructions can be used with all of them.
    if (X86::VK1PAIRRegClass.hasSubClassEq(RC) ||
        X86::VK2PAIRRegClass.hasSubClassEq(RC) ||
        X86::VK4PAIRRegClass.hasSubClassEq(RC) ||
        X86::VK8PAIRRegClass.hasSubClassEq(RC) ||
        X86::VK16PAIRRegClass.hasSubClassEq(RC))
      return load ? X86::MASKPAIR16LOAD : X86::MASKPAIR16STORE;
    if ((X86::FR16RegClass.hasSubClassEq(RC) ||
         X86::FR16XRegClass.hasSubClassEq(RC)) &&
        STI.hasFP16())
      return load ? X86::VMOVSHZrm_alt : X86::VMOVSHZmr;
    llvm_unreachable("Unknown 4-byte regclass");
  case 8:
    if (X86::GR64RegClass.hasSubClassEq(RC))
      return load ? X86::MOV64rm : X86::MOV64mr;
    if (X86::FR64XRegClass.hasSubClassEq(RC))
      return load ? (HasAVX512 ? X86::VMOVSDZrm_alt
                     : HasAVX  ? X86::VMOVSDrm_alt
                               : X86::MOVSDrm_alt)
                  : (HasAVX512 ? X86::VMOVSDZmr
                     : HasAVX  ? X86::VMOVSDmr
                               : X86::MOVSDmr);
    if (X86::VR64RegClass.hasSubClassEq(RC))
      return load ? X86::MMX_MOVQ64rm : X86::MMX_MOVQ64mr;
    if (X86::RFP64RegClass.hasSubClassEq(RC))
      return load ? X86::LD_Fp64m : X86::ST_Fp64m;
    if (X86::VK64RegClass.hasSubClassEq(RC)) {
      assert(STI.hasBWI() && "KMOVQ requires BWI");
      return load ? X86::KMOVQkm : X86::KMOVQmk;
    }
    llvm_unreachable("Unknown 8-byte regclass");
  case 10:
    assert(X86::RFP80RegClass.hasSubClassEq(RC) && "Unknown 10-byte regclass");
    return load ? X86::LD_Fp80m : X86::ST_FpP80m;
  case 16: {
    if (X86::VR128XRegClass.hasSubClassEq(RC)) {
      // If stack is realigned we can use aligned stores.
      if (IsStackAligned)
        return load ? (HasVLX      ? X86::VMOVAPSZ128rm
                       : HasAVX512 ? X86::VMOVAPSZ128rm_NOVLX
                       : HasAVX    ? X86::VMOVAPSrm
                                   : X86::MOVAPSrm)
                    : (HasVLX      ? X86::VMOVAPSZ128mr
                       : HasAVX512 ? X86::VMOVAPSZ128mr_NOVLX
                       : HasAVX    ? X86::VMOVAPSmr
                                   : X86::MOVAPSmr);
      else
        return load ? (HasVLX      ? X86::VMOVUPSZ128rm
                       : HasAVX512 ? X86::VMOVUPSZ128rm_NOVLX
                       : HasAVX    ? X86::VMOVUPSrm
                                   : X86::MOVUPSrm)
                    : (HasVLX      ? X86::VMOVUPSZ128mr
                       : HasAVX512 ? X86::VMOVUPSZ128mr_NOVLX
                       : HasAVX    ? X86::VMOVUPSmr
                                   : X86::MOVUPSmr);
    }
    llvm_unreachable("Unknown 16-byte regclass");
  }
  case 32:
    assert(X86::VR256XRegClass.hasSubClassEq(RC) && "Unknown 32-byte regclass");
    // If stack is realigned we can use aligned stores.
    if (IsStackAligned)
      return load ? (HasVLX      ? X86::VMOVAPSZ256rm
                     : HasAVX512 ? X86::VMOVAPSZ256rm_NOVLX
                                 : X86::VMOVAPSYrm)
                  : (HasVLX      ? X86::VMOVAPSZ256mr
                     : HasAVX512 ? X86::VMOVAPSZ256mr_NOVLX
                                 : X86::VMOVAPSYmr);
    else
      return load ? (HasVLX      ? X86::VMOVUPSZ256rm
                     : HasAVX512 ? X86::VMOVUPSZ256rm_NOVLX
                                 : X86::VMOVUPSYrm)
                  : (HasVLX      ? X86::VMOVUPSZ256mr
                     : HasAVX512 ? X86::VMOVUPSZ256mr_NOVLX
                                 : X86::VMOVUPSYmr);
  case 64:
    assert(X86::VR512RegClass.hasSubClassEq(RC) && "Unknown 64-byte regclass");
    assert(STI.hasAVX512() && "Using 512-bit register requires AVX512");
    if (IsStackAligned)
      return load ? X86::VMOVAPSZrm : X86::VMOVAPSZmr;
    else
      return load ? X86::VMOVUPSZrm : X86::VMOVUPSZmr;
  }
}

// Try and copy between VR128/VR64 and GR64 registers.
static unsigned copyToFromAsymmetricReg(unsigned DestReg, unsigned SrcReg,
                                        const X86Subtarget &Subtarget) {
  bool HasAVX = Subtarget.hasAVX();
  bool HasAVX512 = Subtarget.hasAVX512();

  // SrcReg(MaskReg) -> DestReg(GR64)
  // SrcReg(MaskReg) -> DestReg(GR32)

  // All KMASK RegClasses hold the same k registers, can be tested against
  // anyone.
  if (X86::VK16RegClass.contains(SrcReg)) {
    if (X86::GR64RegClass.contains(DestReg)) {
      assert(Subtarget.hasBWI());
      return X86::KMOVQrk;
    }
    if (X86::GR32RegClass.contains(DestReg))
      return Subtarget.hasBWI() ? X86::KMOVDrk : X86::KMOVWrk;
  }

  // SrcReg(GR64) -> DestReg(MaskReg)
  // SrcReg(GR32) -> DestReg(MaskReg)

  // All KMASK RegClasses hold the same k registers, can be tested against
  // anyone.
  if (X86::VK16RegClass.contains(DestReg)) {
    if (X86::GR64RegClass.contains(SrcReg)) {
      assert(Subtarget.hasBWI());
      return X86::KMOVQkr;
    }
    if (X86::GR32RegClass.contains(SrcReg))
      return Subtarget.hasBWI() ? X86::KMOVDkr : X86::KMOVWkr;
  }

  // SrcReg(VR128) -> DestReg(GR64)
  // SrcReg(VR64)  -> DestReg(GR64)
  // SrcReg(GR64)  -> DestReg(VR128)
  // SrcReg(GR64)  -> DestReg(VR64)

  if (X86::GR64RegClass.contains(DestReg)) {
    if (X86::VR128XRegClass.contains(SrcReg))
      // Copy from a VR128 register to a GR64 register.
      return HasAVX512 ? X86::VMOVPQIto64Zrr
             : HasAVX  ? X86::VMOVPQIto64rr
                       : X86::MOVPQIto64rr;
    if (X86::VR64RegClass.contains(SrcReg))
      // Copy from a VR64 register to a GR64 register.
      return X86::MMX_MOVD64from64rr;
  } else if (X86::GR64RegClass.contains(SrcReg)) {
    // Copy from a GR64 register to a VR128 register.
    if (X86::VR128XRegClass.contains(DestReg))
      return HasAVX512 ? X86::VMOV64toPQIZrr
             : HasAVX  ? X86::VMOV64toPQIrr
                       : X86::MOV64toPQIrr;
    // Copy from a GR64 register to a VR64 register.
    if (X86::VR64RegClass.contains(DestReg))
      return X86::MMX_MOVD64to64rr;
  }

  // SrcReg(VR128) -> DestReg(GR32)
  // SrcReg(GR32)  -> DestReg(VR128)

  if (X86::GR32RegClass.contains(DestReg) &&
      X86::VR128XRegClass.contains(SrcReg))
    // Copy from a VR128 register to a GR32 register.
    return HasAVX512 ? X86::VMOVPDI2DIZrr
           : HasAVX  ? X86::VMOVPDI2DIrr
                     : X86::MOVPDI2DIrr;

  if (X86::VR128XRegClass.contains(DestReg) &&
      X86::GR32RegClass.contains(SrcReg))
    // Copy from a VR128 register to a VR128 register.
    return HasAVX512 ? X86::VMOVDI2PDIZrr
           : HasAVX  ? X86::VMOVDI2PDIrr
                     : X86::MOVDI2PDIrr;
  return 0;
}

void X86LLVMWorkaround::copyPhysReg(const TargetInstrInfo &TII,
                                    CgBasicBlock &MBB,
                                    CgBasicBlock::iterator MI,
                                    const DebugLoc &DL, MCRegister DestReg,
                                    MCRegister SrcReg, bool KillSrc) const {
  CgFunction &MF = *MBB.getParent();
  const X86Subtarget &Subtarget = MF.getSubtarget<X86Subtarget>();
  const TargetRegisterInfo &TRI = MF.getRegisterInfo();

  // First deal with the normal symmetric copies.
  bool HasAVX = Subtarget.hasAVX();
  bool HasVLX = Subtarget.hasVLX();
  unsigned Opc = 0;
  if (X86::GR64RegClass.contains(DestReg, SrcReg)) {
    Opc = X86::MOV64rr;
#ifdef ZEN_ENABLE_EVM
  } else if (X86::GR64RegClass.contains(DestReg) &&
             X86::GR32RegClass.contains(SrcReg)) {
    unsigned Dest32 = TRI.getSubReg(DestReg, X86::sub_32bit);
    if (!Dest32)
      Dest32 = DestReg;
    SmallVector<CgOperand, 2> Operands{
        CgOperand::createRegOperand(Dest32, true),
        CgOperand::createRegOperand(SrcReg, false)};
    MF.createCgInstruction(MBB, MI, TII.get(X86::MOV32rr), Operands);
    return;
  } else if (X86::GR32RegClass.contains(DestReg) &&
             X86::GR64RegClass.contains(SrcReg)) {
    unsigned Src32 = TRI.getSubReg(SrcReg, X86::sub_32bit);
    if (!Src32)
      Src32 = SrcReg;
    SmallVector<CgOperand, 2> Operands{
        CgOperand::createRegOperand(DestReg, true),
        CgOperand::createRegOperand(Src32, false)};
    MF.createCgInstruction(MBB, MI, TII.get(X86::MOV32rr), Operands);
    return;
#endif
  } else if (X86::GR32RegClass.contains(DestReg, SrcReg)) {
    Opc = X86::MOV32rr;
  } else if (X86::GR16RegClass.contains(DestReg, SrcReg)) {
    Opc = X86::MOV16rr;
  } else if (X86::GR8RegClass.contains(DestReg, SrcReg)) {
    // Copying to or from a physical H register on x86-64 requires a NOREX
    // move. Otherwise use a normal move.
    if ((isHReg(DestReg) || isHReg(SrcReg)) && Subtarget.is64Bit()) {
      Opc = X86::MOV8rr_NOREX;
      // Both operands must be encodable without an REX prefix.
      assert(X86::GR8_NOREXRegClass.contains(SrcReg, DestReg) &&
             "8-bit H register can not be copied outside GR8_NOREX");
    } else
      Opc = X86::MOV8rr;
  } else if (X86::VR64RegClass.contains(DestReg, SrcReg)) {
    Opc = X86::MMX_MOVQ64rr;
  } else if (X86::VR128XRegClass.contains(DestReg, SrcReg)) {
    if (HasVLX)
      Opc = X86::VMOVAPSZ128rr;
    else if (X86::VR128RegClass.contains(DestReg, SrcReg))
      Opc = HasAVX ? X86::VMOVAPSrr : X86::MOVAPSrr;
    else {
      // If this an extended register and we don't have VLX we need to use a
      // 512-bit move.
      Opc = X86::VMOVAPSZrr;
      DestReg =
          TRI.getMatchingSuperReg(DestReg, X86::sub_xmm, &X86::VR512RegClass);
      SrcReg =
          TRI.getMatchingSuperReg(SrcReg, X86::sub_xmm, &X86::VR512RegClass);
    }
  } else if (X86::VR256XRegClass.contains(DestReg, SrcReg)) {
    if (HasVLX)
      Opc = X86::VMOVAPSZ256rr;
    else if (X86::VR256RegClass.contains(DestReg, SrcReg))
      Opc = X86::VMOVAPSYrr;
    else {
      // If this an extended register and we don't have VLX we need to use a
      // 512-bit move.
      Opc = X86::VMOVAPSZrr;
      DestReg =
          TRI.getMatchingSuperReg(DestReg, X86::sub_ymm, &X86::VR512RegClass);
      SrcReg =
          TRI.getMatchingSuperReg(SrcReg, X86::sub_ymm, &X86::VR512RegClass);
    }
  } else if (X86::VR512RegClass.contains(DestReg, SrcReg)) {
    Opc = X86::VMOVAPSZrr;
  } else if (X86::VK16RegClass.contains(DestReg, SrcReg)) {
    // All KMASK RegClasses hold the same k registers, can be tested against
    // anyone.
    Opc = Subtarget.hasBWI() ? X86::KMOVQkk : X86::KMOVWkk;
  }
  if (!Opc) {
    Opc = copyToFromAsymmetricReg(DestReg, SrcReg, Subtarget);
  }

  if (Opc) {
    SmallVector<CgOperand, 2> Operands{
        CgOperand::createRegOperand(DestReg, true),
        CgOperand::createRegOperand(SrcReg, false)};
    MF.createCgInstruction(MBB, MI, TII.get(Opc), Operands);
    return;
  }

  if (SrcReg == X86::EFLAGS || DestReg == X86::EFLAGS) {
    // FIXME: We use a fatal error here because historically LLVM has tried
    // lower some of these physreg copies and we want to ensure we get
    // reasonable bug reports if someone encounters a case no other testing
    // found. This path should be removed after the LLVM 7 release.
    report_fatal_error("Unable to copy EFLAGS physical register!");
  }

  report_fatal_error(Twine("Cannot emit physreg copy instruction (dest=") +
                     Twine(DestReg) + ", src=" + Twine(SrcReg) + ")");
}

void X86LLVMWorkaround::storeRegToStackSlot(
    const TargetInstrInfo &_TII, CgBasicBlock &MBB, CgBasicBlock::iterator MI,
    Register SrcReg, bool isKill, int FrameIdx, const TargetRegisterClass *RC,
    const TargetRegisterInfo *TRI) const {
  auto &TII = static_cast<const X86InstrInfo &>(_TII);
  const auto &MF = *MBB.getParent();
  // const auto &MFI = MF.getFrameInfo();
  // auto &RegInfo = MBB.getParent()->getRegInfo();
  assert(MF.getFrameInfo().getObjectSize(FrameIdx) >= TRI->getSpillSize(*RC) &&
         "Stack slot too small for store");
  unsigned Alignment = std::max<uint32_t>(TRI->getSpillSize(*RC), 16);
  bool isAligned =
      (MF.getSubtarget().getFrameLowering()->getStackAlign() >= Alignment);
  //|| (RI.canRealignStack(MF) && !MFI.isFixedObjectIndex(FrameIdx));
  unsigned Opc = getLoadStoreRegOpcode(TII, SrcReg, RC, isAligned,
                                       MF.getSubtarget<X86Subtarget>(), false);
  std::vector<CgOperand> opnds = {};
  const auto &other_opnds = getFrameReferenceOpnds(FrameIdx);
  opnds.insert(opnds.end(), other_opnds.begin(), other_opnds.end());
  opnds.push_back(CgOperand::createRegOperand(SrcReg, false));
  MBB.getParent()->createCgInstruction(MBB, MI, TII.get(Opc), opnds);
}

void X86LLVMWorkaround::loadRegFromStackSlot(
    const TargetInstrInfo &_TII, CgBasicBlock &MBB, CgBasicBlock::iterator MI,
    Register DestReg, int FrameIdx, const TargetRegisterClass *RC,
    const TargetRegisterInfo *TRI) const {
  auto &TII = static_cast<const X86InstrInfo &>(_TII);
  const CgFunction &MF = *MBB.getParent();
  // const CgFrameInfo &MFI = MF.getFrameInfo();
  assert(MF.getFrameInfo().getObjectSize(FrameIdx) >= TRI->getSpillSize(*RC) &&
         "Load size exceeds stack slot");

  unsigned Alignment = std::max<uint32_t>(TRI->getSpillSize(*RC), 16);
  bool isAligned =
      (MF.getSubtarget().getFrameLowering()->getStackAlign() >= Alignment);
  //|| (TII.getRegisterInfo().canRealignStack(MF) &&
  //! MFI.isFixedObjectIndex(FrameIdx));

  unsigned Opc = getLoadStoreRegOpcode(TII, DestReg, RC, isAligned,
                                       MF.getSubtarget<X86Subtarget>(), true);
  std::vector<CgOperand> opnds = {CgOperand::createRegOperand(DestReg, true)};
  const auto &other_opnds = getFrameReferenceOpnds(FrameIdx);
  opnds.insert(opnds.end(), other_opnds.begin(), other_opnds.end());
  MBB.getParent()->createCgInstruction(MBB, MI, TII.get(Opc), opnds);
}

static bool expand2AddrUndef(CgFunction &MF, CgInstruction &MI,
                             const MCInstrDesc &Desc) {
  ZEN_ASSERT(Desc.getNumOperands() == 3 && "Expected two-addr instruction.");
  MCRegister Reg = MI.getOperand(0).getReg();
  SmallVector<CgOperand, 3> Operands{
      CgOperand::createRegOperand(Reg, CgOperand::Define),
      CgOperand::createRegOperand(Reg, CgOperand::Undef),
      CgOperand::createRegOperand(Reg, CgOperand::Undef)};
  MF.replaceCgInstruction(&MI, Desc, Operands);
  return true;
}

static bool expandMOV32r1(CgFunction &MF, CgInstruction &MI,
                          const TargetInstrInfo &TII, bool MinusOne) {
  MCRegister Reg = MI.getOperand(0).getReg();
  SmallVector<CgOperand, 3> XOROperands{
      CgOperand::createRegOperand(Reg, CgOperand::Define),
      CgOperand::createRegOperand(Reg, CgOperand::Undef),
      CgOperand::createRegOperand(Reg, CgOperand::Undef)};
  // Insert the XOR to set the register to zero.
  MF.createCgInstruction(*MI.getParent(), CgBasicBlock::iterator(MI),
                         TII.get(X86::XOR32rr), XOROperands);
  const MCInstrDesc &Desc = TII.get(MinusOne ? X86::DEC32r : X86::INC32r);
  SmallVector<CgOperand, 2> IncOrDecOperands{
      CgOperand::createRegOperand(Reg, true),
      CgOperand::createRegOperand(Reg, false)};
  MF.replaceCgInstruction(&MI, Desc, IncOrDecOperands);
  return true;
}

static bool expandSHXDROT(CgFunction &MF, CgInstruction &MI,
                          const MCInstrDesc &Desc) {
  int64_t ShiftAmt = MI.getOperand(2).getImm();
  SmallVector<CgOperand, 4> Operands{
      CgOperand::createRegOperand(MI.getOperand(0).getReg(), true),
      CgOperand::createRegOperand(MI.getOperand(1).getReg(), false),
      CgOperand::createRegOperand(MI.getOperand(1).getReg(),
                                  MI.getOperand(1).isUndef() ? CgOperand::Undef
                                                             : CgOperand::None),
      CgOperand::createImmOperand(ShiftAmt),
  };
  MF.replaceCgInstruction(&MI, Desc, Operands);
  return true;
}

bool X86LLVMWorkaround::expandPostRAPseudo(const TargetInstrInfo &TII,
                                           CgInstruction &MI) const {
  CgFunction &MF = *MI.getParent()->getParent();
  const X86Subtarget &Subtarget = MF.getSubtarget<X86Subtarget>();
  const X86RegisterInfo *TRI = Subtarget.getRegisterInfo();
  bool HasAVX = Subtarget.hasAVX();

  switch (MI.getOpcode()) {
  case X86::MOV32r0:
    return expand2AddrUndef(MF, MI, TII.get(X86::XOR32rr));
  case X86::MOV32r1:
    return expandMOV32r1(MF, MI, TII, /*MinusOne=*/false);
  case X86::MOV32r_1:
    return expandMOV32r1(MF, MI, TII, /*MinusOne=*/true);
  case X86::FsFLD0SS:
  case X86::FsFLD0SD:
  case X86::FsFLD0SH:
    return expand2AddrUndef(MF, MI, TII.get(X86::XORPSrr));
  case X86::AVX512_FsFLD0SH:
  case X86::AVX512_FsFLD0SS:
  case X86::AVX512_FsFLD0SD: {
    bool HasVLX = Subtarget.hasVLX();
    Register SrcReg = MI.getOperand(0).getReg();
    const TargetRegisterInfo &TRI = MF.getRegisterInfo();
    if (HasVLX || TRI.getEncodingValue(SrcReg) < 16)
      return expand2AddrUndef(
          MF, MI, TII.get(HasVLX ? X86::VPXORDZ128rr : X86::VXORPSrr));
    // Extended register without VLX. Use a larger XOR.
    SrcReg = TRI.getMatchingSuperReg(SrcReg, X86::sub_xmm, &X86::VR512RegClass);
    MI.getOperand(0).setReg(SrcReg);
    return expand2AddrUndef(MF, MI, TII.get(X86::VPXORDZrr));
  }
  case X86::MOV32ri64: {
    Register Reg = MI.getOperand(0).getReg();
    Register Reg32 = TRI->getSubReg(Reg, X86::sub_32bit);
    SmallVector<CgOperand, 2> Operands{
        CgOperand::createRegOperand(Reg32, true),
        CgOperand::createImmOperand(MI.getOperand(1).getImm()),
        CgOperand::createRegOperand(Reg, false, true)};
    MF.replaceCgInstruction(&MI, TII.get(X86::MOV32ri), Operands);
    return true;
  }
  case X86::SHLDROT32ri:
    // TODO: equivalent to X86::ROL32ri
    return expandSHXDROT(MF, MI, TII.get(X86::SHLD32rri8));
  case X86::SHLDROT64ri:
    return expandSHXDROT(MF, MI, TII.get(X86::SHLD64rri8));
  case X86::SHRDROT32ri:
    return expandSHXDROT(MF, MI, TII.get(X86::SHRD32rri8));
  case X86::SHRDROT64ri:
    return expandSHXDROT(MF, MI, TII.get(X86::SHRD64rri8));
  }
  return false;
}

static bool isFrameStoreOpcode(int Opcode, unsigned &MemBytes) {
  switch (Opcode) {
  default:
    return false;
  case X86::MOV8mr:
  case X86::KMOVBmk:
    MemBytes = 1;
    return true;
  case X86::MOV16mr:
  case X86::KMOVWmk:
  case X86::VMOVSHZmr:
    MemBytes = 2;
    return true;
  case X86::MOV32mr:
  case X86::MOVSSmr:
  case X86::VMOVSSmr:
  case X86::VMOVSSZmr:
  case X86::KMOVDmk:
    MemBytes = 4;
    return true;
  case X86::MOV64mr:
  case X86::ST_FpP64m:
  case X86::MOVSDmr:
  case X86::VMOVSDmr:
  case X86::VMOVSDZmr:
  case X86::MMX_MOVD64mr:
  case X86::MMX_MOVQ64mr:
  case X86::MMX_MOVNTQmr:
  case X86::KMOVQmk:
    MemBytes = 8;
    return true;
  case X86::MOVAPSmr:
  case X86::MOVUPSmr:
  case X86::MOVAPDmr:
  case X86::MOVUPDmr:
  case X86::MOVDQAmr:
  case X86::MOVDQUmr:
  case X86::VMOVAPSmr:
  case X86::VMOVUPSmr:
  case X86::VMOVAPDmr:
  case X86::VMOVUPDmr:
  case X86::VMOVDQAmr:
  case X86::VMOVDQUmr:
  case X86::VMOVUPSZ128mr:
  case X86::VMOVAPSZ128mr:
  case X86::VMOVUPSZ128mr_NOVLX:
  case X86::VMOVAPSZ128mr_NOVLX:
  case X86::VMOVUPDZ128mr:
  case X86::VMOVAPDZ128mr:
  case X86::VMOVDQA32Z128mr:
  case X86::VMOVDQU32Z128mr:
  case X86::VMOVDQA64Z128mr:
  case X86::VMOVDQU64Z128mr:
  case X86::VMOVDQU8Z128mr:
  case X86::VMOVDQU16Z128mr:
    MemBytes = 16;
    return true;
  case X86::VMOVUPSYmr:
  case X86::VMOVAPSYmr:
  case X86::VMOVUPDYmr:
  case X86::VMOVAPDYmr:
  case X86::VMOVDQUYmr:
  case X86::VMOVDQAYmr:
  case X86::VMOVUPSZ256mr:
  case X86::VMOVAPSZ256mr:
  case X86::VMOVUPSZ256mr_NOVLX:
  case X86::VMOVAPSZ256mr_NOVLX:
  case X86::VMOVUPDZ256mr:
  case X86::VMOVAPDZ256mr:
  case X86::VMOVDQU8Z256mr:
  case X86::VMOVDQU16Z256mr:
  case X86::VMOVDQA32Z256mr:
  case X86::VMOVDQU32Z256mr:
  case X86::VMOVDQA64Z256mr:
  case X86::VMOVDQU64Z256mr:
    MemBytes = 32;
    return true;
  case X86::VMOVUPSZmr:
  case X86::VMOVAPSZmr:
  case X86::VMOVUPDZmr:
  case X86::VMOVAPDZmr:
  case X86::VMOVDQU8Zmr:
  case X86::VMOVDQU16Zmr:
  case X86::VMOVDQA32Zmr:
  case X86::VMOVDQU32Zmr:
  case X86::VMOVDQA64Zmr:
  case X86::VMOVDQU64Zmr:
    MemBytes = 64;
    return true;
  }
  return false;
}

unsigned X86LLVMWorkaround::isLoadFromStackSlot(const TargetInstrInfo &TII,
                                                const CgInstruction &MI,
                                                int &FrameIndex) const {
  unsigned Dummy;
  return isLoadFromStackSlot(TII, MI, FrameIndex, Dummy);
}
bool static isFrameOperand(const CgInstruction &MI, unsigned int Op,
                           int &FrameIndex) {
  if (MI.getOperand(Op + X86::AddrBaseReg).isFI() &&
      MI.getOperand(Op + X86::AddrScaleAmt).isImm() &&
      MI.getOperand(Op + X86::AddrIndexReg).isReg() &&
      MI.getOperand(Op + X86::AddrDisp).isImm() &&
      MI.getOperand(Op + X86::AddrScaleAmt).getImm() == 1 &&
      MI.getOperand(Op + X86::AddrIndexReg).getReg() == 0 &&
      MI.getOperand(Op + X86::AddrDisp).getImm() == 0) {
    FrameIndex = MI.getOperand(Op + X86::AddrBaseReg).getIndex();
    return true;
  }
  return false;
}

unsigned X86LLVMWorkaround::isLoadFromStackSlot(const TargetInstrInfo &TII,
                                                const CgInstruction &MI,
                                                int &FrameIndex,
                                                unsigned &MemBytes) const {
  if (isFrameLoadOpcode(MI.getOpcode(), MemBytes))
    if (MI.getOperand(0).getSubReg() == 0 && isFrameOperand(MI, 1, FrameIndex))
      return MI.getOperand(0).getReg();
  return 0;
}

void X86LLVMWorkaround::reMaterialize(const TargetInstrInfo &TII,
                                      CgBasicBlock &MBB,
                                      CgBasicBlock::iterator I,
                                      Register DestReg, unsigned SubIdx,
                                      const CgInstruction &Orig,
                                      const TargetRegisterInfo &TRI) const {
  bool ClobbersEFLAGS = Orig.modifiesRegister(X86::EFLAGS, &TRI);
  auto *MF = MBB.getParent();
  if (ClobbersEFLAGS && MBB.computeRegisterLiveness(&TRI, X86::EFLAGS, I) !=
                            CgBasicBlock::LQR_Dead) {
    // The instruction clobbers EFLAGS. Re-materialize as MOV32ri to avoid
    // side effects.
    int Value = 0;
    switch (Orig.getOpcode()) {
    case X86::MOV32r0:
      Value = 0;
      break;
    case X86::MOV32r1:
      Value = 1;
      break;
    case X86::MOV32r_1:
      Value = -1;
      break;
    default:
      llvm_unreachable("Unexpected instruction!");
    }

    SmallVector<CgOperand, 2> Operands{Orig.getOperand(0),
                                       CgOperand::createImmOperand(Value)};
    MF->createCgInstruction(MBB, I, TII.get(X86::MOV32ri), Operands, false);
  } else {
    CgInstruction *MI = MBB.getParent()->CloneMachineInstr(&Orig);
    MBB.insert(I, MI);
  }

  CgInstruction &NewMI = *std::prev(I);
  NewMI.substituteRegister(Orig.getOperand(0).getReg(), DestReg, SubIdx, TRI);
}

unsigned X86LLVMWorkaround::isStoreToStackSlot(const TargetInstrInfo &TII,
                                               const CgInstruction &MI,
                                               int &FrameIndex) const {
  unsigned Dummy;
  return X86LLVMWorkaround::isStoreToStackSlot(TII, MI, FrameIndex, Dummy);
}

unsigned X86LLVMWorkaround::isStoreToStackSlot(const TargetInstrInfo &TII,
                                               const CgInstruction &MI,
                                               int &FrameIndex,
                                               unsigned &MemBytes) const {
  if (isFrameStoreOpcode(MI.getOpcode(), MemBytes))
    if (MI.getOperand(X86::AddrNumOperands).getSubReg() == 0 &&
        isFrameOperand(MI, 0, FrameIndex))
      return MI.getOperand(X86::AddrNumOperands).getReg();
  return 0;
}

//===----------------------------------------------------------------------===//
//
// TargetRegisterClass
//
//===----------------------------------------------------------------------===//

ArrayRef<MCPhysReg>
X86LLVMWorkaround::getRawAllocationOrder(const TargetRegisterClass *TRC,
                                         const CgFunction &MF) const {
  if (TRC == &X86::GR8RegClass) {
    static const MCPhysReg AltOrder1[] = {
        X86::AL,   X86::CL,   X86::DL,   X86::BL,  X86::SIL,  X86::DIL,
        X86::BPL,  X86::SPL,  X86::R8B,  X86::R9B, X86::R10B, X86::R11B,
        X86::R14B, X86::R15B, X86::R12B, X86::R13B};
    const MCRegisterClass &MCR = X86MCRegisterClasses[X86::GR8RegClassID];
    const ArrayRef<MCPhysReg> Order[] = {
        makeArrayRef(MCR.begin(), MCR.getNumRegs()), makeArrayRef(AltOrder1)};
    const unsigned Select = MF.getSubtarget<X86Subtarget>().is64Bit();
    assert(Select < 2);
    return Order[Select];
  }
  return LLVMWorkaround::getRawAllocationOrder(TRC, MF);
}

//===----------------------------------------------------------------------===//
//
// TargetRegisterInfo
//
//===----------------------------------------------------------------------===//

static const X86FrameLowering *getFrameLowering(const CgFunction &MF) {
  return static_cast<const X86FrameLowering *>(
      MF.getSubtarget().getFrameLowering());
}

static bool CantUseSP(const CgFrameInfo &MFI) {
  return MFI.hasVarSizedObjects() || MFI.hasOpaqueSPAdjustment();
}

const TargetRegisterClass *
X86LLVMWorkaround::getGPRsForTailCall(const X86RegisterInfo &TRI,
                                      const CgFunction &MF) const {
  // const Function &F = MF.getFunction();
  // if (IsWin64 || (F.getCallingConv() == CallingConv::Win64))
  //     return &X86::GR64_TCW64RegClass;
  // else if (Is64Bit)
  return &X86::GR64_TCRegClass;

  // bool hasHipeCC = (F.getCallingConv() == CallingConv::HiPE);
  // if (hasHipeCC)
  //     return &X86::GR32RegClass;
  // return &X86::GR32_TCRegClass;
}

bool X86LLVMWorkaround::hasBasePointer(const X86RegisterInfo *TRI,
                                       const CgFunction &MF) const {
  //     const X86MachineFunctionInfo *X86FI =
  //     MF.getInfo<X86MachineFunctionInfo>();
  //   if (X86FI->hasPreallocatedCall())
  //     return true;

  const auto &MFI = MF.getFrameInfo();

  //   if (!EnableBasePointer)
  //     return false;

  // When we need stack realignment, we can't address the stack from the frame
  // pointer.  When we have dynamic allocas or stack-adjusting inline asm, we
  // can't address variables from the stack pointer.  MS inline asm can
  // reference locals while also adjusting the stack pointer.  When we can't
  // use both the SP and the FP, we need a separate base pointer register.
  bool CantUseFP = hasStackRealignment(*TRI, MF);
  return CantUseFP && CantUseSP(MFI);
}

bool X86LLVMWorkaround::canRealignStack(const TargetRegisterInfo &_TRI,
                                        const CgFunction &MF) const {
  auto &TRI = static_cast<const X86RegisterInfo &>(_TRI);

  if (!LLVMWorkaround::canRealignStack(TRI, MF))
    return false;

  const auto &MFI = MF.getFrameInfo();
  const auto *MRI = &MF.getRegInfo();

  // Stack realignment requires a frame pointer.  If we already started
  // register allocation with frame pointer elimination, it is too late now.
  if (!MRI->canReserveReg(TRI.getFramePtr()))
    return false;

  // If a base pointer is necessary.  Check that it isn't too late to reserve
  // it.
  if (CantUseSP(MFI))
    return MRI->canReserveReg(TRI.getBaseRegister());
  return true;
}

void X86LLVMWorkaround::eliminateFrameIndex(const TargetRegisterInfo &_TRI,
                                            CgInstruction &MI, int SPAdj,
                                            unsigned FIOperandNum,
                                            RegScavenger *RS) const {
  auto &TRI = static_cast<const X86RegisterInfo &>(_TRI);
  CgBasicBlock &MBB = *MI.getParent();
  // CgFunction &MF = *MBB.getParent();
  CgFunction &MF = *MBB.getParent();
#if 0
  CgBasicBlock::iterator MBBI = MBB.getFirstTerminator();
  bool IsEHFuncletEpilogue = MBBI == MBB.end() ? false
                                               : isFuncletReturnInstr(*MBBI);
#endif
  const X86FrameLowering *TFI = getFrameLowering(MF);
  int FrameIndex = MI.getOperand(FIOperandNum).getIndex();

  // Determine base register and offset.
  int FIOffset;
  Register BasePtr;
  if (MI.isReturn()) {
    assert((!hasStackRealignment(TRI, MF) ||
            MF.getFrameInfo().isFixedObjectIndex(FrameIndex)) &&
           "Return instruction can only reference SP relative frame "
           "objects");
    FIOffset =
        getFrameIndexReferenceSP(TFI, MF, FrameIndex, BasePtr, 0).getFixed();
    //   } else if (TFI->Is64Bit && (MBB.isEHFuncletEntry() ||
    //   IsEHFuncletEpilogue)) {
    //     FIOffset = TFI->getWin64EHFrameIndexRef(MF, FrameIndex, BasePtr);
  } else {
    FIOffset = getFrameIndexReference(TFI, MF, FrameIndex, BasePtr).getFixed();
  }

  // LOCAL_ESCAPE uses a single offset, with no register. It only works in the
  // simple FP case, and doesn't work with stack realignment. On 32-bit, the
  // offset is from the traditional base pointer location.  On 64-bit, the
  // offset is from the SP at the end of the prologue, not the FP location.
  // This matches the behavior of llvm.frameaddress.
  unsigned Opc = MI.getOpcode();
  //   if (Opc == TargetOpcode::LOCAL_ESCAPE) {
  //     CgOperand &FI = MI.getOperand(FIOperandNum);
  //     FI.ChangeToImmediate(FIOffset);
  //     return;
  //   }

  // For LEA64_32r when BasePtr is 32-bits (X32) we can use full-size 64-bit
  // register as source operand, semantic is the same and destination is
  // 32-bits. It saves one byte per lea in code since 0x67 prefix is avoided.
  // Don't change BasePtr since it is used later for stack adjustment.
  Register MachineBasePtr = BasePtr;
  if (Opc == X86::LEA64_32r && X86::GR32RegClass.contains(BasePtr))
    MachineBasePtr = getX86SubSuperRegister(BasePtr, 64);

  // This must be part of a four operand memory reference.  Replace the
  // FrameIndex with base register.  Add an offset to the offset.
  MI.getOperand(FIOperandNum).ChangeToRegister(MachineBasePtr, false);

  if (BasePtr == TRI.getStackRegister())
    FIOffset += SPAdj;

  // The frame index format for stackmaps and patchpoints is different from
  // the X86 format. It only has a FI and an offset.
  //   if (Opc == TargetOpcode::STACKMAP || Opc == TargetOpcode::PATCHPOINT) {
  //     assert(BasePtr == TRI.getFramePtr() && "Expected the FP as base
  //     register"); int64_t Offset = MI.getOperand(FIOperandNum + 1).getImm()
  //     + FIOffset; MI.getOperand(FIOperandNum +
  //     1).ChangeToImmediate(Offset); return;
  //   }

  if (MI.getOperand(FIOperandNum + 3).isImm()) {
    // Offset is a 32-bit integer.
    int Imm = (int)(MI.getOperand(FIOperandNum + 3).getImm());
    int Offset = FIOffset + Imm;
    assert((!MF.getSubtarget<X86Subtarget>().is64Bit() ||
            isInt<32>((long long)FIOffset + Imm)) &&
           "Requesting 64-bit offset in 32-bit immediate!");
    // if (Offset != 0 || !tryOptimizeLEAtoMOV(II))
    if (Offset != 0)
      MI.getOperand(FIOperandNum + 3).ChangeToImmediate(Offset);
  } else {
    ZEN_ASSERT_TODO();
    // Offset is symbolic. This is extremely rare.
    // uint64_t Offset = FIOffset +
    //   (uint64_t)MI.getOperand(FIOperandNum+3).getOffset();
    // MI.getOperand(FIOperandNum + 3).setOffset(Offset);
  }
}

unsigned
X86LLVMWorkaround::findDeadCallerSavedReg(const X86RegisterInfo *TRI,
                                          CgBasicBlock &MBB,
                                          CgBasicBlock::iterator &MBBI) const {
  const CgFunction *MF = MBB.getParent();
  //   if (MF->callsEHReturn())
  //     return 0;

  const TargetRegisterClass &AvailableRegs = *getGPRsForTailCall(*TRI, *MF);

  if (MBBI == MBB.end())
    return 0;

  switch (MBBI->getOpcode()) {
  default:
    return 0;
  case TargetOpcode::PATCHABLE_RET:
  case X86::RET:
  case X86::RET32:
  case X86::RET64:
  case X86::RETI32:
  case X86::RETI64:
  case X86::TCRETURNdi:
  case X86::TCRETURNri:
  case X86::TCRETURNmi:
  case X86::TCRETURNdi64:
  case X86::TCRETURNri64:
  case X86::TCRETURNmi64:
  case X86::EH_RETURN:
  case X86::EH_RETURN64: {
    SmallSet<uint16_t, 8> Uses;
    for (unsigned I = 0, E = MBBI->getNumOperands(); I != E; ++I) {
      CgOperand &MO = MBBI->getOperand(I);
      if (!MO.isReg() || MO.isDef())
        continue;
      Register Reg = MO.getReg();
      if (!Reg)
        continue;
      for (MCRegAliasIterator AI(Reg, TRI, true); AI.isValid(); ++AI)
        Uses.insert(*AI);
    }

    for (auto CS : AvailableRegs)
      if (!Uses.count(CS) && CS != X86::RIP && CS != X86::RSP && CS != X86::ESP)
        return CS;
  }
  }

  return 0;
}

Register X86LLVMWorkaround::getFrameRegister(const TargetRegisterInfo *TRI,
                                             const CgFunction &MF) const {
  const X86RegisterInfo &X86TRI = static_cast<const X86RegisterInfo &>(*TRI);
  const X86FrameLowering *TFI = getFrameLowering(MF);
  return hasFP(*TFI, MF) ? X86TRI.getFramePtr() : X86TRI.getStackRegister();
}

const TargetRegisterClass *
X86LLVMWorkaround::getLargestLegalSuperClass(const TargetRegisterInfo &TRI,
                                             const TargetRegisterClass *RC,
                                             const CgFunction &MF) const {
  // Don't allow super-classes of GR8_NOREX.  This class is only used after
  // extracting sub_8bit_hi sub-registers.  The H sub-registers cannot be
  // copied to the full GR8 register class in 64-bit mode, so we cannot allow
  // the reigster class inflation.
  //
  // The GR8_NOREX class is always used in a way that won't be constrained to
  // a sub-class, so sub-classes like GR8_ABCD_L are allowed to expand to the
  // full GR8 class.
  if (RC == &X86::GR8_NOREXRegClass)
    return RC;

  const X86Subtarget &Subtarget = MF.getSubtarget<X86Subtarget>();

  const TargetRegisterClass *Super = RC;
  TargetRegisterClass::sc_iterator I = RC->getSuperClasses();
  do {
    switch (Super->getID()) {
    case X86::FR32RegClassID:
    case X86::FR64RegClassID:
      // If AVX-512 isn't supported we should only inflate to these
      // classes.
      if (!Subtarget.hasAVX512() &&
          TRI.getRegSizeInBits(*Super) == TRI.getRegSizeInBits(*RC))
        return Super;
      break;
    case X86::VR128RegClassID:
    case X86::VR256RegClassID:
      // If VLX isn't supported we should only inflate to these
      // classes.
      if (!Subtarget.hasVLX() &&
          TRI.getRegSizeInBits(*Super) == TRI.getRegSizeInBits(*RC))
        return Super;
      break;
    case X86::VR128XRegClassID:
    case X86::VR256XRegClassID:
      // If VLX isn't support we shouldn't inflate to these classes.
      if (Subtarget.hasVLX() &&
          TRI.getRegSizeInBits(*Super) == TRI.getRegSizeInBits(*RC))
        return Super;
      break;
    case X86::FR32XRegClassID:
    case X86::FR64XRegClassID:
      // If AVX-512 isn't support we shouldn't inflate to these
      // classes.
      if (Subtarget.hasAVX512() &&
          TRI.getRegSizeInBits(*Super) == TRI.getRegSizeInBits(*RC))
        return Super;
      break;
    case X86::GR8RegClassID:
    case X86::GR16RegClassID:
    case X86::GR32RegClassID:
    case X86::GR64RegClassID:
    case X86::RFP32RegClassID:
    case X86::RFP64RegClassID:
    case X86::RFP80RegClassID:
    case X86::VR512_0_15RegClassID:
    case X86::VR512RegClassID:
      // Don't return a super-class that would shrink the spill size.
      // That can happen with the vector and float classes.
      if (TRI.getRegSizeInBits(*Super) == TRI.getRegSizeInBits(*RC))
        return Super;
    }
    Super = *I++;
  } while (Super);
  return RC;
}

const TargetRegisterClass *X86LLVMWorkaround::getPointerRegClass(
    const TargetRegisterInfo &TRI, const CgFunction &MF, unsigned Kind) const {
  const X86Subtarget &Subtarget = MF.getSubtarget<X86Subtarget>();
  switch (Kind) {
  default:
    llvm_unreachable("Unexpected Kind in getPointerRegClass!");
  case 0: // Normal GPRs.
    if (Subtarget.isTarget64BitLP64())
      return &X86::GR64RegClass;
    // If the target is 64bit but we have been told to use 32bit
    // addresses, we can still use 64-bit register as long as we know
    // the high bits are zeros. Reflect that in the returned register
    // class.
    if (Subtarget.is64Bit()) {
      // When the target also allows 64-bit frame pointer and we do
      // have a frame, this is fine to use it for the address accesses
      // as well.
      const X86FrameLowering *TFI = getFrameLowering(MF);
      return hasFP(*TFI, MF) && TFI->Uses64BitFramePtr
                 ? &X86::LOW32_ADDR_ACCESS_RBPRegClass
                 : &X86::LOW32_ADDR_ACCESSRegClass;
    }
    return &X86::GR32RegClass;
  case 1: // Normal GPRs except the stack pointer (for encoding reasons).
    if (Subtarget.isTarget64BitLP64())
      return &X86::GR64_NOSPRegClass;
    // NOSP does not contain RIP, so no special case here.
    return &X86::GR32_NOSPRegClass;
  case 2: // NOREX GPRs.
    if (Subtarget.isTarget64BitLP64())
      return &X86::GR64_NOREXRegClass;
    return &X86::GR32_NOREXRegClass;
  case 3: // NOREX GPRs except the stack pointer (for encoding reasons).
    if (Subtarget.isTarget64BitLP64())
      return &X86::GR64_NOREX_NOSPRegClass;
    // NOSP does not contain RIP, so no special case here.
    return &X86::GR32_NOREX_NOSPRegClass;
  case 4: // Available for tailcall (not callee-saved GPRs).
    return getGPRsForTailCall(static_cast<const X86RegisterInfo &>(TRI), MF);
  }
}

static CgShapeT getTileShape(Register VirtReg, CgVirtRegMap *VRM,
                             const CgRegisterInfo *MRI) {
  if (VRM->hasShape(VirtReg))
    return VRM->getShape(VirtReg);

  const CgOperand &Def = *MRI->def_begin(VirtReg);
  CgInstruction *MI = const_cast<CgInstruction *>(Def.getParent());
  unsigned OpCode = MI->getOpcode();
  switch (OpCode) {
  default:
    llvm_unreachable("Unexpected machine instruction on tile register!");
    break;
  case X86::COPY: {
    Register SrcReg = MI->getOperand(1).getReg();
    CgShapeT Shape = getTileShape(SrcReg, VRM, MRI);
    VRM->assignVirt2Shape(VirtReg, Shape);
    return Shape;
  }
  // We only collect the tile shape that is defined.
  case X86::PTILELOADDV:
  case X86::PTILELOADDT1V:
  case X86::PTDPBSSDV:
  case X86::PTDPBSUDV:
  case X86::PTDPBUSDV:
  case X86::PTDPBUUDV:
  case X86::PTILEZEROV:
  case X86::PTDPBF16PSV:
    auto &MO1 = MI->getOperand(1);
    auto &MO2 = MI->getOperand(2);
    CgShapeT Shape(&MO1, &MO2, MRI);
    VRM->assignVirt2Shape(VirtReg, Shape);
    return Shape;
  }
}

bool X86LLVMWorkaround::getRegAllocationHints(
    const TargetRegisterInfo &TRI, Register VirtReg, ArrayRef<MCPhysReg> Order,
    SmallVectorImpl<MCPhysReg> &Hints, const CgFunction &MF,
    const CgVirtRegMap *VRM, const CgLiveRegMatrix *Matrix) const {
  const auto *MRI = &MF.getRegInfo();
  const TargetRegisterClass &RC = *MRI->getRegClass(VirtReg);
  bool BaseImplRetVal = LLVMWorkaround::getRegAllocationHints(
      TRI, VirtReg, Order, Hints, MF, VRM, Matrix);

  if (RC.getID() != X86::TILERegClassID)
    return BaseImplRetVal;

  CgShapeT VirtShape =
      getTileShape(VirtReg, const_cast<CgVirtRegMap *>(VRM), MRI);
  auto AddHint = [&](MCPhysReg PhysReg) {
    Register VReg = Matrix->getOneVReg(PhysReg);
    if (VReg == MCRegister::NoRegister) { // Not allocated yet
      Hints.push_back(PhysReg);
      return;
    }
    CgShapeT PhysShape =
        getTileShape(VReg, const_cast<CgVirtRegMap *>(VRM), MRI);
    if (PhysShape == VirtShape)
      Hints.push_back(PhysReg);
  };

  SmallSet<MCPhysReg, 4> CopyHints;
  CopyHints.insert(Hints.begin(), Hints.end());
  Hints.clear();
  for (auto Hint : CopyHints) {
    if (RC.contains(Hint) && !MRI->isReserved(Hint))
      AddHint(Hint);
  }
  for (MCPhysReg PhysReg : Order) {
    if (!CopyHints.count(PhysReg) && RC.contains(PhysReg) &&
        !MRI->isReserved(PhysReg))
      AddHint(PhysReg);
  }

#define DEBUG_TYPE "tile-hint"
  LLVM_DEBUG({
    dbgs() << "Hints for virtual register " << format_hex(VirtReg, 8) << "\n";
    for (auto Hint : Hints) {
      dbgs() << "tmm" << Hint << ",";
    }
    dbgs() << "\n";
  });
#undef DEBUG_TYPE

  return true;
}

BitVector X86LLVMWorkaround::getReservedRegs(const TargetRegisterInfo &TRI,
                                             const CgFunction &MF) const {
  BitVector Reserved(TRI.getNumRegs());
  const X86FrameLowering *TFI = getFrameLowering(MF);

  // Set the floating point control register as reserved.
  Reserved.set(X86::FPCW);

  // Set the floating point status register as reserved.
  Reserved.set(X86::FPSW);

  // Set the SIMD floating point control register as reserved.
  Reserved.set(X86::MXCSR);

  auto &X86_TRI = static_cast<const X86RegisterInfo &>(TRI);
  // Set the stack-pointer register and its aliases as reserved.
  for (const MCPhysReg &SubReg : X86_TRI.subregs_inclusive(X86::RSP))
    Reserved.set(SubReg);

  // Set the Shadow Stack Pointer as reserved.
  Reserved.set(X86::SSP);

  // Set the instruction pointer register and its aliases as reserved.
  for (const MCPhysReg &SubReg : X86_TRI.subregs_inclusive(X86::RIP))
    Reserved.set(SubReg);

  // Set the frame-pointer register and its aliases as reserved if needed.
  if (hasFP(*TFI, MF)) {
    for (const MCPhysReg &SubReg : X86_TRI.subregs_inclusive(X86::RBP))
      Reserved.set(SubReg);
  }

  // Set the base-pointer register and its aliases as reserved if needed.
#if 0
  if (hasBasePointer(TRI, MF)) {
    CallingConv::ID CC = MF.getFunction().getCallingConv();
    const uint32_t *RegMask = getCallPreservedMask(MF, CC);
    if (CgOperand::clobbersPhysReg(RegMask, getBaseRegister()))
      report_fatal_error(
        "Stack realignment in presence of dynamic allocas is not supported with"
        "this calling convention.");

    Register BasePtr = getX86SubSuperRegister(getBaseRegister(), 64);
    for (const MCPhysReg &SubReg : subregs_inclusive(BasePtr))
      Reserved.set(SubReg);
  }
#endif

  // Mark the segment registers as reserved.
  Reserved.set(X86::CS);
  Reserved.set(X86::SS);
  Reserved.set(X86::DS);
  Reserved.set(X86::ES);
  Reserved.set(X86::FS);
  Reserved.set(X86::GS);

  // Mark the floating point stack registers as reserved.
  for (unsigned n = 0; n != 8; ++n)
    Reserved.set(X86::ST0 + n);

  // Reserve the registers that only exist in 64-bit mode.
  bool Is64Bit = TFI->Is64Bit;
  if (!Is64Bit) {
    // These 8-bit registers are part of the x86-64 extension even though
    // their super-registers are old 32-bits.
    Reserved.set(X86::SIL);
    Reserved.set(X86::DIL);
    Reserved.set(X86::BPL);
    Reserved.set(X86::SPL);
    Reserved.set(X86::SIH);
    Reserved.set(X86::DIH);
    Reserved.set(X86::BPH);
    Reserved.set(X86::SPH);

    for (unsigned n = 0; n != 8; ++n) {
      // R8, R9, ...
      for (MCRegAliasIterator AI(X86::R8 + n, &TRI, true); AI.isValid(); ++AI)
        Reserved.set(*AI);

      // XMM8, XMM9, ...
      for (MCRegAliasIterator AI(X86::XMM8 + n, &TRI, true); AI.isValid(); ++AI)
        Reserved.set(*AI);
    }
  }
  if (!Is64Bit || !MF.getSubtarget<X86Subtarget>().hasAVX512()) {
    for (unsigned n = 16; n != 32; ++n) {
      for (MCRegAliasIterator AI(X86::XMM0 + n, &TRI, true); AI.isValid(); ++AI)
        Reserved.set(*AI);
    }
  }

  assert(TRI.checkAllSuperRegsMarked(Reserved,
                                     {X86::SIL, X86::DIL, X86::BPL, X86::SPL,
                                      X86::SIH, X86::DIH, X86::BPH, X86::SPH}));
  return Reserved;
}

//===----------------------------------------------------------------------===//
//
// TargetFrameLowering
//
//===----------------------------------------------------------------------===//

// If we're forcing a stack realignment we can't rely on just the frame
// info, we need to know the ABI stack alignment as well in case we
// have a call out.  Otherwise just make sure we have some alignment - we'll
// go with the minimum SlotSize.
static uint64_t calculateMaxStackAlign(const CgFunction &MF) {
  const auto &MFI = MF.getFrameInfo();
  Align MaxAlign = MFI.getMaxAlign(); // Desired stack alignment.
                                      //   Align StackAlign = getStackAlign();
  //   if (MF.getFunction().hasFnAttribute("stackrealign")) {
  //     if (MFI.hasCalls())
  //       MaxAlign = (StackAlign > MaxAlign) ? StackAlign : MaxAlign;
  //     else if (MaxAlign < SlotSize)
  //       MaxAlign = Align(SlotSize);
  //   }
  return MaxAlign.value();
}

void X86LLVMWorkaround::emitPrologue(const TargetFrameLowering &_TFI,
                                     CgFunction &MF, CgBasicBlock &MBB) const {
  auto &TFI = static_cast<const X86FrameLowering &>(_TFI);
  auto &STI = TFI.STI;
  auto *TRI = TFI.TRI;
  assert(&STI == &MF.getSubtarget<X86Subtarget>() &&
         "MF used frame lowering for wrong subtarget");
  CgBasicBlock::iterator MBBI = MBB.begin();
  CgFrameInfo &MFI = MF.getFrameInfo();
  uint64_t MaxAlign = calculateMaxStackAlign(MF); // Desired stack alignment.
  uint64_t StackSize = MFI.getStackSize(); // Number of bytes to allocate.
  bool IsFunclet = false;
  bool IsClrFunclet = false;
  bool HasFP = hasFP(TFI, MF);
  bool IsWin64Prologue = false;
  bool NeedsWin64CFI = false;
  bool NeedsWinCFI = false;
  bool NeedsDwarfCFI = false;
  Register FramePtr = getFrameRegister(TRI, MF);
  const Register MachineFramePtr =
      STI.isTarget64BitILP32() ? Register(getX86SubSuperRegister(FramePtr, 64))
                               : FramePtr;
  Register BasePtr = TRI->getBaseRegister();
  bool HasWinCFI = false;

  // Debug location must be unknown since the first debug location is used
  // to determine the end of the prologue.
  DebugLoc DL;
  unsigned TailCallArgReserveSize = 0;
  const bool EmitStackProbeCall = false;
  unsigned StackProbeSize = 0;

  uint64_t NumBytes = 0;
  int stackGrowth = -TFI.SlotSize;

  if (HasFP) {
    assert(MF.getRegInfo().isReserved(MachineFramePtr) && "FP reserved");
    // Calculate required stack adjustment.
    uint64_t FrameSize = StackSize - TFI.SlotSize;

    NumBytes =
        FrameSize - (MF.getCalleeSavedFrameSize() + TailCallArgReserveSize);

    // Callee-saved registers are pushed on stack before the stack is
    // realigned.
    if (hasStackRealignment(*TRI, MF) && !IsWin64Prologue)
      NumBytes = alignTo(NumBytes, MaxAlign);

    SmallVector<CgOperand, 1> operands{
        CgOperand::createRegOperand(MachineFramePtr, CgOperand::Kill),
    };
    CgInstruction *inst = MF.createCgInstruction(
        MBB, MBBI, TFI.TII.get(TFI.Is64Bit ? X86::PUSH64r : X86::PUSH32r),
        operands);
    inst->setFlag(CgInstruction::FrameSetup);

    if (!IsFunclet) {
      if (!IsWin64Prologue && !IsFunclet) {
        // Update EBP with the new base value.
        SmallVector<CgOperand, 2> operands{
            CgOperand::createRegOperand(FramePtr, CgOperand::Define),
            CgOperand::createRegOperand(TFI.StackPtr),
        };
        CgInstruction *inst = MF.createCgInstruction(
            MBB, MBBI,
            TFI.TII.get(TFI.Uses64BitFramePtr ? X86::MOV64rr : X86::MOV32rr),
            operands);
        inst->setFlag(CgInstruction::FrameSetup);
      }
    }
  } else {
    NumBytes = StackSize - MF.getCalleeSavedFrameSize();
  }

  if (!IsFunclet) {
    if (HasFP && hasStackRealignment(*TRI, MF))
      MFI.setOffsetAdjustment(-NumBytes);
    else
      MFI.setOffsetAdjustment(-StackSize);
  }

  // Skip the callee-saved push instructions.

  while (MBBI != MBB.end() && MBBI->getFlag(CgInstruction::FrameSetup) &&
         (MBBI->getOpcode() == X86::PUSH32r ||
          MBBI->getOpcode() == X86::PUSH64r)) {
    ++MBBI;
  }

  // Realign stack after we pushed callee-saved registers (so that we'll be
  // able to calculate their offsets from the frame pointer).
  // Don't do this for Win64, it needs to realign the stack after the
  // prologue.
  if (!IsWin64Prologue && !IsFunclet && hasStackRealignment(*TRI, MF)) {
    assert(HasFP && "There should be a frame pointer if stack is realigned.");
    ZEN_ASSERT_TODO();
    // BuildStackAlignAND(MBB, MBBI, DL, TFI.StackPtr, MaxAlign);
  }

  NumBytes -= mergeSPUpdates(TFI, MBB, MBBI, true);
  // Adjust stack pointer: ESP -= numbytes.

  // Windows and cygwin/mingw require a prologue helper routine when
  // allocating more than 4K bytes on the stack.  Windows uses __chkstk and
  // cygwin/mingw uses __alloca.  __alloca and the 32-bit version of __chkstk
  // will probe the stack and adjust the stack pointer in one go.  The 64-bit
  // version of
  // __chkstk is only responsible for probing the stack.  The 64-bit prologue
  // is responsible for adjusting the stack pointer.  Touching the stack at 4K
  // increments is necessary to ensure that the guard pages used by the OS
  // virtual memory manager are allocated in correct sequence.
  uint64_t AlignedNumBytes = NumBytes;

  if (NumBytes) {
    emitSPUpdate(TFI, MBB, MBBI, DL, -(int64_t)NumBytes,
                 /*InEpilogue=*/false);
  }

  unsigned SPOrEstablisher = TFI.StackPtr;

  while (MBBI != MBB.end() && MBBI->getFlag(CgInstruction::FrameSetup)) {
    ++MBBI;
  }

  // We already dealt with stack realignment and funclets above.
  if (IsFunclet && STI.is32Bit())
    return;
  // If we need a base pointer, set it up here. It's whatever the value
  // of the stack pointer is at this point. Any variable size objects
  // will be allocated after this, so we can still use the base pointer
  // to reference locals.
  if (hasBasePointer(TRI, MF)) {
    // Update the base pointer with the current stack pointer.
    unsigned Opc = TFI.Uses64BitFramePtr ? X86::MOV64rr : X86::MOV32rr;
    SmallVector<CgOperand, 2> operands{
        CgOperand::createRegOperand(BasePtr, CgOperand::Define),
        CgOperand::createRegOperand(SPOrEstablisher, CgOperand::Kill),
    };
    CgInstruction *inst =
        MF.createCgInstruction(MBB, MBBI, TFI.TII.get(Opc), operands);
    inst->setFlag(CgInstruction::FrameSetup);
  }
}

void X86LLVMWorkaround::emitEpilogue(const TargetFrameLowering &_TFI,
                                     CgFunction &MF, CgBasicBlock &MBB) const {
  auto &TFI = static_cast<const X86FrameLowering &>(_TFI);
  auto &STI = TFI.STI;
  auto *TRI = TFI.TRI;

  assert(&STI == &MF.getSubtarget<X86Subtarget>() &&
         "MF used frame lowering for wrong subtarget");
  // CgBasicBlock::iterator Terminator = MBB.getFirstTerminator();
  CgBasicBlock::iterator Terminator = MBB.back().getIterator();
  CgBasicBlock::iterator MBBI = Terminator;
  Register FramePtr = getFrameRegister(TRI, MF);
  // Register MachineFramePtr =
  //     Is64BitILP32 ? Register(getX86SubSuperRegister(FramePtr, 64)) :
  //     FramePtr;
  Register MachineFramePtr = FramePtr;

  ZEN_ASSERT(MBBI->isReturn());
  CgFrameInfo &MFI = MF.getFrameInfo();
  bool IsWin64Prologue = false;

  // Get the number of bytes to allocate from the FrameInfo.
  uint64_t StackSize = MFI.getStackSize();
  uint64_t MaxAlign = calculateMaxStackAlign(MF);
  unsigned CSSize = MF.getCalleeSavedFrameSize();
  unsigned TailCallArgReserveSize = 0;
  bool HasFP = hasFP(TFI, MF);

  uint64_t NumBytes = 0;

  bool NeedsDwarfCFI = false;

  if (HasFP) {
    // Calculate required stack adjustment.
    uint64_t FrameSize = StackSize - TFI.SlotSize;
    NumBytes = FrameSize - CSSize - TailCallArgReserveSize;

    // Callee-saved registers were pushed on stack before the stack was
    // realigned.
    if (hasStackRealignment(*TRI, MF) && !IsWin64Prologue)
      NumBytes = alignTo(FrameSize, MaxAlign);
  } else {
    NumBytes = StackSize - CSSize - TailCallArgReserveSize;
  }

  if (HasFP) {
    // Update RSP with the RBP.
    // SmallVector<CgOperand, 2> operands{
    //     CgOperand::createRegOperand(TFI.StackPtr, CgOperand::Define),
    //     CgOperand::createRegOperand(MachineFramePtr),
    // };
    // CgInstruction *inst = MF.createCgInstruction(
    //     MBB, MBBI,
    //     TFI.TII.get(TFI.Uses64BitFramePtr ? X86::MOV64rr : X86::MOV32rr),
    //     operands);
    // inst->setFlag(CgInstruction::FrameDestroy);

    // Pop RBP
    SmallVector<CgOperand, 1> operands = {
        CgOperand::createRegOperand(MachineFramePtr, CgOperand::Define),
    };
    auto *inst = MF.createCgInstruction(
        MBB, MBBI, TFI.TII.get(TFI.Is64Bit ? X86::POP64r : X86::POP32r),
        operands);
    inst->setFlag(CgInstruction::FrameDestroy);
  } else {
    NumBytes = StackSize - CSSize;
  }

  CgBasicBlock::iterator FirstCSPop = MBBI;
  // Skip the callee-saved pop instructions.
  while (MBBI != MBB.begin()) {
    CgBasicBlock::iterator PI = std::prev(MBBI);
    unsigned Opc = PI->getOpcode();

    if (!PI->isTerminator()) {
      if ((Opc != X86::POP32r || !PI->getFlag(CgInstruction::FrameDestroy)) &&
          (Opc != X86::POP64r || !PI->getFlag(CgInstruction::FrameDestroy)) &&
          (Opc != X86::BTR64ri8 || !PI->getFlag(CgInstruction::FrameDestroy)) &&
          (Opc != X86::ADD64ri8 || !PI->getFlag(CgInstruction::FrameDestroy)))
        break;
      FirstCSPop = PI;
    }

    --MBBI;
  }
  MBBI = FirstCSPop;

  // If there is an ADD32ri or SUB32ri of ESP immediately before this
  // instruction, merge the two instructions.
  if (NumBytes || MFI.hasVarSizedObjects())
    NumBytes += mergeSPUpdates(TFI, MBB, MBBI, true);

  DebugLoc DL;
  if (NumBytes) {
    emitSPUpdate(TFI, MBB, MBBI, DL, NumBytes, /*InEpilogue=*/true);
  }
}

int X86LLVMWorkaround::mergeSPUpdates(const X86FrameLowering &TFI,
                                      CgBasicBlock &MBB,
                                      CgBasicBlock::iterator &MBBI,
                                      bool doMergeWithPrevious) const {
  if ((doMergeWithPrevious && MBBI == MBB.begin()) ||
      (!doMergeWithPrevious && MBBI == MBB.end()))
    return 0;

  auto PI = doMergeWithPrevious ? std::prev(MBBI) : MBBI;

  // PI = skipDebugInstructionsBackward(PI, MBB.begin());
  // It is assumed that ADD/SUB/LEA instruction is succeeded by one CFI
  // instruction, and that there are no DBG_VALUE or other instructions
  // between ADD/SUB/LEA and its corresponding CFI instruction.
  /* TODO: Add support for the case where there are multiple CFI instructions
    below the ADD/SUB/LEA, e.g.:
    ...
    add
    cfi_def_cfa_offset
    cfi_offset
    ...
  */
  if (doMergeWithPrevious && PI != MBB.begin() && PI->isCFIInstruction())
    PI = std::prev(PI);

  unsigned Opc = PI->getOpcode();
  int Offset = 0;

  if ((Opc == X86::ADD64ri32 || Opc == X86::ADD64ri8 || Opc == X86::ADD32ri ||
       Opc == X86::ADD32ri8) &&
      PI->getOperand(0).getReg() == TFI.StackPtr) {
    assert(PI->getOperand(1).getReg() == TFI.StackPtr);
    Offset = PI->getOperand(2).getImm();
  } else if ((Opc == X86::LEA32r || Opc == X86::LEA64_32r) &&
             PI->getOperand(0).getReg() == TFI.StackPtr &&
             PI->getOperand(1).getReg() == TFI.StackPtr &&
             PI->getOperand(2).getImm() == 1 &&
             PI->getOperand(3).getReg() == X86::NoRegister &&
             PI->getOperand(5).getReg() == X86::NoRegister) {
    // For LEAs we have: def = lea SP, FI, noreg, Offset, noreg.
    Offset = PI->getOperand(4).getImm();
  } else if ((Opc == X86::SUB64ri32 || Opc == X86::SUB64ri8 ||
              Opc == X86::SUB32ri || Opc == X86::SUB32ri8) &&
             PI->getOperand(0).getReg() == TFI.StackPtr) {
    assert(PI->getOperand(1).getReg() == TFI.StackPtr);
    Offset = -PI->getOperand(2).getImm();
  } else
    return 0;

  PI = MBB.erase(PI);
  // if (PI != MBB.end() && PI->isCFIInstruction()) {
  //   auto CIs = MBB.getParent()->getFrameInstructions();
  //   MCCFIInstruction CI = CIs[PI->getOperand(0).getCFIIndex()];
  //   if (CI.getOperation() == MCCFIInstruction::OpDefCfaOffset ||
  //       CI.getOperation() == MCCFIInstruction::OpAdjustCfaOffset)
  //     PI = MBB.erase(PI);
  // }
  if (!doMergeWithPrevious)
    MBBI = skipDebugInstructionsForward(PI, MBB.end());

  return Offset;
}

void X86LLVMWorkaround::emitSPUpdate(const X86FrameLowering &TFI,
                                     CgBasicBlock &MBB,
                                     CgBasicBlock::iterator &MBBI,
                                     const DebugLoc &DL, int64_t NumBytes,
                                     bool InEpilogue) const {
#if 0
  bool isSub = NumBytes < 0;
  uint64_t Offset = isSub ? -NumBytes : NumBytes;
  CgInstruction::MIFlag Flag =
      isSub ? CgInstruction::FrameSetup : CgInstruction::FrameDestroy;

  uint64_t Chunk = (1LL << 31) - 1;

  CgFunction &MF = *MBB.getParent();
  const X86Subtarget &STI = MF.getSubtarget<X86Subtarget>();
  const X86TargetLowering &TLI = *STI.getTargetLowering();
  const bool EmitInlineStackProbe = TLI.hasInlineStackProbe(MF);

  // It's ok to not take into account large chunks when probing, as the
  // allocation is split in smaller chunks anyway.
  if (EmitInlineStackProbe && !InEpilogue) {

    // This pseudo-instruction is going to be expanded, potentially using a
    // loop, by inlineStackProbe().
    BuildMI(MBB, MBBI, DL, TII.get(X86::STACKALLOC_W_PROBING)).addImm(Offset);
    return;
  } else if (Offset > Chunk) {
    // Rather than emit a long series of instructions for large offsets,
    // load the offset into a register and do one sub/add
    unsigned Reg = 0;
    unsigned Rax = (unsigned)(Is64Bit ? X86::RAX : X86::EAX);

    if (isSub && !isEAXLiveIn(MBB))
      Reg = Rax;
    else
      Reg = TRI->findDeadCallerSavedReg(MBB, MBBI);

    unsigned AddSubRROpc =
        isSub ? getSUBrrOpcode(Is64Bit) : getADDrrOpcode(Is64Bit);
    if (Reg) {
      BuildMI(MBB, MBBI, DL, TII.get(getMOVriOpcode(Is64Bit, Offset)), Reg)
          .addImm(Offset)
          .setMIFlag(Flag);
      CgInstruction *MI = BuildMI(MBB, MBBI, DL, TII.get(AddSubRROpc), StackPtr)
                             .addReg(StackPtr)
                             .addReg(Reg);
      MI->getOperand(3).setIsDead(); // The EFLAGS implicit def is dead.
      return;
    } else if (Offset > 8 * Chunk) {
      // If we would need more than 8 add or sub instructions (a >16GB stack
      // frame), it's worth spilling RAX to materialize this immediate.
      //   pushq %rax
      //   movabsq +-$Offset+-SlotSize, %rax
      //   addq %rsp, %rax
      //   xchg %rax, (%rsp)
      //   movq (%rsp), %rsp
      assert(Is64Bit && "can't have 32-bit 16GB stack frame");
      BuildMI(MBB, MBBI, DL, TII.get(X86::PUSH64r))
          .addReg(Rax, RegState::Kill)
          .setMIFlag(Flag);
      // Subtract is not commutative, so negate the offset and always use add.
      // Subtract 8 less and add 8 more to account for the PUSH we just did.
      if (isSub)
        Offset = -(Offset - SlotSize);
      else
        Offset = Offset + SlotSize;
      BuildMI(MBB, MBBI, DL, TII.get(getMOVriOpcode(Is64Bit, Offset)), Rax)
          .addImm(Offset)
          .setMIFlag(Flag);
      CgInstruction *MI = BuildMI(MBB, MBBI, DL, TII.get(X86::ADD64rr), Rax)
                             .addReg(Rax)
                             .addReg(StackPtr);
      MI->getOperand(3).setIsDead(); // The EFLAGS implicit def is dead.
      // Exchange the new SP in RAX with the top of the stack.
      addRegOffset(
          BuildMI(MBB, MBBI, DL, TII.get(X86::XCHG64rm), Rax).addReg(Rax),
          StackPtr, false, 0);
      // Load new SP from the top of the stack into RSP.
      addRegOffset(BuildMI(MBB, MBBI, DL, TII.get(X86::MOV64rm), StackPtr),
                   StackPtr, false, 0);
      return;
    }
  }
#endif
  bool Is64Bit = TFI.Is64Bit;
  CgFunction *MF = MBB.getParent();
  const X86InstrInfo &TII = TFI.TII;
  const X86RegisterInfo *TRI = TFI.TRI;

  bool isSub = NumBytes < 0;
  uint64_t Offset = isSub ? -NumBytes : NumBytes;
  uint64_t Chunk = (1LL << 31) - 1;
  CgInstruction::MIFlag Flag =
      isSub ? CgInstruction::FrameSetup : CgInstruction::FrameDestroy;
  while (Offset) {
    uint64_t ThisVal = std::min(Offset, Chunk);
    if (ThisVal == TFI.SlotSize) {

      // Use push / pop for slot sized adjustments as a size optimization.
      // We need to find a dead register when using pop.
      unsigned Reg = isSub ? (unsigned)(Is64Bit ? X86::RAX : X86::EAX)
                           : findDeadCallerSavedReg(TRI, MBB, MBBI);
      // TODO
      if (Reg) {
        unsigned Opc = isSub ? (Is64Bit ? X86::PUSH64r : X86::PUSH32r)
                             : (Is64Bit ? X86::POP64r : X86::POP32r);
        // BuildMI(MBB, MBBI, DL, TII.get(Opc))
        //     .addReg(Reg,
        //             getDefRegState(!isSub) | getUndefRegState(isSub))
        //     .setMIFlag(Flag);
        SmallVector<CgOperand, 1> Operands{
            CgOperand::createRegOperand(Reg, !isSub)};
        auto *inst =
            MF->createCgInstruction(MBB, MBBI, TII.get(Opc), Operands, false);
        inst->setFlag(Flag);

        Offset -= ThisVal;
        continue;
      }
    }

    BuildStackAdjustment(TFI, MBB, MBBI, DL, isSub ? -ThisVal : ThisVal,
                         InEpilogue);
    //.setFlag(Flag);

    Offset -= ThisVal;
  }
}

void X86LLVMWorkaround::determineCalleeSaves(const TargetFrameLowering *TFI,
                                             CgFunction &MF,
                                             BitVector &SavedRegs,
                                             RegScavenger *RS) const {
  LLVMWorkaround::determineCalleeSaves(TFI, MF, SavedRegs, RS);

#if 0
  // Spill the BasePtr if it's used.
  if (TRI->hasBasePointer(MF)){
    Register BasePtr = TRI->getBaseRegister();
    if (STI.isTarget64BitILP32())
      BasePtr = getX86SubSuperRegister(BasePtr, 64);
    SavedRegs.set(BasePtr);
  }
#endif
}

bool X86LLVMWorkaround::assignCalleeSavedSpillSlots(
    const TargetFrameLowering *TFI, CgFunction &MF,
    const TargetRegisterInfo *TRI, std::vector<CalleeSavedInfo> &CSI) const {
  const X86FrameLowering *X86TFI = static_cast<const X86FrameLowering *>(TFI);
  const X86Subtarget &STI = X86TFI->STI;

  CgFrameInfo &MFI = MF.getFrameInfo();

  unsigned CalleeSavedFrameSize = 0;
  unsigned XMMCalleeSavedFrameSize = 0;
  int SpillSlotOffset = TFI->getOffsetOfLocalArea();

  // Spill the BasePtr if it's used.
  if (hasFP(*TFI, MF)) {
    // emitPrologue always spills frame register the first thing.
    SpillSlotOffset -= X86TFI->SlotSize;
    MFI.CreateFixedSpillStackObject(X86TFI->SlotSize, SpillSlotOffset);

    // Since emitPrologue and emitEpilogue will handle spilling and
    // restoring of the frame register, we can delete it from CSI list and
    // not have to worry about avoiding it later.
    Register FPReg = getFrameRegister(TRI, MF);
    for (unsigned i = 0; i < CSI.size(); ++i) {
      if (TRI->regsOverlap(CSI[i].getReg(), FPReg)) {
        CSI.erase(CSI.begin() + i);
        break;
      }
    }
  }

  // Assign slots for GPRs. It increases frame size.
  for (CalleeSavedInfo &I : llvm::reverse(CSI)) {
    Register Reg = I.getReg();

    if (!X86::GR64RegClass.contains(Reg) && !X86::GR32RegClass.contains(Reg))
      continue;

    SpillSlotOffset -= X86TFI->SlotSize;
    CalleeSavedFrameSize += X86TFI->SlotSize;

    int CgSlotIndex =
        MFI.CreateFixedSpillStackObject(X86TFI->SlotSize, SpillSlotOffset);
    I.setFrameIdx(CgSlotIndex);
  }

  MF.setCalleeSavedFrameSize(CalleeSavedFrameSize);
  MFI.setCVBytesOfCalleeSavedRegisters(CalleeSavedFrameSize);

  // Assign slots for XMMs.
  for (CalleeSavedInfo &I : llvm::reverse(CSI)) {
    Register Reg = I.getReg();
    if (X86::GR64RegClass.contains(Reg) || X86::GR32RegClass.contains(Reg))
      continue;

    // If this is k-register make sure we lookup via the largest legal type.
    MVT VT = MVT::Other;
    if (X86::VK16RegClass.contains(Reg))
      VT = STI.hasBWI() ? MVT::v64i1 : MVT::v16i1;

    const TargetRegisterClass *RC = TRI->getMinimalPhysRegClass(Reg, VT);
    unsigned Size = TRI->getSpillSize(*RC);
    Align Alignment = TRI->getSpillAlign(*RC);
    // ensure alignment
    assert(SpillSlotOffset < 0 && "SpillSlotOffset should always < 0 on X86");
    SpillSlotOffset = -alignTo(-SpillSlotOffset, Alignment);

    // spill into slot
    SpillSlotOffset -= Size;
    int CgSlotIndex = MFI.CreateFixedSpillStackObject(Size, SpillSlotOffset);
    I.setFrameIdx(CgSlotIndex);
    MFI.ensureMaxAlignment(Alignment);

    // Save the start offset and size of XMM in stack frame for funclets.
    if (X86::VR128RegClass.contains(Reg)) {
      XMMCalleeSavedFrameSize += Size;
    }
  }

  return true;
}

bool X86LLVMWorkaround::spillCalleeSavedRegisters(
    const TargetFrameLowering *TFI, CgBasicBlock &MBB,
    CgBasicBlock::iterator MI, ArrayRef<CalleeSavedInfo> CSI,
    const TargetRegisterInfo *TRI) const {
  const X86FrameLowering *X86TFI = static_cast<const X86FrameLowering *>(TFI);
  const X86Subtarget &STI = X86TFI->STI;
  const X86InstrInfo &TII = X86TFI->TII;
  CgFunction &MF = *MBB.getParent();

  unsigned Opc = STI.is64Bit() ? X86::PUSH64r : X86::PUSH32r;
  for (const CalleeSavedInfo &I : llvm::reverse(CSI)) {
    Register Reg = I.getReg();

    if (!X86::GR64RegClass.contains(Reg) && !X86::GR32RegClass.contains(Reg))
      continue;

    const CgRegisterInfo &MRI = MF.getRegInfo();
    bool isLiveIn = MRI.isLiveIn(Reg);
    if (!isLiveIn)
      MBB.addLiveIn(Reg);

    // Decide whether we can add a kill flag to the use.
    bool CanKill = !isLiveIn;
    // Check if any subregister is live-in
    if (CanKill) {
      for (MCRegAliasIterator AReg(Reg, TRI, false); AReg.isValid(); ++AReg) {
        if (MRI.isLiveIn(*AReg)) {
          CanKill = false;
          break;
        }
      }
    }

    // Do not set a kill flag on values that are also marked as live-in.
    // This happens with the @llvm-returnaddress intrinsic and with
    // arguments passed in callee saved registers. Omitting the kill flags
    // is conservatively correct even if the live-in is not used after all.
    SmallVector<CgOperand, 1> operands{
        CgOperand::createRegOperand(Reg, CanKill ? CgOperand::Kill
                                                 : CgOperand::None),
    };
    CgInstruction *inst =
        MF.createCgInstruction(MBB, MI, TII.get(Opc), operands);
    inst->setFlag(CgInstruction::FrameSetup);
  }

  // Make XMM regs spilled. X86 does not have ability of push/pop XMM.
  // It can be done by spilling XMMs to stack frame.
  for (const CalleeSavedInfo &I : llvm::reverse(CSI)) {
    Register Reg = I.getReg();
    if (X86::GR64RegClass.contains(Reg) || X86::GR32RegClass.contains(Reg))
      continue;

    // If this is k-register make sure we lookup via the largest legal type.
    MVT VT = MVT::Other;
    if (X86::VK16RegClass.contains(Reg))
      VT = STI.hasBWI() ? MVT::v64i1 : MVT::v16i1;

    // Add the callee-saved register as live-in. It's killed at the spill.
    MBB.addLiveIn(Reg);
    const TargetRegisterClass *RC = TRI->getMinimalPhysRegClass(Reg, VT);

    storeRegToStackSlot(TII, MBB, MI, Reg, true, I.getFrameIdx(), RC, TRI);
    --MI;
    MI->setFlag(CgInstruction::FrameSetup);
    ++MI;
  }

  return true;
}

bool X86LLVMWorkaround::restoreCalleeSavedRegisters(
    const TargetFrameLowering *TFI, CgBasicBlock &MBB,
    CgBasicBlock::iterator MI, MutableArrayRef<CalleeSavedInfo> CSI,
    const TargetRegisterInfo *TRI) const {
  if (CSI.empty()) {
    return false;
  }

  const X86FrameLowering *X86TFI = static_cast<const X86FrameLowering *>(TFI);
  const X86Subtarget &STI = X86TFI->STI;
  const X86InstrInfo &TII = X86TFI->TII;
  CgFunction &MF = *MBB.getParent();

  // Reload XMMs from stack frame.
  for (const CalleeSavedInfo &I : CSI) {
    Register Reg = I.getReg();
    if (X86::GR64RegClass.contains(Reg) || X86::GR32RegClass.contains(Reg))
      continue;

    // If this is k-register make sure we lookup via the largest legal type.
    MVT VT = MVT::Other;
    if (X86::VK16RegClass.contains(Reg))
      VT = STI.hasBWI() ? MVT::v64i1 : MVT::v16i1;

    const TargetRegisterClass *RC = TRI->getMinimalPhysRegClass(Reg, VT);
    loadRegFromStackSlot(TII, MBB, MI, Reg, I.getFrameIdx(), RC, TRI);
  }

  // POP GPRs.
  unsigned Opc = STI.is64Bit() ? X86::POP64r : X86::POP32r;
  for (const CalleeSavedInfo &I : CSI) {
    Register Reg = I.getReg();
    if (!X86::GR64RegClass.contains(Reg) && !X86::GR32RegClass.contains(Reg))
      continue;

    SmallVector<CgOperand, 1> operands{CgOperand::createRegOperand(Reg, false)};
    CgInstruction *inst =
        MF.createCgInstruction(MBB, MI, TII.get(Opc), operands);
    inst->setFlag(CgInstruction::FrameDestroy);
  }
  return true;
}

bool X86LLVMWorkaround::hasFP(const TargetFrameLowering &_TFI,
                              const CgFunction &MF) const {
  const auto *TFI = static_cast<const X86FrameLowering *>(&_TFI);
  const auto &MFI = MF.getFrameInfo();
  auto *TRI = TFI->TRI;
#if 0
  return (MF.getTarget().Options.DisableFramePointerElim(MF) ||
          TRI->hasStackRealignment(MF) || MFI.hasVarSizedObjects() ||
          MFI.isFrameAddressTaken() || MFI.hasOpaqueSPAdjustment() ||
          MF.getInfo<X86MachineFunctionInfo>()->getForceFramePointer() ||
          MF.getInfo<X86MachineFunctionInfo>()->hasPreallocatedCall() ||
          MF.callsUnwindInit() || MF.hasEHFunclets() || MF.callsEHReturn() ||
          MFI.hasStackMap() || MFI.hasPatchPoint() ||
          (isWin64Prologue(MF) && MFI.hasCopyImplyingStackAdjustment()));
#endif
  return hasStackRealignment(*TRI, MF) || MFI.hasVarSizedObjects() ||
         MFI.isFrameAddressTaken() || MFI.hasOpaqueSPAdjustment() || true;
}

bool X86LLVMWorkaround::hasReservedCallFrame(const TargetFrameLowering &TFI,
                                             const CgFunction &MF) const {
#if 0
      return !MF.getFrameInfo().hasVarSizedObjects() &&
         !MF.getInfo<X86MachineFunctionInfo>()->getHasPushSequences() &&
         !MF.getInfo<X86MachineFunctionInfo>()->hasPreallocatedCall();
#endif
  return !MF.getFrameInfo().hasVarSizedObjects();
}

bool X86LLVMWorkaround::needsFrameIndexResolution(
    const TargetFrameLowering &_TFI, const CgFunction &MF) const {
  auto &TFI = static_cast<const X86FrameLowering &>(_TFI);
  // TODO:
  // return MF.getFrameInfo().hasStackObjects() ||
  //      MF.getInfo<X86CgFunctionInfo>()->getHasPushSequences();
  return MF.getFrameInfo().hasStackObjects();
}

StackOffset
X86LLVMWorkaround::getFrameIndexReference(const TargetFrameLowering *_TFI,
                                          const CgFunction &MF, int FI,
                                          Register &FrameReg) const {
  const auto *TFI = static_cast<const X86FrameLowering *>(_TFI);

  const auto &MFI = MF.getFrameInfo();
  auto *TRI = TFI->TRI;

  bool IsFixed = MFI.isFixedObjectIndex(FI);
  // We can't calculate offset from frame pointer if the stack is realigned,
  // so enforce usage of stack/base pointer.  The base pointer is used when we
  // have dynamic allocas in addition to dynamic realignment.
  if (hasBasePointer(TRI, MF))
    FrameReg = IsFixed ? TRI->getFramePtr() : TRI->getBaseRegister();
  else if (hasStackRealignment(*TRI, MF))
    FrameReg = IsFixed ? TRI->getFramePtr() : TRI->getStackRegister();
  else
    FrameReg = getFrameRegister(TRI, MF);

  // Offset will hold the offset from the stack pointer at function entry to
  // the object. We need to factor in additional offsets applied during the
  // prologue to the frame, base, and stack pointer depending on which is
  // used.
  int Offset = MFI.getObjectOffset(FI) - TFI->getOffsetOfLocalArea();

  uint64_t StackSize = MFI.getStackSize();

#if 0
  const X86MachineFunctionInfo *X86FI = MF.getInfo<X86MachineFunctionInfo>();
  unsigned CSSize = MF.getCalleeSavedFrameSize();
  uint64_t StackSize = MFI.getStackSize();
  bool IsWin64Prologue = MF.getTarget().getMCAsmInfo()->usesWindowsCFI();
  int64_t FPDelta = 0;
    assert(!MFI.hasCalls() || (StackSize % 16) == 8);

    // Calculate required stack adjustment.
    uint64_t FrameSize = StackSize - SlotSize;
    // If required, include space for extra hidden slot for stashing base pointer.
    if (X86FI->getRestoreBasePointer())
      FrameSize += SlotSize;
    uint64_t NumBytes = FrameSize - CSSize;

    uint64_t SEHFrameOffset = calculateSetFPREG(NumBytes);
    if (FI && FI == X86FI->getFAIndex())
      return StackOffset::getFixed(-SEHFrameOffset);

    // FPDelta is the offset from the "traditional" FP location of the old base
    // pointer followed by return address and the location required by the
    // restricted Win64 prologue.
    // Add FPDelta to all offsets below that go through the frame pointer.
    FPDelta = FrameSize - SEHFrameOffset;
    assert((!MFI.hasCalls() || (FPDelta % 16) == 0) &&
           "FPDelta isn't aligned per the Win64 ABI!");
  }
#endif
  if (FrameReg == TRI->getFramePtr()) {
    // Skip saved EBP/RBP
    Offset += TFI->SlotSize;

    // Account for restricted Windows prologue.
    // Offset += FPDelta;

    // Skip the RETADDR move area
    // int TailCallReturnAddrDelta = X86FI->getTCReturnAddrDelta();
    // if (TailCallReturnAddrDelta < 0)
    //   Offset -= TailCallReturnAddrDelta;

    return StackOffset::getFixed(Offset);
  }

  // FrameReg is either the stack pointer or a base pointer. But the base is
  // located at the end of the statically known StackSize so the distinction
  // doesn't really matter.
  if (hasStackRealignment(*TRI, MF) || hasBasePointer(TRI, MF))
    assert(isAligned(MFI.getObjectAlign(FI), -(Offset + StackSize)));
  return StackOffset::getFixed(Offset + StackSize);
}

StackOffset X86LLVMWorkaround::getFrameIndexReferenceSP(
    const X86FrameLowering *TFI, const CgFunction &MF, int FI, Register &SPReg,
    int Adjustment) const {

  const auto &MFI = MF.getFrameInfo();
  auto *TRI = TFI->TRI;

  SPReg = TRI->getStackRegister();
  return StackOffset::getFixed(MFI.getObjectOffset(FI) -
                               TFI->getOffsetOfLocalArea() + Adjustment);
}

static unsigned getSUBriOpcode(bool IsLP64, int64_t Imm) {
  if (IsLP64) {
    if (isInt<8>(Imm))
      return X86::SUB64ri8;
    return X86::SUB64ri32;
  } else {
    if (isInt<8>(Imm))
      return X86::SUB32ri8;
    return X86::SUB32ri;
  }
}

static unsigned getADDriOpcode(bool IsLP64, int64_t Imm) {
  if (IsLP64) {
    if (isInt<8>(Imm))
      return X86::ADD64ri8;
    return X86::ADD64ri32;
  } else {
    if (isInt<8>(Imm))
      return X86::ADD32ri8;
    return X86::ADD32ri;
  }
}

CgInstruction *X86LLVMWorkaround::BuildStackAdjustment(
    const X86FrameLowering &TFI, CgBasicBlock &MBB, CgBasicBlock::iterator MBBI,
    const DebugLoc &DL, int64_t Offset, bool InEpilogue) const {
#if 0
  assert(Offset != 0 && "zero offset stack adjustment requested");

  // On Atom, using LEA to adjust SP is preferred, but using it in the epilogue
  // is tricky.
  bool UseLEA;
  if (!InEpilogue) {
    // Check if inserting the prologue at the beginning
    // of MBB would require to use LEA operations.
    // We need to use LEA operations if EFLAGS is live in, because
    // it means an instruction will read it before it gets defined.
    UseLEA = STI.useLeaForSP() || MBB.isLiveIn(X86::EFLAGS);
  } else {
    // If we can use LEA for SP but we shouldn't, check that none
    // of the terminators uses the eflags. Otherwise we will insert
    // a ADD that will redefine the eflags and break the condition.
    // Alternatively, we could move the ADD, but this may not be possible
    // and is an optimization anyway.
    UseLEA = canUseLEAForSPInEpilogue(*MBB.getParent());
    if (UseLEA && !STI.useLeaForSP())
      UseLEA = flagsNeedToBePreservedBeforeTheTerminators(MBB);
    // If that assert breaks, that means we do not do the right thing
    // in canUseAsEpilogue.
    assert((UseLEA || !flagsNeedToBePreservedBeforeTheTerminators(MBB)) &&
           "We shouldn't have allowed this insertion point");
  }

  MachineInstrBuilder MI;
#endif
  // TODO
  bool UseLEA = false;
  CgInstruction *MI = nullptr;
  if (UseLEA) {
    // MI = addRegOffset(BuildMI(MBB, MBBI, DL,
    //                           TII.get(getLEArOpcode(Uses64BitFramePtr)),
    //                           StackPtr),
    //                   StackPtr, false, Offset);
  } else {
    bool IsSub = Offset < 0;
    uint64_t AbsOffset = IsSub ? -Offset : Offset;
    const unsigned Opc = IsSub
                             ? getSUBriOpcode(TFI.Uses64BitFramePtr, AbsOffset)
                             : getADDriOpcode(TFI.Uses64BitFramePtr, AbsOffset);
    std::array<CgOperand, 3> opnds = {
        CgOperand::createRegOperand(TFI.StackPtr, false),
        CgOperand::createRegOperand(TFI.StackPtr, false),
        CgOperand::createImmOperand(AbsOffset)};
    MI = MBB.getParent()->createCgInstruction(MBB, MBBI, TFI.TII.get(Opc),
                                              opnds);
    // MI = BuildMI(MBB, MBBI, DL, TFI.TII.get(Opc), TFI.StackPtr)
    //          .addReg(StackPtr)
    //          .addImm(AbsOffset);
    // MI->getOperand(3).setIsDead(); // The EFLAGS implicit def is dead.
  }
  return MI;
}

//===----------------------------------------------------------------------===//
//
// LLVMTargetMachine
//
//===----------------------------------------------------------------------===//

X86Subtarget *
X86LLVMWorkaround::getSubtargetImpl(const LLVMTargetMachine &TM,
                                    CompileMemPool &MemPool) const {
  const auto &X86TM = static_cast<const llvm::X86TargetMachine &>(TM);

  auto &TargetTriple = X86TM.getTargetTriple();
  StringRef CPU = X86TM.getTargetCPU();
  StringRef TuneCPU = CPU == "x86-64" ? "generic" : CPU;
  StringRef FS = X86TM.getTargetFeatureString();
  auto StackAlignmentOverride = 0;
  auto PreferVectorWidthOverride = 0;
  auto RequiredVectorWidth = UINT32_MAX;

  llvm::SmallString<512> Key;

  Key += CPU;
  Key += TuneCPU;
  Key += FS;

  return MemPool.newObject<X86Subtarget>(
      TargetTriple, CPU, TuneCPU, FS, X86TM,
      llvm::MaybeAlign(StackAlignmentOverride), PreferVectorWidthOverride,
      RequiredVectorWidth);
}
