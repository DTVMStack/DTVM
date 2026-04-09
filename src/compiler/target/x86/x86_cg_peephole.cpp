// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/target/x86/x86_cg_peephole.h"
#include "compiler/cgir/pass/cg_register_info.h"
#include "compiler/llvm-prebuild/Target/X86/X86Subtarget.h"
#include "compiler/target/x86/x86_constants.h"
#include <algorithm>
#include <iterator>
#include <vector>

using namespace llvm;

namespace COMPILER {
namespace {

constexpr unsigned InvalidOpcode = 0;
constexpr size_t MaxCmpFoldFunctionBlocks = 10000;

bool isTestOpcode(unsigned Opcode) {
  switch (Opcode) {
  case X86::TEST8rr:
  case X86::TEST16rr:
  case X86::TEST32rr:
  case X86::TEST64rr:
    return true;
  default:
    return false;
  }
}

bool isSelfTest(const CgInstruction &Inst, CgRegister Reg) {
  if (!isTestOpcode(Inst.getOpcode())) {
    return false;
  }

  const auto &LHS = Inst.getOperand(0);
  const auto &RHS = Inst.getOperand(1);
  return LHS.isReg() && RHS.isReg() && LHS.getReg() == Reg &&
         RHS.getReg() == Reg;
}

X86::CondCode getOppositeCond(X86::CondCode CC) {
  switch (CC) {
  case X86::COND_O:
    return X86::COND_NO;
  case X86::COND_NO:
    return X86::COND_O;
  case X86::COND_B:
    return X86::COND_AE;
  case X86::COND_AE:
    return X86::COND_B;
  case X86::COND_E:
    return X86::COND_NE;
  case X86::COND_NE:
    return X86::COND_E;
  case X86::COND_BE:
    return X86::COND_A;
  case X86::COND_A:
    return X86::COND_BE;
  case X86::COND_S:
    return X86::COND_NS;
  case X86::COND_NS:
    return X86::COND_S;
  case X86::COND_P:
    return X86::COND_NP;
  case X86::COND_NP:
    return X86::COND_P;
  case X86::COND_L:
    return X86::COND_GE;
  case X86::COND_GE:
    return X86::COND_L;
  case X86::COND_LE:
    return X86::COND_G;
  case X86::COND_G:
    return X86::COND_LE;
  default:
    return X86::COND_INVALID;
  }
}

bool getFoldedBranchCond(int64_t BranchCond, int64_t SetCond,
                         int64_t &NewCond) {
  if (BranchCond == X86::COND_NE) {
    NewCond = SetCond;
    return true;
  }
  if (BranchCond != X86::COND_E) {
    return false;
  }

  X86::CondCode Opposite = getOppositeCond(static_cast<X86::CondCode>(SetCond));
  if (Opposite == X86::COND_INVALID) {
    return false;
  }

  NewCond = Opposite;
  return true;
}

bool isImmMoveValue(const CgInstruction &Inst, int64_t Value) {
  switch (Inst.getOpcode()) {
  case X86::MOV8ri:
  case X86::MOV16ri:
  case X86::MOV32ri:
  case X86::MOV32ri64:
  case X86::MOV64ri32:
  case X86::MOV64ri:
    break;
  default:
    return false;
  }

  return Inst.getNumOperands() >= 2 && Inst.getOperand(1).isImm() &&
         Inst.getOperand(1).getImm() == Value;
}

bool getImmMoveDstReg(const CgInstruction &Inst, int64_t Value,
                      CgRegister &DstReg) {
  if (!isImmMoveValue(Inst, Value) || Inst.getNumOperands() < 1 ||
      !Inst.getOperand(0).isReg()) {
    return false;
  }

  DstReg = Inst.getOperand(0).getReg();
  return true;
}

unsigned getAdcImmOpcode(unsigned Opcode) {
  switch (Opcode) {
  case X86::ADC8rr:
    return X86::ADC8ri;
  case X86::ADC16rr:
    return X86::ADC16ri;
  case X86::ADC32rr:
    return X86::ADC32ri;
  case X86::ADC64rr:
    return X86::ADC64ri32;
  default:
    return InvalidOpcode;
  }
}

bool isAddRegOpcode(unsigned Opcode) {
  switch (Opcode) {
  case X86::ADD8rr:
  case X86::ADD16rr:
  case X86::ADD32rr:
  case X86::ADD64rr:
    return true;
  default:
    return false;
  }
}

bool isSelfImmZeroLogic(const CgInstruction &Inst, CgRegister Reg) {
  if (Inst.getNumOperands() < 3 || !Inst.getOperand(0).isReg() ||
      !Inst.getOperand(1).isReg() || !Inst.getOperand(2).isImm() ||
      Inst.getOperand(0).getReg() != Reg ||
      Inst.getOperand(1).getReg() != Reg || Inst.getOperand(2).getImm() != 0) {
    return false;
  }

  switch (Inst.getOpcode()) {
  case X86::OR8ri:
  case X86::OR16ri8:
  case X86::OR16ri:
  case X86::OR32ri8:
  case X86::OR32ri:
  case X86::OR64ri8:
  case X86::OR64ri32:
  case X86::AND8ri:
  case X86::AND16ri8:
  case X86::AND16ri:
  case X86::AND32ri8:
  case X86::AND32ri:
  case X86::AND64ri8:
  case X86::AND64ri32:
    return true;
  default:
    return false;
  }
}

bool isSelfAndZeroImm(const CgInstruction &Inst, CgRegister Reg) {
  if (!isSelfImmZeroLogic(Inst, Reg)) {
    return false;
  }

  switch (Inst.getOpcode()) {
  case X86::AND8ri:
  case X86::AND16ri8:
  case X86::AND16ri:
  case X86::AND32ri8:
  case X86::AND32ri:
  case X86::AND64ri8:
  case X86::AND64ri32:
    return true;
  default:
    return false;
  }
}

bool isNoOpImmOpcode(unsigned Opcode) {
  switch (Opcode) {
  case X86::ADD64ri8:
  case X86::OR64ri8:
  case X86::OR64ri32:
    return true;
  default:
    return false;
  }
}

bool isZeroLogicChainOpcode(const CgInstruction &Inst, CgRegister Reg) {
  switch (Inst.getOpcode()) {
  case X86::OR64ri8:
  case X86::OR64ri32:
  case X86::AND64ri8:
  case X86::AND64ri32:
    break;
  default:
    return false;
  }

  if (Inst.getNumOperands() < 3 || !Inst.getOperand(0).isReg() ||
      !Inst.getOperand(1).isReg() || !Inst.getOperand(2).isImm()) {
    return false;
  }

  return Inst.getOperand(0).getReg() == Reg &&
         Inst.getOperand(1).getReg() == Reg;
}

bool areFlagsDeadAfter(CgBasicBlock &MBB, CgBasicBlock::iterator MII) {
  auto LocalMII = MII;
  ++LocalMII;
  for (; LocalMII != MBB.end(); ++LocalMII) {
    auto &Inst = *LocalMII;
    if (Inst.readsRegister(X86::EFLAGS)) {
      return false;
    }
    if (Inst.modifiesRegister(X86::EFLAGS)) {
      return true;
    }
  }

  return false;
}

bool isFullCopyFromReg(const CgInstruction &Inst, CgRegister SrcReg,
                       CgRegister &DstReg) {
  if (!Inst.isFullCopy() || Inst.getNumOperands() < 2 ||
      !Inst.getOperand(0).isReg() || !Inst.getOperand(1).isReg() ||
      Inst.getOperand(1).getReg() != SrcReg) {
    return false;
  }

  DstReg = Inst.getOperand(0).getReg();
  return true;
}

bool isFullCopyToReg(const CgInstruction &Inst, CgRegister DstReg,
                     CgRegister &SrcReg) {
  if (!Inst.isFullCopy() || Inst.getNumOperands() < 2 ||
      !Inst.getOperand(0).isReg() || !Inst.getOperand(1).isReg() ||
      Inst.getOperand(0).getReg() != DstReg) {
    return false;
  }

  SrcReg = Inst.getOperand(1).getReg();
  return true;
}

bool isZeroExtendCopyFromReg(const CgInstruction &Inst, CgRegister SrcReg,
                             CgRegister &DstReg) {
  switch (Inst.getOpcode()) {
  case X86::MOVZX32rr8:
  case X86::MOVZX32rr16:
  case X86::MOVZX64rr8:
  case X86::MOVZX64rr16:
    break;
  default:
    return false;
  }

  if (Inst.getNumOperands() < 2 || !Inst.getOperand(0).isReg() ||
      !Inst.getOperand(1).isReg() || Inst.getOperand(1).getReg() != SrcReg) {
    return false;
  }

  DstReg = Inst.getOperand(0).getReg();
  return true;
}

bool isZeroExtendCopyToReg(const CgInstruction &Inst, CgRegister DstReg,
                           CgRegister &SrcReg) {
  switch (Inst.getOpcode()) {
  case X86::MOVZX32rr8:
  case X86::MOVZX32rr16:
  case X86::MOVZX64rr8:
  case X86::MOVZX64rr16:
    break;
  default:
    return false;
  }

  if (Inst.getNumOperands() < 2 || !Inst.getOperand(0).isReg() ||
      !Inst.getOperand(1).isReg() || Inst.getOperand(0).getReg() != DstReg) {
    return false;
  }

  SrcReg = Inst.getOperand(1).getReg();
  return true;
}

bool getBoolOrOtherReg(const CgInstruction &Inst, CgRegister BoolReg,
                       CgRegister &DstReg, CgRegister &OtherReg) {
  switch (Inst.getOpcode()) {
  case X86::OR32rr:
  case X86::OR64rr:
    break;
  default:
    return false;
  }

  if (Inst.getNumOperands() < 3 || !Inst.getOperand(0).isReg() ||
      !Inst.getOperand(1).isReg() || !Inst.getOperand(2).isReg()) {
    return false;
  }

  const CgRegister LHS = Inst.getOperand(1).getReg();
  const CgRegister RHS = Inst.getOperand(2).getReg();
  if (LHS == BoolReg) {
    OtherReg = RHS;
  } else if (RHS == BoolReg) {
    OtherReg = LHS;
  } else {
    return false;
  }

  DstReg = Inst.getOperand(0).getReg();
  return true;
}

bool collectZeroDefChainBefore(CgBasicBlock &MBB,
                               CgBasicBlock::iterator StartMII,
                               CgRegister ZeroReg,
                               SmallVector<CgInstruction *, 4> &ZeroToErase) {
  CgRegister CurrentReg = ZeroReg;
  for (auto LocalMII = StartMII; LocalMII != MBB.begin();) {
    --LocalMII;
    auto &Inst = *LocalMII;
    if (!Inst.modifiesRegister(CurrentReg)) {
      continue;
    }

    CgRegister PrevReg = 0;
    CgRegister ZeroDstReg = 0;
    if (getImmMoveDstReg(Inst, 0, ZeroDstReg) && ZeroDstReg == CurrentReg) {
      ZeroToErase.push_back(&Inst);
      std::reverse(ZeroToErase.begin(), ZeroToErase.end());
      return true;
    }
    if (isSelfAndZeroImm(Inst, CurrentReg)) {
      ZeroToErase.push_back(&Inst);
      std::reverse(ZeroToErase.begin(), ZeroToErase.end());
      return true;
    }
    if (isSelfImmZeroLogic(Inst, CurrentReg)) {
      ZeroToErase.push_back(&Inst);
      continue;
    }
    if (isFullCopyToReg(Inst, CurrentReg, PrevReg) ||
        isZeroExtendCopyToReg(Inst, CurrentReg, PrevReg)) {
      ZeroToErase.push_back(&Inst);
      CurrentReg = PrevReg;
      continue;
    }

    return false;
  }

  return false;
}

CgOperand cloneRegOperand(const CgOperand &Operand) {
  ZEN_ASSERT(Operand.isReg());
  CgOperand NewOperand = CgOperand::createRegOperand(
      Operand.getReg(), Operand.isDef(), Operand.isImplicit(),
      Operand.isUse() && Operand.isKill(), Operand.isDef() && Operand.isDead(),
      Operand.isUndef());
  if (Operand.getSubReg() != 0) {
    NewOperand.setSubReg(Operand.getSubReg());
  }
  if (Operand.isInternalRead()) {
    NewOperand.setIsInternalRead();
  }
  if (Operand.isDef() && Operand.isEarlyClobber()) {
    NewOperand.setIsEarlyClobber();
  }
  if (CgRegister::isPhysicalRegister(Operand.getReg()) &&
      Operand.isRenamable()) {
    NewOperand.setIsRenamable();
  }
  return NewOperand;
}

CgInstruction *getImmMoveDef(CgRegister Reg, CgRegisterInfo &MRI,
                             int64_t ImmValue) {
  SmallVector<CgRegister, 4> Visited;
  while (Reg.isVirtual()) {
    if (std::find(Visited.begin(), Visited.end(), Reg) != Visited.end()) {
      return nullptr;
    }
    Visited.push_back(Reg);

    CgInstruction *Def = MRI.getUniqueVRegDef(Reg);
    if (Def == nullptr) {
      return nullptr;
    }
    if (Def->isFullCopy()) {
      if (!Def->getOperand(1).isReg()) {
        return nullptr;
      }
      Reg = Def->getOperand(1).getReg();
      continue;
    }

    return isImmMoveValue(*Def, ImmValue) ? Def : nullptr;
  }

  return nullptr;
}

bool getSimplifiedSetccAfterTest(int64_t SetCond, bool &UseConst,
                                 int64_t &ValueOrCond) {
  UseConst = false;
  switch (static_cast<X86::CondCode>(SetCond)) {
  case X86::COND_O:
  case X86::COND_B:
    UseConst = true;
    ValueOrCond = 0;
    return true;
  case X86::COND_NO:
  case X86::COND_AE:
    UseConst = true;
    ValueOrCond = 1;
    return true;
  case X86::COND_A:
    ValueOrCond = X86::COND_NE;
    return true;
  case X86::COND_BE:
    ValueOrCond = X86::COND_E;
    return true;
  case X86::COND_L:
    ValueOrCond = X86::COND_S;
    return true;
  case X86::COND_GE:
    ValueOrCond = X86::COND_NS;
    return true;
  default:
    return false;
  }
}

/// Match and fold: setcc -> [zext -> or-with-zero ->] test -> jcc
/// into:           cmp/test -> jcc (eliminating intermediate bool
/// materialization) The or-with-zero step is optional; direct self-test is also
/// matched.
bool matchDirectBoolBranch(CgBasicBlock &MBB, CgBasicBlock::iterator StartMII,
                           CgRegister BoolReg, int64_t SetCond,
                           SmallVector<CgInstruction *, 4> &ToErase,
                           CgInstruction *&BranchInst, int64_t &FoldedCond) {
  SmallVector<CgInstruction *, 4> LocalToErase;
  SmallVector<CgInstruction *, 4> ZeroChainToErase;
  CgRegister ZeroReg = 0;
  for (auto LocalMII = StartMII; LocalMII != MBB.end(); ++LocalMII) {
    auto &Inst = *LocalMII;
    CgRegister CopiedReg = 0;
    if (isFullCopyFromReg(Inst, BoolReg, CopiedReg)) {
      LocalToErase.push_back(&Inst);
      BoolReg = CopiedReg;
      continue;
    }

    if (ZeroReg != 0 && isFullCopyFromReg(Inst, ZeroReg, CopiedReg)) {
      ZeroChainToErase.push_back(&Inst);
      ZeroReg = CopiedReg;
      continue;
    }

    if (ZeroReg != 0 && isZeroExtendCopyFromReg(Inst, ZeroReg, CopiedReg)) {
      ZeroChainToErase.push_back(&Inst);
      ZeroReg = CopiedReg;
      continue;
    }

    CgRegister ZeroDstReg = 0;
    if (getImmMoveDstReg(Inst, 0, ZeroDstReg)) {
      ZeroChainToErase.clear();
      ZeroChainToErase.push_back(&Inst);
      ZeroReg = ZeroDstReg;
      continue;
    }

    CgRegister OrDstReg = 0;
    CgRegister OrOtherReg = 0;
    if (getBoolOrOtherReg(Inst, BoolReg, OrDstReg, OrOtherReg)) {
      SmallVector<CgInstruction *, 4> MatchedZeroToErase;
      if (ZeroReg != 0 && OrOtherReg == ZeroReg) {
        MatchedZeroToErase = ZeroChainToErase;
      } else if (!collectZeroDefChainBefore(MBB, LocalMII, OrOtherReg,
                                            MatchedZeroToErase)) {
        MatchedZeroToErase.clear();
      }

      if (MatchedZeroToErase.empty()) {
        ZeroReg = 0;
        ZeroChainToErase.clear();
      } else {
        LocalToErase.insert(LocalToErase.end(), MatchedZeroToErase.begin(),
                            MatchedZeroToErase.end());
      }

      if (!MatchedZeroToErase.empty()) {
        ZeroChainToErase.clear();
        LocalToErase.push_back(&Inst);
        ZeroReg = 0;
        BoolReg = OrDstReg;
        continue;
      }
    }

    if (isSelfTest(Inst, BoolReg)) {
      auto BranchMII = std::next(LocalMII);
      if (BranchMII == MBB.end()) {
        return false;
      }

      auto &CandidateBranchInst = *BranchMII;
      if (CandidateBranchInst.getOpcode() != X86::JCC_1 ||
          !getFoldedBranchCond(CandidateBranchInst.getOperand(1).getImm(),
                               SetCond, FoldedCond)) {
        return false;
      }

      LocalToErase.push_back(&Inst);
      ToErase.insert(ToErase.end(), LocalToErase.begin(), LocalToErase.end());
      BranchInst = &CandidateBranchInst;
      return true;
    }

    if (ZeroReg != 0 &&
        (Inst.readsRegister(ZeroReg) || Inst.modifiesRegister(ZeroReg))) {
      ZeroReg = 0;
      ZeroChainToErase.clear();
    }

    if (Inst.readsRegister(X86::EFLAGS) || Inst.modifiesRegister(X86::EFLAGS) ||
        Inst.readsRegister(BoolReg) || Inst.modifiesRegister(BoolReg)) {
      return false;
    }
  }

  return false;
}

/// Match and fold: setcc -> {mov 0, mov 1} -> test -> cmov -> test -> jcc
/// into:           cmp/test -> jcc (eliminating CMOV-based bool select)
/// The two mov defs (0 and 1) may appear in either order.
bool matchCmovBoolBranch(CgBasicBlock &MBB, CgBasicBlock::iterator StartMII,
                         CgRegister BoolReg, int64_t SetCond,
                         SmallVector<CgInstruction *, 4> &ToErase,
                         CgInstruction *&BranchInst, int64_t &FoldedCond) {
  SmallVector<CgInstruction *, 4> LocalToErase;
  CgInstruction *ZeroInst = nullptr;
  CgInstruction *OneInst = nullptr;
  for (auto LocalMII = StartMII; LocalMII != MBB.end(); ++LocalMII) {
    auto &Inst = *LocalMII;
    if (isImmMoveValue(Inst, 0)) {
      ZeroInst = &Inst;
      continue;
    }
    if (isImmMoveValue(Inst, 1)) {
      OneInst = &Inst;
      continue;
    }

    CgRegister CopiedReg = 0;
    if (isFullCopyFromReg(Inst, BoolReg, CopiedReg)) {
      LocalToErase.push_back(&Inst);
      BoolReg = CopiedReg;
      continue;
    }

    if (!isSelfTest(Inst, BoolReg)) {
      if ((ZeroInst != nullptr && ZeroInst->getOperand(0).isReg() &&
           (Inst.readsRegister(ZeroInst->getOperand(0).getReg()) ||
            Inst.modifiesRegister(ZeroInst->getOperand(0).getReg()))) ||
          (OneInst != nullptr && OneInst->getOperand(0).isReg() &&
           (Inst.readsRegister(OneInst->getOperand(0).getReg()) ||
            Inst.modifiesRegister(OneInst->getOperand(0).getReg())))) {
        return false;
      }
      if (Inst.readsRegister(X86::EFLAGS) ||
          Inst.modifiesRegister(X86::EFLAGS) || Inst.readsRegister(BoolReg) ||
          Inst.modifiesRegister(BoolReg)) {
        return false;
      }
      continue;
    }

    if (ZeroInst == nullptr || OneInst == nullptr ||
        !ZeroInst->getOperand(0).isReg() || !OneInst->getOperand(0).isReg()) {
      return false;
    }

    auto CmovMII = std::next(LocalMII);
    if (CmovMII == MBB.end()) {
      return false;
    }
    CgRegister ZeroReg = ZeroInst->getOperand(0).getReg();
    CgRegister CmovCopiedZeroReg = 0;
    if (isFullCopyFromReg(*CmovMII, ZeroReg, CmovCopiedZeroReg)) {
      LocalToErase.push_back(&*CmovMII);
      ZeroReg = CmovCopiedZeroReg;
      ++CmovMII;
      if (CmovMII == MBB.end()) {
        return false;
      }
    }
    auto &CmovInst = *CmovMII;
    if (CmovInst.getOpcode() != X86::CMOV64rr ||
        CmovInst.getNumOperands() < 4 || !CmovInst.getOperand(0).isReg() ||
        !CmovInst.getOperand(1).isReg() || !CmovInst.getOperand(2).isReg() ||
        !CmovInst.getOperand(3).isImm() ||
        CmovInst.getOperand(1).getReg() != ZeroReg ||
        CmovInst.getOperand(2).getReg() != OneInst->getOperand(0).getReg()) {
      return false;
    }

    auto FinalTestMII = std::next(CmovMII);
    if (FinalTestMII == MBB.end()) {
      return false;
    }
    auto &FinalTestInst = *FinalTestMII;
    if (!isSelfTest(FinalTestInst, CmovInst.getOperand(0).getReg())) {
      return false;
    }

    auto BranchMII = std::next(FinalTestMII);
    if (BranchMII == MBB.end()) {
      return false;
    }

    auto &CandidateBranchInst = *BranchMII;
    if (CandidateBranchInst.getOpcode() != X86::JCC_1) {
      return false;
    }

    int64_t BoolBranchCond = 0;
    if (!getFoldedBranchCond(CandidateBranchInst.getOperand(1).getImm(),
                             CmovInst.getOperand(3).getImm(), BoolBranchCond) ||
        !getFoldedBranchCond(BoolBranchCond, SetCond, FoldedCond)) {
      return false;
    }

    LocalToErase.push_back(&Inst);
    LocalToErase.push_back(&CmovInst);
    LocalToErase.push_back(&FinalTestInst);
    ToErase.insert(ToErase.end(), LocalToErase.begin(), LocalToErase.end());
    BranchInst = &CandidateBranchInst;
    return true;
  }

  return false;
}

} // namespace

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
  if (isTestOpcode(Inst.getOpcode())) {
    optimizeTestSetcc(MBB, MII);
  }
  // NOTE: x86 TEST instructions have the MCID::Compare flag set, so both
  // optimizeTestSetcc (above) and optimizeCmp (below) fire on TEST.
  // optimizeTestSetcc runs first to simplify the condition code (e.g.,
  // SETA -> SETNE) before optimizeCmp attempts the branch fold.
  // This composition is intentional and order-dependent.
  if (Inst.isCompare()) {
    optimizeCmp(MBB, MII);
  }

  optimizeAdcZeroReg(MBB, MII);
  optimizeAddZeroReg(MBB, MII);
  optimizeNoOpImm(MBB, MII);
}

void X86CgPeephole::optimizeTestSetcc(CgBasicBlock &MBB,
                                      CgBasicBlock::iterator &MII) {
  auto &Inst = *MII;
  if (!isTestOpcode(Inst.getOpcode())) {
    return;
  }

  auto LocalMII = std::next(MII);
  if (LocalMII == MBB.end()) {
    return;
  }

  auto &SetccInst = *LocalMII;
  if (SetccInst.getOpcode() != X86::SETCCr || SetccInst.getNumOperands() < 2 ||
      !SetccInst.getOperand(0).isReg() || !SetccInst.getOperand(1).isImm()) {
    return;
  }

  bool UseConst = false;
  int64_t ValueOrCond = 0;
  if (!getSimplifiedSetccAfterTest(SetccInst.getOperand(1).getImm(), UseConst,
                                   ValueOrCond)) {
    return;
  }

  if (!UseConst) {
    SetccInst.getOperand(1).setImm(ValueOrCond);
    return;
  }

  SmallVector<CgOperand, 2> Operands{
      cloneRegOperand(SetccInst.getOperand(0)),
      CgOperand::createImmOperand(ValueOrCond),
  };
  MBB.getParent()->replaceCgInstruction(
      &SetccInst, MBB.getParent()->getTargetInstrInfo().get(X86::MOV8ri),
      Operands);
}

void X86CgPeephole::optimizeCmp(CgBasicBlock &MBB,
                                CgBasicBlock::iterator &MII) {
  if (MBB.getParent()->size() > MaxCmpFoldFunctionBlocks) {
    return;
  }

  auto LocalMII = MII;
  ++LocalMII;
  if (LocalMII == MBB.end()) {
    return;
  }

  auto &SetccInst = *LocalMII;
  if (SetccInst.getOpcode() != X86::SETCCr) {
    return;
  }

  const auto &SetccDst = SetccInst.getOperand(0);
  if (!SetccDst.isReg()) {
    return;
  }

  const auto SetCond = SetccInst.getOperand(1).getImm();
  SmallVector<CgInstruction *, 4> ToErase;
  ToErase.push_back(&SetccInst);
  CgRegister TestReg = SetccDst.getReg();

  ++LocalMII;
  if (LocalMII == MBB.end()) {
    return;
  }

  auto &NextInst = *LocalMII;
  if (NextInst.getOpcode() == X86::MOVZX32rr8) {
    const auto &Dst = NextInst.getOperand(0);
    const auto &Src = NextInst.getOperand(1);
    if (!Dst.isReg() || !Src.isReg() || Src.getReg() != TestReg) {
      return;
    }
    TestReg = Dst.getReg();
    ToErase.push_back(&NextInst);
    ++LocalMII;
    if (LocalMII == MBB.end()) {
      return;
    }
  }

  CgInstruction *BranchInst = nullptr;
  int64_t FoldedCond = 0;
  if (!matchDirectBoolBranch(MBB, LocalMII, TestReg, SetCond, ToErase,
                             BranchInst, FoldedCond) &&
      !matchCmovBoolBranch(MBB, LocalMII, TestReg, SetCond, ToErase, BranchInst,
                           FoldedCond)) {
    return;
  }

  for (CgInstruction *EraseInst : ToErase) {
    EraseInst->eraseFromParent();
  }
  BranchInst->getOperand(1).setImm(FoldedCond);
}

void X86CgPeephole::optimizeNoOpImm(CgBasicBlock &MBB,
                                    CgBasicBlock::iterator &MII) {
  auto &Inst = *MII;
  if (!isNoOpImmOpcode(Inst.getOpcode()) || Inst.getNumOperands() < 3) {
    return;
  }

  const auto &Dst = Inst.getOperand(0);
  const auto &Src = Inst.getOperand(1);
  const auto &Imm = Inst.getOperand(2);
  if (!Dst.isReg() || !Src.isReg() || !Imm.isImm() || Imm.getImm() != 0 ||
      Dst.getReg() != Src.getReg()) {
    return;
  }

  if (!areFlagsDeadAfter(MBB, MII)) {
    return;
  }
  auto NextMII = std::next(MII);
  // Whitelist of observed successor patterns in current JIT output.
  // areFlagsDeadAfter already guarantees flags safety; this extra guard
  // limits the optimization to patterns we have verified in practice.
  if (Inst.getOpcode() == X86::ADD64ri8) {
    if (NextMII == MBB.end() || (NextMII->getOpcode() != X86::MOV64mr &&
                                 NextMII->getOpcode() != X86::MOV64rm &&
                                 NextMII->getOpcode() != X86::TEST64rr)) {
      return;
    }
  } else if (NextMII == MBB.end() ||
             !isZeroLogicChainOpcode(*NextMII, Dst.getReg())) {
    return;
  }

  eraseCurrentInstruction(MBB, MII);
}

void X86CgPeephole::optimizeAdcZeroReg(CgBasicBlock &MBB,
                                       CgBasicBlock::iterator &MII) {
  auto &Inst = *MII;
  const unsigned NewOpcode = getAdcImmOpcode(Inst.getOpcode());
  if (NewOpcode == InvalidOpcode || Inst.getNumOperands() < 3) {
    return;
  }

  const auto &RHS = Inst.getOperand(2);
  if (!RHS.isReg() || !RHS.getReg().isVirtual()) {
    return;
  }

  auto *MF = MBB.getParent();
  auto &MRI = MF->getRegInfo();
  if (getImmMoveDef(RHS.getReg(), MRI, 0) == nullptr) {
    return;
  }

  SmallVector<CgInstruction *, 4> Uses;
  for (auto &UseInst : MRI.use_instructions(RHS.getReg())) {
    if (UseInst.getNumOperands() < 3 ||
        getAdcImmOpcode(UseInst.getOpcode()) == InvalidOpcode ||
        !UseInst.getOperand(2).isReg() ||
        UseInst.getOperand(2).getReg() != RHS.getReg()) {
      return;
    }
    Uses.push_back(&UseInst);
  }

  CgInstruction *CurrentInst = &Inst;
  for (CgInstruction *UseInst : Uses) {
    SmallVector<CgOperand, 3> Operands{
        cloneRegOperand(UseInst->getOperand(0)),
        cloneRegOperand(UseInst->getOperand(1)),
        CgOperand::createImmOperand(0),
    };
    CgInstruction *NewInst = MF->replaceCgInstruction(
        UseInst,
        MF->getTargetInstrInfo().get(getAdcImmOpcode(UseInst->getOpcode())),
        Operands);
    if (UseInst == CurrentInst) {
      MII = CgBasicBlock::iterator(NewInst);
    }
  }
}

void X86CgPeephole::optimizeAddZeroReg(CgBasicBlock &MBB,
                                       CgBasicBlock::iterator &MII) {
  auto &Inst = *MII;
  if (!isAddRegOpcode(Inst.getOpcode()) || Inst.getNumOperands() < 3) {
    return;
  }

  const auto &Dst = Inst.getOperand(0);
  const auto &LHS = Inst.getOperand(1);
  const auto &RHS = Inst.getOperand(2);
  if (!Dst.isReg() || !LHS.isReg() || !RHS.isReg() ||
      Dst.getReg() != LHS.getReg() || !RHS.getReg().isVirtual()) {
    return;
  }

  if (!areFlagsDeadAfter(MBB, MII)) {
    return;
  }

  // The zero-def chain is intentionally not erased here: the zero register
  // may have other uses beyond this ADD. Dead zero-def instructions will
  // be cleaned up by subsequent DCE.
  SmallVector<CgInstruction *, 4> ZeroToErase;
  if (!collectZeroDefChainBefore(MBB, MII, RHS.getReg(), ZeroToErase)) {
    return;
  }

  eraseCurrentInstruction(MBB, MII);
}

void X86CgPeephole::optimizeBranchInBlockEnd(CgBasicBlock &MBB,
                                             CgInstruction &MI) {
  ZEN_ASSERT(MI.getNumOperands() > 0);
  CgOperand &MO = MI.getOperand(0);
  ZEN_ASSERT(MO.isMBB());
  CgBasicBlock *TargetMBB = MO.getMBB();
  if (TargetMBB->getNumber() == MBB.getNumber() + 1) {
    // remove the unconditional branch
    MI.eraseFromParent();
    return;
  }

  auto ThisMII = CgBasicBlock::iterator(&MI);
  if (ThisMII == MBB.begin()) {
    return;
  }

  auto PrevMII = std::prev(ThisMII);
  CgInstruction &PrevMI = *PrevMII;
  if (PrevMI.getOpcode() != X86::JCC_1 || PrevMI.getNumOperands() < 2) {
    return;
  }

  CgOperand &BranchTarget = PrevMI.getOperand(0);
  CgOperand &BranchCond = PrevMI.getOperand(1);
  if (!BranchTarget.isMBB() || !BranchCond.isImm()) {
    return;
  }

  CgBasicBlock *FallthroughMBB = BranchTarget.getMBB();
  if (FallthroughMBB->getNumber() != MBB.getNumber() + 1) {
    return;
  }

  X86::CondCode Opposite =
      getOppositeCond(static_cast<X86::CondCode>(BranchCond.getImm()));
  if (Opposite == X86::COND_INVALID) {
    return;
  }

  BranchTarget.setMBB(TargetMBB);
  BranchCond.setImm(Opposite);
  MI.eraseFromParent();
}

void X86CgPeephole::eraseCurrentInstruction(CgBasicBlock &MBB,
                                            CgBasicBlock::iterator &MII) {
  auto Next = MBB.erase(MII);
  if (MBB.empty()) {
    MII = Next;
    return;
  }

  if (Next == MBB.begin()) {
    MII = Next;
    return;
  }

  MII = std::prev(Next);
}

} // namespace COMPILER
