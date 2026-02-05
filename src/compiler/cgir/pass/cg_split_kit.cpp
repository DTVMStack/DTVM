
//===- SplitKit.cpp - Toolkit for splitting live ranges -------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the CgSplitAnalysis class as well as mutator functions for
// live range splitting.
//
//===----------------------------------------------------------------------===//

#include "compiler/cgir/pass/cg_split_kit.h"
#include "compiler/cgir/cg_instruction.h"
#include "compiler/cgir/cg_operand.h"
#include "compiler/cgir/pass/cg_block_frequency_info.h"
#include "compiler/cgir/pass/cg_dominators.h"
#include "compiler/cgir/pass/cg_loop_info.h"
#include "compiler/cgir/pass/cg_register_info.h"
#include "compiler/cgir/pass/live_range_edit.h"
#include "compiler/cgir/pass/virt_reg_map.h"
#include "llvm/ADT/None.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/TargetOpcodes.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/Support/Allocator.h"
#include "llvm/Support/BlockFrequency.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <cassert>
#include <iterator>
#include <limits>
#include <tuple>

using namespace llvm;
using namespace COMPILER;

#define DEBUG_TYPE "regalloc"

//===----------------------------------------------------------------------===//
//                     Last Insert Point Analysis
//===----------------------------------------------------------------------===//

CgInsertPointAnalysis::CgInsertPointAnalysis(const CgLiveIntervals &lis,
                                             unsigned BBNum)
    : LIS(lis), LastInsertPoint(BBNum) {}

CgSlotIndex
CgInsertPointAnalysis::computeLastInsertPoint(const CgLiveInterval &CurLI,
                                              const CgBasicBlock &MBB) {
  unsigned Num = MBB.getNumber();
  std::pair<CgSlotIndex, CgSlotIndex> &LIP = LastInsertPoint[Num];
  CgSlotIndex MBBEnd = LIS.getMBBEndIdx(&MBB);

  SmallVector<const CgBasicBlock *, 1> ExceptionalSuccessors;
  bool EHPadSuccessor = false;
#if 0
  for (const CgBasicBlock *SMBB : MBB.successors()) {
    if (SMBB->isEHPad()) {
      ExceptionalSuccessors.push_back(SMBB);
      EHPadSuccessor = true;
    } else if (SMBB->isInlineAsmBrIndirectTarget())
      ExceptionalSuccessors.push_back(SMBB);
  }
#endif

  // Compute insert points on the first call. The pair is independent of the
  // current live interval.
  if (!LIP.first.isValid()) {
    CgBasicBlock::const_iterator FirstTerm = MBB.getFirstTerminator();
    if (FirstTerm == MBB.end())
      LIP.first = MBBEnd;
    else
      LIP.first = LIS.getInstructionIndex(*FirstTerm);

    // If there is a landing pad or inlineasm_br successor, also find the
    // instruction. If there is no such instruction, we don't need to do
    // anything special.  We assume there cannot be multiple instructions
    // that are Calls with EHPad successors or INLINEASM_BR in a block.
    // Further, we assume that if there are any, they will be after any
    // other call instructions in the block.
    if (ExceptionalSuccessors.empty())
      return LIP.first;
    for (const CgInstruction &MI : llvm::reverse(MBB)) {
      if ((EHPadSuccessor && MI.isCall()) ||
          MI.getOpcode() == TargetOpcode::INLINEASM_BR) {
        LIP.second = LIS.getInstructionIndex(MI);
        break;
      }
    }
  }

  // If CurLI is live into a landing pad successor, move the last insert point
  // back to the call that may throw.
  if (!LIP.second)
    return LIP.first;

  if (none_of(ExceptionalSuccessors, [&](const CgBasicBlock *EHPad) {
        return LIS.isLiveInToMBB(CurLI, EHPad);
      }))
    return LIP.first;

  // Find the value leaving MBB.
  const CgVNInfo *VNI = CurLI.getVNInfoBefore(MBBEnd);
  if (!VNI)
    return LIP.first;

  // The def of statepoint instruction is a gc relocation and it should be
  // alive in landing pad. So we cannot split interval after statepoint
  // instruction.
  if (CgSlotIndex::isSameInstr(VNI->def, LIP.second))
    if (auto *I = LIS.getInstructionFromIndex(LIP.second))
      if (I->getOpcode() == TargetOpcode::STATEPOINT)
        return LIP.second;

  // If the value leaving MBB was defined after the call in MBB, it can't
  // really be live-in to the landing pad.  This can happen if the landing pad
  // has a PHI, and this register is undef on the exceptional edge.
  // <rdar://problem/10664933>
  if (!CgSlotIndex::isEarlierInstr(VNI->def, LIP.second) && VNI->def < MBBEnd)
    return LIP.first;

  // Value is properly live-in to the landing pad.
  // Only allow inserts before the call.
  return LIP.second;
}

CgBasicBlock::iterator
CgInsertPointAnalysis::getLastInsertPointIter(const CgLiveInterval &CurLI,
                                              CgBasicBlock &MBB) {
  CgSlotIndex LIP = getLastInsertPoint(CurLI, MBB);
  if (LIP == LIS.getMBBEndIdx(&MBB))
    return MBB.end();
  return CgBasicBlock::iterator(LIS.getInstructionFromIndex(LIP));
}

//===----------------------------------------------------------------------===//
//                                 Split Analysis
//===----------------------------------------------------------------------===//

CgSplitAnalysis::CgSplitAnalysis(const CgVirtRegMap &vrm,
                                 const CgLiveIntervals &lis,
                                 const CgLoopInfo &mli)
    : MF(vrm.getCgFunction()), VRM(vrm), LIS(lis), Loops(mli),
      TII(*MF.getSubtarget().getInstrInfo()), IPA(lis, MF.getNumBlockIDs()) {}

void CgSplitAnalysis::clear() {
  UseSlots.clear();
  UseBlocks.clear();
  ThroughBlocks.clear();
  CurLI = nullptr;
}

/// analyzeUses - Count instructions, basic blocks, and loops using CurLI.
void CgSplitAnalysis::analyzeUses() {
  assert(UseSlots.empty() && "Call clear first");

  // First get all the defs from the interval values. This provides the correct
  // slots for early clobbers.
  for (const CgVNInfo *VNI : CurLI->valnos)
    if (!VNI->isPHIDef() && !VNI->isUnused())
      UseSlots.push_back(VNI->def);

  // Get use slots form the use-def chain.
  const CgRegisterInfo &MRI = MF.getRegInfo();
  for (CgOperand &MO : MRI.use_nodbg_operands(CurLI->reg()))
    if (!MO.isUndef())
      UseSlots.push_back(LIS.getInstructionIndex(*MO.getParent()).getRegSlot());

  array_pod_sort(UseSlots.begin(), UseSlots.end());

  // Remove duplicates, keeping the smaller slot for each instruction.
  // That is what we want for early clobbers.
  UseSlots.erase(
      std::unique(UseSlots.begin(), UseSlots.end(), CgSlotIndex::isSameInstr),
      UseSlots.end());

  // Compute per-live block info.
  calcLiveBlockInfo();

  LLVM_DEBUG(dbgs() << "Analyze counted " << UseSlots.size() << " instrs in "
                    << UseBlocks.size() << " blocks, through "
                    << NumThroughBlocks << " blocks.\n");
}

/// calcLiveBlockInfo - Fill the LiveBlocks array with information about blocks
/// where CurLI is live.
void CgSplitAnalysis::calcLiveBlockInfo() {
  ThroughBlocks.resize(MF.getNumBlockIDs());
  NumThroughBlocks = NumGapBlocks = 0;
  if (CurLI->empty())
    return;

  CgLiveInterval::const_iterator LVI = CurLI->begin();
  CgLiveInterval::const_iterator LVE = CurLI->end();

  SmallVectorImpl<CgSlotIndex>::const_iterator UseI, UseE;
  UseI = UseSlots.begin();
  UseE = UseSlots.end();

  // Loop over basic blocks where CurLI is live.
  CgFunction::iterator MFI = LIS.getMBBFromIndex(LVI->start)->getIterator();
  while (true) {
    BlockInfo BI;
    BI.MBB = *MFI;
    CgSlotIndex Start, Stop;
    std::tie(Start, Stop) = LIS.getSlotIndexes()->getMBBRange(BI.MBB);

    // If the block contains no uses, the range must be live through. At one
    // point, RegisterCoalescer could create dangling ranges that ended
    // mid-block.
    if (UseI == UseE || *UseI >= Stop) {
      ++NumThroughBlocks;
      ThroughBlocks.set(BI.MBB->getNumber());
      // The range shouldn't end mid-block if there are no uses. This shouldn't
      // happen.
      assert(LVI->end >= Stop && "range ends mid block with no uses");
    } else {
      // This block has uses. Find the first and last uses in the block.
      BI.FirstInstr = *UseI;
      assert(BI.FirstInstr >= Start);
      do
        ++UseI;
      while (UseI != UseE && *UseI < Stop);
      BI.LastInstr = UseI[-1];
      assert(BI.LastInstr < Stop);

      // LVI is the first live segment overlapping MBB.
      BI.LiveIn = LVI->start <= Start;

      // When not live in, the first use should be a def.
      if (!BI.LiveIn) {
        assert(LVI->start == LVI->valno->def && "Dangling Segment start");
        assert(LVI->start == BI.FirstInstr && "First instr should be a def");
        BI.FirstDef = BI.FirstInstr;
      }

      // Look for gaps in the live range.
      BI.LiveOut = true;
      while (LVI->end < Stop) {
        CgSlotIndex LastStop = LVI->end;
        if (++LVI == LVE || LVI->start >= Stop) {
          BI.LiveOut = false;
          BI.LastInstr = LastStop;
          break;
        }

        if (LastStop < LVI->start) {
          // There is a gap in the live range. Create duplicate entries for the
          // live-in snippet and the live-out snippet.
          ++NumGapBlocks;

          // Push the Live-in part.
          BI.LiveOut = false;
          UseBlocks.push_back(BI);
          UseBlocks.back().LastInstr = LastStop;

          // Set up BI for the live-out part.
          BI.LiveIn = false;
          BI.LiveOut = true;
          BI.FirstInstr = BI.FirstDef = LVI->start;
        }

        // A Segment that starts in the middle of the block must be a def.
        assert(LVI->start == LVI->valno->def && "Dangling Segment start");
        if (!BI.FirstDef)
          BI.FirstDef = LVI->start;
      }

      UseBlocks.push_back(BI);

      // LVI is now at LVE or LVI->end >= Stop.
      if (LVI == LVE)
        break;
    }

    // Live segment ends exactly at Stop. Move to the next segment.
    if (LVI->end == Stop && ++LVI == LVE)
      break;

    // Pick the next basic block.
    if (LVI->start < Stop)
      ++MFI;
    else
      MFI = LIS.getMBBFromIndex(LVI->start)->getIterator();
  }

  assert(getNumLiveBlocks() == countLiveBlocks(CurLI) && "Bad block count");
}

unsigned CgSplitAnalysis::countLiveBlocks(const CgLiveInterval *cli) const {
  if (cli->empty())
    return 0;
  CgLiveInterval *li = const_cast<CgLiveInterval *>(cli);
  CgLiveInterval::iterator LVI = li->begin();
  CgLiveInterval::iterator LVE = li->end();
  unsigned Count = 0;

  // Loop over basic blocks where li is live.
  CgFunction::const_iterator MFI =
      LIS.getMBBFromIndex(LVI->start)->getIterator();
  CgSlotIndex Stop = LIS.getMBBEndIdx(*MFI);
  while (true) {
    ++Count;
    LVI = li->advanceTo(LVI, Stop);
    if (LVI == LVE)
      return Count;
    do {
      ++MFI;
      Stop = LIS.getMBBEndIdx(*MFI);
    } while (Stop <= LVI->start);
  }
}

bool CgSplitAnalysis::isOriginalEndpoint(CgSlotIndex Idx) const {
  unsigned OrigReg = VRM.getOriginal(CurLI->reg());
  const CgLiveInterval &Orig = LIS.getInterval(OrigReg);
  assert(!Orig.empty() && "Splitting empty interval?");
  CgLiveInterval::const_iterator I = Orig.find(Idx);

  // Range containing Idx should begin at Idx.
  if (I != Orig.end() && I->start <= Idx)
    return I->start == Idx;

  // Range does not contain Idx, previous must end at Idx.
  return I != Orig.begin() && (--I)->end == Idx;
}

void CgSplitAnalysis::analyze(const CgLiveInterval *li) {
  clear();
  CurLI = li;
  analyzeUses();
}

//===----------------------------------------------------------------------===//
//                               Split Editor
//===----------------------------------------------------------------------===//

/// Create a new CgSplitEditor for editing the CgLiveInterval analyzed by SA.
CgSplitEditor::CgSplitEditor(CgSplitAnalysis &SA, CgLiveIntervals &LIS,
                             CgVirtRegMap &VRM, CgDominatorTree &MDT,
                             CgBlockFrequencyInfo &MBFI, CgVirtRegAuxInfo &VRAI)
    : SA(SA), MF(SA.MF), LIS(LIS), VRM(VRM),
      MRI(VRM.getCgFunction().getRegInfo()), MDT(MDT),
      TII(*VRM.getCgFunction().getSubtarget().getInstrInfo()),
      TRI(*VRM.getCgFunction().getSubtarget().getRegisterInfo()), MBFI(MBFI),
      VRAI(VRAI), RegAssign(Allocator) {}

void CgSplitEditor::reset(CgLiveRangeEdit &LRE, ComplementSpillMode SM) {
  Edit = &LRE;
  SpillMode = SM;
  OpenIdx = 0;
  RegAssign.clear();
  Values.clear();

  // Reset the CgLiveIntervalCalc instances needed for this spill mode.
  LICalc[0].reset(&VRM.getCgFunction(), LIS.getSlotIndexes(), &MDT,
                  &LIS.getVNInfoAllocator());
  if (SpillMode)
    LICalc[1].reset(&VRM.getCgFunction(), LIS.getSlotIndexes(), &MDT,
                    &LIS.getVNInfoAllocator());

  Edit->anyRematerializable();
}

#if !defined(NDEBUG) || defined(LLVM_ENABLE_DUMP)
LLVM_DUMP_METHOD void CgSplitEditor::dump() const {
  if (RegAssign.empty()) {
    dbgs() << " empty\n";
    return;
  }

  for (RegAssignMap::const_iterator I = RegAssign.begin(); I.valid(); ++I)
    dbgs() << " [" << I.start() << ';' << I.stop() << "):" << I.value();
  dbgs() << '\n';
}
#endif

/// Find a subrange corresponding to the exact lane mask @p LM in the live
/// interval @p LI. The interval @p LI is assumed to contain such a subrange.
/// This function is used to find corresponding subranges between the
/// original interval and the new intervals.
template <typename T> auto &getSubrangeImpl(LaneBitmask LM, T &LI) {
  for (auto &S : LI.subranges())
    if (S.LaneMask == LM)
      return S;
  llvm_unreachable("SubRange for this mask not found");
}

CgLiveInterval::SubRange &getSubRangeForMaskExact(LaneBitmask LM,
                                                  CgLiveInterval &LI) {
  return getSubrangeImpl(LM, LI);
}

const CgLiveInterval::SubRange &
getSubRangeForMaskExact(LaneBitmask LM, const CgLiveInterval &LI) {
  return getSubrangeImpl(LM, LI);
}

/// Find a subrange corresponding to the lane mask @p LM, or a superset of it,
/// in the live interval @p LI. The interval @p LI is assumed to contain such
/// a subrange.  This function is used to find corresponding subranges between
/// the original interval and the new intervals.
const CgLiveInterval::SubRange &getSubRangeForMask(LaneBitmask LM,
                                                   const CgLiveInterval &LI) {
  for (const CgLiveInterval::SubRange &S : LI.subranges())
    if ((S.LaneMask & LM) == LM)
      return S;
  llvm_unreachable("SubRange for this mask not found");
}

void CgSplitEditor::addDeadDef(CgLiveInterval &LI, CgVNInfo *VNI,
                               bool Original) {
  if (!LI.hasSubRanges()) {
    LI.createDeadDef(VNI);
    return;
  }

  CgSlotIndex Def = VNI->def;
  if (Original) {
    // If we are transferring a def from the original interval, make sure
    // to only update the subranges for which the original subranges had
    // a def at this location.
    for (CgLiveInterval::SubRange &S : LI.subranges()) {
      auto &PS = getSubRangeForMask(S.LaneMask, Edit->getParent());
      CgVNInfo *PV = PS.getVNInfoAt(Def);
      if (PV != nullptr && PV->def == Def)
        S.createDeadDef(Def, LIS.getVNInfoAllocator());
    }
  } else {
    // This is a new def: either from rematerialization, or from an inserted
    // copy. Since rematerialization can regenerate a definition of a sub-
    // register, we need to check which subranges need to be updated.
    const CgInstruction *DefMI = LIS.getInstructionFromIndex(Def);
    assert(DefMI != nullptr);
    LaneBitmask LM;
    for (const CgOperand &DefOp : DefMI->defs()) {
      Register R = DefOp.getReg();
      if (R != LI.reg())
        continue;
      if (unsigned SR = DefOp.getSubReg())
        LM |= TRI.getSubRegIndexLaneMask(SR);
      else {
        LM = MRI.getMaxLaneMaskForVReg(R);
        break;
      }
    }
    for (CgLiveInterval::SubRange &S : LI.subranges())
      if ((S.LaneMask & LM).any())
        S.createDeadDef(Def, LIS.getVNInfoAllocator());
  }
}

CgVNInfo *CgSplitEditor::defValue(unsigned RegIdx, const CgVNInfo *ParentVNI,
                                  CgSlotIndex Idx, bool Original) {
  assert(ParentVNI && "Mapping  NULL value");
  assert(Idx.isValid() && "Invalid CgSlotIndex");
  assert(Edit->getParent().getVNInfoAt(Idx) == ParentVNI && "Bad Parent VNI");
  CgLiveInterval *LI = &LIS.getInterval(Edit->get(RegIdx));

  // Create a new value.
  CgVNInfo *VNI = LI->getNextValue(Idx, LIS.getVNInfoAllocator());

  bool Force = LI->hasSubRanges();
  ValueForcePair FP(Force ? nullptr : VNI, Force);
  // Use insert for lookup, so we can add missing values with a second lookup.
  std::pair<ValueMap::iterator, bool> InsP =
      Values.insert(std::make_pair(std::make_pair(RegIdx, ParentVNI->id), FP));

  // This was the first time (RegIdx, ParentVNI) was mapped, and it is not
  // forced. Keep it as a simple def without any liveness.
  if (!Force && InsP.second)
    return VNI;

  // If the previous value was a simple mapping, add liveness for it now.
  if (CgVNInfo *OldVNI = InsP.first->second.getPointer()) {
    addDeadDef(*LI, OldVNI, Original);

    // No longer a simple mapping.  Switch to a complex mapping. If the
    // interval has subranges, make it a forced mapping.
    InsP.first->second = ValueForcePair(nullptr, Force);
  }

  // This is a complex mapping, add liveness for VNI
  addDeadDef(*LI, VNI, Original);
  return VNI;
}

void CgSplitEditor::forceRecompute(unsigned RegIdx, const CgVNInfo &ParentVNI) {
  ValueForcePair &VFP = Values[std::make_pair(RegIdx, ParentVNI.id)];
  CgVNInfo *VNI = VFP.getPointer();

  // ParentVNI was either unmapped or already complex mapped. Either way, just
  // set the force bit.
  if (!VNI) {
    VFP.setInt(true);
    return;
  }

  // This was previously a single mapping. Make sure the old def is represented
  // by a trivial live range.
  addDeadDef(LIS.getInterval(Edit->get(RegIdx)), VNI, false);

  // Mark as complex mapped, forced.
  VFP = ValueForcePair(nullptr, true);
}

CgSlotIndex CgSplitEditor::buildSingleSubRegCopy(
    Register FromReg, Register ToReg, CgBasicBlock &MBB,
    CgBasicBlock::iterator InsertBefore, unsigned SubIdx,
    CgLiveInterval &DestLI, bool Late, CgSlotIndex Def) {
  ZEN_ASSERT_TODO();
  // const MCInstrDesc &Desc = TII.get(TargetOpcode::COPY);
  // bool FirstCopy = !Def.isValid();

  //   SmallVector<CgOperand, 1> operands{
  //       CgOperand::createRegOperand(ToReg, CgOperand::Kill),
  //   };

  // CgInstruction *CopyMI = BuildMI(MBB, InsertBefore, DebugLoc(), Desc)
  //     .addReg(ToReg, RegState::Define | getUndefRegState(FirstCopy)
  //             | getInternalReadRegState(!FirstCopy), SubIdx)
  //     .addReg(FromReg, 0, SubIdx);

  // CgSlotIndexes &Indexes = *LIS.getSlotIndexes();
  // if (FirstCopy) {
  //   Def = Indexes.insertCgInstrInMaps(*CopyMI, Late).getRegSlot();
  // } else {
  //   CopyMI->bundleWithPred();
  // }
  // return Def;
}

CgSlotIndex CgSplitEditor::buildCopy(Register FromReg, Register ToReg,
                                     LaneBitmask LaneMask, CgBasicBlock &MBB,
                                     CgBasicBlock::iterator InsertBefore,
                                     bool Late, unsigned RegIdx) {
  const MCInstrDesc &Desc = TII.get(TargetOpcode::COPY);
  CgSlotIndexes &Indexes = *LIS.getSlotIndexes();
  if (LaneMask.all() || LaneMask == MRI.getMaxLaneMaskForVReg(FromReg)) {
    SmallVector<CgOperand, 2> operands{
        CgOperand::createRegOperand(ToReg, CgOperand::Define),
        CgOperand::createRegOperand(FromReg),
    };
    CgInstruction *CopyMI =
        MF.createCgInstruction(MBB, InsertBefore, Desc, operands);
    // The full vreg is copied.
    // CgInstruction *CopyMI = MF->createCgInstruction(MBB, InsertBefore
    //     BuildMI(MBB, InsertBefore, DebugLoc(), Desc, ToReg).addReg(FromReg);
    return Indexes.insertCgInstructionInMaps(*CopyMI, Late).getRegSlot();
  }

  // Only a subset of lanes needs to be copied. The following is a simple
  // heuristic to construct a sequence of COPYs. We could add a target
  // specific callback if this turns out to be suboptimal.
  CgLiveInterval &DestLI = LIS.getInterval(Edit->get(RegIdx));

  // First pass: Try to find a perfectly matching subregister index. If none
  // exists find the one covering the most lanemask bits.
  const TargetRegisterClass *RC = MRI.getRegClass(FromReg);
  assert(RC == MRI.getRegClass(ToReg) && "Should have same reg class");

  SmallVector<unsigned, 8> SubIndexes;

  // Abort if we cannot possibly implement the COPY with the given indexes.
  ZEN_ASSERT_TODO();
  // if (!TRI.getCoveringSubRegIndexes(MRI, RC, LaneMask, SubIndexes))
  //   report_fatal_error("Impossible to implement partial COPY");

  CgSlotIndex Def;
  for (unsigned BestIdx : SubIndexes) {
    Def = buildSingleSubRegCopy(FromReg, ToReg, MBB, InsertBefore, BestIdx,
                                DestLI, Late, Def);
  }

  BumpPtrAllocator &Allocator = LIS.getVNInfoAllocator();
  DestLI.refineSubRanges(
      Allocator, LaneMask,
      [Def, &Allocator](CgLiveInterval::SubRange &SR) {
        SR.createDeadDef(Def, Allocator);
      },
      Indexes, TRI);

  return Def;
}

CgVNInfo *CgSplitEditor::defFromParent(unsigned RegIdx,
                                       const CgVNInfo *ParentVNI,
                                       CgSlotIndex UseIdx, CgBasicBlock &MBB,
                                       CgBasicBlock::iterator I) {
  CgSlotIndex Def;
  CgLiveInterval *LI = &LIS.getInterval(Edit->get(RegIdx));

  // We may be trying to avoid interference that ends at a deleted instruction,
  // so always begin RegIdx 0 early and all others late.
  bool Late = RegIdx != 0;

  // Attempt cheap-as-a-copy rematerialization.
  unsigned Original = VRM.getOriginal(Edit->get(RegIdx));
  CgLiveInterval &OrigLI = LIS.getInterval(Original);
  CgVNInfo *OrigVNI = OrigLI.getVNInfoAt(UseIdx);

  Register Reg = LI->reg();
  bool DidRemat = false;
  if (OrigVNI) {
    CgLiveRangeEdit::Remat RM(ParentVNI);
    RM.OrigMI = LIS.getInstructionFromIndex(OrigVNI->def);
    if (Edit->canRematerializeAt(RM, OrigVNI, UseIdx, true)) {
      Def = Edit->rematerializeAt(MBB, I, Reg, RM, TRI, Late);
      DidRemat = true;
    }
  }
  if (!DidRemat) {
    LaneBitmask LaneMask;
    if (OrigLI.hasSubRanges()) {
      LaneMask = LaneBitmask::getNone();
      for (CgLiveInterval::SubRange &S : OrigLI.subranges()) {
        if (S.liveAt(UseIdx))
          LaneMask |= S.LaneMask;
      }
    } else {
      LaneMask = LaneBitmask::getAll();
    }

    if (LaneMask.none()) {
      // const MCInstrDesc &Desc = TII.get(TargetOpcode::IMPLICIT_DEF);
      // CgInstruction *ImplicitDef = BuildMI(MBB, I, DebugLoc(), Desc, Reg);
      // CgSlotIndexes &Indexes = *LIS.getSlotIndexes();
      // Def = Indexes.insertCgInstrInMaps(*ImplicitDef, Late).getRegSlot();
    } else {
      Def = buildCopy(Edit->getReg(), Reg, LaneMask, MBB, I, Late, RegIdx);
    }
  }

  // Define the value in Reg.
  return defValue(RegIdx, ParentVNI, Def, false);
}

/// Create a new virtual register and live interval.
unsigned CgSplitEditor::openIntv() {
  // Create the complement as index 0.
  if (Edit->empty())
    Edit->createEmptyInterval();

  // Create the open interval.
  OpenIdx = Edit->size();
  Edit->createEmptyInterval();
  return OpenIdx;
}

void CgSplitEditor::selectIntv(unsigned Idx) {
  assert(Idx != 0 && "Cannot select the complement interval");
  assert(Idx < Edit->size() && "Can only select previously opened interval");
  LLVM_DEBUG(dbgs() << "    selectIntv " << OpenIdx << " -> " << Idx << '\n');
  OpenIdx = Idx;
}

CgSlotIndex CgSplitEditor::enterIntvBefore(CgSlotIndex Idx) {
  assert(OpenIdx && "openIntv not called before enterIntvBefore");
  LLVM_DEBUG(dbgs() << "    enterIntvBefore " << Idx);
  Idx = Idx.getBaseIndex();
  CgVNInfo *ParentVNI = Edit->getParent().getVNInfoAt(Idx);
  if (!ParentVNI) {
    LLVM_DEBUG(dbgs() << ": not live\n");
    return Idx;
  }
  LLVM_DEBUG(dbgs() << ": valno " << ParentVNI->id << '\n');
  CgInstruction *MI = LIS.getInstructionFromIndex(Idx);
  assert(MI && "enterIntvBefore called with invalid index");

  CgVNInfo *VNI = defFromParent(OpenIdx, ParentVNI, Idx, *MI->getParent(),
                                MI->getIterator());
  return VNI->def;
}

CgSlotIndex CgSplitEditor::enterIntvAfter(CgSlotIndex Idx) {
  assert(OpenIdx && "openIntv not called before enterIntvAfter");
  LLVM_DEBUG(dbgs() << "    enterIntvAfter " << Idx);
  Idx = Idx.getBoundaryIndex();
  CgVNInfo *ParentVNI = Edit->getParent().getVNInfoAt(Idx);
  if (!ParentVNI) {
    LLVM_DEBUG(dbgs() << ": not live\n");
    return Idx;
  }
  LLVM_DEBUG(dbgs() << ": valno " << ParentVNI->id << '\n');
  CgInstruction *MI = LIS.getInstructionFromIndex(Idx);
  if (!MI) {
    LLVM_DEBUG(dbgs() << "      no MI at " << Idx << ", resolving via MBB\n");
    CgBasicBlock *MBB = LIS.getMBBFromIndex(Idx);
    if (!MBB) {
      LLVM_DEBUG(dbgs() << "      no MBB for index, keeping " << Idx << '\n');
      return Idx;
    }

    CgSlotIndex End = LIS.getMBBEndIdx(MBB);
    if (Idx >= End.getPrevSlot()) {
      LLVM_DEBUG(dbgs() << "      at end of " << printCgBBReference(*MBB)
                        << ", using end\n");
      return enterIntvAtEnd(*MBB);
    }

    CgSlotIndex NextIdx = LIS.getSlotIndexes()->getNextNonNullIndex(Idx);
    CgInstruction *NextMI = LIS.getInstructionFromIndex(NextIdx);
    if (!NextMI || NextMI->getParent() != MBB) {
      LLVM_DEBUG(dbgs() << "      next MI not in block, using end\n");
      return enterIntvAtEnd(*MBB);
    }

    CgVNInfo *VNI =
        defFromParent(OpenIdx, ParentVNI, Idx, *MBB, NextMI->getIterator());
    return VNI->def;
  }

  CgVNInfo *VNI = defFromParent(OpenIdx, ParentVNI, Idx, *MI->getParent(),
                                std::next(CgBasicBlock::iterator(MI)));
  return VNI->def;
}

CgSlotIndex CgSplitEditor::enterIntvAtEnd(CgBasicBlock &MBB) {
  assert(OpenIdx && "openIntv not called before enterIntvAtEnd");
  CgSlotIndex End = LIS.getMBBEndIdx(&MBB);
  CgSlotIndex Last = End.getPrevSlot();
  LLVM_DEBUG(dbgs() << "    enterIntvAtEnd " << printCgBBReference(MBB) << ", "
                    << Last);
  CgVNInfo *ParentVNI = Edit->getParent().getVNInfoAt(Last);
  if (!ParentVNI) {
    LLVM_DEBUG(dbgs() << ": not live\n");
    return End;
  }
  CgSlotIndex LSP = SA.getLastSplitPoint(&MBB);
  if (LSP < Last) {
    // It could be that the use after LSP is a def, and thus the ParentVNI
    // just selected starts at that def.  For this case to exist, the def
    // must be part of a tied def/use pair (as otherwise we'd have split
    // distinct live ranges into individual live intervals), and thus we
    // can insert the def into the VNI of the use and the tied def/use
    // pair can live in the resulting interval.
    Last = LSP;
    ParentVNI = Edit->getParent().getVNInfoAt(Last);
    if (!ParentVNI) {
      // undef use --> undef tied def
      LLVM_DEBUG(dbgs() << ": tied use not live\n");
      return End;
    }
  }

  LLVM_DEBUG(dbgs() << ": valno " << ParentVNI->id);
  CgVNInfo *VNI = defFromParent(OpenIdx, ParentVNI, Last, MBB,
                                SA.getLastSplitPointIter(&MBB));
  RegAssign.insert(VNI->def, End, OpenIdx);
  LLVM_DEBUG(dump());
  return VNI->def;
}

/// useIntv - indicate that all instructions in MBB should use OpenLI.
void CgSplitEditor::useIntv(const CgBasicBlock &MBB) {
  useIntv(LIS.getMBBStartIdx(&MBB), LIS.getMBBEndIdx(&MBB));
}

void CgSplitEditor::useIntv(CgSlotIndex Start, CgSlotIndex End) {
  assert(OpenIdx && "openIntv not called before useIntv");
  LLVM_DEBUG(dbgs() << "    useIntv [" << Start << ';' << End << "):");
  RegAssign.insert(Start, End, OpenIdx);
  LLVM_DEBUG(dump());
}

CgSlotIndex CgSplitEditor::leaveIntvAfter(CgSlotIndex Idx) {
  assert(OpenIdx && "openIntv not called before leaveIntvAfter");
  LLVM_DEBUG(dbgs() << "    leaveIntvAfter " << Idx);

  // The interval must be live beyond the instruction at Idx.
  CgSlotIndex Boundary = Idx.getBoundaryIndex();
  CgVNInfo *ParentVNI = Edit->getParent().getVNInfoAt(Boundary);
  if (!ParentVNI) {
    LLVM_DEBUG(dbgs() << ": not live\n");
    return Boundary.getNextSlot();
  }
  LLVM_DEBUG(dbgs() << ": valno " << ParentVNI->id << '\n');
  CgInstruction *MI = LIS.getInstructionFromIndex(Boundary);
  assert(MI && "No instruction at index");

  // In spill mode, make live ranges as short as possible by inserting the copy
  // before MI.  This is only possible if that instruction doesn't redefine the
  // value.  The inserted COPY is not a kill, and we don't need to recompute
  // the source live range.  The spiller also won't try to hoist this copy.
  if (SpillMode && !CgSlotIndex::isSameInstr(ParentVNI->def, Idx) &&
      MI->readsVirtualRegister(Edit->getReg())) {
    forceRecompute(0, *ParentVNI);
    defFromParent(0, ParentVNI, Idx, *MI->getParent(), MI->getIterator());
    return Idx;
  }

  CgVNInfo *VNI = defFromParent(0, ParentVNI, Boundary, *MI->getParent(),
                                std::next(CgBasicBlock::iterator(MI)));
  return VNI->def;
}

CgSlotIndex CgSplitEditor::leaveIntvBefore(CgSlotIndex Idx) {
  assert(OpenIdx && "openIntv not called before leaveIntvBefore");
  LLVM_DEBUG(dbgs() << "    leaveIntvBefore " << Idx);

  // The interval must be live into the instruction at Idx.
  Idx = Idx.getBaseIndex();
  CgVNInfo *ParentVNI = Edit->getParent().getVNInfoAt(Idx);
  if (!ParentVNI) {
    LLVM_DEBUG(dbgs() << ": not live\n");
    return Idx.getNextSlot();
  }
  LLVM_DEBUG(dbgs() << ": valno " << ParentVNI->id << '\n');

  CgInstruction *MI = LIS.getInstructionFromIndex(Idx);
  assert(MI && "No instruction at index");
  CgVNInfo *VNI =
      defFromParent(0, ParentVNI, Idx, *MI->getParent(), MI->getIterator());
  return VNI->def;
}

CgSlotIndex CgSplitEditor::leaveIntvAtTop(CgBasicBlock &MBB) {
  assert(OpenIdx && "openIntv not called before leaveIntvAtTop");
  CgSlotIndex Start = LIS.getMBBStartIdx(&MBB);
  LLVM_DEBUG(dbgs() << "    leaveIntvAtTop " << printCgBBReference(MBB) << ", "
                    << Start);

  CgVNInfo *ParentVNI = Edit->getParent().getVNInfoAt(Start);
  if (!ParentVNI) {
    LLVM_DEBUG(dbgs() << ": not live\n");
    return Start;
  }

  CgVNInfo *VNI = defFromParent(0, ParentVNI, Start, MBB,
                                MBB.SkipPHIsLabelsAndDebug(MBB.begin()));
  RegAssign.insert(Start, VNI->def, OpenIdx);
  LLVM_DEBUG(dump());
  return VNI->def;
}

static bool hasTiedUseOf(CgInstruction &MI, unsigned Reg) {
  return any_of(MI.defs(), [Reg](const CgOperand &MO) {
    return MO.isReg() && MO.isTied() && MO.getReg() == Reg;
  });
}

void CgSplitEditor::overlapIntv(CgSlotIndex Start, CgSlotIndex End) {
  assert(OpenIdx && "openIntv not called before overlapIntv");
  const CgVNInfo *ParentVNI = Edit->getParent().getVNInfoAt(Start);
  assert(ParentVNI == Edit->getParent().getVNInfoBefore(End) &&
         "Parent changes value in extended range");
  assert(LIS.getMBBFromIndex(Start) == LIS.getMBBFromIndex(End) &&
         "Range cannot span basic blocks");

  // The complement interval will be extended as needed by LICalc.extend().
  if (ParentVNI)
    forceRecompute(0, *ParentVNI);

  // If the last use is tied to a def, we can't mark it as live for the
  // interval which includes only the use.  That would cause the tied pair
  // to end up in two different intervals.
  if (auto *MI = LIS.getInstructionFromIndex(End))
    if (hasTiedUseOf(*MI, Edit->getReg())) {
      LLVM_DEBUG(dbgs() << "skip overlap due to tied def at end\n");
      return;
    }

  LLVM_DEBUG(dbgs() << "    overlapIntv [" << Start << ';' << End << "):");
  RegAssign.insert(Start, End, OpenIdx);
  LLVM_DEBUG(dump());
}

//===----------------------------------------------------------------------===//
//                                  Spill modes
//===----------------------------------------------------------------------===//

void CgSplitEditor::removeBackCopies(SmallVectorImpl<CgVNInfo *> &Copies) {
  CgLiveInterval *LI = &LIS.getInterval(Edit->get(0));
  LLVM_DEBUG(dbgs() << "Removing " << Copies.size() << " back-copies.\n");
  RegAssignMap::iterator AssignI;
  AssignI.setMap(RegAssign);

  for (const CgVNInfo *C : Copies) {
    CgSlotIndex Def = C->def;
    CgInstruction *MI = LIS.getInstructionFromIndex(Def);
    assert(MI && "No instruction for back-copy");

    CgBasicBlock *MBB = MI->getParent();
    CgBasicBlock::iterator MBBI(MI);
    bool AtBegin;
    do
      AtBegin = MBBI == MBB->begin();
    while (!AtBegin && (--MBBI)->isDebugOrPseudoInstr());

    LLVM_DEBUG(dbgs() << "Removing " << Def << '\t' << *MI);
    LIS.removeVRegDefAt(*LI, Def);
    LIS.RemoveCgInstructionFromMaps(*MI);
    MI->eraseFromParent();

    // Adjust RegAssign if a register assignment is killed at Def. We want to
    // avoid calculating the live range of the source register if possible.
    AssignI.find(Def.getPrevSlot());
    if (!AssignI.valid() || AssignI.start() >= Def)
      continue;
    // If MI doesn't kill the assigned register, just leave it.
    if (AssignI.stop() != Def)
      continue;
    unsigned RegIdx = AssignI.value();
    // We could hoist back-copy right after another back-copy. As a result
    // MMBI points to copy instruction which is actually dead now.
    // We cannot set its stop to MBBI which will be the same as start and
    // interval does not support that.
    CgSlotIndex Kill =
        AtBegin ? CgSlotIndex() : LIS.getInstructionIndex(*MBBI).getRegSlot();
    if (AtBegin || !MBBI->readsVirtualRegister(Edit->getReg()) ||
        Kill <= AssignI.start()) {
      LLVM_DEBUG(dbgs() << "  cannot find simple kill of RegIdx " << RegIdx
                        << '\n');
      forceRecompute(RegIdx, *Edit->getParent().getVNInfoAt(Def));
    } else {
      LLVM_DEBUG(dbgs() << "  move kill to " << Kill << '\t' << *MBBI);
      AssignI.setStop(Kill);
    }
  }
}

CgBasicBlock *CgSplitEditor::findShallowDominator(CgBasicBlock *MBB,
                                                  CgBasicBlock *DefMBB) {
  if (MBB == DefMBB)
    return MBB;
  assert(MDT.dominates(DefMBB, MBB) && "MBB must be dominated by the def.");

  const CgLoopInfo &Loops = SA.Loops;
  const CgLoop *DefLoop = Loops.getLoopFor(DefMBB);
  CgDomTreeNode *DefDomNode = MDT[DefMBB];

  // Best candidate so far.
  CgBasicBlock *BestMBB = MBB;
  unsigned BestDepth = std::numeric_limits<unsigned>::max();

  while (true) {
    const CgLoop *Loop = Loops.getLoopFor(MBB);

    // MBB isn't in a loop, it doesn't get any better.  All dominators have a
    // higher frequency by definition.
    if (!Loop) {
      LLVM_DEBUG(dbgs() << "Def in " << printCgBBReference(*DefMBB)
                        << " dominates " << printCgBBReference(*MBB)
                        << " at depth 0\n");
      return MBB;
    }

    // We'll never be able to exit the DefLoop.
    if (Loop == DefLoop) {
      LLVM_DEBUG(dbgs() << "Def in " << printCgBBReference(*DefMBB)
                        << " dominates " << printCgBBReference(*MBB)
                        << " in the same loop\n");
      return MBB;
    }

    // Least busy dominator seen so far.
    unsigned Depth = Loop->getLoopDepth();
    if (Depth < BestDepth) {
      BestMBB = MBB;
      BestDepth = Depth;
      LLVM_DEBUG(dbgs() << "Def in " << printCgBBReference(*DefMBB)
                        << " dominates " << printCgBBReference(*MBB)
                        << " at depth " << Depth << '\n');
    }

    // Leave loop by going to the immediate dominator of the loop header.
    // This is a bigger stride than simply walking up the dominator tree.
    CgDomTreeNode *IDom = MDT[Loop->getHeader()]->getIDom();

    // Too far up the dominator tree?
    if (!IDom || !MDT.dominates(DefDomNode, IDom))
      return BestMBB;

    MBB = IDom->getBlock();
  }
}

void CgSplitEditor::computeRedundantBackCopies(
    DenseSet<unsigned> &NotToHoistSet,
    SmallVectorImpl<CgVNInfo *> &BackCopies) {
  CgLiveInterval *LI = &LIS.getInterval(Edit->get(0));
  const CgLiveInterval *Parent = &Edit->getParent();
  SmallVector<SmallPtrSet<CgVNInfo *, 8>, 8> EqualVNs(Parent->getNumValNums());
  SmallPtrSet<CgVNInfo *, 8> DominatedVNIs;

  // Aggregate VNIs having the same value as ParentVNI.
  for (CgVNInfo *VNI : LI->valnos) {
    if (VNI->isUnused())
      continue;
    CgVNInfo *ParentVNI = Edit->getParent().getVNInfoAt(VNI->def);
    EqualVNs[ParentVNI->id].insert(VNI);
  }

  // For VNI aggregation of each ParentVNI, collect dominated, i.e.,
  // redundant VNIs to BackCopies.
  for (unsigned i = 0, e = Parent->getNumValNums(); i != e; ++i) {
    const CgVNInfo *ParentVNI = Parent->getValNumInfo(i);
    if (!NotToHoistSet.count(ParentVNI->id))
      continue;
    SmallPtrSetIterator<CgVNInfo *> It1 = EqualVNs[ParentVNI->id].begin();
    SmallPtrSetIterator<CgVNInfo *> It2 = It1;
    for (; It1 != EqualVNs[ParentVNI->id].end(); ++It1) {
      It2 = It1;
      for (++It2; It2 != EqualVNs[ParentVNI->id].end(); ++It2) {
        if (DominatedVNIs.count(*It1) || DominatedVNIs.count(*It2))
          continue;

        CgBasicBlock *MBB1 = LIS.getMBBFromIndex((*It1)->def);
        CgBasicBlock *MBB2 = LIS.getMBBFromIndex((*It2)->def);
        if (MBB1 == MBB2) {
          DominatedVNIs.insert((*It1)->def < (*It2)->def ? (*It2) : (*It1));
        } else if (MDT.dominates(MBB1, MBB2)) {
          DominatedVNIs.insert(*It2);
        } else if (MDT.dominates(MBB2, MBB1)) {
          DominatedVNIs.insert(*It1);
        }
      }
    }
    if (!DominatedVNIs.empty()) {
      forceRecompute(0, *ParentVNI);
      append_range(BackCopies, DominatedVNIs);
      DominatedVNIs.clear();
    }
  }
}

/// For SM_Size mode, find a common dominator for all the back-copies for
/// the same ParentVNI and hoist the backcopies to the dominator BB.
/// For SM_Speed mode, if the common dominator is hot and it is not beneficial
/// to do the hoisting, simply remove the dominated backcopies for the same
/// ParentVNI.
void CgSplitEditor::hoistCopies() {
  // Get the complement interval, always RegIdx 0.
  CgLiveInterval *LI = &LIS.getInterval(Edit->get(0));
  const CgLiveInterval *Parent = &Edit->getParent();

  // Track the nearest common dominator for all back-copies for each ParentVNI,
  // indexed by ParentVNI->id.
  using DomPair = std::pair<CgBasicBlock *, CgSlotIndex>;
  SmallVector<DomPair, 8> NearestDom(Parent->getNumValNums());
  // The total cost of all the back-copies for each ParentVNI.
  SmallVector<BlockFrequency, 8> Costs(Parent->getNumValNums());
  // The ParentVNI->id set for which hoisting back-copies are not beneficial
  // for Speed.
  DenseSet<unsigned> NotToHoistSet;

  // Find the nearest common dominator for parent values with multiple
  // back-copies.  If a single back-copy dominates, put it in DomPair.second.
  for (CgVNInfo *VNI : LI->valnos) {
    if (VNI->isUnused())
      continue;
    CgVNInfo *ParentVNI = Edit->getParent().getVNInfoAt(VNI->def);
    assert(ParentVNI && "Parent not live at complement def");

    // Don't hoist remats.  The complement is probably going to disappear
    // completely anyway.
    if (Edit->didRematerialize(ParentVNI))
      continue;

    CgBasicBlock *ValMBB = LIS.getMBBFromIndex(VNI->def);

    DomPair &Dom = NearestDom[ParentVNI->id];

    // Keep directly defined parent values.  This is either a PHI or an
    // instruction in the complement range.  All other copies of ParentVNI
    // should be eliminated.
    if (VNI->def == ParentVNI->def) {
      LLVM_DEBUG(dbgs() << "Direct complement def at " << VNI->def << '\n');
      Dom = DomPair(ValMBB, VNI->def);
      continue;
    }
    // Skip the singly mapped values.  There is nothing to gain from hoisting a
    // single back-copy.
    if (Values.lookup(std::make_pair(0, ParentVNI->id)).getPointer()) {
      LLVM_DEBUG(dbgs() << "Single complement def at " << VNI->def << '\n');
      continue;
    }

    if (!Dom.first) {
      // First time we see ParentVNI.  VNI dominates itself.
      Dom = DomPair(ValMBB, VNI->def);
    } else if (Dom.first == ValMBB) {
      // Two defs in the same block.  Pick the earlier def.
      if (!Dom.second.isValid() || VNI->def < Dom.second)
        Dom.second = VNI->def;
    } else {
      // Different basic blocks. Check if one dominates.
      CgBasicBlock *Near = MDT.findNearestCommonDominator(Dom.first, ValMBB);
      if (Near == ValMBB)
        // Def ValMBB dominates.
        Dom = DomPair(ValMBB, VNI->def);
      else if (Near != Dom.first)
        // None dominate. Hoist to common dominator, need new def.
        Dom = DomPair(Near, CgSlotIndex());
      Costs[ParentVNI->id] += MBFI.getBlockFreq(ValMBB);
    }

    LLVM_DEBUG(dbgs() << "Multi-mapped complement " << VNI->id << '@'
                      << VNI->def << " for parent " << ParentVNI->id << '@'
                      << ParentVNI->def << " hoist to "
                      << printCgBBReference(*Dom.first) << ' ' << Dom.second
                      << '\n');
  }

  // Insert the hoisted copies.
  for (unsigned i = 0, e = Parent->getNumValNums(); i != e; ++i) {
    DomPair &Dom = NearestDom[i];
    if (!Dom.first || Dom.second.isValid())
      continue;
    // This value needs a hoisted copy inserted at the end of Dom.first.
    const CgVNInfo *ParentVNI = Parent->getValNumInfo(i);
    CgBasicBlock *DefMBB = LIS.getMBBFromIndex(ParentVNI->def);
    // Get a less loopy dominator than Dom.first.
    Dom.first = findShallowDominator(Dom.first, DefMBB);
    if (SpillMode == SM_Speed &&
        MBFI.getBlockFreq(Dom.first) > Costs[ParentVNI->id]) {
      NotToHoistSet.insert(ParentVNI->id);
      continue;
    }
    CgSlotIndex LSP = SA.getLastSplitPoint(Dom.first);
    if (LSP <= ParentVNI->def) {
      NotToHoistSet.insert(ParentVNI->id);
      continue;
    }
    Dom.second = defFromParent(0, ParentVNI, LSP, *Dom.first,
                               SA.getLastSplitPointIter(Dom.first))
                     ->def;
  }

  // Remove redundant back-copies that are now known to be dominated by another
  // def with the same value.
  SmallVector<CgVNInfo *, 8> BackCopies;
  for (CgVNInfo *VNI : LI->valnos) {
    if (VNI->isUnused())
      continue;
    CgVNInfo *ParentVNI = Edit->getParent().getVNInfoAt(VNI->def);
    const DomPair &Dom = NearestDom[ParentVNI->id];
    if (!Dom.first || Dom.second == VNI->def ||
        NotToHoistSet.count(ParentVNI->id))
      continue;
    BackCopies.push_back(VNI);
    forceRecompute(0, *ParentVNI);
  }

  // If it is not beneficial to hoist all the BackCopies, simply remove
  // redundant BackCopies in speed mode.
  if (SpillMode == SM_Speed && !NotToHoistSet.empty())
    computeRedundantBackCopies(NotToHoistSet, BackCopies);

  removeBackCopies(BackCopies);
}

/// transferValues - Transfer all possible values to the new live ranges.
/// Values that were rematerialized are left alone, they need LICalc.extend().
bool CgSplitEditor::transferValues() {
  bool Skipped = false;
  RegAssignMap::const_iterator AssignI = RegAssign.begin();
  for (const CgLiveRange::Segment &S : Edit->getParent()) {
    LLVM_DEBUG(dbgs() << "  blit " << S << ':');
    CgVNInfo *ParentVNI = S.valno;
    // RegAssign has holes where RegIdx 0 should be used.
    CgSlotIndex Start = S.start;
    AssignI.advanceTo(Start);
    do {
      unsigned RegIdx;
      CgSlotIndex End = S.end;
      if (!AssignI.valid()) {
        RegIdx = 0;
      } else if (AssignI.start() <= Start) {
        RegIdx = AssignI.value();
        if (AssignI.stop() < End) {
          End = AssignI.stop();
          ++AssignI;
        }
      } else {
        RegIdx = 0;
        End = std::min(End, AssignI.start());
      }

      // The interval [Start;End) is continuously mapped to RegIdx, ParentVNI.
      LLVM_DEBUG(dbgs() << " [" << Start << ';' << End << ")=" << RegIdx << '('
                        << printReg(Edit->get(RegIdx)) << ')');
      CgLiveInterval &LI = LIS.getInterval(Edit->get(RegIdx));

      // Check for a simply defined value that can be blitted directly.
      ValueForcePair VFP = Values.lookup(std::make_pair(RegIdx, ParentVNI->id));
      if (CgVNInfo *VNI = VFP.getPointer()) {
        LLVM_DEBUG(dbgs() << ':' << VNI->id);
        LI.addSegment(CgLiveInterval::Segment(Start, End, VNI));
        Start = End;
        continue;
      }

      // Skip values with forced recomputation.
      if (VFP.getInt()) {
        LLVM_DEBUG(dbgs() << "(recalc)");
        Skipped = true;
        Start = End;
        continue;
      }

      CgLiveIntervalCalc &LIC = getLICalc(RegIdx);

      // This value has multiple defs in RegIdx, but it wasn't rematerialized,
      // so the live range is accurate. Add live-in blocks in [Start;End) to the
      // LiveInBlocks.
      CgFunction::iterator MBB = LIS.getMBBFromIndex(Start)->getIterator();
      CgSlotIndex BlockStart, BlockEnd;
      std::tie(BlockStart, BlockEnd) = LIS.getSlotIndexes()->getMBBRange(*MBB);

      // The first block may be live-in, or it may have its own def.
      if (Start != BlockStart) {
        CgVNInfo *VNI = LI.extendInBlock(BlockStart, std::min(BlockEnd, End));
        assert(VNI && "Missing def for complex mapped value");
        LLVM_DEBUG(dbgs() << ':' << VNI->id << "*"
                          << printCgBBReference(**MBB));
        // MBB has its own def. Is it also live-out?
        if (BlockEnd <= End)
          LIC.setLiveOutValue(*MBB, VNI);

        // Skip to the next block for live-in.
        ++MBB;
        BlockStart = BlockEnd;
      }

      // Handle the live-in blocks covered by [Start;End).
      assert(Start <= BlockStart && "Expected live-in block");
      while (BlockStart < End) {
        LLVM_DEBUG(dbgs() << ">" << printCgBBReference(**MBB));
        BlockEnd = LIS.getMBBEndIdx(*MBB);
        if (BlockStart == ParentVNI->def) {
          // This block has the def of a parent PHI, so it isn't live-in.
          assert(ParentVNI->isPHIDef() && "Non-phi defined at block start?");
          CgVNInfo *VNI = LI.extendInBlock(BlockStart, std::min(BlockEnd, End));
          assert(VNI && "Missing def for complex mapped parent PHI");
          if (End >= BlockEnd)
            LIC.setLiveOutValue(*MBB, VNI); // Live-out as well.
        } else {
          // This block needs a live-in value.  The last block covered may not
          // be live-out.
          if (End < BlockEnd)
            LIC.addLiveInBlock(LI, MDT[*MBB], End);
          else {
            // Live-through, and we don't know the value.
            LIC.addLiveInBlock(LI, MDT[*MBB]);
            LIC.setLiveOutValue(*MBB, nullptr);
          }
        }
        BlockStart = BlockEnd;
        ++MBB;
      }
      Start = End;
    } while (Start != S.end);
    LLVM_DEBUG(dbgs() << '\n');
  }

  LICalc[0].calculateValues();
  if (SpillMode)
    LICalc[1].calculateValues();

  return Skipped;
}

static bool removeDeadSegment(CgSlotIndex Def, CgLiveRange &LR) {
  const CgLiveRange::Segment *Seg = LR.getSegmentContaining(Def);
  if (Seg == nullptr)
    return true;
  if (Seg->end != Def.getDeadSlot())
    return false;
  // This is a dead PHI. Remove it.
  LR.removeSegment(*Seg, true);
  return true;
}

void CgSplitEditor::extendPHIRange(CgBasicBlock &B, CgLiveIntervalCalc &LIC,
                                   CgLiveRange &LR, LaneBitmask LM,
                                   ArrayRef<CgSlotIndex> Undefs) {
  for (CgBasicBlock *P : B.predecessors()) {
    CgSlotIndex End = LIS.getMBBEndIdx(P);
    CgSlotIndex LastUse = End.getPrevSlot();
    // The predecessor may not have a live-out value. That is OK, like an
    // undef PHI operand.
    const CgLiveInterval &PLI = Edit->getParent();
    // Need the cast because the inputs to ?: would otherwise be deemed
    // "incompatible": SubRange vs CgLiveInterval.
    const CgLiveRange &PSR = !LM.all() ? getSubRangeForMaskExact(LM, PLI)
                                       : static_cast<const CgLiveRange &>(PLI);
    if (PSR.liveAt(LastUse))
      LIC.extend(LR, End, /*PhysReg=*/0, Undefs);
  }
}

void CgSplitEditor::extendPHIKillRanges() {
  // Extend live ranges to be live-out for successor PHI values.

  // Visit each PHI def slot in the parent live interval. If the def is dead,
  // remove it. Otherwise, extend the live interval to reach the end indexes
  // of all predecessor blocks.

  const CgLiveInterval &ParentLI = Edit->getParent();
  for (const CgVNInfo *V : ParentLI.valnos) {
    if (V->isUnused() || !V->isPHIDef())
      continue;

    unsigned RegIdx = RegAssign.lookup(V->def);
    CgLiveInterval &LI = LIS.getInterval(Edit->get(RegIdx));
    CgLiveIntervalCalc &LIC = getLICalc(RegIdx);
    CgBasicBlock &B = *LIS.getMBBFromIndex(V->def);
    if (!removeDeadSegment(V->def, LI))
      extendPHIRange(B, LIC, LI, LaneBitmask::getAll(), /*Undefs=*/{});
  }

  SmallVector<CgSlotIndex, 4> Undefs;
  CgLiveIntervalCalc SubLIC;

  for (const CgLiveInterval::SubRange &PS : ParentLI.subranges()) {
    for (const CgVNInfo *V : PS.valnos) {
      if (V->isUnused() || !V->isPHIDef())
        continue;
      unsigned RegIdx = RegAssign.lookup(V->def);
      CgLiveInterval &LI = LIS.getInterval(Edit->get(RegIdx));
      CgLiveInterval::SubRange &S = getSubRangeForMaskExact(PS.LaneMask, LI);
      if (removeDeadSegment(V->def, S))
        continue;

      CgBasicBlock &B = *LIS.getMBBFromIndex(V->def);
      SubLIC.reset(&VRM.getCgFunction(), LIS.getSlotIndexes(), &MDT,
                   &LIS.getVNInfoAllocator());
      Undefs.clear();
      LI.computeSubRangeUndefs(Undefs, PS.LaneMask, MRI, *LIS.getSlotIndexes());
      extendPHIRange(B, SubLIC, S, PS.LaneMask, Undefs);
    }
  }
}

/// rewriteAssigned - Rewrite all uses of Edit->getReg().
void CgSplitEditor::rewriteAssigned(bool ExtendRanges) {
  struct ExtPoint {
    ExtPoint(const CgOperand &O, unsigned R, CgSlotIndex N)
        : MO(O), RegIdx(R), Next(N) {}

    CgOperand MO;
    unsigned RegIdx;
    CgSlotIndex Next;
  };

  SmallVector<ExtPoint, 4> ExtPoints;

  for (CgOperand &MO :
       llvm::make_early_inc_range(MRI.reg_operands(Edit->getReg()))) {
    CgInstruction *MI = MO.getParent();
    // CgLiveDebugVariables should have handled all DBG_VALUE instructions.
    if (MI->isDebugValue()) {
      LLVM_DEBUG(dbgs() << "Zapping " << *MI);
      MO.setReg(0);
      continue;
    }

    // <undef> operands don't really read the register, so it doesn't matter
    // which register we choose.  When the use operand is tied to a def, we must
    // use the same register as the def, so just do that always.
    CgSlotIndex Idx = LIS.getInstructionIndex(*MI);
    if (MO.isDef() || MO.isUndef())
      Idx = Idx.getRegSlot(MO.isEarlyClobber());

    // Rewrite to the mapped register at Idx.
    unsigned RegIdx = RegAssign.lookup(Idx);
    CgLiveInterval &LI = LIS.getInterval(Edit->get(RegIdx));
    MO.setReg(LI.reg());
    LLVM_DEBUG(dbgs() << "  rewr " << printCgBBReference(*MI->getParent())
                      << '\t' << Idx << ':' << RegIdx << '\t' << *MI);

    // Extend liveness to Idx if the instruction reads reg.
    if (!ExtendRanges || MO.isUndef())
      continue;

    // Skip instructions that don't read Reg.
    if (MO.isDef()) {
      if (!MO.getSubReg() && !MO.isEarlyClobber())
        continue;
      // We may want to extend a live range for a partial redef, or for a use
      // tied to an early clobber.
      if (!Edit->getParent().liveAt(Idx.getPrevSlot()))
        continue;
    } else {
      assert(MO.isUse());
      bool IsEarlyClobber = false;
      if (MO.isTied()) {
        // We want to extend a live range into `e` slot rather than `r` slot if
        // tied-def is early clobber, because the `e` slot already contained
        // in the live range of early-clobber tied-def operand, give an example
        // here:
        //  0  %0 = ...
        // 16  early-clobber %0 = Op %0 (tied-def 0), ...
        // 32  ... = Op %0
        // Before extend:
        //   %0 = [0r, 0d) [16e, 32d)
        // The point we want to extend is 0d to 16e not 16r in this case, but if
        // we use 16r here we will extend nothing because that already contained
        // in [16e, 32d).
        unsigned OpIdx = MI->getOperandNo(&MO);
        unsigned DefOpIdx = MI->findTiedOperandIdx(OpIdx);
        const CgOperand &DefOp = MI->getOperand(DefOpIdx);
        IsEarlyClobber = DefOp.isEarlyClobber();
      }

      Idx = Idx.getRegSlot(IsEarlyClobber);
    }

    CgSlotIndex Next = Idx;
    if (LI.hasSubRanges()) {
      // We have to delay extending subranges until we have seen all operands
      // defining the register. This is because a <def,read-undef> operand
      // will create an "undef" point, and we cannot extend any subranges
      // until all of them have been accounted for.
      if (MO.isUse())
        ExtPoints.push_back(ExtPoint(MO, RegIdx, Next));
    } else {
      CgLiveIntervalCalc &LIC = getLICalc(RegIdx);
      LIC.extend(LI, Next, 0, ArrayRef<CgSlotIndex>());
    }
  }

  for (ExtPoint &EP : ExtPoints) {
    CgLiveInterval &LI = LIS.getInterval(Edit->get(EP.RegIdx));
    assert(LI.hasSubRanges());

    CgLiveIntervalCalc SubLIC;
    Register Reg = EP.MO.getReg(), Sub = EP.MO.getSubReg();
    LaneBitmask LM = Sub != 0 ? TRI.getSubRegIndexLaneMask(Sub)
                              : MRI.getMaxLaneMaskForVReg(Reg);
    for (CgLiveInterval::SubRange &S : LI.subranges()) {
      if ((S.LaneMask & LM).none())
        continue;
      // The problem here can be that the new register may have been created
      // for a partially defined original register. For example:
      //   %0:subreg_hireg<def,read-undef> = ...
      //   ...
      //   %1 = COPY %0
      if (S.empty())
        continue;
      SubLIC.reset(&VRM.getCgFunction(), LIS.getSlotIndexes(), &MDT,
                   &LIS.getVNInfoAllocator());
      SmallVector<CgSlotIndex, 4> Undefs;
      LI.computeSubRangeUndefs(Undefs, S.LaneMask, MRI, *LIS.getSlotIndexes());
      SubLIC.extend(S, EP.Next, 0, Undefs);
    }
  }

  for (Register R : *Edit) {
    CgLiveInterval &LI = LIS.getInterval(R);
    if (!LI.hasSubRanges())
      continue;
    LI.clear();
    LI.removeEmptySubRanges();
    LIS.constructMainRangeFromSubranges(LI);
  }
}

void CgSplitEditor::deleteRematVictims() {
  SmallVector<CgInstruction *, 8> Dead;
  for (const Register &R : *Edit) {
    CgLiveInterval *LI = &LIS.getInterval(R);
    for (const CgLiveRange::Segment &S : LI->segments) {
      // Dead defs end at the dead slot.
      if (S.end != S.valno->def.getDeadSlot())
        continue;
      if (S.valno->isPHIDef())
        continue;
      CgInstruction *MI = LIS.getInstructionFromIndex(S.valno->def);
      assert(MI && "Missing instruction for dead def");
      MI->addRegisterDead(LI->reg(), &TRI);

      if (!MI->allDefsAreDead())
        continue;

      LLVM_DEBUG(dbgs() << "All defs dead: " << *MI);
      Dead.push_back(MI);
    }
  }

  if (Dead.empty())
    return;

  Edit->eliminateDeadDefs(Dead, None);
}

void CgSplitEditor::forceRecomputeVNI(const CgVNInfo &ParentVNI) {
  // Fast-path for common case.
  if (!ParentVNI.isPHIDef()) {
    for (unsigned I = 0, E = Edit->size(); I != E; ++I)
      forceRecompute(I, ParentVNI);
    return;
  }

  // Trace value through phis.
  SmallPtrSet<const CgVNInfo *, 8> Visited; ///< whether VNI was/is in worklist.
  SmallVector<const CgVNInfo *, 4> WorkList;
  Visited.insert(&ParentVNI);
  WorkList.push_back(&ParentVNI);

  const CgLiveInterval &ParentLI = Edit->getParent();
  const CgSlotIndexes &Indexes = *LIS.getSlotIndexes();
  do {
    const CgVNInfo &VNI = *WorkList.back();
    WorkList.pop_back();
    for (unsigned I = 0, E = Edit->size(); I != E; ++I)
      forceRecompute(I, VNI);
    if (!VNI.isPHIDef())
      continue;

    CgBasicBlock &MBB = *Indexes.getMBBFromIndex(VNI.def);
    for (const CgBasicBlock *Pred : MBB.predecessors()) {
      CgSlotIndex PredEnd = Indexes.getMBBEndIdx(Pred);
      CgVNInfo *PredVNI = ParentLI.getVNInfoBefore(PredEnd);
      assert(PredVNI && "Value available in PhiVNI predecessor");
      if (Visited.insert(PredVNI).second)
        WorkList.push_back(PredVNI);
    }
  } while (!WorkList.empty());
}

void CgSplitEditor::finish(SmallVectorImpl<unsigned> *LRMap) {
  // At this point, the live intervals in Edit contain VNInfos corresponding to
  // the inserted copies.

  // Add the original defs from the parent interval.
  for (const CgVNInfo *ParentVNI : Edit->getParent().valnos) {
    if (ParentVNI->isUnused())
      continue;
    unsigned RegIdx = RegAssign.lookup(ParentVNI->def);
    defValue(RegIdx, ParentVNI, ParentVNI->def, true);

    // Force rematted values to be recomputed everywhere.
    // The new live ranges may be truncated.
    if (Edit->didRematerialize(ParentVNI))
      forceRecomputeVNI(*ParentVNI);
  }

  // Hoist back-copies to the complement interval when in spill mode.
  switch (SpillMode) {
  case SM_Partition:
    // Leave all back-copies as is.
    break;
  case SM_Size:
  case SM_Speed:
    // hoistCopies will behave differently between size and speed.
    hoistCopies();
  }

  // Transfer the simply mapped values, check if any are skipped.
  bool Skipped = transferValues();

  // Rewrite virtual registers, possibly extending ranges.
  rewriteAssigned(Skipped);

  if (Skipped)
    extendPHIKillRanges();

  // Delete defs that were rematted everywhere.
  if (Skipped)
    deleteRematVictims();

  // Get rid of unused values and set phi-kill flags.
  for (Register Reg : *Edit) {
    CgLiveInterval &LI = LIS.getInterval(Reg);
    LI.removeEmptySubRanges();
    LI.RenumberValues();
  }

  // Provide a reverse mapping from original indices to Edit ranges.
  if (LRMap) {
    auto Seq = llvm::seq<unsigned>(0, Edit->size());
    LRMap->assign(Seq.begin(), Seq.end());
  }

  // Now check if any registers were separated into multiple components.
  ConnectedVNInfoEqClasses ConEQ(LIS);
  for (unsigned i = 0, e = Edit->size(); i != e; ++i) {
    // Don't use iterators, they are invalidated by create() below.
    Register VReg = Edit->get(i);
    CgLiveInterval &LI = LIS.getInterval(VReg);
    SmallVector<CgLiveInterval *, 8> SplitLIs;
    LIS.splitSeparateComponents(LI, SplitLIs);
    Register Original = VRM.getOriginal(VReg);
    for (CgLiveInterval *SplitLI : SplitLIs)
      VRM.setIsSplitFromReg(SplitLI->reg(), Original);

    // The new intervals all map back to i.
    if (LRMap)
      LRMap->resize(Edit->size(), i);
  }

  // Calculate spill weight and allocation hints for new intervals.
  Edit->calculateRegClassAndHint(VRM.getCgFunction(), VRAI);

  assert(!LRMap || LRMap->size() == Edit->size());
}

//===----------------------------------------------------------------------===//
//                            Single Block Splitting
//===----------------------------------------------------------------------===//

bool CgSplitAnalysis::shouldSplitSingleBlock(const BlockInfo &BI,
                                             bool SingleInstrs) const {
  // Always split for multiple instructions.
  if (!BI.isOneInstr())
    return true;
  // Don't split for single instructions unless explicitly requested.
  if (!SingleInstrs)
    return false;
  // Splitting a live-through range always makes progress.
  if (BI.LiveIn && BI.LiveOut)
    return true;
  // No point in isolating a copy. It has no register class constraints.
  if (LIS.getInstructionFromIndex(BI.FirstInstr)->isCopyLike())
    return false;
  // Finally, don't isolate an end point that was created by earlier splits.
  return isOriginalEndpoint(BI.FirstInstr);
}

void CgSplitEditor::splitSingleBlock(const CgSplitAnalysis::BlockInfo &BI) {
  openIntv();
  CgSlotIndex LastSplitPoint = SA.getLastSplitPoint(BI.MBB);
  CgSlotIndex SegStart =
      enterIntvBefore(std::min(BI.FirstInstr, LastSplitPoint));
  if (!BI.LiveOut || BI.LastInstr < LastSplitPoint) {
    useIntv(SegStart, leaveIntvAfter(BI.LastInstr));
  } else {
    // The last use is after the last valid split point.
    CgSlotIndex SegStop = leaveIntvBefore(LastSplitPoint);
    useIntv(SegStart, SegStop);
    overlapIntv(SegStop, BI.LastInstr);
  }
}

//===----------------------------------------------------------------------===//
//                    Global Live Range Splitting Support
//===----------------------------------------------------------------------===//

// These methods support a method of global live range splitting that uses a
// global algorithm to decide intervals for CFG edges. They will insert split
// points and color intervals in basic blocks while avoiding interference.
//
// Note that splitSingleBlock is also useful for blocks where both CFG edges
// are on the stack.

void CgSplitEditor::splitLiveThroughBlock(unsigned MBBNum, unsigned IntvIn,
                                          CgSlotIndex LeaveBefore,
                                          unsigned IntvOut,
                                          CgSlotIndex EnterAfter) {
  CgSlotIndex Start, Stop;
  std::tie(Start, Stop) = LIS.getSlotIndexes()->getMBBRange(MBBNum);

  LLVM_DEBUG(dbgs() << "%bb." << MBBNum << " [" << Start << ';' << Stop
                    << ") intf " << LeaveBefore << '-' << EnterAfter
                    << ", live-through " << IntvIn << " -> " << IntvOut);

  assert((IntvIn || IntvOut) && "Use splitSingleBlock for isolated blocks");

  assert((!LeaveBefore || LeaveBefore < Stop) && "Interference after block");
  assert((!IntvIn || !LeaveBefore || LeaveBefore > Start) && "Impossible intf");
  assert((!EnterAfter || EnterAfter >= Start) && "Interference before block");

  CgBasicBlock *MBB = VRM.getCgFunction().getBlockNumbered(MBBNum);

  if (!IntvOut) {
    LLVM_DEBUG(dbgs() << ", spill on entry.\n");
    //
    //        <<<<<<<<<    Possible LeaveBefore interference.
    //    |-----------|    Live through.
    //    -____________    Spill on entry.
    //
    selectIntv(IntvIn);
    CgSlotIndex Idx = leaveIntvAtTop(*MBB);
    assert((!LeaveBefore || Idx <= LeaveBefore) && "Interference");
    (void)Idx;
    return;
  }

  if (!IntvIn) {
    LLVM_DEBUG(dbgs() << ", reload on exit.\n");
    //
    //    >>>>>>>          Possible EnterAfter interference.
    //    |-----------|    Live through.
    //    ___________--    Reload on exit.
    //
    selectIntv(IntvOut);
    CgSlotIndex Idx = enterIntvAtEnd(*MBB);
    assert((!EnterAfter || Idx >= EnterAfter) && "Interference");
    (void)Idx;
    return;
  }

  if (IntvIn == IntvOut && !LeaveBefore && !EnterAfter) {
    LLVM_DEBUG(dbgs() << ", straight through.\n");
    //
    //    |-----------|    Live through.
    //    -------------    Straight through, same intv, no interference.
    //
    selectIntv(IntvOut);
    useIntv(Start, Stop);
    return;
  }

  // We cannot legally insert splits after LSP.
  CgSlotIndex LSP = SA.getLastSplitPoint(MBBNum);
  assert((!IntvOut || !EnterAfter || EnterAfter < LSP) && "Impossible intf");

  if (IntvIn != IntvOut &&
      (!LeaveBefore || !EnterAfter ||
       LeaveBefore.getBaseIndex() > EnterAfter.getBoundaryIndex())) {
    LLVM_DEBUG(dbgs() << ", switch avoiding interference.\n");
    //
    //    >>>>     <<<<    Non-overlapping EnterAfter/LeaveBefore interference.
    //    |-----------|    Live through.
    //    ------=======    Switch intervals between interference.
    //
    selectIntv(IntvOut);
    CgSlotIndex Idx;
    if (LeaveBefore && LeaveBefore < LSP) {
      Idx = enterIntvBefore(LeaveBefore);
      useIntv(Idx, Stop);
    } else {
      Idx = enterIntvAtEnd(*MBB);
    }
    selectIntv(IntvIn);
    useIntv(Start, Idx);
    assert((!LeaveBefore || Idx <= LeaveBefore) && "Interference");
    assert((!EnterAfter || Idx >= EnterAfter) && "Interference");
    return;
  }

  LLVM_DEBUG(dbgs() << ", create local intv for interference.\n");
  //
  //    >>><><><><<<<    Overlapping EnterAfter/LeaveBefore interference.
  //    |-----------|    Live through.
  //    ==---------==    Switch intervals before/after interference.
  //
  assert(LeaveBefore <= EnterAfter && "Missed case");

  selectIntv(IntvOut);
  CgSlotIndex Idx = enterIntvAfter(EnterAfter);
  useIntv(Idx, Stop);
  assert((!EnterAfter || Idx >= EnterAfter) && "Interference");

  selectIntv(IntvIn);
  Idx = leaveIntvBefore(LeaveBefore);
  useIntv(Start, Idx);
  assert((!LeaveBefore || Idx <= LeaveBefore) && "Interference");
}

void CgSplitEditor::splitRegInBlock(const CgSplitAnalysis::BlockInfo &BI,
                                    unsigned IntvIn, CgSlotIndex LeaveBefore) {
  CgSlotIndex Start, Stop;
  std::tie(Start, Stop) = LIS.getSlotIndexes()->getMBBRange(BI.MBB);

  LLVM_DEBUG(dbgs() << printCgBBReference(*BI.MBB) << " [" << Start << ';'
                    << Stop << "), uses " << BI.FirstInstr << '-'
                    << BI.LastInstr << ", reg-in " << IntvIn
                    << ", leave before " << LeaveBefore
                    << (BI.LiveOut ? ", stack-out" : ", killed in block"));

  assert(IntvIn && "Must have register in");
  assert(BI.LiveIn && "Must be live-in");
  assert((!LeaveBefore || LeaveBefore > Start) && "Bad interference");

  if (!BI.LiveOut && (!LeaveBefore || LeaveBefore >= BI.LastInstr)) {
    LLVM_DEBUG(dbgs() << " before interference.\n");
    //
    //               <<<    Interference after kill.
    //     |---o---x   |    Killed in block.
    //     =========        Use IntvIn everywhere.
    //
    selectIntv(IntvIn);
    useIntv(Start, BI.LastInstr);
    return;
  }

  CgSlotIndex LSP = SA.getLastSplitPoint(BI.MBB);

  if (!LeaveBefore || LeaveBefore > BI.LastInstr.getBoundaryIndex()) {
    //
    //               <<<    Possible interference after last use.
    //     |---o---o---|    Live-out on stack.
    //     =========____    Leave IntvIn after last use.
    //
    //                 <    Interference after last use.
    //     |---o---o--o|    Live-out on stack, late last use.
    //     ============     Copy to stack after LSP, overlap IntvIn.
    //            \_____    Stack interval is live-out.
    //
    if (BI.LastInstr < LSP) {
      LLVM_DEBUG(dbgs() << ", spill after last use before interference.\n");
      selectIntv(IntvIn);
      CgSlotIndex Idx = leaveIntvAfter(BI.LastInstr);
      useIntv(Start, Idx);
      assert((!LeaveBefore || Idx <= LeaveBefore) && "Interference");
    } else {
      LLVM_DEBUG(dbgs() << ", spill before last split point.\n");
      selectIntv(IntvIn);
      CgSlotIndex Idx = leaveIntvBefore(LSP);
      overlapIntv(Idx, BI.LastInstr);
      useIntv(Start, Idx);
      assert((!LeaveBefore || Idx <= LeaveBefore) && "Interference");
    }
    return;
  }

  // The interference is overlapping somewhere we wanted to use IntvIn. That
  // means we need to create a local interval that can be allocated a
  // different register.
  unsigned LocalIntv = openIntv();
  (void)LocalIntv;
  LLVM_DEBUG(dbgs() << ", creating local interval " << LocalIntv << ".\n");

  if (!BI.LiveOut || BI.LastInstr < LSP) {
    //
    //           <<<<<<<    Interference overlapping uses.
    //     |---o---o---|    Live-out on stack.
    //     =====----____    Leave IntvIn before interference, then spill.
    //
    CgSlotIndex To = leaveIntvAfter(BI.LastInstr);
    CgSlotIndex From = enterIntvBefore(LeaveBefore);
    useIntv(From, To);
    selectIntv(IntvIn);
    useIntv(Start, From);
    assert((!LeaveBefore || From <= LeaveBefore) && "Interference");
    return;
  }

  //           <<<<<<<    Interference overlapping uses.
  //     |---o---o--o|    Live-out on stack, late last use.
  //     =====-------     Copy to stack before LSP, overlap LocalIntv.
  //            \_____    Stack interval is live-out.
  //
  CgSlotIndex To = leaveIntvBefore(LSP);
  overlapIntv(To, BI.LastInstr);
  CgSlotIndex From = enterIntvBefore(std::min(To, LeaveBefore));
  useIntv(From, To);
  selectIntv(IntvIn);
  useIntv(Start, From);
  assert((!LeaveBefore || From <= LeaveBefore) && "Interference");
}

void CgSplitEditor::splitRegOutBlock(const CgSplitAnalysis::BlockInfo &BI,
                                     unsigned IntvOut, CgSlotIndex EnterAfter) {
  CgSlotIndex Start, Stop;
  std::tie(Start, Stop) = LIS.getSlotIndexes()->getMBBRange(BI.MBB);

  LLVM_DEBUG(dbgs() << printCgBBReference(*BI.MBB) << " [" << Start << ';'
                    << Stop << "), uses " << BI.FirstInstr << '-'
                    << BI.LastInstr << ", reg-out " << IntvOut
                    << ", enter after " << EnterAfter
                    << (BI.LiveIn ? ", stack-in" : ", defined in block"));

  CgSlotIndex LSP = SA.getLastSplitPoint(BI.MBB);

  assert(IntvOut && "Must have register out");
  assert(BI.LiveOut && "Must be live-out");
  assert((!EnterAfter || EnterAfter < LSP) && "Bad interference");

  if (!BI.LiveIn && (!EnterAfter || EnterAfter <= BI.FirstInstr)) {
    LLVM_DEBUG(dbgs() << " after interference.\n");
    //
    //    >>>>             Interference before def.
    //    |   o---o---|    Defined in block.
    //        =========    Use IntvOut everywhere.
    //
    selectIntv(IntvOut);
    useIntv(BI.FirstInstr, Stop);
    return;
  }

  if (!EnterAfter || EnterAfter < BI.FirstInstr.getBaseIndex()) {
    LLVM_DEBUG(dbgs() << ", reload after interference.\n");
    //
    //    >>>>             Interference before def.
    //    |---o---o---|    Live-through, stack-in.
    //    ____=========    Enter IntvOut before first use.
    //
    selectIntv(IntvOut);
    CgSlotIndex Idx = enterIntvBefore(std::min(LSP, BI.FirstInstr));
    useIntv(Idx, Stop);
    assert((!EnterAfter || Idx >= EnterAfter) && "Interference");
    return;
  }

  // The interference is overlapping somewhere we wanted to use IntvOut. That
  // means we need to create a local interval that can be allocated a
  // different register.
  LLVM_DEBUG(dbgs() << ", interference overlaps uses.\n");
  //
  //    >>>>>>>          Interference overlapping uses.
  //    |---o---o---|    Live-through, stack-in.
  //    ____---======    Create local interval for interference range.
  //
  selectIntv(IntvOut);
  CgSlotIndex Idx = enterIntvAfter(EnterAfter);
  useIntv(Idx, Stop);
  assert((!EnterAfter || Idx >= EnterAfter) && "Interference");

  openIntv();
  CgSlotIndex From = enterIntvBefore(std::min(Idx, BI.FirstInstr));
  useIntv(From, Idx);
}

void CgSplitAnalysis::BlockInfo::print(raw_ostream &OS) const {
  OS << "{" << printCgBBReference(*MBB) << ", "
     << "uses " << FirstInstr << " to " << LastInstr << ", "
     << "1st def " << FirstDef << ", " << (LiveIn ? "live in" : "dead in")
     << ", " << (LiveOut ? "live out" : "dead out") << "}";
}

void CgSplitAnalysis::BlockInfo::dump() const {
  print(dbgs());
  dbgs() << "\n";
}
