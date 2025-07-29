
//===- InlineSpiller.cpp - Insert spills and restores inline --------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// The inline spiller modifies the machine function directly instead of
// inserting spills and restores in CgVirtRegMap.
//
//===----------------------------------------------------------------------===//

#include "compiler/cgir/pass/cg_spiller.h"
#include "compiler/cgir/pass/cg_split_kit.h"
#include "compiler/cgir/pass/live_interval.h"
#include "compiler/cgir/pass/live_intervals.h"
#include "compiler/cgir/pass/live_range_edit.h"
#include "compiler/cgir/pass/live_stacks.h"
#include "compiler/cgir/pass/slot_indexes.h"
#include "compiler/cgir/pass/virt_reg_map.h"
#include "compiler/context.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/MapVector.h"
#include "llvm/ADT/None.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SetVector.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/TargetOpcodes.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/Support/BlockFrequency.h"
#include "llvm/Support/BranchProbability.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include <cassert>
#include <iterator>
#include <tuple>
#include <utility>
#include <vector>

using namespace llvm;
using namespace COMPILER;

#define DEBUG_TYPE "regalloc"

namespace {

class HoistSpillHelper : private CgLiveRangeEdit::Delegate {
  CgFunction &MF;
  CgLiveIntervals &LIS;
  CgLiveStacks &LSS;
  CgDominatorTree &MDT;
  CgLoopInfo &Loops;
  CgVirtRegMap &VRM;
  CgRegisterInfo &MRI;
  const TargetInstrInfo &TII;
  const TargetRegisterInfo &TRI;
  const CgBlockFrequencyInfo &MBFI;

  CgInsertPointAnalysis IPA;
  LLVMWorkaround *_llvm_workaround;

  // Map from StackSlot to the CgLiveInterval of the original register.
  // Note the CgLiveInterval of the original register may have been deleted
  // after it is spilled. We keep a copy here to track the range where
  // spills can be moved.
  DenseMap<int, std::unique_ptr<CgLiveInterval>> StackSlotToOrigLI;

  // Map from pair of (StackSlot and Original VNI) to a set of spills which
  // have the same stackslot and have equal values defined by Original VNI.
  // These spills are mergeable and are hoist candiates.
  using MergeableSpillsMap =
      MapVector<std::pair<int, CgVNInfo *>, SmallPtrSet<CgInstruction *, 16>>;
  MergeableSpillsMap MergeableSpills;

  /// This is the map from original register to a set containing all its
  /// siblings. To hoist a spill to another BB, we need to find out a live
  /// sibling there and use it as the source of the new spill.
  DenseMap<Register, SmallSetVector<Register, 16>> Virt2SiblingsMap;

  bool isSpillCandBB(CgLiveInterval &OrigLI, CgVNInfo &OrigVNI,
                     CgBasicBlock &BB, Register &LiveReg);

  void
  rmRedundantSpills(SmallPtrSet<CgInstruction *, 16> &Spills,
                    SmallVectorImpl<CgInstruction *> &SpillsToRm,
                    DenseMap<CgDomTreeNode *, CgInstruction *> &SpillBBToSpill);

  void
  getVisitOrders(CgBasicBlock *Root, SmallPtrSet<CgInstruction *, 16> &Spills,
                 SmallVectorImpl<CgDomTreeNode *> &Orders,
                 SmallVectorImpl<CgInstruction *> &SpillsToRm,
                 DenseMap<CgDomTreeNode *, unsigned> &SpillsToKeep,
                 DenseMap<CgDomTreeNode *, CgInstruction *> &SpillBBToSpill);

  void runHoistSpills(CgLiveInterval &OrigLI, CgVNInfo &OrigVNI,
                      SmallPtrSet<CgInstruction *, 16> &Spills,
                      SmallVectorImpl<CgInstruction *> &SpillsToRm,
                      DenseMap<CgBasicBlock *, unsigned> &SpillsToIns);

public:
  HoistSpillHelper(CgFunction &mf, CgVirtRegMap &vrm)
      : MF(mf), LIS(*MF.LIS), LSS(*MF.LSS), MDT(*MF.DomTree), Loops(*MF.Loops),
        VRM(vrm), MRI(mf.getRegInfo()), TII(*mf.getSubtarget().getInstrInfo()),
        TRI(*mf.getSubtarget().getRegisterInfo()), MBFI(*MF.MBFI),
        IPA(LIS, mf.getNumBlockIDs()),
        _llvm_workaround(&MF.getContext().getLLVMWorkaround()) {}

  void addToMergeableSpills(CgInstruction &Spill, int StackSlot,
                            unsigned Original);
  bool rmFromMergeableSpills(CgInstruction &Spill, int StackSlot);
  void hoistAllSpills();
  void LRE_DidCloneVirtReg(Register, Register) override;
};

class InlineSpiller : public CgSpiller {
  CgFunction &MF;
  CgLiveIntervals &LIS;
  CgLiveStacks &LSS;
  CgDominatorTree &MDT;
  CgLoopInfo &Loops;
  CgVirtRegMap &VRM;
  CgRegisterInfo &MRI;
  const TargetInstrInfo &TII;
  const TargetRegisterInfo &TRI;
  const CgBlockFrequencyInfo &MBFI;

  // Variables that are valid during spill(), but used by multiple methods.
  CgLiveRangeEdit *Edit = nullptr;
  CgLiveInterval *StackInt = nullptr;
  int StackSlot = 0;
  Register Original;

  // All registers to spill to StackSlot, including the main register.
  SmallVector<Register, 8> RegsToSpill;

  // All COPY instructions to/from snippets.
  // They are ignored since both operands refer to the same stack slot.
  SmallPtrSet<CgInstruction *, 8> SnippetCopies;

  // Values that failed to remat at some point.
  SmallPtrSet<CgVNInfo *, 8> UsedValues;

  // Dead defs generated during spilling.
  SmallVector<CgInstruction *, 8> DeadDefs;

  // Object records spills information and does the hoisting.
  HoistSpillHelper HSpiller;

  // Live range weight calculator.
  CgVirtRegAuxInfo &VRAI;

  LLVMWorkaround *_llvm_workaround = nullptr;

  ~InlineSpiller() override = default;

public:
  InlineSpiller(CgFunction &MF, CgVirtRegMap &VRM, CgVirtRegAuxInfo &VRAI)
      : MF(MF), LIS(*MF.LIS), LSS(*MF.LSS), MDT(*MF.DomTree), Loops(*MF.Loops),
        VRM(VRM), MRI(MF.getRegInfo()), TII(*MF.getSubtarget().getInstrInfo()),
        TRI(*MF.getSubtarget().getRegisterInfo()), MBFI(*MF.MBFI),
        HSpiller(MF, VRM), VRAI(VRAI),
        _llvm_workaround(&MF.getContext().getLLVMWorkaround()) {}

  void spill(CgLiveRangeEdit &) override;
  void postOptimization() override;

private:
  bool isSnippet(const CgLiveInterval &SnipLI);
  void collectRegsToSpill();

  bool isRegToSpill(Register Reg) { return is_contained(RegsToSpill, Reg); }

  bool isSibling(Register Reg);
  bool hoistSpillInsideBB(CgLiveInterval &SpillLI, CgInstruction &CopyMI);
  void eliminateRedundantSpills(CgLiveInterval &LI, CgVNInfo *VNI);

  void markValueUsed(CgLiveInterval *, CgVNInfo *);
  bool canGuaranteeAssignmentAfterRemat(Register VReg, CgInstruction &MI);
  bool reMaterializeFor(CgLiveInterval &, CgInstruction &MI);
  void reMaterializeAll();

  bool coalesceStackAccess(CgInstruction *MI, Register Reg);
  bool foldMemoryOperand(ArrayRef<std::pair<CgInstruction *, unsigned>>,
                         CgInstruction *LoadMI = nullptr);
  void insertReload(Register VReg, CgSlotIndex, CgBasicBlock::iterator MI);
  void insertSpill(Register VReg, bool isKill, CgBasicBlock::iterator MI);

  void spillAroundUses(Register Reg);
  void spillAll();
};

} // end anonymous namespace

CgSpiller::~CgSpiller() = default;

void CgSpiller::anchor() {}

CgSpiller *COMPILER::cgCreateInlineSpiller(CgFunction &MF, CgVirtRegMap &VRM,
                                           CgVirtRegAuxInfo &VRAI) {
  return new InlineSpiller(MF, VRM, VRAI);
}

//===----------------------------------------------------------------------===//
//                                Snippets
//===----------------------------------------------------------------------===//

// When spilling a virtual register, we also spill any snippets it is connected
// to. The snippets are small live ranges that only have a single real use,
// leftovers from live range splitting. Spilling them enables memory operand
// folding or tightens the live range around the single use.
//
// This minimizes register pressure and maximizes the store-to-load distance for
// spill slots which can be important in tight loops.

/// isFullCopyOf - If MI is a COPY to or from Reg, return the other register,
/// otherwise return 0.
static Register isFullCopyOf(const CgInstruction &MI, Register Reg) {
  if (!MI.isFullCopy())
    return Register();
  if (MI.getOperand(0).getReg() == Reg)
    return MI.getOperand(1).getReg();
  if (MI.getOperand(1).getReg() == Reg)
    return MI.getOperand(0).getReg();
  return Register();
}

static void getVDefInterval(const CgInstruction &MI, CgLiveIntervals &LIS) {
  for (const CgOperand &MO : MI.operands())
    if (MO.isReg() && MO.isDef() && Register::isVirtualRegister(MO.getReg()))
      LIS.getInterval(MO.getReg());
}

/// isSnippet - Identify if a live interval is a snippet that should be spilled.
/// It is assumed that SnipLI is a virtual register with the same original as
/// Edit->getReg().
bool InlineSpiller::isSnippet(const CgLiveInterval &SnipLI) {
  Register Reg = Edit->getReg();

  // A snippet is a tiny live range with only a single instruction using it
  // besides copies to/from Reg or spills/fills. We accept:
  //
  //   %snip = COPY %Reg / FILL fi#
  //   %snip = USE %snip
  //   %Reg = COPY %snip / SPILL %snip, fi#
  //
  if (SnipLI.getNumValNums() > 2 || !LIS.intervalIsInOneMBB(SnipLI))
    return false;

  CgInstruction *UseMI = nullptr;

  // Check that all uses satisfy our criteria.
  for (CgRegisterInfo::reg_instr_nodbg_iterator
           RI = MRI.reg_instr_nodbg_begin(SnipLI.reg()),
           E = MRI.reg_instr_nodbg_end();
       RI != E;) {
    CgInstruction &MI = *RI++;

    // Allow copies to/from Reg.
    if (isFullCopyOf(MI, Reg))
      continue;

    // Allow stack slot loads.
    int FI;
    if (SnipLI.reg() == _llvm_workaround->isLoadFromStackSlot(TII, MI, FI) &&
        FI == StackSlot)
      continue;

    // Allow stack slot stores.
    if (SnipLI.reg() == _llvm_workaround->isStoreToStackSlot(TII, MI, FI) &&
        FI == StackSlot)
      continue;

    // Allow a single additional instruction.
    if (UseMI && &MI != UseMI)
      return false;
    UseMI = &MI;
  }
  return true;
}

/// collectRegsToSpill - Collect live range snippets that only have a single
/// real use.
void InlineSpiller::collectRegsToSpill() {
  Register Reg = Edit->getReg();

  // Main register always spills.
  RegsToSpill.assign(1, Reg);
  SnippetCopies.clear();

  // Snippets all have the same original, so there can't be any for an
  // original register.
  if (Original == Reg)
    return;

  for (CgInstruction &MI :
       llvm::make_early_inc_range(MRI.reg_instructions(Reg))) {
    Register SnipReg = isFullCopyOf(MI, Reg);
    if (!isSibling(SnipReg))
      continue;
    CgLiveInterval &SnipLI = LIS.getInterval(SnipReg);
    if (!isSnippet(SnipLI))
      continue;
    SnippetCopies.insert(&MI);
    if (isRegToSpill(SnipReg))
      continue;
    RegsToSpill.push_back(SnipReg);
    LLVM_DEBUG(dbgs() << "\talso spill snippet " << SnipLI << '\n');
  }
}

bool InlineSpiller::isSibling(Register Reg) {
  return Reg.isVirtual() && VRM.getOriginal(Reg) == Original;
}

/// It is beneficial to spill to earlier place in the same BB in case
/// as follows:
/// There is an alternative def earlier in the same MBB.
/// Hoist the spill as far as possible in SpillMBB. This can ease
/// register pressure:
///
///   x = def
///   y = use x
///   s = copy x
///
/// Hoisting the spill of s to immediately after the def removes the
/// interference between x and y:
///
///   x = def
///   spill x
///   y = use killed x
///
/// This hoist only helps when the copy kills its source.
///
bool InlineSpiller::hoistSpillInsideBB(CgLiveInterval &SpillLI,
                                       CgInstruction &CopyMI) {
  CgSlotIndex Idx = LIS.getInstructionIndex(CopyMI);
#ifndef NDEBUG
  CgVNInfo *VNI = SpillLI.getVNInfoAt(Idx.getRegSlot());
  assert(VNI && VNI->def == Idx.getRegSlot() && "Not defined by copy");
#endif

  Register SrcReg = CopyMI.getOperand(1).getReg();
  CgLiveInterval &SrcLI = LIS.getInterval(SrcReg);
  CgVNInfo *SrcVNI = SrcLI.getVNInfoAt(Idx);
  CgLiveQueryResult SrcQ = SrcLI.Query(Idx);
  CgBasicBlock *DefMBB = LIS.getMBBFromIndex(SrcVNI->def);
  if (DefMBB != CopyMI.getParent() || !SrcQ.isKill())
    return false;

  // Conservatively extend the stack slot range to the range of the original
  // value. We may be able to do better with stack slot coloring by being more
  // careful here.
  assert(StackInt && "No stack slot assigned yet.");
  CgLiveInterval &OrigLI = LIS.getInterval(Original);
  CgVNInfo *OrigVNI = OrigLI.getVNInfoAt(Idx);
  StackInt->MergeValueInAsValue(OrigLI, OrigVNI, StackInt->getValNumInfo(0));
  LLVM_DEBUG(dbgs() << "\tmerged orig valno " << OrigVNI->id << ": "
                    << *StackInt << '\n');

  // We are going to spill SrcVNI immediately after its def, so clear out
  // any later spills of the same value.
  eliminateRedundantSpills(SrcLI, SrcVNI);

  CgBasicBlock *MBB = LIS.getMBBFromIndex(SrcVNI->def);
  CgBasicBlock::iterator MII;
  if (SrcVNI->isPHIDef())
    MII = MBB->SkipPHIsLabelsAndDebug(MBB->begin());
  else {
    CgInstruction *DefMI = LIS.getInstructionFromIndex(SrcVNI->def);
    assert(DefMI && "Defining instruction disappeared");
    MII = CgBasicBlock::iterator(DefMI);
    ++MII;
  }
  CgInstrSpan MIS(MII, MBB);
  // Insert spill without kill flag immediately after def.
  _llvm_workaround->storeRegToStackSlot(
      TII, *MBB, MII, SrcReg, false, StackSlot, MRI.getRegClass(SrcReg), &TRI);
  LIS.InsertMachineInstrRangeInMaps(MIS.begin(), MII);
  for (const CgInstruction &MI : make_range(MIS.begin(), MII))
    getVDefInterval(MI, LIS);
  --MII; // Point to store instruction.
  LLVM_DEBUG(dbgs() << "\thoisted: " << SrcVNI->def << '\t' << *MII);

  // If there is only 1 store instruction is required for spill, add it
  // to mergeable list. In X86 AMX, 2 intructions are required to store.
  // We disable the merge for this case.
  if (MIS.begin() == MII)
    HSpiller.addToMergeableSpills(*MII, StackSlot, Original);
  return true;
}

/// eliminateRedundantSpills - SLI:VNI is known to be on the stack. Remove any
/// redundant spills of this value in SLI.reg and sibling copies.
void InlineSpiller::eliminateRedundantSpills(CgLiveInterval &SLI,
                                             CgVNInfo *VNI) {
  assert(VNI && "Missing value");
  SmallVector<std::pair<CgLiveInterval *, CgVNInfo *>, 8> WorkList;
  WorkList.push_back(std::make_pair(&SLI, VNI));
  assert(StackInt && "No stack slot assigned yet.");

  do {
    CgLiveInterval *LI;
    std::tie(LI, VNI) = WorkList.pop_back_val();
    Register Reg = LI->reg();
    LLVM_DEBUG(dbgs() << "Checking redundant spills for " << VNI->id << '@'
                      << VNI->def << " in " << *LI << '\n');

    // Regs to spill are taken care of.
    if (isRegToSpill(Reg))
      continue;

    // Add all of VNI's live range to StackInt.
    StackInt->MergeValueInAsValue(*LI, VNI, StackInt->getValNumInfo(0));
    LLVM_DEBUG(dbgs() << "Merged to stack int: " << *StackInt << '\n');

    // Find all spills and copies of VNI.
    for (CgInstruction &MI :
         llvm::make_early_inc_range(MRI.use_nodbg_instructions(Reg))) {
      if (!MI.isCopy() && !MI.mayStore())
        continue;
      CgSlotIndex Idx = LIS.getInstructionIndex(MI);
      if (LI->getVNInfoAt(Idx) != VNI)
        continue;

      // Follow sibling copies down the dominator tree.
      if (Register DstReg = isFullCopyOf(MI, Reg)) {
        if (isSibling(DstReg)) {
          CgLiveInterval &DstLI = LIS.getInterval(DstReg);
          CgVNInfo *DstVNI = DstLI.getVNInfoAt(Idx.getRegSlot());
          assert(DstVNI && "Missing defined value");
          assert(DstVNI->def == Idx.getRegSlot() && "Wrong copy def slot");
          WorkList.push_back(std::make_pair(&DstLI, DstVNI));
        }
        continue;
      }

      // Erase spills.
      int FI;
      if (Reg == _llvm_workaround->isStoreToStackSlot(TII, MI, FI) &&
          FI == StackSlot) {
        LLVM_DEBUG(dbgs() << "Redundant spill " << Idx << '\t' << MI);
        // eliminateDeadDefs won't normally remove stores, so switch
        // opcode.
        MI.setDesc(TII.get(TargetOpcode::KILL));
        DeadDefs.push_back(&MI);
      }
    }
  } while (!WorkList.empty());
}

//===----------------------------------------------------------------------===//
//                            Rematerialization
//===----------------------------------------------------------------------===//

/// markValueUsed - Remember that VNI failed to rematerialize, so its defining
/// instruction cannot be eliminated. See through snippet copies
void InlineSpiller::markValueUsed(CgLiveInterval *LI, CgVNInfo *VNI) {
  SmallVector<std::pair<CgLiveInterval *, CgVNInfo *>, 8> WorkList;
  WorkList.push_back(std::make_pair(LI, VNI));
  do {
    std::tie(LI, VNI) = WorkList.pop_back_val();
    if (!UsedValues.insert(VNI).second)
      continue;

    if (VNI->isPHIDef()) {
      CgBasicBlock *MBB = LIS.getMBBFromIndex(VNI->def);
      for (CgBasicBlock *P : MBB->predecessors()) {
        CgVNInfo *PVNI = LI->getVNInfoBefore(LIS.getMBBEndIdx(P));
        if (PVNI)
          WorkList.push_back(std::make_pair(LI, PVNI));
      }
      continue;
    }

    // Follow snippet copies.
    CgInstruction *MI = LIS.getInstructionFromIndex(VNI->def);
    if (!SnippetCopies.count(MI))
      continue;
    CgLiveInterval &SnipLI = LIS.getInterval(MI->getOperand(1).getReg());
    assert(isRegToSpill(SnipLI.reg()) && "Unexpected register in copy");
    CgVNInfo *SnipVNI = SnipLI.getVNInfoAt(VNI->def.getRegSlot(true));
    assert(SnipVNI && "Snippet undefined before copy");
    WorkList.push_back(std::make_pair(&SnipLI, SnipVNI));
  } while (!WorkList.empty());
}

bool InlineSpiller::canGuaranteeAssignmentAfterRemat(Register VReg,
                                                     CgInstruction &MI) {
  // Here's a quick explanation of the problem we're trying to handle here:
  // * There are some pseudo instructions with more vreg uses than there are
  //   physical registers on the machine.
  // * This is normally handled by spilling the vreg, and folding the reload
  //   into the user instruction.  (Thus decreasing the number of used vregs
  //   until the remainder can be assigned to physregs.)
  // * However, since we may try to spill vregs in any order, we can end up
  //   trying to spill each operand to the instruction, and then rematting it
  //   instead.  When that happens, the new live intervals (for the remats)
  //   are expected to be trivially assignable (i.e. RS_Done).  However, since
  //   we may have more remats than physregs, we're guaranteed to fail to
  //   assign one.
  // At the moment, we only handle this for STATEPOINTs since they're the only
  // pseudo op where we've seen this.  If we start seeing other instructions
  // with the same problem, we need to revisit this.
  if (MI.getOpcode() != TargetOpcode::STATEPOINT)
    return true;
    // For STATEPOINTs we allow re-materialization for fixed arguments only
    // hoping that number of physical registers is enough to cover all fixed
    // arguments. If it is not true we need to revisit it.
#if 0
    for (unsigned Idx = StatepointOpers(&MI).getVarIdx(),
                  EndIdx = MI.getNumOperands();
         Idx < EndIdx; ++Idx) {
        CgOperand &MO = MI.getOperand(Idx);
        if (MO.isReg() && MO.getReg() == VReg)
            return false;
    }
#endif
  return true;
}

static VirtRegInfo CgAnalyzeVirtRegInBundle(
    CgInstruction &MI, Register Reg,
    SmallVectorImpl<std::pair<CgInstruction *, unsigned>> *Ops) {
  VirtRegInfo RI = {false, false, false};
  //  for (MIBundleOperands O(MI); O.isValid(); ++O) {
  for (auto I = MI.begin(), E = MI.end(); I != E; ++I) {
    auto &MO = *I;
    if (!MO.isReg() || MO.getReg() != Reg)
      continue;

    // Remember each (MI, OpNo) that refers to Reg.
    if (Ops)
      Ops->push_back(std::make_pair(MO.getParent(), &(*I) - &(*MI.begin())));

    // Both defs and uses can read virtual registers.
    if (MO.readsReg()) {
      RI.Reads = true;
      if (MO.isDef())
        RI.Tied = true;
    }

    // Only defs can write.
    if (MO.isDef())
      RI.Writes = true;
    else if (!RI.Tied &&
             MO.getParent()->isRegTiedToDefOperand(&(*I) - &(*MI.begin())))
      RI.Tied = true;
  }
  return RI;
}

/// reMaterializeFor - Attempt to rematerialize before MI instead of reloading.
bool InlineSpiller::reMaterializeFor(CgLiveInterval &VirtReg,
                                     CgInstruction &MI) {
  // Analyze instruction
  SmallVector<std::pair<CgInstruction *, unsigned>, 8> Ops;
  VirtRegInfo RI = CgAnalyzeVirtRegInBundle(MI, VirtReg.reg(), &Ops);

  if (!RI.Reads)
    return false;

  CgSlotIndex UseIdx = LIS.getInstructionIndex(MI).getRegSlot(true);
  CgVNInfo *ParentVNI = VirtReg.getVNInfoAt(UseIdx.getBaseIndex());

  if (!ParentVNI) {
    LLVM_DEBUG(dbgs() << "\tadding <undef> flags: ");
    for (CgOperand &MO : MI.operands())
      if (MO.isReg() && MO.isUse() && MO.getReg() == VirtReg.reg())
        MO.setIsUndef();
    LLVM_DEBUG(dbgs() << UseIdx << '\t' << MI);
    return true;
  }

  if (SnippetCopies.count(&MI))
    return false;

  CgLiveInterval &OrigLI = LIS.getInterval(Original);
  CgVNInfo *OrigVNI = OrigLI.getVNInfoAt(UseIdx);
  CgLiveRangeEdit::Remat RM(ParentVNI);
  RM.OrigMI = LIS.getInstructionFromIndex(OrigVNI->def);

  if (!Edit->canRematerializeAt(RM, OrigVNI, UseIdx, false)) {
    markValueUsed(&VirtReg, ParentVNI);
    LLVM_DEBUG(dbgs() << "\tcannot remat for " << UseIdx << '\t' << MI);
    return false;
  }

  // If the instruction also writes VirtReg.reg, it had better not require the
  // same register for uses and defs.
  if (RI.Tied) {
    markValueUsed(&VirtReg, ParentVNI);
    LLVM_DEBUG(dbgs() << "\tcannot remat tied reg: " << UseIdx << '\t' << MI);
    return false;
  }

  // Before rematerializing into a register for a single instruction, try to
  // fold a load into the instruction. That avoids allocating a new register.
  if (RM.OrigMI->canFoldAsLoad() && foldMemoryOperand(Ops, RM.OrigMI)) {
    Edit->markRematerialized(RM.ParentVNI);
    return true;
  }

  // If we can't guarantee that we'll be able to actually assign the new vreg,
  // we can't remat.
  if (!canGuaranteeAssignmentAfterRemat(VirtReg.reg(), MI)) {
    markValueUsed(&VirtReg, ParentVNI);
    LLVM_DEBUG(dbgs() << "\tcannot remat for " << UseIdx << '\t' << MI);
    return false;
  }

  // Allocate a new register for the remat.
  Register NewVReg = Edit->createFrom(Original);

  // Finally we can rematerialize OrigMI before MI.
  CgSlotIndex DefIdx = Edit->rematerializeAt(
      *MI.getParent(), CgBasicBlock::iterator(MI), NewVReg, RM, TRI);

  // We take the DebugLoc from MI, since OrigMI may be attributed to a
  // different source location.
  auto *NewMI = LIS.getInstructionFromIndex(DefIdx);
  // NewMI->setDebugLoc(MI.getDebugLoc());

  (void)DefIdx;
  LLVM_DEBUG(dbgs() << "\tremat:  " << DefIdx << '\t'
                    << *LIS.getInstructionFromIndex(DefIdx));

  // Replace operands
  for (const auto &OpPair : Ops) {
    CgOperand &MO = OpPair.first->getOperand(OpPair.second);
    if (MO.isReg() && MO.isUse() && MO.getReg() == VirtReg.reg()) {
      MO.setReg(NewVReg);
      MO.setIsKill();
    }
  }
  LLVM_DEBUG(dbgs() << "\t        " << UseIdx << '\t' << MI << '\n');

  return true;
}

/// reMaterializeAll - Try to rematerialize as many uses as possible,
/// and trim the live ranges after.
void InlineSpiller::reMaterializeAll() {
  if (!Edit->anyRematerializable())
    return;

  UsedValues.clear();

  // Try to remat before all uses of snippets.
  bool anyRemat = false;
  for (Register Reg : RegsToSpill) {
    CgLiveInterval &LI = LIS.getInterval(Reg);
    for (CgInstruction &MI : llvm::make_early_inc_range(MRI.reg_bundles(Reg))) {
      // Debug values are not allowed to affect codegen.
      if (MI.isDebugValue())
        continue;

      assert(!MI.isDebugInstr() && "Did not expect to find a use in debug "
                                   "instruction that isn't a DBG_VALUE");

      anyRemat |= reMaterializeFor(LI, MI);
    }
  }
  if (!anyRemat)
    return;

  // Remove any values that were completely rematted.
  for (Register Reg : RegsToSpill) {
    CgLiveInterval &LI = LIS.getInterval(Reg);
    for (CgVNInfo *VNI : LI.vnis()) {
      if (VNI->isUnused() || VNI->isPHIDef() || UsedValues.count(VNI))
        continue;
      CgInstruction *MI = LIS.getInstructionFromIndex(VNI->def);
      MI->addRegisterDead(Reg, &TRI);
      if (!MI->allDefsAreDead())
        continue;
      LLVM_DEBUG(dbgs() << "All defs dead: " << *MI);
      DeadDefs.push_back(MI);
    }
  }

  // Eliminate dead code after remat. Note that some snippet copies may be
  // deleted here.
  if (DeadDefs.empty())
    return;
  LLVM_DEBUG(dbgs() << "Remat created " << DeadDefs.size() << " dead defs.\n");
  Edit->eliminateDeadDefs(DeadDefs, RegsToSpill);

  // CgLiveRangeEdit::eliminateDeadDef is used to remove dead define
  // instructions after rematerialization.  To remove a VNI for a vreg from
  // its CgLiveInterval, CgLiveIntervals::removeVRegDefAt is used. However,
  // after non-PHI VNIs are all removed, PHI VNI are still left in the
  // CgLiveInterval. So to get rid of unused reg, we need to check whether it
  // has non-dbg reference instead of whether it has non-empty interval.
  unsigned ResultPos = 0;
  for (Register Reg : RegsToSpill) {
    if (MRI.reg_nodbg_empty(Reg)) {
      Edit->eraseVirtReg(Reg);
      continue;
    }

    assert(LIS.hasInterval(Reg) &&
           (!LIS.getInterval(Reg).empty() || !MRI.reg_nodbg_empty(Reg)) &&
           "Empty and not used live-range?!");

    RegsToSpill[ResultPos++] = Reg;
  }
  RegsToSpill.erase(RegsToSpill.begin() + ResultPos, RegsToSpill.end());
  LLVM_DEBUG(dbgs() << RegsToSpill.size()
                    << " registers to spill after remat.\n");
}

//===----------------------------------------------------------------------===//
//                                 Spilling
//===----------------------------------------------------------------------===//

/// If MI is a load or store of StackSlot, it can be removed.
bool InlineSpiller::coalesceStackAccess(CgInstruction *MI, Register Reg) {
  int FI = 0;
  Register InstrReg = _llvm_workaround->isLoadFromStackSlot(TII, *MI, FI);
  bool IsLoad = InstrReg;
  if (!IsLoad)
    InstrReg = _llvm_workaround->isStoreToStackSlot(TII, *MI, FI);

  // We have a stack access. Is it the right register and slot?
  if (InstrReg != Reg || FI != StackSlot)
    return false;

  if (!IsLoad)
    HSpiller.rmFromMergeableSpills(*MI, StackSlot);

  LLVM_DEBUG(dbgs() << "Coalescing stack access: " << *MI);
  LIS.RemoveCgInstructionFromMaps(*MI);
  MI->eraseFromParent();

  return true;
}

#if !defined(NDEBUG) || defined(LLVM_ENABLE_DUMP)
LLVM_DUMP_METHOD
// Dump the range of instructions from B to E with their slot indexes.
static void dumpCgInstrRangeWithSlotIndex(CgBasicBlock::iterator B,
                                          CgBasicBlock::iterator E,
                                          CgLiveIntervals const &LIS,
                                          const char *const header,
                                          Register VReg = Register()) {
  char NextLine = '\n';
  char SlotIndent = '\t';

  if (std::next(B) == E) {
    NextLine = ' ';
    SlotIndent = ' ';
  }

  dbgs() << '\t' << header << ": " << NextLine;

  for (CgBasicBlock::iterator I = B; I != E; ++I) {
    CgSlotIndex Idx = LIS.getInstructionIndex(*I).getRegSlot();

    // If a register was passed in and this instruction has it as a
    // destination that is marked as an early clobber, print the
    // early-clobber slot index.
    if (VReg) {
      CgOperand *MO = I->findRegisterDefOperand(VReg);
      if (MO && MO->isEarlyClobber())
        Idx = Idx.getRegSlot(true);
    }

    dbgs() << SlotIndent << Idx << '\t' << *I;
  }
}
#endif

/// foldMemoryOperand - Try folding stack slot references in Ops into their
/// instructions.
///
/// @param Ops    Operand indices from AnalyzeVirtRegInBundle().
/// @param LoadMI Load instruction to use instead of stack slot when non-null.
/// @return       True on success.
bool InlineSpiller::foldMemoryOperand(
    ArrayRef<std::pair<CgInstruction *, unsigned>> Ops, CgInstruction *LoadMI) {
  return false;

#if 0
    if (Ops.empty())
        return false;
    // Don't attempt folding in bundles.
    CgInstruction *MI = Ops.front().first;
    if (Ops.back().first != MI || MI->isBundled())
        return false;

    bool WasCopy = MI->isCopy();
    Register ImpReg;

    // TII::foldMemoryOperand will do what we need here for statepoint
    // (fold load into use and remove corresponding def). We will replace
    // uses of removed def with loads (spillAroundUses).
    // For that to work we need to untie def and use to pass it through
    // foldMemoryOperand and signal foldPatchpoint that it is allowed to
    // fold them.
    bool UntieRegs = MI->getOpcode() == TargetOpcode::STATEPOINT;

    // Spill subregs if the target allows it.
    // We always want to spill subregs for stackmap/patchpoint pseudos.
    bool SpillSubRegs = TII.isSubregFoldable()
                        || MI->getOpcode() == TargetOpcode::STATEPOINT
                        || MI->getOpcode() == TargetOpcode::PATCHPOINT
                        || MI->getOpcode() == TargetOpcode::STACKMAP;

    // TargetInstrInfo::foldMemoryOperand only expects explicit, non-tied
    // operands.
    SmallVector<unsigned, 8> FoldOps;
    for (const auto &OpPair : Ops) {
        unsigned Idx = OpPair.second;
        assert(MI == OpPair.first
               && "Instruction conflict during operand folding");
        CgOperand &MO = MI->getOperand(Idx);

        // No point restoring an undef read, and we'll produce an invalid live
        // interval.
        // TODO: Is this really the correct way to handle undef tied uses?
        if (MO.isUse() && !MO.readsReg() && !MO.isTied())
            continue;

        if (MO.isImplicit()) {
            ImpReg = MO.getReg();
            continue;
        }

        if (!SpillSubRegs && MO.getSubReg())
            return false;
        // We cannot fold a load instruction into a def.
        if (LoadMI && MO.isDef())
            return false;
        // Tied use operands should not be passed to foldMemoryOperand.
        if (UntieRegs || !MI->isRegTiedToDefOperand(Idx))
            FoldOps.push_back(Idx);
    }

    // If we only have implicit uses, we won't be able to fold that.
    // Moreover, TargetInstrInfo::foldMemoryOperand will assert if we try!
    if (FoldOps.empty())
        return false;

    CgInstrSpan MIS(CgBasicBlock::iterator(MI), MI->getParent());

    SmallVector<std::pair<unsigned, unsigned>> TiedOps;
    if (UntieRegs)
        for (unsigned Idx : FoldOps) {
            CgOperand &MO = MI->getOperand(Idx);
            if (!MO.isTied())
                continue;
            unsigned Tied = MI->findTiedOperandIdx(Idx);
            if (MO.isUse())
                TiedOps.emplace_back(Tied, Idx);
            else {
                assert(MO.isDef() && "Tied to not use and def?");
                TiedOps.emplace_back(Idx, Tied);
            }
            MI->untieRegOperand(Idx);
        }

    CgInstruction *FoldMI =
        LoadMI ? TII.foldMemoryOperand(*MI, FoldOps, *LoadMI, &LIS)
               : TII.foldMemoryOperand(*MI, FoldOps, StackSlot, &LIS, &VRM);
    CgInstruction *FoldMI = nullptr;
    if (!FoldMI) {
        // Re-tie operands.
        for (auto Tied : TiedOps)
            MI->tieOperands(Tied.first, Tied.second);
        return false;
    }

    // Remove LIS for any dead defs in the original MI not in FoldMI.
    for (MIBundleOperands MO(*MI); MO.isValid(); ++MO) {
        if (!MO->isReg())
            continue;
        Register Reg = MO->getReg();
        if (!Reg || Register::isVirtualRegister(Reg) || MRI.isReserved(Reg)) {
            continue;
        }
        // Skip non-Defs, including undef uses and internal reads.
        if (MO->isUse())
            continue;
        PhysRegInfo RI = AnalyzePhysRegInBundle(*FoldMI, Reg, &TRI);
        if (RI.FullyDefined)
            continue;
        // FoldMI does not define this physreg. Remove the LI segment.
        assert(MO->isDead() && "Cannot fold physreg def");
        CgSlotIndex Idx = LIS.getInstructionIndex(*MI).getRegSlot();
        LIS.removePhysRegDefAt(Reg.asMCReg(), Idx);
    }

    int FI;
    if (_llvm_workaround->isStoreToStackSlot(TII, *MI, FI)
        && HSpiller.rmFromMergeableSpills(*MI, FI))
        LIS.ReplaceCgInstrInMaps(*MI, *FoldMI);
    // Update the call site info.
    if (MI->isCandidateForCallSiteEntry())
        MI->getMF()->moveCallSiteInfo(MI, FoldMI);

    // If we've folded a store into an instruction labelled with debug-info,
    // record a substitution from the old operand to the memory operand. Handle
    // the simple common case where operand 0 is the one being folded, plus when
    // the destination operand is also a tied def. More values could be
    // substituted / preserved with more analysis.
    if (MI->peekDebugInstrNum() && Ops[0].second == 0) {
        // Helper lambda.
        auto MakeSubstitution = [this, FoldMI, MI, &Ops]() {
            // Substitute old operand zero to the new instructions memory
            // operand.
            unsigned OldOperandNum = Ops[0].second;
            unsigned NewNum = FoldMI->getDebugInstrNum();
            unsigned OldNum = MI->getDebugInstrNum();
            MF.makeDebugValueSubstitution(
                { OldNum, OldOperandNum },
                { NewNum, CgFunction::DebugOperandMemNumber });
        };

        const CgOperand &Op0 = MI->getOperand(Ops[0].second);
        if (Ops.size() == 1 && Op0.isDef()) {
            MakeSubstitution();
        }
        else if (Ops.size() == 2 && Op0.isDef() && MI->getOperand(1).isTied()
                 && Op0.getReg() == MI->getOperand(1).getReg()) {
            MakeSubstitution();
        }
    }
    else if (MI->peekDebugInstrNum()) {
        // This is a debug-labelled instruction, but the operand being folded
        // isn't at operand zero. Most likely this means it's a load being
        // folded in. Substitute any register defs from operand zero up to the
        // one being folded -- past that point, we don't know what the new
        // operand indexes will be.
        MF.substituteDebugValuesForInst(*MI, *FoldMI, Ops[0].second);
    }

    MI->eraseFromParent();

    // Insert any new instructions other than FoldMI into the LIS maps.
    assert(!MIS.empty() && "Unexpected empty span of instructions!");
    for (CgInstruction &MI : MIS)
        if (&MI != FoldMI)
            LIS.InsertCgInstrInMaps(MI);

    // TII.foldMemoryOperand may have left some implicit operands on the
    // instruction.  Strip them.
    if (ImpReg)
        for (unsigned i = FoldMI->getNumOperands(); i; --i) {
            CgOperand &MO = FoldMI->getOperand(i - 1);
            if (!MO.isReg() || !MO.isImplicit())
                break;
            if (MO.getReg() == ImpReg)
                FoldMI->removeOperand(i - 1);
        }

    LLVM_DEBUG(
        dumpCgInstrRangeWithSlotIndex(MIS.begin(), MIS.end(), LIS, "folded"));

    if (!WasCopy) {
    }
    else if (Ops.front().second == 0) {
        // If there is only 1 store instruction is required for spill, add it
        // to mergeable list. In X86 AMX, 2 intructions are required to store.
        // We disable the merge for this case.
        if (std::distance(MIS.begin(), MIS.end()) <= 1)
            HSpiller.addToMergeableSpills(*FoldMI, StackSlot, Original);
    }
    return true;
#endif
}

void InlineSpiller::insertReload(Register NewVReg, CgSlotIndex Idx,
                                 CgBasicBlock::iterator MI) {
  CgBasicBlock &MBB = *MI->getParent();

  CgInstrSpan MIS(MI, &MBB);
  _llvm_workaround->loadRegFromStackSlot(TII, MBB, MI, NewVReg, StackSlot,
                                         MRI.getRegClass(NewVReg), &TRI);

  LIS.InsertMachineInstrRangeInMaps(MIS.begin(), MI);

  LLVM_DEBUG(
      dumpCgInstrRangeWithSlotIndex(MIS.begin(), MI, LIS, "reload", NewVReg));
}

/// Check if \p Def fully defines a VReg with an undefined value.
/// If that's the case, that means the value of VReg is actually
/// not relevant.
static bool isRealSpill(const CgInstruction &Def) {
  if (!Def.isImplicitDef())
    return true;
  assert(Def.getNumOperands() == 1 &&
         "Implicit def with more than one definition");
  // We can say that the VReg defined by Def is undef, only if it is
  // fully defined by Def. Otherwise, some of the lanes may not be
  // undef and the value of the VReg matters.
  return Def.getOperand(0).getSubReg();
}

/// insertSpill - Insert a spill of NewVReg after MI.
void InlineSpiller::insertSpill(Register NewVReg, bool isKill,
                                CgBasicBlock::iterator MI) {
  // Spill are not terminators, so inserting spills after terminators will
  // violate invariants in CgVerifier.
  assert(!MI->isTerminator() && "Inserting a spill after a terminator");
  CgBasicBlock &MBB = *MI->getParent();

  CgInstrSpan MIS(MI, &MBB);
  CgBasicBlock::iterator SpillBefore = std::next(MI);
  bool IsRealSpill = isRealSpill(*MI);

  if (IsRealSpill)
    _llvm_workaround->storeRegToStackSlot(TII, MBB, SpillBefore, NewVReg,
                                          isKill, StackSlot,
                                          MRI.getRegClass(NewVReg), &TRI);
  else {
    // Don't spill undef value.
    // Anything works for undef, in particular keeping the memory
    // uninitialized is a viable option and it saves code size and
    // run time.
    std::array<CgOperand, 1> operands = {
        CgOperand::createRegOperand(NewVReg, false, isKill = true)};
    MF.createCgInstruction(MBB, SpillBefore, TII.get(TargetOpcode::KILL),
                           operands);
  }

  CgBasicBlock::iterator Spill = std::next(MI);
  LIS.InsertMachineInstrRangeInMaps(Spill, MIS.end());
  for (const CgInstruction &MI : make_range(Spill, MIS.end()))
    getVDefInterval(MI, LIS);

  LLVM_DEBUG(dumpCgInstrRangeWithSlotIndex(Spill, MIS.end(), LIS, "spill"));
  // If there is only 1 store instruction is required for spill, add it
  // to mergeable list. In X86 AMX, 2 intructions are required to store.
  // We disable the merge for this case.
  if (IsRealSpill && std::distance(Spill, MIS.end()) <= 1)
    HSpiller.addToMergeableSpills(*Spill, StackSlot, Original);
}

/// spillAroundUses - insert spill code around each use of Reg.
void InlineSpiller::spillAroundUses(Register Reg) {
  LLVM_DEBUG(dbgs() << "spillAroundUses " << printReg(Reg) << '\n');
  CgLiveInterval &OldLI = LIS.getInterval(Reg);

  // Iterate over instructions using Reg.
  for (CgInstruction &MI : llvm::make_early_inc_range(MRI.reg_bundles(Reg))) {
    // Debug values are not allowed to affect codegen.
#if 0
        if (MI.isDebugValue()) {
            // Modify DBG_VALUE now that the value is in a spill slot.
            CgBasicBlock *MBB = MI.getParent();
            LLVM_DEBUG(dbgs() << "Modifying debug info due to spill:\t" << MI);
            buildDbgValueForSpill(*MBB, &MI, MI, StackSlot, Reg);
            MBB->erase(MI);
            continue;
        }

        assert(!MI.isDebugInstr()
               && "Did not expect to find a use in debug "
                  "instruction that isn't a DBG_VALUE");
#endif

    // Ignore copies to/from snippets. We'll delete them.
    if (SnippetCopies.count(&MI))
      continue;

    // Stack slot accesses may coalesce away.
    if (coalesceStackAccess(&MI, Reg))
      continue;

    // Analyze instruction.
    SmallVector<std::pair<CgInstruction *, unsigned>, 8> Ops;
    VirtRegInfo RI = CgAnalyzeVirtRegInBundle(MI, Reg, &Ops);

    // Find the slot index where this instruction reads and writes OldLI.
    // This is usually the def slot, except for tied early clobbers.
    CgSlotIndex Idx = LIS.getInstructionIndex(MI).getRegSlot();
    if (CgVNInfo *VNI = OldLI.getVNInfoAt(Idx.getRegSlot(true)))
      if (CgSlotIndex::isSameInstr(Idx, VNI->def))
        Idx = VNI->def;

    // Check for a sibling copy.
    Register SibReg = isFullCopyOf(MI, Reg);
    if (SibReg && isSibling(SibReg)) {
      // This may actually be a copy between snippets.
      if (isRegToSpill(SibReg)) {
        LLVM_DEBUG(dbgs() << "Found new snippet copy: " << MI);
        SnippetCopies.insert(&MI);
        continue;
      }
      if (RI.Writes) {
        if (hoistSpillInsideBB(OldLI, MI)) {
          // This COPY is now dead, the value is already in the stack
          // slot.
          MI.getOperand(0).setIsDead();
          DeadDefs.push_back(&MI);
          continue;
        }
      } else {
        // This is a reload for a sib-reg copy. Drop spills downstream.
        CgLiveInterval &SibLI = LIS.getInterval(SibReg);
        eliminateRedundantSpills(SibLI, SibLI.getVNInfoAt(Idx));
        // The COPY will fold to a reload below.
      }
    }

    // Attempt to fold memory ops.
    if (foldMemoryOperand(Ops))
      continue;

    // Create a new virtual register for spill/fill.
    // FIXME: Infer regclass from instruction alone.
    Register NewVReg = Edit->createFrom(Reg);

    if (RI.Reads)
      insertReload(NewVReg, Idx, CgBasicBlock::iterator(&MI));

    // Rewrite instruction operands.
    bool hasLiveDef = false;
    for (const auto &OpPair : Ops) {
      CgOperand &MO = OpPair.first->getOperand(OpPair.second);
      MO.setReg(NewVReg);
      if (MO.isUse()) {
        if (!OpPair.first->isRegTiedToDefOperand(OpPair.second))
          MO.setIsKill();
      } else {
        if (!MO.isDead())
          hasLiveDef = true;
      }
    }
    LLVM_DEBUG(dbgs() << "\trewrite: " << Idx << '\t' << MI << '\n');

    // FIXME: Use a second vreg if instruction has no tied ops.
    if (RI.Writes)
      if (hasLiveDef)
        insertSpill(NewVReg, true, CgBasicBlock::iterator(&MI));
  }
}

/// spillAll - Spill all registers remaining after rematerialization.
void InlineSpiller::spillAll() {
  // Update CgLiveStacks now that we are committed to spilling.
  if (StackSlot == CgVirtRegMap::NO_STACK_SLOT) {
    StackSlot = VRM.assignVirt2StackSlot(Original);
    StackInt = &LSS.getOrCreateInterval(StackSlot, MRI.getRegClass(Original));
    StackInt->getNextValue(CgSlotIndex(), LSS.getVNInfoAllocator());
  } else
    StackInt = &LSS.getInterval(StackSlot);

  if (Original != Edit->getReg())
    VRM.assignVirt2StackSlot(Edit->getReg(), StackSlot);

  assert(StackInt->getNumValNums() == 1 && "Bad stack interval values");
  for (Register Reg : RegsToSpill)
    StackInt->MergeSegmentsInAsValue(LIS.getInterval(Reg),
                                     StackInt->getValNumInfo(0));
  LLVM_DEBUG(dbgs() << "Merged spilled regs: " << *StackInt << '\n');

  // Spill around uses of all RegsToSpill.
  for (Register Reg : RegsToSpill)
    spillAroundUses(Reg);

  // Hoisted spills may cause dead code.
  if (!DeadDefs.empty()) {
    LLVM_DEBUG(dbgs() << "Eliminating " << DeadDefs.size() << " dead defs\n");
    Edit->eliminateDeadDefs(DeadDefs, RegsToSpill);
  }

  // Finally delete the SnippetCopies.
  for (Register Reg : RegsToSpill) {
    for (CgInstruction &MI :
         llvm::make_early_inc_range(MRI.reg_instructions(Reg))) {
      assert(SnippetCopies.count(&MI) && "Remaining use wasn't a snippet copy");
      // FIXME: Do this with a CgLiveRangeEdit callback.
      LIS.RemoveCgInstructionFromMaps(MI);
      MI.eraseFromParent();
    }
  }

  // Delete all spilled registers.
  for (Register Reg : RegsToSpill)
    Edit->eraseVirtReg(Reg);
}

void InlineSpiller::spill(CgLiveRangeEdit &edit) {
  Edit = &edit;
  assert(!Register::isStackSlot(edit.getReg()) &&
         "Trying to spill a stack slot.");
  // Share a stack slot among all descendants of Original.
  Original = VRM.getOriginal(edit.getReg());
  StackSlot = VRM.getStackSlot(Original);
  StackInt = nullptr;

  LLVM_DEBUG(dbgs() << "Inline spilling "
                    << TRI.getRegClassName(MRI.getRegClass(edit.getReg()))
                    << ':' << edit.getParent() << "\nFrom original "
                    << printReg(Original) << '\n');
  assert(edit.getParent().isSpillable() &&
         "Attempting to spill already spilled value.");
  assert(DeadDefs.empty() && "Previous spill didn't remove dead defs");

  collectRegsToSpill();
  reMaterializeAll();

  // Remat may handle everything.
  if (!RegsToSpill.empty())
    spillAll();

  Edit->calculateRegClassAndHint(MF, VRAI);
}

/// Optimizations after all the reg selections and spills are done.
void InlineSpiller::postOptimization() { HSpiller.hoistAllSpills(); }

/// When a spill is inserted, add the spill to MergeableSpills map.
void HoistSpillHelper::addToMergeableSpills(CgInstruction &Spill, int StackSlot,
                                            unsigned Original) {
  BumpPtrAllocator &Allocator = LIS.getVNInfoAllocator();
  CgLiveInterval &OrigLI = LIS.getInterval(Original);
  // save a copy of CgLiveInterval in StackSlotToOrigLI because the original
  // CgLiveInterval may be cleared after all its references are spilled.
  if (StackSlotToOrigLI.find(StackSlot) == StackSlotToOrigLI.end()) {
    auto LI = std::make_unique<CgLiveInterval>(OrigLI.reg(), OrigLI.weight());
    LI->assign(OrigLI, Allocator);
    StackSlotToOrigLI[StackSlot] = std::move(LI);
  }
  CgSlotIndex Idx = LIS.getInstructionIndex(Spill);
  CgVNInfo *OrigVNI =
      StackSlotToOrigLI[StackSlot]->getVNInfoAt(Idx.getRegSlot());
  std::pair<int, CgVNInfo *> MIdx = std::make_pair(StackSlot, OrigVNI);
  MergeableSpills[MIdx].insert(&Spill);
}

/// When a spill is removed, remove the spill from MergeableSpills map.
/// Return true if the spill is removed successfully.
bool HoistSpillHelper::rmFromMergeableSpills(CgInstruction &Spill,
                                             int StackSlot) {
  auto It = StackSlotToOrigLI.find(StackSlot);
  if (It == StackSlotToOrigLI.end())
    return false;
  CgSlotIndex Idx = LIS.getInstructionIndex(Spill);
  CgVNInfo *OrigVNI = It->second->getVNInfoAt(Idx.getRegSlot());
  std::pair<int, CgVNInfo *> MIdx = std::make_pair(StackSlot, OrigVNI);
  return MergeableSpills[MIdx].erase(&Spill);
}

/// Check BB to see if it is a possible target BB to place a hoisted spill,
/// i.e., there should be a living sibling of OrigReg at the insert point.
bool HoistSpillHelper::isSpillCandBB(CgLiveInterval &OrigLI, CgVNInfo &OrigVNI,
                                     CgBasicBlock &BB, Register &LiveReg) {
  CgSlotIndex Idx = IPA.getLastInsertPoint(OrigLI, BB);
  // The original def could be after the last insert point in the root block,
  // we can't hoist to here.
  if (Idx < OrigVNI.def) {
    // TODO: We could be better here. If LI is not alive in landing pad
    // we could hoist spill after LIP.
    LLVM_DEBUG(dbgs() << "can't spill in root block - def after LIP\n");
    return false;
  }
  Register OrigReg = OrigLI.reg();
  SmallSetVector<Register, 16> &Siblings = Virt2SiblingsMap[OrigReg];
  assert(OrigLI.getVNInfoAt(Idx) == &OrigVNI && "Unexpected VNI");

  for (const Register &SibReg : Siblings) {
    CgLiveInterval &LI = LIS.getInterval(SibReg);
    CgVNInfo *VNI = LI.getVNInfoAt(Idx);
    if (VNI) {
      LiveReg = SibReg;
      return true;
    }
  }
  return false;
}

/// Remove redundant spills in the same BB. Save those redundant spills in
/// SpillsToRm, and save the spill to keep and its BB in SpillBBToSpill map.
void HoistSpillHelper::rmRedundantSpills(
    SmallPtrSet<CgInstruction *, 16> &Spills,
    SmallVectorImpl<CgInstruction *> &SpillsToRm,
    DenseMap<CgDomTreeNode *, CgInstruction *> &SpillBBToSpill) {
  // For each spill saw, check SpillBBToSpill[] and see if its BB already has
  // another spill inside. If a BB contains more than one spill, only keep the
  // earlier spill with smaller CgSlotIndex.
  for (auto *const CurrentSpill : Spills) {
    CgBasicBlock *Block = CurrentSpill->getParent();
    CgDomTreeNode *Node = MDT.getBase().getNode(Block);
    CgInstruction *PrevSpill = SpillBBToSpill[Node];
    if (PrevSpill) {
      CgSlotIndex PIdx = LIS.getInstructionIndex(*PrevSpill);
      CgSlotIndex CIdx = LIS.getInstructionIndex(*CurrentSpill);
      CgInstruction *SpillToRm = (CIdx > PIdx) ? CurrentSpill : PrevSpill;
      CgInstruction *SpillToKeep = (CIdx > PIdx) ? PrevSpill : CurrentSpill;
      SpillsToRm.push_back(SpillToRm);
      SpillBBToSpill[MDT.getBase().getNode(Block)] = SpillToKeep;
    } else {
      SpillBBToSpill[MDT.getBase().getNode(Block)] = CurrentSpill;
    }
  }
  for (auto *const SpillToRm : SpillsToRm)
    Spills.erase(SpillToRm);
}

/// Starting from \p Root find a top-down traversal order of the dominator
/// tree to visit all basic blocks containing the elements of \p Spills.
/// Redundant spills will be found and put into \p SpillsToRm at the same
/// time. \p SpillBBToSpill will be populated as part of the process and
/// maps a basic block to the first store occurring in the basic block.
/// \post SpillsToRm.union(Spills\@post) == Spills\@pre
void HoistSpillHelper::getVisitOrders(
    CgBasicBlock *Root, SmallPtrSet<CgInstruction *, 16> &Spills,
    SmallVectorImpl<CgDomTreeNode *> &Orders,
    SmallVectorImpl<CgInstruction *> &SpillsToRm,
    DenseMap<CgDomTreeNode *, unsigned> &SpillsToKeep,
    DenseMap<CgDomTreeNode *, CgInstruction *> &SpillBBToSpill) {
  // The set contains all the possible BB nodes to which we may hoist
  // original spills.
  SmallPtrSet<CgDomTreeNode *, 8> WorkSet;
  // Save the BB nodes on the path from the first BB node containing
  // non-redundant spill to the Root node.
  SmallPtrSet<CgDomTreeNode *, 8> NodesOnPath;
  // All the spills to be hoisted must originate from a single def instruction
  // to the OrigReg. It means the def instruction should dominate all the
  // spills to be hoisted. We choose the BB where the def instruction is
  // located as the Root.
  CgDomTreeNode *RootIDomNode = MDT[Root]->getIDom();
  // For every node on the dominator tree with spill, walk up on the dominator
  // tree towards the Root node until it is reached. If there is other node
  // containing spill in the middle of the path, the previous spill saw will
  // be redundant and the node containing it will be removed. All the nodes on
  // the path starting from the first node with non-redundant spill to the
  // Root node will be added to the WorkSet, which will contain all the
  // possible locations where spills may be hoisted to after the loop below is
  // done.
  for (auto *const Spill : Spills) {
    CgBasicBlock *Block = Spill->getParent();
    CgDomTreeNode *Node = MDT[Block];
    CgInstruction *SpillToRm = nullptr;
    while (Node != RootIDomNode) {
      // If Node dominates Block, and it already contains a spill, the
      // spill in Block will be redundant.
      if (Node != MDT[Block] && SpillBBToSpill[Node]) {
        SpillToRm = SpillBBToSpill[MDT[Block]];
        break;
        /// If we see the Node already in WorkSet, the path from the
        /// Node to the Root node must already be traversed by another
        /// spill. Then no need to repeat.
      } else if (WorkSet.count(Node)) {
        break;
      } else {
        NodesOnPath.insert(Node);
      }
      Node = Node->getIDom();
    }
    if (SpillToRm) {
      SpillsToRm.push_back(SpillToRm);
    } else {
      // Add a BB containing the original spills to SpillsToKeep -- i.e.,
      // set the initial status before hoisting start. The value of BBs
      // containing original spills is set to 0, in order to descriminate
      // with BBs containing hoisted spills which will be inserted to
      // SpillsToKeep later during hoisting.
      SpillsToKeep[MDT[Block]] = 0;
      WorkSet.insert(NodesOnPath.begin(), NodesOnPath.end());
    }
    NodesOnPath.clear();
  }

  // Sort the nodes in WorkSet in top-down order and save the nodes
  // in Orders. Orders will be used for hoisting in runHoistSpills.
  unsigned idx = 0;
  Orders.push_back(MDT.getBase().getNode(Root));
  do {
    CgDomTreeNode *Node = Orders[idx++];
    for (CgDomTreeNode *Child : Node->children()) {
      if (WorkSet.count(Child))
        Orders.push_back(Child);
    }
  } while (idx != Orders.size());
  assert(Orders.size() == WorkSet.size() &&
         "Orders have different size with WorkSet");

#ifndef NDEBUG
  LLVM_DEBUG(dbgs() << "Orders size is " << Orders.size() << "\n");
  SmallVector<CgDomTreeNode *, 32>::reverse_iterator RIt = Orders.rbegin();
  for (; RIt != Orders.rend(); RIt++)
    LLVM_DEBUG(dbgs() << "BB" << (*RIt)->getBlock()->getNumber() << ",");
  LLVM_DEBUG(dbgs() << "\n");
#endif
}

/// Try to hoist spills according to BB hotness. The spills to removed will
/// be saved in \p SpillsToRm. The spills to be inserted will be saved in
/// \p SpillsToIns.
void HoistSpillHelper::runHoistSpills(
    CgLiveInterval &OrigLI, CgVNInfo &OrigVNI,
    SmallPtrSet<CgInstruction *, 16> &Spills,
    SmallVectorImpl<CgInstruction *> &SpillsToRm,
    DenseMap<CgBasicBlock *, unsigned> &SpillsToIns) {
  // Visit order of dominator tree nodes.
  SmallVector<CgDomTreeNode *, 32> Orders;
  // SpillsToKeep contains all the nodes where spills are to be inserted
  // during hoisting. If the spill to be inserted is an original spill
  // (not a hoisted one), the value of the map entry is 0. If the spill
  // is a hoisted spill, the value of the map entry is the VReg to be used
  // as the source of the spill.
  DenseMap<CgDomTreeNode *, unsigned> SpillsToKeep;
  // Map from BB to the first spill inside of it.
  DenseMap<CgDomTreeNode *, CgInstruction *> SpillBBToSpill;

  rmRedundantSpills(Spills, SpillsToRm, SpillBBToSpill);

  CgBasicBlock *Root = LIS.getMBBFromIndex(OrigVNI.def);
  getVisitOrders(Root, Spills, Orders, SpillsToRm, SpillsToKeep,
                 SpillBBToSpill);

  // SpillsInSubTreeMap keeps the map from a dom tree node to a pair of
  // nodes set and the cost of all the spills inside those nodes.
  // The nodes set are the locations where spills are to be inserted
  // in the subtree of current node.
  using NodesCostPair =
      std::pair<SmallPtrSet<CgDomTreeNode *, 16>, BlockFrequency>;
  DenseMap<CgDomTreeNode *, NodesCostPair> SpillsInSubTreeMap;

  // Iterate Orders set in reverse order, which will be a bottom-up order
  // in the dominator tree. Once we visit a dom tree node, we know its
  // children have already been visited and the spill locations in the
  // subtrees of all the children have been determined.
  SmallVector<CgDomTreeNode *, 32>::reverse_iterator RIt = Orders.rbegin();
  for (; RIt != Orders.rend(); RIt++) {
    CgBasicBlock *Block = (*RIt)->getBlock();

    // If Block contains an original spill, simply continue.
    if (SpillsToKeep.find(*RIt) != SpillsToKeep.end() && !SpillsToKeep[*RIt]) {
      SpillsInSubTreeMap[*RIt].first.insert(*RIt);
      // SpillsInSubTreeMap[*RIt].second contains the cost of spill.
      SpillsInSubTreeMap[*RIt].second = MBFI.getBlockFreq(Block);
      continue;
    }

    // Collect spills in subtree of current node (*RIt) to
    // SpillsInSubTreeMap[*RIt].first.
    for (CgDomTreeNode *Child : (*RIt)->children()) {
      if (SpillsInSubTreeMap.find(Child) == SpillsInSubTreeMap.end())
        continue;
      // The stmt "SpillsInSubTree = SpillsInSubTreeMap[*RIt].first" below
      // should be placed before getting the begin and end iterators of
      // SpillsInSubTreeMap[Child].first, or else the iterators may be
      // invalidated when SpillsInSubTreeMap[*RIt] is seen the first time
      // and the map grows and then the original buckets in the map are
      // moved.
      SmallPtrSet<CgDomTreeNode *, 16> &SpillsInSubTree =
          SpillsInSubTreeMap[*RIt].first;
      BlockFrequency &SubTreeCost = SpillsInSubTreeMap[*RIt].second;
      SubTreeCost += SpillsInSubTreeMap[Child].second;
      auto BI = SpillsInSubTreeMap[Child].first.begin();
      auto EI = SpillsInSubTreeMap[Child].first.end();
      SpillsInSubTree.insert(BI, EI);
      SpillsInSubTreeMap.erase(Child);
    }

    SmallPtrSet<CgDomTreeNode *, 16> &SpillsInSubTree =
        SpillsInSubTreeMap[*RIt].first;
    BlockFrequency &SubTreeCost = SpillsInSubTreeMap[*RIt].second;
    // No spills in subtree, simply continue.
    if (SpillsInSubTree.empty())
      continue;

    // Check whether Block is a possible candidate to insert spill.
    Register LiveReg;
    if (!isSpillCandBB(OrigLI, OrigVNI, *Block, LiveReg))
      continue;

    // If there are multiple spills that could be merged, bias a little
    // to hoist the spill.
    BranchProbability MarginProb = (SpillsInSubTree.size() > 1)
                                       ? BranchProbability(9, 10)
                                       : BranchProbability(1, 1);
    if (SubTreeCost > MBFI.getBlockFreq(Block) * MarginProb) {
      // Hoist: Move spills to current Block.
      for (auto *const SpillBB : SpillsInSubTree) {
        // When SpillBB is a BB contains original spill, insert the
        // spill to SpillsToRm.
        if (SpillsToKeep.find(SpillBB) != SpillsToKeep.end() &&
            !SpillsToKeep[SpillBB]) {
          CgInstruction *SpillToRm = SpillBBToSpill[SpillBB];
          SpillsToRm.push_back(SpillToRm);
        }
        // SpillBB will not contain spill anymore, remove it from
        // SpillsToKeep.
        SpillsToKeep.erase(SpillBB);
      }
      // Current Block is the BB containing the new hoisted spill. Add it
      // to SpillsToKeep. LiveReg is the source of the new spill.
      SpillsToKeep[*RIt] = LiveReg;
      LLVM_DEBUG({
        dbgs() << "spills in BB: ";
        for (const auto Rspill : SpillsInSubTree)
          dbgs() << Rspill->getBlock()->getNumber() << " ";
        dbgs() << "were promoted to BB" << (*RIt)->getBlock()->getNumber()
               << "\n";
      });
      SpillsInSubTree.clear();
      SpillsInSubTree.insert(*RIt);
      SubTreeCost = MBFI.getBlockFreq(Block);
    }
  }
  // For spills in SpillsToKeep with LiveReg set (i.e., not original spill),
  // save them to SpillsToIns.
  for (const auto &Ent : SpillsToKeep) {
    if (Ent.second)
      SpillsToIns[Ent.first->getBlock()] = Ent.second;
  }
}

/// For spills with equal values, remove redundant spills and hoist those left
/// to less hot spots.
///
/// Spills with equal values will be collected into the same set in
/// MergeableSpills when spill is inserted. These equal spills are originated
/// from the same defining instruction and are dominated by the instruction.
/// Before hoisting all the equal spills, redundant spills inside in the same
/// BB are first marked to be deleted. Then starting from the spills left, walk
/// up on the dominator tree towards the Root node where the define instruction
/// is located, mark the dominated spills to be deleted along the way and
/// collect the BB nodes on the path from non-dominated spills to the define
/// instruction into a WorkSet. The nodes in WorkSet are the candidate places
/// where we are considering to hoist the spills. We iterate the WorkSet in
/// bottom-up order, and for each node, we will decide whether to hoist spills
/// inside its subtree to that node. In this way, we can get benefit locally
/// even if hoisting all the equal spills to one cold place is impossible.
void HoistSpillHelper::hoistAllSpills() {
#if 0 // TODO
  SmallVector<Register, 4> NewVRegs;
  CgLiveRangeEdit Edit(nullptr, NewVRegs, MF, LIS, &VRM, this);

  for (unsigned i = 0, e = MRI.getNumVirtRegs(); i != e; ++i) {
    Register Reg = Register::index2VirtReg(i);
    Register Original = VRM.getPreSplitReg(Reg);
    if (!MRI.def_empty(Reg))
      Virt2SiblingsMap[Original].insert(Reg);
  }

  // Each entry in MergeableSpills contains a spill set with equal values.
  for (auto &Ent : MergeableSpills) {
    int Slot = Ent.first.first;
    CgLiveInterval &OrigLI = *StackSlotToOrigLI[Slot];
    CgVNInfo *OrigVNI = Ent.first.second;
    SmallPtrSet<CgInstruction *, 16> &EqValSpills = Ent.second;
    if (Ent.second.empty())
      continue;

    LLVM_DEBUG({
      dbgs() << "\nFor Slot" << Slot << " and VN" << OrigVNI->id << ":\n"
             << "Equal spills in BB: ";
      for (const auto spill : EqValSpills)
        dbgs() << spill->getParent()->getNumber() << " ";
      dbgs() << "\n";
    });

    // SpillsToRm is the spill set to be removed from EqValSpills.
    SmallVector<CgInstruction *, 16> SpillsToRm;
    // SpillsToIns is the spill set to be newly inserted after hoisting.
    DenseMap<CgBasicBlock *, unsigned> SpillsToIns;

    // workaround: instruction may be erased
    for (auto *Spill : EqValSpills) {
      if (LIS.isNotInMIMap(*Spill)) {
        EqValSpills.erase(Spill);
      }
    }
    runHoistSpills(OrigLI, *OrigVNI, EqValSpills, SpillsToRm, SpillsToIns);

    LLVM_DEBUG({
      dbgs() << "Finally inserted spills in BB: ";
      for (const auto &Ispill : SpillsToIns)
        dbgs() << Ispill.first->getNumber() << " ";
      dbgs() << "\nFinally removed spills in BB: ";
      for (const auto Rspill : SpillsToRm)
        dbgs() << Rspill->getParent()->getNumber() << " ";
      dbgs() << "\n";
    });

    // Stack live range update.
    CgLiveInterval &StackIntvl = LSS.getInterval(Slot);
    if (!SpillsToIns.empty() || !SpillsToRm.empty())
      StackIntvl.MergeValueInAsValue(OrigLI, OrigVNI,
                                     StackIntvl.getValNumInfo(0));

    // Insert hoisted spills.
    for (auto const &Insert : SpillsToIns) {
      CgBasicBlock *BB = Insert.first;
      Register LiveReg = Insert.second;
      CgBasicBlock::iterator MII = IPA.getLastInsertPointIter(OrigLI, *BB);
      CgInstrSpan MIS(MII, BB);
      _llvm_workaround->storeRegToStackSlot(TII, *BB, MII, LiveReg, false, Slot,
                                            MRI.getRegClass(LiveReg), &TRI);
      LIS.InsertMachineInstrRangeInMaps(MIS.begin(), MII);
      for (const CgInstruction &MI : make_range(MIS.begin(), MII))
        getVDefInterval(MI, LIS);
    }

    // Remove redundant spills or change them to dead instructions.
    for (auto *const RMEnt : SpillsToRm) {
      RMEnt->setDesc(TII.get(TargetOpcode::KILL));
      for (unsigned i = RMEnt->getNumOperands(); i; --i) {
        CgOperand &MO = RMEnt->getOperand(i - 1);
        if (MO.isReg() && MO.isImplicit() && MO.isDef() && !MO.isDead())
          RMEnt->removeOperand(i - 1);
      }
    }
    Edit.eliminateDeadDefs(SpillsToRm, None);
  }
#endif
}

/// For VirtReg clone, the \p New register should have the same physreg or
/// stackslot as the \p old register.
void HoistSpillHelper::LRE_DidCloneVirtReg(Register New, Register Old) {
  if (VRM.hasPhys(Old))
    VRM.assignVirt2Phys(New, VRM.getPhys(Old));
  else if (VRM.getStackSlot(Old) != CgVirtRegMap::NO_STACK_SLOT)
    VRM.assignVirt2StackSlot(New, VRM.getStackSlot(Old));
  else
    llvm_unreachable("VReg should be assigned either physreg or stackslot");
  if (VRM.hasShape(Old))
    VRM.assignVirt2Shape(New, VRM.getShape(Old));
}
