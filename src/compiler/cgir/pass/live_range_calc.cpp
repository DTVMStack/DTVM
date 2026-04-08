//===- LiveRangeCalc.cpp - Calculate live ranges -------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Implementation of the LiveRangeCalc class.
//
//===----------------------------------------------------------------------===//

#include "compiler/cgir/pass/live_range_calc.h"
#include "compiler/cgir/cg_basic_block.h"
#include "compiler/cgir/cg_function.h"
#include "compiler/cgir/cg_instruction.h"
#include "compiler/cgir/pass/cg_dominators.h"
#include "compiler/cgir/pass/cg_register_info.h"
#include "compiler/cgir/pass/live_interval.h"
#include "compiler/cgir/pass/slot_indexes.h"
#include "llvm/ADT/BitVector.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SetVector.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <cassert>
#include <iterator>
#include <tuple>
#include <utility>

using namespace llvm;

#define DEBUG_TYPE "regalloc"

// Reserve an address that indicates a value that is known to be "undef".
static CgVNInfo UndefVNI(0xbad, CgSlotIndex());

void CgLiveRangeCalc::resetLiveOutMap() {
  unsigned NumBlocks = MF->getNumBlockIDs();
  Seen.clear();
  Seen.resize(NumBlocks);
  EntryInfos.clear();
  Map.resize(NumBlocks);
}

void CgLiveRangeCalc::reset(const CgFunction *mf, CgSlotIndexes *SI,
                            CgDominatorTree *MDT, CgVNInfo::Allocator *VNIA) {
  MF = mf;
  MRI = &MF->getRegInfo();
  Indexes = SI;
  DomTree = MDT;
  Alloc = VNIA;
  resetLiveOutMap();
  LiveIn.clear();
}

void CgLiveRangeCalc::updateFromLiveIns() {
  CgLiveRangeUpdater Updater;
  for (const LiveInBlock &I : LiveIn) {
    if (!I.DomNode)
      continue;
    CgBasicBlock *MBB = I.DomNode->getBlock();
    assert(I.Value && "No live-in value found");
    CgSlotIndex Start, End;
    std::tie(Start, End) = Indexes->getMBBRange(MBB);

    if (I.Kill.isValid())
      // Value is killed inside this block.
      End = I.Kill;
    else {
      // The value is live-through, update LiveOut as well.
      // Defer the Domtree lookup until it is needed.
      assert(Seen.test(MBB->getNumber()));
      Map[MBB] = LiveOutPair(I.Value, nullptr);
    }
    Updater.setDest(&I.LR);
    Updater.add(Start, End, I.Value);
  }
  LiveIn.clear();
}

void CgLiveRangeCalc::extend(CgLiveRange &LR, CgSlotIndex Use, unsigned PhysReg,
                             ArrayRef<CgSlotIndex> Undefs) {
  assert(Use.isValid() && "Invalid CgSlotIndex");
  assert(Indexes && "Missing CgSlotIndexes");
  assert(DomTree && "Missing dominator tree");

  CgBasicBlock *UseMBB = Indexes->getMBBFromIndex(Use.getPrevSlot());
  assert(UseMBB && "No MBB at Use");

  // Is there a def in the same MBB we can extend?
  auto EP = LR.extendInBlock(Undefs, Indexes->getMBBStartIdx(UseMBB), Use);
  if (EP.first != nullptr || EP.second)
    return;

  // Find the single reaching def, or determine if Use is jointly dominated by
  // multiple values, and we may need to create even more phi-defs to preserve
  // CgVNInfo SSA form.  Perform a search for all predecessor blocks where we
  // know the dominating CgVNInfo.
  if (findReachingDefs(LR, *UseMBB, Use, PhysReg, Undefs))
    return;

  // When there were multiple different values, we may need new PHIs.
  calculateValues();
}

// This function is called by a client after using the low-level API to add
// live-out and live-in blocks.  The unique value optimization is not
// available, CgSplitEditor::transferValues handles that case directly anyway.
void CgLiveRangeCalc::calculateValues() {
  assert(Indexes && "Missing CgSlotIndexes");
  assert(DomTree && "Missing dominator tree");
  updateSSA();
  updateFromLiveIns();
}

bool CgLiveRangeCalc::isDefOnEntry(CgLiveRange &LR,
                                   ArrayRef<CgSlotIndex> Undefs,
                                   CgBasicBlock &MBB, BitVector &DefOnEntry,
                                   BitVector &UndefOnEntry) {
  unsigned BN = MBB.getNumber();
  if (DefOnEntry[BN])
    return true;
  if (UndefOnEntry[BN])
    return false;

  auto MarkDefined = [BN, &DefOnEntry](CgBasicBlock &B) -> bool {
    for (CgBasicBlock *S : B.successors())
      DefOnEntry[S->getNumber()] = true;
    DefOnEntry[BN] = true;
    return true;
  };

  SetVector<unsigned> WorkList;
  // Checking if the entry of MBB is reached by some def: add all predecessors
  // that are potentially defined-on-exit to the work list.
  for (CgBasicBlock *P : MBB.predecessors())
    WorkList.insert(P->getNumber());

  for (unsigned i = 0; i != WorkList.size(); ++i) {
    // Determine if the exit from the block is reached by some def.
    unsigned N = WorkList[i];
    CgBasicBlock &B = *MF->getCgBasicBlock(N);
    if (Seen[N]) {
      const LiveOutPair &LOB = Map[&B];
      if (LOB.first != nullptr && LOB.first != &UndefVNI)
        return MarkDefined(B);
    }
    CgSlotIndex Begin, End;
    std::tie(Begin, End) = Indexes->getMBBRange(&B);
    // Treat End as not belonging to B.
    // If LR has a segment S that starts at the next block, i.e. [End, ...),
    // std::upper_bound will return the segment following S. Instead,
    // S should be treated as the first segment that does not overlap B.
    CgLiveRange::iterator UB = upper_bound(LR, End.getPrevSlot());
    if (UB != LR.begin()) {
      CgLiveRange::Segment &Seg = *std::prev(UB);
      if (Seg.end > Begin) {
        // There is a segment that overlaps B. If the range is not
        // explicitly undefined between the end of the segment and the
        // end of the block, treat the block as defined on exit. If it
        // is, go to the next block on the work list.
        if (LR.isUndefIn(Undefs, Seg.end, End))
          continue;
        return MarkDefined(B);
      }
    }

    // No segment overlaps with this block. If this block is not defined on
    // entry, or it undefines the range, do not process its predecessors.
    if (UndefOnEntry[N] || LR.isUndefIn(Undefs, Begin, End)) {
      UndefOnEntry[N] = true;
      continue;
    }
    if (DefOnEntry[N])
      return MarkDefined(B);

    // Still don't know: add all predecessors to the work list.
    for (CgBasicBlock *P : B.predecessors())
      WorkList.insert(P->getNumber());
  }

  UndefOnEntry[BN] = true;
  return false;
}

bool CgLiveRangeCalc::findReachingDefs(CgLiveRange &LR, CgBasicBlock &UseMBB,
                                       CgSlotIndex Use, unsigned PhysReg,
                                       ArrayRef<CgSlotIndex> Undefs) {
  unsigned UseMBBNum = UseMBB.getNumber();

  // Block numbers where LR should be live-in.
  SmallVector<unsigned, 16> WorkList(1, UseMBBNum);

  // Remember if we have seen more than one value.
  bool UniqueVNI = true;
  CgVNInfo *TheVNI = nullptr;

  bool FoundUndef = false;

  // Using Seen as a visited set, perform a BFS for all reaching defs.
  for (unsigned i = 0; i != WorkList.size(); ++i) {
    CgBasicBlock *MBB = MF->getCgBasicBlock(WorkList[i]);

#if 0
#ifndef NDEBUG
        if (MBB->pred_empty()) {
            MBB->getParent()->verify();
            errs()
                << "Use of " << printReg(PhysReg, MRI->getTargetRegisterInfo())
                << " does not have a corresponding definition on every path:\n";
            const CgInstruction *MI = Indexes->getInstructionFromIndex(Use);
            if (MI != nullptr)
                errs() << Use << " " << *MI;
            report_fatal_error("Use not jointly dominated by defs.");
        }

        if (Register::isPhysicalRegister(PhysReg) && !MBB->isLiveIn(PhysReg)) {
            MBB->getParent()->verify();
            const TargetRegisterInfo *TRI = MRI->getTargetRegisterInfo();
            errs() << "The register " << printReg(PhysReg, TRI)
                   << " needs to be live in to " << printCgBBReference(*MBB)
                   << ", but is missing from the live-in list.\n";
            report_fatal_error("Invalid global physical register");
        }
#endif
#endif

    FoundUndef |= MBB->pred_empty();

    for (CgBasicBlock *Pred : MBB->predecessors()) {
      // Is this a known live-out block?
      if (Seen.test(Pred->getNumber())) {
        if (CgVNInfo *VNI = Map[Pred].first) {
          if (TheVNI && TheVNI != VNI)
            UniqueVNI = false;
          TheVNI = VNI;
        }
        continue;
      }

      CgSlotIndex Start, End;
      std::tie(Start, End) = Indexes->getMBBRange(Pred);

      // First time we see Pred.  Try to determine the live-out value, but
      // set it as null if Pred is live-through with an unknown value.
      auto EP = LR.extendInBlock(Undefs, Start, End);
      CgVNInfo *VNI = EP.first;
      FoundUndef |= EP.second;
      setLiveOutValue(Pred, EP.second ? &UndefVNI : VNI);
      if (VNI) {
        if (TheVNI && TheVNI != VNI)
          UniqueVNI = false;
        TheVNI = VNI;
      }
      if (VNI || EP.second)
        continue;

      // No, we need a live-in value for Pred as well
      if (Pred != &UseMBB)
        WorkList.push_back(Pred->getNumber());
      else
        // Loopback to UseMBB, so value is really live through.
        Use = CgSlotIndex();
    }
  }

  LiveIn.clear();
  FoundUndef |= (TheVNI == nullptr || TheVNI == &UndefVNI);
  if (FoundUndef)
    UniqueVNI = false;

  // Both updateSSA() and CgLiveRangeUpdater benefit from ordered blocks, but
  // neither require it. Skip the sorting overhead for small updates.
  if (WorkList.size() > 4)
    array_pod_sort(WorkList.begin(), WorkList.end());

  // If a unique reaching def was found, blit in the live ranges immediately.
  if (UniqueVNI) {
    assert(TheVNI != nullptr && TheVNI != &UndefVNI);
    CgLiveRangeUpdater Updater(&LR);
    for (unsigned BN : WorkList) {
      CgSlotIndex Start, End;
      std::tie(Start, End) = Indexes->getMBBRange(BN);
      // Trim the live range in UseMBB.
      if (BN == UseMBBNum && Use.isValid())
        End = Use;
      else
        Map[MF->getCgBasicBlock(BN)] = LiveOutPair(TheVNI, nullptr);
      Updater.add(Start, End, TheVNI);
    }
    return true;
  }

  // Prepare the defined/undefined bit vectors.
  EntryInfoMap::iterator Entry;
  bool DidInsert;
  std::tie(Entry, DidInsert) = EntryInfos.insert(
      std::make_pair(&LR, std::make_pair(BitVector(), BitVector())));
  if (DidInsert) {
    // Initialize newly inserted entries.
    unsigned N = MF->getNumBlockIDs();
    Entry->second.first.resize(N);
    Entry->second.second.resize(N);
  }
  BitVector &DefOnEntry = Entry->second.first;
  BitVector &UndefOnEntry = Entry->second.second;

  // Multiple values were found, so transfer the work list to the LiveIn array
  // where UpdateSSA will use it as a work list.
  LiveIn.reserve(WorkList.size());
  for (unsigned BN : WorkList) {
    CgBasicBlock *MBB = MF->getCgBasicBlock(BN);
    if (!Undefs.empty() &&
        !isDefOnEntry(LR, Undefs, *MBB, DefOnEntry, UndefOnEntry))
      continue;
    addLiveInBlock(LR, DomTree->getNode(MBB));
    if (MBB == &UseMBB)
      LiveIn.back().Kill = Use;
  }

  return false;
}

// This is essentially the same iterative algorithm that SSAUpdater uses,
// except we already have a dominator tree, so we don't have to recompute it.
void CgLiveRangeCalc::updateSSA() {
  assert(Indexes && "Missing CgSlotIndexes");
  assert(DomTree && "Missing dominator tree");

  // Interate until convergence.
  bool Changed;
  do {
    Changed = false;
    // Propagate live-out values down the dominator tree, inserting phi-defs
    // when necessary.
    for (LiveInBlock &I : LiveIn) {
      CgDomTreeNode *Node = I.DomNode;
      // Skip block if the live-in value has already been determined.
      if (!Node)
        continue;
      CgBasicBlock *MBB = Node->getBlock();
      CgDomTreeNode *IDom = Node->getIDom();
      LiveOutPair IDomValue;

      // We need a live-in value to a block with no immediate dominator?
      // This is probably an unreachable block that has survived somehow.
      bool needPHI = !IDom || !Seen.test(IDom->getBlock()->getNumber());

      // IDom dominates all of our predecessors, but it may not be their
      // immediate dominator. Check if any of them have live-out values
      // that are properly dominated by IDom. If so, we need a phi-def
      // here.
      if (!needPHI) {
        IDomValue = Map[IDom->getBlock()];

        // Cache the DomTree node that defined the value.
        if (IDomValue.first && IDomValue.first != &UndefVNI &&
            !IDomValue.second) {
          Map[IDom->getBlock()].second = IDomValue.second =
              DomTree->getNode(Indexes->getMBBFromIndex(IDomValue.first->def));
        }

        for (CgBasicBlock *Pred : MBB->predecessors()) {
          LiveOutPair &Value = Map[Pred];
          if (!Value.first || Value.first == IDomValue.first)
            continue;
          if (Value.first == &UndefVNI) {
            needPHI = true;
            break;
          }

          // Cache the DomTree node that defined the value.
          if (!Value.second)
            Value.second =
                DomTree->getNode(Indexes->getMBBFromIndex(Value.first->def));

          // This predecessor is carrying something other than
          // IDomValue. It could be because IDomValue hasn't
          // propagated yet, or it could be because MBB is in the
          // dominance frontier of that value.
          if (DomTree->dominates(IDom, Value.second)) {
            needPHI = true;
            break;
          }
        }
      }

      // The value may be live-through even if Kill is set, as can happen
      // when we are called from extendRange. In that case LiveOutSeen is
      // true, and LiveOut indicates a foreign or missing value.
      LiveOutPair &LOP = Map[MBB];

      // Create a phi-def if required.
      if (needPHI) {
        Changed = true;
        assert(Alloc && "Need CgVNInfo allocator to create PHI-defs");
        CgSlotIndex Start, End;
        std::tie(Start, End) = Indexes->getMBBRange(MBB);
        CgLiveRange &LR = I.LR;
        CgVNInfo *VNI = LR.getNextValue(Start, *Alloc);
        I.Value = VNI;
        // This block is done, we know the final value.
        I.DomNode = nullptr;

        // Add liveness since updateFromLiveIns now skips this node.
        if (I.Kill.isValid()) {
          if (VNI)
            LR.addSegment(CgLiveInterval::Segment(Start, I.Kill, VNI));
        } else {
          if (VNI)
            LR.addSegment(CgLiveInterval::Segment(Start, End, VNI));
          LOP = LiveOutPair(VNI, Node);
        }
      } else if (IDomValue.first && IDomValue.first != &UndefVNI) {
        // No phi-def here. Remember incoming value.
        I.Value = IDomValue.first;

        // If the IDomValue is killed in the block, don't propagate
        // through.
        if (I.Kill.isValid())
          continue;

        // Propagate IDomValue if it isn't killed:
        // MBB is live-out and doesn't define its own value.
        if (LOP.first == IDomValue.first)
          continue;
        Changed = true;
        LOP = IDomValue;
      }
    }
  } while (Changed);
}

bool CgLiveRangeCalc::isJointlyDominated(const CgBasicBlock *MBB,
                                         ArrayRef<CgSlotIndex> Defs,
                                         const CgSlotIndexes &Indexes) {
  const CgFunction &MF = *MBB->getParent();
  BitVector DefBlocks(MF.getNumBlockIDs());
  for (CgSlotIndex I : Defs)
    DefBlocks.set(Indexes.getMBBFromIndex(I)->getNumber());

  SetVector<unsigned> PredQueue;
  PredQueue.insert(MBB->getNumber());
  for (unsigned i = 0; i != PredQueue.size(); ++i) {
    unsigned BN = PredQueue[i];
    if (DefBlocks[BN])
      return true;
    const CgBasicBlock *B = MF.getCgBasicBlock(BN);
    for (const CgBasicBlock *P : B->predecessors())
      PredQueue.insert(P->getNumber());
  }
  return false;
}
