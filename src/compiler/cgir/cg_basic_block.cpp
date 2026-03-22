/*
 * Copyright (C) 2021-2023 the DTVM authors.
 */
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "compiler/cgir/cg_basic_block.h"
#include "compiler/cgir/cg_function.h"
#include "compiler/common/consts.h"
#include "llvm/MC/MCAsmInfo.h"

using namespace COMPILER;

CgBasicBlock::CgBasicBlock(CgFunction &parent)
    : _parent(&parent), Predecessors(parent.getContext().MemPool),
      Successors(parent.getContext().MemPool),
      LiveIns(parent.getContext().MemPool) {
  _cg_instructions.Parent = this;
}

CgBasicBlock::CgBasicBlock(uint32_t idx, CgFunction &parent)
    : CgBasicBlock(parent) {
  _idx = idx;
}

CgBasicBlock::parent_iterator CgBasicBlock::getIterator() {
  ZEN_ASSERT(_parent != nullptr);
  return _parent->begin() + _idx;
}
CgBasicBlock::const_parent_iterator CgBasicBlock::getIterator() const {
  return _parent->begin() + _idx;
}

void CgBasicBlock::removeSuccessor(CgBasicBlock *Succ) {
  auto It = std::find(Successors.begin(), Successors.end(), Succ);
  removeSuccessor(It);
}

void CgBasicBlock::removeSuccessor(succ_iterator It) {
  ZEN_ASSERT(It != Successors.end());
  (*It)->removePredecessor(this);
  Successors.erase(It);
}

void CgBasicBlock::removePredecessor(CgBasicBlock *Pred) {
  auto It = std::find(Predecessors.begin(), Predecessors.end(), Pred);
  ZEN_ASSERT(It != Predecessors.end());
  Predecessors.erase(It);
}

void CgBasicBlock::replaceSuccessor(CgBasicBlock *Old, CgBasicBlock *New) {
  if (Old == New) {
    return;
  }

  auto E = Successors.end();
  auto OldIt = E;
  auto NewIt = E;
  for (auto It = Successors.begin(); It != E; ++It) {
    if (*It == Old) {
      OldIt = It;
      if (NewIt != E) {
        break;
      }
    }
    if (*It == New) {
      NewIt = It;
      if (OldIt != E) {
        break;
      }
    }
  }
  ZEN_ASSERT(OldIt != E && "Old is not a successor of this block");

  if (NewIt == E) {
    Old->removePredecessor(this);
    New->addPredecessor(this);
    *OldIt = New;
    return;
  }

  removeSuccessor(OldIt);
}

void CgBasicBlock::sortUniqueLiveIns() {
  llvm::sort(LiveIns,
             [](const RegisterMaskPair &LI0, const RegisterMaskPair &LI1) {
               return LI0.PhysReg < LI1.PhysReg;
             });
  // Liveins are sorted by physreg now we can merge their lanemasks.
  LiveInVector::const_iterator I = LiveIns.begin();
  LiveInVector::const_iterator J;
  LiveInVector::iterator Out = LiveIns.begin();
  for (; I != LiveIns.end(); ++Out, I = J) {
    MCRegister PhysReg = I->PhysReg;
    LaneBitmask LaneMask = I->LaneMask;
    for (J = std::next(I); J != LiveIns.end() && J->PhysReg == PhysReg; ++J)
      LaneMask |= J->LaneMask;
    Out->PhysReg = PhysReg;
    Out->LaneMask = LaneMask;
  }
  LiveIns.erase(Out, LiveIns.end());
}

void CgBasicBlock::printAsOperand(raw_ostream &OS, bool /*PrintType*/) const {
  OS << '%' << "bb." << getNumber();
  ;
  // printName(OS, 0);
}

void CgBasicBlock::print(llvm::raw_ostream &OS) const {
  OS << "@" << _idx << ":\n";
  for (auto &inst : _cg_instructions) {
    OS << kDumpIndent;
    inst.print(OS);
  }
}

void CgBasicBlock::print(raw_ostream &OS, const CgSlotIndexes *Indexes,
                         bool IsStandalone) const {
  const CgFunction *MF = getParent();
  if (!MF) {
    OS << "Can't print out CgBasicBlock because parent CgFunction"
       << " is null\n";
    return;
  }

  // if (Indexes && PrintSlotIndexes)
  if (Indexes && true)
    OS << Indexes->getMBBStartIdx(this) << '\t';

  // printName(OS, PrintNameIr | PrintNameAttributes, &MST);
  // printName(OS, true);
  printAsOperand(OS);
  OS << ":\n";

  const TargetRegisterInfo *TRI = MF->getSubtarget().getRegisterInfo();
  const auto &MRI = MF->getRegInfo();
  const TargetInstrInfo &TII = *getParent()->getSubtarget().getInstrInfo();
  bool HasLineAttributes = false;

  // Print the preds of this block according to the CFG.
  if (!pred_empty() && IsStandalone) {
    if (Indexes)
      OS << '\t';
    // Don't indent(2), align with previous line attributes.
    OS << "; predecessors: ";
    ListSeparator LS;
    for (auto *Pred : predecessors())
      OS << LS << printCgBBReference(*Pred);
    OS << '\n';
    HasLineAttributes = true;
  }

  if (!succ_empty()) {
    if (Indexes)
      OS << '\t';
    // Print the successors
    OS.indent(2) << "successors: ";
    ListSeparator LS;
    for (auto I = succ_begin(), E = succ_end(); I != E; ++I) {
      OS << LS << printCgBBReference(**I);
#if 0
      if (!Probs.empty())
        OS << '('
           << format("0x%08" PRIx32, getSuccProbability(I).getNumerator())
           << ')';
#endif
    }
    // if (!Probs.empty() && IsStandalone) {
    if (false) {
      // Print human readable probabilities as comments.
      OS << "; ";
      ListSeparator LS;
      for (auto I = succ_begin(), E = succ_end(); I != E; ++I) {
        const BranchProbability &BP = getSuccProbability(I);
        OS << LS << printCgBBReference(**I) << '('
           << format("%.2f%%",
                     rint(((double)BP.getNumerator() / BP.getDenominator()) *
                          100.0 * 100.0) /
                         100.0)
           << ')';
      }
    }

    OS << '\n';
    HasLineAttributes = true;
  }

#if 0
  if (!livein_empty() && MRI.tracksLiveness()) {
    if (Indexes) OS << '\t';
    OS.indent(2) << "liveins: ";

    ListSeparator LS;
    for (const auto &LI : liveins()) {
      OS << LS << printReg(LI.PhysReg, TRI);
      if (!LI.LaneMask.all())
        OS << ":0x" << PrintLaneMask(LI.LaneMask);
    }
    HasLineAttributes = true;
  }
#endif

  if (HasLineAttributes)
    OS << '\n';

  bool IsInBundle = false;
  for (const CgInstruction &MI : *this) {
    // if (Indexes && PrintSlotIndexes) {
    if (Indexes && true) {
      if (Indexes->hasIndex(MI))
        OS << Indexes->getInstructionIndex(MI);
      OS << '\t';
    }

    // if (IsInBundle && !MI.isInsideBundle()) {
    if (false) {
      OS.indent(2) << "}\n";
      IsInBundle = false;
    }

    OS.indent(IsInBundle ? 4 : 2);
    MI.print(OS);
    // MI.print(OS, IsStandalone, /*SkipOpers=*/false,
    // /*SkipDebugLoc=*/false,
    //         /*AddNewLine=*/false, &TII);

    if (!IsInBundle && MI.getFlag(CgInstruction::BundledSucc)) {
      OS << " {";
      IsInBundle = true;
    }
    // OS << '\n';
  }

  if (IsInBundle)
    OS.indent(2) << "}\n";

#if 0
  if (IrrLoopHeaderWeight && IsStandalone) {
    if (Indexes) OS << '\t';
    OS.indent(2) << "; Irreducible loop header weight: "
                 << IrrLoopHeaderWeight.value() << '\n';
  }
#endif
}

#if !defined(NDEBUG) || defined(LLVM_ENABLE_DUMP)
void CgBasicBlock::dump() const { print(llvm::dbgs()); }
#endif

llvm::MCSymbol *CgBasicBlock::getSymbol() const {
  if (!BlockSymbol) {
    const CgFunction *MF = getParent();
    MCContext &Ctx = MF->getMCContext();
    const StringRef Prefix = Ctx.getAsmInfo()->getPrivateLabelPrefix();
#if defined(ZEN_ENABLE_EVM) && defined(ZEN_ENABLE_LINUX_PERF)
    std::string BlockComment =
        getSourceName().empty()
            ? std::to_string(getNumber())
            : getSourceName() + "_" + std::to_string(getSourceOffset());
    BlockSymbol = Ctx.getOrCreateSymbol(
        "EVMBB" + Twine(MF->getFunction().getFuncIdx()) + "_" + BlockComment);
#else
    BlockSymbol = Ctx.getOrCreateSymbol(Twine(Prefix) + "BB" +
                                        Twine(MF->getFunction().getFuncIdx()) +
                                        "_" + Twine(getNumber()));
#endif
  }
  return BlockSymbol;
}

/// Return whether (physical) register "Reg" has been <def>ined and not <kill>ed
/// as of just before "MI".
///
/// Search is localised to a neighborhood of
/// Neighborhood instructions before (searching for defs or kills) and N
/// instructions after (searching just for defs) MI.
CgBasicBlock::LivenessQueryResult
CgBasicBlock::computeRegisterLiveness(const TargetRegisterInfo *TRI,
                                      MCRegister Reg, const_iterator Before,
                                      unsigned Neighborhood) const {
  unsigned N = Neighborhood;

  // Try searching forwards from Before, looking for reads or defs.
  const_iterator I(Before);
  for (; I != end() && N > 0; ++I) {
    if (I->isDebugOrPseudoInstr())
      continue;

    --N;

    PhysRegInfo Info = I->AnalyzePhysRegInBundle(Reg, TRI);

    // Register is live when we read it here.
    if (Info.Read)
      return LQR_Live;
    // Register is dead if we can fully overwrite or clobber it here.
    if (Info.FullyDefined || Info.Clobbered)
      return LQR_Dead;
  }

  // If we reached the end, it is safe to clobber Reg at the end of a block of
  // no successor has it live in.
  if (I == end()) {
    for (CgBasicBlock *S : successors()) {
      for (const CgBasicBlock::RegisterMaskPair &LI : S->liveins()) {
        if (TRI->regsOverlap(LI.PhysReg, Reg))
          return LQR_Live;
      }
    }

    return LQR_Dead;
  }

  N = Neighborhood;

  // Start by searching backwards from Before, looking for kills, reads or
  // defs.
  I = const_iterator(Before);
  // If this is the first insn in the block, don't search backwards.
  if (I != begin()) {
    do {
      --I;

      if (I->isDebugOrPseudoInstr())
        continue;

      --N;

      PhysRegInfo Info = I->AnalyzePhysRegInBundle(Reg, TRI);

      // Defs happen after uses so they take precedence if both are
      // present.

      // Register is dead after a dead def of the full register.
      if (Info.DeadDef)
        return LQR_Dead;
      // Register is (at least partially) live after a def.
      if (Info.Defined) {
        if (!Info.PartialDeadDef)
          return LQR_Live;
        // As soon as we saw a partial definition (dead or not),
        // we cannot tell if the value is partial live without
        // tracking the lanemasks. We are not going to do this,
        // so fall back on the remaining of the analysis.
        break;
      }
      // Register is dead after a full kill or clobber and no def.
      if (Info.Killed || Info.Clobbered)
        return LQR_Dead;
      // Register must be live if we read it.
      if (Info.Read)
        return LQR_Live;

    } while (I != begin() && N > 0);
  }

  // If all the instructions before this in the block are debug instructions,
  // skip over them.
  while (I != begin() && std::prev(I)->isDebugOrPseudoInstr())
    --I;

  // Did we get to the start of the block?
  if (I == begin()) {
    // If so, the register's state is definitely defined by the live-in
    // state.
    for (const CgBasicBlock::RegisterMaskPair &LI : liveins())
      if (TRI->regsOverlap(LI.PhysReg, Reg))
        return LQR_Live;

    return LQR_Dead;
  }

  // At this point we have no idea of the liveness of the register.
  return LQR_Unknown;
}

namespace llvm {
void ilist_traits<CgInstruction>::deleteNode(CgInstruction *MI) {
  // TODO: do not free instruction for now, CgFunction manages instructions
  assert(!MI->getParent() && "MI is qstill in a block!");
  // used to destroy memory
  MI->setParent(Parent);
  Parent->getParent()->deleteCgInstruction(MI);
}

/// When we add an instruction to a basic block list, we update its parent
/// pointer and add its operands from reg use/def lists if appropriate.
void ilist_traits<CgInstruction>::addNodeToList(CgInstruction *N) {
  assert(!N->getParent() && "machine instruction already in a basic block");
  N->setParent(Parent);

  // Add the instruction's register operands to their corresponding
  // use/def lists.
  auto *MF = Parent->getParent();
  N->addRegOperandsToUseLists(MF->getRegInfo());
  // MF->handleInsertion(*N);
}

/// When we remove an instruction from a basic block list, we update its parent
/// pointer and remove its operands from reg use/def lists if appropriate.
void ilist_traits<CgInstruction>::removeNodeFromList(CgInstruction *N) {
  assert(N->getParent() && "machine instruction not in a basic block");

  // Remove from the use/def lists.
  if (auto *MF = N->getParent()->getParent()) {
    //     // MF->handleRemoval(*N);
    N->removeRegOperandsFromUseLists(MF->getRegInfo());
  }

  N->setParent(nullptr);
}

/// When moving a range of instructions from one MBB list to another, we need to
/// update the parent pointers and the use/def lists.
void ilist_traits<CgInstruction>::transferNodesFromList(ilist_traits &FromList,
                                                        instr_iterator First,
                                                        instr_iterator Last) {
  assert(Parent->getParent() == FromList.Parent->getParent() &&
         "cannot transfer MachineInstrs between MachineFunctions");

  // If it's within the same BB, there's nothing to do.
  if (this == &FromList)
    return;

  assert(Parent != FromList.Parent && "Two lists have the same parent?");

  // If splicing between two blocks within the same function, just update the
  // parent pointers.
  for (; First != Last; ++First)
    First->setParent(Parent);
}

} // namespace llvm
