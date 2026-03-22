/*
 * Copyright (C) 2021-2023 the DTVM authors.
 */
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#ifndef COMPILER_IR_CG_BASIC_BLOCK_H
#define COMPILER_IR_CG_BASIC_BLOCK_H

#include "compiler/cgir/cg_instruction.h"
#include "llvm/ADT/Optional.h"
#include "llvm/ADT/ilist.h"

using namespace llvm;
using namespace COMPILER;

namespace llvm {
class raw_ostream;
}

namespace COMPILER {

class CgSlotIndexes;

class CgBasicBlock : public NonCopyable {
public:
  /// Pair of physical register and lane mask.
  /// This is not simply a std::pair typedef because the members should be
  /// named clearly as they both have an integer type.
  struct RegisterMaskPair {
  public:
    MCPhysReg PhysReg;
    LaneBitmask LaneMask;

    RegisterMaskPair(MCPhysReg PhysReg, LaneBitmask LaneMask)
        : PhysReg(PhysReg), LaneMask(LaneMask) {}
  };

  using CgInstructionListType = ilist<CgInstruction>;
  using iterator = CgInstructionListType::iterator;
  using const_iterator = CgInstructionListType::const_iterator;

  using reverse_iterator = CgInstructionListType::reverse_iterator;
  using const_reverse_iterator = CgInstructionListType::const_reverse_iterator;

  using CgBasicBlockListType = CompileVector<CgBasicBlock *>;
  using parent_iterator = CgBasicBlockListType::iterator;
  using const_parent_iterator = CgBasicBlockListType::const_iterator;

  CgBasicBlock(CgFunction &parent);
  CgBasicBlock(uint32_t idx, CgFunction &parent);
  ~CgBasicBlock() = default;

  void dump() const;
  void print(raw_ostream &OS) const;
  void print(raw_ostream &OS, const CgSlotIndexes *,
             bool IsStandalone = true) const;

  CgFunction *getParent() const { return _parent; }
  parent_iterator getIterator();
  const_parent_iterator getIterator() const;

  /// Convenience function that returns true if the block ends in a return
  /// instruction.
  bool isReturnBlock() const { return !empty() && back().isReturn(); }
  bool isLegalToHoistInto() const { return !isReturnBlock(); }

  // Printing method used by LoopInfo.
  void printAsOperand(raw_ostream &OS, bool PrintType = true) const;

  uint32_t getNumber() const { return _idx; }
  void setNumber(uint32_t N) { _idx = N; }
  std::string getName() const { return std::to_string(_idx); }

  MCSymbol *getSymbol() const;

  /// Insert MI into the instruction list before I.
  iterator insert(iterator I, CgInstruction *MI) {
    assert((I == end() || I->getParent() == this) &&
           "iterator points outside of basic block");
    // assert(!MI->isBundledWithPred() && !MI->isBundledWithSucc() &&
    //        "Cannot insert instruction with bundle flags");
    return _cg_instructions.insert(I, MI);
  }

  /// Insert MI into the instruction list after I.
  iterator insertAfter(iterator I, CgInstruction *MI) {
    assert((I == end() || I->getParent() == this) &&
           "iterator points outside of basic block");
    // assert(!MI->isBundledWithPred() && !MI->isBundledWithSucc() &&
    //        "Cannot insert instruction with bundle flags");
    return _cg_instructions.insertAfter(I, MI);
  }

  iterator erase(iterator it) { return _cg_instructions.erase(it); }
  iterator erase(CgInstruction *inst) { return erase(iterator(inst)); }
  /// Take an instruction from MBB 'Other' at the position From, and insert it
  /// into this MBB right before 'Where'.
  ///
  /// If From points to a bundle of instructions, the whole bundle is moved.
  void splice(iterator Where, CgBasicBlock *Other, iterator From) {
    // The range splice() doesn't allow noop moves, but this one does.
    if (Where != From)
      splice(Where, Other, From, std::next(From));
  }

  /// Take a block of instructions from MBB 'Other' in the range [From, To),
  /// and insert them into this MBB right before 'Where'.
  ///
  /// The instruction at 'Where' must not be included in the range of
  /// instructions to move.
  void splice(iterator Where, CgBasicBlock *Other, iterator From, iterator To) {
    _cg_instructions.splice(Where, Other->_cg_instructions, From, To);
  }
  iterator begin() { return _cg_instructions.begin(); }
  iterator end() { return _cg_instructions.end(); }
  const_iterator begin() const { return _cg_instructions.begin(); }
  const_iterator end() const { return _cg_instructions.end(); }
  reverse_iterator rbegin() { return _cg_instructions.rbegin(); }
  reverse_iterator rend() { return _cg_instructions.rend(); }
  using instr_range = iterator_range<iterator>;
  using const_instr_range = iterator_range<const_iterator>;
  instr_range instrs() { return instr_range(begin(), end()); }
  const_instr_range instrs() const { return const_instr_range(begin(), end()); }

  CgInstruction &front() { return _cg_instructions.front(); }
  CgInstruction &back() { return _cg_instructions.back(); }
  const CgInstruction &front() const { return _cg_instructions.front(); }
  const CgInstruction &back() const { return _cg_instructions.back(); }

  iterator SkipPHIsLabelsAndDebug(iterator I, bool SkipPseudoOp = true) {
    return I;
  }

  bool empty() const { return _cg_instructions.empty(); }

  using pred_iterator = CompileVector<CgBasicBlock *>::iterator;
  using const_pred_iterator = CompileVector<CgBasicBlock *>::const_iterator;
  using succ_iterator = CompileVector<CgBasicBlock *>::iterator;
  using const_succ_iterator = CompileVector<CgBasicBlock *>::const_iterator;
  using pred_reverse_iterator = CompileVector<CgBasicBlock *>::reverse_iterator;
  using const_pred_reverse_iterator =
      CompileVector<CgBasicBlock *>::const_reverse_iterator;
  using succ_reverse_iterator = CompileVector<CgBasicBlock *>::reverse_iterator;
  using const_succ_reverse_iterator =
      CompileVector<CgBasicBlock *>::const_reverse_iterator;
  pred_iterator pred_begin() { return Predecessors.begin(); }
  const_pred_iterator pred_begin() const { return Predecessors.begin(); }
  pred_iterator pred_end() { return Predecessors.end(); }
  const_pred_iterator pred_end() const { return Predecessors.end(); }
  pred_reverse_iterator pred_rbegin() { return Predecessors.rbegin(); }
  const_pred_reverse_iterator pred_rbegin() const {
    return Predecessors.rbegin();
  }
  pred_reverse_iterator pred_rend() { return Predecessors.rend(); }
  const_pred_reverse_iterator pred_rend() const { return Predecessors.rend(); }
  unsigned pred_size() const { return (unsigned)Predecessors.size(); }
  bool pred_empty() const { return Predecessors.empty(); }
  succ_iterator succ_begin() { return Successors.begin(); }
  const_succ_iterator succ_begin() const { return Successors.begin(); }
  succ_iterator succ_end() { return Successors.end(); }
  const_succ_iterator succ_end() const { return Successors.end(); }
  succ_reverse_iterator succ_rbegin() { return Successors.rbegin(); }
  const_succ_reverse_iterator succ_rbegin() const {
    return Successors.rbegin();
  }
  succ_reverse_iterator succ_rend() { return Successors.rend(); }
  const_succ_reverse_iterator succ_rend() const { return Successors.rend(); }
  unsigned succ_size() const { return (unsigned)Successors.size(); }
  bool succ_empty() const { return Successors.empty(); }

  inline iterator_range<pred_iterator> predecessors() {
    return make_range(pred_begin(), pred_end());
  }
  inline iterator_range<const_pred_iterator> predecessors() const {
    return make_range(pred_begin(), pred_end());
  }
  inline iterator_range<succ_iterator> successors() {
    return make_range(succ_begin(), succ_end());
  }
  inline iterator_range<const_succ_iterator> successors() const {
    return make_range(succ_begin(), succ_end());
  }
  inline iterator_range<iterator> terminators() {
    return make_range(getFirstTerminator(), end());
  }
  inline iterator_range<const_iterator> terminators() const {
    return make_range(getFirstTerminator(), end());
  }

  /// Possible outcome of a register liveness query to
  /// computeRegisterLiveness()
  enum LivenessQueryResult {
    LQR_Live,   ///< Register is known to be (at least partially) live.
    LQR_Dead,   ///< Register is known to be fully dead.
    LQR_Unknown ///< Register liveness not decidable from local
                ///< neighborhood.
  };

  /// Return whether (physical) register \p Reg has been defined and not
  /// killed as of just before \p Before.
  ///
  /// Search is localised to a neighborhood of \p Neighborhood instructions
  /// before (searching for defs or kills) and \p Neighborhood instructions
  /// after (searching just for defs) \p Before.
  ///
  /// \p Reg must be a physical register.
  LivenessQueryResult computeRegisterLiveness(const TargetRegisterInfo *TRI,
                                              MCRegister Reg,
                                              const_iterator Before,
                                              unsigned Neighborhood = 10) const;

  void addSuccessorWithoutProb(CgBasicBlock *Succ) {
    // We need to make sure probability list is either empty or has the same
    // size of successor list. When this function is called, we can safely
    // delete all probability in the list. Probs.clear();
    Successors.push_back(Succ);
    Succ->addPredecessor(this);
  }

  void removeSuccessor(CgBasicBlock *Succ);
  void removeSuccessor(succ_iterator It);

  bool isSuccessor(const CgBasicBlock *MBB) const {
    return is_contained(successors(), MBB);
  }

  void addPredecessor(CgBasicBlock *Pred) { Predecessors.push_back(Pred); }
  void removePredecessor(CgBasicBlock *Pred);
  void replaceSuccessor(CgBasicBlock *Old, CgBasicBlock *New);

  // Only call this method when you are certain that all blocks have been added
  // to the basic block list.
  bool isLayoutSuccessor(const CgBasicBlock *MBB) const {
    return getNumber() + 1 == MBB->getNumber();
  }

  const_iterator getFirstTerminator() const {
    return const_cast<CgBasicBlock *>(this)->getFirstTerminator();
  }

  iterator getFirstTerminator() {
    iterator B = begin(), E = end(), I = E;
    while (I != B && (--I)->isTerminator())
      ; /*noop */
    while (I != E && !I->isTerminator())
      ++I;
    return I;
  }

  // LiveIn management methods.

  using LiveInVector = CompileVector<RegisterMaskPair>;
  // Iteration support for live in sets.  These sets are kept in sorted
  // order by their register number.
  using livein_iterator = LiveInVector::const_iterator;

  /// Adds the specified register as a live in. Note that it is an error to
  /// add the same register to the same set more than once unless the
  /// intention is to call sortUniqueLiveIns after all registers are added.
  void addLiveIn(MCRegister PhysReg,
                 LaneBitmask LaneMask = LaneBitmask::getAll()) {
    LiveIns.push_back(RegisterMaskPair(PhysReg, LaneMask));
  }
  void addLiveIn(const RegisterMaskPair &RegMaskPair) {
    LiveIns.push_back(RegMaskPair);
  }

  void sortUniqueLiveIns();

  /// Return true if the specified register is in the live in set.
  bool isLiveIn(MCPhysReg Reg,
                LaneBitmask LaneMask = LaneBitmask::getAll()) const {
    livein_iterator I = find_if(LiveIns, [Reg](const RegisterMaskPair &LI) {
      return LI.PhysReg == Reg;
    });
    return I != livein_end() && (I->LaneMask & LaneMask).any();
  }

  livein_iterator livein_begin() const { return LiveIns.begin(); }
  livein_iterator livein_end() const { return LiveIns.end(); }
  bool livein_empty() const { return LiveIns.empty(); }
  iterator_range<livein_iterator> liveins() const {
    return make_range(livein_begin(), livein_end());
  }

  /// Return probability of the edge from this block to MBB. This method
  /// should
  /// NOT be called directly, but by using getEdgeProbability method from
  /// CgBranchProbabilityInfo class.
  BranchProbability getSuccProbability(const_succ_iterator Succ) const {
    return BranchProbability(1, succ_size());
  }

  llvm::Optional<uint64_t> getIrrLoopHeaderWeight() const { return 0; }

#if defined(ZEN_ENABLE_EVM) && defined(ZEN_ENABLE_LINUX_PERF)
  void setSourceOffset(uint64_t Offset) { SourceOffset = Offset; }
  uint64_t getSourceOffset() const { return SourceOffset; }

  void setSourceName(const std::string &Name) { SourceName = Name; }
  std::string getSourceName() const { return SourceName; }
#endif // ZEN_ENABLE_EVM && ZEN_ENABLE_LINUX_PERF

private:
  uint32_t _idx;
  CgFunction *_parent;
  CgInstructionListType _cg_instructions;

  CompileVector<CgBasicBlock *> Predecessors;
  CompileVector<CgBasicBlock *> Successors;

  /// Keep track of the physical registers that are livein of the basicblock.
  LiveInVector LiveIns;

  /// since getSymbol is a relatively heavy-weight operation, the symbol
  /// is only computed once and is cached.
  mutable MCSymbol *BlockSymbol = nullptr;
#if defined(ZEN_ENABLE_EVM) && defined(ZEN_ENABLE_LINUX_PERF)
  uint64_t SourceOffset = 0;
  std::string SourceName;
#endif // ZEN_ENABLE_EVM && ZEN_ENABLE_LINUX_PERF
};

/// CgInstrSpan provides an interface to get an iteration range
/// containing the instruction it was initialized with, along with all
/// those instructions inserted prior to or following that instruction
/// at some point after the CgInstrSpan is constructed.
class CgInstrSpan {
  CgBasicBlock &MBB;
  CgBasicBlock::iterator I, B, E;

public:
  CgInstrSpan(CgBasicBlock::iterator I, CgBasicBlock *BB)
      : MBB(*BB), I(I), B(I == MBB.begin() ? MBB.end() : std::prev(I)),
        E(std::next(I)) {
    assert(I == BB->end() || I->getParent() == BB);
  }

  CgBasicBlock::iterator begin() {
    return B == MBB.end() ? MBB.begin() : std::next(B);
  }
  CgBasicBlock::iterator end() { return E; }
  bool empty() { return begin() == end(); }

  CgBasicBlock::iterator getInitial() { return I; }
};

} // namespace COMPILER

inline Printable printCgBBReference(const CgBasicBlock &MBB) {
  return Printable([&MBB](raw_ostream &OS) { return MBB.printAsOperand(OS); });
}

namespace llvm {
using namespace COMPILER;
inline raw_ostream &operator<<(raw_ostream &OS, const CgBasicBlock &MBB) {
  MBB.print(OS);
  return OS;
}

//===--------------------------------------------------------------------===//
// GraphTraits specializations for machine basic block graphs (machine-CFGs)
//===--------------------------------------------------------------------===//

// Provide specializations of GraphTraits to be able to treat a
// CgFunction as a graph of CgBasicBlocks.
//

template <> struct GraphTraits<CgBasicBlock *> {
  using NodeRef = CgBasicBlock *;
  using ChildIteratorType = CgBasicBlock::succ_iterator;

  static NodeRef getEntryNode(CgBasicBlock *BB) { return BB; }
  static ChildIteratorType child_begin(NodeRef N) { return N->succ_begin(); }
  static ChildIteratorType child_end(NodeRef N) { return N->succ_end(); }
};

template <> struct GraphTraits<const CgBasicBlock *> {
  using NodeRef = const CgBasicBlock *;
  using ChildIteratorType = CgBasicBlock::const_succ_iterator;

  static NodeRef getEntryNode(const CgBasicBlock *BB) { return BB; }
  static ChildIteratorType child_begin(NodeRef N) { return N->succ_begin(); }
  static ChildIteratorType child_end(NodeRef N) { return N->succ_end(); }
};

// Provide specializations of GraphTraits to be able to treat a
// CgFunction as a graph of CgBasicBlocks and to walk it
// in inverse order.  Inverse order for a function is considered
// to be when traversing the predecessor edges of a MBB
// instead of the successor edges.
//
template <> struct GraphTraits<Inverse<CgBasicBlock *>> {
  using NodeRef = CgBasicBlock *;
  using ChildIteratorType = CgBasicBlock::pred_iterator;

  static NodeRef getEntryNode(Inverse<CgBasicBlock *> G) { return G.Graph; }

  static ChildIteratorType child_begin(NodeRef N) { return N->pred_begin(); }
  static ChildIteratorType child_end(NodeRef N) { return N->pred_end(); }
};

template <> struct GraphTraits<Inverse<const CgBasicBlock *>> {
  using NodeRef = const CgBasicBlock *;
  using ChildIteratorType = CgBasicBlock::const_pred_iterator;

  static NodeRef getEntryNode(Inverse<const CgBasicBlock *> G) {
    return G.Graph;
  }

  static ChildIteratorType child_begin(NodeRef N) { return N->pred_begin(); }
  static ChildIteratorType child_end(NodeRef N) { return N->pred_end(); }
};

} // namespace llvm

#endif // COMPILER_IR_CG_BASIC_BLOCK_H
