/*
 * Copyright (C) 2021-2023 the DTVM authors.
 */
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#ifndef COMPILER_IR_CG_INSTRUCTION_H
#define COMPILER_IR_CG_INSTRUCTION_H

#include "compiler/cgir/cg_operand.h"
#include "compiler/context.h"
#include "llvm/ADT/ilist.h"
#include "llvm/MC/MCInstrDesc.h"

namespace llvm {
struct PhysRegInfo;
}

namespace COMPILER {

class CgFunction;
class CgBasicBlock;
class CgRegisterInfo;
class CgInstruction
    : public ContextObject,
      public llvm::ilist_node_with_parent<CgInstruction, CgBasicBlock> {
  friend class CgFunction;
  friend class CgOperand;

  using iterator = CgOperand *;
  using const_iterator = const CgOperand *;

  enum QueryType {
    IgnoreBundle, // Ignore bundles
    AnyInBundle,  // Return true if any instruction in bundle has property
    AllInBundle   // Return true if all instructions in bundle have property
  };

public:
  enum MIFlag {
    NoFlags = 0,
    FrameSetup = 1 << 0,   // Instruction is used as a part of
                           // function frame setup code.
    FrameDestroy = 1 << 1, // Instruction is used as a part of
                           // function frame destruction code.
    BundledPred = 1 << 2,  // Instruction has bundled predecessors.
    BundledSucc = 1 << 3,  // Instruction has bundled successors.
    FmNoNans = 1 << 4,     // Instruction does not support Fast
                           // math nan values.
    FmNoInfs = 1 << 5,     // Instruction does not support Fast
                           // math infinity values.
    FmNsz = 1 << 6,        // Instruction is not required to retain
                           // signed zero values.
    FmArcp = 1 << 7,       // Instruction supports Fast math
                           // reciprocal approximations.
    FmContract = 1 << 8,   // Instruction supports Fast math
                           // contraction operations like fma.
    FmAfn = 1 << 9,        // Instruction may map to Fast math
                           // intrinsic approximation.
    FmReassoc = 1 << 10,   // Instruction supports Fast math
                           // reassociation of operand order.
    NoUWrap = 1 << 11,     // Instruction supports binary operator
                           // no unsigned wrap.
    NoSWrap = 1 << 12,     // Instruction supports binary operator
                           // no signed wrap.
    IsExact = 1 << 13,     // Instruction supports division is
                           // known to be exact.
    NoFPExcept = 1 << 14,  // Instruction does not raise
                           // floatint-point exceptions.
    NoMerge = 1 << 15,     // Passes that drop source location info
                           // (e.g. branch folding) should skip
                           // this instruction.
  };

public:
  ~CgInstruction();
  /// Return whether an MI flag is set.
  bool getFlag(MIFlag Flag) const { return Flags & Flag; }

  /// Set a MI flag.
  void setFlag(MIFlag Flag) { Flags |= (uint16_t)Flag; }
  unsigned getFlags() const { return Flags; }
  void setFlags(unsigned flags) {
    // Filter out the automatically maintained flags.
    unsigned Mask = BundledPred | BundledSucc;
    Flags = (Flags & Mask) | (flags & ~Mask);
  }

  const CgBasicBlock *getParent() const { return Parent; }
  CgBasicBlock *getParent() { return Parent; }

  /// Return the function that contains the basic block that this instruction
  /// belongs to.
  ///
  /// Note: this is undefined behaviour if the instruction does not have a
  /// parent.
  const CgFunction *getMF() const;
  CgFunction *getMF() {
    return const_cast<CgFunction *>(
        static_cast<const CgInstruction *>(this)->getMF());
  }

  // Intrusive list support
  friend struct ilist_traits<CgInstruction>;
  friend struct ilist_callback_traits<CgBasicBlock>;
  void setParent(CgBasicBlock *P) { Parent = P; }

  unsigned getOpcode() const { return MCID->Opcode; }
  const MCInstrDesc &getDesc() const { return *MCID; }
  void setDesc(const MCInstrDesc &TID) { MCID = &TID; }

  /// Returns the number of non-implicit operands.
  unsigned getNumExplicitOperands() const;

  /// Returns the number of non-implicit definitions.
  unsigned getNumExplicitDefs() const;

  const_iterator begin() const { return Operands; }
  const_iterator end() const { return Operands + NumOperands; }
  iterator begin() { return Operands; }
  iterator end() { return Operands + NumOperands; }
  iterator_range<iterator> operands() { return make_range(begin(), end()); }
  iterator_range<const_iterator> operands() const {
    return make_range(begin(), end());
  }

  /// Returns a range over all operands that are used to determine the
  /// variable
  /// location for this DBG_VALUE instruction.
  iterator_range<iterator> debug_operands() {
    assert(isDebugValue() && "Must be a debug value instruction.");
    return isDebugValueList() ? make_range(begin() + 2, end())
                              : make_range(begin(), begin() + 1);
  }
  /// \copydoc debug_operands()
  iterator_range<const_iterator> debug_operands() const {
    assert(isDebugValue() && "Must be a debug value instruction.");
    return isDebugValueList() ? make_range(begin() + 2, end())
                              : make_range(begin(), begin() + 1);
  }

  using mop_iterator = iterator;
  using const_mop_iterator = const_iterator;

  /// Returns a range over all explicit operands that are register definitions.
  /// Implicit definition are not included!
  iterator_range<mop_iterator> defs() {
    return make_range(begin(), begin() + getNumExplicitDefs());
  }
  /// \copydoc defs()
  iterator_range<const_mop_iterator> defs() const {
    return make_range(begin(), begin() + getNumExplicitDefs());
  }
  /// Returns a range that includes all operands that are register uses.
  /// This may include unrelated operands which are not register uses.
  iterator_range<mop_iterator> uses() {
    return make_range(begin() + getNumExplicitDefs(), end());
  }
  /// \copydoc uses()
  iterator_range<const_mop_iterator> uses() const {
    return make_range(begin() + getNumExplicitDefs(), end());
  }
  iterator_range<mop_iterator> explicit_uses() {
    return make_range(begin() + getNumExplicitDefs(),
                      begin() + getNumExplicitOperands());
  }
  iterator_range<const_mop_iterator> explicit_uses() const {
    return make_range(begin() + getNumExplicitDefs(),
                      begin() + getNumExplicitOperands());
  }

  CgOperand &getOperand(uint32_t i) {
    ZEN_ASSERT(i < NumOperands);
    return Operands[i];
  }
  const CgOperand &getOperand(uint32_t i) const {
    ZEN_ASSERT(i < NumOperands);
    return Operands[i];
  }

  /// Returns the number of the operand iterator \p I points to.
  unsigned getOperandNo(const_mop_iterator I) const { return I - begin(); }

  /// Returns whether this debug value has at least one debug operand with the
  /// register \p Reg.
  bool hasDebugOperandForReg(CgRegister Reg) const {
    return any_of(debug_operands(), [Reg](const CgOperand &Op) {
      return Op.isReg() && Op.getReg() == Reg;
    });
  }

  unsigned getNumOperands() const { return NumOperands; }

  bool memoperands_empty() const { return true; }

  /// Returns the total number of definitions.
  unsigned getNumDefs() const {
    return getNumExplicitDefs() + MCID->getNumImplicitDefs();
  }

  void eraseFromParent();
  void eraseFromBundle() { eraseFromParent(); }
  CgInstruction *removeFromBundle();

  bool isCopy() const { return getOpcode() == llvm::TargetOpcode::COPY; }
  bool isFullCopy() const {
    return isCopy() && !getOperand(0).getSubReg() && !getOperand(1).getSubReg();
  }

  /// Return true if the instruction behaves like a copy.
  /// This does not include native copy instructions.
  bool isCopyLike() const { return isCopy() || isSubregToReg(); }

  /// Return true is the instruction is an identity copy.
  bool isIdentityCopy() const {
    return isCopy() && getOperand(0).getReg() == getOperand(1).getReg() &&
           getOperand(0).getSubReg() == getOperand(1).getSubReg();
  }

  /// Return true if the CgInstruction reads the specified register.
  /// If TargetRegisterInfo is passed, then it also checks if there
  /// is a read of a super-register.
  /// This does not count partial redefines of virtual registers as reads:
  ///   %reg1024:6 = OP.
  bool readsRegister(CgRegister Reg,
                     const TargetRegisterInfo *TRI = nullptr) const {
    return findRegisterUseOperandIdx(Reg, false, TRI) != -1;
  }

  bool isImplicitDef() const {
    return getOpcode() == TargetOpcode::IMPLICIT_DEF;
  }
  bool isMoveImmediate(QueryType Type = IgnoreBundle) const {
    return hasProperty(MCID::MoveImm, Type);
  }
  bool isSubregToReg() const {
    return getOpcode() == TargetOpcode::SUBREG_TO_REG;
  }
  bool isKill() const { return getOpcode() == TargetOpcode::KILL; }

  /// If this instruction is embedded into a CgFunction, return the
  /// CgRegisterInfo object for the current function, otherwise
  /// return null.
  CgRegisterInfo *getRegInfo();

  void addRegOperandsToUseLists(CgRegisterInfo &MRI);

  void removeRegOperandsFromUseLists(CgRegisterInfo &MRI);

  bool hasProperty(unsigned MCFlag, QueryType Type = AnyInBundle) const {
    assert(MCFlag < 64 && "MCFlag out of range for bit mask in "
                          "getFlags/hasPropertyInBundle.");
#if 0
    // Inline the fast path for unbundled or bundle-internal instructions.
    if (Type == IgnoreBundle || !isBundled() || isBundledWithPred())
      return getDesc().getFlags() & (1ULL << MCFlag);

    // If this is the first instruction in a bundle, take the slow path.
    return hasPropertyInBundle(1ULL << MCFlag, Type);
#endif
    return getDesc().getFlags() & (1ULL << MCFlag);
  }

  /// Return true if this is a pseudo instruction that doesn't
  /// correspond to a real machine instruction.
  bool isPseudo(QueryType Type = IgnoreBundle) const {
    return hasProperty(MCID::Pseudo, Type);
  }

  bool isReturn(QueryType Type = AnyInBundle) const {
    return hasProperty(MCID::Return, Type);
  }

  bool isCall(QueryType Type = AnyInBundle) const {
    return hasProperty(MCID::Call, Type);
  }
  bool isPHI() const {
    return getOpcode() == TargetOpcode::PHI ||
           getOpcode() == TargetOpcode::G_PHI;
  }
  bool isBundle() const { return getOpcode() == TargetOpcode::BUNDLE; }

  bool isInlineAsm() const {
    return getOpcode() == TargetOpcode::INLINEASM ||
           getOpcode() == TargetOpcode::INLINEASM_BR;
  }

  /// Return true if this instruction part of a bundle. This is true
  /// if either itself or its following instruction is marked "InsideBundle".
  bool isBundled() const { return isBundledWithPred() || isBundledWithSucc(); }

  /// Return true if this instruction is part of a bundle, and it is not the
  /// first instruction in the bundle.
  bool isBundledWithPred() const { return getFlag(BundledPred); }

  /// Return true if this instruction is part of a bundle, and it is not the
  /// last instruction in the bundle.
  bool isBundledWithSucc() const { return getFlag(BundledSucc); }

  /// Returns true if the specified instruction stops control flow
  /// from executing the instruction immediately following it.  Examples
  /// include unconditional branches and return instructions.
  bool isBarrier(QueryType Type = AnyInBundle) const {
    return hasProperty(MCID::Barrier, Type);
  }

  /// Returns true if this instruction part of the terminator for a basic
  /// block. Typically this is things like return and branch instructions.
  ///
  /// Various passes use this to insert code into the bottom of a basic block,
  /// but before control flow occurs.
  bool isTerminator(QueryType Type = AnyInBundle) const {
    return hasProperty(MCID::Terminator, Type);
  }

  /// Returns true if this is a conditional, unconditional, or indirect
  /// branch. Predicates below can be used to discriminate between these
  /// cases, and the TargetInstrInfo::analyzeBranch method can be used to get
  /// more information.
  bool isBranch(QueryType Type = AnyInBundle) const {
    return hasProperty(MCID::Branch, Type);
  }

  /// Return true if this is an indirect branch, such as a
  /// branch through a register.
  bool isIndirectBranch(QueryType Type = AnyInBundle) const {
    return hasProperty(MCID::IndirectBranch, Type);
  }

  /// Return true if this is a branch which may fall
  /// through to the next instruction or may transfer control flow to some
  /// other block.  The TargetInstrInfo::analyzeBranch method can be used to
  /// get more information about this branch.
  bool isConditionalBranch(QueryType Type = AnyInBundle) const {
    return isBranch(Type) && !isBarrier(Type) && !isIndirectBranch(Type);
  }

  /// Return true if this is a branch which always
  /// transfers control flow to some other block.  The
  /// TargetInstrInfo::analyzeBranch method can be used to get more
  /// information about this branch.
  bool isUnconditionalBranch(QueryType Type = AnyInBundle) const {
    return isBranch(Type) && isBarrier(Type) && !isIndirectBranch(Type);
  }

  /// Return true if this instruction is a comparison.
  bool isCompare(QueryType Type = IgnoreBundle) const {
    return hasProperty(MCID::Compare, Type);
  }

  /// Return true if this may be a 2- or 3-address
  /// instruction (of the form "X = op Y, Z, ..."), which produces the same
  /// result if Y and Z are exchanged.  If this flag is set, then the
  /// TargetInstrInfo::commuteInstruction method may be used to hack on the
  /// instruction.
  ///
  /// Note that this flag may be set on instructions that are only commutable
  /// sometimes.  In these cases, the call to commuteInstruction will fail.
  /// Also note that some instructions require non-trivial modification to
  /// commute them.
  bool isCommutable(QueryType Type = IgnoreBundle) const {
    return hasProperty(MCID::Commutable, Type);
  }

  bool isPseudoProbe() const {
    return getOpcode() == TargetOpcode::PSEUDO_PROBE;
  }

  bool isNonListDebugValue() const {
    return getOpcode() == TargetOpcode::DBG_VALUE;
  }
  bool isDebugValueList() const {
    return getOpcode() == TargetOpcode::DBG_VALUE_LIST;
  }
  bool isDebugValue() const {
    return isNonListDebugValue() || isDebugValueList();
  }
  bool isDebugOrPseudoInstr() const {
    return isDebugInstr() || isPseudoProbe();
  }

  bool isEHLabel() const { return getOpcode() == TargetOpcode::EH_LABEL; }
  bool isGCLabel() const { return getOpcode() == TargetOpcode::GC_LABEL; }
  bool isAnnotationLabel() const {
    return getOpcode() == TargetOpcode::ANNOTATION_LABEL;
  }
  bool isLabel() const {
    return isEHLabel() || isGCLabel() || isAnnotationLabel();
  }

  bool isCFIInstruction() const {
    return getOpcode() == TargetOpcode::CFI_INSTRUCTION;
  }
  bool isPosition() const { return isLabel() || isCFIInstruction(); }
  bool isDebugLabel() const { return getOpcode() == TargetOpcode::DBG_LABEL; }
  bool isDebugRef() const { return getOpcode() == TargetOpcode::DBG_INSTR_REF; }
  bool isDebugPHI() const { return getOpcode() == TargetOpcode::DBG_PHI; }
  bool isDebugInstr() const {
    return isDebugValue() || isDebugLabel() || isDebugRef() || isDebugPHI();
  }

  /// Return true if the CgInstruction reads the specified virtual register.
  /// Take into account that a partial define is a read-modify-write
  /// operation.
  bool readsVirtualRegister(Register Reg) const {
    return readsWritesVirtualRegister(Reg).first;
  }

  /// Return a pair of bools (reads, writes) indicating if this instruction
  /// reads or writes Reg. This also considers partial defines.
  /// If Ops is not null, all operand indices for Reg are added.
  std::pair<bool, bool>
  readsWritesVirtualRegister(Register Reg,
                             SmallVectorImpl<unsigned> *Ops = nullptr) const;

  /// Return true if the use operand of the specified index is tied to a def
  /// operand. It also returns the def operand index by reference if DefOpIdx
  /// is not null.
  bool isRegTiedToDefOperand(unsigned UseOpIdx,
                             unsigned *DefOpIdx = nullptr) const {
    const CgOperand &MO = getOperand(UseOpIdx);
    if (!MO.isReg() || !MO.isUse() || !MO.isTied())
      return false;
    if (DefOpIdx)
      *DefOpIdx = findTiedOperandIdx(UseOpIdx);
    return true;
  }

  /// Given the index of a register def operand,
  /// check if the register def is tied to a source operand, due to either
  /// two-address elimination or inline assembly constraints. Returns the
  /// first tied use operand index by reference if UseOpIdx is not null.
  bool isRegTiedToUseOperand(unsigned DefOpIdx,
                             unsigned *UseOpIdx = nullptr) const {
    const CgOperand &MO = getOperand(DefOpIdx);
    if (!MO.isReg() || !MO.isDef() || !MO.isTied())
      return false;
    if (UseOpIdx)
      *UseOpIdx = findTiedOperandIdx(DefOpIdx);
    return true;
  }

  /// We have determined MI kills a register. Look for the
  /// operand that uses it and mark it as IsKill. If AddIfNotFound is true,
  /// add a implicit operand if it's not found. Returns true if the operand
  /// exists / is added.
  bool addRegisterKilled(Register IncomingReg,
                         const TargetRegisterInfo *RegInfo,
                         bool AddIfNotFound = false);

  /// Clear all kill flags affecting Reg.  If RegInfo is provided, this
  /// includes all aliasing registers.
  void clearRegisterKills(Register Reg, const TargetRegisterInfo *RegInfo);

  /// We have determined MI defined a register without a use.
  /// Look for the operand that defines it and mark it as IsDead. If
  /// AddIfNotFound is true, add a implicit operand if it's not found. Returns
  /// true if the operand exists / is added.
  bool addRegisterDead(Register Reg, const TargetRegisterInfo *RegInfo,
                       bool AddIfNotFound = false);

  void addRegisterDefined(Register Reg,
                          const TargetRegisterInfo *RegInfo = nullptr);
  /// Mark all subregister defs of register @p Reg with the undef flag.
  /// This function is used when we determined to have a subregister def in an
  /// otherwise undefined super register.
  void setRegisterDefReadUndef(Register Reg, bool IsUndef = true);

  /// Return true if all the defs of this instruction are dead.
  bool allDefsAreDead() const;

  bool isNotDuplicable(QueryType Type = AnyInBundle) const {
    return hasProperty(MCID::NotDuplicable, Type);
  }
  /// Return true if this instruction could possibly read memory.
  /// Instructions with this flag set are not necessarily simple load
  /// instructions, they may load a value and modify it, for example.
  bool mayLoad(QueryType Type = AnyInBundle) const {
    if (isInlineAsm()) {
      unsigned ExtraInfo = getOperand(InlineAsm::MIOp_ExtraInfo).getImm();
      if (ExtraInfo & InlineAsm::Extra_MayLoad)
        return true;
    }
    return hasProperty(MCID::MayLoad, Type);
  }

  /// Return true if this instruction could possibly modify memory.
  /// Instructions with this flag set are not necessarily simple store
  /// instructions, they may store a modified value based on their operands,
  /// or may not actually modify anything, for example.
  bool mayStore(QueryType Type = AnyInBundle) const {
    if (isInlineAsm()) {
      unsigned ExtraInfo = getOperand(InlineAsm::MIOp_ExtraInfo).getImm();
      if (ExtraInfo & InlineAsm::Extra_MayStore)
        return true;
    }
    return hasProperty(MCID::MayStore, Type);
  }

  /// Return true if this instruction could possibly read or modify memory.
  bool mayLoadOrStore(QueryType Type = AnyInBundle) const {
    return mayLoad(Type) || mayStore(Type);
  }

  bool hasOrderedMemoryRef() const;

  /// Returns true if this instruction source operands
  /// have special register allocation requirements that are not captured by
  /// the operand register classes. e.g. ARM::STRD's two source registers must
  /// be an even / odd pair, ARM::STM registers have to be in ascending order.
  /// Post-register allocation passes should not attempt to change allocations
  /// for sources of instructions with this flag.
  bool hasExtraSrcRegAllocReq(QueryType Type = AnyInBundle) const {
    return hasProperty(MCID::ExtraSrcRegAllocReq, Type);
  }

  /// Returns true if this instruction def operands
  /// have special register allocation requirements that are not captured by
  /// the operand register classes. e.g. ARM::LDRD's two def registers must be
  /// an even / odd pair, ARM::LDM registers have to be in ascending order.
  /// Post-register allocation passes should not attempt to change allocations
  /// for definitions of instructions with this flag.
  bool hasExtraDefRegAllocReq(QueryType Type = AnyInBundle) const {
    return hasProperty(MCID::ExtraDefRegAllocReq, Type);
  }

  /// Return true if this instruction could possibly raise a floating-point
  /// exception.  This is the case if the instruction is a floating-point
  /// instruction that can in principle raise an exception, as indicated
  /// by the MCID::MayRaiseFPException property, *and* at the same time,
  /// the instruction is used in a context where we expect floating-point
  /// exceptions are not disabled, as indicated by the NoFPExcept MI flag.
  bool mayRaiseFPException() const {
    return hasProperty(MCID::MayRaiseFPException) &&
           !getFlag(MIFlag::NoFPExcept);
  }

  bool hasUnmodeledSideEffects() const;
  bool isDereferenceableInvariantLoad() const;
  bool isAsCheapAsAMove(QueryType Type = AllInBundle) const {
    // Only returns true for a bundle if all bundled instructions are cheap.
    return hasProperty(MCID::CheapAsAMove, Type);
  }
  bool canFoldAsLoad(QueryType Type = IgnoreBundle) const {
    return hasProperty(MCID::FoldableAsLoad, Type);
  }

  bool isSafeToMove(void *AA, bool &SawStore) const;

  void substituteRegister(Register FromReg, Register ToReg, unsigned SubIdx,
                          const TargetRegisterInfo &RegInfo);
  CgOperand *findRegisterDefOperand(Register Reg, bool isDead = false,
                                    bool Overlap = false,
                                    const TargetRegisterInfo *TRI = nullptr) {
    int Idx = findRegisterDefOperandIdx(Reg, isDead, Overlap, TRI);
    return (Idx == -1) ? nullptr : &getOperand(Idx);
  }
  int findRegisterDefOperandIdx(Register Reg, bool isDead = false,
                                bool Overlap = false,
                                const TargetRegisterInfo *TRI = nullptr) const;
  bool modifiesRegister(Register Reg,
                        const TargetRegisterInfo *TRI = nullptr) const {
    return findRegisterDefOperandIdx(Reg, false, true, TRI) != -1;
  }

  const TargetRegisterClass *
  getRegClassConstraint(unsigned OpIdx, const TargetInstrInfo *TII,
                        const TargetRegisterInfo *TRI) const;

  const TargetRegisterClass *
  getRegClassConstraintEffect(unsigned OpIdx, const TargetRegisterClass *CurRC,
                              const TargetInstrInfo *TII,
                              const TargetRegisterInfo *TRI) const;

  /// Break any tie involving OpIdx.
  void untieRegOperand(unsigned OpIdx) {
    CgOperand &MO = getOperand(OpIdx);
    if (MO.isReg() && MO.isTied()) {
      getOperand(findTiedOperandIdx(OpIdx) - 1).TiedTo = 0;
      MO.TiedTo = 0;
    }
  }

  unsigned findTiedOperandIdx(unsigned OpIdx) const;

  /// Returns the operand index that is a use of the specific register or -1
  /// if it is not found. It further tightens the search criteria to a use
  /// that kills the register if isKill is true.
  int findRegisterUseOperandIdx(Register Reg, bool isKill = false,
                                const TargetRegisterInfo *TRI = nullptr) const;

  /// Add the specified operand to the instruction.  If it is an implicit
  /// operand, it is added to the end of the operand list.  If it is an
  /// explicit operand it is added at the end of the explicit operand list
  /// (before the first implicit operand).
  ///
  /// MF must be the machine function that was used to allocate this
  /// instruction.
  ///
  /// MachineInstrBuilder provides a more convenient interface for creating
  /// instructions and adding operands.
  void addOperand(CgFunction &MF, const CgOperand &Op);

  /// Add an operand without providing an MF reference. This only works for
  /// instructions that are inserted in a basic block.
  ///
  /// MachineInstrBuilder and the two-argument addOperand(MF, MO) should be
  /// preferred.
  void addOperand(const CgOperand &Op);

  /// Erase an operand from an instruction, leaving it with one
  /// fewer operand than it started with.
  void removeOperand(unsigned OpNo);

  llvm::PhysRegInfo AnalyzePhysRegInBundle(CgRegister Reg,
                                           const TargetRegisterInfo *TRI) const;

  /// Sets all register debug operands in this debug value instruction to be
  /// undef.
  void setDebugValueUndef() {
    assert(isDebugValue() && "Must be a debug value instruction.");
    for (CgOperand &MO : debug_operands()) {
      if (MO.isReg()) {
        MO.setReg(0);
        MO.setSubReg(0);
      }
    }
  }

  void dump() const;
  void print(llvm::raw_ostream &OS) const;

private:
  //    CgInstruction(const MCInstrDesc &mcid, ArrayRef<CgOperand> operands,
  //                 bool no_implicit);
  CgInstruction(const llvm::MCInstrDesc &mcid,
                llvm::ArrayRef<CgOperand> operands, bool no_implicit,
                CompileContext &Context);
  CgInstruction(CgFunction &, const CgInstruction &);

  void tieOperands(unsigned DefIdx, unsigned UseIdx);

  /// Given the index of a tied register operand, find the
  /// operand it is tied to. Defs are tied to uses and vice versa. Returns the
  /// index of the tied operand which must exist.

  CgBasicBlock *Parent = nullptr;
  const llvm::MCInstrDesc *MCID;
  unsigned NumOperands = 0;
  unsigned CapOperands = 0;
  CgOperand *Operands = nullptr;
  uint16_t Flags = 0;
};

} // namespace COMPILER

namespace llvm {

template <> struct ilist_traits<COMPILER::CgInstruction> {
private:
  friend class COMPILER::CgBasicBlock; // Set by the owning CgBasicBlock.

  COMPILER::CgBasicBlock *Parent;

  using instr_iterator = simple_ilist<COMPILER::CgInstruction>::iterator;

public:
  void addNodeToList(COMPILER::CgInstruction *N);
  void removeNodeFromList(COMPILER::CgInstruction *N);
  void transferNodesFromList(ilist_traits &FromList, instr_iterator First,
                             instr_iterator Last);
  void deleteNode(COMPILER::CgInstruction *MI);
};

inline raw_ostream &operator<<(raw_ostream &OS,
                               const COMPILER::CgInstruction &MI) {
  MI.print(OS);
  return OS;
}
} // namespace llvm

#endif // COMPILER_IR_CG_INSTRUCTION_H
