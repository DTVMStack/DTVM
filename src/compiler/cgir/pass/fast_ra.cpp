/*
 * Copyright (C) 2021-2023 the DTVM authors.
 */
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "compiler/cgir/pass/fast_ra.h"
#include "compiler/cgir/pass/cg_frame_info.h"
#include "compiler/cgir/pass/cg_register_class_info.h"
#include "compiler/common/llvm_workaround.h"
#include "compiler/context.h"
#include "llvm/ADT/IndexedMap.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SparseSet.h"
#include "llvm/MC/MCRegister.h"
#include "llvm/Support/Debug.h"

using namespace COMPILER;

using namespace llvm;

#define DEBUG_TYPE "regalloc"
//
// STATISTIC(NumStores, "Number of stores added");
// STATISTIC(NumLoads , "Number of loads added");
// STATISTIC(NumCoalesced, "Number of copies coalesced");
//
//
// static RegisterRegAlloc
//  fastRegAlloc("fast", "fast register allocator",
//  createFastRegisterAllocator);

static bool isCoalescable(const CgInstruction &MI) { return MI.isFullCopy(); }

static bool dominates(CgBasicBlock &MBB, CgBasicBlock::const_iterator A,
                      CgBasicBlock::const_iterator B) {
  auto MBBEnd = MBB.end();
  if (B == MBBEnd)
    return true;

  CgBasicBlock::const_iterator I = MBB.begin();
  for (; I != A && I != B; ++I)
    ;

  return I == A;
}

class FastRA::Impl {
public:
  using inst_reverse_iterator = CgBasicBlock::reverse_iterator;
  using inst_iterator = CgBasicBlock::iterator;
  enum RegUnitState {
    regFree,
    regPreAssigned,
    regLiveIn,
  };

  struct LiveReg {
    CgInstruction *LastUse = nullptr; ///< Last instr to use reg.

    CgRegister VirtReg;
    MCPhysReg PhysReg = 0;
    bool Reloaded = false;
    bool LiveOut = false; ///< Register is possibly live out.

    explicit LiveReg(CgRegister vreg) : VirtReg(vreg) {}

    unsigned getSparseSetIndex() const {
      return Register::virtReg2Index(VirtReg);
    }
  };

  enum : unsigned {
    spillClean = 50,
    spillDirty = 100,
    spillPrefBonus = 20,
    spillImpossible = ~0u
  };

  CgFunction *_cg_func = nullptr;
  const TargetRegisterInfo *TRI = nullptr;
  const TargetInstrInfo *TII = nullptr;

  CgFrameInfo *MFI = nullptr;
  LLVMWorkaround *_llvm_workaround = nullptr;
  CgRegisterInfo *MRI = nullptr;
  CgBasicBlock *MBB = nullptr;

  std::vector<unsigned> RegUnitStates; // RegUnitState or vreg

  SmallVector<CgInstruction *, 32> coalesced;

  // The default 8-bit sparse index probes the dense set in strides of 256.
  // Use full-width indices so large-block clobber discovery stays bounded by
  // physical units rather than reintroducing a virtual-live-set scan.
  using LiveRegMap = SparseSet<LiveReg, identity<unsigned>, uint32_t>;
  LiveRegMap LiveVirtRegs;

  BitVector MayLiveAcrossBlocks;

  using RegUnitSet = SparseSet<uint16_t, identity<uint16_t>>;
  RegUnitSet UsedInInstr;
  RegUnitSet PhysRegUses;
  SmallVector<uint16_t, 8> DefOperandIndexes;
  // Register masks attached to the current instruction.
  SmallVector<const uint32_t *> RegMasks;

  CgRegisterClassInfo RegClassInfo;
  IndexedMap<int, VirtReg2IndexFunctor> StackSlotForVirtReg;

  Impl() : StackSlotForVirtReg(-1) {}

  void runOnCgFunction(CgFunction &cg_func) {
    _cg_func = &cg_func;

    TRI = &(cg_func.getRegisterInfo());
    TII = &(cg_func.getTargetInstrInfo());
    MRI = &(cg_func.getRegInfo());
    MFI = &(cg_func.getFrameInfo());
    _llvm_workaround = &(cg_func.getContext().getLLVMWorkaround());
    MRI->freezeReservedRegs(cg_func);
    RegClassInfo.runOnCgFunction(cg_func);

    unsigned NumRegUnits = TRI->getNumRegUnits();
    UsedInInstr.clear();
    UsedInInstr.setUniverse(NumRegUnits);
    PhysRegUses.clear();
    PhysRegUses.setUniverse(NumRegUnits);

    unsigned NumVirtRegs = MRI->getNumVirtRegs();
    StackSlotForVirtReg.resize(NumVirtRegs);
    LiveVirtRegs.setUniverse(NumVirtRegs);
    MayLiveAcrossBlocks.clear();
    MayLiveAcrossBlocks.resize(NumVirtRegs);

    for (auto *bb : cg_func) {
      allocateCgBasicBlock(*bb);
    }

    StackSlotForVirtReg.clear();
  }

  void allocateCgBasicBlock(CgBasicBlock &bb) {
    MBB = &bb;

    RegUnitStates.assign(TRI->getNumRegUnits(), regFree);
    coalesced.clear();

    for (auto &inst : reverse(bb)) {
      allocateCgInstruction(inst);
    }

    reloadAtBegin(bb);

    for (auto it : coalesced)
      bb.erase(it);
  }

  /// Returns false if \p VirtReg is known to not live out of the current
  /// block.
  bool mayLiveOut(Register VirtReg) {
    if (MayLiveAcrossBlocks.test(Register::virtReg2Index(VirtReg))) {
      // Cannot be live-out if there are no successors.
      return !MBB->succ_empty();
    }

    const CgInstruction *SelfLoopDef = nullptr;

    // If this block loops back to itself, it is necessary to check whether
    // the use comes after the def.
    if (MBB->isSuccessor(MBB)) {
      // Find the first def in the self loop MBB.
      for (const auto &DefInst : MRI->def_instructions(VirtReg)) {
        if (DefInst.getParent() != MBB) {
          MayLiveAcrossBlocks.set(Register::virtReg2Index(VirtReg));
          return true;
        } else {
          if (!SelfLoopDef || dominates(*MBB, DefInst.getIterator(),
                                        SelfLoopDef->getIterator()))
            SelfLoopDef = &DefInst;
        }
      }
      if (!SelfLoopDef) {
        MayLiveAcrossBlocks.set(Register::virtReg2Index(VirtReg));
        return true;
      }
    }

    // See if the first \p Limit uses of the register are all in the current
    // block.
    static const unsigned Limit = 8;
    unsigned C = 0;
    for (const auto &UseInst : MRI->use_instructions(VirtReg)) {
      if (UseInst.getParent() != MBB || ++C >= Limit) {
        MayLiveAcrossBlocks.set(Register::virtReg2Index(VirtReg));
        // Cannot be live-out if there are no successors.
        return !MBB->succ_empty();
      }

      if (SelfLoopDef) {
        // Try to handle some simple cases to avoid spilling and
        // reloading every value inside a self looping block.
        if (SelfLoopDef == &UseInst ||
            !dominates(*MBB, SelfLoopDef->getIterator(),
                       UseInst.getIterator())) {
          MayLiveAcrossBlocks.set(Register::virtReg2Index(VirtReg));
          return true;
        }
      }
    }
    return false;
  }

  /// Returns false if \p VirtReg is known to not be live into the current
  /// block.
  bool mayLiveIn(Register VirtReg) {
    if (MayLiveAcrossBlocks.test(Register::virtReg2Index(VirtReg)))
      return !MBB->pred_empty();

    // See if the first \p Limit def of the register are all in the current
    // block.
    static const unsigned Limit = 8;
    unsigned C = 0;
    for (const auto &DefInst : MRI->def_instructions(VirtReg)) {
      if (DefInst.getParent() != MBB || ++C >= Limit) {
        MayLiveAcrossBlocks.set(Register::virtReg2Index(VirtReg));
        return !MBB->pred_empty();
      }
    }

    return false;
  }

  unsigned calcSpillCost(MCPhysReg PhysReg) const {
    for (MCRegUnitIterator UI(PhysReg, TRI); UI.isValid(); ++UI) {
      unsigned VirtReg = RegUnitStates[*UI];
      switch (VirtReg) {
      case regFree:
        break;
      case regPreAssigned:
        //  LLVM_DEBUG(dbgs() << "Cannot spill pre-assigned "
        //					<< printReg(PhysReg, TRI) <<
        //'\n');
        return spillImpossible;
      default: {
        bool SureSpill = StackSlotForVirtReg[VirtReg] != -1 ||
                         findLiveVirtReg(VirtReg)->LiveOut;
        return SureSpill ? spillClean : spillDirty;
      }
      }
    }
    return 0;
  }

  void allocateCgInstruction(CgInstruction &inst);

  // Allocates a register for a VirtReg use.
  void useVirtReg(CgInstruction &inst, CgOperand &opnd, CgRegister vreg);
  bool usePhysReg(CgInstruction &inst, MCPhysReg Reg) {
    ZEN_ASSERT(Register::isPhysicalRegister(Reg) && "expected physreg");
    bool displacedAny = displacePhysReg(inst, Reg);
    setPhysRegState(Reg, regPreAssigned);
    markRegUsedInInstr(Reg);
    return displacedAny;
  }
  bool definePhysReg(CgInstruction &MI, MCPhysReg Reg) {
    bool displacedAny = displacePhysReg(MI, Reg);
    setPhysRegState(Reg, regPreAssigned);
    return displacedAny;
  }

  void defineLiveThroughVirtReg(CgInstruction &MI, unsigned OpNum,
                                Register VirtReg);
  void defineVirtReg(CgInstruction &MI, unsigned OpNum, CgRegister VirtReg,
                     bool LookAtPhysRegUses = false);
  void allocVirtReg(CgInstruction &inst, LiveReg &vreg_info, CgRegister hint,
                    bool LookAtPhysRegUses);

  void assignVirtToPhysReg(CgInstruction &inst, LiveReg &vreg_info,
                           MCRegister preg) {
    auto vreg = vreg_info.VirtReg;
    ZEN_ASSERT(vreg_info.PhysReg == 0);
    ZEN_ASSERT(preg != 0);
    vreg_info.PhysReg = preg;
    setPhysRegState(preg, vreg);
    // TODO: assignDanglingDebugValues
  }

  void setPhysRegState(MCPhysReg preg, unsigned new_state) {
    for (MCRegUnitIterator unit(preg, TRI); unit.isValid(); ++unit)
      RegUnitStates[*unit] = new_state;
  }

  // Check if physreg is clobbered by instruction's regmask(s).
  bool isClobberedByRegMasks(MCPhysReg PhysReg) const {
    return llvm::any_of(RegMasks, [PhysReg](const uint32_t *Mask) {
      return CgOperand::clobbersPhysReg(Mask, PhysReg);
    });
  }

  /// Check if a physreg or any of its aliases are used in this instruction.
  bool isRegUsedInInstr(MCPhysReg PhysReg, bool LookAtPhysRegUses) const {
    if (LookAtPhysRegUses && isClobberedByRegMasks(PhysReg))
      return true;
    for (MCRegUnitIterator Units(PhysReg, TRI); Units.isValid(); ++Units) {
      if (UsedInInstr.count(*Units))
        return true;
      if (LookAtPhysRegUses && PhysRegUses.count(*Units))
        return true;
    }
    return false;
  }

  /// Mark a physreg as used in this instruction.
  void markRegUsedInInstr(MCPhysReg PhysReg) {
    for (MCRegUnitIterator Units(PhysReg, TRI); Units.isValid(); ++Units)
      UsedInInstr.insert(*Units);
  }

  /// Remove mark of physical register being used in the instruction.
  void unmarkRegUsedInInstr(MCPhysReg PhysReg) {
    for (MCRegUnitIterator Units(PhysReg, TRI); Units.isValid(); ++Units)
      UsedInInstr.erase(*Units);
  }

  /// Mark physical register as being used in a register use operand.
  /// This is only used by the special livethrough handling code.
  void markPhysRegUsedInInstr(MCPhysReg PhysReg) {
    for (MCRegUnitIterator Units(PhysReg, TRI); Units.isValid(); ++Units)
      PhysRegUses.insert(*Units);
  }

  bool isPhysRegFree(MCPhysReg PhysReg) const {
    for (MCRegUnitIterator UI(PhysReg, TRI); UI.isValid(); ++UI) {
      if (RegUnitStates[*UI] != regFree)
        return false;
    }
    return true;
  }

  void setPhysReg(CgInstruction &MI, CgOperand &MO, MCPhysReg PhysReg) {
    if (!MO.getSubReg()) {
      MO.setReg(PhysReg);
      // MO.setIsRenamable(true);
      return;
    }

    // Handle subregister index.
    MO.setReg(PhysReg ? TRI->getSubReg(PhysReg, MO.getSubReg()) : MCRegister());
    // MO.setIsRenamable(true);
    // Note: We leave the subreg number around a little longer in case of
    // defs.
    // This is so that the register freeing logic in allocateInstruction can
    // still recognize this as subregister defs. The code there will clear
    // the number.
    if (!MO.isDef()) {
      MO.setSubReg(0);
    }

    // TODO: if (MO.isKill()) { ... }
    // TODO: if (MO.isDef() && MO.isUndef()) { ... }
  }

  LiveRegMap::iterator findLiveVirtReg(CgRegister vreg) {
    return LiveVirtRegs.find(Register::virtReg2Index(vreg));
  }

  LiveRegMap::const_iterator findLiveVirtReg(CgRegister vreg) const {
    return LiveVirtRegs.find(Register::virtReg2Index(vreg));
  }

  /// This allocates space for the specified virtual register to be held on
  /// the
  /// stack.
  int getStackSpaceFor(Register VirtReg) {
    // Find the location Reg would belong...
    int SS = StackSlotForVirtReg[VirtReg];
    // Already has space allocated?
    if (SS != -1)
      return SS;

    // Allocate a new stack object for this spill location...
    const TargetRegisterClass &RC = *MRI->getRegClass(VirtReg);
    unsigned Size = TRI->getSpillSize(RC);
    Align Alignment = TRI->getSpillAlign(RC);
    int FrameIdx = MFI->CreateSpillStackObject(Size, Alignment);

    // Assign the slot.
    StackSlotForVirtReg[VirtReg] = FrameIdx;
    return FrameIdx;
  }

  /// Insert spill instruction for \p AssignedReg before \p Before. Update
  /// DBG_VALUEs with \p VirtReg operands with the stack slot.
  void spill(CgBasicBlock::iterator Before, Register VirtReg,
             MCPhysReg AssignedReg, bool Kill, bool LiveOut) {
    LLVM_DEBUG(dbgs() << "Spilling " << printReg(VirtReg, TRI) << " in "
                      << printReg(AssignedReg, TRI));
    int FI = getStackSpaceFor(VirtReg);
    LLVM_DEBUG(dbgs() << " to stack slot #" << FI << '\n');

    const TargetRegisterClass &RC = *MRI->getRegClass(VirtReg);
    _llvm_workaround->storeRegToStackSlot(*TII, *MBB, Before, AssignedReg, Kill,
                                          FI, &RC, TRI);
  }

  void reload(inst_iterator Before, Register VirtReg, MCPhysReg PhysReg) {
    //   LLVM_DEBUG(dbgs() << "Reloading " << printReg(VirtReg, TRI) << "
    //   into "
    //                     << printReg(PhysReg, TRI) << '\n');
    int FI = getStackSpaceFor(VirtReg);
    const TargetRegisterClass &RC = *MRI->getRegClass(VirtReg);
    // TII->loadRegFromStackSlot(*MBB, Before, PhysReg, FI, &RC, TRI);
    _llvm_workaround->loadRegFromStackSlot(*TII, *MBB, Before, PhysReg, FI, &RC,
                                           TRI);
  }

  /// Reload all currently assigned virtual registers.
  void reloadAtBegin(CgBasicBlock &MBB) {
    if (LiveVirtRegs.empty())
      return;
#if 0
        for (CgBasicBlock::RegisterMaskPair P : MBB.liveins()) {
            MCPhysReg Reg = P.PhysReg;
            // Set state to live-in. This possibly overrides mappings to virtual
            // registers but we don't care anymore at this point.
            setPhysRegState(Reg, regLiveIn);
        }
#endif

    SmallSet<Register, 2> PrologLiveIns;
#if 0
        // The LiveRegMap is keyed by an unsigned (the virtreg number), so the
        // order of spilling here is deterministic, if arbitrary.
        CgBasicBlock::iterator InsertBefore =
            getMBBBeginInsertionPoint(MBB, PrologLiveIns);
#endif
    CgBasicBlock::iterator InsertBefore = MBB.begin();

    for (const LiveReg &LR : LiveVirtRegs) {
      MCPhysReg PhysReg = LR.PhysReg;
      if (PhysReg == 0)
        continue;

      MCRegister FirstUnit = *MCRegUnitIterator(PhysReg, TRI);
      if (RegUnitStates[FirstUnit] == regLiveIn)
        continue;
#if 0
            assert((&MBB != &MBB.getParent()->front() || IgnoreMissingDefs)
                   && "no reload in start block. Missing vreg def?");
#endif
      if (PrologLiveIns.count(PhysReg)) {
        // FIXME: Theoretically this should use an insert point skipping
        // labels but I'm not sure how labels should interact with
        // prolog instruction that need reloads.
        reload(MBB.begin(), LR.VirtReg, PhysReg);
      } else
        reload(InsertBefore, LR.VirtReg, PhysReg);
    }
    LiveVirtRegs.clear();
  }

  Register traceCopyChain(Register Reg) const {
    static const unsigned ChainLengthLimit = 3;
    unsigned C = 0;
    do {
      if (Reg.isPhysical())
        return Reg;
      ZEN_ASSERT(Reg.isVirtual());

      CgInstruction *VRegDef = MRI->getUniqueVRegDef(Reg);
      if (!VRegDef || !isCoalescable(*VRegDef))
        return 0;
      Reg = VRegDef->getOperand(1).getReg();
    } while (++C <= ChainLengthLimit);
    return 0;
  }

  /// Check if any of \p VirtReg's definitions is a copy. If it is follow the
  /// chain of copies to check whether we reach a physical register we can
  /// coalesce with.
  Register traceCopies(Register VirtReg) const {
    static const unsigned DefLimit = 3;
    unsigned C = 0;

    for (const auto &MI : MRI->def_instructions(VirtReg)) {
      if (isCoalescable(MI)) {
        Register Reg = MI.getOperand(1).getReg();
        Reg = traceCopyChain(Reg);
        if (Reg.isValid())
          return Reg;
      }

      if (++C >= DefLimit)
        break;
    }
    return Register();
  }

  /// Mark PhysReg as reserved or free after spilling any virtregs. This is
  /// very similar to defineVirtReg except the physreg is reserved instead of
  /// allocated.
  bool displacePhysReg(CgInstruction &inst, MCPhysReg PhysReg) {
    // CgInstruction &MI = *(*inst_it);
    bool displacedAny = false;

    for (MCRegUnitIterator UI(PhysReg, TRI); UI.isValid(); ++UI) {
      unsigned Unit = *UI;
      unsigned VirtReg = RegUnitStates[Unit];
      switch (VirtReg) {
      default: {
        LiveRegMap::iterator LRI = findLiveVirtReg(VirtReg);
        ZEN_ASSERT(LRI != LiveVirtRegs.end() && "datastructures in sync");
        auto ReloadBefore = std::next(inst.getIterator());
        reload(ReloadBefore, VirtReg, LRI->PhysReg);

        setPhysRegState(LRI->PhysReg, regFree);
        LRI->PhysReg = 0;
        LRI->Reloaded = true;
        displacedAny = true;
        break;
      }
      case regPreAssigned:
        RegUnitStates[Unit] = regFree;
        displacedAny = true;
        break;
      case regFree:
        break;
      }
    }
    return displacedAny;
  }

  void freePhysReg(MCPhysReg preg) {
    MCRegister first_unit = *MCRegUnitIterator(preg, TRI);
    unsigned state = RegUnitStates[first_unit];
    switch (state) {
    case regFree:
      break;
    case regPreAssigned:
      setPhysRegState(preg, regFree);
      break;
    default: {
      auto it = findLiveVirtReg(state);
      ZEN_ASSERT(it != LiveVirtRegs.end());
      setPhysRegState(preg, regFree);
      it->PhysReg = 0;
    }
    }
  }
};

void FastRA::Impl::allocVirtReg(CgInstruction &MI, LiveReg &LR,
                                CgRegister Hint0, bool LookAtPhysRegUses) {
  const CgRegister VirtReg = LR.VirtReg;
  ZEN_ASSERT(LR.PhysReg == 0);
  const TargetRegisterClass &RC = *(MRI->getRegClass(VirtReg));

  if (Hint0.isPhysical() && MRI->isAllocatable(Hint0) && RC.contains(Hint0) &&
      !isRegUsedInInstr(Hint0, LookAtPhysRegUses)) {
    ZEN_ASSERT(isPhysRegFree(Hint0));
    assignVirtToPhysReg(MI, LR, Hint0);
    return;
  } else {
    Hint0 = CgRegister();
  }

  // Try other hint.
  Register Hint1 = traceCopies(VirtReg);
  if (Hint1.isPhysical() && MRI->isAllocatable(Hint1) && RC.contains(Hint1) &&
      !isRegUsedInInstr(Hint1, LookAtPhysRegUses)) {
    // Take hint if the register is currently free.
    if (isPhysRegFree(Hint1)) {
      LLVM_DEBUG(dbgs() << "\tPreferred Register 0: " << printReg(Hint1, TRI)
                        << '\n');
      assignVirtToPhysReg(MI, LR, Hint1);
      return;
    } else {
      LLVM_DEBUG(dbgs() << "\tPreferred Register 1: " << printReg(Hint1, TRI)
                        << " occupied\n");
    }
  } else {
    Hint1 = Register();
  }

  MCPhysReg BestReg = 0;
  unsigned BestCost = spillImpossible;
  ArrayRef<MCPhysReg> CgAllocationOrder = RegClassInfo.getOrder(&RC);
  for (MCPhysReg PhysReg : CgAllocationOrder) {
    // LLVM_DEBUG(dbgs() << "\tRegister: " << printReg(PhysReg, TRI) << '
    // ');
    if (isRegUsedInInstr(PhysReg, LookAtPhysRegUses)) {
      // LLVM_DEBUG(dbgs() << "already used in instr.\n");
      continue;
    }

    unsigned Cost = calcSpillCost(PhysReg);
    // LLVM_DEBUG(dbgs() << "Cost: " << Cost << " BestCost: " << BestCost <<
    // '\n'); Immediate take a register with cost 0.
    if (Cost == 0) {
      assignVirtToPhysReg(MI, LR, PhysReg);
      return;
    }

    // if (PhysReg == Hint0 || PhysReg == Hint1)
    if (PhysReg == Hint0)
      Cost -= spillPrefBonus;

    if (Cost < BestCost) {
      BestReg = PhysReg;
      BestCost = Cost;
    }
  }

  if (!BestReg) {
    // Nothing we can do: Report an error and keep going with an invalid
    // allocation.
    // if (MI.isInlineAsm())
    //  MI.emitError("inline assembly requires more registers than
    //  available");
    // else
    //  MI.emitError("ran out of registers during register allocation");
    throw getError(ErrorCode::RegAllocFailed);
  }

  displacePhysReg(MI, BestReg);
  assignVirtToPhysReg(MI, LR, BestReg);
}

/// Variation of defineVirtReg() with special handling for livethrough regs
/// (tied or earlyclobber) that may interfere with preassigned uses.
void FastRA::Impl::defineLiveThroughVirtReg(CgInstruction &MI, unsigned OpNum,
                                            Register VirtReg) {
  LiveRegMap::iterator LRI = findLiveVirtReg(VirtReg);
  if (LRI != LiveVirtRegs.end()) {
    MCPhysReg PrevReg = LRI->PhysReg;
    if (PrevReg != 0 && isRegUsedInInstr(PrevReg, true)) {
      LLVM_DEBUG(dbgs() << "Need new assignment for " << printReg(PrevReg, TRI)
                        << " (tied/earlyclobber resolution)\n");
      freePhysReg(PrevReg);
      LRI->PhysReg = 0;
      allocVirtReg(MI, *LRI, 0, true);
      CgBasicBlock::iterator InsertBefore =
          std::next((CgBasicBlock::iterator)MI.getIterator());
      LLVM_DEBUG(dbgs() << "Copy " << printReg(LRI->PhysReg, TRI) << " to "
                        << printReg(PrevReg, TRI) << '\n');

      // BuildMI(*MBB, InsertBefore, MI.getDebugLoc(),
      //         TII->get(TargetOpcode::COPY), PrevReg)
      //     .addReg(LRI->PhysReg, llvm::RegState::Kill);
      SmallVector<CgOperand, 2> CopyOperands{
          CgOperand::createRegOperand(PrevReg, true),
          CgOperand::createRegOperand(LRI->PhysReg, false),
      };
      CgFunction *MF = MBB->getParent();
      MF->createCgInstruction(*MBB, InsertBefore, TII->get(TargetOpcode::COPY),
                              CopyOperands);
    }
    CgOperand &MO = MI.getOperand(OpNum);
    if (MO.getSubReg()) {
      LRI->LastUse = &MI;
    }
  }
  return defineVirtReg(MI, OpNum, VirtReg, true);
}

void FastRA::Impl::defineVirtReg(CgInstruction &MI, unsigned OpNum,
                                 CgRegister VirtReg, bool LookAtPhysRegUses) {
  ZEN_ASSERT(VirtReg.isVirtual() && "Not a virtual register");
  CgOperand &MO = MI.getOperand(OpNum);

  auto [LRI, inserted] = LiveVirtRegs.insert(LiveReg(VirtReg));
  if (inserted) {
    if (mayLiveOut(VirtReg)) {
      LRI->LiveOut = true;
    }
  }

  if (LRI->PhysReg == 0) {
    allocVirtReg(MI, *LRI, 0, LookAtPhysRegUses);
  } else {
    ZEN_ASSERT(!isRegUsedInInstr(LRI->PhysReg, LookAtPhysRegUses));
  }

  MCPhysReg PhysReg = LRI->PhysReg;
  ZEN_ASSERT(PhysReg != 0);

  if (LRI->Reloaded || LRI->LiveOut) {
    if (!MI.isImplicitDef()) {
      CgBasicBlock::iterator SpillBefore = std::next(MI.getIterator());
      LLVM_DEBUG(dbgs() << "Spill Reason: LO: " << LRI->LiveOut
                        << " RL: " << LRI->Reloaded << '\n');
      bool Kill = LRI->LastUse == nullptr;
      spill(SpillBefore, VirtReg, PhysReg, Kill, LRI->LiveOut);
      LRI->LastUse = nullptr;
    }
    LRI->LiveOut = false;
    LRI->Reloaded = false;
  }

  markRegUsedInInstr(PhysReg);
  setPhysReg(MI, MO, PhysReg);
}
void FastRA::Impl::useVirtReg(CgInstruction &MI, CgOperand &opnd,
                              CgRegister vreg) {
  auto [LRI, inserted] = LiveVirtRegs.insert(LiveReg(vreg));

  if (inserted) {
    if (mayLiveOut(vreg)) {
      LRI->LiveOut = true;
    }
  }

  if (LRI->PhysReg == 0) {
    CgRegister hint;
    // TODO, check with llvm
    if (MI.isCopy() && MI.getOperand(1).getSubReg() == 0) {
      hint = MI.getOperand(0).getReg();
      ZEN_ASSERT(hint);
    }
    allocVirtReg(MI, *LRI, hint, false);
  } else {
    // TODO:     assert((!MO.isKill() || LRI->LastUse == &MI) && "Invalid
    // kill flag");
  }

  ZEN_ASSERT(LRI->PhysReg);

  LRI->LastUse = &MI;

  markRegUsedInInstr(LRI->PhysReg);
  setPhysReg(MI, opnd, LRI->PhysReg);
}

void FastRA::Impl::allocateCgInstruction(CgInstruction &MI) {
  UsedInInstr.clear();
  RegMasks.clear();

  // Scan for special cases; Apply pre-assigned register defs to state.
  bool HasPhysRegUse = false;
  bool HasRegMask = false;
  bool HasVRegDef = false;
  bool HasDef = false;
  bool NeedToAssignLiveThroughs = false;
  for (CgOperand &MO : MI) {
    if (MO.isReg()) {
      Register Reg = MO.getReg();
      if (Reg.isVirtual()) {
        if (MO.isDef()) {
          HasDef = true;
          HasVRegDef = true;
          // if (MO.isEarlyClobber()) {
          //     HasEarlyClobber = true;
          //     NeedToAssignLiveThroughs = true;
          // }
          // if ((MO.isTied() && !TiedOpIsUndef(MO, I))
          //     || (MO.getSubReg() != 0 && !MO.isUndef()))
          //     NeedToAssignLiveThroughs = true;
          if (MO.isTied()) {
            NeedToAssignLiveThroughs = true;
          }
        }
      } else if (Reg.isPhysical()) {
        if (!MRI->isReserved(Reg)) {
          // Allocate physreg defs.
          if (MO.isDef()) {
            HasDef = true;
            definePhysReg(MI, Reg);
            // bool displacedAny = definePhysReg(MI, Reg);
            // if (MO.isEarlyClobber())
            //     HasEarlyClobber = true;
            // if (!displacedAny)
            //     MO.setIsDead(true);
          }
          if (MO.readsReg()) {
            HasPhysRegUse = true;
          }
        }
      }
    } else if (MO.isRegMask()) {
      HasRegMask = true;
      RegMasks.push_back(MO.getRegMask());
    }
  }

  // Allocate virtreg defs.
  if (HasDef) {
    if (HasVRegDef) {
      // Special handling for tied operands or subregister defs:
      // Compared to "normal" defs these:
      // - Must not use a register that is pre-assigned for a use operand.
      // - In order to solve tricky inline assembly constraints we change
      //   the heuristic to figure out a good operand order before doing
      //   assignments.
      if (NeedToAssignLiveThroughs) {
        DefOperandIndexes.clear();
        PhysRegUses.clear();

        LLVM_DEBUG(dbgs() << "Need to assign livethroughs\n");
        for (unsigned I = 0, E = MI.getNumOperands(); I < E; ++I) {
          const CgOperand &MO = MI.getOperand(I);
          if (!MO.isReg())
            continue;
          Register Reg = MO.getReg();
          if (MO.readsReg()) {
            if (Reg.isPhysical()) {
              LLVM_DEBUG(dbgs()
                         << "mark extra used: " << printReg(Reg, TRI) << '\n');
              markPhysRegUsedInInstr(Reg);
            }
          }

          if (MO.isDef()) {
            if (Reg.isVirtual()) {
              DefOperandIndexes.push_back(I);
            }
          }
        }

        for (uint16_t OpIdx : DefOperandIndexes) {
          CgOperand &MO = MI.getOperand(OpIdx);
          unsigned Reg = MO.getReg();
          if (MO.isTied()) {
            defineLiveThroughVirtReg(MI, OpIdx, Reg);
          } else {
            defineVirtReg(MI, OpIdx, Reg);
          }
        }
      } else {
        // Assign virtual register defs.
        for (unsigned I = 0, E = MI.getNumOperands(); I < E; ++I) {
          CgOperand &MO = MI.getOperand(I);
          if (!MO.isReg() || !MO.isDef()) {
            continue;
          }
          Register Reg = MO.getReg();
          if (Reg.isVirtual()) {
            defineVirtReg(MI, I, Reg);
          }
        }
      }
    }

    // Free registers occupied by defs.
    // Iterate operands in reverse order, so we see the implicit super
    // register defs first (we added them earlier in case of
    // <def,read-undef>).
    for (CgOperand &MO : reverse(MI)) {
      if (!MO.isReg() || !MO.isDef()) {
        continue;
      }

      // subreg defs don't free the full register. We left the subreg
      // number around as a marker in setPhysReg() to recognize this case
      // here.
      if (MO.getSubReg() != 0) {
        MO.setSubReg(0);
        continue;
      }

      ZEN_ASSERT((!MO.isTied() || !isClobberedByRegMasks(MO.getReg())) &&
                 "tied def assigned to clobbered register");
      // Do not free tied operands
      if (MO.isTied()) {
        continue;
      }
      auto Reg = MO.getReg();
      if (!Reg) {
        continue;
      }
      ZEN_ASSERT(Reg.isPhysical());
      if (MRI->isReserved(Reg)) {
        continue;
      }
      freePhysReg(Reg);
      unmarkRegUsedInInstr(Reg);
    }
  }

  // Displace clobbered registers.
  if (HasRegMask) {
    ZEN_ASSERT(!RegMasks.empty() && "expected RegMask");
    // MRI bookkeeping.
    for (const auto *RM : RegMasks) {
      MRI->addPhysRegsUsedFromRegMask(RM);
    }

    // Spilled values remain in LiveVirtRegs with PhysReg == 0. Scanning all
    // of them at every call can become quadratic in a long block. For large
    // sets, discover assigned values through the bounded physical-unit map.
    if (LiveVirtRegs.size() > RegUnitStates.size()) {
      SmallVector<LiveReg *, 16> Clobbered;
      for (unsigned State : RegUnitStates) {
        if (!Register::isVirtualRegister(State))
          continue;
        auto LRI = findLiveVirtReg(State);
        ZEN_ASSERT(LRI != LiveVirtRegs.end());
        MCPhysReg PhysReg = LRI->PhysReg;
        if (PhysReg != 0 && isClobberedByRegMasks(PhysReg))
          Clobbered.push_back(&*LRI);
      }
      // SparseSet's dense entries are contiguous. Preserve the original scan
      // order and handle multi-unit physical registers only once. Displacement
      // clears assignments but does not insert/erase LiveVirtRegs entries.
      llvm::sort(Clobbered);
      Clobbered.erase(std::unique(Clobbered.begin(), Clobbered.end()),
                      Clobbered.end());
      for (const LiveReg *LR : Clobbered) {
        if (LR->PhysReg != 0)
          displacePhysReg(MI, LR->PhysReg);
      }
    } else {
      for (const LiveReg &LR : LiveVirtRegs) {
        MCPhysReg PhysReg = LR.PhysReg;
        if (PhysReg != 0 && isClobberedByRegMasks(PhysReg)) {
          displacePhysReg(MI, PhysReg);
        }
      }
    }
  }

  // Apply pre-assigned register uses to state.
  if (HasPhysRegUse) {
    for (CgOperand &MO : MI) {
      if (!MO.isReg() || !MO.readsReg()) {
        continue;
      }
      Register Reg = MO.getReg();
      if (!Reg.isPhysical()) {
        continue;
      }
      if (MRI->isReserved(Reg)) {
        continue;
      }
      usePhysReg(MI, Reg);
      // bool displacedAny = usePhysReg(MI, Reg);
      // if (!displacedAny && !MRI->isReserved(Reg))
      //     MO.setIsKill(true);
    }
  }

  // Allocate virtreg uses and insert reloads as necessary.
  for (CgOperand &MO : MI) {
    if (!MO.isReg() || !MO.isUse()) {
      continue;
    }
    Register Reg = MO.getReg();
    if (!Reg.isVirtual()) {
      continue;
    }

    // if (MO.isUndef()) {
    //     HasUndefUse = true;
    //     continue;
    // }
    mayLiveIn(Reg);

    ZEN_ASSERT(MO.readsReg() && "reading use");
    useVirtReg(MI, MO, Reg);
  }

  // TODO: if (HasUndefUse) { ... }

  // process coalescing regs
  if (MI.isCopy() && MI.getOperand(0).getReg() == MI.getOperand(1).getReg() &&
      MI.getNumOperands() == 2) {
    coalesced.push_back(&MI);
  }
}

FastRA::FastRA(CgFunction &MF) : _impl(new Impl()) { runOnCgFunction(MF); }
FastRA::~FastRA() = default;

void FastRA::runOnCgFunction(CgFunction &cg_func) {
  _impl->runOnCgFunction(cg_func);
}
