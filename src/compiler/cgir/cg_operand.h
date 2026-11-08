/*
 * Copyright (C) 2021-2023 the DTVM authors.
 */
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#ifndef COMPILER_IR_CG_OPERAND_H
#define COMPILER_IR_CG_OPERAND_H

#include "compiler/common/common_defs.h"
#include "llvm/CodeGen/Register.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/MC/MCRegister.h"

#define OPNDIDX_TO_TIEDIDX(IDX) (IDX + UINT16_MAX + 2)
#define TIEDIDX_TO_OPNDIDX(IDX) (IDX - UINT16_MAX - 1)

namespace COMPILER {

using namespace llvm;

using CgRegister = llvm::Register;

class CgFunction;
class CgBasicBlock;
class CgInstruction;

class CgOperand {
public:
  friend class CgRegisterInfo;
  enum Kind : uint8_t {
    REGISTER,
    IMMEDIATE,
    FUNCTION,
    BASIC_BLOCK,
    FRAME_IDX,
    JUMP_TABLE_INDEX,
    REGISTER_MASK
  };
  enum RegState : unsigned {
    None = 0,
    /// Register definition.
    Define = 1 << 1,
    /// Not emitted register (e.g. carry, or temporary result).
    Implicit = 1 << 2,
    /// The last use of a register.
    Kill = 1 << 3,
    /// Unused definition.
    Dead = 1 << 4,
    /// Value of the register doesn't matter.
    Undef = 1 << 5,
  };
  static CgOperand
  createRegOperand(CgRegister RegNo, bool IsDef, bool IsImplicit = false,
                   bool IsKill = false, bool IsDead = false,
                   bool IsUndef = false, bool IsEarlyClobber = false,
                   bool IsInternalRead = false, bool IsRenamable = false) {
    CgOperand op(REGISTER);
    op.setReg(RegNo);
    op.IsDef = IsDef;
    op.IsImplicit = IsImplicit;
    op.IsDeadOrKill = IsKill || IsDead;
    op.IsUndef = IsUndef;
    op.IsInternalRead = IsInternalRead;
    op.IsRenamable = IsRenamable;
    op.IsEarlyClobber = IsEarlyClobber;
    op.TiedTo = 0;
    op.Contents.Reg.Prev = nullptr;
    op.Contents.Reg.Next = nullptr;
    return op;
  }

  static CgOperand createRegOperand(Register RegNo, unsigned flags = 0) {
    return createRegOperand(RegNo, flags & RegState::Define,
                            flags & RegState::Implicit, flags & RegState::Kill,
                            flags & RegState::Dead, flags & RegState::Undef);
  }

  static CgOperand createMBB(CgBasicBlock *MBB, unsigned TargetFlags = 0) {
    CgOperand op(BASIC_BLOCK);
    op.setMBB(MBB);
    // Op.setTargetFlags(TargetFlags);
    return op;
  }

  void setMBB(CgBasicBlock *MBB) {
    assert(isMBB() && "Wrong CgOperand mutator");
    Contents.MBB = MBB;
  }

  CgBasicBlock *getMBB() const {
    assert(isMBB() && "Wrong CgOperand accessor");
    return Contents.MBB;
  }

  void setIndex(int Idx) {
    // assert((isFI() || isCPI() || isTargetIndex() || isJTI()) &&
    //           "Wrong CgOperand mutator");
    assert((isFI() || isJTI()) && "Wrong CgOperand mutator");
    Contents.Index = Idx;
  }
  int getIndex() const {
    assert((isFI() || isJTI()) && "Wrong CgOperand mutator");
    return Contents.Index;
  }

  static CgOperand createImmOperand(int64_t ImmVal) {
    CgOperand op(IMMEDIATE);
    op.setImm(ImmVal);
    return op;
  }

  static CgOperand createFI(int Idx) {
    CgOperand op(FRAME_IDX);
    op.setIndex(Idx);
    return op;
  }

  static CgOperand createFuncOperand(uint32_t FuncIdx) {
    CgOperand op(FUNCTION);
    op.Contents.FuncIdx = FuncIdx;
    return op;
  }

  static CgOperand createJTI(uint32_t Idx) {
    CgOperand op(JUMP_TABLE_INDEX);
    op.setIndex(Idx);
    return op;
  }

  static CgOperand createRegMask(const uint32_t *Mask) {
    ZEN_ASSERT(Mask && "Missing register mask");
    CgOperand Op(REGISTER_MASK);
    Op.Contents.RegMask = Mask;
    return Op;
  }

  Kind getType() const { return OpKind; }

  bool isDef() const {
    ZEN_ASSERT(isReg() && "Wrong CgOperand accessor");
    return IsDef;
  }
  bool isUse() const {
    ZEN_ASSERT(isReg() && "Wrong CgOperand accessor");
    return !IsDef;
  }
  bool isImplicit() const {
    ZEN_ASSERT(isReg() && "Wrong CgOperand accessor");
    return IsImplicit;
  }
  bool isDead() const {
    ZEN_ASSERT(isReg() && "Wrong CgOperand accessor");
    return IsDeadOrKill && IsDef;
  }
  bool isKill() const {
    ZEN_ASSERT(isReg() && "Wrong CgOperand accessor");
    return IsDeadOrKill && !IsDef;
  }
  bool isUndef() const {
    ZEN_ASSERT(isReg() && "Wrong CgOperand accessor");
    return IsUndef;
  }

  /// isRenamable - Returns true if this register may be renamed, i.e. it does
  /// not generate a value that is somehow read in a way that is not
  /// represented by the Machine IR (e.g. to meet an ABI or ISA requirement).
  /// This is only valid on physical register operands.  Virtual registers are
  /// assumed to always be renamable regardless of the value of this field.
  ///
  /// Operands that are renamable can freely be changed to any other register
  /// that is a member of the register class returned by
  /// MI->getRegClassConstraint().
  ///
  /// isRenamable can return false for several different reasons:
  ///
  /// - ABI constraints (since liveness is not always precisely modeled).  We
  ///   conservatively handle these cases by setting all physical register
  ///   operands that didn’t start out as virtual regs to not be renamable.
  ///   Also any physical register operands created after register allocation
  ///   or whose register is changed after register allocation will not be
  ///   renamable.  This state is tracked in the CgOperand::IsRenamable
  ///   bit.
  ///
  /// - Opcode/target constraints: for opcodes that have complex register
  /// class
  ///   requirements (e.g. that depend on other operands/instructions), we set
  ///   hasExtraSrcRegAllocReq/hasExtraDstRegAllocReq in the machine opcode
  ///   description.  Operands belonging to instructions with opcodes that are
  ///   marked hasExtraSrcRegAllocReq/hasExtraDstRegAllocReq return false from
  ///   isRenamable().  Additionally, the AllowRegisterRenaming target
  ///   property prevents any operands from being marked renamable for targets
  ///   that don't have detailed opcode
  ///   hasExtraSrcRegAllocReq/hasExtraDstRegAllocReq values.
  bool isRenamable() const;

  bool isReg() const { return OpKind == REGISTER; }
  bool isImm() const { return OpKind == IMMEDIATE; }
  bool isFunc() const { return OpKind == FUNCTION; }
  bool isMBB() const { return OpKind == BASIC_BLOCK; }
  bool isFI() const { return OpKind == FRAME_IDX; }
  bool isJTI() const { return OpKind == JUMP_TABLE_INDEX; }
  bool isRegMask() const { return OpKind == REGISTER_MASK; }

  /// Return true if this operand can validly be appended to an arbitrary
  /// operand list. i.e. this behaves like an implicit operand.
  bool isValidExcessOperand() const {
    return (isReg() && isImplicit()) || isRegMask();
  }

  void setSubReg(unsigned SubReg) {
    ZEN_ASSERT(isReg() && "Wrong CgOperand mutator");
    SubReg_TargetFlags = SubReg;
    ZEN_ASSERT(SubReg_TargetFlags == SubReg && "SubReg out of range");
  }

  void setReg(CgRegister Reg);

  CgRegister getReg() const {
    ZEN_ASSERT(isReg());
    return CgRegister(RegNo);
  }
  unsigned getSubReg() const {
    ZEN_ASSERT(isReg() && "Wrong CgOperand accessor");
    return SubReg_TargetFlags;
  }
  /// readsReg - Returns true if this operand reads the previous value of its
  /// register.  A use operand with the <undef> flag set doesn't read its
  /// register.  A sub-register def implicitly reads the other parts of the
  /// register being redefined unless the <undef> flag is set.
  ///
  /// This refers to reading the register value from before the current
  /// instruction or bundle. Internal bundle reads are not included.

  bool readsReg() const {
    ZEN_ASSERT(isReg() && "Wrong CgOperand accessor");
    // TODO: return !isUndef() && !isInternalRead() && (isUse() ||
    // getSubReg());
    return !isUndef() && (isUse() || getSubReg());
  }

  static constexpr unsigned TIED_MAX = 15;
  bool isTied() const {
    ZEN_ASSERT(isReg());
    return TiedTo;
  }

  bool isInternalRead() const {
    assert(isReg() && "Wrong CgOperand accessor");
    return IsInternalRead;
  }
  bool isEarlyClobber() const {
    assert(isReg() && "Wrong CgOperand accessor");
    return IsEarlyClobber;
  }

  void setTied(unsigned OpIdx) {
    ZEN_ASSERT(isReg());
    ZEN_ASSERT(OpIdx < TIED_MAX);
    TiedTo = OPNDIDX_TO_TIEDIDX(OpIdx);
  }

  int64_t getImm() const {
    ZEN_ASSERT(isImm());
    return Contents.ImmVal;
  }

  void setImm(int64_t ImmVal) {
    ZEN_ASSERT(isImm());
    Contents.ImmVal = ImmVal;
  }

  void setParent(CgInstruction *Parent) { ParentMI = Parent; }
  auto *getParent() const { return ParentMI; }

  // An operand copied out of an instruction must not retain its parent's
  // use/def links or operand ties when inserted into a different instruction.
  // The new instruction rebuilds ties from its own descriptor.
  CgOperand detachedCopy() const {
    CgOperand Copy(*this);
    Copy.ParentMI = nullptr;
    if (Copy.isReg()) {
      Copy.Contents.Reg.Prev = nullptr;
      Copy.Contents.Reg.Next = nullptr;
      Copy.TiedTo = 0;
    }
    return Copy;
  }

  uint32_t getFunc() const {
    ZEN_ASSERT(isFunc());
    return Contents.FuncIdx;
  }

  /// clobbersPhysReg - Returns true if this RegMask clobbers PhysReg.
  /// It is sometimes necessary to detach the register mask pointer from its
  /// machine operand. This static method can be used for such detached bit
  /// mask pointers.
  static bool clobbersPhysReg(const uint32_t *RegMask, MCRegister PhysReg) {
    // See TargetRegisterInfo.h.
    ZEN_ASSERT(PhysReg < (1u << 30) && "Not a physical register");
    return !(RegMask[PhysReg / 32] & (1u << PhysReg % 32));
  }

  /// clobbersPhysReg - Returns true if this RegMask operand clobbers PhysReg.
  bool clobbersPhysReg(MCRegister PhysReg) const {
    return clobbersPhysReg(getRegMask(), PhysReg);
  }

  const uint32_t *getRegMask() const {
    ZEN_ASSERT(isRegMask());
    return Contents.RegMask;
  }

  unsigned getTargetFlags() const { return isReg() ? 0 : SubReg_TargetFlags; }
  void setTargetFlags(unsigned F) {
    assert(!isReg() && "Register operands can't have target flags");
    SubReg_TargetFlags = F;
    assert(SubReg_TargetFlags == F && "Target flags out of range");
  }
  void addTargetFlag(unsigned F) {
    assert(!isReg() && "Register operands can't have target flags");
    SubReg_TargetFlags |= F;
    assert((SubReg_TargetFlags & F) && "Target flags out of range");
  }

  void setIsKill(bool Val = true) {
    assert(isReg() && !IsDef && "Wrong CgOperand mutator");
    IsDeadOrKill = Val;
  }

  void setIsDead(bool Val = true) {
    assert(isReg() && IsDef && "Wrong CgOperand mutator");
    IsDeadOrKill = Val;
  }

  void setIsUndef(bool Val = true) {
    assert(isReg() && "Wrong CgOperand mutator");
    IsUndef = Val;
  }
  void setIsInternalRead(bool Val = true) {
    assert(isReg() && "Wrong CgOperand mutator");
    IsInternalRead = Val;
  }
  void setIsEarlyClobber(bool Val = true) {
    assert(isReg() && IsDef && "Wrong CgOperand mutator");
    IsEarlyClobber = Val;
  }

  void setIsRenamable(bool Val = true);

  void ChangeToRegister(Register Reg, bool isDef, bool isImp = false,
                        bool isKill = false, bool isDead = false,
                        bool isUndef = false, bool isDebug = false);
  void ChangeToImmediate(int64_t ImmVal, unsigned TargetFlags = 0);

  void substPhysReg(MCRegister Reg, const TargetRegisterInfo &TRI);
  void substVirtReg(Register Reg, unsigned SubIdx,
                    const TargetRegisterInfo &TRI);

  /// isOnRegUseList - Return true if this operand is on a register use/def
  /// list or false if not.  This can only be called for register operands
  /// that are part of a machine instruction.
  bool isOnRegUseList() const {
    assert(isReg() && "Can only add reg operand to use lists");
    return Contents.Reg.Prev != nullptr;
  }

  void dump() const;
  void print(llvm::raw_ostream &OS) const;

private:
  friend class CgInstruction;

  explicit CgOperand(Kind Kind)
      : OpKind(Kind), SubReg_TargetFlags(0), TiedTo(0), IsDef(0), IsImplicit(0),
        IsDeadOrKill(0), IsRenamable(0), IsUndef(0), IsInternalRead(0),
        IsEarlyClobber(0), PaddingBits(0) {}
  Kind OpKind : 8;
  unsigned SubReg_TargetFlags : 12;
  unsigned TiedTo : 32;
  unsigned IsDef : 1;
  unsigned IsImplicit : 1;
  unsigned IsDeadOrKill : 1;
  unsigned IsRenamable : 1;
  unsigned IsUndef : 1;
  unsigned IsInternalRead : 1;
  unsigned IsEarlyClobber : 1;

  // when TiedTo field changed from 4bits to 32bits, need padding the bits
  unsigned PaddingBits : 4;

  uint32_t RegNo = 0;

  union Value {
    struct { // For MO_Register.
      // Register number is in SmallContents.RegNo.
      CgOperand *Prev; // Access list for register. See MRI.
      CgOperand *Next;
    } Reg;

    int64_t ImmVal;
    uint32_t FuncIdx;
    CgBasicBlock *MBB;
    int Index; // For MO_*Index - The index itself.
    const uint32_t *RegMask;
  } Contents;
  CgInstruction *ParentMI = nullptr;
};

} // namespace COMPILER

#endif // COMPILER_IR_CG_OPERAND_H
