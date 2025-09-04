// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef COMPILER_IR_INSTRUCTIONS_H
#define COMPILER_IR_INSTRUCTIONS_H

#include "compiler/common/common_defs.h"
#include "compiler/context.h"
#include "compiler/mir/basic_block.h"
#include "compiler/mir/constant.h"
#include "compiler/mir/instruction.h"
#include "compiler/mir/opcode.h"
#include "llvm/ADT/ArrayRef.h"

namespace COMPILER {

template <uint8_t FixOperandNum>
class FixedOperandInstruction : public MInstruction {
protected:
  template <class InstType, typename... Arguments>
  static InstType *create(CompileMemPool &MemPool, Arguments &&...args) {
    return new (MInstruction::allocMem<InstType>(MemPool, FixOperandNum))
        InstType(std::forward<Arguments>(args)...);
  }
  using MInstruction::MInstruction;
};

class DynamicOperandInstruction : public MInstruction {
protected:
  template <class InstType, typename... Arguments>
  static InstType *create(CompileMemPool &MemPool, OperandNum opnd_num,
                          Arguments &&...args) {
    return new (MInstruction::allocMem<InstType>(MemPool, opnd_num))
        InstType(std::forward<Arguments>(args)...);
  }
  template <class InstType, typename... Arguments>
  static InstType *createWithMemPool(CompileMemPool &MemPool,
                                     OperandNum opnd_num, Arguments &&...args) {
    return new (MInstruction::allocMem<InstType>(MemPool, opnd_num))
        InstType(MemPool, std::forward<Arguments>(args)...);
  }
  using MInstruction::MInstruction;
};

class BinaryInstruction : public FixedOperandInstruction<2> {
public:
  template <typename... Arguments>
  static BinaryInstruction *create(Arguments &&...args) {
    return FixedOperandInstruction::create<BinaryInstruction>(
        std::forward<Arguments>(args)...);
  }

protected:
  // Used for subclass
  BinaryInstruction(Kind kind, Opcode opcode, MType *type, MInstruction *lhs,
                    MInstruction *rhs)
      : FixedOperandInstruction(kind, opcode, 2, type) {
    setOperand<0>(lhs);
    setOperand<1>(rhs);
  }

private:
  friend class FixedOperandInstruction;
  BinaryInstruction(Opcode opcode, MType *type, MInstruction *lhs,
                    MInstruction *rhs)
      : FixedOperandInstruction(MInstruction::BINARY, opcode, 2, type) {
    setOperand<0>(lhs);
    setOperand<1>(rhs);
  }
};

class AdcInstruction : public FixedOperandInstruction<3> {
public:
  template <typename... Arguments>
  static AdcInstruction *create(Arguments &&...Args) {
    return FixedOperandInstruction::create<AdcInstruction>(
        std::forward<Arguments>(Args)...);
  }

  static bool classof(const MInstruction *Inst) {
    return Inst->getOpcode() == OP_adc;
  }

private:
  friend class FixedOperandInstruction;
  AdcInstruction(MType *Type, MInstruction *Operand1, MInstruction *Operand2,
                 MInstruction *Carry)
      : FixedOperandInstruction(MInstruction::ADC, OP_adc, 3, Type) {
    setOperand<0>(Operand1);
    setOperand<1>(Operand2);
    setOperand<2>(Carry);
  }
};

class UnaryInstruction : public FixedOperandInstruction<1> {
public:
  template <typename... Arguments>
  static UnaryInstruction *create(Arguments &&...args) {
    return FixedOperandInstruction::create<UnaryInstruction>(
        std::forward<Arguments>(args)...);
  }

protected:
  // Used for subclass
  UnaryInstruction(Kind kind, Opcode opcode, MType *type, MInstruction *operand)
      : FixedOperandInstruction(kind, opcode, 1, type) {
    setOperand<0>(operand);
  }

private:
  friend class FixedOperandInstruction;
  UnaryInstruction(Opcode opcode, MType *type, MInstruction *operand)
      : FixedOperandInstruction(MInstruction::UNARY, opcode, 1, type) {
    setOperand<0>(operand);
  }
};

class NaryInstruction : public FixedOperandInstruction<0> {
public:
  template <typename... Arguments>
  static NaryInstruction *create(CompileMemPool &MemPool, Arguments &&...args) {
    return FixedOperandInstruction::create<NaryInstruction>(
        MemPool, std::forward<Arguments>(args)...);
  }

private:
  friend class FixedOperandInstruction;
  NaryInstruction(Opcode opcode, MType *type)
      : FixedOperandInstruction(MInstruction::UNARY, opcode, 0, type) {}

protected:
  NaryInstruction(Kind kind, Opcode opcode, MType *type)
      : FixedOperandInstruction(kind, opcode, 0, type) {}
};

class DassignInstruction : public UnaryInstruction {
public:
  template <typename... Arguments>
  static DassignInstruction *create(Arguments &&...args) {
    return FixedOperandInstruction::create<DassignInstruction>(
        std::forward<Arguments>(args)...);
  }

  static bool classof(const MInstruction *inst) {
    return inst->getOpcode() == OP_dassign;
  }

  uint32_t getVarIdx() const { return _var_idx; }

private:
  friend class FixedOperandInstruction;
  DassignInstruction(MType *type, MInstruction *operand, uint32_t var_idx)
      : UnaryInstruction(MInstruction::DASSIGN, OP_dassign, type, operand),
        _var_idx(var_idx) {}
  uint32_t _var_idx;
};

class NotInstruction : public UnaryInstruction {
public:
  template <typename... Arguments>
  static NotInstruction *create(Arguments &&...Args) {
    return FixedOperandInstruction::create<NotInstruction>(
        std::forward<Arguments>(Args)...);
  }

  static bool classof(const MInstruction *Inst) {
    return Inst->getOpcode() == OP_not;
  }

private:
  friend class FixedOperandInstruction;
  NotInstruction(MType *Type, MInstruction *Operand)
      : UnaryInstruction(MInstruction::UNARY, OP_not, Type, Operand) {}
};

class LoadInstruction : public UnaryInstruction {
public:
  template <typename... Arguments>
  static LoadInstruction *create(Arguments &&...Args) {
    return FixedOperandInstruction::create<LoadInstruction>(
        std::forward<Arguments>(Args)...);
  }

  static bool classof(const MInstruction *Instr) {
    return Instr->getOpcode() == OP_load;
  }

  const MInstruction *getBase() const { return getOperand<0>(); }
  uint32_t getScale() const { return Scale; }
  const MInstruction *getIndex() const { return Index; }
  int32_t getOffset() const { return Offset; }
  MType *getDestType() const { return getType(); }
  MType *getSrcType() const { return SrcType; }
  bool getSext() const { return Sext; }

private:
  friend class FixedOperandInstruction;
  LoadInstruction(MType *DestType, MType *SrcType, MInstruction *Base,
                  uint32_t Scale, MInstruction *Index, int32_t Offset,
                  bool Sext)
      : UnaryInstruction(MInstruction::LOAD, OP_load, DestType, Base),
        SrcType(SrcType), Scale(Scale), Index(Index), Offset(Offset),
        Sext(Sext) {}

  LoadInstruction(MType *DestType, MInstruction *Base, uint32_t Scale,
                  MInstruction *Index, int32_t Offset)
      : LoadInstruction(DestType, DestType, Base, Scale, Index, Offset, false) {
  }

  LoadInstruction(MType *DestType, MInstruction *Base)
      : LoadInstruction(DestType, Base, 1, nullptr, 0) {}

  LoadInstruction(MType *DestType, MInstruction *Base, uint32_t Scale,
                  MInstruction *Index)
      : LoadInstruction(DestType, Base, Scale, Index, 0) {}

  LoadInstruction(MType *DestType, MInstruction *Base, int32_t Offset)
      : LoadInstruction(DestType, Base, 1, nullptr, Offset) {}

  MType *SrcType;
  uint32_t Scale; // {1,2,4,8}
  MInstruction *Index;
  int32_t Offset; // Equivalent to displacement in x86 addressing mode
  bool Sext;
};

class StoreInstruction : public BinaryInstruction {
public:
  template <typename... Arguments>
  static StoreInstruction *create(Arguments &&...Args) {
    return FixedOperandInstruction::create<StoreInstruction>(
        std::forward<Arguments>(Args)...);
  }

  static bool classof(const MInstruction *Instr) {
    return Instr->getOpcode() == OP_store;
  }

  const MInstruction *getValue() const { return getOperand<0>(); }
  const MInstruction *getBase() const { return getOperand<1>(); }
  uint32_t getScale() const { return Scale; }
  const MInstruction *getIndex() const { return Index; }
  int32_t getOffset() const { return Offset; }

private:
  friend class FixedOperandInstruction;
  StoreInstruction(MType *Type, MInstruction *Value, MInstruction *Base,
                   uint32_t SC, MInstruction *Index, int32_t Offset)
      : BinaryInstruction(MInstruction::STORE, OP_store, Type, Value, Base),
        Scale(SC), Index(Index), Offset(Offset) {}

  StoreInstruction(MType *Type, MInstruction *Value, MInstruction *BaseAddrOp)
      : StoreInstruction(Type, Value, BaseAddrOp, 1, nullptr, 0) {}
  StoreInstruction(MType *Type, MInstruction *Value, MInstruction *BaseAddrOp,
                   int32_t Off)
      : StoreInstruction(Type, Value, BaseAddrOp, 1, nullptr, Off) {}
  StoreInstruction(MType *Type, MInstruction *Value, MInstruction *BaseAddrOp,
                   uint32_t SC, MInstruction *IndexOp)
      : StoreInstruction(Type, Value, BaseAddrOp, SC, IndexOp, 0) {}

  uint32_t Scale; // {1,2,4,8}
  MInstruction *Index;
  int32_t Offset; // Equivalent to displacement in x86 addressing mode
};

class ConversionInstruction : public UnaryInstruction {
public:
  template <typename... Arguments>
  static ConversionInstruction *create(Arguments &&...args) {
    return FixedOperandInstruction::create<ConversionInstruction>(
        std::forward<Arguments>(args)...);
  }

private:
  friend class FixedOperandInstruction;
  ConversionInstruction(Opcode opcode, MType *type, MInstruction *operand)
      : UnaryInstruction(Kind::CONVERSION, opcode, type, operand) {}
};

class DreadInstruction : public NaryInstruction {
public:
  template <typename... Arguments>
  static DreadInstruction *create(Arguments &&...args) {
    return FixedOperandInstruction::create<DreadInstruction>(
        std::forward<Arguments>(args)...);
  }

  uint32_t getVarIdx() const { return _var_idx; }

  static bool classof(const MInstruction *inst) {
    return inst->getOpcode() == OP_dread;
  }

private:
  friend class FixedOperandInstruction;
  DreadInstruction(MType *type, uint32_t idx)
      : NaryInstruction(MInstruction::DREAD, OP_dread, type), _var_idx(idx) {}
  uint32_t _var_idx;
};

class ConstantInstruction : public NaryInstruction {
public:
  template <typename... Arguments>
  static ConstantInstruction *create(Arguments &&...args) {
    return FixedOperandInstruction::create<ConstantInstruction>(
        std::forward<Arguments>(args)...);
  }

  static bool classof(const MInstruction *inst) {
    return inst->getOpcode() == OP_const;
  }
  auto &getConstant() const { return _constant; };

private:
  friend class FixedOperandInstruction;
  ConstantInstruction(MType *type, MConstant &constant)
      : NaryInstruction(Kind::CONSTANT, OP_const, type), _constant(constant) {}
  MConstant &_constant;
};

class CallInstructionBase : public DynamicOperandInstruction {
public:
  template <typename T, typename Callee>
  static T *create(CompileMemPool &MemPool, MType *type, Callee callee,
                   llvm::ArrayRef<MInstruction *> args) {
    return DynamicOperandInstruction::create<T>(MemPool, args.size(), type,
                                                callee, args);
  }

  static bool classof(const MInstruction *inst) {
    return inst->getKind() == CALL;
  }

protected:
  CallInstructionBase(MType *type, Opcode opcode,
                      llvm::ArrayRef<MInstruction *> args)
      : DynamicOperandInstruction(MInstruction::CALL, opcode, args.size(),
                                  type) {
    for (OperandNum i = 0; i < args.size(); i++) {
      setOperand(i, args[i]);
    }
  }
};

// Direct Call Instruction
class CallInstruction : public CallInstructionBase {
public:
  template <typename... Arguments>
  static CallInstruction *create(Arguments &&...args) {
    return CallInstructionBase::create<CallInstruction>(
        std::forward<Arguments>(args)...);
  }

  static bool classof(const MInstruction *inst) {
    return inst->getOpcode() == OP_call;
  }

  uint32_t getCalleeIdx() const { return _callee_idx; }

private:
  friend class DynamicOperandInstruction;
  CallInstruction(MType *type, uint32_t callee_idx,
                  llvm::ArrayRef<MInstruction *> args)
      : CallInstructionBase(type, OP_call, args), _callee_idx(callee_idx) {}

  uint32_t _callee_idx = 0;
};

// Indirect Call Instruction
class ICallInstruction : public CallInstructionBase {
public:
  template <typename... Arguments>
  static ICallInstruction *create(Arguments &&...args) {
    return CallInstructionBase::create<ICallInstruction>(
        std::forward<Arguments>(args)...);
  }

  static bool classof(const MInstruction *inst) {
    return inst->getOpcode() == OP_icall;
  }

  MInstruction *getCalleeAddr() const { return _callee_addr; }

private:
  friend class DynamicOperandInstruction;
  ICallInstruction(MType *type, MInstruction *callee_addr,
                   llvm::ArrayRef<MInstruction *> args)
      : CallInstructionBase(type, OP_icall, args), _callee_addr(callee_addr) {}
  MInstruction *_callee_addr;
};

class BrInstruction : public NaryInstruction {
public:
  template <typename... Arguments>
  static BrInstruction *create(Arguments &&...Args) {
    return FixedOperandInstruction::create<BrInstruction>(
        std::forward<Arguments>(Args)...);
  }

  static bool classof(const MInstruction *Instr) {
    return Instr->getOpcode() == OP_br;
  }

  MBasicBlock *getTargetBlock() const { return TargetBlock; }

protected:
  friend class FixedOperandInstruction;
  BrInstruction(CompileContext &Ctx, MBasicBlock *Target)
      : NaryInstruction(MInstruction::BR, OP_br, &Ctx.VoidType),
        TargetBlock(Target) {}
  MBasicBlock *TargetBlock;
};

class BrIfInstruction : public UnaryInstruction {
public:
  template <typename... Arguments>
  static BrIfInstruction *create(Arguments &&...Args) {
    return FixedOperandInstruction::create<BrIfInstruction>(
        std::forward<Arguments>(Args)...);
  }

  static bool classof(const MInstruction *Instr) {
    return Instr->getOpcode() == OP_br_if;
  }

  MBasicBlock *getTrueBlock() const { return TrueBlock; }

  MBasicBlock *getFalseBlock() const { return FalseBlock; }
  void setFalseBlock(MBasicBlock *BB) { FalseBlock = BB; }
  bool hasFalseBlock() const { return FalseBlock != nullptr; }

protected:
  friend class FixedOperandInstruction;
  BrIfInstruction(CompileContext &Ctx, MInstruction *Condition,
                  MBasicBlock *TrueBB, MBasicBlock *FalseBB = nullptr)
      : UnaryInstruction(MInstruction::BR_IF, OP_br_if, &Ctx.VoidType,
                         Condition),
        TrueBlock(TrueBB), FalseBlock(FalseBB) {}
  MBasicBlock *TrueBlock;
  MBasicBlock *FalseBlock;
};

class SwitchInstruction : public DynamicOperandInstruction {
  typedef std::pair<ConstantInstruction *, MBasicBlock *> CaseType;

public:
  template <typename... Arguments>
  static SwitchInstruction *
  create(CompileMemPool &MemPool, CompileContext &Ctx, MInstruction *Condition,
         MBasicBlock *DefaultBlock, llvm::ArrayRef<CaseType> Cases) {
    return DynamicOperandInstruction::createWithMemPool<SwitchInstruction>(
        MemPool, Cases.size() + 1, Ctx, Condition, DefaultBlock, Cases);
  }

  static bool classof(const MInstruction *Instr) {
    return Instr->getOpcode() == OP_switch;
  }

  uint32_t getNumCases() const { return getNumOperands() - 1; }

  const MInstruction *getCondition() const { return getOperand<0>(); }

  const MBasicBlock *getDefaultBlock() const { return Blocks[0]; }

  const ConstantInstruction *getCaseValue(uint32_t I) const {
    ZEN_ASSERT(I < getNumCases());
    return llvm::cast<ConstantInstruction>(getOperand(I + 1));
  }

  const MBasicBlock *getCaseBlock(uint32_t I) const {
    ZEN_ASSERT(I < getNumCases());
    return Blocks[I + 1];
  }

protected:
  friend class DynamicOperandInstruction;
  SwitchInstruction(CompileMemPool &MemPool, CompileContext &Ctx,
                    MInstruction *Condition, MBasicBlock *DefaultBlock,
                    llvm::ArrayRef<CaseType> Cases)
      : DynamicOperandInstruction(MInstruction::SWITCH, OP_switch,
                                  Cases.size() + 1, &Ctx.VoidType),
        Blocks(Cases.size() + 1, MemPool) {
    setOperand(0, Condition);
    Blocks[0] = DefaultBlock;
    for (size_t I = 0; I < Cases.size(); I++) {
      setOperand(I + 1, Cases[I].first);
      Blocks[I + 1] = Cases[I].second;
    }
  }

  CompileVector<MBasicBlock *> Blocks;
};

class ReturnInstruction : public DynamicOperandInstruction {
public:
  static ReturnInstruction *create(CompileMemPool &MemPool, MType *type,
                                   MInstruction *opnd) {
    uint32_t opnd_num = 0;
    if (!type->isVoid()) {
      ZEN_ASSERT(opnd != nullptr);
      opnd_num = 1;
    }
    return DynamicOperandInstruction::create<ReturnInstruction>(
        MemPool, opnd_num, type, opnd, opnd_num);
  }
  static bool classof(const MInstruction *inst) {
    return inst->getOpcode() == OP_return;
  }

private:
  friend class DynamicOperandInstruction;
  ReturnInstruction(MType *type, MInstruction *operand, uint32_t opnd_num)
      : DynamicOperandInstruction(MInstruction::RETURN, OP_return, opnd_num,
                                  type) {
    if (opnd_num != 0) {
      setOperand<0>(operand);
    }
  }
};

class CmpInstruction : public BinaryInstruction {
public:
  enum Predicate : unsigned {
#define CONDCODE(TEXT, PREDICATE, VALUE) PREDICATE,
#include "compiler/mir/cond_codes.def"
#undef CONDCODE
  };
  template <typename... Arguments>
  static CmpInstruction *create(Arguments &&...args) {
    return FixedOperandInstruction::create<CmpInstruction>(
        std::forward<Arguments>(args)...);
  }

  static bool classof(const MInstruction *inst) {
    return inst->getOpcode() == OP_cmp;
  }

  Predicate getPredicate() const { return _predicate; }

  std::string getPredicateName() const;

private:
  friend class FixedOperandInstruction;
  CmpInstruction(Predicate predicate, MType *type, MInstruction *lhs,
                 MInstruction *rhs)
      : BinaryInstruction(MInstruction::CMP, OP_cmp, type, lhs, rhs),
        _predicate(predicate) {}
  Predicate _predicate;
};

class SelectInstruction : public FixedOperandInstruction<3> {
public:
  template <typename... Arguments>
  static SelectInstruction *create(Arguments &&...args) {
    return FixedOperandInstruction::create<SelectInstruction>(
        std::forward<Arguments>(args)...);
  }

  static bool classof(const MInstruction *inst) {
    return inst->getOpcode() == OP_select;
  }

private:
  friend class FixedOperandInstruction;
  SelectInstruction(MType *type, MInstruction *cond, MInstruction *lhs,
                    MInstruction *rhs)
      : FixedOperandInstruction(MInstruction::SELECT, OP_select, 3, type) {
    setOperand<0>(cond);
    setOperand<1>(lhs);
    setOperand<2>(rhs);
  }
};

class WasmCheckMemoryAccessInstruction : public UnaryInstruction {
public:
  template <typename... Arguments>
  static WasmCheckMemoryAccessInstruction *create(Arguments &&...Args) {
    return FixedOperandInstruction::create<WasmCheckMemoryAccessInstruction>(
        std::forward<Arguments>(Args)...);
  }

  static bool classof(const MInstruction *Instr) {
    return Instr->getOpcode() == OP_wasm_check_memory_access;
  }

  const MInstruction *getBase() const { return Base; }
  uint64_t getOffset() const { return Offset; }
  uint32_t getSize() const { return Size; }
  const MInstruction *getBoundary() const { return getOperand<0>(); }

private:
  friend class FixedOperandInstruction;
  WasmCheckMemoryAccessInstruction(CompileContext &Ctx, MInstruction *Base,
                                   uint64_t Offset, uint32_t Size,
                                   MInstruction *Boundary)
      : UnaryInstruction(MInstruction::WASM_CHECK, OP_wasm_check_memory_access,
                         &Ctx.VoidType, Boundary),
        Base(Base), Offset(Offset), Size(Size) {}
  MInstruction *Base;
  uint64_t Offset;
  uint32_t Size;
};

class WasmCheckStackBoundaryInstruction : public UnaryInstruction {
public:
  template <typename... Arguments>
  static WasmCheckStackBoundaryInstruction *create(Arguments &&...args) {
    return FixedOperandInstruction::create<WasmCheckStackBoundaryInstruction>(
        std::forward<Arguments>(args)...);
  }

  static bool classof(const MInstruction *inst) {
    return inst->getOpcode() == OP_wasm_check_stack_boundary;
  }

private:
  friend class FixedOperandInstruction;
  WasmCheckStackBoundaryInstruction(CompileContext &context,
                                    MInstruction *boundary)
      : UnaryInstruction(MInstruction::WASM_CHECK, OP_wasm_check_stack_boundary,
                         &context.VoidType, boundary) {}
};

class WasmVisitStackGuardInstruction : public NaryInstruction {
public:
  template <typename... Arguments>
  static WasmVisitStackGuardInstruction *create(Arguments &&...args) {
    return FixedOperandInstruction::create<WasmVisitStackGuardInstruction>(
        std::forward<Arguments>(args)...);
  }

  static bool classof(const MInstruction *inst) {
    return inst->getOpcode() == OP_wasm_visit_stack_guard;
  }

private:
  friend class FixedOperandInstruction;
  WasmVisitStackGuardInstruction(CompileContext &context)
      : NaryInstruction(MInstruction::WASM_CHECK, OP_wasm_visit_stack_guard,
                        &context.VoidType) {}
};

class WasmOverflowI128BinaryInstruction : public FixedOperandInstruction<4> {
public:
  template <typename... Arguments>
  static WasmOverflowI128BinaryInstruction *create(Arguments &&...Args) {
    return FixedOperandInstruction::create<WasmOverflowI128BinaryInstruction>(
        std::forward<Arguments>(Args)...);
  }

  static bool classof(const MInstruction *Instr) {
    return Instr->getKind() == OVERFLOW_I128_BINARY;
  }

private:
  friend class FixedOperandInstruction;
  WasmOverflowI128BinaryInstruction(MType *Type, Opcode Opc,
                                    MInstruction *LHSLo, MInstruction *LHSHi,
                                    MInstruction *RHSLo, MInstruction *RHSHi)
      : FixedOperandInstruction(MInstruction::OVERFLOW_I128_BINARY, Opc, 4,
                                Type) {
    setOperand<0>(LHSLo);
    setOperand<1>(LHSHi);
    setOperand<2>(RHSLo);
    setOperand<3>(RHSHi);
  }
};

} // namespace COMPILER

#endif // COMPILER_IR_INSTRUCTIONS_H
