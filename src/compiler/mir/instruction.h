// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef COMPILER_IR_INSTRUCTION_H
#define COMPILER_IR_INSTRUCTION_H

#include "compiler/common/common_defs.h"
#include "compiler/mir/opcode.h"
#include "compiler/mir/type.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

namespace COMPILER {

class MFunction;
class MBasicBlock;
class MInstruction : public NonCopyable {
  friend class MFunction;

public:
  enum Kind : uint8_t {
    //===---------- Expression Instructions ----------===//
    CONSTANT,
    UNARY,
    BINARY,
    ADC,
    CMP,
    CONVERSION,
    SELECT,
    DREAD,
    LOAD,
    OVERFLOW_I128_BINARY,
    EVM_UMUL128,
    EVM_UMUL128_HI,

    //===---------- Statement Instructions ----------===//
    DASSIGN,
    STORE,
    BR,
    BR_IF,
    SWITCH,
    RETURN,
    WASM_CHECK,

    //===---------- Expression & Statement Instructions ----------===//
    CALL
  };

  bool isStatement() const { return _parent.index() == 0; }
  MBasicBlock *getParentBB() const {
    ZEN_ASSERT(isStatement());
    return std::get<0>(_parent);
  }
  MInstruction *getParentInst() const {
    ZEN_ASSERT(!isStatement());
    return std::get<1>(_parent);
  }
  void setParentBB(MBasicBlock *parent) { _parent = parent; }
  void setParentInst(MInstruction *parent) { _parent = parent; }
  MBasicBlock *getBasicBlock() const {
    const MInstruction *cur = this;
    while (!cur->isStatement()) {
      cur = cur->getParentInst();
    }
    return cur->getParentBB();
  }

  MType *getType() const { return _type; }
  void setType(MType *type) { _type = type; }
  Opcode getOpcode() const { return _opcode; }
  Kind getKind() const { return _kind; }
  OperandNum getNumOperands() const { return _operand_num; };

  template <OperandNum idx> MInstruction *&getOperand() {
    ZEN_ASSERT(idx < _operand_num);
    return *(reinterpret_cast<MInstruction **>(this) - _operand_num + idx);
  }
  template <OperandNum idx> const MInstruction *getOperand() const {
    ZEN_ASSERT(idx < _operand_num);
    return *(reinterpret_cast<const MInstruction *const *>(this) -
             _operand_num + idx);
  }
  template <OperandNum idx> void setOperand(MInstruction *inst) {
    getOperand<idx>() = inst;
    inst->setParentInst(this);
  }

  MInstruction *&getOperand(OperandNum idx) {
    ZEN_ASSERT(idx < _operand_num);
    return *(reinterpret_cast<MInstruction **>(this) - _operand_num + idx);
  }
  const MInstruction *getOperand(OperandNum idx) const {
    ZEN_ASSERT(idx < _operand_num);
    return *(reinterpret_cast<const MInstruction *const *>(this) -
             _operand_num + idx);
  }
  void setOperand(OperandNum idx, MInstruction *inst) {
    getOperand(idx) = inst;
    inst->setParentInst(this);
  }

  bool isCommutative() const {
    switch (_opcode) {
    case OP_add:
    case OP_mul:
    case OP_and:
    case OP_or:
    case OP_xor:
    case OP_fpmin:
    case OP_fpmax:
      return true;
    default:
      return false;
    }
  }

  bool isTerminator() const;

  void print(llvm::raw_ostream &OS) const;
  void dump() const;

protected:
  template <typename T>
  static void *allocMem(CompileMemPool &MemPool, OperandNum NumOperands) {
    uint32_t TotalSize = sizeof(T) + sizeof(MInstruction *) * NumOperands;
    uint8_t *Start = reinterpret_cast<uint8_t *>(MemPool.allocate(TotalSize));
    uint8_t *Obj = Start + TotalSize - sizeof(T);
    return reinterpret_cast<void *>(Obj);
  }

  static void freeMem(CompileMemPool &MemPool, MInstruction *Inst) {
    uint8_t *Obj = reinterpret_cast<uint8_t *>(Inst);
    uint8_t *Start = Obj - sizeof(MInstruction *) * (Inst->_operand_num);
    MemPool.deallocate(reinterpret_cast<void *>(Start));
  }

  // only MFunction can create MInstruction
  MInstruction(Kind kind, Opcode opcode, OperandNum operand_num, MType *type)
      : _kind(kind), _opcode(opcode), _operand_num(operand_num), _type(type) {}

  virtual ~MInstruction() = default;

  Kind _kind;
  Opcode _opcode;
  OperandNum _operand_num;
  MType *_type;
  zen::common::Variant<MBasicBlock *, MInstruction *> _parent;
};

inline llvm::raw_ostream &operator<<(llvm::raw_ostream &OS,
                                     const MInstruction &Inst) {
  Inst.print(OS);
  return OS;
}

inline llvm::raw_ostream &operator<<(llvm::raw_ostream &OS,
                                     const MInstruction *Inst) {
  Inst->print(OS);
  return OS;
}

} // namespace COMPILER

#endif // COMPILER_IR_INSTRUCTION_H
