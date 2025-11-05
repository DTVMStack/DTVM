// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef COMPILER_IR_BASIC_BLOCK_H
#define COMPILER_IR_BASIC_BLOCK_H

#include "compiler/context.h"
#include "compiler/mir/instruction.h"

namespace COMPILER {
class MFunction;

class MBasicBlock : public ContextObject {
public:
  MBasicBlock(MFunction &Parent);

  MBasicBlock(uint32_t BBIdx, MFunction &Parent);

  ~MBasicBlock() override = default;

  void print(llvm::raw_ostream &OS) const;

  void dump() const;

  auto begin() { return Statements.begin(); }
  auto end() { return Statements.end(); }
  bool empty() const { return Statements.empty(); }

  void addStatement(MInstruction *Inst) {
    Statements.push_back(Inst);
    Inst->setParentBB(this);
  }

  void addStatement(size_t Idx, MInstruction *Inst) {
    auto It = Statements.begin();
    std::advance(It, Idx);
    Statements.insert(It, Inst);
    Inst->setParentBB(this);
  }

  size_t getNumStatements() const { return Statements.size(); }

  void clear() { Statements.clear(); }

  uint32_t getIdx() const { return BBIdx; }

  void setIdx(uint32_t Idx) { BBIdx = Idx; }

  MFunction &getParent() const { return Parent; }

  using PredIterator = CompileVector<MBasicBlock *>::iterator;
  using ConstPredIterator = CompileVector<MBasicBlock *>::const_iterator;
  using SuccIterator = CompileVector<MBasicBlock *>::iterator;
  using ConstSuccIterator = CompileVector<MBasicBlock *>::const_iterator;

  llvm::iterator_range<SuccIterator> predecessors() {
    return llvm::make_range(Predecessors.begin(), Predecessors.end());
  }
  llvm::iterator_range<ConstSuccIterator> predecessors() const {
    return llvm::make_range(Predecessors.begin(), Predecessors.end());
  }
  llvm::iterator_range<SuccIterator> successors() {
    return llvm::make_range(Successors.begin(), Successors.end());
  }
  llvm::iterator_range<ConstSuccIterator> successors() const {
    return llvm::make_range(Successors.begin(), Successors.end());
  }

  void addSuccessor(MBasicBlock *Succ);
  void removeSuccessor(MBasicBlock *Succ);
  void removeSuccessor(SuccIterator It);
  void addPredecessor(MBasicBlock *Pred);
  void removePredecessor(MBasicBlock *Pred);
  void replaceSuccessor(MBasicBlock *Old, MBasicBlock *New);
#ifdef ZEN_ENABLE_EVM
  void setJumpDestBB(const bool &IsJumpDest) { JumpDestBBFlag = IsJumpDest; }
  bool isJumpDestBB() const { return JumpDestBBFlag; }
#endif // ZEN_ENABLE_EVM

private:
  uint32_t BBIdx = 0;
  MFunction &Parent;
  CompileList<MInstruction *> Statements;
  CompileVector<MBasicBlock *> Predecessors;
  CompileVector<MBasicBlock *> Successors;
#ifdef ZEN_ENABLE_EVM
  bool JumpDestBBFlag = false;
#endif // ZEN_ENABLE_EVM
};

} // namespace COMPILER

#endif // COMPILER_IR_BASIC_BLOCK_H
