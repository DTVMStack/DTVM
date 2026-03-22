/*
 * Copyright (C) 2021-2023 the DTVM authors.
 */
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#ifndef COMPILER_IR_CG_FUNCTION_H
#define COMPILER_IR_CG_FUNCTION_H

#include "compiler/cgir/cg_basic_block.h"
#include "compiler/cgir/pass/cg_block_frequency_info.h"
#include "compiler/cgir/pass/cg_dominators.h"
#include "compiler/cgir/pass/cg_frame_info.h"
#include "compiler/cgir/pass/cg_loop_info.h"
#include "compiler/cgir/pass/cg_register_info.h"
#include "compiler/cgir/pass/edge_bundles.h"
#include "compiler/cgir/pass/live_intervals.h"
#include "compiler/cgir/pass/live_reg_matrix.h"
#include "compiler/cgir/pass/live_stacks.h"
#include "compiler/cgir/pass/reg_alloc_eviction_advisor.h"
#include "compiler/cgir/pass/slot_indexes.h"
#include "compiler/cgir/pass/spill_placement.h"
#include "compiler/cgir/pass/virt_reg_map.h"
#include "compiler/context.h"
#include "compiler/mir/function.h"
#include "llvm/CodeGen/TargetFrameLowering.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/MC/MCInstrDesc.h"
#include "llvm/Target/TargetMachine.h"

namespace COMPILER {

class CgFunction;

struct CgFunctionInfo {
  virtual ~CgFunctionInfo() = default;

  /// Factory function: default behavior is to call new using the
  /// supplied allocator.
  ///
  /// This function can be overridden in a derive class.
  template <typename Ty>
  static Ty *create(CompileMemPool &MemPool, CgFunction &MF) {
    return MemPool.newObject<Ty>(MF);
  }

  template <typename Ty>
  static Ty *create(CompileMemPool &MemPool, const Ty &MFI) {
    return MemPool.newObject<Ty>(MFI);
  }
};

class CgFunction : public ContextObject {
public:
  using CgBasicBlockListType = CompileVector<CgBasicBlock *>;
  using iterator = CgBasicBlockListType::iterator;
  using const_iterator = CgBasicBlockListType::const_iterator;

  using CgInstructionListType = CompileVector<CgInstruction *>;

  CgFunction(CompileContext &Context, MFunction &MIRFunc)
      : ContextObject(Context), _cg_basic_blocks(Context.MemPool),
        JumpTables(Context.MemPool), JTISymbols(Context.MemPool) {
    _mir_func = &MIRFunc;
    STI = &Context.getSubtargetInfo();
    _cg_register_info = Context.MemPool.newObject<CgRegisterInfo>(*this);
    FrameInfo = Context.MemPool.newObject<CgFrameInfo>(
        Ctx.getSubtargetInfo().getFrameLowering()->getStackAlign());
  }

  ~CgFunction() {
    clearCgBasicBlocks();
    Ctx.MemPool.deleteObject(_cg_register_info);
    Ctx.MemPool.deleteObject(FrameInfo);
  }

  // Only create basic block but not insert it into function
  CgBasicBlock *createCgBasicBlock() {
    return Ctx.MemPool.newObject<CgBasicBlock>(*this);
  }

  void appendCgBasicBlock(CgBasicBlock *CgBB) {
    CgBB->setNumber(_cg_basic_blocks.size());
    _cg_basic_blocks.emplace_back(CgBB);
  }

  void insertCgBasicBlockAfter(CgBasicBlock *After, CgBasicBlock *CgBB);

  CgBasicBlock *getCgBasicBlock(BlockNum BBIdx) const {
    ZEN_ASSERT(BBIdx < _cg_basic_blocks.size());
    return _cg_basic_blocks[BBIdx];
  }
  CgBasicBlock *getBlockNumbered(BlockNum BBIdx) const {
    return getCgBasicBlock(BBIdx);
  }
  // for BumpPtrAllocator, ignore this
  void deleteCgBasicBlock(CgBasicBlock *BB) {
    ZEN_ASSERT(BB);
    Ctx.MemPool.deleteObject(BB);
  }
  void clearCgBasicBlocks() {
    for (CgBasicBlock *BB : _cg_basic_blocks) {
      deleteCgBasicBlock(BB);
    }
    _cg_basic_blocks.clear();
  }

  BlockNum getNumBlockIDs() const { return _cg_basic_blocks.size(); }

  // for BumpPtrAllocator, ignore this
  void deleteCgInstruction(CgInstruction *Inst) {
    ZEN_ASSERT(Inst);
    Ctx.MemPool.deleteObject(Inst);
  }

  CgInstruction *createCgInstruction(CgBasicBlock &bb,
                                     const llvm::MCInstrDesc &mcid,
                                     CgRegister op0_reg, CgRegister op1_reg,
                                     CgRegister res_reg) {
    CgOperand op0 = CgOperand::createRegOperand(res_reg, true);
    CgOperand op1 = CgOperand::createRegOperand(op0_reg, false);
    CgOperand op2 = CgOperand::createRegOperand(op1_reg, false);
    std::array<CgOperand, 3> operands = {op0, op1, op2};
    return createCgInstruction(bb, mcid, operands);
  }
  CgInstruction *createCgInstruction(CgBasicBlock &bb,
                                     const llvm::MCInstrDesc &mcid,
                                     CgRegister op_reg, CgRegister res_reg) {
    CgOperand op0 = CgOperand::createRegOperand(res_reg, true);
    CgOperand op1 = CgOperand::createRegOperand(op_reg, false);
    std::array<CgOperand, 2> operands = {op0, op1};
    return createCgInstruction(bb, mcid, operands);
  }

  CgInstruction *createCgInstruction(CgBasicBlock &bb,
                                     const llvm::MCInstrDesc &mcid,
                                     CgRegister res_reg) {
    CgOperand op0 = CgOperand::createRegOperand(res_reg, true);
    std::array<CgOperand, 1> operands = {op0};
    return createCgInstruction(bb, mcid, operands);
  }

  CgInstruction *createCgInstruction(CgBasicBlock &bb,
                                     CgBasicBlock::iterator insert_before,
                                     const llvm::MCInstrDesc &mcid,
                                     llvm::MutableArrayRef<CgOperand> operands,
                                     bool no_implicit = false);

  CgInstruction *createCgInstruction(CgBasicBlock &bb,
                                     const llvm::MCInstrDesc &mcid,
                                     llvm::MutableArrayRef<CgOperand> operands,
                                     bool no_implicit = false);

  CgInstruction *replaceCgInstruction(CgInstruction *inst,
                                      const llvm::MCInstrDesc &mcid,
                                      llvm::MutableArrayRef<CgOperand> operands,
                                      bool no_implicit = false);

  CgInstruction *CloneMachineInstr(const CgInstruction *Orig);

  MFunction &getFunction() const { return *_mir_func; }
  std::string getName() const {
    return std::to_string(_mir_func->getFuncIdx());
  }

  const auto &getTargetInstrInfo() const { return *(STI->getInstrInfo()); }
  const auto &getRegisterInfo() const { return *(STI->getRegisterInfo()); }
  const auto &getSubtarget() const { return *STI; }
  template <typename STC> const STC &getSubtarget() const {
    return static_cast<const STC &>(*STI);
  }

  auto &getRegInfo() { return *_cg_register_info; }
  auto &getRegInfo() const { return *_cg_register_info; }

  auto &getFrameInfo() { return *FrameInfo; }
  auto &getFrameInfo() const { return *FrameInfo; }

  unsigned getCalleeSavedFrameSize() const { return CalleeSavedFrameSize; }
  void setCalleeSavedFrameSize(unsigned bytes) { CalleeSavedFrameSize = bytes; }

  llvm::MCContext &getMCContext() const { return Ctx.getMCContext(); }
  const llvm::TargetMachine &getTarget() const {
    return Ctx.getTargetMachine();
  }

  void dump() const;
  void print(llvm::raw_ostream &OS, const CgSlotIndexes * = nullptr) const;

  iterator begin() { return _cg_basic_blocks.begin(); }
  iterator end() { return _cg_basic_blocks.end(); }
  const_iterator begin() const { return _cg_basic_blocks.cbegin(); }
  const_iterator end() const { return _cg_basic_blocks.cend(); }

  const auto &front() const { return *(_cg_basic_blocks.front()); }
  auto &front() { return *(_cg_basic_blocks.front()); }

  size_t size() const { return _cg_basic_blocks.size(); }

  uint32_t createJumpTableIndex(const CompileVector<CgBasicBlock *> &DestBBs);

  /* These following three methods are only used for during MC lowering */

  MCSymbol *getSymbol();

  MCSymbol *getJTISymbol(uint32_t JTI);

  const CompileVector<CompileVector<CgBasicBlock *>> &getJumpTables() const {
    return JumpTables;
  }

private:
  MFunction *_mir_func;

  const llvm::TargetSubtargetInfo *STI;

  CgBasicBlockListType _cg_basic_blocks;

  CgRegisterInfo *_cg_register_info;
  CgFrameInfo *FrameInfo;

  // The index of JumpTables is the JTI of the corresponding jump table entry
  CompileVector<CompileVector<CgBasicBlock *>> JumpTables;
  CompileVector<MCSymbol *> JTISymbols;

  /// CalleeSavedFrameSize - Size of the callee-saved register portion of the
  /// stack frame in bytes.
  unsigned CalleeSavedFrameSize = 0;

  // pass related
public:
  CgSlotIndexes *Indexes = nullptr;
  CgVirtRegMap *VRM = nullptr;
  CgDominatorTree *DomTree = nullptr;
  CgLoopInfo *Loops = nullptr;
  CgBlockFrequencyInfo *MBFI = nullptr;
  CgLiveIntervals *LIS = nullptr;
  CgLiveStacks *LSS = nullptr;
  CgLiveRegMatrix *Matrix = nullptr;
  CgEdgeBundles *EdgeBundles = nullptr;
  CgSpillPlacement *SpillPlacer = nullptr;
  std::unique_ptr<CgRegAllocEvictionAdvisorAnalysis> EvictAdvisor{nullptr};
};

} // namespace COMPILER

namespace llvm {
using namespace COMPILER;

//===--------------------------------------------------------------------===//
// GraphTraits specializations for function basic block graphs (CFGs)
//===--------------------------------------------------------------------===//

// Provide specializations of GraphTraits to be able to treat a
// machine function as a graph of machine basic blocks... these are
// the same as the machine basic block iterators, except that the root
// node is implicitly the first node of the function.
//
template <>
struct GraphTraits<CgFunction *> : public GraphTraits<CgBasicBlock *> {
  static auto getEntryNode(CgFunction *F) { return &F->front(); }

  // nodes_iterator/begin/end - Allow iteration over all nodes in the graph
  // using nodes_iterator = pointer_iterator<CgFunction::iterator>;
  using nodes_iterator = CgFunction::iterator;

  static nodes_iterator nodes_begin(CgFunction *F) {
    return nodes_iterator(F->begin());
  }

  static nodes_iterator nodes_end(CgFunction *F) {
    return nodes_iterator(F->end());
  }

  static unsigned size(CgFunction *F) { return F->size(); }
};
template <>
struct GraphTraits<const CgFunction *>
    : public GraphTraits<const CgBasicBlock *> {
  static auto getEntryNode(const CgFunction *F) { return &F->front(); }

  // nodes_iterator/begin/end - Allow iteration over all nodes in the graph
  // using nodes_iterator = pointer_iterator<CgFunction::const_iterator>;
  using nodes_iterator = CgFunction::const_iterator;

  static nodes_iterator nodes_begin(const CgFunction *F) {
    return nodes_iterator(F->begin());
  }

  static nodes_iterator nodes_end(const CgFunction *F) {
    return nodes_iterator(F->end());
  }

  static unsigned size(const CgFunction *F) { return F->size(); }
};

// Provide specializations of GraphTraits to be able to treat a function as a
// graph of basic blocks... and to walk it in inverse order.  Inverse order for
// a function is considered to be when traversing the predecessor edges of a BB
// instead of the successor edges.
//
template <>
struct GraphTraits<Inverse<CgFunction *>>
    : public GraphTraits<Inverse<CgBasicBlock *>> {
  static auto getEntryNode(Inverse<CgFunction *> G) {
    return &G.Graph->front();
  }
};
template <>
struct GraphTraits<Inverse<const CgFunction *>>
    : public GraphTraits<Inverse<const CgBasicBlock *>> {
  static auto getEntryNode(Inverse<const CgFunction *> G) {
    return &G.Graph->front();
  }
};

} // namespace llvm

#endif // COMPILER_IR_CG_FUNCTION_H
