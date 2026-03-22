/*
 * Copyright (C) 2021-2023 the DTVM authors.
 */
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "compiler/cgir/cg_function.h"
#include "compiler/common/consts.h"
#include "llvm/CodeGen/TargetInstrInfo.h"

using namespace COMPILER;

void CgFunction::print(llvm::raw_ostream &OS,
                       const CgSlotIndexes *Indexes) const {
  OS << "cgfunc %" << _mir_func->getFuncIdx();
  _mir_func->getFunctionType()->print(OS);

  OS << " {\n";

  FrameInfo->print(*this, OS);

  for (auto *bb : _cg_basic_blocks) {
    bb->print(OS, Indexes);
  }

  OS << "}\n";
}
#if !defined(NDEBUG) || defined(LLVM_ENABLE_DUMP)
void CgFunction::dump() const { print(llvm::dbgs()); }
#endif

CgInstruction *
CgFunction::createCgInstruction(CgBasicBlock &bb, const llvm::MCInstrDesc &mcid,
                                llvm::MutableArrayRef<CgOperand> operands,
                                bool no_implicit) {
  return createCgInstruction(bb, bb.end(), mcid, operands, no_implicit);
}

CgInstruction *CgFunction::createCgInstruction(
    CgBasicBlock &bb, CgBasicBlock::iterator insert_before,
    const llvm::MCInstrDesc &mcid, llvm::MutableArrayRef<CgOperand> operands,
    bool no_implicit) {
  // TIED_TO, two address
  for (OperandNum opnd_id = 0; opnd_id < operands.size(); ++opnd_id) {
    auto &opnd = operands[opnd_id];
    if (opnd.isReg() && opnd.isUse() && !opnd.isImplicit()) {
      int def_idx = mcid.getOperandConstraint(opnd_id, llvm::MCOI::TIED_TO);
      if (def_idx != -1) {
        auto tie_reg = operands[def_idx].getReg();
        if (tie_reg != opnd.getReg()) {
          createCgInstruction(
              bb, getTargetInstrInfo().get(llvm::TargetOpcode::COPY),
              opnd.getReg(), tie_reg);
        }
        opnd.setReg(tie_reg);
      }
    }
  }

  auto *inst = new (Ctx.MemPool.allocate(sizeof(CgInstruction)))
      CgInstruction(mcid, operands, no_implicit, getContext());
  bb.insert(insert_before, inst);

  return inst;
}

CgInstruction *CgFunction::replaceCgInstruction(
    CgInstruction *inst, const llvm::MCInstrDesc &mcid,
    llvm::MutableArrayRef<CgOperand> operands, bool no_implicit) {
  CgBasicBlock *bb = inst->getParent();
  CgBasicBlock::iterator insert_before = bb->erase(inst);
  return createCgInstruction(*bb, insert_before, mcid, operands, no_implicit);
}

/// Create a new CgInstruction which is a copy of the 'Orig' instruction,
/// identical in all ways except the instruction has no parent, prev, or next.
CgInstruction *CgFunction::CloneMachineInstr(const CgInstruction *Orig) {
  return new (Ctx.MemPool.allocate(sizeof(CgInstruction)))
      CgInstruction(*this, *Orig);
}

void CgFunction::insertCgBasicBlockAfter(CgBasicBlock *After,
                                         CgBasicBlock *CgBB) {
  ZEN_ASSERT(After != nullptr);
  ZEN_ASSERT(CgBB != nullptr);

  const size_t InsertIndex = static_cast<size_t>(After->getNumber()) + 1;
  auto It = _cg_basic_blocks.begin() + InsertIndex;
  _cg_basic_blocks.insert(It, CgBB);
  for (size_t Index = InsertIndex; Index < _cg_basic_blocks.size(); ++Index) {
    _cg_basic_blocks[Index]->setNumber(Index);
  }
}

uint32_t
CgFunction::createJumpTableIndex(const CompileVector<CgBasicBlock *> &DestBBs) {
  ZEN_ASSERT(!DestBBs.empty() && "Cannot create an empty jump table!");
  JumpTables.emplace_back(DestBBs);
  return JumpTables.size() - 1;
}

MCSymbol *CgFunction::getSymbol() {
  return getContext().getOrCreateFuncMCSymbol(_mir_func->getFuncIdx());
}

MCSymbol *CgFunction::getJTISymbol(uint32_t JTI) {
  ZEN_ASSERT(!JumpTables.empty() && "Jump table is empty!");
  ZEN_ASSERT(JTI < JumpTables.size() && "Invalid JTI!");
  if (JTI >= JTISymbols.size()) {
    JTISymbols.resize(JTI + 1);
  }
  llvm::MCSymbol *&JTISymbol = JTISymbols[JTI];
  if (!JTISymbol) {
    std::string Name = ".LJTI" + getName() + '_' + std::to_string(JTI);
    JTISymbol = getContext().getOrCreateMCSymbol(Name);
  }
  return JTISymbol;
}
