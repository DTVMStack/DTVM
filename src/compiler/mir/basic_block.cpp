// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "compiler/mir/basic_block.h"
#include "compiler/common/consts.h"
#include "compiler/mir/function.h"

using namespace COMPILER;

MBasicBlock::MBasicBlock(MFunction &P)
    : ContextObject(P.getContext()), Parent(P) {}

MBasicBlock::MBasicBlock(uint32_t Idx, MFunction &P) : MBasicBlock(P) {
  BBIdx = Idx;
}

void MBasicBlock::addSuccessor(MBasicBlock *Succ) {
  Successors.push_back(Succ);
  Succ->addPredecessor(this);
}

void MBasicBlock::removeSuccessor(MBasicBlock *Succ) {
  auto It = std::find(Successors.begin(), Successors.end(), Succ);
  removeSuccessor(It);
}

void MBasicBlock::removeSuccessor(SuccIterator It) {
  ZEN_ASSERT(It != Successors.end());
  (*It)->removePredecessor(this);
  eraseUnordered(Successors, It);
}

void MBasicBlock::addPredecessor(MBasicBlock *Pred) {
  Predecessors.push_back(Pred);
}

void MBasicBlock::removePredecessor(MBasicBlock *Pred) {
  auto It = std::find(Predecessors.begin(), Predecessors.end(), Pred);
  ZEN_ASSERT(It != Predecessors.end());
  eraseUnordered(Predecessors, It);
}

void MBasicBlock::replaceSuccessor(MBasicBlock *Old, MBasicBlock *New) {
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

  // If New isn't already a successor, let it take Old's place.
  if (NewIt == E) {
    Old->removePredecessor(this);
    New->addPredecessor(this);
    *OldIt = New;
    return;
  }

  // New is already a successor, so remove Old.
  removeSuccessor(OldIt);
}

static void printBlockList(const std::string &ListName,
                           const MBasicBlock::BlockList &Blocks,
                           llvm::raw_ostream &OS) {
  if (Blocks.empty()) {
    return;
  }
  OS << kDumpIndent << ListName << ": ";
  for (const MBasicBlock *BB : Blocks) {
    OS << "@" << BB->getIdx();
    if (BB != Blocks.back()) {
      OS << ", ";
    } else {
      OS << '\n';
    }
  }
}

void MBasicBlock::print(llvm::raw_ostream &OS) const {
  OS << "@" << BBIdx << ":\n";
  printBlockList("predecessors", Predecessors, OS);
  printBlockList("successors", Successors, OS);
  OS << '\n';
  for (MInstruction *Inst : Statements) {
    OS << kDumpIndent;
    Inst->print(OS);
  }
}

#if !defined(NDEBUG) || defined(LLVM_ENABLE_DUMP)
void MBasicBlock::dump() const { print(llvm::dbgs()); }
#endif
