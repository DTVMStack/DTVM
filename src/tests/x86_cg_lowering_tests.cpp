// Copyright (C) 2021-2026 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/cgir/cg_basic_block.h"
#include "compiler/cgir/cg_function.h"
#include "compiler/context.h"
#include "compiler/mir/basic_block.h"
#include "compiler/mir/constants.h"
#include "compiler/mir/function.h"
#include "compiler/mir/instructions.h"
#include "compiler/mir/pass/peephole.h"
#include "compiler/mir/variable.h"
#include "compiler/target/x86/x86_cg_peephole.h"
#include "compiler/target/x86/x86lowering.h"

#include "llvm/ADT/APFloat.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/CodeGen/TargetOpcodes.h"
#include "llvm/Support/raw_ostream.h"

#include <gtest/gtest.h>
#include <string>
#include <utility>
#include <vector>

using namespace COMPILER;
using namespace llvm;

namespace {

void finishLitmus(MFunction &F) {
#ifdef NDEBUG
  F.detachFromPool();
#else
  (void)F;
#endif
}

std::string dumpCg(const CgFunction &MF) {
  std::string S;
  llvm::raw_string_ostream OS(S);
  MF.print(OS);
  return OS.str();
}

struct Jcc {
  unsigned CC;
  unsigned Target;
};

std::vector<Jcc> collectJcc(const CgFunction &MF) {
  std::vector<Jcc> Out;
  for (CgBasicBlock *BB : MF) {
    for (auto &MI : *BB) {
      if (MI.getOpcode() == X86::JCC_1) {
        Out.push_back({static_cast<unsigned>(MI.getOperand(1).getImm()),
                       MI.getOperand(0).getMBB()->getNumber()});
      }
    }
  }
  return Out;
}

unsigned countOpcode(const CgFunction &MF, unsigned Opc) {
  unsigned N = 0;
  for (CgBasicBlock *BB : MF) {
    for (auto &MI : *BB) {
      if (MI.getOpcode() == Opc) {
        ++N;
      }
    }
  }
  return N;
}

MInstruction *makeInt(MFunction &F, MBasicBlock &BB, MType *Ty, uint64_t V) {
  return F.createInstruction<COMPILER::ConstantInstruction>(
      false, BB, Ty, *MConstantInt::get(F.getContext(), *Ty, V));
}

MInstruction *makeFP(MFunction &F, MBasicBlock &BB, MType *Ty,
                     const APFloat &V) {
  return F.createInstruction<COMPILER::ConstantInstruction>(
      false, BB, Ty, *MConstantFloat::get(F.getContext(), *Ty, V));
}

void retImm(MFunction &F, MBasicBlock &BB, MType *Ty, uint64_t V) {
  F.createInstruction<COMPILER::ReturnInstruction>(true, BB, Ty,
                                                   makeInt(F, BB, Ty, V));
}

// Short diamond: result starts at 3, true arm stores 7, rejoin/false returns
// it. True's terminator targets False, which is what
// isShortDiamondTrueFallthrough requires (not a two-arm if-else).
void buildFpShortDiamond37(MFunction &F, CompileContext &Ctx, MType *I32,
                           CmpInstruction::Predicate Pred, MInstruction *LHS,
                           MInstruction *RHS, MBasicBlock *Entry,
                           MBasicBlock *TrueBB, MBasicBlock *FalseBB) {
  COMPILER::Variable *Res = F.createVariable(I32);
  F.createInstruction<COMPILER::DassignInstruction>(true, *Entry, &Ctx.VoidType,
                                                    makeInt(F, *Entry, I32, 3),
                                                    Res->getVarIdx());
  auto *Cmp = F.createInstruction<COMPILER::CmpInstruction>(false, *Entry, Pred,
                                                            I32, LHS, RHS);
  F.createInstruction<COMPILER::BrIfInstruction>(true, *Entry, Ctx, Cmp, TrueBB,
                                                 FalseBB);
  Entry->addSuccessor(TrueBB);
  Entry->addSuccessor(FalseBB);
  F.createInstruction<COMPILER::DassignInstruction>(
      true, *TrueBB, &Ctx.VoidType, makeInt(F, *TrueBB, I32, 7),
      Res->getVarIdx());
  F.createInstruction<COMPILER::BrInstruction>(true, *TrueBB, Ctx, FalseBB);
  TrueBB->addSuccessor(FalseBB);
  auto *Ret = F.createInstruction<COMPILER::DreadInstruction>(
      false, *FalseBB, I32, Res->getVarIdx());
  F.createInstruction<COMPILER::ReturnInstruction>(true, *FalseBB, I32, Ret);
}

// br_if cmp, Taken  (no false block). After lowering the JCC target is the
// Taken CgBB, typically numbered 2 because startNewBlockAfterBranch inserts
// a fallthrough block as 1.
void lowerDirectBrIf(MFunction &F, MType *RetTy, CmpInstruction::Predicate Pred,
                     MInstruction *LHS, MInstruction *RHS, MBasicBlock *Entry,
                     MBasicBlock *Taken) {
  auto *Cmp = F.createInstruction<COMPILER::CmpInstruction>(false, *Entry, Pred,
                                                            RetTy, LHS, RHS);
  F.createInstruction<COMPILER::BrIfInstruction>(true, *Entry, F.getContext(),
                                                 Cmp, Taken);
  Entry->addSuccessor(Taken);
  retImm(F, *Entry, RetTy, 1);
  retImm(F, *Taken, RetTy, 0);
}

void expectOneJcc(const CgFunction &MF, unsigned CC, unsigned Target,
                  const std::string &Dump) {
  const auto Jccs = collectJcc(MF);
  ASSERT_EQ(Jccs.size(), 1u) << Dump;
  EXPECT_EQ(Jccs[0].CC, CC) << Dump;
  EXPECT_EQ(Jccs[0].Target, Target) << Dump;
}

bool findUcomi(const CgFunction &MF, unsigned &Opc, CgRegister &Op0,
               CgRegister &Op1, const std::string &Dump) {
  for (CgBasicBlock *BB : MF) {
    for (auto &MI : *BB) {
      if (MI.getOpcode() == X86::UCOMISDrr ||
          MI.getOpcode() == X86::UCOMISSrr) {
        Opc = MI.getOpcode();
        Op0 = MI.getOperand(0).getReg();
        Op1 = MI.getOperand(1).getReg();
        return true;
      }
    }
  }
  ADD_FAILURE() << "no UCOMI\n" << Dump;
  return false;
}

CgRegister copyDestFromPhys(const CgFunction &MF, unsigned Phys) {
  for (CgBasicBlock *BB : MF) {
    for (auto &MI : *BB) {
      if (!MI.isCopy() || MI.getNumOperands() < 2) {
        continue;
      }
      const CgOperand &Dst = MI.getOperand(0);
      const CgOperand &Src = MI.getOperand(1);
      if (Dst.isReg() && Src.isReg() && Src.getReg() == Phys) {
        return Dst.getReg();
      }
    }
  }
  return CgRegister();
}

void addCopyUse(CgFunction &MF, CgBasicBlock &BB, CgRegister Src,
                const TargetRegisterClass *RC) {
  CgRegister Dst = MF.getRegInfo().createVirtualRegister(RC);
  MF.createCgInstruction(BB, MF.getTargetInstrInfo().get(TargetOpcode::COPY),
                         Src, Dst);
}

} // namespace

TEST(X86CgLowering, BrIfCmpEmitsDirectJccWithoutSetcc) {
  CompileContext Ctx;
  Ctx.initialize();
  MType *I32 = &CompileContext::I32Type;
  MFunction F(Ctx, 0);
  F.setFunctionType(MFunctionType::create(Ctx, *I32, {I32}));
  MBasicBlock *Entry = F.createBasicBlock();
  MBasicBlock *Taken = F.createBasicBlock();
  F.appendBlock(Entry);
  F.appendBlock(Taken);

  auto *Param =
      F.createInstruction<COMPILER::DreadInstruction>(false, *Entry, I32, 0);
  lowerDirectBrIf(F, I32, CmpInstruction::ICMP_SLT, Param,
                  makeInt(F, *Entry, I32, 10), Entry, Taken);

  CgFunction MF(Ctx, F);
  X86CgLowering Lowering(MF);

  // Snapshot before peephole: the old path emitted SETCC+TEST+JCC, which the
  // peep can also collapse. Direct cmp+jcc must already be present here.
  const std::string Dump = dumpCg(MF);
  EXPECT_EQ(countOpcode(MF, X86::SETCCr), 0u) << Dump;
  EXPECT_EQ(countOpcode(MF, X86::TEST32rr), 0u) << Dump;
  expectOneJcc(MF, X86::COND_L, /*Taken after fallthrough*/ 2, Dump);
  finishLitmus(F);
}

TEST(X86CgLowering, DirectJccSignedUnsignedI32I64Boundaries) {
  struct Case {
    bool I64;
    CmpInstruction::Predicate Pred;
    uint64_t RHS;
    unsigned CC;
  };
  const Case Cases[] = {
      {false, CmpInstruction::ICMP_SLT, 0, X86::COND_L},
      {false, CmpInstruction::ICMP_SLT, 0x80000000ull, X86::COND_L},
      {false, CmpInstruction::ICMP_ULT, 0x80000000ull, X86::COND_B},
      {false, CmpInstruction::ICMP_SGT, static_cast<uint64_t>(-1), X86::COND_G},
      {false, CmpInstruction::ICMP_UGT, static_cast<uint64_t>(-1), X86::COND_A},
      {true, CmpInstruction::ICMP_SLT, 0, X86::COND_L},
      {true, CmpInstruction::ICMP_SLT, 0x8000000000000000ull, X86::COND_L},
      {true, CmpInstruction::ICMP_ULT, 0x8000000000000000ull, X86::COND_B},
      {true, CmpInstruction::ICMP_SGE, static_cast<uint64_t>(-1), X86::COND_GE},
      {true, CmpInstruction::ICMP_UGE, static_cast<uint64_t>(-1), X86::COND_AE},
  };
  for (const Case &C : Cases) {
    CompileContext Ctx;
    Ctx.initialize();
    MType *RetTy = &CompileContext::I32Type;
    MType *CmpTy = C.I64 ? &CompileContext::I64Type : &CompileContext::I32Type;
    MFunction F(Ctx, 0);
    F.setFunctionType(MFunctionType::create(Ctx, *RetTy, {CmpTy}));
    MBasicBlock *Entry = F.createBasicBlock();
    MBasicBlock *Taken = F.createBasicBlock();
    F.appendBlock(Entry);
    F.appendBlock(Taken);

    auto *Param = F.createInstruction<COMPILER::DreadInstruction>(false, *Entry,
                                                                  CmpTy, 0);
    lowerDirectBrIf(F, RetTy, C.Pred, Param, makeInt(F, *Entry, CmpTy, C.RHS),
                    Entry, Taken);

    CgFunction MF(Ctx, F);
    X86CgLowering Lowering(MF);
    const std::string Dump = dumpCg(MF);
    EXPECT_EQ(countOpcode(MF, X86::SETCCr), 0u) << Dump;
    expectOneJcc(MF, C.CC, 2, Dump);
    finishLitmus(F);
  }
}

TEST(X86CgLowering, BrIfOfCachedCmpUsesSetcc) {
  // dassign of the same CmpInstruction runs first and fills _expr_reg_map;
  // the later br_if must take the boolean TEST+JCC path.
  CompileContext Ctx;
  Ctx.initialize();
  MType *I32 = &CompileContext::I32Type;
  MFunction F(Ctx, 0);
  F.setFunctionType(MFunctionType::create(Ctx, *I32, {I32}));
  MBasicBlock *Entry = F.createBasicBlock();
  MBasicBlock *Taken = F.createBasicBlock();
  F.appendBlock(Entry);
  F.appendBlock(Taken);

  COMPILER::Variable *Var = F.createVariable(I32);
  auto *Param =
      F.createInstruction<COMPILER::DreadInstruction>(false, *Entry, I32, 0);
  auto *Cmp = F.createInstruction<COMPILER::CmpInstruction>(
      false, *Entry, CmpInstruction::ICMP_SLT, I32, Param,
      makeInt(F, *Entry, I32, 10));
  F.createInstruction<COMPILER::DassignInstruction>(true, *Entry, &Ctx.VoidType,
                                                    Cmp, Var->getVarIdx());
  F.createInstruction<COMPILER::BrIfInstruction>(true, *Entry, Ctx, Cmp, Taken);
  Entry->addSuccessor(Taken);
  retImm(F, *Entry, I32, 1);
  retImm(F, *Taken, I32, 0);

  CgFunction MF(Ctx, F);
  X86CgLowering Lowering(MF);

  const std::string Dump = dumpCg(MF);
  EXPECT_GE(countOpcode(MF, X86::SETCCr), 1u) << Dump;
  EXPECT_GE(countOpcode(MF, X86::TEST32rr) + countOpcode(MF, X86::TEST8rr), 1u)
      << Dump;
  expectOneJcc(MF, X86::COND_NE, 2, Dump);
  finishLitmus(F);
}

TEST(X86CgLowering, BrIfOfCmpValueStillUsesSetcc) {
  CompileContext Ctx;
  Ctx.initialize();
  MType *I32 = &CompileContext::I32Type;
  MFunction F(Ctx, 0);
  F.setFunctionType(MFunctionType::create(Ctx, *I32, {I32}));
  MBasicBlock *Entry = F.createBasicBlock();
  MBasicBlock *Taken = F.createBasicBlock();
  F.appendBlock(Entry);
  F.appendBlock(Taken);

  COMPILER::Variable *Var = F.createVariable(I32);
  auto *Param =
      F.createInstruction<COMPILER::DreadInstruction>(false, *Entry, I32, 0);
  auto *Cmp = F.createInstruction<COMPILER::CmpInstruction>(
      false, *Entry, CmpInstruction::ICMP_SLT, I32, Param,
      makeInt(F, *Entry, I32, 10));
  F.createInstruction<COMPILER::DassignInstruction>(true, *Entry, &Ctx.VoidType,
                                                    Cmp, Var->getVarIdx());
  auto *Cond = F.createInstruction<COMPILER::DreadInstruction>(
      false, *Entry, I32, Var->getVarIdx());
  F.createInstruction<COMPILER::BrIfInstruction>(true, *Entry, Ctx, Cond,
                                                 Taken);
  Entry->addSuccessor(Taken);
  retImm(F, *Entry, I32, 1);
  retImm(F, *Taken, I32, 0);

  CgFunction MF(Ctx, F);
  X86CgLowering Lowering(MF);

  const std::string Dump = dumpCg(MF);
  EXPECT_GE(countOpcode(MF, X86::SETCCr), 1u) << Dump;
  finishLitmus(F);
}

TEST(X86CgLowering, ShortDiamondInvertsCCToFalseEdge) {
  CompileContext Ctx;
  Ctx.initialize();
  MType *I32 = &CompileContext::I32Type;
  MFunction F(Ctx, 0);
  F.setFunctionType(MFunctionType::create(Ctx, *I32, {I32}));
  MBasicBlock *Entry = F.createBasicBlock();
  MBasicBlock *TrueBB = F.createBasicBlock();
  MBasicBlock *FalseBB = F.createBasicBlock();
  F.appendBlock(Entry);
  F.appendBlock(TrueBB);
  F.appendBlock(FalseBB);

  auto *Param =
      F.createInstruction<COMPILER::DreadInstruction>(false, *Entry, I32, 0);
  auto *Cmp = F.createInstruction<COMPILER::CmpInstruction>(
      false, *Entry, CmpInstruction::ICMP_SLT, I32, Param,
      makeInt(F, *Entry, I32, 0));
  F.createInstruction<COMPILER::BrIfInstruction>(true, *Entry, Ctx, Cmp, TrueBB,
                                                 FalseBB);
  Entry->addSuccessor(TrueBB);
  Entry->addSuccessor(FalseBB);
  F.createInstruction<COMPILER::BrInstruction>(true, *TrueBB, Ctx, FalseBB);
  TrueBB->addSuccessor(FalseBB);
  retImm(F, *FalseBB, I32, 0);

  CgFunction MF(Ctx, F);
  X86CgLowering Lowering(MF);
  const std::string Dump = dumpCg(MF);
  EXPECT_EQ(countOpcode(MF, X86::SETCCr), 0u) << Dump;
  expectOneJcc(MF, X86::COND_GE, /*FalseBB*/ 2, Dump);
  finishLitmus(F);
}

TEST(X86CgLowering, FpDirectJccNanInfSignedZero) {
  struct Case {
    CmpInstruction::Predicate Pred;
    APFloat RHS;
    unsigned CC;
  };
  const fltSemantics &Dbl = APFloat::IEEEdouble();
  const fltSemantics &Flt = APFloat::IEEEsingle();
  const Case Cases[] = {
      {CmpInstruction::FCMP_OGT, APFloat::getNaN(Dbl), X86::COND_A},
      {CmpInstruction::FCMP_OLT, APFloat::getNaN(Dbl), X86::COND_A},
      {CmpInstruction::FCMP_OGE, APFloat::getNaN(Dbl), X86::COND_AE},
      {CmpInstruction::FCMP_OLE, APFloat::getNaN(Dbl), X86::COND_AE},
      {CmpInstruction::FCMP_OGT, APFloat::getInf(Dbl), X86::COND_A},
      {CmpInstruction::FCMP_OGT, APFloat::getInf(Dbl, true), X86::COND_A},
      {CmpInstruction::FCMP_OGT, APFloat::getZero(Dbl, true), X86::COND_A},
      {CmpInstruction::FCMP_UNO, APFloat::getNaN(Dbl), X86::COND_P},
      {CmpInstruction::FCMP_ORD, APFloat::getZero(Dbl), X86::COND_NP},
  };
  for (int Width = 0; Width < 2; ++Width) {
    MType *FPTy = Width ? &CompileContext::F32Type : &CompileContext::F64Type;
    const fltSemantics &Sem = Width ? Flt : Dbl;
    for (const Case &C : Cases) {
      CompileContext Ctx;
      Ctx.initialize();
      MType *I32 = &CompileContext::I32Type;
      MFunction F(Ctx, 0);
      F.setFunctionType(MFunctionType::create(Ctx, *I32, {FPTy}));
      MBasicBlock *Entry = F.createBasicBlock();
      MBasicBlock *Taken = F.createBasicBlock();
      F.appendBlock(Entry);
      F.appendBlock(Taken);

      APFloat RHS = C.RHS;
      if (&C.RHS.getSemantics() != &Sem) {
        bool Unused = false;
        RHS.convert(Sem, APFloat::rmNearestTiesToEven, &Unused);
      }
      auto *Param = F.createInstruction<COMPILER::DreadInstruction>(
          false, *Entry, FPTy, 0);
      lowerDirectBrIf(F, I32, C.Pred, Param, makeFP(F, *Entry, FPTy, RHS),
                      Entry, Taken);

      CgFunction MF(Ctx, F);
      X86CgLowering Lowering(MF);
      const std::string Dump = dumpCg(MF);
      EXPECT_EQ(countOpcode(MF, X86::SETCCr), 0u) << Dump;
      expectOneJcc(MF, C.CC, 2, Dump);
      unsigned UcomiOpc = 0;
      CgRegister U0, U1, ParamV = copyDestFromPhys(MF, X86::XMM0);
      ASSERT_TRUE(findUcomi(MF, UcomiOpc, U0, U1, Dump));
      EXPECT_EQ(UcomiOpc, Width ? X86::UCOMISSrr : X86::UCOMISDrr) << Dump;
      ASSERT_TRUE(ParamV.isVirtual()) << Dump;
      // OLT/OLE swap UCOMI operands so COND_A/AE still means "param ? const".
      const bool Swapped = C.Pred == CmpInstruction::FCMP_OLT ||
                           C.Pred == CmpInstruction::FCMP_OLE;
      if (Swapped) {
        EXPECT_EQ(U1, ParamV) << Dump;
        EXPECT_NE(U0, ParamV) << Dump;
      } else {
        EXPECT_EQ(U0, ParamV) << Dump;
        EXPECT_NE(U1, ParamV) << Dump;
      }
      finishLitmus(F);
    }
  }
}

TEST(X86CgLowering, FpDirectJccSwapsOltOleOperands) {
  struct Case {
    CmpInstruction::Predicate Pred;
    unsigned CC;
    bool Swap;
  };
  const Case Cases[] = {
      {CmpInstruction::FCMP_OLT, X86::COND_A, true},
      {CmpInstruction::FCMP_OLE, X86::COND_AE, true},
      {CmpInstruction::FCMP_OGT, X86::COND_A, false},
      {CmpInstruction::FCMP_OGE, X86::COND_AE, false},
  };
  for (int Width = 0; Width < 2; ++Width) {
    MType *FPTy = Width ? &CompileContext::F32Type : &CompileContext::F64Type;
    for (const Case &C : Cases) {
      CompileContext Ctx;
      Ctx.initialize();
      MType *I32 = &CompileContext::I32Type;
      MFunction F(Ctx, 0);
      F.setFunctionType(MFunctionType::create(Ctx, *I32, {FPTy, FPTy}));
      MBasicBlock *Entry = F.createBasicBlock();
      MBasicBlock *Taken = F.createBasicBlock();
      F.appendBlock(Entry);
      F.appendBlock(Taken);

      auto *P0 = F.createInstruction<COMPILER::DreadInstruction>(false, *Entry,
                                                                 FPTy, 0);
      auto *P1 = F.createInstruction<COMPILER::DreadInstruction>(false, *Entry,
                                                                 FPTy, 1);
      lowerDirectBrIf(F, I32, C.Pred, P0, P1, Entry, Taken);

      CgFunction MF(Ctx, F);
      X86CgLowering Lowering(MF);
      const std::string Dump = dumpCg(MF);
      EXPECT_EQ(countOpcode(MF, X86::SETCCr), 0u) << Dump;
      expectOneJcc(MF, C.CC, 2, Dump);
      unsigned UcomiOpc = 0;
      CgRegister U0, U1;
      ASSERT_TRUE(findUcomi(MF, UcomiOpc, U0, U1, Dump));
      EXPECT_EQ(UcomiOpc, Width ? X86::UCOMISSrr : X86::UCOMISDrr) << Dump;
      CgRegister V0 = copyDestFromPhys(MF, X86::XMM0);
      CgRegister V1 = copyDestFromPhys(MF, X86::XMM1);
      ASSERT_TRUE(V0.isVirtual() && V1.isVirtual()) << Dump;
      if (C.Swap) {
        EXPECT_EQ(U0, V1) << Dump;
        EXPECT_EQ(U1, V0) << Dump;
      } else {
        EXPECT_EQ(U0, V0) << Dump;
        EXPECT_EQ(U1, V1) << Dump;
      }
      finishLitmus(F);
    }
  }
}

TEST(X86CgLowering, FpDirectJccNanOnEitherOperand) {
  struct Case {
    bool NanLHS;
    CmpInstruction::Predicate Pred;
    bool ExpectParamAsOp0;
  };
  const Case Cases[] = {
      {false, CmpInstruction::FCMP_OGT, true},  // param, nan
      {true, CmpInstruction::FCMP_OGT, false},  // nan, param
      {false, CmpInstruction::FCMP_OLT, false}, // swap: nan, param
      {true, CmpInstruction::FCMP_OLT, true},   // swap: param, nan
  };
  for (const Case &C : Cases) {
    CompileContext Ctx;
    Ctx.initialize();
    MType *I32 = &CompileContext::I32Type;
    MType *F64 = &CompileContext::F64Type;
    MFunction F(Ctx, 0);
    F.setFunctionType(MFunctionType::create(Ctx, *I32, {F64}));
    MBasicBlock *Entry = F.createBasicBlock();
    MBasicBlock *Taken = F.createBasicBlock();
    F.appendBlock(Entry);
    F.appendBlock(Taken);

    auto *Param =
        F.createInstruction<COMPILER::DreadInstruction>(false, *Entry, F64, 0);
    auto *Nan = makeFP(F, *Entry, F64, APFloat::getNaN(APFloat::IEEEdouble()));
    if (C.NanLHS) {
      lowerDirectBrIf(F, I32, C.Pred, Nan, Param, Entry, Taken);
    } else {
      lowerDirectBrIf(F, I32, C.Pred, Param, Nan, Entry, Taken);
    }

    CgFunction MF(Ctx, F);
    X86CgLowering Lowering(MF);
    const std::string Dump = dumpCg(MF);
    EXPECT_EQ(countOpcode(MF, X86::SETCCr), 0u) << Dump;
    expectOneJcc(MF, X86::COND_A, 2, Dump);
    unsigned UcomiOpc = 0;
    CgRegister U0, U1, ParamV = copyDestFromPhys(MF, X86::XMM0);
    ASSERT_TRUE(findUcomi(MF, UcomiOpc, U0, U1, Dump));
    ASSERT_TRUE(ParamV.isVirtual()) << Dump;
    if (C.ExpectParamAsOp0) {
      EXPECT_EQ(U0, ParamV) << Dump;
      EXPECT_NE(U1, ParamV) << Dump;
    } else {
      EXPECT_NE(U0, ParamV) << Dump;
      EXPECT_EQ(U1, ParamV) << Dump;
    }
    finishLitmus(F);
  }
}

TEST(X86CgLowering, FpShortDiamondInvertsFalseEdge) {
  CompileContext Ctx;
  Ctx.initialize();
  MType *I32 = &CompileContext::I32Type;
  MType *F64 = &CompileContext::F64Type;
  MFunction F(Ctx, 0);
  F.setFunctionType(MFunctionType::create(Ctx, *I32, {F64}));
  MBasicBlock *Entry = F.createBasicBlock();
  MBasicBlock *TrueBB = F.createBasicBlock();
  MBasicBlock *FalseBB = F.createBasicBlock();
  F.appendBlock(Entry);
  F.appendBlock(TrueBB);
  F.appendBlock(FalseBB);

  auto *Param =
      F.createInstruction<COMPILER::DreadInstruction>(false, *Entry, F64, 0);
  auto *Nan = makeFP(F, *Entry, F64, APFloat::getNaN(APFloat::IEEEdouble()));
  auto *Cmp = F.createInstruction<COMPILER::CmpInstruction>(
      false, *Entry, CmpInstruction::FCMP_OGT, I32, Param, Nan);
  F.createInstruction<COMPILER::BrIfInstruction>(true, *Entry, Ctx, Cmp, TrueBB,
                                                 FalseBB);
  Entry->addSuccessor(TrueBB);
  Entry->addSuccessor(FalseBB);
  F.createInstruction<COMPILER::BrInstruction>(true, *TrueBB, Ctx, FalseBB);
  TrueBB->addSuccessor(FalseBB);
  retImm(F, *FalseBB, I32, 0);

  CgFunction MF(Ctx, F);
  X86CgLowering Lowering(MF);
  const std::string Dump = dumpCg(MF);
  EXPECT_EQ(countOpcode(MF, X86::SETCCr), 0u) << Dump;
  expectOneJcc(MF, X86::COND_BE, 2, Dump);
  unsigned UcomiOpc = 0;
  CgRegister U0, U1, ParamV = copyDestFromPhys(MF, X86::XMM0);
  ASSERT_TRUE(findUcomi(MF, UcomiOpc, U0, U1, Dump));
  ASSERT_TRUE(ParamV.isVirtual()) << Dump;
  EXPECT_EQ(U0, ParamV) << Dump;
  EXPECT_NE(U1, ParamV) << Dump;
  finishLitmus(F);
}

TEST(X86CgLowering, FpShortDiamondOltSwapsAndInverts) {
  struct Case {
    CmpInstruction::Predicate Pred;
    bool NanRHS;
    bool ExpectParamAsUcomiOp0;
    const char *Name;
  };
  const Case Cases[] = {
      {CmpInstruction::FCMP_OGT, false, true, "OGT finite"},
      {CmpInstruction::FCMP_OLT, false, false, "OLT finite swap"},
      {CmpInstruction::FCMP_OGT, true, true, "OGT nan rhs"},
      {CmpInstruction::FCMP_OLT, true, false, "OLT nan rhs swap"},
  };
  for (const Case &C : Cases) {
    CompileContext Ctx;
    Ctx.initialize();
    MType *I32 = &CompileContext::I32Type;
    MType *F64 = &CompileContext::F64Type;
    MFunction F(Ctx, 0);
    F.setFunctionType(MFunctionType::create(Ctx, *I32, {F64}));
    MBasicBlock *Entry = F.createBasicBlock();
    MBasicBlock *TrueBB = F.createBasicBlock();
    MBasicBlock *FalseBB = F.createBasicBlock();
    F.appendBlock(Entry);
    F.appendBlock(TrueBB);
    F.appendBlock(FalseBB);

    auto *Param =
        F.createInstruction<COMPILER::DreadInstruction>(false, *Entry, F64, 0);
    auto *RHS = C.NanRHS ? makeFP(F, *Entry, F64,
                                  APFloat::getNaN(APFloat::IEEEdouble()))
                         : makeFP(F, *Entry, F64, APFloat(2.0));
    buildFpShortDiamond37(F, Ctx, I32, C.Pred, Param, RHS, Entry, TrueBB,
                          FalseBB);

    CgFunction MF(Ctx, F);
    X86CgLowering Lowering(MF);
    const std::string Dump = std::string(C.Name) + "\n" + dumpCg(MF);
    EXPECT_EQ(countOpcode(MF, X86::SETCCr), 0u) << Dump;
    // OGT/OLT both use COND_A; the diamond inverts to COND_BE on the false
    // edge.
    expectOneJcc(MF, X86::COND_BE, 2, Dump);
    unsigned UcomiOpc = 0;
    CgRegister U0, U1, ParamV = copyDestFromPhys(MF, X86::XMM0);
    ASSERT_TRUE(findUcomi(MF, UcomiOpc, U0, U1, Dump));
    ASSERT_TRUE(ParamV.isVirtual()) << Dump;
    if (C.ExpectParamAsUcomiOp0) {
      EXPECT_EQ(U0, ParamV) << Dump;
      EXPECT_NE(U1, ParamV) << Dump;
    } else {
      EXPECT_EQ(U1, ParamV) << Dump;
      EXPECT_NE(U0, ParamV) << Dump;
    }
    finishLitmus(F);
  }
}

TEST(X86CgLowering, FcmpOeqUneStayOnTwoTestFallback) {
  for (auto Pred : {CmpInstruction::FCMP_OEQ, CmpInstruction::FCMP_UNE}) {
    CompileContext Ctx;
    Ctx.initialize();
    MType *I32 = &CompileContext::I32Type;
    MType *F64 = &CompileContext::F64Type;
    MFunction F(Ctx, 0);
    F.setFunctionType(MFunctionType::create(Ctx, *I32, {F64}));
    MBasicBlock *Entry = F.createBasicBlock();
    MBasicBlock *Taken = F.createBasicBlock();
    F.appendBlock(Entry);
    F.appendBlock(Taken);

    auto *Param =
        F.createInstruction<COMPILER::DreadInstruction>(false, *Entry, F64, 0);
    lowerDirectBrIf(
        F, I32, Pred, Param,
        makeFP(F, *Entry, F64, APFloat::getNaN(APFloat::IEEEdouble())), Entry,
        Taken);

    CgFunction MF(Ctx, F);
    X86CgLowering Lowering(MF);
    const std::string Dump = dumpCg(MF);
    EXPECT_GE(countOpcode(MF, X86::SETCCr), 2u) << Dump;
    EXPECT_GE(countOpcode(MF, X86::TEST32rr) + countOpcode(MF, X86::TEST8rr) +
                  countOpcode(MF, X86::AND8rr) + countOpcode(MF, X86::OR8rr),
              1u)
        << Dump;
    expectOneJcc(MF, X86::COND_NE, 2, Dump);
    finishLitmus(F);
  }
}

namespace {

struct SetccChainRegs {
  CgRegister Setcc;
  CgRegister Wide;
};

enum class PeepTestKind {
  RrSame,  // TEST r,r — the foldable form
  RrOther, // TEST r,other — must not fold
  RiMask,  // TEST ri with mask 2 — not a boolean nonzero test
};

// CMP; SETCC; [MOVZX]; TEST; JE — keep this chain contiguous so
// optimizeCmp reaches the TEST/one-use guards. Extra live consumers belong
// in a successor, not between these instructions.
SetccChainRegs buildSetccTestJe(CgFunction &MF, CgBasicBlock &BB,
                                CgBasicBlock &Dest, bool WithMovzx,
                                PeepTestKind Kind = PeepTestKind::RrSame) {
  auto &MRI = MF.getRegInfo();
  const auto &TII = MF.getTargetInstrInfo();
  CgRegister LHS = MRI.createVirtualRegister(&X86::GR32RegClass);
  CgRegister RHS = MRI.createVirtualRegister(&X86::GR32RegClass);
  CgRegister Setcc = MRI.createVirtualRegister(&X86::GR8RegClass);
  CgRegister Wide = MRI.createVirtualRegister(&X86::GR32RegClass);

  SmallVector<CgOperand, 2> CmpOps{
      CgOperand::createRegOperand(LHS, false),
      CgOperand::createRegOperand(RHS, false),
  };
  MF.createCgInstruction(BB, TII.get(X86::CMP32rr), CmpOps);

  SmallVector<CgOperand, 2> SetOps{
      CgOperand::createRegOperand(Setcc, true),
      CgOperand::createImmOperand(X86::COND_L),
  };
  MF.createCgInstruction(BB, TII.get(X86::SETCCr), SetOps);

  CgRegister TestReg = Setcc;
  unsigned TestOpc = X86::TEST8rr;
  const TargetRegisterClass *TestRC = &X86::GR8RegClass;
  if (WithMovzx) {
    MF.createCgInstruction(BB, TII.get(X86::MOVZX32rr8), Setcc, Wide);
    TestReg = Wide;
    TestOpc = X86::TEST32rr;
    TestRC = &X86::GR32RegClass;
  }

  SmallVector<CgOperand, 2> TestOps;
  if (Kind == PeepTestKind::RiMask) {
    TestOpc = WithMovzx ? X86::TEST32ri : X86::TEST8ri;
    TestOps = {CgOperand::createRegOperand(TestReg, false),
               CgOperand::createImmOperand(0x2)};
  } else if (Kind == PeepTestKind::RrOther) {
    CgRegister Other = MRI.createVirtualRegister(TestRC);
    TestOps = {CgOperand::createRegOperand(TestReg, false),
               CgOperand::createRegOperand(Other, false)};
  } else {
    TestOps = {CgOperand::createRegOperand(TestReg, false),
               CgOperand::createRegOperand(TestReg, false)};
  }
  MF.createCgInstruction(BB, TII.get(TestOpc), TestOps);

  SmallVector<CgOperand, 2> JccOps{
      CgOperand::createMBB(&Dest),
      CgOperand::createImmOperand(X86::COND_E),
  };
  MF.createCgInstruction(BB, TII.get(X86::JCC_1), JccOps);
  return {Setcc, WithMovzx ? Wide : CgRegister()};
}

} // namespace

TEST(X86CgPeephole, OptimizeCmpSetccMovzxTestJe) {
  CompileContext Ctx;
  Ctx.initialize();
  MType *I32 = &CompileContext::I32Type;
  MFunction F(Ctx, 0);
  F.setFunctionType(MFunctionType::create(Ctx, *I32, {I32}));
  MBasicBlock *Entry = F.createBasicBlock();
  F.appendBlock(Entry);
  retImm(F, *Entry, I32, 0);

  CgFunction MF(Ctx, F);
  CgBasicBlock *BB0 = MF.createCgBasicBlock();
  CgBasicBlock *BB1 = MF.createCgBasicBlock();
  MF.appendCgBasicBlock(BB0);
  MF.appendCgBasicBlock(BB1);
  buildSetccTestJe(MF, *BB0, *BB1, /*WithMovzx=*/true);

  X86CgPeephole Peep(MF);
  (void)Peep;
  const std::string Dump = dumpCg(MF);
  EXPECT_EQ(countOpcode(MF, X86::SETCCr), 0u) << Dump;
  EXPECT_EQ(countOpcode(MF, X86::MOVZX32rr8), 0u) << Dump;
  EXPECT_EQ(countOpcode(MF, X86::TEST32rr), 0u) << Dump;
  expectOneJcc(MF, X86::COND_GE, 1, Dump);
  finishLitmus(F);
}

TEST(X86CgPeephole, OptimizeCmpSetccTestJe) {
  CompileContext Ctx;
  Ctx.initialize();
  MType *I32 = &CompileContext::I32Type;
  MFunction F(Ctx, 0);
  F.setFunctionType(MFunctionType::create(Ctx, *I32, {I32}));
  MBasicBlock *Entry = F.createBasicBlock();
  F.appendBlock(Entry);
  retImm(F, *Entry, I32, 0);

  CgFunction MF(Ctx, F);
  CgBasicBlock *BB0 = MF.createCgBasicBlock();
  CgBasicBlock *BB1 = MF.createCgBasicBlock();
  MF.appendCgBasicBlock(BB0);
  MF.appendCgBasicBlock(BB1);
  buildSetccTestJe(MF, *BB0, *BB1, /*WithMovzx=*/false);

  X86CgPeephole Peep(MF);
  (void)Peep;
  const std::string Dump = dumpCg(MF);
  EXPECT_EQ(countOpcode(MF, X86::SETCCr), 0u) << Dump;
  EXPECT_EQ(countOpcode(MF, X86::TEST8rr), 0u) << Dump;
  expectOneJcc(MF, X86::COND_GE, 1, Dump);
  finishLitmus(F);
}

TEST(X86CgPeephole, OptimizeCmpKeepsLiveBooleanConsumer) {
  struct Case {
    bool WithMovzx;
    bool ExtraSetcc;
    bool ExtraWide;
    const char *Name;
  };
  // Extra COPY lives in the JE successor so SETCC[+MOVZX]+TEST+JE stay
  // adjacent and the one-use guards are the only reason the peep bails.
  const Case Cases[] = {
      {true, true, false, "extra SETCC use with MOVZX"},
      {true, false, true, "extra MOVZX dest use"},
      {false, true, false, "extra SETCC use without MOVZX"},
  };
  for (const Case &C : Cases) {
    CompileContext Ctx;
    Ctx.initialize();
    MType *I32 = &CompileContext::I32Type;
    MFunction F(Ctx, 0);
    F.setFunctionType(MFunctionType::create(Ctx, *I32, {I32}));
    MBasicBlock *Entry = F.createBasicBlock();
    F.appendBlock(Entry);
    retImm(F, *Entry, I32, 0);

    CgFunction MF(Ctx, F);
    CgBasicBlock *BB0 = MF.createCgBasicBlock();
    CgBasicBlock *BB1 = MF.createCgBasicBlock();
    MF.appendCgBasicBlock(BB0);
    MF.appendCgBasicBlock(BB1);
    SetccChainRegs R = buildSetccTestJe(MF, *BB0, *BB1, C.WithMovzx);
    if (C.ExtraSetcc) {
      addCopyUse(MF, *BB1, R.Setcc, &X86::GR8RegClass);
    }
    if (C.ExtraWide) {
      addCopyUse(MF, *BB1, R.Wide, &X86::GR32RegClass);
    }

    X86CgPeephole Peep(MF);
    (void)Peep;
    const std::string Dump = std::string(C.Name) + "\n" + dumpCg(MF);
    EXPECT_EQ(countOpcode(MF, X86::SETCCr), 1u) << Dump;
    EXPECT_GE(countOpcode(MF, TargetOpcode::COPY), 1u) << Dump;
    if (C.WithMovzx) {
      EXPECT_EQ(countOpcode(MF, X86::MOVZX32rr8), 1u) << Dump;
      EXPECT_EQ(countOpcode(MF, X86::TEST32rr), 1u) << Dump;
    } else {
      EXPECT_EQ(countOpcode(MF, X86::TEST8rr), 1u) << Dump;
    }
    expectOneJcc(MF, X86::COND_E, 1, Dump);
    finishLitmus(F);
  }
}

TEST(X86CgPeephole, OptimizeCmpDoesNotFoldMismatchedTest) {
  struct Case {
    bool WithMovzx;
    PeepTestKind Kind;
    unsigned TestOpc;
    const char *Name;
  };
  const Case Cases[] = {
      {true, PeepTestKind::RrOther, X86::TEST32rr, "TEST32rr r,other"},
      {false, PeepTestKind::RrOther, X86::TEST8rr, "TEST8rr r,other"},
      {true, PeepTestKind::RiMask, X86::TEST32ri, "TEST32ri mask 2"},
      {false, PeepTestKind::RiMask, X86::TEST8ri, "TEST8ri mask 2"},
  };
  for (const Case &C : Cases) {
    CompileContext Ctx;
    Ctx.initialize();
    MType *I32 = &CompileContext::I32Type;
    MFunction F(Ctx, 0);
    F.setFunctionType(MFunctionType::create(Ctx, *I32, {I32}));
    MBasicBlock *Entry = F.createBasicBlock();
    F.appendBlock(Entry);
    retImm(F, *Entry, I32, 0);

    CgFunction MF(Ctx, F);
    CgBasicBlock *BB0 = MF.createCgBasicBlock();
    CgBasicBlock *BB1 = MF.createCgBasicBlock();
    MF.appendCgBasicBlock(BB0);
    MF.appendCgBasicBlock(BB1);
    buildSetccTestJe(MF, *BB0, *BB1, C.WithMovzx, C.Kind);

    X86CgPeephole Peep(MF);
    (void)Peep;
    const std::string Dump = std::string(C.Name) + "\n" + dumpCg(MF);
    EXPECT_EQ(countOpcode(MF, X86::SETCCr), 1u) << Dump;
    EXPECT_EQ(countOpcode(MF, C.TestOpc), 1u) << Dump;
    if (C.WithMovzx) {
      EXPECT_EQ(countOpcode(MF, X86::MOVZX32rr8), 1u) << Dump;
    }
    expectOneJcc(MF, X86::COND_E, 1, Dump);
    finishLitmus(F);
  }
}

namespace {
std::string dumpLeaOpcodes(const CgFunction &MF) {
  std::string S;
  const auto &TII = MF.getTargetInstrInfo();
  for (const CgBasicBlock *BB : MF) {
    for (const CgInstruction &I : *BB) {
      S += TII.getName(I.getOpcode()).str();
      S += '\n';
    }
  }
  return S;
}

struct LeaLoweringFixture {
  CompileContext Ctx;
  MType *I32;
  MType *I64;
  MFunction F;
  MBasicBlock *Entry;

  LeaLoweringFixture()
      : I32(&CompileContext::I32Type), I64(&CompileContext::I64Type), F(Ctx, 0),
        Entry(F.createBasicBlock()) {
    Ctx.initialize();
    F.setFunctionType(MFunctionType::create(Ctx, *I32, {I32, I64}));
    F.appendBlock(Entry);
  }

  ~LeaLoweringFixture() { finishLitmus(F); }

  MInstruction *paramI32() {
    return F.createInstruction<DreadInstruction>(false, *Entry, I32, 0);
  }
  MInstruction *paramI64() {
    return F.createInstruction<DreadInstruction>(false, *Entry, I64, 1);
  }
  MInstruction *iconst32(uint64_t V) {
    return F.createInstruction<COMPILER::ConstantInstruction>(
        false, *Entry, I32, *MConstantInt::get(Ctx, *I32, V));
  }
  MInstruction *iconst64(uint64_t V) {
    return F.createInstruction<COMPILER::ConstantInstruction>(
        false, *Entry, I64, *MConstantInt::get(Ctx, *I64, V));
  }

  std::string lowerRet(MInstruction *V, bool Optimize = false) {
    F.setFunctionType(MFunctionType::create(Ctx, *V->getType(), {I32, I64}));
    F.createInstruction<COMPILER::ReturnInstruction>(true, *Entry, V->getType(),
                                                     V);
    if (Optimize) {
      MIRPeephole Peep;
      Peep.runOnMFunction(F);
    }
    std::string Dump;
    {
      CgFunction MF(Ctx, F);
      X86CgLowering Lowering(MF);
      Dump = dumpLeaOpcodes(MF);
    }
    return Dump;
  }
};

} // namespace

TEST(X86CgLowering, AddImmI32EmitsLEA64_32r) {
  LeaLoweringFixture B;
  auto *Add = B.F.createInstruction<BinaryInstruction>(
      false, *B.Entry, OP_add, B.I32, B.paramI32(), B.iconst32(10408));
  const std::string Dump = B.lowerRet(Add);
  EXPECT_NE(Dump.find("LEA64_32r"), std::string::npos) << Dump;
  EXPECT_EQ(Dump.find("ADD32ri"), std::string::npos) << Dump;
}

TEST(X86CgLowering, AddImmI64StaysAddNotLEA) {
  // LEA does not write CF; i64 add-imm must stay ADD for EVM ADC chains.
  LeaLoweringFixture B;
  auto *Add = B.F.createInstruction<BinaryInstruction>(
      false, *B.Entry, OP_add, B.I64, B.paramI64(), B.iconst64(10408));
  const std::string Dump = B.lowerRet(Add);
  EXPECT_EQ(Dump.find("LEA64r"), std::string::npos) << Dump;
}

TEST(X86CgLowering, SubImmI32EmitsLEA64_32r) {
  LeaLoweringFixture B;
  auto *Sub = B.F.createInstruction<BinaryInstruction>(
      false, *B.Entry, OP_sub, B.I32, B.paramI32(), B.iconst32(8));
  const std::string Dump = B.lowerRet(Sub);
  EXPECT_NE(Dump.find("LEA64_32r"), std::string::npos) << Dump;
}

TEST(X86CgLowering, SubImmI64StaysSubAfterPeephole) {
  LeaLoweringFixture B;
  auto *Sub = B.F.createInstruction<BinaryInstruction>(
      false, *B.Entry, OP_sub, B.I64, B.paramI64(), B.iconst64(1));
  const std::string Dump = B.lowerRet(Sub, true);
  EXPECT_NE(Dump.find("SUB64ri"), std::string::npos) << Dump;
  EXPECT_EQ(Dump.find("ADD64ri"), std::string::npos) << Dump;
  EXPECT_EQ(Dump.find("LEA64r"), std::string::npos) << Dump;
}

TEST(X86CgLowering, ConstantMinusI32DoesNotBecomeLEA) {
  LeaLoweringFixture B;
  auto *Sub = B.F.createInstruction<BinaryInstruction>(
      false, *B.Entry, OP_sub, B.I32, B.iconst32(8), B.paramI32());
  EXPECT_EQ(B.lowerRet(Sub).find("LEA64_32r"), std::string::npos);
}

TEST(X86CgLowering, WrapAddImmStillLEANotDispFold) {
  // 0xfffffff0 + 0x10 wraps to 0 as i32. LEA64_32r preserves wrap;
  // folding into a 64-bit load disp would not.
  LeaLoweringFixture B;
  auto *Add = B.F.createInstruction<BinaryInstruction>(
      false, *B.Entry, OP_add, B.I32, B.paramI32(), B.iconst32(0x10));
  const std::string Dump = B.lowerRet(Add);
  EXPECT_NE(Dump.find("LEA64_32r"), std::string::npos) << Dump;
}

TEST(X86CgLowering, I64AddImmTooWideStaysAdd) {
  LeaLoweringFixture B;
  auto *Add = B.F.createInstruction<BinaryInstruction>(
      false, *B.Entry, OP_add, B.I64, B.paramI64(), B.iconst64(0x100000000ull));
  const std::string Dump = B.lowerRet(Add);
  EXPECT_EQ(Dump.find("LEA64r"), std::string::npos) << Dump;
}
