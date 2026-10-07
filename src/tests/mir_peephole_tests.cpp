// Copyright (C) 2021-2026 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/context.h"
#include "compiler/mir/basic_block.h"
#include "compiler/mir/constants.h"
#include "compiler/mir/function.h"
#include "compiler/mir/instructions.h"
#include "compiler/mir/pass/dead_basicblock_elim.h"
#include "compiler/mir/pass/peephole.h"
#include "compiler/mir/type.h"
#include "runtime/isolation.h"
#include "runtime/runtime.h"
#include "zetaengine.h"

#include "llvm/Support/raw_ostream.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

using namespace COMPILER;
using zen::common::RunMode;
using zen::common::TypedValue;
using zen::common::UntypedValue;
using zen::common::WASMType;
using zen::runtime::Instance;
using zen::runtime::Isolation;
using zen::runtime::Module;
using zen::runtime::Runtime;
using zen::runtime::RuntimeConfig;

namespace {

std::string dumpFunc(const MFunction &F) {
  std::string S;
  llvm::raw_string_ostream OS(S);
  F.print(OS);
  return OS.str();
}

void finishLitmus(MFunction &F) {
#ifdef NDEBUG
  // Release+ASan: skip walking bump IR (LLVM red zones in ~MFunction).
  // Debug: let the normal destructor deallocate so AllocSizes empties.
  F.detachFromPool();
#else
  (void)F;
#endif
}

struct MirBuilder {
  CompileContext Ctx;
  MFunction F;
  MType *I32;
  MBasicBlock *Entry;

  MirBuilder()
      : F(Ctx, 0), I32(&CompileContext::I32Type), Entry(F.createBasicBlock()) {
    MFunctionType *FT = MFunctionType::create(Ctx, *I32, {I32});
    F.setFunctionType(FT);
    F.appendBlock(Entry);
  }

  MInstruction *param() {
    return F.createInstruction<DreadInstruction>(false, *Entry, I32, 0);
  }
  MInstruction *iconst(uint64_t V) {
    return F.createInstruction<ConstantInstruction>(
        false, *Entry, I32, *MConstantInt::get(Ctx, *I32, V));
  }
  MInstruction *unary(Opcode Opc, MInstruction *Op) {
    return F.createInstruction<UnaryInstruction>(false, *Entry, Opc, I32, Op);
  }
  MInstruction *bin(Opcode Opc, MInstruction *L, MInstruction *R) {
    return F.createInstruction<BinaryInstruction>(false, *Entry, Opc, I32, L,
                                                  R);
  }
  MInstruction *cmp(CmpInstruction::Predicate P, MInstruction *L,
                    MInstruction *R) {
    return F.createInstruction<CmpInstruction>(false, *Entry, P, I32, L, R);
  }
  MInstruction *select(MInstruction *C, MInstruction *T, MInstruction *FVal) {
    return F.createInstruction<SelectInstruction>(false, *Entry, I32, C, T,
                                                  FVal);
  }
  void ret(MInstruction *V) {
    F.createInstruction<ReturnInstruction>(true, *Entry, I32, V);
  }
  void run() {
    MIRPeephole Peep;
    Peep.runOnMFunction(F);
    DeadMBasicBlockElim DCE;
    DCE.runOnMFunction(F);
  }

  ~MirBuilder() { finishLitmus(F); }
};

std::vector<uint8_t> loadPeepholeWasm() {
  const char *Path = PEEP_WASM_PATH;
  std::ifstream In(Path, std::ios::binary);
  EXPECT_TRUE(In) << "failed to open " << Path;
  return std::vector<uint8_t>((std::istreambuf_iterator<char>(In)),
                              std::istreambuf_iterator<char>());
}

std::unique_ptr<Runtime> makeRuntime(RunMode Mode, bool DisableMT = false,
                                     bool Lazy = false) {
  RuntimeConfig Cfg;
  Cfg.Mode = Mode;
#ifdef ZEN_ENABLE_BUILTIN_WASI
  Cfg.DisableWASI = true;
#endif
#ifdef ZEN_ENABLE_MULTIPASS_JIT
  Cfg.DisableMultipassMultithread = DisableMT;
  Cfg.NumMultipassThreads = 4;
  Cfg.EnableMultipassLazy = Lazy;
#endif
  return Runtime::newRuntime(Cfg);
}

// Thread-safe: no gtest macros. Instance must not be shared across threads.
bool tryCallI32(Runtime &RT, Instance &Inst, const char *Name, int32_t Arg,
                int32_t &Out) {
  std::vector<TypedValue> Results;
  if (!RT.callWasmFunction(Inst, Name, {std::to_string(Arg)}, Results)) {
    return false;
  }
  if (Inst.hasError() || Results.size() != 1) {
    return false;
  }
  Out = Results[0].Value.I32;
  return true;
}

int32_t callI32(Runtime &RT, Instance &Inst, const char *Name, int32_t Arg) {
  int32_t Out = 0;
  EXPECT_TRUE(tryCallI32(RT, Inst, Name, Arg, Out))
      << (Inst.hasError() ? Inst.getError().getFormattedMessage() : Name);
  return Out;
}

} // namespace

TEST(MIRPeepholeLitmus, CtzEqzFoldsToBitTest) {
  MirBuilder B;
  B.ret(
      B.cmp(CmpInstruction::ICMP_EQ, B.unary(OP_ctz, B.param()), B.iconst(0)));
  B.run();
  const std::string Dump = dumpFunc(B.F);
  EXPECT_EQ(Dump.find("ctz"), std::string::npos) << Dump;
  EXPECT_NE(Dump.find("and"), std::string::npos) << Dump;
  EXPECT_NE(Dump.find("ine"), std::string::npos) << Dump;
}

TEST(MIRPeepholeLitmus, ClzEqzFoldsToSignTest) {
  MirBuilder B;
  B.ret(
      B.cmp(CmpInstruction::ICMP_EQ, B.unary(OP_clz, B.param()), B.iconst(0)));
  B.run();
  const std::string Dump = dumpFunc(B.F);
  EXPECT_EQ(Dump.find("clz"), std::string::npos) << Dump;
  EXPECT_NE(Dump.find("islt"), std::string::npos) << Dump;
}

TEST(MIRPeepholeLitmus, CtzEqFourDoesNotFold) {
  MirBuilder B;
  B.ret(
      B.cmp(CmpInstruction::ICMP_EQ, B.unary(OP_ctz, B.param()), B.iconst(4)));
  B.run();
  const std::string Dump = dumpFunc(B.F);
  EXPECT_NE(Dump.find("ctz"), std::string::npos) << Dump;
}

TEST(MIRPeepholeLitmus, ClzNeZeroFoldsToSge) {
  MirBuilder B;
  B.ret(
      B.cmp(CmpInstruction::ICMP_NE, B.unary(OP_clz, B.param()), B.iconst(0)));
  B.run();
  const std::string Dump = dumpFunc(B.F);
  EXPECT_EQ(Dump.find("clz"), std::string::npos) << Dump;
  EXPECT_NE(Dump.find("isge"), std::string::npos) << Dump;
}

TEST(MIRPeepholeLitmus, SelectICmpFoldsToCond) {
  MirBuilder B;
  auto *Sel = B.select(B.param(), B.iconst(7), B.iconst(3));
  B.ret(B.cmp(CmpInstruction::ICMP_EQ, Sel, B.iconst(7)));
  B.run();
  const std::string Dump = dumpFunc(B.F);
  EXPECT_EQ(Dump.find("select"), std::string::npos) << Dump;
  EXPECT_NE(Dump.find("ine"), std::string::npos) << Dump;
}

TEST(MIRPeepholeLitmus, SelectICmpOtherConstIsZero) {
  MirBuilder B;
  auto *Sel = B.select(B.param(), B.iconst(7), B.iconst(3));
  B.ret(B.cmp(CmpInstruction::ICMP_EQ, Sel, B.iconst(9)));
  B.run();
  const std::string Dump = dumpFunc(B.F);
  EXPECT_NE(Dump.find("const.i32 0"), std::string::npos) << Dump;
}

TEST(MIRPeepholeLitmus, SelectNonConstArmDoesNotFold) {
  MirBuilder B;
  auto *Sel = B.select(B.param(), B.param(), B.iconst(3));
  B.ret(B.cmp(CmpInstruction::ICMP_EQ, Sel, B.iconst(3)));
  B.run();
  const std::string Dump = dumpFunc(B.F);
  EXPECT_NE(Dump.find("select"), std::string::npos) << Dump;
}

TEST(MIRPeepholeLitmus, AlgebraIdentities) {
  {
    MirBuilder B;
    B.ret(B.bin(OP_add, B.param(), B.iconst(0)));
    B.run();
    EXPECT_EQ(dumpFunc(B.F).find("add"), std::string::npos) << dumpFunc(B.F);
  }
  {
    MirBuilder B;
    auto *X = B.param();
    B.ret(B.bin(OP_sub, X, X));
    B.run();
    EXPECT_NE(dumpFunc(B.F).find("const.i32 0"), std::string::npos)
        << dumpFunc(B.F);
  }
  {
    MirBuilder B;
    B.ret(B.bin(OP_mul, B.param(), B.iconst(0)));
    B.run();
    EXPECT_NE(dumpFunc(B.F).find("const.i32 0"), std::string::npos)
        << dumpFunc(B.F);
  }
  {
    MirBuilder B;
    auto *X = B.param();
    B.ret(B.bin(OP_xor, X, X));
    B.run();
    EXPECT_NE(dumpFunc(B.F).find("const.i32 0"), std::string::npos)
        << dumpFunc(B.F);
  }
  {
    MirBuilder B;
    B.ret(B.bin(OP_shl, B.param(), B.iconst(0)));
    B.run();
    EXPECT_EQ(dumpFunc(B.F).find("shl"), std::string::npos) << dumpFunc(B.F);
  }
  {
    MirBuilder B;
    B.ret(B.bin(OP_add, B.iconst(2), B.iconst(3)));
    B.run();
    EXPECT_NE(dumpFunc(B.F).find("const.i32 5"), std::string::npos)
        << dumpFunc(B.F);
  }
  {
    MirBuilder B;
    B.ret(B.unary(OP_not, B.unary(OP_not, B.param())));
    B.run();
    EXPECT_EQ(dumpFunc(B.F).find("not"), std::string::npos) << dumpFunc(B.F);
  }
}

TEST(PhiIncomingLayout, RemoveIncomingKeepsRemainingPairs) {
  CompileContext Ctx;
  MType *I32 = &CompileContext::I32Type;
  MFunction F(Ctx, 0);
  F.setFunctionType(MFunctionType::create(Ctx, *I32, {I32}));
  MBasicBlock *Entry = F.createBasicBlock();
  MBasicBlock *B0 = F.createBasicBlock();
  MBasicBlock *B1 = F.createBasicBlock();
  MBasicBlock *B2 = F.createBasicBlock();
  F.appendBlock(Entry);
  F.appendBlock(B0);
  F.appendBlock(B1);
  F.appendBlock(B2);

  auto makeConst = [&](uint64_t V) {
    return F.createInstruction<ConstantInstruction>(
        false, *Entry, I32, *MConstantInt::get(Ctx, *I32, V));
  };
  MInstruction *V0 = makeConst(10);
  MInstruction *V1 = makeConst(20);
  MInstruction *V2 = makeConst(30);

  {
    PhiInstruction::Incoming Inc3[] = {{B0, V0}, {B1, V1}, {B2, V2}};
    auto *Phi = F.createInstruction<PhiInstruction>(
        false, *Entry, I32, llvm::ArrayRef<PhiInstruction::Incoming>(Inc3));
    Phi->removeIncoming(1);
    ASSERT_EQ(Phi->getNumIncoming(), 2u);
    EXPECT_EQ(Phi->getIncomingBlock(0), B0);
    EXPECT_EQ(Phi->getIncomingValue(0), V0);
    EXPECT_EQ(Phi->getIncomingBlock(1), B2);
    EXPECT_EQ(Phi->getIncomingValue(1), V2);
  }
  {
    PhiInstruction::Incoming Inc2[] = {{B0, V0}, {B1, V1}};
    auto *Phi = F.createInstruction<PhiInstruction>(
        false, *Entry, I32, llvm::ArrayRef<PhiInstruction::Incoming>(Inc2));
    Phi->removeIncoming(1);
    ASSERT_EQ(Phi->getNumIncoming(), 1u);
    EXPECT_EQ(Phi->getIncomingBlock(0), B0);
    EXPECT_EQ(Phi->getIncomingValue(0), V0);
  }
  {
    PhiInstruction::Incoming Inc3[] = {{B0, V0}, {B1, V1}, {B2, V2}};
    auto *Phi = F.createInstruction<PhiInstruction>(
        false, *Entry, I32, llvm::ArrayRef<PhiInstruction::Incoming>(Inc3));
    Phi->removeIncoming(0);
    ASSERT_EQ(Phi->getNumIncoming(), 2u);
    EXPECT_EQ(Phi->getIncomingBlock(0), B1);
    EXPECT_EQ(Phi->getIncomingValue(0), V1);
    EXPECT_EQ(Phi->getIncomingBlock(1), B2);
    EXPECT_EQ(Phi->getIncomingValue(1), V2);
  }
  finishLitmus(F);
}

TEST(MIRPeepholeLitmus, ConstBrIfStripsPhiOnLiveDropTarget) {
  CompileContext Ctx;
  MType *I32 = &CompileContext::I32Type;
  MFunction F(Ctx, 0);
  F.setFunctionType(MFunctionType::create(Ctx, *I32, {I32}));
  MBasicBlock *Entry = F.createBasicBlock();
  MBasicBlock *Left = F.createBasicBlock();
  MBasicBlock *Merge = F.createBasicBlock();
  F.appendBlock(Entry);
  F.appendBlock(Left);
  F.appendBlock(Merge);

  auto *Zero = F.createInstruction<ConstantInstruction>(
      false, *Entry, I32, *MConstantInt::get(Ctx, *I32, 0));
  auto *FromEntry = F.createInstruction<ConstantInstruction>(
      false, *Entry, I32, *MConstantInt::get(Ctx, *I32, 1));
  F.createInstruction<BrIfInstruction>(true, *Entry, Ctx, Zero, Merge, Left);
  Entry->addSuccessor(Merge);
  Entry->addSuccessor(Left);

  auto *FromLeft = F.createInstruction<ConstantInstruction>(
      false, *Left, I32, *MConstantInt::get(Ctx, *I32, 42));
  F.createInstruction<BrInstruction>(true, *Left, Ctx, Merge);
  Left->addSuccessor(Merge);

  PhiInstruction::Incoming Inc[] = {{Entry, FromEntry}, {Left, FromLeft}};
  auto *Phi = F.createInstruction<PhiInstruction>(
      false, *Merge, I32, llvm::ArrayRef<PhiInstruction::Incoming>(Inc));
  Merge->addStatement(Phi);
  F.createInstruction<ReturnInstruction>(true, *Merge, I32, Phi);

  MIRPeephole Peep;
  Peep.runOnMFunction(F);

  ASSERT_EQ(Phi->getNumIncoming(), 1u);
  EXPECT_EQ(Phi->getIncomingBlock(0), Left);
  EXPECT_EQ(Phi->getIncomingValue(0), FromLeft);
  EXPECT_EQ(dumpFunc(F).find("br_if"), std::string::npos) << dumpFunc(F);
  finishLitmus(F);
}

TEST(MIRPeepholeLitmus, ConstZeroBrIfWithoutFalseFallsThrough) {
  CompileContext Ctx;
  MType *I32 = &CompileContext::I32Type;
  MFunction F(Ctx, 0);
  F.setFunctionType(MFunctionType::create(Ctx, *I32, {I32}));
  MBasicBlock *Entry = F.createBasicBlock();
  MBasicBlock *Trap = F.createBasicBlock();
  F.appendBlock(Entry);
  F.appendBlock(Trap);

  auto *Zero = F.createInstruction<ConstantInstruction>(
      false, *Entry, I32, *MConstantInt::get(Ctx, *I32, 0));
  F.createInstruction<BrIfInstruction>(true, *Entry, Ctx, Zero, Trap);
  Entry->addSuccessor(Trap);
  auto *Seven = F.createInstruction<ConstantInstruction>(
      false, *Entry, I32, *MConstantInt::get(Ctx, *I32, 7));
  F.createInstruction<ReturnInstruction>(true, *Entry, I32, Seven);

  auto *Z = F.createInstruction<ConstantInstruction>(
      false, *Trap, I32, *MConstantInt::get(Ctx, *I32, 0));
  F.createInstruction<ReturnInstruction>(true, *Trap, I32, Z);

  MIRPeephole Peep;
  Peep.runOnMFunction(F);
  DeadMBasicBlockElim DCE;
  DCE.runOnMFunction(F);

  const std::string Dump = dumpFunc(F);
  EXPECT_EQ(Dump.find("br_if"), std::string::npos) << Dump;
  EXPECT_NE(Dump.find("const.i32 7"), std::string::npos) << Dump;
  EXPECT_TRUE(Trap->empty()) << Dump;
  finishLitmus(F);
}

TEST(MIRPeepholeLitmus, ConstBrIfBecomesUncondAndKillsDeadBlock) {
  CompileContext Ctx;
  MType *I32 = &CompileContext::I32Type;
  MFunction F(Ctx, 0);
  F.setFunctionType(MFunctionType::create(Ctx, *I32, {I32}));
  MBasicBlock *BB0 = F.createBasicBlock();
  MBasicBlock *BB1 = F.createBasicBlock();
  MBasicBlock *BB2 = F.createBasicBlock();
  MBasicBlock *BB3 = F.createBasicBlock();
  F.appendBlock(BB0);
  F.appendBlock(BB1);
  F.appendBlock(BB2);
  F.appendBlock(BB3);

  auto *One = F.createInstruction<ConstantInstruction>(
      false, *BB0, I32, *MConstantInt::get(Ctx, *I32, 1));
  F.createInstruction<BrIfInstruction>(true, *BB0, Ctx, One, BB1, BB2);
  BB0->addSuccessor(BB1);
  BB0->addSuccessor(BB2);

  auto *X1 = F.createInstruction<DreadInstruction>(false, *BB1, I32, 0);
  auto *C1 = F.createInstruction<ConstantInstruction>(
      false, *BB1, I32, *MConstantInt::get(Ctx, *I32, 1));
  auto *Add1 =
      F.createInstruction<BinaryInstruction>(false, *BB1, OP_add, I32, X1, C1);
  F.createInstruction<DassignInstruction>(true, *BB1, &Ctx.VoidType, Add1, 0);
  F.createInstruction<BrInstruction>(true, *BB1, Ctx, BB3);
  BB1->addSuccessor(BB3);

  auto *X2 = F.createInstruction<DreadInstruction>(false, *BB2, I32, 0);
  auto *C2 = F.createInstruction<ConstantInstruction>(
      false, *BB2, I32, *MConstantInt::get(Ctx, *I32, 2));
  auto *Add2 =
      F.createInstruction<BinaryInstruction>(false, *BB2, OP_add, I32, X2, C2);
  F.createInstruction<DassignInstruction>(true, *BB2, &Ctx.VoidType, Add2, 0);
  F.createInstruction<BrInstruction>(true, *BB2, Ctx, BB3);
  BB2->addSuccessor(BB3);

  auto *X3 = F.createInstruction<DreadInstruction>(false, *BB3, I32, 0);
  F.createInstruction<ReturnInstruction>(true, *BB3, I32, X3);

  MIRPeephole Peep;
  Peep.runOnMFunction(F);
  DeadMBasicBlockElim DCE;
  DCE.runOnMFunction(F);

  const std::string Dump = dumpFunc(F);
  EXPECT_EQ(Dump.find("br_if"), std::string::npos) << Dump;
  EXPECT_NE(Dump.find("br @1"), std::string::npos) << Dump;
  EXPECT_TRUE(BB2->empty()) << Dump;
  finishLitmus(F);
}

TEST(MIRPeepholeWasm, MultipassMatchesExpected) {
  auto Bytes = loadPeepholeWasm();
  ASSERT_FALSE(Bytes.empty());
  auto RT = makeRuntime(RunMode::MultipassMode);
  ASSERT_NE(RT, nullptr);
  auto ModRet = RT->loadModule("peep", Bytes.data(), Bytes.size());
  ASSERT_TRUE(ModRet) << ModRet.getError().getFormattedMessage();
  Isolation *Iso = RT->createManagedIsolation();
  ASSERT_NE(Iso, nullptr);
  auto InstRet = Iso->createInstance(**ModRet);
  ASSERT_TRUE(InstRet) << InstRet.getError().getFormattedMessage();
  Instance *Inst = *InstRet;

  EXPECT_EQ(callI32(*RT, *Inst, "ctz_eqz", 0), 0);
  EXPECT_EQ(callI32(*RT, *Inst, "ctz_eqz", 1), 1);
  EXPECT_EQ(callI32(*RT, *Inst, "ctz_eqz", 2), 0);
  EXPECT_EQ(callI32(*RT, *Inst, "ctz_eqz", -1), 1);
  EXPECT_EQ(callI32(*RT, *Inst, "clz_eqz", static_cast<int32_t>(0x80000000u)),
            1);
  EXPECT_EQ(callI32(*RT, *Inst, "clz_eqz", 1), 0);
  EXPECT_EQ(callI32(*RT, *Inst, "ctz_eq4", 16), 1);
  EXPECT_EQ(callI32(*RT, *Inst, "ctz_eq4", 1), 0);
  EXPECT_EQ(callI32(*RT, *Inst, "select_eq_true", 0), 0);
  EXPECT_EQ(callI32(*RT, *Inst, "select_eq_true", 1), 1);
  EXPECT_EQ(callI32(*RT, *Inst, "add0", 42), 42);
  EXPECT_EQ(callI32(*RT, *Inst, "const_if_true", 10), 11);
  EXPECT_EQ(callI32(*RT, *Inst, "const_if_false", 10), 12);
  EXPECT_EQ(callI32(*RT, *Inst, "f8", 9), 9);
  EXPECT_EQ(callI32(*RT, *Inst, "f9", 9), 9);
  EXPECT_EQ(callI32(*RT, *Inst, "f12", 0), 1);
  EXPECT_EQ(callI32(*RT, *Inst, "f12", 16), 1);
  EXPECT_EQ(callI32(*RT, *Inst, "f13", 0), 1);
  EXPECT_EQ(callI32(*RT, *Inst, "f13", 1), 1);
  EXPECT_EQ(callI32(*RT, *Inst, "f15", 0), 5);
  EXPECT_EQ(callI32(*RT, *Inst, "const_br_if_fallthrough", 0), 1);
}

#ifdef ZEN_ENABLE_SINGLEPASS_JIT
TEST(MIRPeepholeWasm, SinglepassMatchesMultipass) {
  auto Bytes = loadPeepholeWasm();
  ASSERT_FALSE(Bytes.empty());
  auto RTM = makeRuntime(RunMode::MultipassMode);
  auto RTS = makeRuntime(RunMode::SinglepassMode);
  ASSERT_NE(RTM, nullptr);
  ASSERT_NE(RTS, nullptr);
  auto ModM = RTM->loadModule("peepm", Bytes.data(), Bytes.size());
  auto ModS = RTS->loadModule("peeps", Bytes.data(), Bytes.size());
  ASSERT_TRUE(ModM);
  ASSERT_TRUE(ModS);
  Isolation *IsoM = RTM->createManagedIsolation();
  Isolation *IsoS = RTS->createManagedIsolation();
  auto InstM = IsoM->createInstance(**ModM);
  auto InstS = IsoS->createInstance(**ModS);
  ASSERT_TRUE(InstM);
  ASSERT_TRUE(InstS);

  const int32_t Inputs[] = {0,  1,  2,  4,
                            16, -1, 42, static_cast<int32_t>(0x80000000u)};
  const char *Fns[] = {"ctz_eqz", "clz_eqz", "ctz_eq4", "select_eq_true",
                       "add0",    "f3",      "f4",      "f8",
                       "f9",      "f12",     "f13",     "f14"};
  for (const char *Fn : Fns) {
    for (int32_t X : Inputs) {
      EXPECT_EQ(callI32(*RTM, **InstM, Fn, X), callI32(*RTS, **InstS, Fn, X))
          << Fn << " x=" << X;
    }
  }
}
#endif

TEST(MIRPeepholeConcurrent, ParallelCompileAndExecute) {
  auto Bytes = loadPeepholeWasm();
  ASSERT_FALSE(Bytes.empty());
  constexpr int kThreads = 8;
  constexpr int kIters = 40;
  std::atomic<int> Failures{0};
  std::vector<std::thread> Threads;
  Threads.reserve(kThreads);
  for (int T = 0; T < kThreads; ++T) {
    Threads.emplace_back([&, T] {
      for (int I = 0; I < kIters; ++I) {
        auto RT = makeRuntime(RunMode::MultipassMode, /*DisableMT=*/false);
        if (!RT) {
          Failures++;
          return;
        }
        auto ModRet =
            RT->loadModule("peep" + std::to_string(T) + "_" + std::to_string(I),
                           Bytes.data(), Bytes.size());
        if (!ModRet) {
          Failures++;
          return;
        }
        Isolation *Iso = RT->createManagedIsolation();
        auto InstRet = Iso->createInstance(**ModRet);
        if (!InstRet) {
          Failures++;
          return;
        }
        Instance *Inst = *InstRet;
        int32_t V = 0;
        const int32_t Sign = static_cast<int32_t>(0x80000000u);
        if (!tryCallI32(*RT, *Inst, "ctz_eqz", 1, V) || V != 1 ||
            !tryCallI32(*RT, *Inst, "clz_eqz", Sign, V) || V != 1 ||
            !tryCallI32(*RT, *Inst, "select_eq_true", 1, V) || V != 1 ||
            !tryCallI32(*RT, *Inst, "add0", 7, V) || V != 7 ||
            !tryCallI32(*RT, *Inst, "const_if_true", 3, V) || V != 4 ||
            !tryCallI32(*RT, *Inst, "const_if_false", 3, V) || V != 5 ||
            !tryCallI32(*RT, *Inst, "f8", 9, V) || V != 9 ||
            !tryCallI32(*RT, *Inst, "f9", 9, V) || V != 9 ||
            !tryCallI32(*RT, *Inst, "f12", 16, V) || V != 1 ||
            !tryCallI32(*RT, *Inst, "f13", 0, V) || V != 1 ||
            !tryCallI32(*RT, *Inst, "f15", 0, V) || V != 5 ||
            !tryCallI32(*RT, *Inst, "const_br_if_fallthrough", 0, V) ||
            V != 1) {
          Failures++;
          return;
        }
      }
    });
  }
  for (auto &Th : Threads) {
    Th.join();
  }
  EXPECT_EQ(Failures.load(), 0);
}

#ifdef ZEN_ENABLE_MULTIPASS_JIT
// Per-runtime lazy compile (do not share one Instance across threads).
TEST(MIRPeepholeConcurrent, ParallelLazyCompileAndExecute) {
  auto Bytes = loadPeepholeWasm();
  ASSERT_FALSE(Bytes.empty());
  constexpr int kThreads = 8;
  constexpr int kIters = 20;
  std::atomic<int> Failures{0};
  std::vector<std::thread> Threads;
  Threads.reserve(kThreads);
  for (int T = 0; T < kThreads; ++T) {
    Threads.emplace_back([&, T] {
      for (int I = 0; I < kIters; ++I) {
        auto RT = makeRuntime(RunMode::MultipassMode, /*DisableMT=*/false,
                              /*Lazy=*/true);
        if (!RT) {
          Failures++;
          return;
        }
        auto ModRet = RT->loadModule("lazypeep" + std::to_string(T) + "_" +
                                         std::to_string(I),
                                     Bytes.data(), Bytes.size());
        if (!ModRet) {
          Failures++;
          return;
        }
        Isolation *Iso = RT->createManagedIsolation();
        auto InstRet = Iso->createInstance(**ModRet);
        if (!InstRet) {
          Failures++;
          return;
        }
        Instance *Inst = *InstRet;
        int32_t V = 0;
        const char *Fns[] = {"f0",  "f1",  "f2",  "f3", "f4",  "f5",
                             "f6",  "f7",  "f8",  "f9", "f10", "f11",
                             "f12", "f13", "f14", "f15"};
        for (const char *Fn : Fns) {
          if (!tryCallI32(*RT, *Inst, Fn, 1, V)) {
            Failures++;
            return;
          }
        }
        if (!tryCallI32(*RT, *Inst, "f15", 0, V) || V != 5 ||
            !tryCallI32(*RT, *Inst, "f8", 11, V) || V != 11 ||
            !tryCallI32(*RT, *Inst, "f13", 0, V) || V != 1) {
          Failures++;
          return;
        }
      }
    });
  }
  for (auto &Th : Threads) {
    Th.join();
  }
  EXPECT_EQ(Failures.load(), 0);
}

TEST(MIRPeepholeConcurrent, LazyJitWarmupThenReplay) {
  auto Bytes = loadPeepholeWasm();
  ASSERT_FALSE(Bytes.empty());
  auto RT = makeRuntime(RunMode::MultipassMode, /*DisableMT=*/false,
                        /*Lazy=*/true);
  ASSERT_NE(RT, nullptr);
  auto ModRet = RT->loadModule("peeplazy", Bytes.data(), Bytes.size());
  ASSERT_TRUE(ModRet) << ModRet.getError().getFormattedMessage();
  Isolation *Iso = RT->createManagedIsolation();
  auto InstRet = Iso->createInstance(**ModRet);
  ASSERT_TRUE(InstRet) << InstRet.getError().getFormattedMessage();
  Instance *Inst = *InstRet;

  const char *Fns[] = {"f0", "f1", "f2",  "f3",  "f4",  "f5",  "f6",  "f7",
                       "f8", "f9", "f10", "f11", "f12", "f13", "f14", "f15"};
  for (const char *Fn : Fns) {
    (void)callI32(*RT, *Inst, Fn, 1);
  }
  ASSERT_FALSE(Inst->hasError()) << Inst->getError().getFormattedMessage();

  constexpr int kIters = 200;
  for (int I = 0; I < kIters; ++I) {
    const char *Fn = Fns[static_cast<unsigned>(I) % 16];
    int32_t Arg = (I & 1) ? 1 : static_cast<int32_t>(0x80000000u);
    int32_t Got = callI32(*RT, *Inst, Fn, Arg);
    if (std::string(Fn) == "f15") {
      EXPECT_EQ(Got, 5);
    }
    if (std::string(Fn) == "f8" || std::string(Fn) == "f9") {
      EXPECT_EQ(Got, Arg);
    }
    if (std::string(Fn) == "f12" || std::string(Fn) == "f13") {
      EXPECT_EQ(Got, 1);
    }
  }
  EXPECT_FALSE(Inst->hasError()) << Inst->getError().getFormattedMessage();
}
#endif

TEST(MIRPeepholePerf, Microbenchmarks) {
  auto Bytes = loadPeepholeWasm();
  ASSERT_FALSE(Bytes.empty());
  auto RT = makeRuntime(RunMode::MultipassMode, /*DisableMT=*/true);
  ASSERT_NE(RT, nullptr);
  auto ModRet = RT->loadModule("peepbench", Bytes.data(), Bytes.size());
  ASSERT_TRUE(ModRet);
  Isolation *Iso = RT->createManagedIsolation();
  auto InstRet = Iso->createInstance(**ModRet);
  ASSERT_TRUE(InstRet);
  Instance *Inst = *InstRet;

  const char *Names[] = {"bench_ctz_eqz",  "bench_select", "bench_algebra",
                         "bench_const_br", "bench_mixed",  "bitmix"};
  constexpr int32_t kIters = 2000000;
  std::printf("\nMIR peephole microbench (multipass, %d loop iters, 3 runs)\n",
              kIters);
  for (const char *Name : Names) {
    // Warmup
    (void)callI32(*RT, *Inst, Name, 1000);
    double BestMs = 1e100;
    double SumMs = 0;
    for (int R = 0; R < 3; ++R) {
      auto T0 = std::chrono::steady_clock::now();
      int32_t Ret = callI32(*RT, *Inst, Name, kIters);
      auto T1 = std::chrono::steady_clock::now();
      double Ms = std::chrono::duration<double, std::milli>(T1 - T0).count();
      BestMs = std::min(BestMs, Ms);
      SumMs += Ms;
      (void)Ret;
    }
    std::printf("  %-16s  best=%.3f ms  mean=%.3f ms\n", Name, BestMs,
                SumMs / 3.0);
  }
}
