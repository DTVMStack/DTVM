// Copyright (C) 2021-2026 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/context.h"
#include "compiler/mir/basic_block.h"
#include "compiler/mir/constants.h"
#include "compiler/mir/function.h"
#include "compiler/mir/instructions.h"
#include "compiler/mir/opcode.h"
#include "compiler/mir/pass/dead_basicblock_elim.h"
#include "compiler/mir/pass/peephole.h"
#include "compiler/mir/type.h"
#include "runtime/isolation.h"
#include "runtime/module.h"
#include "runtime/runtime.h"
#include "zetaengine.h"

#include "llvm/ADT/APFloat.h"
#include "llvm/Support/raw_ostream.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
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

bool tryCallNoArg(Runtime &RT, Instance &Inst, const char *Name, int32_t &Out) {
  std::vector<TypedValue> Results;
  if (!RT.callWasmFunction(Inst, Name, {}, Results)) {
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

int32_t callI32NoArg(Runtime &RT, Instance &Inst, const char *Name) {
  std::vector<TypedValue> Results;
  const bool Ok = RT.callWasmFunction(Inst, Name, {}, Results);
  EXPECT_TRUE(Ok) << (Inst.hasError() ? Inst.getError().getFormattedMessage()
                                      : Name);
  if (!Ok || Results.size() != 1) {
    EXPECT_EQ(Results.size(), 1u);
    return 0;
  }
  return Results[0].Value.I32;
}

bool codeHasDiv(const uint8_t *P, size_t N) {
  for (size_t I = 0; I + 1 < N; ++I) {
    size_t J = I;
    if (P[J] >= 0x40 && P[J] <= 0x4f) {
      ++J;
      if (J + 1 >= N) {
        break;
      }
    }
    if (P[J] == 0xf7) {
      const unsigned Reg = (P[J + 1] >> 3) & 7u;
      if (Reg == 6 || Reg == 7) {
        return true;
      }
    }
  }
  return false;
}

bool codeHasAndImm7(const uint8_t *P, size_t N) {
  for (size_t I = 0; I + 2 < N; ++I) {
    if (P[I] == 0x83 && ((P[I + 1] >> 3) & 7u) == 4 && P[I + 2] == 7) {
      return true;
    }
    if (P[I] == 0x25 && I + 4 < N && P[I + 1] == 7 && P[I + 2] == 0 &&
        P[I + 3] == 0 && P[I + 4] == 0) {
      return true;
    }
    if (P[I] == 0x81 && ((P[I + 1] >> 3) & 7u) == 4 && I + 5 < N &&
        P[I + 2] == 7 && P[I + 3] == 0 && P[I + 4] == 0 && P[I + 5] == 0) {
      return true;
    }
  }
  return false;
}

bool codeHasShrImm3(const uint8_t *P, size_t N) {
  for (size_t I = 0; I + 2 < N; ++I) {
    if (P[I] == 0xc1 && ((P[I + 1] >> 3) & 7u) == 5 && P[I + 2] == 3) {
      return true;
    }
  }
  return false;
}

const uint8_t *jitFuncBytes(const zen::runtime::Module &Mod, const char *Name,
                            size_t &Len) {
  uint32_t FuncIdx = 0;
  if (!Mod.getExportFunc(Name, FuncIdx)) {
    return nullptr;
  }
  const auto *CE = Mod.getCodeEntry(FuncIdx);
  if (CE == nullptr || CE->JITCodePtr == nullptr) {
    return nullptr;
  }
  const auto *P = CE->JITCodePtr;
  const auto *Base = static_cast<const uint8_t *>(Mod.getJITCode());
  const auto *End = Base + Mod.getJITCodeSize();
  const uint8_t *Next = End;
  const uint32_t Imports = Mod.getNumImportFunctions();
  for (uint32_t I = 0; I < Mod.getNumInternalFunctions(); ++I) {
    const auto *Other = Mod.getCodeEntry(Imports + I);
    if (Other != nullptr && Other->JITCodePtr > P && Other->JITCodePtr < Next) {
      Next = Other->JITCodePtr;
    }
  }
  Len = static_cast<size_t>(Next - P);
  return P;
}

bool tryCallF64(Runtime &RT, Instance &Inst, const char *Name, int32_t Arg,
                double &Out) {
  std::vector<TypedValue> Results;
  if (!RT.callWasmFunction(Inst, Name, {std::to_string(Arg)}, Results)) {
    return false;
  }
  if (Inst.hasError() || Results.size() != 1) {
    return false;
  }
  Out = Results[0].Value.F64;
  return true;
}

double callF64(Runtime &RT, Instance &Inst, const char *Name, int32_t Arg) {
  double Out = 0.0;
  EXPECT_TRUE(tryCallF64(RT, Inst, Name, Arg, Out))
      << (Inst.hasError() ? Inst.getError().getFormattedMessage() : Name);
  return Out;
}

// NaN comparisons with `>` are false, so `abs(D-2)>eps` would accept NaN.
bool isCloseToTwo(double D) {
  return std::isfinite(D) && std::abs(D - 2.0) <= 1e-6;
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

TEST(MIRPeepholeLitmus, URemPow2FoldsToAnd) {
  MirBuilder B;
  B.ret(B.bin(OP_urem, B.param(), B.iconst(8)));
  B.run();
  const std::string Dump = dumpFunc(B.F);
  EXPECT_EQ(Dump.find("urem"), std::string::npos) << Dump;
  EXPECT_NE(Dump.find("and"), std::string::npos) << Dump;
  EXPECT_NE(Dump.find("const.i32 7"), std::string::npos) << Dump;
}

TEST(MIRPeepholeLitmus, UDivPow2FoldsToUShr) {
  MirBuilder B;
  B.ret(B.bin(OP_udiv, B.param(), B.iconst(8)));
  B.run();
  const std::string Dump = dumpFunc(B.F);
  EXPECT_EQ(Dump.find("udiv"), std::string::npos) << Dump;
  EXPECT_NE(Dump.find("ushr"), std::string::npos) << Dump;
  EXPECT_NE(Dump.find("const.i32 3"), std::string::npos) << Dump;
}

TEST(MIRPeepholeLitmus, UDivByOneReturnsOperand) {
  MirBuilder B;
  B.ret(B.bin(OP_udiv, B.param(), B.iconst(1)));
  B.run();
  const std::string Dump = dumpFunc(B.F);
  EXPECT_EQ(Dump.find("udiv"), std::string::npos) << Dump;
  EXPECT_EQ(Dump.find("ushr"), std::string::npos) << Dump;
  EXPECT_NE(Dump.find("return $0"), std::string::npos) << Dump;
}

TEST(MIRPeepholeLitmus, URemByOneIsZero) {
  MirBuilder B;
  B.ret(B.bin(OP_urem, B.param(), B.iconst(1)));
  B.run();
  const std::string Dump = dumpFunc(B.F);
  EXPECT_EQ(Dump.find("urem"), std::string::npos) << Dump;
  EXPECT_NE(Dump.find("const.i32 0"), std::string::npos) << Dump;
}

TEST(MIRPeepholeLitmus, URemByOneKeepsNestedDivByZero) {
  MirBuilder B;
  auto *Inner = B.bin(OP_udiv, B.param(), B.iconst(0));
  B.ret(B.bin(OP_urem, Inner, B.iconst(1)));
  B.run();
  const std::string Dump = dumpFunc(B.F);
  EXPECT_NE(Dump.find("udiv"), std::string::npos) << Dump;
  EXPECT_EQ(Dump.find("return const.i32 0"), std::string::npos)
      << "must not replace trapping dividend with a zero: " << Dump;
}

TEST(MIRPeepholeLitmus, URemByOneKeepsNestedCall) {
  MirBuilder B;
  llvm::ArrayRef<MInstruction *> NoArgs;
  auto *Call = B.F.createInstruction<CallInstruction>(false, *B.Entry, B.I32,
                                                      0u, NoArgs);
  B.ret(B.bin(OP_urem, Call, B.iconst(1)));
  B.run();
  const std::string Dump = dumpFunc(B.F);
  EXPECT_NE(Dump.find("call"), std::string::npos) << Dump;
}

TEST(MIRPeepholeLitmus, URemByOneKeepsNestedLoad) {
  MirBuilder B;
  auto *Ld =
      B.F.createInstruction<LoadInstruction>(false, *B.Entry, B.I32, B.param());
  B.ret(B.bin(OP_urem, Ld, B.iconst(1)));
  B.run();
  const std::string Dump = dumpFunc(B.F);
  EXPECT_NE(Dump.find("load"), std::string::npos) << Dump;
}

TEST(MIRPeepholeLitmus, URemByOneKeepsNestedFPToSI) {
  CompileContext Ctx;
  MType *I32 = &CompileContext::I32Type;
  MType *F64 = &CompileContext::F64Type;
  MFunction F(Ctx, 0);
  F.setFunctionType(MFunctionType::create(Ctx, *I32, {F64}));
  MBasicBlock *Entry = F.createBasicBlock();
  F.appendBlock(Entry);
  auto *X = F.createInstruction<DreadInstruction>(false, *Entry, F64, 0);
  auto *Cvt = F.createInstruction<ConversionInstruction>(
      false, *Entry, OP_wasm_fptosi, I32, X);
  auto *One = F.createInstruction<ConstantInstruction>(
      false, *Entry, I32, *MConstantInt::get(Ctx, *I32, 1));
  auto *URem = F.createInstruction<BinaryInstruction>(false, *Entry, OP_urem,
                                                      I32, Cvt, One);
  F.createInstruction<ReturnInstruction>(true, *Entry, I32, URem);
  MIRPeephole Peep;
  Peep.runOnMFunction(F);
  const std::string Dump = dumpFunc(F);
  EXPECT_NE(Dump.find("wasm_fptosi"), std::string::npos) << Dump;
  EXPECT_EQ(Dump.find("return const.i32 0"), std::string::npos)
      << "must keep trapping fptosi (NaN/overflow): " << Dump;
  finishLitmus(F);
}

TEST(MIRPeepholeLitmus, URemByOneKeepsNestedFPToUI) {
  CompileContext Ctx;
  MType *I32 = &CompileContext::I32Type;
  MType *F64 = &CompileContext::F64Type;
  MFunction F(Ctx, 0);
  F.setFunctionType(MFunctionType::create(Ctx, *I32, {F64}));
  MBasicBlock *Entry = F.createBasicBlock();
  F.appendBlock(Entry);
  auto *X = F.createInstruction<DreadInstruction>(false, *Entry, F64, 0);
  auto *Cvt = F.createInstruction<ConversionInstruction>(
      false, *Entry, OP_wasm_fptoui, I32, X);
  auto *One = F.createInstruction<ConstantInstruction>(
      false, *Entry, I32, *MConstantInt::get(Ctx, *I32, 1));
  auto *URem = F.createInstruction<BinaryInstruction>(false, *Entry, OP_urem,
                                                      I32, Cvt, One);
  F.createInstruction<ReturnInstruction>(true, *Entry, I32, URem);
  MIRPeephole Peep;
  Peep.runOnMFunction(F);
  const std::string Dump = dumpFunc(F);
  EXPECT_NE(Dump.find("wasm_fptoui"), std::string::npos) << Dump;
  EXPECT_EQ(Dump.find("return const.i32 0"), std::string::npos)
      << "must keep trapping fptoui (NaN/overflow): " << Dump;
  finishLitmus(F);
}

TEST(MIRPeepholeLitmus, URemByOneKeepsNestedEvmUdivZeroDivisor) {
  CompileContext Ctx;
  MType *I64 = &CompileContext::I64Type;
  MFunction F(Ctx, 0);
  F.setFunctionType(MFunctionType::create(Ctx, *I64, {I64}));
  MBasicBlock *Entry = F.createBasicBlock();
  F.appendBlock(Entry);
  auto *X = F.createInstruction<DreadInstruction>(false, *Entry, I64, 0);
  auto *Zero = F.createInstruction<ConstantInstruction>(
      false, *Entry, I64, *MConstantInt::get(Ctx, *I64, 0));
  auto *Div = F.createInstruction<EvmUdiv128By64Instruction>(
      false, *Entry, OP_evm_udiv128_by64, I64, Zero, X, Zero);
  auto *One = F.createInstruction<ConstantInstruction>(
      false, *Entry, I64, *MConstantInt::get(Ctx, *I64, 1));
  auto *URem = F.createInstruction<BinaryInstruction>(false, *Entry, OP_urem,
                                                      I64, Div, One);
  F.createInstruction<ReturnInstruction>(true, *Entry, I64, URem);
  MIRPeephole Peep;
  Peep.runOnMFunction(F);
  const std::string Dump = dumpFunc(F);
  EXPECT_NE(Dump.find("evm_udiv128_by64"), std::string::npos) << Dump;
  EXPECT_EQ(Dump.find("return const.i64 0"), std::string::npos)
      << "must keep trapping evm_udiv128_by64 (zero divisor): " << Dump;
  finishLitmus(F);
}

TEST(MIRPeepholeLitmus, URemByOneKeepsNestedEvmUdivQuotientOverflow) {
  CompileContext Ctx;
  MType *I64 = &CompileContext::I64Type;
  MFunction F(Ctx, 0);
  F.setFunctionType(MFunctionType::create(Ctx, *I64, {}));
  MBasicBlock *Entry = F.createBasicBlock();
  F.appendBlock(Entry);
  auto *Zero = F.createInstruction<ConstantInstruction>(
      false, *Entry, I64, *MConstantInt::get(Ctx, *I64, 0));
  auto *One = F.createInstruction<ConstantInstruction>(
      false, *Entry, I64, *MConstantInt::get(Ctx, *I64, 1));
  // (1:0)/1 does not fit in 64 bits; unguarded DIV64r traps.
  auto *Div = F.createInstruction<EvmUdiv128By64Instruction>(
      false, *Entry, OP_evm_udiv128_by64, I64, One, Zero, One);
  auto *URem = F.createInstruction<BinaryInstruction>(false, *Entry, OP_urem,
                                                      I64, Div, One);
  F.createInstruction<ReturnInstruction>(true, *Entry, I64, URem);
  MIRPeephole Peep;
  Peep.runOnMFunction(F);
  const std::string Dump = dumpFunc(F);
  EXPECT_NE(Dump.find("evm_udiv128_by64"), std::string::npos) << Dump;
  EXPECT_EQ(Dump.find("return const.i64 0"), std::string::npos)
      << "must keep trapping evm_udiv128_by64 (quotient overflow): " << Dump;
  finishLitmus(F);
}

TEST(MIRPeepholeLitmus, URemByOneKeepsNestedEvmUremExtractor) {
  CompileContext Ctx;
  MType *I64 = &CompileContext::I64Type;
  MFunction F(Ctx, 0);
  F.setFunctionType(MFunctionType::create(Ctx, *I64, {I64}));
  MBasicBlock *Entry = F.createBasicBlock();
  F.appendBlock(Entry);
  auto *X = F.createInstruction<DreadInstruction>(false, *Entry, I64, 0);
  auto *Zero = F.createInstruction<ConstantInstruction>(
      false, *Entry, I64, *MConstantInt::get(Ctx, *I64, 0));
  auto *Div = F.createInstruction<EvmUdiv128By64Instruction>(
      false, *Entry, OP_evm_udiv128_by64, I64, Zero, X, Zero);
  auto *Rem =
      F.createInstruction<EvmUrem128By64Instruction>(false, *Entry, I64, Div);
  auto *One = F.createInstruction<ConstantInstruction>(
      false, *Entry, I64, *MConstantInt::get(Ctx, *I64, 1));
  auto *URem = F.createInstruction<BinaryInstruction>(false, *Entry, OP_urem,
                                                      I64, Rem, One);
  F.createInstruction<ReturnInstruction>(true, *Entry, I64, URem);
  MIRPeephole Peep;
  Peep.runOnMFunction(F);
  const std::string Dump = dumpFunc(F);
  EXPECT_NE(Dump.find("evm_udiv128_by64"), std::string::npos) << Dump;
  EXPECT_NE(Dump.find("evm_urem128_by64"), std::string::npos) << Dump;
  EXPECT_EQ(Dump.find("return const.i64 0"), std::string::npos)
      << "must keep trapping extractor of evm_udiv128_by64: " << Dump;
  finishLitmus(F);
}

TEST(MIRPeepholeLitmus, URemByOneKeepsNestedI128Overflow) {
  CompileContext Ctx;
  MType *I64 = &CompileContext::I64Type;
  MFunction F(Ctx, 0);
  F.setFunctionType(MFunctionType::create(Ctx, *I64, {I64, I64, I64, I64}));
  MBasicBlock *Entry = F.createBasicBlock();
  F.appendBlock(Entry);
  auto *LoL = F.createInstruction<DreadInstruction>(false, *Entry, I64, 0);
  auto *HiL = F.createInstruction<DreadInstruction>(false, *Entry, I64, 1);
  auto *LoR = F.createInstruction<DreadInstruction>(false, *Entry, I64, 2);
  auto *HiR = F.createInstruction<DreadInstruction>(false, *Entry, I64, 3);
  auto *Add = F.createInstruction<WasmOverflowI128BinaryInstruction>(
      false, *Entry, I64, OP_wasm_uadd128_overflow, LoL, HiL, LoR, HiR);
  auto *One = F.createInstruction<ConstantInstruction>(
      false, *Entry, I64, *MConstantInt::get(Ctx, *I64, 1));
  auto *URem = F.createInstruction<BinaryInstruction>(false, *Entry, OP_urem,
                                                      I64, Add, One);
  F.createInstruction<ReturnInstruction>(true, *Entry, I64, URem);
  MIRPeephole Peep;
  Peep.runOnMFunction(F);
  const std::string Dump = dumpFunc(F);
  EXPECT_NE(Dump.find("wasm_uadd128_overflow"), std::string::npos) << Dump;
  EXPECT_EQ(Dump.find("return const.i64 0"), std::string::npos)
      << "must keep trapping i128 overflow: " << Dump;
  finishLitmus(F);
}

TEST(MIRPeepholeLitmus, URemDreadOfConstPow2FoldsToAnd) {
  MirBuilder B;
  B.F.createVariable(B.I32);
  auto *C8 = B.iconst(8);
  B.F.createInstruction<DassignInstruction>(true, *B.Entry, &B.Ctx.VoidType, C8,
                                            1);
  auto *Dr = B.F.createInstruction<DreadInstruction>(false, *B.Entry, B.I32, 1);
  B.ret(B.bin(OP_urem, B.param(), Dr));
  B.run();
  const std::string Dump = dumpFunc(B.F);
  EXPECT_EQ(Dump.find("urem"), std::string::npos) << Dump;
  EXPECT_NE(Dump.find("and"), std::string::npos) << Dump;
  EXPECT_NE(Dump.find("const.i32 7"), std::string::npos) << Dump;
}

TEST(MIRPeepholeLitmus, UDivDreadOfConstPow2FoldsToUShr) {
  MirBuilder B;
  B.F.createVariable(B.I32);
  auto *C8 = B.iconst(8);
  B.F.createInstruction<DassignInstruction>(true, *B.Entry, &B.Ctx.VoidType, C8,
                                            1);
  auto *Dr = B.F.createInstruction<DreadInstruction>(false, *B.Entry, B.I32, 1);
  B.ret(B.bin(OP_udiv, B.param(), Dr));
  B.run();
  const std::string Dump = dumpFunc(B.F);
  EXPECT_EQ(Dump.find("udiv"), std::string::npos) << Dump;
  EXPECT_NE(Dump.find("ushr"), std::string::npos) << Dump;
  EXPECT_NE(Dump.find("const.i32 3"), std::string::npos) << Dump;
}

TEST(MIRPeepholeLitmus, ConstURemFolds) {
  MirBuilder B;
  B.ret(B.bin(OP_urem, B.iconst(10), B.iconst(8)));
  B.run();
  EXPECT_NE(dumpFunc(B.F).find("const.i32 2"), std::string::npos)
      << dumpFunc(B.F);
}

TEST(MIRPeepholeLitmus, ConstUDivFolds) {
  MirBuilder B;
  B.ret(B.bin(OP_udiv, B.iconst(10), B.iconst(8)));
  B.run();
  EXPECT_NE(dumpFunc(B.F).find("const.i32 1"), std::string::npos)
      << dumpFunc(B.F);
}

TEST(MIRPeepholeLitmus, ConstUDivNonPow2Folds) {
  MirBuilder B;
  B.ret(B.bin(OP_udiv, B.iconst(10), B.iconst(3)));
  B.run();
  EXPECT_NE(dumpFunc(B.F).find("const.i32 3"), std::string::npos)
      << dumpFunc(B.F);
}

TEST(MIRPeepholeLitmus, ConstUDivZeroDoesNotFold) {
  MirBuilder B;
  B.ret(B.bin(OP_udiv, B.iconst(10), B.iconst(0)));
  B.run();
  EXPECT_NE(dumpFunc(B.F).find("udiv"), std::string::npos) << dumpFunc(B.F);
}

TEST(MIRPeepholeLitmus, URemHighBitPow2FoldsToAnd) {
  MirBuilder B;
  B.ret(B.bin(OP_urem, B.param(), B.iconst(0x80000000u)));
  B.run();
  const std::string Dump = dumpFunc(B.F);
  EXPECT_EQ(Dump.find("urem"), std::string::npos) << Dump;
  EXPECT_NE(Dump.find("and"), std::string::npos) << Dump;
}

TEST(MIRPeepholeLitmus, URemI64HighBitPow2FoldsToAnd) {
  CompileContext Ctx;
  MType *I64 = &CompileContext::I64Type;
  MFunction F(Ctx, 0);
  F.setFunctionType(MFunctionType::create(Ctx, *I64, {I64}));
  MBasicBlock *Entry = F.createBasicBlock();
  F.appendBlock(Entry);
  auto *X = F.createInstruction<DreadInstruction>(false, *Entry, I64, 0);
  auto *C = F.createInstruction<ConstantInstruction>(
      false, *Entry, I64, *MConstantInt::get(Ctx, *I64, 0x8000000000000000ull));
  auto *URem =
      F.createInstruction<BinaryInstruction>(false, *Entry, OP_urem, I64, X, C);
  F.createInstruction<ReturnInstruction>(true, *Entry, I64, URem);
  MIRPeephole Peep;
  Peep.runOnMFunction(F);
  const std::string Dump = dumpFunc(F);
  EXPECT_EQ(Dump.find("urem"), std::string::npos) << Dump;
  EXPECT_NE(Dump.find("and"), std::string::npos) << Dump;
  finishLitmus(F);
}

TEST(MIRPeepholeLitmus, URemI64WideMaskFoldsToAnd) {
  CompileContext Ctx;
  MType *I64 = &CompileContext::I64Type;
  MFunction F(Ctx, 0);
  F.setFunctionType(MFunctionType::create(Ctx, *I64, {I64}));
  MBasicBlock *Entry = F.createBasicBlock();
  F.appendBlock(Entry);
  auto *X = F.createInstruction<DreadInstruction>(false, *Entry, I64, 0);
  auto *C = F.createInstruction<ConstantInstruction>(
      false, *Entry, I64, *MConstantInt::get(Ctx, *I64, 0x100000000ull));
  auto *URem =
      F.createInstruction<BinaryInstruction>(false, *Entry, OP_urem, I64, X, C);
  F.createInstruction<ReturnInstruction>(true, *Entry, I64, URem);
  MIRPeephole Peep;
  Peep.runOnMFunction(F);
  const std::string Dump = dumpFunc(F);
  EXPECT_EQ(Dump.find("urem"), std::string::npos) << Dump;
  EXPECT_NE(Dump.find("and"), std::string::npos) << Dump;
  EXPECT_NE(Dump.find("const.i64 4294967295"), std::string::npos) << Dump;
  finishLitmus(F);
}

TEST(MIRPeepholeLitmus, ConstURemNonPow2Folds) {
  MirBuilder B;
  B.ret(B.bin(OP_urem, B.iconst(10), B.iconst(3)));
  B.run();
  EXPECT_NE(dumpFunc(B.F).find("const.i32 1"), std::string::npos)
      << dumpFunc(B.F);
}

TEST(MIRPeepholeLitmus, URemZeroDoesNotFold) {
  MirBuilder B;
  B.ret(B.bin(OP_urem, B.param(), B.iconst(0)));
  B.run();
  EXPECT_NE(dumpFunc(B.F).find("urem"), std::string::npos) << dumpFunc(B.F);
}

TEST(MIRPeepholeLitmus, UDivZeroDoesNotFold) {
  MirBuilder B;
  B.ret(B.bin(OP_udiv, B.param(), B.iconst(0)));
  B.run();
  EXPECT_NE(dumpFunc(B.F).find("udiv"), std::string::npos) << dumpFunc(B.F);
}

TEST(MIRPeepholeLitmus, URemNonPow2DoesNotFold) {
  MirBuilder B;
  B.ret(B.bin(OP_urem, B.param(), B.iconst(6)));
  B.run();
  EXPECT_NE(dumpFunc(B.F).find("urem"), std::string::npos) << dumpFunc(B.F);
}

TEST(MIRPeepholeLitmus, SRemPow2DoesNotFold) {
  MirBuilder B;
  B.ret(B.bin(OP_srem, B.param(), B.iconst(8)));
  B.run();
  EXPECT_NE(dumpFunc(B.F).find("srem"), std::string::npos) << dumpFunc(B.F);
}

TEST(MIRPeepholeLitmus, SDivPow2DoesNotFold) {
  MirBuilder B;
  B.ret(B.bin(OP_sdiv, B.param(), B.iconst(8)));
  B.run();
  EXPECT_NE(dumpFunc(B.F).find("sdiv"), std::string::npos) << dumpFunc(B.F);
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

TEST(MIRPeepholeLitmus, MulPow2FoldsToShl) {
  MirBuilder B;
  B.ret(B.bin(OP_mul, B.param(), B.iconst(8)));
  B.run();
  const std::string Dump = dumpFunc(B.F);
  EXPECT_EQ(Dump.find("mul"), std::string::npos) << Dump;
  EXPECT_NE(Dump.find("shl"), std::string::npos) << Dump;
  EXPECT_NE(Dump.find("const.i32 3"), std::string::npos) << Dump;
}

TEST(MIRPeepholeLitmus, MulThreeDoesNotFoldToShl) {
  MirBuilder B;
  B.ret(B.bin(OP_mul, B.param(), B.iconst(3)));
  B.run();
  EXPECT_NE(dumpFunc(B.F).find("mul"), std::string::npos) << dumpFunc(B.F);
}

TEST(MIRPeepholeLitmus, AddImmReassoc) {
  MirBuilder B;
  auto *Inner = B.bin(OP_add, B.param(), B.iconst(10408));
  B.ret(B.bin(OP_add, Inner, B.iconst(8)));
  B.run();
  const std::string Dump = dumpFunc(B.F);
  EXPECT_NE(Dump.find("const.i32 10416"), std::string::npos) << Dump;
}

TEST(MIRPeepholeLitmus, SubImmCanonicalizesToAdd) {
  MirBuilder B;
  B.ret(B.bin(OP_sub, B.param(), B.iconst(8)));
  B.run();
  const std::string Dump = dumpFunc(B.F);
  EXPECT_EQ(Dump.find("sub"), std::string::npos) << Dump;
  EXPECT_NE(Dump.find("add"), std::string::npos) << Dump;
}

TEST(MIRPeepholeLitmus, SubImmI64PreservesBorrowProducer) {
  CompileContext Ctx;
  MType *I64 = &CompileContext::I64Type;
  MFunction F(Ctx, 0);
  F.setFunctionType(MFunctionType::create(Ctx, *I64, {I64}));
  MBasicBlock *Entry = F.createBasicBlock();
  F.appendBlock(Entry);
  auto *X = F.createInstruction<DreadInstruction>(false, *Entry, I64, 0);
  auto *One = F.createInstruction<ConstantInstruction>(
      false, *Entry, I64, *MConstantInt::get(Ctx, *I64, 1));
  auto *Sub = F.createInstruction<BinaryInstruction>(false, *Entry, OP_sub, I64,
                                                     X, One);
  F.createInstruction<ReturnInstruction>(true, *Entry, I64, Sub);
  MIRPeephole Peep;
  Peep.runOnMFunction(F);
  const std::string Dump = dumpFunc(F);
  EXPECT_NE(Dump.find("sub"), std::string::npos) << Dump;
  EXPECT_EQ(Dump.find("add"), std::string::npos) << Dump;
  finishLitmus(F);
}

TEST(MIRPeepholeLitmus, AddImmI64PreservesFinalCarryProducer) {
  CompileContext Ctx;
  MType *I64 = &CompileContext::I64Type;
  MFunction F(Ctx, 0);
  F.setFunctionType(MFunctionType::create(Ctx, *I64, {I64}));
  MBasicBlock *Entry = F.createBasicBlock();
  F.appendBlock(Entry);
  auto *X = F.createInstruction<DreadInstruction>(false, *Entry, I64, 0);
  auto makeConst = [&](uint64_t V) {
    return F.createInstruction<ConstantInstruction>(
        false, *Entry, I64, *MConstantInt::get(Ctx, *I64, V));
  };
  auto *Inner = F.createInstruction<BinaryInstruction>(false, *Entry, OP_add,
                                                       I64, X, makeConst(10));
  auto *Outer = F.createInstruction<BinaryInstruction>(
      false, *Entry, OP_add, I64, Inner, makeConst(3));
  F.createInstruction<ReturnInstruction>(true, *Entry, I64, Outer);
  MIRPeephole Peep;
  Peep.runOnMFunction(F);
  const std::string Dump = dumpFunc(F);
  EXPECT_NE(Dump.find("const.i64 10"), std::string::npos) << Dump;
  EXPECT_NE(Dump.find("const.i64 3"), std::string::npos) << Dump;
  EXPECT_EQ(Dump.find("const.i64 13"), std::string::npos) << Dump;
  finishLitmus(F);
}

TEST(MIRPeepholeLitmus, AddThenSubImmReassoc) {
  MirBuilder B;
  auto *Inner = B.bin(OP_add, B.param(), B.iconst(10408));
  B.ret(B.bin(OP_sub, Inner, B.iconst(8)));
  B.run();
  const std::string Dump = dumpFunc(B.F);
  EXPECT_NE(Dump.find("const.i32 10400"), std::string::npos) << Dump;
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

TEST(MIRPeepholeLitmus, HoistsNonZeroFPConstOutOfNonEntryBlock) {
  CompileContext Ctx;
  MType *F64 = &CompileContext::F64Type;
  MFunction F(Ctx, 0);
  F.setFunctionType(MFunctionType::create(Ctx, *F64, {F64}));
  MBasicBlock *Entry = F.createBasicBlock();
  MBasicBlock *Body = F.createBasicBlock();
  F.appendBlock(Entry);
  F.appendBlock(Body);

  F.createInstruction<BrInstruction>(true, *Entry, Ctx, Body);
  Entry->addSuccessor(Body);

  auto *Param = F.createInstruction<DreadInstruction>(false, *Body, F64, 0);
  auto *C = F.createInstruction<ConstantInstruction>(
      false, *Body, F64, *MConstantFloat::get(Ctx, *F64, 0.2));
  auto *Mul = F.createInstruction<BinaryInstruction>(false, *Body, OP_mul, F64,
                                                     Param, C);
  F.createInstruction<ReturnInstruction>(true, *Body, F64, Mul);

  MIRPeephole Peep;
  Peep.runOnMFunction(F);

  const std::string Dump = dumpFunc(F);
  EXPECT_NE(Dump.find("var $1"), std::string::npos) << Dump;
  const auto At0 = Dump.find("@0:");
  const auto At1 = Dump.find("@1:");
  ASSERT_NE(At0, std::string::npos) << Dump;
  ASSERT_NE(At1, std::string::npos) << Dump;
  const std::string EntryDump = Dump.substr(At0, At1 - At0);
  const std::string BodyDump = Dump.substr(At1);
  EXPECT_NE(EntryDump.find("const.f64"), std::string::npos) << Dump;
  EXPECT_EQ(BodyDump.find("const.f64"), std::string::npos) << Dump;
  EXPECT_NE(BodyDump.find("mul"), std::string::npos) << Dump;
  finishLitmus(F);
}

TEST(MIRPeepholeLitmus, DoesNotHoistPlusZeroFPConst) {
  CompileContext Ctx;
  MType *F64 = &CompileContext::F64Type;
  MFunction F(Ctx, 0);
  F.setFunctionType(MFunctionType::create(Ctx, *F64, {F64}));
  MBasicBlock *Entry = F.createBasicBlock();
  MBasicBlock *Body = F.createBasicBlock();
  F.appendBlock(Entry);
  F.appendBlock(Body);

  F.createInstruction<BrInstruction>(true, *Entry, Ctx, Body);
  Entry->addSuccessor(Body);

  auto *Param = F.createInstruction<DreadInstruction>(false, *Body, F64, 0);
  auto *C = F.createInstruction<ConstantInstruction>(
      false, *Body, F64, *MConstantFloat::get(Ctx, *F64, 0.0));
  auto *Add = F.createInstruction<BinaryInstruction>(false, *Body, OP_add, F64,
                                                     Param, C);
  F.createInstruction<ReturnInstruction>(true, *Body, F64, Add);

  MIRPeephole Peep;
  Peep.runOnMFunction(F);

  const std::string Dump = dumpFunc(F);
  EXPECT_EQ(Dump.find("var $1"), std::string::npos) << Dump;
  EXPECT_NE(Dump.find("const.f64"), std::string::npos) << Dump;
  finishLitmus(F);
}

TEST(MIRPeepholeLitmus, HoistsMinusZeroFPConst) {
  CompileContext Ctx;
  MType *F64 = &CompileContext::F64Type;
  MFunction F(Ctx, 0);
  F.setFunctionType(MFunctionType::create(Ctx, *F64, {F64}));
  MBasicBlock *Entry = F.createBasicBlock();
  MBasicBlock *Body = F.createBasicBlock();
  F.appendBlock(Entry);
  F.appendBlock(Body);

  F.createInstruction<BrInstruction>(true, *Entry, Ctx, Body);
  Entry->addSuccessor(Body);

  auto *Param = F.createInstruction<DreadInstruction>(false, *Body, F64, 0);
  auto *C = F.createInstruction<ConstantInstruction>(
      false, *Body, F64,
      *MConstantFloat::get(
          Ctx, *F64,
          llvm::APFloat::getZero(llvm::APFloat::IEEEdouble(), true)));
  auto *Add = F.createInstruction<BinaryInstruction>(false, *Body, OP_add, F64,
                                                     Param, C);
  F.createInstruction<ReturnInstruction>(true, *Body, F64, Add);

  MIRPeephole Peep;
  Peep.runOnMFunction(F);

  const std::string Dump = dumpFunc(F);
  EXPECT_NE(Dump.find("var $1"), std::string::npos) << Dump;
  finishLitmus(F);
}

TEST(MIRPeepholeLitmus, HoistsF32AndDedupsRepeatedConst) {
  CompileContext Ctx;
  MType *F32 = &CompileContext::F32Type;
  MFunction F(Ctx, 0);
  F.setFunctionType(MFunctionType::create(Ctx, *F32, {F32}));
  MBasicBlock *Entry = F.createBasicBlock();
  MBasicBlock *Body = F.createBasicBlock();
  F.appendBlock(Entry);
  F.appendBlock(Body);

  F.createInstruction<BrInstruction>(true, *Entry, Ctx, Body);
  Entry->addSuccessor(Body);

  auto *Param = F.createInstruction<DreadInstruction>(false, *Body, F32, 0);
  auto *C0 = F.createInstruction<ConstantInstruction>(
      false, *Body, F32, *MConstantFloat::get(Ctx, *F32, 0.2f));
  auto *C1 = F.createInstruction<ConstantInstruction>(
      false, *Body, F32, *MConstantFloat::get(Ctx, *F32, 0.2f));
  auto *Mul = F.createInstruction<BinaryInstruction>(false, *Body, OP_mul, F32,
                                                     Param, C0);
  auto *Add = F.createInstruction<BinaryInstruction>(false, *Body, OP_add, F32,
                                                     Mul, C1);
  F.createInstruction<ReturnInstruction>(true, *Body, F32, Add);

  MIRPeephole Peep;
  Peep.runOnMFunction(F);

  const std::string Dump = dumpFunc(F);
  EXPECT_NE(Dump.find("var $1"), std::string::npos) << Dump;
  EXPECT_EQ(Dump.find("var $2"), std::string::npos) << Dump;
  finishLitmus(F);
}

TEST(MIRPeepholeLitmus, DoesNotHoistWhenEntryHasPredecessor) {
  CompileContext Ctx;
  MType *F64 = &CompileContext::F64Type;
  MFunction F(Ctx, 0);
  F.setFunctionType(MFunctionType::create(Ctx, *F64, {F64}));
  MBasicBlock *Entry = F.createBasicBlock();
  MBasicBlock *Body = F.createBasicBlock();
  F.appendBlock(Entry);
  F.appendBlock(Body);

  F.createInstruction<BrInstruction>(true, *Entry, Ctx, Body);
  Entry->addSuccessor(Body);
  F.createInstruction<BrInstruction>(true, *Body, Ctx, Entry);
  Body->addSuccessor(Entry);

  auto *Param = F.createInstruction<DreadInstruction>(false, *Body, F64, 0);
  auto *C = F.createInstruction<ConstantInstruction>(
      false, *Body, F64, *MConstantFloat::get(Ctx, *F64, 0.2));
  auto *Mul = F.createInstruction<BinaryInstruction>(false, *Body, OP_mul, F64,
                                                     Param, C);
  F.createInstruction<ReturnInstruction>(true, *Body, F64, Mul);

  MIRPeephole Peep;
  Peep.runOnMFunction(F);

  const std::string Dump = dumpFunc(F);
  EXPECT_EQ(Dump.find("var $1"), std::string::npos) << Dump;
  finishLitmus(F);
}

TEST(MIRPeepholeLitmus, DoesNotHoistFPConstUsedOnlyInEntry) {
  CompileContext Ctx;
  MType *F64 = &CompileContext::F64Type;
  MFunction F(Ctx, 0);
  F.setFunctionType(MFunctionType::create(Ctx, *F64, {F64}));
  MBasicBlock *Entry = F.createBasicBlock();
  F.appendBlock(Entry);

  auto *Param = F.createInstruction<DreadInstruction>(false, *Entry, F64, 0);
  auto *C = F.createInstruction<ConstantInstruction>(
      false, *Entry, F64, *MConstantFloat::get(Ctx, *F64, 0.2));
  auto *Mul = F.createInstruction<BinaryInstruction>(false, *Entry, OP_mul, F64,
                                                     Param, C);
  F.createInstruction<ReturnInstruction>(true, *Entry, F64, Mul);

  MIRPeephole Peep;
  Peep.runOnMFunction(F);

  const std::string Dump = dumpFunc(F);
  EXPECT_EQ(Dump.find("var $1"), std::string::npos) << Dump;
  EXPECT_NE(Dump.find("const.f64"), std::string::npos) << Dump;
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
  EXPECT_EQ(callI32(*RT, *Inst, "rem_u8", 0), 0);
  EXPECT_EQ(callI32(*RT, *Inst, "rem_u8", 7), 7);
  EXPECT_EQ(callI32(*RT, *Inst, "rem_u8", 8), 0);
  EXPECT_EQ(callI32(*RT, *Inst, "rem_u8", 9), 1);
  EXPECT_EQ(callI32(*RT, *Inst, "rem_u8", -1), 7);
  EXPECT_EQ(callI32(*RT, *Inst, "div_u8", 0), 0);
  EXPECT_EQ(callI32(*RT, *Inst, "div_u8", 7), 0);
  EXPECT_EQ(callI32(*RT, *Inst, "div_u8", 8), 1);
  EXPECT_EQ(callI32(*RT, *Inst, "div_u8", 9), 1);
  EXPECT_EQ(callI32(*RT, *Inst, "div_u8", -1),
            static_cast<int32_t>(0x1fffffffu));
  EXPECT_EQ(callI32(*RT, *Inst, "rem_u6", 10), 4);
  EXPECT_EQ(callI32(*RT, *Inst, "rem_s8", -5), -5);
  EXPECT_EQ(callI32(*RT, *Inst, "rem_u_hi", static_cast<int32_t>(0x80000001u)),
            1);
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

  int32_t TrapOut = 0;
  EXPECT_FALSE(tryCallI32(*RT, *Inst, "div_u0", 1, TrapOut));
  EXPECT_TRUE(Inst->hasError()) << Inst->getError().getFormattedMessage();
  Inst->clearError();
  EXPECT_FALSE(tryCallI32(*RT, *Inst, "rem1_of_div0", 1, TrapOut));
  EXPECT_TRUE(Inst->hasError()) << Inst->getError().getFormattedMessage();
  Inst->clearError();
  EXPECT_FALSE(tryCallI32(*RT, *Inst, "rem1_of_oob_load", 0, TrapOut));
  EXPECT_TRUE(Inst->hasError()) << Inst->getError().getFormattedMessage();
  Inst->clearError();
  EXPECT_FALSE(tryCallNoArg(*RT, *Inst, "rem1_of_trunc_s_nan", TrapOut));
  EXPECT_TRUE(Inst->hasError()) << Inst->getError().getFormattedMessage();
  Inst->clearError();
  EXPECT_FALSE(tryCallNoArg(*RT, *Inst, "rem1_of_trunc_s_ovf", TrapOut));
  EXPECT_TRUE(Inst->hasError()) << Inst->getError().getFormattedMessage();
  Inst->clearError();
  EXPECT_FALSE(tryCallNoArg(*RT, *Inst, "rem1_of_trunc_u_nan", TrapOut));
  EXPECT_TRUE(Inst->hasError()) << Inst->getError().getFormattedMessage();
  Inst->clearError();
  EXPECT_EQ(callI32(*RT, *Inst, "rem1_of_call", 42), 0);
  EXPECT_EQ(callI32NoArg(*RT, *Inst, "g"), 1);

  size_t RemLen = 0;
  const uint8_t *RemBytes = jitFuncBytes(*Inst->getModule(), "rem_u8", RemLen);
  ASSERT_NE(RemBytes, nullptr);
  EXPECT_FALSE(codeHasDiv(RemBytes, RemLen))
      << "wasm rem_u by 8 still emits DIV";
  EXPECT_TRUE(codeHasAndImm7(RemBytes, RemLen))
      << "wasm rem_u by 8 should AND with 7";
  size_t DivLen = 0;
  const uint8_t *DivBytes = jitFuncBytes(*Inst->getModule(), "div_u8", DivLen);
  ASSERT_NE(DivBytes, nullptr);
  EXPECT_FALSE(codeHasDiv(DivBytes, DivLen))
      << "wasm div_u by 8 still emits DIV";
  EXPECT_TRUE(codeHasShrImm3(DivBytes, DivLen))
      << "wasm div_u by 8 should SHR by 3";
  EXPECT_EQ(callI32(*RT, *Inst, "mul8", 3), 24);
  EXPECT_EQ(callI32(*RT, *Inst, "add_reassoc", 1), 10417);
  EXPECT_EQ(callI32(*RT, *Inst, "count_lt", 0), 0);
  EXPECT_EQ(callI32(*RT, *Inst, "count_lt", 5), 5);
  EXPECT_EQ(callI32(*RT, *Inst, "count_lt", 1), 1);
  EXPECT_DOUBLE_EQ(callF64(*RT, *Inst, "scale02", 0), 0.0);
  EXPECT_DOUBLE_EQ(callF64(*RT, *Inst, "scale02", 5), 2.0);
  EXPECT_EQ(callI32(*RT, *Inst, "i32_slt0", -1), 1);
  EXPECT_EQ(callI32(*RT, *Inst, "i32_ult0", -1), 0);
  EXPECT_EQ(callI32(*RT, *Inst, "i32_slt_min", 0), 0);
  EXPECT_EQ(callI32(*RT, *Inst, "i32_ult_min", 0), 1);
  EXPECT_EQ(callI32(*RT, *Inst, "i32_ult_min", -1), 0);
  EXPECT_EQ(callI32(*RT, *Inst, "i64_slt0", -1), 1);
  EXPECT_EQ(callI32(*RT, *Inst, "i64_ult0", -1), 0);
  EXPECT_EQ(callI32(*RT, *Inst, "f64_gt_nan", 1), 0);
  EXPECT_EQ(callI32(*RT, *Inst, "f64_lt_nan", 1), 0);
  EXPECT_EQ(callI32(*RT, *Inst, "f64_eq_nan", 0), 0);
  EXPECT_EQ(callI32(*RT, *Inst, "f64_ne_nan", 0), 1);
  EXPECT_EQ(callI32(*RT, *Inst, "f64_eq_signed_zero", 0), 1);
  EXPECT_EQ(callI32(*RT, *Inst, "f64_gt_inf", 1), 0);
  EXPECT_EQ(callI32(*RT, *Inst, "f64_gt_ninf", 0), 1);
  EXPECT_EQ(callI32(*RT, *Inst, "if_slt", -1), 1);
  EXPECT_EQ(callI32(*RT, *Inst, "if_slt", 1), 0);
  EXPECT_EQ(callI32(*RT, *Inst, "if_f64_gt_nan", 1), 0);
  EXPECT_EQ(callI32(*RT, *Inst, "f64_gt_2", 1), 0);
  EXPECT_EQ(callI32(*RT, *Inst, "f64_gt_2", 3), 1);
  EXPECT_EQ(callI32(*RT, *Inst, "f64_lt_2", 1), 1);
  EXPECT_EQ(callI32(*RT, *Inst, "f64_lt_2", 3), 0);
  EXPECT_EQ(callI32(*RT, *Inst, "f64_gt_nan_lhs", 1), 0);
  EXPECT_EQ(callI32(*RT, *Inst, "f64_gt_nan_rhs", 1), 0);
  EXPECT_EQ(callI32(*RT, *Inst, "f64_lt_nan_lhs", 1), 0);
  EXPECT_EQ(callI32(*RT, *Inst, "f64_lt_nan_rhs", 1), 0);
  EXPECT_EQ(callI32(*RT, *Inst, "f32_gt_2", 1), 0);
  EXPECT_EQ(callI32(*RT, *Inst, "f32_gt_2", 3), 1);
  EXPECT_EQ(callI32(*RT, *Inst, "f32_lt_2", 1), 1);
  EXPECT_EQ(callI32(*RT, *Inst, "f32_lt_2", 3), 0);
  EXPECT_EQ(callI32(*RT, *Inst, "f32_gt_nan", 1), 0);
  EXPECT_EQ(callI32(*RT, *Inst, "if_f64_gt_2", 1), 3);
  EXPECT_EQ(callI32(*RT, *Inst, "if_f64_gt_2", 3), 7);
  EXPECT_EQ(callI32(*RT, *Inst, "if_f64_lt_2", 1), 7);
  EXPECT_EQ(callI32(*RT, *Inst, "if_f64_lt_2", 3), 3);
  EXPECT_EQ(callI32(*RT, *Inst, "if_f64_gt_nan_7_3", 1), 3);
  EXPECT_EQ(callI32(*RT, *Inst, "if_f64_gt_2_short", 1), 3);
  EXPECT_EQ(callI32(*RT, *Inst, "if_f64_gt_2_short", 2), 3);
  EXPECT_EQ(callI32(*RT, *Inst, "if_f64_gt_2_short", 3), 7);
  EXPECT_EQ(callI32(*RT, *Inst, "if_f64_lt_2_short", 1), 7);
  EXPECT_EQ(callI32(*RT, *Inst, "if_f64_lt_2_short", 2), 3);
  EXPECT_EQ(callI32(*RT, *Inst, "if_f64_lt_2_short", 3), 3);
  EXPECT_EQ(callI32(*RT, *Inst, "if_f64_gt_nan_short", 1), 3);
  EXPECT_EQ(callI32(*RT, *Inst, "if_f64_gt_nan_short", 3), 3);
  EXPECT_EQ(callI32(*RT, *Inst, "if_f64_lt_nan_lhs_short", 1), 3);
  EXPECT_EQ(callI32(*RT, *Inst, "if_f32_gt_2_short", 1), 3);
  EXPECT_EQ(callI32(*RT, *Inst, "if_f32_gt_2_short", 3), 7);
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
  const char *Fns[] = {"mul8",
                       "add_reassoc",
                       "ctz_eqz",
                       "clz_eqz",
                       "ctz_eq4",
                       "select_eq_true",
                       "add0",
                       "rem_u8",
                       "div_u8",
                       "rem_u6",
                       "rem_s8",
                       "f3",
                       "f4",
                       "f8",
                       "f9",
                       "f12",
                       "f13",
                       "f14",
                       "i32_slt0",
                       "i32_ult0",
                       "i32_slt_min",
                       "i32_ult_min",
                       "i64_slt0",
                       "i64_ult0",
                       "if_slt",
                       "f64_gt_nan",
                       "f64_eq_nan",
                       "f64_ne_nan",
                       "f64_eq_signed_zero",
                       "if_f64_gt_nan",
                       "f64_gt_2",
                       "f64_lt_2",
                       "f64_gt_nan_lhs",
                       "f64_gt_nan_rhs",
                       "f64_lt_nan_lhs",
                       "f64_lt_nan_rhs",
                       "f32_gt_2",
                       "f32_lt_2",
                       "f32_gt_nan",
                       "if_f64_gt_2",
                       "if_f64_lt_2",
                       "if_f64_gt_nan_7_3",
                       "if_f64_gt_2_short",
                       "if_f64_lt_2_short",
                       "if_f64_gt_nan_short",
                       "if_f64_lt_nan_lhs_short",
                       "if_f32_gt_2_short"};
  for (const char *Fn : Fns) {
    for (int32_t X : Inputs) {
      EXPECT_EQ(callI32(*RTM, **InstM, Fn, X), callI32(*RTS, **InstS, Fn, X))
          << Fn << " x=" << X;
    }
  }
  // Negative bounds, including INT_MIN, take the signed ge_s exit
  // immediately. Very large positive bounds are the expensive ones.
  const int32_t LoopInputs[] = {
      0, 1, 2, 4, 5, -1, static_cast<int32_t>(0x80000000u)};
  for (int32_t X : LoopInputs) {
    EXPECT_EQ(callI32(*RTM, **InstM, "count_lt", X),
              callI32(*RTS, **InstS, "count_lt", X))
        << "count_lt x=" << X;
    EXPECT_DOUBLE_EQ(callF64(*RTM, **InstM, "scale02", X),
                     callF64(*RTS, **InstS, "scale02", X))
        << "scale02 x=" << X;
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
            V != 1 || !tryCallI32(*RT, *Inst, "count_lt", 5, V) || V != 5 ||
            !tryCallI32(*RT, *Inst, "f64_gt_2", 3, V) || V != 1 ||
            !tryCallI32(*RT, *Inst, "f64_lt_2", 3, V) || V != 0 ||
            !tryCallI32(*RT, *Inst, "if_f64_gt_2", 3, V) || V != 7 ||
            !tryCallI32(*RT, *Inst, "if_f64_lt_2", 3, V) || V != 3 ||
            !tryCallI32(*RT, *Inst, "if_f64_gt_2_short", 3, V) || V != 7 ||
            !tryCallI32(*RT, *Inst, "if_f64_lt_2_short", 3, V) || V != 3 ||
            !tryCallI32(*RT, *Inst, "if_f64_gt_nan_short", 1, V) || V != 3) {
          Failures++;
          return;
        }
        double D = 0.0;
        if (!tryCallF64(*RT, *Inst, "scale02", 5, D) || !isCloseToTwo(D)) {
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
            !tryCallI32(*RT, *Inst, "f13", 0, V) || V != 1 ||
            !tryCallI32(*RT, *Inst, "count_lt", 5, V) || V != 5 ||
            !tryCallI32(*RT, *Inst, "f64_gt_2", 3, V) || V != 1 ||
            !tryCallI32(*RT, *Inst, "f64_lt_2", 3, V) || V != 0 ||
            !tryCallI32(*RT, *Inst, "if_f64_gt_2_short", 3, V) || V != 7 ||
            !tryCallI32(*RT, *Inst, "if_f64_lt_2_short", 1, V) || V != 7) {
          Failures++;
          return;
        }
        double D = 0.0;
        if (!tryCallF64(*RT, *Inst, "scale02", 5, D) || !isCloseToTwo(D)) {
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
  EXPECT_EQ(callI32(*RT, *Inst, "count_lt", 5), 5);
  EXPECT_DOUBLE_EQ(callF64(*RT, *Inst, "scale02", 5), 2.0);
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
    if ((I % 20) == 0) {
      EXPECT_EQ(callI32(*RT, *Inst, "count_lt", 5), 5);
      EXPECT_DOUBLE_EQ(callF64(*RT, *Inst, "scale02", 5), 2.0);
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
