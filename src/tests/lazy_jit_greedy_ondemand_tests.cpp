// Copyright (C) 2021-2026 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/compiler.h"
#include "compiler/stub/stub_jmp_target.h"
#include "runtime/isolation.h"
#include "runtime/memory.h"
#include "runtime/module.h"
#include "runtime/runtime.h"
#include "zetaengine.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

using COMPILER::LazyJITCompiler;
using zen::common::RunMode;
using zen::common::TypedValue;
using zen::runtime::CodeEntry;
using zen::runtime::Instance;
using zen::runtime::Isolation;
using zen::runtime::Module;
using zen::runtime::Runtime;
using zen::runtime::RuntimeConfig;

namespace {

std::vector<uint8_t> loadWasmFile(const char *Path) {
  std::ifstream In(Path, std::ios::binary);
  EXPECT_TRUE(In) << "failed to open " << Path;
  return std::vector<uint8_t>((std::istreambuf_iterator<char>(In)),
                              std::istreambuf_iterator<char>());
}

std::unique_ptr<Runtime>
makeRuntime(bool Lazy, bool DisableGreedyRA, bool DisableMT,
            bool PrivateTiering = false,
            const RuntimeConfig *PolicyConfig = nullptr) {
  RuntimeConfig Cfg;
  Cfg.Mode = RunMode::MultipassMode;
#ifdef ZEN_ENABLE_BUILTIN_WASI
  Cfg.DisableWASI = true;
#endif
#ifdef ZEN_ENABLE_MULTIPASS_JIT
  Cfg.EnableMultipassLazy = Lazy;
  Cfg.EnableLazyPrivateTiering = PrivateTiering;
  if (PrivateTiering) {
    Cfg.LazyTierPolicy = zen::runtime::LazyPrivateTierPolicy::Loops;
    Cfg.LazyTierCallThreshold = 1;
    Cfg.LazyTierLoopThreshold = 1;
    Cfg.LazyTierBudgetMs = 1000;
  }
  Cfg.DisableMultipassGreedyRA = DisableGreedyRA;
  Cfg.DisableMultipassMultithread = DisableMT;
  Cfg.NumMultipassThreads = 4;
  if (PolicyConfig) {
    Cfg.DisableLazyAutoGreedy = PolicyConfig->DisableLazyAutoGreedy;
    Cfg.LazyAutoGreedyMaxModuleBytes =
        PolicyConfig->LazyAutoGreedyMaxModuleBytes;
    Cfg.LazyAutoGreedyMaxFunctionBytes =
        PolicyConfig->LazyAutoGreedyMaxFunctionBytes;
    Cfg.LazyAutoGreedyBudgetMs = PolicyConfig->LazyAutoGreedyBudgetMs;
  }
#endif
  return Runtime::newRuntime(Cfg);
}

int32_t callI32(Runtime &RT, Instance &Inst, const char *Name, int32_t Arg) {
  std::vector<TypedValue> Results;
  EXPECT_TRUE(RT.callWasmFunction(Inst, Name, {std::to_string(Arg)}, Results))
      << (Inst.hasError() ? Inst.getError().getFormattedMessage() : Name);
  EXPECT_EQ(Results.size(), 1u);
  return Results[0].Value.I32;
}

/// If Ptr is a lazy stub `jmp rel32`, return the compiled body (or nullptr
/// while still on the trampoline). Otherwise treat Ptr as the body.
const uint8_t *resolvedJitBody(const uint8_t *Ptr) {
  if (!Ptr || Ptr[0] != 0xe9) {
    return Ptr;
  }
  if (COMPILER::stub_jmp::loadRel32(Ptr) ==
      COMPILER::stub_jmp::kTrampolineRel32) {
    return nullptr;
  }
  return Ptr + 5 + COMPILER::stub_jmp::loadRel32(Ptr);
}

struct CodeShape {
  uint32_t StackSub = 0;
  uint32_t RbpStores = 0;
};

/// Prefix heuristic, not a complete-function spill count. Scans a bounded
/// byte window for `sub $imm, %rsp` and `mov %rN, disp(%rbp)` encodings.
/// Does not stop at `ret` (this kernel's early return precedes the loop).
/// Immediates/displacements can false-positive; use only for relative
/// FastRA vs Greedy comparison on these fixtures.
CodeShape scanCodeShapePrefix(const uint8_t *P, size_t N) {
  CodeShape S;
  if (!P || N < 4) {
    return S;
  }
  size_t I = 0;
  if (N >= 4 && P[0] == 0xf3 && P[1] == 0x0f && P[2] == 0x1e && P[3] == 0xfa) {
    I = 4;
  }
  while (I + 2 < N) {
    size_t J = I;
    uint8_t B = P[J];
    bool RexW = false;
    if ((B & 0xf0) == 0x40) {
      RexW = (B & 0x08) != 0;
      ++J;
      if (J >= N) {
        break;
      }
      B = P[J];
    }
    if (RexW && B == 0x83 && J + 2 < N && P[J + 1] == 0xec) {
      S.StackSub = P[J + 2];
      I = J + 3;
      continue;
    }
    if (RexW && B == 0x81 && J + 5 < N && P[J + 1] == 0xec) {
      uint32_t Imm = 0;
      std::memcpy(&Imm, P + J + 2, 4);
      S.StackSub = Imm;
      I = J + 6;
      continue;
    }
    if (B == 0x89 && J + 1 < N) {
      uint8_t ModRM = P[J + 1];
      if ((ModRM & 0xc7) == 0x45 && J + 2 < N) {
        ++S.RbpStores;
        I = J + 3;
        continue;
      }
      if ((ModRM & 0xc7) == 0x85 && J + 5 < N) {
        ++S.RbpStores;
        I = J + 6;
        continue;
      }
    }
    ++I;
  }
  return S;
}

constexpr size_t kShapePrefixBytes = 512;

struct LoadedMod {
  std::unique_ptr<Runtime> RT;
  Module *Mod = nullptr;
  Instance *Inst = nullptr;
  LazyJITCompiler *Lazy = nullptr;
};

LoadedMod loadModule(const std::vector<uint8_t> &Bytes, const char *Name,
                     bool Lazy, bool DisableGreedyRA, bool DisableMT,
                     bool Instantiate = true, bool PrivateTiering = false,
                     const RuntimeConfig *PolicyConfig = nullptr) {
  LoadedMod Out;
  Out.RT = makeRuntime(Lazy, DisableGreedyRA, DisableMT, PrivateTiering,
                       PolicyConfig);
  EXPECT_NE(Out.RT, nullptr);
  auto ModRet = Out.RT->loadModule(Name, Bytes.data(), Bytes.size());
  EXPECT_TRUE(ModRet) << ModRet.getError().getFormattedMessage();
  Out.Mod = *ModRet;
  if (Instantiate) {
    Isolation *Iso = Out.RT->createManagedIsolation();
    EXPECT_NE(Iso, nullptr);
    auto InstRet = Iso->createInstance(*Out.Mod);
    EXPECT_TRUE(InstRet) << InstRet.getError().getFormattedMessage();
    Out.Inst = *InstRet;
  }
  if (Lazy) {
    Out.Lazy = Out.Mod->getLazyJITCompiler();
    EXPECT_NE(Out.Lazy, nullptr);
  }
  return Out;
}

CodeShape bodyShape(Module &Mod, uint32_t FuncIdx) {
  CodeEntry *CE = Mod.getCodeEntry(FuncIdx);
  EXPECT_NE(CE, nullptr);
  EXPECT_NE(CE->JITCodePtr, nullptr);
  const uint8_t *Body = resolvedJitBody(CE->JITCodePtr);
  EXPECT_NE(Body, nullptr) << "lazy stub still on trampoline";
  return scanCodeShapePrefix(Body, kShapePrefixBytes);
}

bool stubIsTrampoline(Module &Mod, uint32_t FuncIdx) {
  CodeEntry *CE = Mod.getCodeEntry(FuncIdx);
  EXPECT_NE(CE, nullptr);
  return resolvedJitBody(CE->JITCodePtr) == nullptr;
}

/// Wait for completed background Greedy publications (not merely started
/// attempts). `getBackgroundPublishCount` is incremented with release after
/// canonical pointer, Done, and stub xchg, so an acquire load that observes
/// Min is a completion barrier for those publishes.
bool waitForBackgroundPublishes(LazyJITCompiler &Lazy, uint32_t Min,
                                int TimeoutMs) {
  const auto Deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(TimeoutMs);
  while (Lazy.getBackgroundPublishCount() < Min) {
    if (std::chrono::steady_clock::now() >= Deadline) {
      return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  return true;
}

struct CompiledFib {
  LoadedMod LM;
  CodeShape Shape;
  int32_t Fib10 = 0;
};

CompiledFib compileAndRunOneFn(bool Lazy, bool DisableGreedyRA,
                               bool DisableMT) {
  CompiledFib Out;
  auto Bytes = loadWasmFile(FIB_ITER_ONEFN_WASM_PATH);
  EXPECT_FALSE(Bytes.empty());
  Out.LM = loadModule(Bytes, "fib", Lazy, DisableGreedyRA, DisableMT);
  Out.Fib10 = callI32(*Out.LM.RT, *Out.LM.Inst, "fib", 10);
  Out.Shape = bodyShape(*Out.LM.Mod, 0);
  return Out;
}

} // namespace

TEST(LazyJitGreedyOndemand, FastRASpillsMoreThanGreedyOnFibLoop) {
  CompiledFib Fast =
      compileAndRunOneFn(/*Lazy=*/false, /*DisableGreedyRA=*/true,
                         /*DisableMT=*/true);
  CompiledFib Greedy = compileAndRunOneFn(
      /*Lazy=*/false, /*DisableGreedyRA=*/false, /*DisableMT=*/true);
  EXPECT_EQ(Fast.Fib10, 55);
  EXPECT_EQ(Greedy.Fib10, 55);
  EXPECT_GT(Fast.Shape.RbpStores, Greedy.Shape.RbpStores)
      << "prefix heuristic FastRA rbp-stores=" << Fast.Shape.RbpStores
      << " Greedy rbp-stores=" << Greedy.Shape.RbpStores
      << " FastRA sub=" << Fast.Shape.StackSub
      << " Greedy sub=" << Greedy.Shape.StackSub;
  EXPECT_GE(Fast.Shape.StackSub, Greedy.Shape.StackSub);
}

TEST(LazyJitGreedyOndemand, LazyMtOneFnHasNoBackgroundPool) {
  auto Bytes = loadWasmFile(FIB_ITER_ONEFN_WASM_PATH);
  ASSERT_FALSE(Bytes.empty());
  LoadedMod LM = loadModule(Bytes, "fib1", /*Lazy=*/true,
                            /*DisableGreedyRA=*/false, /*DisableMT=*/false);
  ASSERT_NE(LM.Mod, nullptr);
  ASSERT_NE(LM.Lazy, nullptr);
  EXPECT_EQ(LM.Mod->getNumInternalFunctions(), 1u);
  EXPECT_FALSE(LM.Lazy->hasBackgroundCompilePool());
  EXPECT_EQ(LM.Lazy->getForegroundCompileCount(), 0u);
  EXPECT_EQ(LM.Lazy->getBackgroundCompileCount(), 0u);
  EXPECT_EQ(LM.Lazy->getBackgroundPublishCount(), 0u);
  EXPECT_TRUE(stubIsTrampoline(*LM.Mod, 0));

  EXPECT_EQ(callI32(*LM.RT, *LM.Inst, "fib", 10), 55);
  EXPECT_FALSE(LM.Lazy->hasBackgroundCompilePool());
  EXPECT_EQ(LM.Lazy->getForegroundCompileCount(), 1u);
  EXPECT_EQ(LM.Lazy->getBackgroundCompileCount(), 0u);
  EXPECT_EQ(LM.Lazy->getBackgroundPublishCount(), 0u);
  EXPECT_FALSE(stubIsTrampoline(*LM.Mod, 0));

  CompiledFib Greedy = compileAndRunOneFn(
      /*Lazy=*/false, /*DisableGreedyRA=*/false, /*DisableMT=*/true);
  CompiledFib Fast =
      compileAndRunOneFn(/*Lazy=*/false, /*DisableGreedyRA=*/true,
                         /*DisableMT=*/true);
  CodeShape LazyShape = bodyShape(*LM.Mod, 0);
  EXPECT_EQ(LazyShape.RbpStores, Greedy.Shape.RbpStores);
  EXPECT_EQ(LazyShape.StackSub, Greedy.Shape.StackSub);
  EXPECT_NE(LazyShape.RbpStores, Fast.Shape.RbpStores)
      << "litmus is weak if FastRA and Greedy prefix counts match";

  EXPECT_EQ(callI32(*LM.RT, *LM.Inst, "fib", 10), 55);
  EXPECT_EQ(LM.Lazy->getForegroundCompileCount(), 1u)
      << "second call must not recompile";
  EXPECT_EQ(LM.Lazy->getBackgroundCompileCount(), 0u);
  EXPECT_EQ(LM.Lazy->getBackgroundPublishCount(), 0u);

  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  EXPECT_EQ(LM.Lazy->getBackgroundCompileCount(), 0u)
      << "no late background compile after the first call";
  EXPECT_EQ(LM.Lazy->getBackgroundPublishCount(), 0u);
  EXPECT_FALSE(LM.Lazy->hasBackgroundCompilePool());
}

TEST(LazyJitGreedyOndemand, LazyMtOneFnDisableGreedyIsFastRASync) {
  auto Bytes = loadWasmFile(FIB_ITER_ONEFN_WASM_PATH);
  ASSERT_FALSE(Bytes.empty());
  LoadedMod LM = loadModule(Bytes, "fibf", /*Lazy=*/true,
                            /*DisableGreedyRA=*/true, /*DisableMT=*/false);
  ASSERT_NE(LM.Lazy, nullptr);
  EXPECT_EQ(LM.Mod->getNumInternalFunctions(), 1u);
  EXPECT_FALSE(LM.Lazy->hasBackgroundCompilePool());
  EXPECT_EQ(callI32(*LM.RT, *LM.Inst, "fib", 10), 55);
  EXPECT_EQ(LM.Lazy->getForegroundCompileCount(), 1u);
  EXPECT_EQ(LM.Lazy->getBackgroundCompileCount(), 0u);
  EXPECT_EQ(LM.Lazy->getBackgroundPublishCount(), 0u);

  CompiledFib Fast =
      compileAndRunOneFn(/*Lazy=*/false, /*DisableGreedyRA=*/true,
                         /*DisableMT=*/true);
  CompiledFib Greedy = compileAndRunOneFn(
      /*Lazy=*/false, /*DisableGreedyRA=*/false, /*DisableMT=*/true);
  CodeShape LazyShape = bodyShape(*LM.Mod, 0);
  EXPECT_EQ(LazyShape.RbpStores, Fast.Shape.RbpStores);
  EXPECT_EQ(LazyShape.StackSub, Fast.Shape.StackSub);
  EXPECT_GT(LazyShape.RbpStores, Greedy.Shape.RbpStores);
}

TEST(LazyJitGreedyOndemand, LazyMtTwoFnStillTiers) {
  auto Bytes = loadWasmFile(FIB_ITER_TWOFN_WASM_PATH);
  ASSERT_FALSE(Bytes.empty());
  LoadedMod LM = loadModule(Bytes, "fib2", /*Lazy=*/true,
                            /*DisableGreedyRA=*/false, /*DisableMT=*/false);
  ASSERT_NE(LM.Lazy, nullptr);
  EXPECT_EQ(LM.Mod->getNumInternalFunctions(), 2u);
  EXPECT_TRUE(LM.Lazy->hasBackgroundCompilePool())
      << "two-internal-function lazy-MT must keep the Greedy background pool";
  ASSERT_TRUE(waitForBackgroundPublishes(*LM.Lazy, 2, 5000))
      << "timed out waiting for background Greedy publication; started="
      << LM.Lazy->getBackgroundCompileCount()
      << " published=" << LM.Lazy->getBackgroundPublishCount();
  EXPECT_EQ(LM.Lazy->getBackgroundCompileCount(), 2u);
  EXPECT_EQ(LM.Lazy->getBackgroundPublishCount(), 2u);
  EXPECT_EQ(LM.Lazy->getForegroundCompileCount(), 0u);

  for (uint32_t I = 0; I < 2; ++I) {
    EXPECT_FALSE(stubIsTrampoline(*LM.Mod, I))
        << "func " << I << " still on trampoline";
    CodeEntry *CE = LM.Mod->getCodeEntry(I);
    ASSERT_NE(CE, nullptr);
    const uint8_t *Body = resolvedJitBody(CE->JITCodePtr);
    EXPECT_EQ(Body, LM.Lazy->getGreedyRACodePtr(I))
        << "canonical stub must match published GreedyRA body for func " << I;
  }

  EXPECT_EQ(callI32(*LM.RT, *LM.Inst, "fib", 10), 55);
  EXPECT_EQ(callI32(*LM.RT, *LM.Inst, "id", 7), 7);
  EXPECT_EQ(LM.Lazy->getForegroundCompileCount(), 0u)
      << "calls after Greedy publication must not start FastRA";
  EXPECT_EQ(LM.Lazy->getBackgroundPublishCount(), 2u);
  EXPECT_TRUE(LM.Lazy->hasBackgroundCompilePool());
}

TEST(LazyJitGreedyOndemand, LazyStOneFnStillGreedy) {
  CompiledFib LazyST = compileAndRunOneFn(
      /*Lazy=*/true, /*DisableGreedyRA=*/false, /*DisableMT=*/true);
  CompiledFib Greedy = compileAndRunOneFn(
      /*Lazy=*/false, /*DisableGreedyRA=*/false, /*DisableMT=*/true);
  ASSERT_NE(LazyST.LM.Lazy, nullptr);
  EXPECT_FALSE(LazyST.LM.Lazy->hasBackgroundCompilePool());
  EXPECT_EQ(LazyST.LM.Lazy->getBackgroundCompileCount(), 0u);
  EXPECT_EQ(LazyST.LM.Lazy->getBackgroundPublishCount(), 0u);
  EXPECT_EQ(LazyST.LM.Lazy->getForegroundCompileCount(), 1u);
  EXPECT_EQ(LazyST.Fib10, 55);
  EXPECT_EQ(LazyST.Shape.RbpStores, Greedy.Shape.RbpStores);
  EXPECT_EQ(LazyST.Shape.StackSub, Greedy.Shape.StackSub);
}

TEST(LazyJitGreedyOndemand, BackgroundSeedsExcludeDirectAndIndirectCallees) {
  auto Bytes = loadWasmFile(LAZY_ENTRY_SEEDS_WASM_PATH);
  ASSERT_FALSE(Bytes.empty());
  LoadedMod LM = loadModule(Bytes, "seeds", /*Lazy=*/true,
                            /*DisableGreedyRA=*/false, /*DisableMT=*/false,
                            /*Instantiate=*/false);
  ASSERT_NE(LM.Lazy, nullptr);
  ASSERT_EQ(LM.Mod->getNumInternalFunctions(), 8u);
  ASSERT_TRUE(LM.Lazy->hasBackgroundCompilePool());
  ASSERT_TRUE(waitForBackgroundPublishes(*LM.Lazy, 2, 5000));
  EXPECT_EQ(LM.Lazy->getBackgroundCompileCount(), 2u)
      << "start + one unique exported function, despite two export names";
  EXPECT_EQ(LM.Lazy->getForegroundCompileCount(), 0u);
  for (uint32_t I : {0u, 7u}) {
    EXPECT_FALSE(stubIsTrampoline(*LM.Mod, I));
    EXPECT_EQ(resolvedJitBody(LM.Mod->getCodeEntry(I)->JITCodePtr),
              LM.Lazy->getGreedyRACodePtr(I));
  }
  for (uint32_t I = 1; I < 7; ++I) {
    EXPECT_TRUE(stubIsTrampoline(*LM.Mod, I)) << "func " << I;
    EXPECT_EQ(LM.Lazy->getGreedyRACodePtr(I), nullptr) << "func " << I;
  }

  Isolation *Iso = LM.RT->createManagedIsolation();
  ASSERT_NE(Iso, nullptr);
  auto InstRet = Iso->createInstance(*LM.Mod);
  ASSERT_TRUE(InstRet) << InstRet.getError().getFormattedMessage();
  LM.Inst = *InstRet;
  EXPECT_EQ(LM.Lazy->getForegroundCompileCount(), 1u)
      << "only the unexported init helper is demanded at instantiation";
  EXPECT_EQ(callI32(*LM.RT, *LM.Inst, "entry", 7), 32);
  EXPECT_EQ(LM.Lazy->getForegroundCompileCount(), 4u)
      << "init helper plus direct, leaf and selected indirect target";
  EXPECT_EQ(callI32(*LM.RT, *LM.Inst, "entry_alias", 9), 38);
  EXPECT_EQ(LM.Lazy->getForegroundCompileCount(), 4u)
      << "repeated calls must reuse compiled bodies";
  EXPECT_EQ(LM.Lazy->getBackgroundPublishCount(), 2u);
  for (uint32_t I : {5u, 6u}) {
    EXPECT_TRUE(stubIsTrampoline(*LM.Mod, I)) << "cold func " << I;
    EXPECT_EQ(LM.Lazy->getGreedyRACodePtr(I), nullptr);
  }
}

TEST(LazyJitGreedyOndemand, EntrySeedFixtureKeepsEagerAndSerialBehavior) {
  auto Bytes = loadWasmFile(LAZY_ENTRY_SEEDS_WASM_PATH);
  ASSERT_FALSE(Bytes.empty());
  LoadedMod Eager = loadModule(Bytes, "seeds_eager", /*Lazy=*/false,
                               /*DisableGreedyRA=*/false, /*DisableMT=*/true);
  LoadedMod Serial = loadModule(Bytes, "seeds_serial", /*Lazy=*/true,
                                /*DisableGreedyRA=*/false, /*DisableMT=*/true);
  ASSERT_NE(Serial.Lazy, nullptr);
  EXPECT_FALSE(Serial.Lazy->hasBackgroundCompilePool());
  for (int32_t X : {0, 7, -1}) {
    EXPECT_EQ(callI32(*Eager.RT, *Eager.Inst, "entry", X), 3 * X + 11);
    EXPECT_EQ(callI32(*Serial.RT, *Serial.Inst, "entry_alias", X), 3 * X + 11);
  }
  EXPECT_EQ(Serial.Lazy->getBackgroundCompileCount(), 0u);
  for (uint32_t I : {5u, 6u}) {
    EXPECT_TRUE(stubIsTrampoline(*Serial.Mod, I));
    EXPECT_FALSE(stubIsTrampoline(*Eager.Mod, I));
  }
}

TEST(LazyJitGreedyOndemand, NumericNestsChooseGreedyOnFirstDemandOnly) {
  for (bool PrivateTiering : {false, true}) {
    auto Bytes = loadWasmFile(NUMERIC_LOOP_WASM_PATH);
    ASSERT_FALSE(Bytes.empty());
    LoadedMod LM =
        loadModule(Bytes, "numeric", true, false, false, true, PrivateTiering);
    ASSERT_TRUE(waitForBackgroundPublishes(*LM.Lazy, 1, 5000));
    ASSERT_EQ(LM.Lazy->getBackgroundPublishCount(), 1u);
    ASSERT_EQ(LM.Lazy->getForegroundLoopGreedyCount(), 0u);
    for (uint32_t I = 0; I < 7; ++I)
      EXPECT_TRUE(stubIsTrampoline(*LM.Mod, I));
    ASSERT_GT(LM.Mod->getCodeEntry(5)->CodeSize, 2048u);
    ASSERT_LE(LM.Mod->getCodeEntry(5)->CodeSize, 4096u);
    const double Expected[] = {9, 6, 3, 9.5, 9, 9, 9, 9};
    const uint32_t Selected[] = {1, 1, 1, 1, 2, 2, 2, 2};
    for (uint32_t I = 0; I < 8; ++I) {
      std::vector<TypedValue> Results;
      ASSERT_TRUE(LM.RT->callWasmFunction(*LM.Inst, "entry",
                                          {std::to_string(I), "3"}, Results));
      ASSERT_EQ(Results.size(), 1u);
      EXPECT_DOUBLE_EQ(Results[0].Value.F64, Expected[I]);
      EXPECT_EQ(LM.Lazy->getForegroundLoopGreedyCount(), Selected[I]);
      EXPECT_TRUE(stubIsTrampoline(*LM.Mod, 6));
    }
    EXPECT_EQ(LM.Lazy->getBackgroundPublishCount(), 1u);
    const auto Compiles = LM.Lazy->getForegroundCompileCount();
    std::vector<TypedValue> Results;
    ASSERT_TRUE(
        LM.RT->callWasmFunction(*LM.Inst, "alias", {"0", "3"}, Results));
    EXPECT_DOUBLE_EQ(Results[0].Value.F64, 9);
    EXPECT_EQ(LM.Lazy->getForegroundCompileCount(), Compiles);
    EXPECT_EQ(LM.Lazy->getForegroundLoopGreedyCount(), 2u);
  }
}

TEST(LazyJitGreedyOndemand, NumericNestKeepsExplicitFastEagerAndSerialChoices) {
  auto Bytes = loadWasmFile(NUMERIC_LOOP_WASM_PATH);
  for (unsigned Mode = 0; Mode < 3; ++Mode) {
    LoadedMod LM =
        loadModule(Bytes, "numeric_modes", Mode != 1, Mode == 0, Mode != 0);
    std::vector<TypedValue> Results;
    ASSERT_TRUE(
        LM.RT->callWasmFunction(*LM.Inst, "entry", {"0", "3"}, Results));
    ASSERT_EQ(Results.size(), 1u);
    EXPECT_DOUBLE_EQ(Results[0].Value.F64, 9);
    if (LM.Lazy)
      EXPECT_EQ(LM.Lazy->getForegroundLoopGreedyCount(), 0u);
  }
}

TEST(LazyJitGreedyOndemand, DeepWordNestsChooseGreedyOnFirstDemandOnly) {
  auto Bytes = loadWasmFile(WORD_LOOP_WASM_PATH);
  ASSERT_FALSE(Bytes.empty());
  LoadedMod LM = loadModule(Bytes, "words", true, false, false);
  ASSERT_TRUE(waitForBackgroundPublishes(*LM.Lazy, 1, 5000));
  ASSERT_EQ(LM.Lazy->getForegroundLoopGreedyCount(), 0u);
  for (uint32_t I = 0; I < 14; ++I)
    EXPECT_TRUE(stubIsTrampoline(*LM.Mod, I));
  ASSERT_GT(LM.Mod->getCodeEntry(9)->CodeSize, 2048u);
  const uint32_t Expected[] = {27, 27, 9, 27, 27, 27, 3, 27, 27, 27, 27, 81};
  const uint32_t Selected[] = {1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};
  for (uint32_t I = 0; I < 12; ++I) {
    std::vector<TypedValue> Results;
    ASSERT_TRUE(LM.RT->callWasmFunction(*LM.Inst, "entry",
                                        {std::to_string(I), "3"}, Results));
    ASSERT_EQ(Results.size(), 1u);
    EXPECT_EQ(Results[0].Value.I32, Expected[I]);
    EXPECT_EQ(LM.Lazy->getForegroundLoopGreedyCount(), Selected[I]);
    EXPECT_TRUE(stubIsTrampoline(*LM.Mod, 8));
  }
  EXPECT_EQ(LM.Lazy->getBackgroundPublishCount(), 1u);
  const auto Compiles = LM.Lazy->getForegroundCompileCount();
  std::vector<TypedValue> Results;
  ASSERT_TRUE(LM.RT->callWasmFunction(*LM.Inst, "alias", {"0", "3"}, Results));
  ASSERT_EQ(Results.size(), 1u);
  EXPECT_EQ(Results[0].Value.I32, 27u);
  EXPECT_EQ(LM.Lazy->getForegroundCompileCount(), Compiles);
}

TEST(LazyJitGreedyOndemand, DeepWordKeepsExplicitFastEagerAndSerialChoices) {
  auto Bytes = loadWasmFile(WORD_LOOP_WASM_PATH);
  for (unsigned Mode = 0; Mode < 3; ++Mode) {
    LoadedMod LM =
        loadModule(Bytes, "word_modes", Mode != 1, Mode == 0, Mode != 0);
    std::vector<TypedValue> Results;
    ASSERT_TRUE(
        LM.RT->callWasmFunction(*LM.Inst, "entry", {"0", "3"}, Results));
    ASSERT_EQ(Results.size(), 1u);
    EXPECT_EQ(Results[0].Value.I32, 27u);
    if (LM.Lazy)
      EXPECT_EQ(LM.Lazy->getForegroundLoopGreedyCount(), 0u);
  }
}

TEST(LazyJitGreedyOndemand, InitialGreedyPressureSkipsPrivateFastProfiling) {
  auto Bytes = loadWasmFile(NUMERIC_LOOP_WASM_PATH);
  LoadedMod LM = loadModule(Bytes, "pressure", true, false, false, true, true);
  ASSERT_TRUE(waitForBackgroundPublishes(*LM.Lazy, 1, 5000));
  for (uint32_t I = 0; I < 10; ++I) {
    std::vector<TypedValue> Results;
    ASSERT_TRUE(
        LM.RT->callWasmFunction(*LM.Inst, "entry", {"8", "3"}, Results));
    ASSERT_EQ(Results.size(), 1u);
    EXPECT_DOUBLE_EQ(Results[0].Value.F64, 390);
  }
  EXPECT_EQ(LM.Lazy->getForegroundLoopGreedyCount(), 1u);
  EXPECT_EQ(LM.Lazy->getForegroundCompileCount(), 1u);
  const auto Stats = LM.Lazy->getPrivateTieringStats();
  EXPECT_EQ(Stats.AdmittedFunctions, 0u);
  EXPECT_EQ(Stats.ProfilingPublishes, 0u);
  EXPECT_EQ(Stats.GreedyPublishes, 0u);
}

TEST(LazyJitGreedyOndemand, InitialPolicySizeAndDisableGuards) {
  auto Bytes = loadWasmFile(WORD_LOOP_WASM_PATH);
  for (unsigned Guard = 0; Guard < 4; ++Guard) {
    RuntimeConfig Policy;
    Policy.DisableLazyAutoGreedy = Guard == 0;
    Policy.LazyAutoGreedyMaxModuleBytes =
        Guard == 1 ? Bytes.size() - 1 : Bytes.size();
    Policy.LazyAutoGreedyMaxFunctionBytes = Guard == 2 ? 1 : 2048;
    LoadedMod LM = loadModule(Bytes, "guarded_words", true, false, false, true,
                              false, &Policy);
    ASSERT_EQ(LM.Mod->getBinarySize(), Bytes.size());
    ASSERT_TRUE(waitForBackgroundPublishes(*LM.Lazy, 1, 5000));
    std::vector<TypedValue> Results;
    ASSERT_TRUE(
        LM.RT->callWasmFunction(*LM.Inst, "entry", {"0", "3"}, Results));
    ASSERT_EQ(Results.size(), 1u);
    EXPECT_EQ(Results[0].Value.I32, 27u);
    EXPECT_EQ(LM.Lazy->getForegroundLoopGreedyCount(), Guard == 3 ? 1u : 0u);
    EXPECT_EQ(LM.Lazy->getBackgroundPublishCount(), 1u);
  }
}

TEST(WasmBucketMemory, GrowthPreservesPrefixZeroesAndInstanceIsolation) {
  auto Bytes = loadWasmFile(BUCKET_GROW_WASM_PATH);
  auto RT = makeRuntime(false, false, true);
  ASSERT_NE(RT, nullptr);
  auto ModRet = RT->loadModule("bucket_growth", Bytes.data(), Bytes.size());
  ASSERT_TRUE(ModRet);
  auto *Mod = *ModRet;
  auto *Iso = RT->createManagedIsolation();
  ASSERT_NE(Iso, nullptr);
  auto ARet = Iso->createInstance(*Mod);
  auto BRet = Iso->createInstance(*Mod);
  ASSERT_TRUE(ARet);
  ASSERT_TRUE(BRet);
  auto *A = *ARet;
  auto *B = *BRet;
  if (A->getDefaultMemoryInst().Kind !=
      zen::runtime::WM_MEMORY_DATA_TYPE_BUCKET_MMAP)
    GTEST_SKIP() << "bucket mmap is unavailable on this platform";
  auto Call = [&](Instance *Inst, const char *Name,
                  std::vector<std::string> Args) -> uint32_t {
    std::vector<TypedValue> Results;
    const bool OK = RT->callWasmFunction(*Inst, Name, Args, Results);
    EXPECT_TRUE(OK);
    if (!OK || Results.empty())
      return 0;
    return Results[0].Value.I32;
  };
  auto Write = [&](Instance *Inst, const char *Addr, const char *Value) {
    std::vector<TypedValue> Results;
    EXPECT_TRUE(RT->callWasmFunction(*Inst, "write", {Addr, Value}, Results));
  };
  auto *Base = A->getDefaultMemoryInst().MemBase;
  Write(A, "0", "123");
  EXPECT_EQ(Call(A, "grow", {"2"}), 1u);
  EXPECT_EQ(A->getDefaultMemoryInst().MemBase, Base);
  EXPECT_EQ(Call(A, "read", {"0"}), 123u);
  EXPECT_EQ(Call(B, "read", {"0"}), 42u);
  EXPECT_EQ(Call(A, "read", {"65535"}), 222u);
  EXPECT_EQ(Call(A, "scan", {"65536", "196608"}), 0u);
  Write(A, "65536", "91");
  Write(A, "196607", "92");
  EXPECT_EQ(Call(B, "grow", {"2"}), 1u);
  EXPECT_EQ(Call(B, "scan", {"65536", "196608"}), 0u);
  Write(B, "65536", "177");
  EXPECT_EQ(Call(A, "read", {"65536"}), 91u);
  EXPECT_EQ(Call(B, "read", {"65536"}), 177u);
  EXPECT_EQ(Call(A, "grow", {"0"}), 3u);
  EXPECT_EQ(Call(A, "grow", {"1"}), 3u);
  EXPECT_EQ(A->getDefaultMemoryInst().MemBase, Base);
  EXPECT_EQ(Call(A, "read", {"196607"}), 92u);
  EXPECT_EQ(Call(A, "scan", {"196608", "262144"}), 0u);
  EXPECT_EQ(Call(A, "grow", {"2000"}), UINT32_MAX);
  EXPECT_EQ(A->getDefaultMemoryInst().CurPages, 4u);
  EXPECT_EQ(Call(A, "read", {"65536"}), 91u);
  std::vector<TypedValue> Results;
  EXPECT_FALSE(RT->callWasmFunction(*A, "read", {"262144"}, Results));
  A->clearError();
  EXPECT_EQ(Call(A, "read", {"65535"}), 222u);
}

TEST(WasmBucketMemory, SlotRetirementAndLargerMappingFallbackStayZero) {
  auto Bytes = loadWasmFile(BUCKET_GROW_WASM_PATH);
  auto RT = makeRuntime(false, false, true);
  ASSERT_NE(RT, nullptr);
  auto ModRet = RT->loadModule("bucket_retirement", Bytes.data(), Bytes.size());
  ASSERT_TRUE(ModRet);
  auto *Mod = *ModRet;
  auto *Iso = RT->createManagedIsolation();
  ASSERT_NE(Iso, nullptr);
  auto Call = [&](Instance *Inst, const char *Name,
                  std::vector<std::string> Args) -> uint32_t {
    std::vector<TypedValue> Results;
    const bool OK = RT->callWasmFunction(*Inst, Name, Args, Results);
    EXPECT_TRUE(OK);
    if (!OK || Results.empty())
      return 0;
    return Results[0].Value.I32;
  };
  for (unsigned I = 0; I < 12; ++I) {
    auto Ret = Iso->createInstance(*Mod);
    ASSERT_TRUE(Ret);
    auto *Inst = *Ret;
    if (Inst->getDefaultMemoryInst().Kind !=
        zen::runtime::WM_MEMORY_DATA_TYPE_BUCKET_MMAP)
      GTEST_SKIP() << "bucket mmap is unavailable on this platform";
    EXPECT_EQ(Call(Inst, "read", {"0"}), 42u);
    EXPECT_EQ(Call(Inst, "read", {"65535"}), 222u);
    EXPECT_EQ(Call(Inst, "grow", {"1"}), 1u);
    EXPECT_EQ(Call(Inst, "scan", {"65536", "131072"}), 0u);
    std::vector<TypedValue> Results;
    ASSERT_TRUE(RT->callWasmFunction(*Inst, "write", {"65536", "99"}, Results));
    EXPECT_TRUE(Iso->deleteInstance(Inst));
  }
  auto Ret = Iso->createInstance(*Mod);
  ASSERT_TRUE(Ret);
  auto *Inst = *Ret;
  auto *Base = Inst->getDefaultMemoryInst().MemBase;
  EXPECT_EQ(Call(Inst, "grow", {"512"}), 1u);
  EXPECT_EQ(Inst->getDefaultMemoryInst().Kind,
            zen::runtime::WM_MEMORY_DATA_TYPE_SINGLE_MMAP);
  EXPECT_NE(Inst->getDefaultMemoryInst().MemBase, Base);
  EXPECT_EQ(Call(Inst, "read", {"0"}), 42u);
  EXPECT_EQ(Call(Inst, "read", {"65535"}), 222u);
  EXPECT_EQ(Call(Inst, "read", {"65536"}), 0u);
  EXPECT_EQ(Call(Inst, "read", {"33619967"}), 0u);
}
