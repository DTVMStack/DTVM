// Copyright (C) 2026 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "compiler/compiler.h"
#include "compiler/lazy_promotion_budget.h"
#include "compiler/stub/stub_builder.h"
#include "runtime/isolation.h"
#include "runtime/module.h"
#include "runtime/runtime.h"
#include <atomic>
#include <chrono>
#include <fstream>
#include <gtest/gtest.h>
#include <stdexcept>
#include <thread>
#include <vector>

using namespace COMPILER;
using namespace zen::runtime;
using namespace zen::common;
namespace {
RuntimeConfig tierConfig() {
  RuntimeConfig C;
  C.Mode = RunMode::MultipassMode;
#ifdef ZEN_ENABLE_BUILTIN_WASI
  C.DisableWASI = true;
#endif
  C.EnableMultipassLazy = true;
  C.EnableLazyPrivateTiering = true;
  C.LazyTierPolicy = LazyPrivateTierPolicy::Loops;
  C.LazyTierCallThreshold = 4;
  C.LazyTierLoopThreshold = 64;
  C.LazyTierBudgetMs = 1000;
  C.NumMultipassThreads = 2;
  return C;
}
struct Fixture {
  std::unique_ptr<Runtime> RT;
  Module *Mod = nullptr;
  Instance *Inst = nullptr;
  explicit Fixture(RuntimeConfig C) : RT(Runtime::newRuntime(C)) {
    EXPECT_NE(RT, nullptr);
    if (!RT)
      return;
    std::ifstream In(PRIVATE_TIER_WASM_PATH, std::ios::binary);
    std::vector<uint8_t> Bytes((std::istreambuf_iterator<char>(In)), {});
    auto M = RT->loadModule("private-tier", Bytes.data(), Bytes.size());
    EXPECT_TRUE(M);
    if (!M)
      return;
    Mod = *M;
    auto *Iso = RT->createManagedIsolation();
    auto I = Iso->createInstance(*Mod);
    EXPECT_TRUE(I);
    if (I)
      Inst = *I;
  }
  LazyJITCompiler *compiler() { return Mod->getLazyJITCompiler(); }
  double repeat(uint32_t Count, uint32_t Trips) {
    std::vector<TypedValue> R;
    EXPECT_TRUE(RT->callWasmFunction(
        *Inst, "repeat", {std::to_string(Count), std::to_string(Trips)}, R));
    EXPECT_FALSE(Inst->hasError());
    return R.empty() ? -1 : R[0].Value.F64;
  }
};
double expected(uint32_t Count, uint32_t Trips) {
  uint64_t X = 1, Sum = 0;
  for (uint32_t I = 0; I < Trips; ++I) {
    X = (X * 1664525 + 1013904223) & 1023;
    Sum += X;
  }
  return Count * (double(Sum + 36) + 11.25);
}
} // namespace

TEST(LazyPrivateTiering, PreservesRegisterAndStackArgumentsAcrossBothTiers) {
  for (auto Policy :
       {LazyPrivateTierPolicy::Calls, LazyPrivateTierPolicy::Loops,
        LazyPrivateTierPolicy::Budgeted}) {
    auto C = tierConfig();
    C.LazyTierPolicy = Policy;
    const uint32_t Count =
        Policy == LazyPrivateTierPolicy::Budgeted ? 4096 : 128;
    Fixture F(C);
    ASSERT_NE(F.Inst, nullptr);
    for (unsigned I = 0; I < 1000; ++I) {
      EXPECT_DOUBLE_EQ(F.repeat(Count, 64), expected(Count, 64));
      if (F.compiler()->getPrivateTieringStats().GreedyPublishes)
        break;
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    auto S = F.compiler()->getPrivateTieringStats();
    EXPECT_EQ(S.AdmittedFunctions, 1u);
    EXPECT_EQ(S.GreedyPublishes, 1u);
    EXPECT_EQ(S.ProfilingPublishes,
              Policy == LazyPrivateTierPolicy::Calls ? 0u : 1u);
    EXPECT_DOUBLE_EQ(F.repeat(Count, 64), expected(Count, 64));
  }
}
TEST(LazyPrivateTiering, OneShotLoopNeverGetsBackedgeInstrumentation) {
  auto C = tierConfig();
  C.LazyTierCallThreshold = 100;
  Fixture F(C);
  ASSERT_NE(F.Inst, nullptr);
  EXPECT_DOUBLE_EQ(F.repeat(1, 100000), expected(1, 100000));
  auto S = F.compiler()->getPrivateTieringStats();
  EXPECT_EQ(S.AdmittedFunctions, 0u);
  EXPECT_EQ(S.ProfilingPublishes, 0u);
  EXPECT_EQ(S.GreedyPublishes, 0u);
}
TEST(LazyPrivateTiering,
     DisabledSerialExplicitFastAndZeroBudgetsKeepPolicyInactive) {
  for (unsigned Mode = 0; Mode < 7; ++Mode) {
    auto C = tierConfig();
    if (Mode == 0)
      C.EnableLazyPrivateTiering = false;
    if (Mode == 1)
      C.DisableMultipassMultithread = true;
    if (Mode == 2)
      C.DisableMultipassGreedyRA = true;
    if (Mode == 3)
      C.LazyTierMaxFunctions = 0;
    if (Mode == 4)
      C.LazyTierBudgetMs = 0;
    if (Mode == 5)
      C.LazyTierMaxBytes = 1;
    if (Mode == 6)
      C.LazyTierMaxFunctionBytes = 1;
    Fixture F(C);
    ASSERT_NE(F.Inst, nullptr);
    EXPECT_DOUBLE_EQ(F.repeat(64, 16), expected(64, 16));
    EXPECT_EQ(F.compiler()->getPrivateTieringStats().AdmittedFunctions, 0u);
  }
}
TEST(LazyPrivateTiering, ProfitabilityGateCanRejectObservedLoopHeat) {
  auto C = tierConfig();
  C.LazyTierPolicy = LazyPrivateTierPolicy::Budgeted;
  C.LazyTierBenefitRatio = 0xffffffffu;
  Fixture F(C);
  ASSERT_NE(F.Inst, nullptr);
  for (unsigned I = 0; I < 20; ++I) {
    EXPECT_DOUBLE_EQ(F.repeat(64, 16), expected(64, 16));
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  EXPECT_EQ(F.compiler()->getPrivateTieringStats().ProfilingPublishes, 1u);
  EXPECT_GT(F.compiler()->getObservedLoopHeat(0), 0u);
  EXPECT_EQ(F.compiler()->getPrivateTieringStats().GreedyPublishes, 0u);
}
TEST(LazyPrivateBudget, HardLimitsRemainBoundedUnderContention) {
  for (uint32_t MaxFunctions : {2u, 4u}) {
    LazyPromotionBudget B(MaxFunctions, 1000, 1000000000);
    std::atomic<unsigned> Admitted{0};
    std::vector<std::thread> Threads;
    for (unsigned I = 0; I < 8; ++I)
      Threads.emplace_back([&] {
        for (unsigned J = 0; J < 100; ++J)
          if (B.tryReserve(300))
            ++Admitted;
      });
    for (auto &T : Threads)
      T.join();
    EXPECT_EQ(Admitted.load(), std::min(MaxFunctions, 3u));
    EXPECT_EQ(B.getBytes(), std::min(MaxFunctions, 3u) * 300u);
  }
}
TEST(LazyPrivateBudget,
     FailedCompilationIsStillChargedAndSoftCapStopsNextTask) {
  LazyPromotionBudget B(4, 1000, 1);
  EXPECT_THROW(B.runIfTimeAvailable([] {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    throw std::runtime_error("test compilation failure");
  }),
               std::runtime_error);
  EXPECT_GT(B.getTimeNs(), 0u);
  bool Ran = false;
  EXPECT_FALSE(B.runIfTimeAvailable([&] { Ran = true; }));
  EXPECT_FALSE(Ran);
}
TEST(LazyPrivateGate, ConcurrentColdCrossingRunsCallbackOnce) {
  struct Cookie {
    uint8_t *Gate = nullptr;
    std::atomic<unsigned> Hits{0};
  } C;
  CodeMemPool Pool;
  JITStubBuilder Builder(Pool);
  alignas(8) std::atomic<uint64_t> Remaining{32};
  auto Callback = +[](void *P) noexcept {
    auto *C = static_cast<Cookie *>(P);
    ++C->Hits;
    JITStubBuilder::stopLoopCounterGate(C->Gate);
  };
  C.Gate = Builder.compileLoopCounterGate(
      reinterpret_cast<uint64_t *>(&Remaining), &C, Callback);
  auto Fn = reinterpret_cast<void (*)()>(C.Gate);
  std::vector<std::thread> Threads;
  for (unsigned I = 0; I < 4; ++I)
    Threads.emplace_back([&] {
      for (unsigned J = 0; J < 1000; ++J)
        Fn();
    });
  for (auto &T : Threads)
    T.join();
  EXPECT_EQ(C.Hits.load(), 1u);
}
