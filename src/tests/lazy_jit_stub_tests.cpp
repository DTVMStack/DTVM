// Copyright (C) 2021-2026 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/stub/stub_jmp_target.h"

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <thread>

namespace {

using COMPILER::stub_jmp::computeRel32;
using COMPILER::stub_jmp::kTrampolineRel32;
using COMPILER::stub_jmp::loadRel32;
using COMPILER::stub_jmp::tryUpdateTargetIfTrampoline;
using COMPILER::stub_jmp::updateTarget;

void initTrampolineStub(uint8_t *Stub) {
  std::memset(Stub, 0xcc, 16);
  Stub[0] = 0xe9; // jmp rel32
  int32_t Rel32 = kTrampolineRel32;
  std::memcpy(Stub + 1, &Rel32, sizeof(Rel32));
}

} // namespace

TEST(LazyJitStubPublish, FastRACasFromTrampolineThenGreedyUpgrade) {
  alignas(16) uint8_t Stub[16];
  initTrampolineStub(Stub);
  uint8_t *FastRA = Stub + 0x100;
  uint8_t *GreedyRA = Stub + 0x200;
  const int32_t FastRARel = computeRel32(Stub, FastRA);
  const int32_t GreedyRel = computeRel32(Stub, GreedyRA);

  EXPECT_TRUE(tryUpdateTargetIfTrampoline(Stub, FastRA));
  EXPECT_EQ(loadRel32(Stub), FastRARel);

  // Second FastRA must not overwrite an already-published compiled body.
  uint8_t *FastRA2 = Stub + 0x180;
  EXPECT_FALSE(tryUpdateTargetIfTrampoline(Stub, FastRA2));
  EXPECT_EQ(loadRel32(Stub), FastRARel);

  // Background GreedyRA may upgrade trampoline or FastRA unconditionally.
  updateTarget(Stub, GreedyRA);
  EXPECT_EQ(loadRel32(Stub), GreedyRel);

  // FastRA after GreedyRA must not downgrade the stub.
  EXPECT_FALSE(tryUpdateTargetIfTrampoline(Stub, FastRA));
  EXPECT_EQ(loadRel32(Stub), GreedyRel);
}

TEST(LazyJitStubPublish, ConcurrentFastRACannotDowngradeGreedy) {
  // Litmus: FG CAS-from-trampoline vs BG unconditional GreedyRA xchg.
  // Final stub target must be GreedyRA whenever BG publishes (always here).
  constexpr int kIters = 200;
  for (int I = 0; I < kIters; ++I) {
    alignas(16) uint8_t Stub[16];
    initTrampolineStub(Stub);
    uint8_t *FastRA = Stub + 0x100;
    uint8_t *GreedyRA = Stub + 0x200;
    const int32_t GreedyRel = computeRel32(Stub, GreedyRA);
    std::atomic<int> Ready{0};

    std::thread FG([&] {
      while (Ready.load(std::memory_order_acquire) == 0) {
      }
      tryUpdateTargetIfTrampoline(Stub, FastRA);
    });
    std::thread BG([&] {
      while (Ready.load(std::memory_order_acquire) == 0) {
      }
      updateTarget(Stub, GreedyRA);
    });
    Ready.store(1, std::memory_order_release);
    FG.join();
    BG.join();

    EXPECT_EQ(loadRel32(Stub), GreedyRel);
  }
}
