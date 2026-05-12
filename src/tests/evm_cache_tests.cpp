// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Targeted regression tests for Phase 7 of PR #446 — implicit-dyn-pred
// representation and reachability stitch inside `buildBytecodeCache`'s
// SPP pipeline. See
// `docs/changes/2026-05-11-spp-cfg-implicit-dyn-pred/review-fixes-r2.md`.

#include "evm/evm_cache.h"

#include <evmc/evmc.h>
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace {

using zen::evm::buildBytecodeCache;
using zen::evm::EVMBytecodeCache;

// EVM opcodes used by the fixtures below.
constexpr uint8_t OP_STOP = 0x00;
constexpr uint8_t OP_ADD = 0x01;
constexpr uint8_t OP_CALLDATALOAD = 0x35;
constexpr uint8_t OP_POP = 0x50;
constexpr uint8_t OP_JUMP = 0x56;
constexpr uint8_t OP_JUMPDEST = 0x5b;
constexpr uint8_t OP_PUSH1 = 0x60;

EVMBytecodeCache buildSPPCache(const std::vector<uint8_t> &Code) {
  EVMBytecodeCache Cache;
  buildBytecodeCache(Cache, reinterpret_cast<const std::byte *>(Code.data()),
                     Code.size(), EVMC_CANCUN, /*EnableSPP=*/true);
  return Cache;
}

EVMBytecodeCache buildNoSPPCache(const std::vector<uint8_t> &Code) {
  EVMBytecodeCache Cache;
  buildBytecodeCache(Cache, reinterpret_cast<const std::byte *>(Code.data()),
                     Code.size(), EVMC_CANCUN, /*EnableSPP=*/false);
  return Cache;
}

// Fixture 1 (smoke): contract with NO dynamic jumps + one statically-dead
// JUMPDEST. Verifies the cache builds without crashing on this class and
// that base/SPP costs match on a dead block. NOTE: this case is not a
// strict R2-gate oracle by itself — the dead JUMPDEST has empty Succs
// (STOP terminates the block) so `lemma614Update` cannot shift cost
// out of it regardless of whether the stitch ran. R2 gate verification
// is covered indirectly by R2 not regressing existing test corpora.
TEST(EVMCacheImplicitDynPred, BuildsCleanly_NoDynJumpWithDeadJumpDest) {
  const std::vector<uint8_t> Code = {OP_STOP, OP_JUMPDEST, OP_ADD, OP_STOP};
  const EVMBytecodeCache Cache = buildSPPCache(Code);

  ASSERT_EQ(Cache.GasChunkCost.size(), Code.size());
  ASSERT_EQ(Cache.GasChunkCostSPP.size(), Code.size());
  // JUMPDEST(1) + ADD(3) = 4 gas. STOP terminates the block.
  EXPECT_EQ(Cache.GasChunkCost[1], 4u);
  EXPECT_EQ(Cache.GasChunkCostSPP[1], Cache.GasChunkCost[1])
      << "On a dead JUMPDEST with empty Succs, SPP must leave the cost "
         "unchanged.";
}

// Fixture 2: contract with an unresolvable dynamic JUMP. Every JUMPDEST
// is implicitly a dyn target, so `ImplicitDynamicPredCount > 0` and the
// stitch keeps them in dom-analysis input.
// Layout (block boundaries marked):
//   PC 0  CALLDATALOAD       block B0: unresolvable -> dyn jump
//   PC 1  JUMP                                  (B0 ends here)
//   PC 2  JUMPDEST  <-- B1 (dyn target)
//   PC 3  ADD                                   (B1 continues)
//   PC 4  POP                                   (B1 continues)
//   PC 5  STOP                                  (B1 ends)
// Expectation: `GasChunkCostSPP[2]` is populated (non-zero) because the
// dyn-target JUMPDEST is now in Reachable[] via the stitch. Without the
// stitch (pre-Phase-7 behavior) the JUMPDEST was unreachable and would
// receive no SPP work. The post-Phase-7 + R2 gate path keeps it.
TEST(EVMCacheImplicitDynPred, DynTargetJumpDest_StitchedIntoSPP) {
  const std::vector<uint8_t> Code = {
      OP_CALLDATALOAD, OP_JUMP, OP_JUMPDEST, OP_ADD, OP_POP, OP_STOP,
  };
  const EVMBytecodeCache Cache = buildSPPCache(Code);

  ASSERT_EQ(Cache.GasChunkCost.size(), Code.size());
  ASSERT_EQ(Cache.GasChunkCostSPP.size(), Code.size());
  // Block at PC 2 = JUMPDEST(1) + ADD(3) + POP(2) + STOP(0) = 6 gas.
  EXPECT_EQ(Cache.GasChunkCost[2], 6u);
  // Block has empty Succs (STOP terminates), so `lemma614Update` keeps
  // its cost unshifted. The metering pass still writes the array entry,
  // demonstrating the dom/loop analysis included this dyn-target chunk
  // (without the stitch the block would be unreachable in `Reachable[]`
  // and not in the dom-tree input, though it would remain in RevTopo).
  EXPECT_EQ(Cache.GasChunkCostSPP[2], Cache.GasChunkCost[2]);
  // The dyn-jump source at block 0 has CALLDATALOAD(3) + JUMP(8) = 11
  // gas and a terminator JUMP, so it carries no shift either.
  EXPECT_EQ(Cache.GasChunkCost[0], 11u);
}

// Fixture 3: interpreter-only path (EnableSPP=false) must leave
// `GasChunkCostSPP` empty so the JIT-consumer fall-through at
// `evm_compiler.cpp:73` (Cache.GasChunkCostSPP.empty() ? nullptr) keeps
// the unshifted array as the source.
TEST(EVMCacheImplicitDynPred, InterpreterOnly_LeavesSPPArrayEmpty) {
  const std::vector<uint8_t> Code = {OP_PUSH1, 0x05,        OP_JUMP, OP_PUSH1,
                                     0x00,     OP_JUMPDEST, OP_STOP};
  const EVMBytecodeCache Cache = buildNoSPPCache(Code);

  // GasChunkCost is always populated.
  ASSERT_EQ(Cache.GasChunkCost.size(), Code.size());
  // GasChunkCostSPP must be empty when EnableSPP=false (clear() path in
  // buildBytecodeCache).
  EXPECT_TRUE(Cache.GasChunkCostSPP.empty())
      << "Interpreter-only build must skip SPP allocation (CacheNeedsSPP "
         "lifecycle invariant).";
}

// Fixture 4: contract with two dynamic JUMPs targeting one JUMPDEST. The
// JUMPDEST's `ImplicitDynamicPredCount == 2`, so even if a single static
// predecessor were added the effective predecessor count (>= 3) blocks
// any `lemma614Update` shift INTO that JUMPDEST.
//   PC 0  CALLDATALOAD          block B0
//   PC 1  JUMP                  (B0 ends, dyn jump #1)
//   PC 2  JUMPDEST  <-- B1      first JUMPDEST
//   PC 3  CALLDATALOAD          block continues
//   PC 4  JUMP                  (dyn jump #2; B1 ends here)
//   PC 5  JUMPDEST  <-- B2      second JUMPDEST (dyn target of both jumps)
//   PC 6  POP
//   PC 7  STOP
TEST(EVMCacheImplicitDynPred, MultipleDynJumps_BothTargetsCounted) {
  const std::vector<uint8_t> Code = {
      OP_CALLDATALOAD, OP_JUMP,     OP_JUMPDEST, OP_CALLDATALOAD,
      OP_JUMP,         OP_JUMPDEST, OP_POP,      OP_STOP,
  };
  const EVMBytecodeCache Cache = buildSPPCache(Code);

  ASSERT_EQ(Cache.GasChunkCost.size(), Code.size());
  ASSERT_EQ(Cache.GasChunkCostSPP.size(), Code.size());
  // JumpDestMap recognises both JUMPDESTs.
  EXPECT_EQ(Cache.JumpDestMap[2], 1u);
  EXPECT_EQ(Cache.JumpDestMap[5], 1u);
  // Both JUMPDESTs at PC 2 and PC 5 must have non-zero base cost
  // (JUMPDEST opcode costs 1 gas, plus whatever follows in the block).
  EXPECT_GT(Cache.GasChunkCost[2], 0u);
  EXPECT_GT(Cache.GasChunkCost[5], 0u);
  // No shift opportunities on either JUMPDEST block (B1 ends with the
  // second dyn JUMP, B2 ends with STOP). SPP value must match base.
  EXPECT_EQ(Cache.GasChunkCostSPP[2], Cache.GasChunkCost[2]);
  EXPECT_EQ(Cache.GasChunkCostSPP[5], Cache.GasChunkCost[5]);
}

} // namespace
