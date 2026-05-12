// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Regression tests for buildBytecodeCache's SPP pipeline: implicit
// dyn-pred count + reachability stitch on dyn-target JUMPDESTs.

#include "evm/evm_cache.h"
#include "evm/evm_cache_for_testing.h"

#include <evmc/evmc.h>
#include <evmc/instructions.h>
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace {

using zen::evm::buildBytecodeCache;
using zen::evm::EVMBytecodeCache;

constexpr uint8_t OP_STOP = static_cast<uint8_t>(evmc_opcode::OP_STOP);
constexpr uint8_t OP_ADD = static_cast<uint8_t>(evmc_opcode::OP_ADD);
constexpr uint8_t OP_CALLDATALOAD =
    static_cast<uint8_t>(evmc_opcode::OP_CALLDATALOAD);
constexpr uint8_t OP_POP = static_cast<uint8_t>(evmc_opcode::OP_POP);
constexpr uint8_t OP_JUMP = static_cast<uint8_t>(evmc_opcode::OP_JUMP);
constexpr uint8_t OP_JUMPDEST = static_cast<uint8_t>(evmc_opcode::OP_JUMPDEST);
constexpr uint8_t OP_PUSH1 = static_cast<uint8_t>(evmc_opcode::OP_PUSH1);

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

// Smoke: no dynamic jumps + a statically-dead JUMPDEST must not crash;
// SPP must leave the dead block's cost unchanged (empty Succs, nothing
// to shift out).
TEST(EVMCacheImplicitDynPred, BuildsCleanly_NoDynJumpWithDeadJumpDest) {
  const std::vector<uint8_t> Code = {OP_STOP, OP_JUMPDEST, OP_ADD, OP_STOP};
  const EVMBytecodeCache Cache = buildSPPCache(Code);

  ASSERT_EQ(Cache.GasChunkCost.size(), Code.size());
  ASSERT_EQ(Cache.GasChunkCostSPP.size(), Code.size());
  // JUMPDEST(1) + ADD(3) = 4 gas.
  EXPECT_EQ(Cache.GasChunkCost[1], 4u);
  EXPECT_EQ(Cache.GasChunkCostSPP[1], Cache.GasChunkCost[1]);
}

// A JUMPDEST reachable only via an unresolved dynamic jump must still
// land in dom-analysis input via the reachability stitch, so its SPP
// entry is populated.
TEST(EVMCacheImplicitDynPred, DynTargetJumpDest_StitchedIntoSPP) {
  const std::vector<uint8_t> Code = {
      OP_CALLDATALOAD, OP_JUMP, OP_JUMPDEST, OP_ADD, OP_POP, OP_STOP,
  };
  const EVMBytecodeCache Cache = buildSPPCache(Code);

  ASSERT_EQ(Cache.GasChunkCost.size(), Code.size());
  ASSERT_EQ(Cache.GasChunkCostSPP.size(), Code.size());
  // JUMPDEST(1) + ADD(3) + POP(2) + STOP(0) = 6 gas.
  EXPECT_EQ(Cache.GasChunkCost[2], 6u);
  EXPECT_EQ(Cache.GasChunkCostSPP[2], Cache.GasChunkCost[2]);
  // CALLDATALOAD(3) + JUMP(8) = 11 gas.
  EXPECT_EQ(Cache.GasChunkCost[0], 11u);
}

// EnableSPP=false must leave GasChunkCostSPP empty so the JIT-consumer
// fall-through hands the unshifted cost array to downstream code.
TEST(EVMCacheImplicitDynPred, InterpreterOnly_LeavesSPPArrayEmpty) {
  const std::vector<uint8_t> Code = {OP_PUSH1, 0x05,        OP_JUMP, OP_PUSH1,
                                     0x00,     OP_JUMPDEST, OP_STOP};
  const EVMBytecodeCache Cache = buildNoSPPCache(Code);

  ASSERT_EQ(Cache.GasChunkCost.size(), Code.size());
  EXPECT_TRUE(Cache.GasChunkCostSPP.empty());
}

// Two dynamic JUMPs => ImplicitDynamicPredCount == 2 on each JUMPDEST.
// effectivePredCount must block any lemma614 shift INTO either JUMPDEST.
TEST(EVMCacheImplicitDynPred, MultipleDynJumps_BothTargetsCounted) {
  const std::vector<uint8_t> Code = {
      OP_CALLDATALOAD, OP_JUMP,     OP_JUMPDEST, OP_CALLDATALOAD,
      OP_JUMP,         OP_JUMPDEST, OP_POP,      OP_STOP,
  };
  const EVMBytecodeCache Cache = buildSPPCache(Code);

  ASSERT_EQ(Cache.GasChunkCost.size(), Code.size());
  ASSERT_EQ(Cache.GasChunkCostSPP.size(), Code.size());
  EXPECT_EQ(Cache.JumpDestMap[2], 1u);
  EXPECT_EQ(Cache.JumpDestMap[5], 1u);
  EXPECT_GT(Cache.GasChunkCost[2], 0u);
  EXPECT_GT(Cache.GasChunkCost[5], 0u);
  EXPECT_EQ(Cache.GasChunkCostSPP[2], Cache.GasChunkCost[2]);
  EXPECT_EQ(Cache.GasChunkCostSPP[5], Cache.GasChunkCost[5]);
}

// Dominator-pass correctness tests. These exercise the bytecode-cache
// dominator pipeline directly via `for_testing::computeIDomForTesting`,
// covering CFG classes that the end-to-end fixtures above do not reach
// observably. See `docs/changes/2026-05-12-evm-dom-chk/README.md` for
// the design rationale; the tests anchor semantics against the current
// iterative-bitset algorithm so the CHK replacement can be validated
// against the same expectations.

TEST(EVMCacheDominator, LinearChain_Correct) {
  // 0 -> 1 -> 2 -> 3 -> 4. Expected: idom[0]=0, idom[i]=i-1 for i=1..4.
  const std::vector<std::vector<uint32_t>> Succs = {
      {1}, {2}, {3}, {4}, {},
  };
  const std::vector<uint8_t> Reachable = {1, 1, 1, 1, 1};
  const auto IDom =
      zen::evm::for_testing::computeIDomForTesting(Succs, Reachable);
  ASSERT_EQ(IDom.size(), 5u);
  EXPECT_EQ(IDom[0], 0u) << "Entry node is its own root.";
  EXPECT_EQ(IDom[1], 0u);
  EXPECT_EQ(IDom[2], 1u);
  EXPECT_EQ(IDom[3], 2u);
  EXPECT_EQ(IDom[4], 3u);
}

TEST(EVMCacheDominator, DiamondCFG_Correct) {
  // A(0) -> B(1) -> D(3); A(0) -> C(2) -> D(3). All meet at A.
  const std::vector<std::vector<uint32_t>> Succs = {
      {1, 2},
      {3},
      {3},
      {},
  };
  const std::vector<uint8_t> Reachable = {1, 1, 1, 1};
  const auto IDom =
      zen::evm::for_testing::computeIDomForTesting(Succs, Reachable);
  ASSERT_EQ(IDom.size(), 4u);
  EXPECT_EQ(IDom[0], 0u);
  EXPECT_EQ(IDom[1], 0u) << "B is dominated by A.";
  EXPECT_EQ(IDom[2], 0u) << "C is dominated by A.";
  EXPECT_EQ(IDom[3], 0u) << "D meets through A only.";
}

TEST(EVMCacheDominator, NestedLoop_Correct) {
  // E(0) -> H1(1); H1 -> H2(2); H2 -> B(3); B -> H2 (inner back); B -> H1
  // (outer back). Expected: idom[0]=0, idom[1]=0, idom[2]=1, idom[3]=2.
  const std::vector<std::vector<uint32_t>> Succs = {
      {1},    // E
      {2},    // H1
      {3},    // H2
      {2, 1}, // B (inner back, outer back)
  };
  const std::vector<uint8_t> Reachable = {1, 1, 1, 1};
  const auto IDom =
      zen::evm::for_testing::computeIDomForTesting(Succs, Reachable);
  ASSERT_EQ(IDom.size(), 4u);
  EXPECT_EQ(IDom[0], 0u);
  EXPECT_EQ(IDom[1], 0u) << "Outer header H1 is dominated by entry E.";
  EXPECT_EQ(IDom[2], 1u) << "Inner header H2 is dominated by H1.";
  EXPECT_EQ(IDom[3], 2u) << "Body B is dominated by H2.";
}

TEST(EVMCacheDominator, DisjointRoots_SelfIdom) {
  // Two disjoint reachable subgraphs join at node 4:
  //   subgraph A: 0 -> 1
  //   subgraph B: 2 -> 3
  //   join node 4 has preds {1, 3}.
  // Expected: idom[4] == 4 (own root, no common dominator).
  const std::vector<std::vector<uint32_t>> Succs = {
      {1}, // 0
      {4}, // 1 (subgraph A) -> join
      {3}, // 2
      {4}, // 3 (subgraph B) -> join
      {},  // 4
  };
  const std::vector<uint8_t> Reachable = {1, 1, 1, 1, 1};
  const auto IDom =
      zen::evm::for_testing::computeIDomForTesting(Succs, Reachable);
  ASSERT_EQ(IDom.size(), 5u);
  EXPECT_EQ(IDom[0], 0u) << "Root of subgraph A.";
  EXPECT_EQ(IDom[1], 0u);
  EXPECT_EQ(IDom[2], 2u) << "Root of subgraph B.";
  EXPECT_EQ(IDom[3], 2u);
  EXPECT_EQ(IDom[4], 4u)
      << "Multi-root join collapses to self per the bitset dataflow's "
         "Dom[N] = {N} fallback.";
}

TEST(EVMCacheDominator, ClassCDescendant_SeedsAtInit) {
  // Class C: node 1 is reachable but its only pred (node 0) is
  // unreachable. The old bitset pass gives Dom[1] = {1} (HasPred=false
  // branch). Node 2 is reachable with pred {1}: Dom[2] = {1, 2}, so
  // node 1 dominates node 2. The new CHK pass must seed IDom[1] = 1
  // at init so node 2's RPO visit can intersect against a settled
  // root and produce IDom[2] = 1. Without init-time seeding, node 2
  // would bottom out at the post-fixpoint sweep with IDom[2] = 2,
  // diverging from the old semantics for class-C descendants.
  const std::vector<std::vector<uint32_t>> Succs = {
      {1}, // 0 (unreachable; edge present so node 1 has a pred)
      {2}, // 1 (class C: reachable, pred=0 is unreachable)
      {3}, // 2 (descendant of class-C root)
      {},  // 3 (descendant of class-C root)
  };
  const std::vector<uint8_t> Reachable = {0, 1, 1, 1};
  const auto IDom =
      zen::evm::for_testing::computeIDomForTesting(Succs, Reachable);
  ASSERT_EQ(IDom.size(), 4u);
  EXPECT_EQ(IDom[0], 0u) << "Unreachable node self-roots (class A).";
  EXPECT_EQ(IDom[1], 1u)
      << "Class-C node seeds as self-root at init (all preds unreachable).";
  EXPECT_EQ(IDom[2], 1u)
      << "Descendant of class-C root takes the root as idom.";
  EXPECT_EQ(IDom[3], 2u) << "Chain extends through the class-C subtree.";
}

} // namespace
