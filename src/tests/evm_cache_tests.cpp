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

// ---- New Phase-3b structural tests --------------------------------------
// These exercise dom-pass × stitch × loop detection behaviour on CFG shapes
// that the prior 5 tests do not cover. Per change-doc, assertions focus on
// **behavioural invariants** (dom-tree well-formedness) rather than specific
// IDom values where the exact array depends on RPO traversal order.

namespace {

// Helper: assert IDom is well-formed (no UINT32_MAX leftover, every non-root
// dominated by its claimed idom).
void assertWellFormedIDom(const std::vector<uint32_t> &IDom,
                          const std::vector<uint8_t> &Reachable) {
  ASSERT_EQ(IDom.size(), Reachable.size());
  for (size_t I = 0; I < IDom.size(); ++I) {
    EXPECT_NE(IDom[I], UINT32_MAX) << "node " << I;
    EXPECT_LT(IDom[I], IDom.size()) << "node " << I;
  }
}

} // namespace

// Single-node self-loop. Node 1 has a back-edge to itself. The dom-pass
// must converge with IDom well-formed; the surrounding pipeline (in
// production) marks node 1 as InCycle=1 and skips Lemma 6.14 on it.
TEST(EVMCacheDominator, SelfLoop_Correct) {
  const std::vector<std::vector<uint32_t>> Succs = {
      {1},    // 0 entry
      {1, 2}, // 1 self-loop + exit
      {},     // 2
  };
  const std::vector<uint8_t> Reachable = {1, 1, 1};
  const auto IDom =
      zen::evm::for_testing::computeIDomForTesting(Succs, Reachable);
  assertWellFormedIDom(IDom, Reachable);
  EXPECT_EQ(IDom[0], 0u);
  EXPECT_EQ(IDom[1], 0u);
  EXPECT_EQ(IDom[2], 1u);
}

// Two overlapping back-edges in a properly nested loop pair: CHK must
// converge to the correct IDom on a CFG where multiple back-edges feed
// the intersect finger-walk. CFG:
//   0 -> 1 -> 2 -> 3 -> {1, 4}   (3->1 back-edge to outer header)
//                       4 -> {2, 5} (4->2 back-edge to inner header)
//                       5 (sink)
// Natural-loop bodies: outer = {1,2,3,4} (header=1), inner = {2,3,4}
// (header=2); inner ⊂ outer, so this is a *reducible nested* loop nest
// — the dominator-based detection at evm_cache.cpp:1029-1042 passes the
// nest-or-disjoint check, the SPP reducibility fallback is NOT entered.
// This test exercises only the IDom output of CHK on the irreducible-
// shaped predecessor graph (node 2 has two preds 1 and 4 with mutually
// non-dominating relationship), where the intersect finger-walk must
// converge to NCA(1,4)=1. Exercising the SPP reducibility fallback
// itself requires end-to-end buildBytecodeCache plumb and is deferred
// to PR B / PR C (see §"Step 5 Scope Reduction" in the change doc).
TEST(EVMCacheDominator, OverlappingBackEdgesIDom) {
  const std::vector<std::vector<uint32_t>> Succs = {
      {1},    // 0 entry
      {2},    // 1
      {3},    // 2
      {1, 4}, // 3: back-edge to 1
      {2, 5}, // 4: cross-back-edge to 2
      {},     // 5 sink
  };
  const std::vector<uint8_t> Reachable = {1, 1, 1, 1, 1, 1};
  const auto IDom =
      zen::evm::for_testing::computeIDomForTesting(Succs, Reachable);
  assertWellFormedIDom(IDom, Reachable);
  // Spine: 0 -> 1 -> 2 -> 3 -> 4 -> 5 dominates linearly because the
  // back-edges never let any node skip its predecessor along the spine.
  EXPECT_EQ(IDom[0], 0u);
  EXPECT_EQ(IDom[1], 0u);
  EXPECT_EQ(IDom[2], 1u);
  EXPECT_EQ(IDom[3], 2u);
  EXPECT_EQ(IDom[4], 3u);
  EXPECT_EQ(IDom[5], 4u);
  // Walking the IDom chain from any cycle member must reach the root.
  for (uint32_t n : {1u, 2u, 3u, 4u, 5u}) {
    uint32_t cur = n;
    for (int hops = 0; hops < 16 && cur != 0; ++hops) {
      cur = IDom[cur];
    }
    EXPECT_EQ(cur, 0u) << "IDom chain from " << n << " must reach entry";
  }
}

// Nested loops sharing an exit edge. Inner loop {2 ↔ 3} sits inside outer
// loop {1 → 2 → 3 → 1}; both exit to the shared node 4.
TEST(EVMCacheDominator, NestedSharedExit) {
  const std::vector<std::vector<uint32_t>> Succs = {
      {1},    // 0 entry
      {2, 4}, // 1 outer header: enters inner OR exits outer
      {3, 4}, // 2 inner header: continues inner OR exits to shared exit
      {2, 1}, // 3 inner body: inner back-edge OR outer back-edge
      {},     // 4 shared exit
  };
  const std::vector<uint8_t> Reachable = {1, 1, 1, 1, 1};
  const auto IDom =
      zen::evm::for_testing::computeIDomForTesting(Succs, Reachable);
  assertWellFormedIDom(IDom, Reachable);
  EXPECT_EQ(IDom[0], 0u);
  EXPECT_EQ(IDom[1], 0u);
  EXPECT_EQ(IDom[2], 1u) << "Inner header dominated by outer header.";
  EXPECT_EQ(IDom[3], 2u) << "Inner body dominated by inner header.";
  EXPECT_EQ(IDom[4], 1u)
      << "Shared exit's idom is outer header (only forced common ancestor).";
}

// Critical edge + empty split block. Diamond CFG A→B→D / A→C→D where D
// has multi-pred and A has multi-succ. splitCriticalEdges inserts empty
// blocks on the A→B and A→C edges (both critical). Verify CHK handles
// the post-split CFG without UINT32_MAX leftover.
TEST(EVMCacheDominator, CriticalEdgeEmptySplitTopology) {
  // Modeling post-split CFG: insertion blocks 4 and 5 sit between
  // A(0)→B(1) and A(0)→C(2), and node 3 is the merge D.
  //   0 → 4 → 1 → 3
  //   0 → 5 → 2 → 3
  const std::vector<std::vector<uint32_t>> Succs = {
      {4, 5}, // 0 = A (multi-succ)
      {3},    // 1 = B
      {3},    // 2 = C
      {},     // 3 = D (multi-pred)
      {1},    // 4 = split block on A→B
      {2},    // 5 = split block on A→C
  };
  const std::vector<uint8_t> Reachable = {1, 1, 1, 1, 1, 1};
  const auto IDom =
      zen::evm::for_testing::computeIDomForTesting(Succs, Reachable);
  assertWellFormedIDom(IDom, Reachable);
  EXPECT_EQ(IDom[0], 0u);
  EXPECT_EQ(IDom[4], 0u);
  EXPECT_EQ(IDom[5], 0u);
  EXPECT_EQ(IDom[1], 4u) << "B dominated by its split block, not A directly.";
  EXPECT_EQ(IDom[2], 5u) << "C dominated by its split block, not A directly.";
  EXPECT_EQ(IDom[3], 0u) << "D's only common dominator after split is A.";
}

// Dyn-target JUMPDEST inside a static loop body. Simulates a Solidity
// `switch` dispatch landed inside a while-loop body. The reachability
// stitch makes node 2 (dyn-target) a stitch root in production; the
// computeIDomForTesting helper takes `Reachable` directly so we model
// the same shape here.
TEST(EVMCacheDominator, DynTargetInStaticLoop) {
  // 0 = entry → 1 = loop header → 2 = dyn-target JUMPDEST inside loop
  //   → 3 = case body → 1 (back-edge) → exit
  // Node 2 has dyn-pred but no static pred from outside the loop;
  // Reachable[2]=1 marks it as stitched.
  const std::vector<std::vector<uint32_t>> Succs = {
      {1},    // 0 entry
      {2, 4}, // 1 header: enter or exit
      {3},    // 2 dyn-target JUMPDEST
      {1},    // 3 case body, back-edge to header
      {},     // 4 exit
  };
  const std::vector<uint8_t> Reachable = {1, 1, 1, 1, 1};
  const auto IDom =
      zen::evm::for_testing::computeIDomForTesting(Succs, Reachable);
  assertWellFormedIDom(IDom, Reachable);
  EXPECT_EQ(IDom[0], 0u);
  EXPECT_EQ(IDom[1], 0u);
  EXPECT_EQ(IDom[2], 1u) << "Stitched dyn-target dominated by static parent.";
  EXPECT_EQ(IDom[3], 2u);
  EXPECT_EQ(IDom[4], 1u);
}

} // namespace
