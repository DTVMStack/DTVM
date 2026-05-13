// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Regression tests for buildBytecodeCache's SPP pipeline: implicit
// dyn-pred count + reachability stitch on dyn-target JUMPDESTs.

#include "evm/evm_cache.h"

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

} // namespace
