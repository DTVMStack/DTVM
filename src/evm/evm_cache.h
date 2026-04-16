// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_EVM_EVM_CACHE_H
#define ZEN_EVM_EVM_CACHE_H

#include "intx/intx.hpp"
#include "platform/platform.h"

#include <evmc/evmc.h>

#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace zen::evm {

struct EVMBytecodeCache {
  std::vector<uint8_t> JumpDestMap;
  std::vector<intx::uint256> PushValueMap;
  std::vector<uint32_t> GasChunkEnd;
  // Per-chunk-start unshifted gas cost. Interpreter reads this — it must
  // equal the original block base cost (see PR #371).
  std::vector<uint64_t> GasChunkCost;
  // Per-chunk-start SPP-shifted gas cost for the multipass JIT. Produced by
  // buildGasChunksSPP's metering pass; never read by the interpreter.
  std::vector<uint64_t> GasChunkCostSPP;
  // Call-site-resolved jump targets for SWAPn→JUMP return patterns. Maps
  // jump PC → list of resolved return address PCs. Used by the MIR compiler
  // for direct-branch optimization (with runtime guard, not CFG refinement).
  std::unordered_map<uint32_t, std::vector<uint32_t>> ResolvedJumpTargets;
};

// Build the bytecode cache. When EnableSPP is true, the expensive SPP
// metering pipeline runs and GasChunkCostSPP is populated with shifted
// per-chunk costs for the multipass JIT. When false (interpreter-only
// modules), the pipeline is skipped and GasChunkCostSPP stays empty.
void buildBytecodeCache(EVMBytecodeCache &Cache, const common::Byte *Code,
                        size_t CodeSize, evmc_revision Rev,
                        bool EnableSPP = false);

} // namespace zen::evm

#endif // ZEN_EVM_EVM_CACHE_H
