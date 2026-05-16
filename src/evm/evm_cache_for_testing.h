// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_EVM_EVM_CACHE_FOR_TESTING_H
#define ZEN_EVM_EVM_CACHE_FOR_TESTING_H

#include <cstdint>
#include <vector>

namespace zen::evm::for_testing {

// Testing-only entry point for dominator-pass correctness checks.
//
// Inputs:
//   Succs[i]   — adjacency list: nodes that block i jumps to.
//   Reachable  — parallel array (1 = visited by computeReachable from
//                some entry). The caller is responsible for matching
//                the production invariant — this helper does NOT run
//                computeReachable, splitCriticalEdges, or the dyn-target
//                reachability stitch, so callers wanting to exercise those
//                passes must do so through buildBytecodeCache instead.
//
// Returns the immediate-dominator array `idom`, where `idom[i] == i`
// marks a dominator-forest root and `idom[i] != i` marks the immediate
// dominator of i. Internally builds the GasBlock vector that the
// production pipeline uses; only the dominator pass is exercised.
std::vector<uint32_t>
computeIDomForTesting(const std::vector<std::vector<uint32_t>> &Succs,
                      const std::vector<uint8_t> &Reachable);

} // namespace zen::evm::for_testing

#endif // ZEN_EVM_EVM_CACHE_FOR_TESTING_H
