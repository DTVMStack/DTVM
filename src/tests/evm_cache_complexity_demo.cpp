// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Standalone demo: time `buildBytecodeCache` on a synthetic contract with
// N JUMPDESTs reached via one dynamic JUMP. Exercises the Phase 7
// `ImplicitDynamicPredCount` path end-to-end and lets a caller observe
// the O(N) cache-build wall-clock empirically.
//
// Usage: evmCacheComplexityDemo <n_jumpdests>
// Output: one CSV row "<n_jumpdests>,<build_ms>" to stdout.
//
// See docs/changes/2026-05-11-spp-cfg-implicit-dyn-pred/scaling_demo.sh
// for a wrapper that tabulates multiple sizes.

#include "evm/evm_cache.h"

#include <evmc/evmc.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

// Build a contract with exactly N JUMPDESTs reachable only via one
// dynamic JUMP, so every JUMPDEST gets stamped with
// ImplicitDynamicPredCount = 1 (Phase 7 path).
//
// Layout:
//   PC 0  CALLDATALOAD          (cost 3, unresolvable push -> dyn jump)
//   PC 1  JUMP                  (block terminator; dyn jump)
//   PC 2..(N+1)  JUMPDEST       (N JUMPDESTs in sequence)
//   PC N+2  STOP
std::vector<uint8_t> makeDynDispatchContract(size_t NumJumpDests) {
  std::vector<uint8_t> Code;
  Code.reserve(NumJumpDests + 3);
  Code.push_back(0x35); // CALLDATALOAD
  Code.push_back(0x56); // JUMP (dyn)
  for (size_t I = 0; I < NumJumpDests; ++I) {
    Code.push_back(0x5b); // JUMPDEST
  }
  Code.push_back(0x00); // STOP
  return Code;
}

double timeCacheBuildMs(const std::vector<uint8_t> &Code) {
  using Clock = std::chrono::steady_clock;
  const auto Start = Clock::now();
  zen::evm::EVMBytecodeCache Cache;
  zen::evm::buildBytecodeCache(Cache,
                               reinterpret_cast<const std::byte *>(Code.data()),
                               Code.size(), EVMC_CANCUN, /*EnableSPP=*/true);
  const auto End = Clock::now();
  return std::chrono::duration<double, std::milli>(End - Start).count();
}

} // namespace

int main(int Argc, char **Argv) {
  if (Argc != 2) {
    std::fprintf(stderr, "usage: %s <n_jumpdests>\n", Argv[0]);
    return 2;
  }
  const size_t N = static_cast<size_t>(std::stoull(Argv[1]));
  const auto Code = makeDynDispatchContract(N);
  const double Ms = timeCacheBuildMs(Code);
  std::printf("%zu,%.3f\n", N, Ms);
  return 0;
}
