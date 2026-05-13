// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Time buildBytecodeCache on a CALLDATALOAD JUMP <N x JUMPDEST> STOP
// contract. Usage: evmCacheComplexityDemo <n_jumpdests>
// Output: "<n_jumpdests>,<build_ms>" on stdout.

#include "evm/evm_cache.h"
#include "platform/platform.h"

#include <evmc/evmc.h>
#include <evmc/instructions.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

constexpr uint8_t OP_STOP = static_cast<uint8_t>(evmc_opcode::OP_STOP);
constexpr uint8_t OP_CALLDATALOAD =
    static_cast<uint8_t>(evmc_opcode::OP_CALLDATALOAD);
constexpr uint8_t OP_JUMP = static_cast<uint8_t>(evmc_opcode::OP_JUMP);
constexpr uint8_t OP_JUMPDEST = static_cast<uint8_t>(evmc_opcode::OP_JUMPDEST);

std::vector<uint8_t> makeDynDispatchContract(size_t NumJumpDests) {
  std::vector<uint8_t> Code;
  Code.reserve(NumJumpDests + 3);
  Code.push_back(OP_CALLDATALOAD);
  Code.push_back(OP_JUMP);
  for (size_t I = 0; I < NumJumpDests; ++I) {
    Code.push_back(OP_JUMPDEST);
  }
  Code.push_back(OP_STOP);
  return Code;
}

double timeCacheBuildMs(const std::vector<uint8_t> &Code) {
  using Clock = zen::common::SteadyClock;
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
