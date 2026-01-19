// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_EVM_EVM_CACHE_H
#define ZEN_EVM_EVM_CACHE_H

#include "intx/intx.hpp"
#include "platform/platform.h"

#include <evmc/evmc.h>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace zen::evm {

struct EVMBytecodeCache {
  std::vector<uint8_t> JumpDestMap;
  std::vector<intx::uint256> PushValueMap;
  std::vector<uint32_t> GasChunkEnd;
  std::vector<uint64_t> GasChunkCost;
};

void buildBytecodeCache(EVMBytecodeCache &Cache, const common::Byte *Code,
                        size_t CodeSize, evmc_revision Rev);

} // namespace zen::evm

#endif // ZEN_EVM_EVM_CACHE_H
