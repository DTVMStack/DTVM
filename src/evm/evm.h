// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "evmc/evmc.hpp"
#include <cstdint>

namespace zen {
namespace evm {
// Limit required memory size to prevent excessive memory consumption
constexpr uint64_t MAX_REQUIRED_MEMORY_SIZE = 1024 * 1024;

constexpr evmc_revision DEFAULT_REVISION = EVMC_CANCUN;

} // namespace evm
} // namespace zen
