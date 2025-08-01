// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "evmc/evmc.hpp"

namespace zen {
namespace evm {
// Limit required memory size to prevent excessive memory consumption
constexpr uint64_t MAX_REQUIRED_MEMORY_SIZE = 1024 * 1024;

constexpr evmc_revision DEFAULT_REVISION = EVMC_CANCUN;

// About gas cost
constexpr auto COLD_ACCOUNT_ACCESS_COST = 2600;
constexpr auto WARM_ACCOUNT_ACCESS_COST = 100;
constexpr auto ADDITIONAL_COLD_ACCOUNT_ACCESS_COST =
    COLD_ACCOUNT_ACCESS_COST - WARM_ACCOUNT_ACCESS_COST;
constexpr auto CALL_VALUE_COST = 9000;
constexpr auto ACCOUNT_CREATION_COST = 25000;
constexpr auto CALL_GAS_STIPEND = 2300;

constexpr auto MAX_SIZE_OF_INITCODE = 0xC000;

} // namespace evm
} // namespace zen
