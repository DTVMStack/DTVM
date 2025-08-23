// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "evmc/evmc.hpp"

namespace zen {
namespace evm {

constexpr auto COLD_SLOAD_COST = 2100;
constexpr auto WARM_STORAGE_READ_COST = 100;
constexpr auto WORD_COPY_COST = 3;

struct StorageStoreCost {
  int16_t GasCost;
  int16_t GasReFund;
};

extern const std::array<
    std::array<StorageStoreCost, EVMC_STORAGE_MODIFIED_RESTORED + 1>,
    EVMC_MAX_REVISION + 1>
    SSTORE_COSTS;
} // namespace evm
} // namespace zen
