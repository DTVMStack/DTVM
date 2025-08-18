// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "evmc/evmc.hpp"
#include "evmc/instructions.h"

namespace zen {
namespace evm {
constexpr auto MAXSTACK = 1024;

// Limit required memory size to prevent excessive memory consumption
constexpr uint64_t MAX_REQUIRED_MEMORY_SIZE = 1024 * 1024;

constexpr evmc_revision DEFAULT_REVISION = EVMC_CANCUN;

// About gas cost
constexpr auto BASIC_EXECUTION_COST = 21000;
constexpr auto COLD_ACCOUNT_ACCESS_COST = 2600;
constexpr auto WARM_ACCOUNT_ACCESS_COST = 100;
constexpr auto ADDITIONAL_COLD_ACCOUNT_ACCESS_COST =
    COLD_ACCOUNT_ACCESS_COST - WARM_ACCOUNT_ACCESS_COST;
constexpr auto CALL_VALUE_COST = 9000;
constexpr auto ACCOUNT_CREATION_COST = 25000;
constexpr auto CALL_GAS_STIPEND = 2300;

constexpr auto MAX_SIZE_OF_INITCODE = 0xC000;

// evmc missing-opcode gas cost
constexpr uint64_t BLOBHASH_GAS_COST = 3;
constexpr uint64_t BLOBBASEFEE_GAS_COST = 2;
constexpr uint64_t TLOAD_GAS_COST = 100;
constexpr uint64_t TSTORE_GAS_COST = 100;
constexpr uint64_t MCOPY_GAS_COST = 3;

// evmc missing-opcode
constexpr evmc_opcode OP_BLOBHASH = static_cast<evmc_opcode>(0x49);
constexpr evmc_opcode OP_BLOBBASEFEE = static_cast<evmc_opcode>(0x4a);
constexpr evmc_opcode OP_TLOAD = static_cast<evmc_opcode>(0x5c);
constexpr evmc_opcode OP_TSTORE = static_cast<evmc_opcode>(0x5d);
constexpr evmc_opcode OP_MCOPY = static_cast<evmc_opcode>(0x5e);

} // namespace evm
} // namespace zen
