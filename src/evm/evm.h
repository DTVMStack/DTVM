// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef ZEN_EVM_EVM_H
#define ZEN_EVM_EVM_H
#include "evmc/evmc.hpp"
#include "evmc/instructions.h"

namespace zen::evm {
using namespace evmc::literals;
constexpr auto MAXSTACK = 1024;

// Limit required memory size to prevent excessive memory consumption
// Ethereum EVM uses UINT32_MAX for memory size, with gas-based limiting
constexpr uint64_t MAX_REQUIRED_MEMORY_SIZE = 16 * 1024 * 1024; // 16MB

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
constexpr uint64_t LegacyModExpBaseGas = 600;
constexpr auto EXP_BYTE_GAS = 50;
constexpr auto EXP_BYTE_GAS_PRE_SPURIOUS_DRAGON = 10;

/// The limit of the size of created contract
/// defined by [EIP-170](https://eips.ethereum.org/EIPS/eip-170)
constexpr auto MAX_CODE_SIZE = 0x6000;

/// The limit of the size of init codes for contract creation
/// defined by [EIP-3860](https://eips.ethereum.org/EIPS/eip-3860)
// constexpr auto MAX_INITCODE_SIZE = 2 * MAX_CODE_SIZE;
constexpr auto MAX_SIZE_OF_INITCODE = 0xC000;

/// The keccak256 hash of the empty input. Used to identify empty account's
/// code.
static constexpr auto EMPTY_CODE_HASH =
    0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470_bytes32;
} // namespace zen::evm

#endif // ZEN_EVM_GAS_EVM_H
