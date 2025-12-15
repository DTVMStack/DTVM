// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef ZEN_UTILS_EVM_H
#define ZEN_UTILS_EVM_H

#include "utils/others.h"
#include <evmc/evmc.hpp>
#include <evmc/mocked_host.hpp>
#include <optional>

namespace zen::utils {

void trimString(std::string &Str);

std::optional<std::vector<uint8_t>> fromHex(std::string_view HexStr);

// Address conversion utilities
std::string stripHexPrefix(const std::string &HexStr);
evmc::bytes hexToBytes(const std::string &HexStr);
evmc::address parseAddress(const std::string &HexAddr);
evmc::bytes32 parseBytes32(const std::string &HexStr);
evmc::uint256be parseUint256(const std::string &HexStr);
std::vector<uint8_t> parseHexData(const std::string &HexStr);

// Address to hex string conversion
std::string addressToHex(const evmc::address &Value);
std::string bytes32ToHex(const evmc::bytes32 &Value);
std::string bytesToHex(const std::vector<uint8_t> &Value);

std::vector<uint8_t> uint256beToBytes(const evmc::uint256be &Value);
evmc::address computeCreateAddress(const evmc::address &Sender,
                                   uint64_t SenderNonce);
bool saveState(const evmc::MockedHost &Host, const std::string &FilePath);
bool loadState(evmc::MockedHost &Host, const std::string &FilePath);
} // namespace zen::utils

#endif // ZEN_UTILS_EVM_H
