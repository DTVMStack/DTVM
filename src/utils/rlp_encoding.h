// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_TEST_MPT_RLP_ENCODING_H
#define ZEN_TEST_MPT_RLP_ENCODING_H

#include <cstddef>
#include <cstdint>
#include <vector>

namespace zen::evm::rlp {

// RLP encoding constants
extern const uint8_t RLP_OFFSET_SHORT_STRING;
extern const uint8_t RLP_OFFSET_SHORT_LIST;

// RLP encoding functions
std::vector<uint8_t> encodeLength(size_t Length, uint8_t Offset);
std::vector<uint8_t> encodeString(const std::vector<uint8_t> &Input);
std::vector<uint8_t> encodeList(const std::vector<std::vector<uint8_t>> &Items);
std::vector<uint8_t>
encodeListFromEncodedItems(const std::vector<std::vector<uint8_t>> &Items);

} // namespace zen::evm::rlp

#endif // ZEN_TEST_MPT_RLP_ENCODING_H
