// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "utils/rlp_encoding.h"

namespace zen::evm::rlp {

// RLP encoding constants
const uint8_t RLP_OFFSET_SHORT_STRING = 0x80;
const uint8_t RLP_OFFSET_SHORT_LIST = 0xc0;

std::vector<uint8_t> encodeLength(size_t Length, uint8_t Offset) {
  std::vector<uint8_t> Result;

  if (Length < 56) {
    Result.push_back(static_cast<uint8_t>(Length + Offset));
  } else {
    std::vector<uint8_t> LengthBytes;
    size_t Temp = Length;
    while (Temp > 0) {
      LengthBytes.insert(LengthBytes.begin(),
                         static_cast<uint8_t>(Temp & 0xFF));
      Temp >>= 8;
    }
    Result.push_back(static_cast<uint8_t>(LengthBytes.size() + Offset + 55));
    Result.insert(Result.end(), LengthBytes.begin(), LengthBytes.end());
  }

  return Result;
}

std::vector<uint8_t> encodeString(const std::vector<uint8_t> &Input) {
  if (Input.empty()) {
    return {RLP_OFFSET_SHORT_STRING};
  }

  if (Input.size() == 1 && Input[0] < RLP_OFFSET_SHORT_STRING) {
    return Input;
  }

  auto LengthBytes = encodeLength(Input.size(), RLP_OFFSET_SHORT_STRING);
  LengthBytes.insert(LengthBytes.end(), Input.begin(), Input.end());
  return LengthBytes;
}

std::vector<uint8_t>
encodeList(const std::vector<std::vector<uint8_t>> &Items) {
  std::vector<uint8_t> Payload;
  for (const auto &Item : Items) {
    auto Encoded = encodeString(Item);
    Payload.insert(Payload.end(), Encoded.begin(), Encoded.end());
  }

  auto LengthBytes = encodeLength(Payload.size(), RLP_OFFSET_SHORT_LIST);
  LengthBytes.insert(LengthBytes.end(), Payload.begin(), Payload.end());
  return LengthBytes;
}

std::vector<uint8_t>
encodeListFromEncodedItems(const std::vector<std::vector<uint8_t>> &Items) {
  std::vector<uint8_t> Payload;
  for (const auto &Item : Items) {
    Payload.insert(Payload.end(), Item.begin(), Item.end());
  }

  auto LengthBytes = encodeLength(Payload.size(), RLP_OFFSET_SHORT_LIST);
  LengthBytes.insert(LengthBytes.end(), Payload.begin(), Payload.end());
  return LengthBytes;
}

} // namespace zen::evm::rlp
