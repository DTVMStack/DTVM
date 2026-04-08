// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_EVM_KECCAK_CACHE_H
#define ZEN_EVM_KECCAK_CACHE_H

#include <cstdint>
#include <cstring>
#include <evmc/evmc.hpp>

namespace zen {
namespace evm {

static constexpr uint32_t KeccakCacheSlots = 16;
static constexpr uint32_t KeccakCacheMaxInputLen = 128;

struct KeccakCacheEntry {
  uint8_t Input[KeccakCacheMaxInputLen];
  uint32_t InputLen = 0;
  evmc::bytes32 Result;
  bool Valid = false;
};

struct KeccakCache {
  KeccakCacheEntry Slots[KeccakCacheSlots];
  uint32_t NextSlot = 0;

  const evmc::bytes32 *lookup(const uint8_t *Data, uint32_t Len) const {
    if (Len > KeccakCacheMaxInputLen)
      return nullptr;
    for (uint32_t I = 0; I < KeccakCacheSlots; ++I) {
      auto &S = Slots[I];
      if (S.Valid && S.InputLen == Len &&
          std::memcmp(S.Input, Data, Len) == 0) {
        return &S.Result;
      }
    }
    return nullptr;
  }

  void insert(const uint8_t *Data, uint32_t Len, const evmc::bytes32 &Result) {
    if (Len > KeccakCacheMaxInputLen)
      return;
    auto &S = Slots[NextSlot];
    std::memcpy(S.Input, Data, Len);
    S.InputLen = Len;
    S.Result = Result;
    S.Valid = true;
    NextSlot = (NextSlot + 1) % KeccakCacheSlots;
  }
};

} // namespace evm
} // namespace zen

#endif // ZEN_EVM_KECCAK_CACHE_H
