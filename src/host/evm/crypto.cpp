// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "host/evm/crypto.h"
#include "host/evm/keccak/keccak.hpp"
#include <array>
#include <cstring>

namespace zen::host::evm::crypto {

// Static member definitions
std::unique_ptr<CryptoInterface> CryptoProvider::Instance;
std::once_flag CryptoProvider::Initialized;

// RealCrypto implementation
void CryptoHost::keccak256(const uint8_t *Input, std::size_t InputLen,
                           uint8_t *Output) {
  const auto Result = ethash::keccak256(Input, InputLen);
  std::memcpy(Output, Result.bytes, 32);
  // placeholderKeccak256(Input, InputLen, Output);
}

std::vector<uint8_t> CryptoHost::keccak256(const std::vector<uint8_t> &Input) {
  std::vector<uint8_t> Result(32);
  keccak256(Input.data(), Input.size(), Result.data());
  return Result;
}

// Convenience functions
void keccak256(const uint8_t *Input, size_t InputLen, uint8_t *Output) {
  CryptoProvider::getInstance().keccak256(Input, InputLen, Output);
}

std::vector<uint8_t> keccak256(const std::vector<uint8_t> &Input) {
  return CryptoProvider::getInstance().keccak256(Input);
}

} // namespace zen::host::evm::crypto
