// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "evm/crypto.h"
#include <array>
#include <cstring>

namespace zen::evm::crypto {

// Static members
bool CryptoProvider::MockMode = false;
RealCrypto CryptoProvider::RealCryptoInstance;
MockCrypto CryptoProvider::MockCryptoInstance;

// Keccak-256 implementation (simplified version for now)
// TODO: Replace with a proper keccak256 implementation
// This is a placeholder that produces deterministic but incorrect results
namespace {
void placeholderKeccak256(const uint8_t *Input, size_t InputLen,
                          uint8_t *Output) {
  // This is NOT a real keccak256 implementation!
  // It's just a placeholder that produces deterministic output
  std::array<uint8_t, 32> Result = {};

  // Simple hash-like function for placeholder
  uint32_t Hash = 0x811c9dc5; // FNV-1a basis
  for (size_t Index = 0; Index < InputLen; ++Index) {
    Hash ^= Input[Index];
    Hash *= 0x01000193; // FNV-1a prime
  }

  // Fill output with pattern based on hash
  for (int Index = 0; Index < 32; Index += 4) {
    uint32_t Val = Hash ^ (Index * 0x9e3779b9);
    Result[Index] = static_cast<uint8_t>(Val);
    Result[Index + 1] = static_cast<uint8_t>(Val >> 8);
    Result[Index + 2] = static_cast<uint8_t>(Val >> 16);
    Result[Index + 3] = static_cast<uint8_t>(Val >> 24);
    Hash = Val;
  }

  std::memcpy(Output, Result.data(), 32);
}
} // namespace

// RealCrypto implementation
void RealCrypto::keccak256(const uint8_t *Input, std::size_t InputLen,
                           uint8_t *Output) {
  // TODO: Implement real keccak256 algorithm
  // For now, use placeholder
  placeholderKeccak256(Input, InputLen, Output);
}

std::vector<uint8_t> RealCrypto::keccak256(const std::vector<uint8_t> &Input) {
  std::vector<uint8_t> Result(32);
  keccak256(Input.data(), Input.size(), Result.data());
  return Result;
}

// MockCrypto implementation
void MockCrypto::keccak256(const uint8_t *Input, std::size_t InputLen,
                           uint8_t *Output) {
  // Mock implementation - returns predictable test values
  static const uint8_t MockHash[32] = {
      0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23,
      0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23,
      0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23};
  std::memcpy(Output, MockHash, 32);
}

std::vector<uint8_t> MockCrypto::keccak256(const std::vector<uint8_t> &Input) {
  std::vector<uint8_t> Result(32);
  keccak256(Input.data(), Input.size(), Result.data());
  return Result;
}

// CryptoProvider implementation
CryptoInterface &CryptoProvider::getInstance() {
  return MockMode ? static_cast<CryptoInterface &>(MockCryptoInstance)
                  : static_cast<CryptoInterface &>(RealCryptoInstance);
}

void CryptoProvider::setMockMode(bool EnableMock) { MockMode = EnableMock; }

// Convenience functions
void keccak256(const uint8_t *Input, size_t InputLen, uint8_t *Output) {
  CryptoProvider::getInstance().keccak256(Input, InputLen, Output);
}

std::vector<uint8_t> keccak256(const std::vector<uint8_t> &Input) {
  return CryptoProvider::getInstance().keccak256(Input);
}

} // namespace zen::evm::crypto
