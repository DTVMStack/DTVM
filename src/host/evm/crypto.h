// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_EVM_CRYPTO_H
#define ZEN_EVM_CRYPTO_H

#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

namespace zen::host::evm::crypto {

class CryptoInterface {
public:
  virtual ~CryptoInterface() = default;

  /**
   * Compute Keccak-256 hash
   * @param Input Input data pointer
   * @param InputLen Input data length
   * @param Output Output buffer (must be at least 32 bytes)
   */
  virtual void keccak256(const uint8_t *Input, std::size_t InputLen,
                         uint8_t *Output) = 0;

  /**
   * Compute Keccak-256 hash (vector version)
   * @param Input Input data
   * @return 32-byte hash result
   */
  virtual std::vector<uint8_t> keccak256(const std::vector<uint8_t> &Input) = 0;
};

class CryptoHost : public CryptoInterface {
public:
  void keccak256(const uint8_t *Input, std::size_t InputLen,
                 uint8_t *Output) override;
  std::vector<uint8_t> keccak256(const std::vector<uint8_t> &Input) override;
};

class CryptoProvider {
private:
  static std::unique_ptr<CryptoInterface> Instance;
  static std::once_flag Initialized;

  static void initializeDefault() {
    if (!Instance) {
      Instance = std::make_unique<CryptoHost>();
    }
  }

public:
  static CryptoInterface &getInstance() {
    std::call_once(Initialized, initializeDefault);
    return *Instance;
  }

  static void setInstance(std::unique_ptr<CryptoInterface> NewInstance) {
    Instance = std::move(NewInstance);
  }
};

// Convenience functions for direct use
void keccak256(const uint8_t *Input, std::size_t InputLen, uint8_t *Output);
std::vector<uint8_t> keccak256(const std::vector<uint8_t> &Input);

} // namespace zen::host::evm::crypto

#endif // ZEN_EVM_CRYPTO_H
