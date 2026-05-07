// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef ZEN_RUNTIME_EVM_MODULE_H
#define ZEN_RUNTIME_EVM_MODULE_H

#include "evm/evm.h"
#include "evm/evm_cache.h"
#include "evmc/evmc.hpp"
#include "runtime/evm_memory_specialization.h"
#include "runtime/module.h"
#include <limits>
#include <memory>

#ifdef ZEN_ENABLE_JIT
namespace COMPILER {
class EVMJITCompiler;
}; // namespace COMPILER
#endif

namespace zen {

namespace runtime {

class EVMModule final : public BaseModule<EVMModule> {
  friend class RuntimeObjectDestroyer;
  friend class action::EVMModuleLoader;

public:
  using Byte = zen::common::Byte;
  static EVMModuleUniquePtr
  newEVMModule(Runtime &RT, CodeHolderUniquePtr CodeHolder, evmc_revision Rev,
               EVMMemorySpecializationProfile MemoryProfile = {});

  virtual ~EVMModule();

  Byte *Code;
  size_t CodeSize;
  evmc::Host *Host;

  const evm::EVMBytecodeCache &getBytecodeCache() const;
  evmc_revision getRevision() const { return Revision; }
  void setRevision(evmc_revision Rev) { Revision = Rev; }
  const EVMMemorySpecializationProfile &getMemorySpecializationProfile() const {
    return MemoryProfile;
  }
  void setMemorySpecializationProfile(EVMMemorySpecializationProfile Profile) {
    MemoryProfile = Profile;
  }
  uint8_t getMemoryLinearStrideSkipLeadingZeroLimbStores() const {
    return MemoryProfile.SkipLeadingZeroLimbStores;
  }
  bool hasFullCallDataLoad0Window() const {
    return MemoryProfile.HasFullCallDataLoad0Window;
  }
  bool hasKnownCallDataLoad0Low64() const {
    return MemoryProfile.HasKnownCallDataLoad0Low64;
  }
  uint64_t getKnownCallDataLoad0Low64() const {
    return MemoryProfile.KnownCallDataLoad0Low64;
  }
  static constexpr int32_t getCodeSizeOffset() {
    static_assert(offsetof(EVMModule, CodeSize) <=
                      std::numeric_limits<int32_t>::max(),
                  "EVMModule offsets should fit in 32-bit signed range");
    return static_cast<int32_t>(offsetof(EVMModule, CodeSize));
  }

#ifdef ZEN_ENABLE_JIT_PRECOMPILE_FALLBACK
  /// Cached result from EVMAnalyzer: true if the contract should fall back
  /// to interpreter mode instead of JIT. Set once at module creation to
  /// avoid per-call O(n) bytecode scans.
  bool ShouldFallbackToInterp = false;
#endif // ZEN_ENABLE_JIT_PRECOMPILE_FALLBACK

#ifdef ZEN_ENABLE_JIT
  common::CodeMemPool &getJITCodeMemPool() {
    if (!JITCodeMemPool) {
      JITCodeMemPool = std::make_unique<common::CodeMemPool>();
    }
    return *JITCodeMemPool;
  }

  void *getJITCode() const { return JITCode; }

  size_t getJITCodeSize() const { return JITCodeSize; }

  void setJITCodeAndSize(void *Code, size_t Size) {
    JITCode = Code;
    JITCodeSize = Size;
  }
#endif // ZEN_ENABLE_JIT

private:
  EVMModule(Runtime *RT);
  EVMModule(const EVMModule &Other) = delete;
  EVMModule &operator=(const EVMModule &Other) = delete;
  CodeHolderUniquePtr CodeHolder;

  Byte *initCode(size_t Size) { return (Byte *)allocateZeros(Size); }

  void initBytecodeCache() const;
  mutable bool BytecodeCacheInitialized = false;
  mutable evm::EVMBytecodeCache BytecodeCache;
  // Whether this module will be consumed by the multipass JIT. When true,
  // buildBytecodeCache runs the expensive SPP metering pipeline so the JIT
  // can read shifted gas costs from GasChunkCostSPP. When false, only the
  // cheap per-block pass runs — interpreter-only modules pay nothing extra.
  //
  // Must be set before any getBytecodeCache() call: once the cache is
  // built, the EnableSPP decision is fixed for the lifetime of the
  // module. Future lazy / on-demand JIT paths must flip this flag before
  // triggering the lazy cache build.
  bool CacheNeedsSPP = false;
  evmc_revision Revision = zen::evm::DEFAULT_REVISION;
  EVMMemorySpecializationProfile MemoryProfile = {};

#ifdef ZEN_ENABLE_JIT_PRECOMPILE_FALLBACK
#endif

#ifdef ZEN_ENABLE_JIT
  std::unique_ptr<common::CodeMemPool> JITCodeMemPool;
  void *JITCode = nullptr;
  size_t JITCodeSize = 0;
#endif // ZEN_ENABLE_JIT
};

} // namespace runtime
} // namespace zen

#endif // ZEN_RUNTIME_EVM_MODULE_H
