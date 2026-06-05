// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "evm/arith_profile.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>

namespace zen::evm::arith_profile {

namespace {

// Lazily-opened append stream guarded by a mutex. statetest is single-threaded
// so contention is nil; the mutex only protects against torn interleaving if a
// future caller is multi-threaded.
struct CsvSink {
  std::mutex Mtx;
  FILE *File = nullptr;
  bool Resolved = false;

  // Open on first use. EnvName selects the gate; DefaultPath is used when the
  // env value is empty or "1". Returns nullptr when the gate is unset.
  FILE *get(const char *EnvName, const char *DefaultPath, const char *Header) {
    std::lock_guard<std::mutex> Lock(Mtx);
    if (Resolved) {
      return File;
    }
    Resolved = true;
    const char *EnvVal = std::getenv(EnvName);
    if (EnvVal == nullptr) {
      return nullptr; // gate off
    }
    const char *Path = DefaultPath;
    if (EnvVal[0] != '\0' && std::strcmp(EnvVal, "1") != 0) {
      Path = EnvVal; // treat a non-trivial value as the output path
    }
    File = std::fopen(Path, "a");
    if (File != nullptr) {
      // Write a header only when the file is empty (offset 0 after
      // append-open).
      if (std::ftell(File) == 0) {
        std::fputs(Header, File);
      }
    }
    return File;
  }
};

CsvSink LimbSink;
CsvSink RangeSink;

} // namespace

bool limbProfileEnabled() {
  static const bool Enabled = std::getenv("ZEN_EVM_LIMB_PROFILE") != nullptr;
  return Enabled;
}

bool rangeProfileEnabled() {
  static const bool Enabled = std::getenv("ZEN_EVM_RANGE_PROFILE") != nullptr;
  return Enabled;
}

void recordLimb(uint64_t CodeHash, uint64_t Pc, uint8_t Opcode,
                uint32_t OperandIndex, uint32_t LimbWidth, uint32_t LimbMask) {
  if (!limbProfileEnabled()) {
    return;
  }
  FILE *F =
      LimbSink.get("ZEN_EVM_LIMB_PROFILE", "/tmp/dtvm_limb_profile.csv",
                   "codehash,pc,opcode,operand_index,limb_width,limb_mask\n");
  if (F == nullptr) {
    return;
  }
  std::lock_guard<std::mutex> Lock(LimbSink.Mtx);
  std::fprintf(F, "%016llx,%llu,%u,%u,%u,%u\n",
               static_cast<unsigned long long>(CodeHash),
               static_cast<unsigned long long>(Pc),
               static_cast<unsigned>(Opcode), OperandIndex, LimbWidth,
               LimbMask);
}

void recordRange(uint64_t CodeHash, uint64_t Pc, uint8_t Opcode,
                 const char *LhsRange, const char *RhsRange,
                 const char *LhsSource, const char *RhsSource, const char *Path,
                 int LhsConst, int RhsConst) {
  if (!rangeProfileEnabled()) {
    return;
  }
  FILE *F =
      RangeSink.get("ZEN_EVM_RANGE_PROFILE", "/tmp/dtvm_range_profile.csv",
                    "codehash,pc,opcode,lhs_range,rhs_range,lhs_source,"
                    "rhs_source,path,lhs_const,rhs_const\n");
  if (F == nullptr) {
    return;
  }
  std::lock_guard<std::mutex> Lock(RangeSink.Mtx);
  std::fprintf(F, "%016llx,%llu,%u,%s,%s,%s,%s,%s,%d,%d\n",
               static_cast<unsigned long long>(CodeHash),
               static_cast<unsigned long long>(Pc),
               static_cast<unsigned>(Opcode), LhsRange, RhsRange, LhsSource,
               RhsSource, Path, LhsConst, RhsConst);
}

} // namespace zen::evm::arith_profile
