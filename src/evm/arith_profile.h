// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_EVM_ARITH_PROFILE_H
#define ZEN_EVM_ARITH_PROFILE_H

// Dual-tap analysis-precision instrumentation.
//
// This header provides the shared join-key hash and the two env-gated CSV
// taps used to measure how much narrow-width arithmetic headroom the static
// value-range analyzer is leaving on the table:
//
//   Stream A (ZEN_EVM_LIMB_PROFILE): interpreter dynamic 64-bit limb width per
//     arithmetic operand, captured before the op mutates the stack.
//   Stream B (ZEN_EVM_RANGE_PROFILE): JIT static EVMValueRange + operand
//     source-kind per arithmetic site, captured once per compile.
//
// Both streams are keyed by (codehash, pc) where codehash is an FNV-1a 64-bit
// hash over the contract code bytes and pc is the zero-based byte offset of the
// opcode in that same code. The two keys align because the interpreter and the
// JIT visit the identical code buffer.
//
// All taps are pure-runtime getenv gates: with neither env set they stay
// dormant and impose no measurable cost beyond a cached env lookup. No new
// CMake flag is required.

#include "intx/intx.hpp"

#include <cstddef>
#include <cstdint>

namespace zen::evm::arith_profile {

// FNV-1a 64-bit over the raw code bytes. Cheap, no crypto dependency, used only
// as an offline join key (collision-tolerant for this analysis purpose).
inline uint64_t fnv1aCodeHash(const uint8_t *Code, size_t CodeSize) {
  uint64_t Hash = 1469598103934665603ull; // FNV offset basis
  for (size_t I = 0; I < CodeSize; ++I) {
    Hash ^= static_cast<uint64_t>(Code[I]);
    Hash *= 1099511628211ull; // FNV prime
  }
  return Hash;
}

// Number of significant 64-bit limbs of a uint256 (0 if zero, else 1..4).
inline uint32_t limbWidth(const intx::uint256 &V) {
  if (V[3] != 0) {
    return 4;
  }
  if (V[2] != 0) {
    return 3;
  }
  if (V[1] != 0) {
    return 2;
  }
  if (V[0] != 0) {
    return 1;
  }
  return 0;
}

// ---- Stream A: interpreter dynamic limb width ----

// Returns true when ZEN_EVM_LIMB_PROFILE is set (cached after first call).
bool limbProfileEnabled();

// Append one CSV row: codehash,pc,opcode,operand_index,limb_width.
// No-op unless limbProfileEnabled().
void recordLimb(uint64_t CodeHash, uint64_t Pc, uint8_t Opcode,
                uint32_t OperandIndex, uint32_t LimbWidth);

// ---- Stream B: JIT static range + source kind ----

// Returns true when ZEN_EVM_RANGE_PROFILE is set (cached after first call).
bool rangeProfileEnabled();

// Append one CSV row:
//   codehash,pc,opcode,lhs_range,rhs_range,lhs_source,rhs_source
// Range/source values are textual enum names. No-op unless
// rangeProfileEnabled().
void recordRange(uint64_t CodeHash, uint64_t Pc, uint8_t Opcode,
                 const char *LhsRange, const char *RhsRange,
                 const char *LhsSource, const char *RhsSource);

} // namespace zen::evm::arith_profile

#endif // ZEN_EVM_ARITH_PROFILE_H
