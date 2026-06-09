// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_EVM_ARITH_PROFILE_H
#define ZEN_EVM_ARITH_PROFILE_H

// Dual-tap analysis-precision instrumentation.
//
// This header provides the shared join-key hash and the two env-gated CSV
// taps used to measure the range-precision gap between dynamic operand widths
// and the static value-range analyzer:
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
// The interpreter limb tap is compiled only when
// ZEN_ENABLE_EVM_ARITH_PROFILE=ON. The JIT range tap remains a runtime env
// gate because it runs during compilation, not on the interpreter opcode hot
// path.

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
// This is the magnitude-collapsed metric: it reports only the highest set limb
// position and therefore cannot distinguish a high-sparse value such as
// {0,x,0,0} from a dense u128 {x,x,0,0} (both report width 2). Use limbMask()
// for the full per-limb occupancy pattern.
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

// 4-bit limb-occupancy mask of a uint256 (little-endian limbs [V0,V1,V2,V3],
// V0 = low 64 bits). Bit i is set iff limb Vi is non-zero, so the result is in
// 0..15. Unlike limbWidth(), this preserves the full per-limb occupancy
// pattern: {0,x,0,0} yields 0b0010 (mask 2) while {x,x,0,0} yields 0b0011
// (mask 3), distinguishing high-sparse from dense operands.
inline uint32_t limbMask(const intx::uint256 &V) {
  return (V[0] != 0 ? 1u : 0u) | (V[1] != 0 ? 2u : 0u) | (V[2] != 0 ? 4u : 0u) |
         (V[3] != 0 ? 8u : 0u);
}

// ---- Stream A: interpreter dynamic limb width ----

// Returns true when ZEN_EVM_LIMB_PROFILE is set (cached after first call).
bool limbProfileEnabled();

// Append one CSV row: codehash,pc,opcode,operand_index,limb_width,limb_mask.
// limb_width is the magnitude-collapsed highest-set-limb metric (0..4);
// limb_mask is the full 4-bit per-limb occupancy pattern (0..15). No-op unless
// limbProfileEnabled().
void recordLimb(uint64_t CodeHash, uint64_t Pc, uint8_t Opcode,
                uint32_t OperandIndex, uint32_t LimbWidth, uint32_t LimbMask);

// Convenience overload: derives both limb_width and limb_mask from the operand
// value so call sites cannot let the two columns drift apart.
inline void recordLimbValue(uint64_t CodeHash, uint64_t Pc, uint8_t Opcode,
                            uint32_t OperandIndex, const intx::uint256 &V) {
  recordLimb(CodeHash, Pc, Opcode, OperandIndex, limbWidth(V), limbMask(V));
}

// ---- Stream B: JIT static range + source kind ----

// Returns true when ZEN_EVM_RANGE_PROFILE is set (cached after first call).
bool rangeProfileEnabled();

// Append one CSV row:
//   codehash,pc,opcode,lhs_range,rhs_range,lhs_source,rhs_source,path,
//   lhs_const,rhs_const
// Range/source/path values are textual enum names. The path column records
// which lowering path the JIT handler actually emitted for the site (e.g.
// FULL / CONST_U64 / NARROW_U64 / NARROW_U128 / FOLDED). lhs_const/rhs_const
// are 1 when that operand is a compile-time constant (Operand::isConstant()),
// else 0. No-op unless rangeProfileEnabled().
void recordRange(uint64_t CodeHash, uint64_t Pc, uint8_t Opcode,
                 const char *LhsRange, const char *RhsRange,
                 const char *LhsSource, const char *RhsSource, const char *Path,
                 int LhsConst, int RhsConst);

} // namespace zen::evm::arith_profile

#endif // ZEN_EVM_ARITH_PROFILE_H
