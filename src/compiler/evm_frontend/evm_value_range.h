// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef EVM_FRONTEND_EVM_VALUE_RANGE_H
#define EVM_FRONTEND_EVM_VALUE_RANGE_H

#include <cstdint>

namespace COMPILER {

// Range classification for u256 operands.  Narrower ranges enable
// single-instruction fast paths instead of expensive multi-limb arithmetic.
// Shared between the EVM IR builder's `Operand` abstraction and EVMAnalyzer's
// per-block-entry stack-slot range tracking.
//
// The enumerator ordering is load-bearing: ordinal must be non-decreasing in
// width (U64 < U128 < U256). bothFitU64, the std::min narrowing in AND, and
// the std::max widening in OR/XOR all rely on this.
enum class EVMValueRange : uint8_t {
  U64,  // Fits in 64 bits  (limbs [1..3] == 0)
  U128, // Fits in 128 bits (limbs [2..3] == 0)
  U256, // Full 256 bits — conservative default
};
static_assert(static_cast<uint8_t>(EVMValueRange::U64) <
                      static_cast<uint8_t>(EVMValueRange::U128) &&
                  static_cast<uint8_t>(EVMValueRange::U128) <
                      static_cast<uint8_t>(EVMValueRange::U256),
              "EVMValueRange enumerators must be ordered U64 < U128 < U256; "
              "AND uses std::min for narrowing and OR/XOR uses std::max for "
              "widening, both rely on this ordinal contract.");

} // namespace COMPILER

#endif // EVM_FRONTEND_EVM_VALUE_RANGE_H
