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
enum class EVMValueRange : uint8_t {
  U64,  // Fits in 64 bits  (limbs [1..3] == 0)
  U128, // Fits in 128 bits (limbs [2..3] == 0)
  U256, // Full 256 bits — conservative default
};

} // namespace COMPILER

#endif // EVM_FRONTEND_EVM_VALUE_RANGE_H
