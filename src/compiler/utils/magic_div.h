// Copyright (C) 2021-2026 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "llvm/ADT/APInt.h"
#include "llvm/Support/DivisionByConstantInfo.h"
#include "llvm/Support/MathExtras.h"

#include <cstdint>
#include <optional>

namespace COMPILER {

/// Unsigned 32-bit magic-number parameters from Hacker's Delight
/// (via LLVM `UnsignedDivisionByConstantInfo`).
///
/// For divisor `d` that is not 0 and not a power of two:
///
///   MULHU = trunc_i32((uext_i64(n) * Magic) >> 32)
///
///   if !IsAdd:
///     q = MULHU >> ShiftAmount
///       = trunc_i32((uext_i64(n) * Magic) >> (32 + ShiftAmount))
///   else:
///     q = (((n - MULHU) >> 1) + MULHU) >> (ShiftAmount - 1)
///
/// Example: d = 20 yields Magic = 0xCCCCCCCD, IsAdd = false,
/// ShiftAmount = 4, i.e.
/// `q = trunc_i32((uext_i64(n) * 0xcccccccd) >> 36)`.
struct U32MagicUDiv {
  uint32_t Magic = 0;
  unsigned ShiftAmount = 0;
  bool IsAdd = false;
};

/// Nullopt for d == 0 or a power of two (including 1). Those stay as
/// `OP_udiv` so wasm divide-by-zero traps and pow2 udiv/urem lowering
/// remain distinct.
inline std::optional<U32MagicUDiv> tryU32MagicUDiv(uint32_t Divisor) {
  if (Divisor == 0 || llvm::isPowerOf2_32(Divisor)) {
    return std::nullopt;
  }
  const llvm::UnsignedDivisionByConstantInfo Info =
      llvm::UnsignedDivisionByConstantInfo::get(llvm::APInt(32, Divisor));
  U32MagicUDiv Out;
  Out.Magic = static_cast<uint32_t>(Info.Magic.getZExtValue());
  Out.ShiftAmount = Info.ShiftAmount;
  Out.IsAdd = Info.IsAdd;
  return Out;
}

/// Apply the expansion in host arithmetic. Matches the MIR rewrite.
inline uint32_t applyU32MagicUDiv(uint32_t N, const U32MagicUDiv &M) {
  const uint32_t Mulhu = static_cast<uint32_t>(
      (static_cast<uint64_t>(N) * static_cast<uint64_t>(M.Magic)) >> 32);
  if (M.IsAdd) {
    const uint32_t NPQ = (N - Mulhu) >> 1;
    return (NPQ + Mulhu) >> (M.ShiftAmount - 1);
  }
  if (M.ShiftAmount == 0) {
    return Mulhu;
  }
  return Mulhu >> M.ShiftAmount;
}

} // namespace COMPILER
