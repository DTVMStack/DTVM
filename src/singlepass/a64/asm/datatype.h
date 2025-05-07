// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_SINGLEPASS_A64_ASM_DATATYPE_H
#define ZEN_SINGLEPASS_A64_ASM_DATATYPE_H

// ============================================================================
// a64/datatype.h
//
// map WASM type to a64 native type
//
// ============================================================================

#include "common/errors.h"
#include "singlepass/common/definitions.h"

namespace zen::singlepass {

namespace A64 {

// WASMType: all supported data type
enum Type {
  I8,   // byte, quarter integer, 8-bit
  I16,  // word, half integer, 16-bit
  I32,  // double word, single integer, 32-bit
  I64,  // quad word, double integer, 64-bit
  F32,  // single precision floating point, 32-bit
  F64,  // double precision floating point, 64-bit
  V128, // vector, 128-bit
  VOID, // void, to catch error
};      // WASMType

} // namespace A64

template <WASMType type> constexpr A64::Type getA64TypeFromWASMType() {
  switch (type) {
  case WASMType::I8:
    return A64::I8;
  case WASMType::I16:
    return A64::I16;
  case WASMType::I32:
    return A64::I32;
  case WASMType::I64:
    return A64::I64;
  case WASMType::F32:
    return A64::F32;
  case WASMType::F64:
    return A64::F64;
  case WASMType::V128:
    return A64::V128;
    //    case WASMType::REF:
    //        return A64::I64; // 64-bit reference
  default:
    ZEN_ASSERT_TODO();
  };
}

constexpr A64::Type getA64TypeFromWASMType(WASMType Type) {
  switch (Type) {
  case WASMType::I8:
    return A64::I8;
  case WASMType::I16:
    return A64::I16;
  case WASMType::I32:
    return A64::I32;
  case WASMType::I64:
    return A64::I64;
  case WASMType::F32:
    return A64::F32;
  case WASMType::F64:
    return A64::F64;
    // case WASMType::V128:
    //   return A64::V128;
    //    case WASMType::REF:
    //        return A64::I64; // 64-bit reference
  default:
    // ZEN_ASSERT_TODO();
    throw getError(ErrorCode::InvalidType);
  };
}

template <A64::Type type> constexpr WASMType getWASMTypeFromA64Type() {
  ZEN_STATIC_ASSERT(type >= A64::I8 && type <= A64::V128);
  switch (type) {
  case A64::I8:
    return WASMType::I8;
  case A64::I16:
    return WASMType::I16;
  case A64::I32:
    return WASMType::I32;
  case A64::I64:
    return WASMType::I64;
  case A64::F32:
    return WASMType::F32;
  case A64::F64:
    return WASMType::F64;
  case A64::V128:
    return WASMType::V128;
  default:
    ZEN_ASSERT_TODO();
  }
}

template <A64::Type type> constexpr A64::Type getIntTypeFromFloatType() {
  ZEN_STATIC_ASSERT(type == A64::I32 || type == A64::I64);
  if (type == A64::I32) {
    return A64::F32;
  }
  return A64::F64;
}

} // namespace zen::singlepass

#endif // ZEN_SINGLEPASS_A64_ASM_DATATYPE_H
