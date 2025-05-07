// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_SINGLEPASS_X64_ASM_DATATYPE_H
#define ZEN_SINGLEPASS_X64_ASM_DATATYPE_H

// ============================================================================
// x64/asm/datatype.h
//
// map WASM type to x64 native type
//
// ============================================================================

#include "common/errors.h"
#include "singlepass/common/definitions.h"

namespace zen::singlepass {

namespace X64 {

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

} // namespace X64

template <WASMType Type> constexpr X64::Type getX64TypeFromWASMType() {
  switch (Type) {
  case WASMType::I8:
    return X64::I8;
  case WASMType::I16:
    return X64::I16;
  case WASMType::I32:
    return X64::I32;
  case WASMType::I64:
    return X64::I64;
  case WASMType::F32:
    return X64::F32;
  case WASMType::F64:
    return X64::F64;
  case WASMType::V128:
    return X64::V128;
    //        case WASMType::REF:
    //            return X64::I64; // 64-bit reference
  default:
    ZEN_ASSERT_TODO();
  };
}

constexpr X64::Type getX64TypeFromWASMType(WASMType Type) {
  switch (Type) {
  case WASMType::I8:
    return X64::I8;
  case WASMType::I16:
    return X64::I16;
  case WASMType::I32:
    return X64::I32;
  case WASMType::I64:
    return X64::I64;
  case WASMType::F32:
    return X64::F32;
  case WASMType::F64:
    return X64::F64;
  case WASMType::V128:
    return X64::V128;
    //        case WASMType::REF:
    //            return X64::I64; // 64-bit reference
  default:
    ZEN_ASSERT_TODO();
  };
}

template <X64::Type Ty> constexpr WASMType getWASMTypeFromX64Type() {
  ZEN_STATIC_ASSERT(Ty >= X64::I8 && Ty <= X64::V128);
  switch (Ty) {
  case X64::I8:
    return WASMType::I8;
  case X64::I16:
    return WASMType::I16;
  case X64::I32:
    return WASMType::I32;
  case X64::I64:
    return WASMType::I64;
  case X64::F32:
    return WASMType::F32;
  case X64::F64:
    return WASMType::F64;
  // case X64::V128:
  //   return WASMType::V128;
  default:
    throw getError(ErrorCode::InvalidType);
    // ZEN_ASSERT_TODO();
  }
}

} // namespace zen::singlepass

#endif // ZEN_SINGLEPASS_X64_ASM_DATATYPE_H
