// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_COMMON_TYPE_H
#define ZEN_COMMON_TYPE_H

#include "common/defines.h"

namespace zen::common {

union V128 {
  int8_t I8x16[16];
  int16_t I16x8[8];
  int32_t I32x8[4];
  int64_t I64x2[2];
  float F32x4[4];
  double F64x2[2];
};

enum class WASMType : uint8_t {
  VOID,
  I8,
  I16,
  I32,
  I64,
  F32,
  F64,
  FUNCREF,
  ANY,
  ERROR_TYPE
};

enum class WASMTypeKind { INTEGER, FLOAT, VECTOR };

typedef std::underlying_type_t<WASMType> WASMTypeUnderlyingType;

// ============================================================================
// WASMTypeAttr
//
// define WASM WASMType attribute
//
// ============================================================================
template <WASMType type> struct WASMTypeAttr;

template <> struct WASMTypeAttr<WASMType::I8> {
  typedef int8_t Type;
  static constexpr WASMTypeKind Kind = WASMTypeKind::INTEGER;
  static constexpr uint32_t Size = 1;
  static constexpr uint32_t NumCells = 1;
};

template <> struct WASMTypeAttr<WASMType::I16> {
  typedef int16_t Type;
  static constexpr WASMTypeKind Kind = WASMTypeKind::INTEGER;
  static constexpr uint32_t Size = 2;
  static constexpr uint32_t NumCells = 1;
};

template <> struct WASMTypeAttr<WASMType::I32> {
  typedef int32_t Type;
  static constexpr WASMTypeKind Kind = WASMTypeKind::INTEGER;
  static constexpr uint32_t Size = 4;
  static constexpr uint32_t NumCells = 1;
};

template <> struct WASMTypeAttr<WASMType::I64> {
  typedef int64_t Type;
  static constexpr WASMTypeKind Kind = WASMTypeKind::INTEGER;
  static constexpr uint32_t Size = 8;
  static constexpr uint32_t NumCells = 2;
};

template <> struct WASMTypeAttr<WASMType::F32> {
  typedef float Type;
  static constexpr WASMTypeKind Kind = WASMTypeKind::FLOAT;
  static constexpr uint32_t Size = 4;
  static constexpr uint32_t NumCells = 1;
};

template <> struct WASMTypeAttr<WASMType::F64> {
  typedef double Type;
  static constexpr WASMTypeKind Kind = WASMTypeKind::FLOAT;
  static constexpr uint32_t Size = 8;
  static constexpr uint32_t NumCells = 2;
};

// ============================================================================
// Type Utility Functions
// ============================================================================

static inline WASMType getWASMValTypeFromOpcode(uint8_t Opcode) {
  switch (Opcode) {
#define DEFINE_VALUE_TYPE(Name, Opc, Text)                                     \
  case Opc:                                                                    \
    return WASMType::Name;
#include "common/wasm_defs/valtype.def"
#undef DEFINE_VALUE_TYPE
  default:
    return WASMType::ERROR_TYPE;
  }
}

static inline WASMType getWASMBlockTypeFromOpcode(uint8_t Opcode) {
  switch (Opcode) {
#define DEFINE_VALUE_TYPE(Name, Opc, Text)                                     \
  case Opc:                                                                    \
    return WASMType::Name;
#define DEFINE_BLOCK_TYPE(Name, Opc, Text) DEFINE_VALUE_TYPE(Name, Opc, Text)
#include "common/wasm_defs/valtype.def"
#undef DEFINE_BLOCK_TYPE
#undef DEFINE_VALUE_TYPE
  default:
    return WASMType::ERROR_TYPE;
  }
}

static inline WASMType getWASMRefTypeFromOpcode(uint8_t Opcode) {
  switch (Opcode) {
#define DEFINE_REF_TYPE(Name, Opc, Text)                                       \
  case Opc:                                                                    \
    return WASMType::Name;
#include "common/wasm_defs/valtype.def"
#undef DEFINE_REF_TYPE
  default:
    return WASMType::ERROR_TYPE;
  }
}

template <typename T> inline WASMType getWASMTypeFromType() noexcept {
  if (std::is_pointer<T>::value)
    return WASMType::I32;
  return WASMType::I64;
}
template <> inline WASMType getWASMTypeFromType<void>() noexcept {
  return WASMType::VOID;
}
template <> inline WASMType getWASMTypeFromType<bool>() noexcept {
  return WASMType::I32;
}
template <> inline WASMType getWASMTypeFromType<uint8_t>() noexcept {
  return WASMType::I32;
}
template <> inline WASMType getWASMTypeFromType<int8_t>() noexcept {
  return WASMType::I32;
}
template <> inline WASMType getWASMTypeFromType<uint16_t>() noexcept {
  return WASMType::I32;
}
template <> inline WASMType getWASMTypeFromType<int16_t>() noexcept {
  return WASMType::I32;
}
template <> inline WASMType getWASMTypeFromType<uint32_t>() noexcept {
  return WASMType::I32;
}
template <> inline WASMType getWASMTypeFromType<int32_t>() noexcept {
  return WASMType::I32;
}
template <> inline WASMType getWASMTypeFromType<uint64_t>() noexcept {
  return WASMType::I64;
}
template <> inline WASMType getWASMTypeFromType<int64_t>() noexcept {
  return WASMType::I64;
}
template <> inline WASMType getWASMTypeFromType<float>() noexcept {
  return WASMType::F32;
}
template <> inline WASMType getWASMTypeFromType<double>() noexcept {
  return WASMType::F64;
}

static inline WASMTypeUnderlyingType getWASMTypeUnderlyingValue(WASMType Type) {
  return static_cast<WASMTypeUnderlyingType>(Type);
}

template <WASMType type>
static inline constexpr WASMTypeKind getWASMTypeKind() {
  return WASMTypeAttr<type>::Kind;
}

static inline WASMTypeKind getWASMTypeKind(WASMType Type) {
  switch (Type) {
  case WASMType::I8:
  case WASMType::I16:
  case WASMType::I32:
  case WASMType::I64:
    return WASMTypeKind::INTEGER;
  case WASMType::F32:
  case WASMType::F64:
    return WASMTypeKind::FLOAT;
  default:
    ZEN_ABORT();
  }
}

template <WASMType type> static inline constexpr uint32_t getWASMTypeSize() {
  return WASMTypeAttr<type>::Size;
}

static inline uint32_t getWASMTypeSize(WASMType Type) {
  switch (Type) {
  case WASMType::I8:
    return 1;
  case WASMType::I16:
    return 2;
  case WASMType::I32:
  case WASMType::F32:
    return 4;
  case WASMType::I64:
  case WASMType::F64:
    return 8;
  case WASMType::ANY:
    return 4;
  default:
    ZEN_ABORT();
  }
}

template <WASMType type> static inline constexpr uint32_t getWASMTypeCellNum() {
  return WASMTypeAttr<type>::NumCells;
}

static inline uint32_t getWASMTypeCellNum(WASMType Type) {
  switch (Type) {
  case WASMType::VOID:
    return 0;
  case WASMType::I8:
  case WASMType::I16:
  case WASMType::I32:
  case WASMType::F32:
    return 1;
  case WASMType::I64:
  case WASMType::F64:
    return 2;
  default:
    ZEN_ABORT();
  }
}

static inline uint32_t getWASMTypeCellNumFromOpcode(uint8_t Opcode) {
  return getWASMTypeCellNum(getWASMBlockTypeFromOpcode(Opcode));
}

template <WASMType type>
static inline constexpr std::pair<WASMTypeKind, uint32_t>
getWASMTypeKindAndSize() {
  return {WASMTypeAttr<type>::kind, WASMTypeAttr<type>::size};
}

static inline std::pair<WASMTypeKind, uint32_t>
getWASMTypeKindAndSize(WASMType Type) {
  switch (Type) {
  case WASMType::I8:
    return {WASMTypeKind::INTEGER, 1};
  case WASMType::I16:
    return {WASMTypeKind::INTEGER, 2};
  case WASMType::I32:
    return {WASMTypeKind::INTEGER, 4};
  case WASMType::I64:
    return {WASMTypeKind::INTEGER, 8};
  case WASMType::F32:
    return {WASMTypeKind::FLOAT, 4};
  case WASMType::F64:
    return {WASMTypeKind::FLOAT, 8};
  default:
    ZEN_ABORT();
  }
}

template <WASMType type> constexpr bool isWASMTypeInteger() {
  return getWASMTypeKind<type>() == WASMTypeKind::INTEGER;
}

template <WASMType type> constexpr bool isWASMTypeFloat() {
  return getWASMTypeKind<type>() == WASMTypeKind::FLOAT;
}

template <WASMType type> constexpr bool isWASMTypeVector() {
  return getWASMTypeKind<type>() == WASMTypeKind::VECTOR;
}

// ============================================================================
// FloatAttr
//
// define float attribute
//
// ============================================================================

template <typename T> struct FloatAttr;

template <> struct FloatAttr<float> {
  template <typename ToIntType, bool is_signed>
  static float toIntMax() = delete;

  template <typename ToIntType, bool is_signed>
  static float toIntMin() = delete;
};

template <> inline float FloatAttr<float>::toIntMax<int32_t, true>() {
  return 2147483648.0;
}

template <> inline float FloatAttr<float>::toIntMax<int64_t, true>() {
  return 9223372036854775808.0;
}

template <> inline float FloatAttr<float>::toIntMin<int32_t, true>() {
  return -2147483904.0;
}

template <> inline float FloatAttr<float>::toIntMin<int64_t, true>() {
  return -9223373136366403584.0;
}

template <> inline float FloatAttr<float>::toIntMax<int32_t, false>() {
  return 4294967296.0;
}

template <> inline float FloatAttr<float>::toIntMax<int64_t, false>() {
  return 18446744073709551616.0;
}

template <> inline float FloatAttr<float>::toIntMin<int32_t, false>() {
  return -1.0;
}

template <> inline float FloatAttr<float>::toIntMin<int64_t, false>() {
  return -1.0;
}

template <> struct FloatAttr<double> {
  template <typename ToIntType, bool is_signed>
  static double toIntMax() = delete;

  template <typename ToIntType, bool is_signed>
  static double toIntMin() = delete;
};

template <> inline double FloatAttr<double>::toIntMax<int32_t, true>() {
  return 2147483648.0;
}

template <> inline double FloatAttr<double>::toIntMax<int64_t, true>() {
  return 9223372036854775808.0;
}

template <> inline double FloatAttr<double>::toIntMin<int32_t, true>() {
  return -2147483649.0;
}

template <> inline double FloatAttr<double>::toIntMin<int64_t, true>() {
  return -9223372036854777856.0;
}

template <> inline double FloatAttr<double>::toIntMax<int32_t, false>() {
  return 4294967296.0;
}

template <> inline double FloatAttr<double>::toIntMax<int64_t, false>() {
  return 18446744073709551616.0;
}

template <> inline double FloatAttr<double>::toIntMin<int32_t, false>() {
  return -1.0;
}

template <> inline double FloatAttr<double>::toIntMin<int64_t, false>() {
  return -1.0;
}

// ============================================================================
// Type Wrapper
// ============================================================================

union UntypedValue {
public:
  UntypedValue() : I64(0) {}
  UntypedValue(int32_t I32) : I32(I32) {}
  UntypedValue(int64_t I64) : I64(I64) {}
  UntypedValue(float F32) : F32(F32) {}
  UntypedValue(double F64) : F64(F64) {}
  int32_t I32;
  int64_t I64;
  float F32;
  double F64;
};

struct TypedValue {
public:
  TypedValue() = default;
  TypedValue(UntypedValue Val, WASMType Ty) : Value(Val), Type(Ty){};
  UntypedValue Value;
  WASMType Type;
};

} // namespace zen::common

#endif // ZEN_COMMON_TYPE_H
