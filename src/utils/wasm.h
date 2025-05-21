// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_UTILS_WASM_H
#define ZEN_UTILS_WASM_H

#include "common/defines.h"
#include "common/enums.h"
#include "common/errors.h"
#include "common/type.h"
#include <type_traits>

namespace zen::utils {

// read leb-encoded number from byte array to value, return new pointer to the
// buffer after the leb number
template <typename T>
const uint8_t *readLEBNumber(const uint8_t *Ip, const uint8_t *End, T &Value) {
  using common::ErrorCode;
  using common::getError;

  constexpr int MaxBytes = (sizeof(T) * 8 + 6) / 7;
  constexpr bool Signed = std::is_signed<T>::value;

  // adjust end
  if (Ip + MaxBytes + 1 < End) {
    End = Ip + MaxBytes + 1;
  }

  T Result = 0;
  uint32_t Shift = 0, Count = 0;
  uint8_t Byte = 0;
  while (Ip < End) {
    Byte = *Ip++;
    Result |= ((T)(Byte & 0x7f)) << Shift;
    Shift += 7;
    if ((Byte & 0x80) == 0) {
      break;
    }
    Count++;
  }

  if (Count >= MaxBytes || Byte & 0x80) {
    throw getError(ErrorCode::LEBIntTooLong);
  }

  if (!Signed && sizeof(T) == 4 && Shift >= sizeof(T) * 8) {
    if (Byte & 0xf0) {
      throw getError(ErrorCode::LEBIntTooLarge);
    }
  } else if constexpr (Signed) {
    if (Shift < (sizeof(T) * 8)) {
      if (Byte & 0x40) {
        Result |= (std::make_unsigned_t<T>(-1) << Shift);
      }
    } else if constexpr (sizeof(T) == 4) {
      bool SignBitSet = Byte & 0x8;
      int TopBits = Byte & 0xf0;
      if ((SignBitSet && TopBits != 0x70) || (!SignBitSet && TopBits != 0))
        throw getError(ErrorCode::LEBIntTooLarge);
    } else {
      ZEN_ASSERT(sizeof(T) == 8);
      bool SignBitSet = Byte & 0x1;
      int32_t TopBits = Byte & 0xfe;

      if ((SignBitSet && TopBits != 0x7e) || (!SignBitSet && TopBits != 0))
        throw getError(ErrorCode::LEBIntTooLarge);
    }
  }

  Value = Result;
  return Ip;
}

template <typename T>
static const uint8_t *readSafeLEBNumber(const uint8_t *Ip, T &Value) {
  constexpr bool IsSigned = std::is_signed<T>::value;

  T Result = 0;
  uint32_t Shift = 0;
  uint8_t Byte = 0;
  while (true) {
    Byte = *Ip++;
    Result |= ((T)(Byte & 0x7f)) << Shift;
    Shift += 7;
    if ((Byte & 0x80) == 0) {
      break;
    }
  }

  if constexpr (IsSigned) {
    if (Shift < (sizeof(T) * 8)) {
      if (Byte & 0x40) {
        Result |= (std::make_unsigned_t<T>(-1) << Shift);
      }
    }
  }

  Value = Result;
  return Ip;
}

// read fixed-length number from byte array to value, return new pointer to the
// buffer after the fixed-length number
template <typename T>
const uint8_t *readFixedNumber(const uint8_t *Ip, const uint8_t *End,
                               T &Value) {
  if (Ip + sizeof(T) > End) {
    return End;
  }

  uint8_t *Ptr = (uint8_t *)&Value;
  for (uint32_t I = 0; I < sizeof(T); ++I) {
    *Ptr++ = *Ip++;
  }
  return Ip;
}

// skip leb-encoded number, return pointer to buffer after the leb number
template <typename T>
const uint8_t *skipLEBNumber(const uint8_t *Ip, const uint8_t *End) {
  constexpr int MaxBytes = (sizeof(T) * 8 + 6) / 7;
  if (Ip + MaxBytes + 1 < End) {
    End = Ip + MaxBytes + 1;
  }

  while ((Ip < End) && (*(Ip++) & 0x80))
    /* empty */;
  ZEN_ASSERT(Ip < End);
  return Ip;
}

const uint8_t *skipBlockType(const uint8_t *Ip, const uint8_t *End);

// skip current block for br, br_table, return and unreachable
const uint8_t *skipCurrentBlock(const uint8_t *Ip, const uint8_t *End);

// byte code to string for dump purpose
const char *getWASMTypeString(common::WASMType Type);
const char *getOpcodeString(uint8_t Opcode);

common::SectionOrder getSectionOrder(common::SectionType SecType);

} // namespace zen::utils

#endif // ZEN_UTILS_WASM_H
