// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_ACTION_LOADER_COMMON_H
#define ZEN_ACTION_LOADER_COMMON_H

#include "common/defines.h"
#include "common/enums.h"
#include "common/errors.h"
#include "common/type.h"
#include "runtime/module.h"
#include "utils/math.h"
#include "utils/wasm.h"

namespace zen::action {

// Base class for ModuleLoader and FunctionLoader
class LoaderCommon {
protected:
  using Byte = common::Byte;
  using Bytes = common::Bytes;
  using ErrorCode = common::ErrorCode;
  using WASMType = common::WASMType;

  LoaderCommon(runtime::Module &M, const Byte *PtrStart, const Byte *PtrEnd)
      : Mod(M), Start(PtrStart), End(PtrEnd), Ptr(PtrStart) {}

  virtual ~LoaderCommon() = default;

  Byte readByte() {
    if (Ptr >= End) {
      throw getError(ErrorCode::UnexpectedEnd);
    }
    return *Ptr++;
  }

  Bytes readBytes(size_t Size) {
    const Byte *PrevPtr = Ptr;
    if (utils::addOverflow(Ptr, Size, Ptr) || Ptr > End) {
      throw getError(ErrorCode::UnexpectedEnd);
    }
    return Bytes(PrevPtr, Size);
  }

  template <typename T> T readLEB() {
    if (Ptr >= End) {
      throw getError(ErrorCode::UnexpectedEnd);
    }
    T Result;
    const uint8_t *LEBPtr = reinterpret_cast<const uint8_t *>(Ptr);
    const uint8_t *LEBEnd = reinterpret_cast<const uint8_t *>(End);
    const uint8_t *LEBNextPtr = utils::readLEBNumber(LEBPtr, LEBEnd, Result);
    Ptr = reinterpret_cast<const Byte *>(LEBNextPtr);
    return Result;
  }

  // Read int32_t in form of LEB128
  int32_t readI32() { return readLEB<int32_t>(); }
  // Read int64_t in form of LEB128
  int64_t readI64() { return readLEB<int64_t>(); }
  // Read uint32_t in form of LEB128
  uint32_t readU32() { return readLEB<uint32_t>(); }
  // Read uint64_t in form of LEB128
  uint32_t readU64() { return readLEB<uint64_t>(); }

  // Read an plain uint32_t
  uint32_t readPlainU32() {
    const Byte *PrevPtr = Ptr;
    if (utils::addOverflow(Ptr, sizeof(uint32_t), Ptr) || Ptr > End) {
      throw getError(ErrorCode::UnexpectedEnd);
    }
    return *reinterpret_cast<const uint32_t *>(PrevPtr);
  }

  template <typename T>
  std::enable_if_t<std::is_floating_point<T>::value, T> readFloatingPoint() {
    constexpr uint32_t FPSize = sizeof(T);
    Bytes FP = readBytes(FPSize);
    T Result;
    std::memcpy(&Result, FP.data(), FPSize);
    return Result;
  }

  float readF32() { return readFloatingPoint<float>(); }
  double readF64() { return readFloatingPoint<double>(); }

  typedef WASMType (*GetWASMTypeFromOpcodeFunc)(uint8_t);
  WASMType readTypeBase(GetWASMTypeFromOpcodeFunc Func) {
    uint8_t TypeOpcode = common::to_underlying(readByte());
    WASMType Type = Func(TypeOpcode);
    if (Type == WASMType::ERROR_TYPE) {
      throw getError(ErrorCode::InvalidType);
    }
    return Type;
  }

  WASMType readValType() {
    return readTypeBase(common::getWASMValTypeFromOpcode);
  }

#ifdef ZEN_ENABLE_WASI_MULTI_VALUE
  // Multi-value support: block type can be a type index
  // Returns: positive value for WASMType, negative value for type index
  // The caller should check if result < 0 to determine if it's a type index
  int32_t readBlockType() {
    uint8_t TypeOpcode = common::to_underlying(readByte());
    WASMType Type = common::getWASMBlockTypeFromOpcode(TypeOpcode);
    if (Type != WASMType::ERROR_TYPE) {
      return static_cast<int32_t>(Type);
    }
    // Type index (signed LEB128)
    // Rewind and read as signed LEB128
    Ptr--;
    int32_t TypeIndex = readLEB<int32_t>();
    if (TypeIndex < 0) {
      // Valid type index (must be non-negative)
      throw getError(ErrorCode::InvalidType);
    }
    // Return negative value to indicate type index
    return -TypeIndex - 1; // -1 means type index 0, -2 means type index 1, etc.
  }
#else
  WASMType readBlockType() {
    return readTypeBase(common::getWASMBlockTypeFromOpcode);
  }
#endif

  WASMType readRefType() {
    return readTypeBase(common::getWASMRefTypeFromOpcode);
  }

  runtime::Module &Mod;

  const Byte *Start;
  const Byte *End;
  const Byte *Ptr;
};

} // namespace zen::action

#endif // ZEN_ACTION_LOADER_COMMON_H
