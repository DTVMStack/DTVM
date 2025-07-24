// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef COMPILER_IR_TYPE_H
#define COMPILER_IR_TYPE_H

#include "compiler/common/common_defs.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

namespace llvm {
struct fltSemantics;
}

namespace COMPILER {

// should be readonly
class MType {
public:
  enum Kind : uint8_t {
#define PRIM_TYPE(TEXT, KIND, SIZE) KIND,
#include "prim_types.def"
#undef PRIM_TYPE
    // derived types
    POINTER_TYPE,
    FUNC_TYPE,
    TUPLE_TYPE,
  };
  MType(Kind kind) : _kind(kind), _subClassData(0) {
    if (isInteger(kind)) {
      _subClassData |= SIGNED_CHECK; // signed

      // bitwidth
      switch (kind) {
#define PRIM_TYPE(TEXT, KIND, SIZE)                                            \
  case KIND:                                                                   \
    _subClassData |= (SIZE * 8);                                               \
    break;
#include "prim_types.def"
#undef PRIM_TYPE
      default:
        break;
      }
    }
  }

  void print(llvm::raw_ostream &OS) const;
  void dump() const;

  bool isVoid() const { return _kind == VOID; }
  Kind getKind() const { return _kind; }

  bool isI8() const { return _kind == I8; }
  bool isI16() const { return _kind == I16; }
  bool isI32() const { return _kind == I32; }
  bool isI64() const { return _kind == I64; }
  bool isF32() const { return _kind == F32; }
  bool isF64() const { return _kind == F64; }
  bool is32Bits() const { return _kind == I32 || _kind == F32; }
  bool is64Bits() const { return _kind == I64 || _kind == F64; }

  static bool isInteger(Kind kind) {
    switch (kind) {
    case I8:
    case I16:
    case I32:
    case I64:
      return true;
    default:
      return false;
    }
  }

  bool isInteger() const { return isInteger(_kind); }
  bool isFloat() const { return _kind == F32 || _kind == F64; }
  bool isPointer() const { return _kind == POINTER_TYPE; }
  bool isSigned() const {
    ZEN_ASSERT(isInteger());
    return _subClassData & SIGNED_CHECK;
  };

  unsigned getBitWidth() const {
    ZEN_ASSERT(isInteger());
    return _subClassData & BITWIDTH_MASK;
  }

  unsigned getNumBytes() const {
    switch (_kind) {
#define PRIM_TYPE(TEXT, KIND, SIZE)                                            \
  case KIND:                                                                   \
    return SIZE;
#include "prim_types.def"
#undef PRIM_TYPE
    case POINTER_TYPE:
#if defined(ZEN_BUILD_TARGET_X86_64) || defined(ZEN_BUILD_TARGET_AARCH64)
      return 8;
#else
      llvm_unreachable("Unsupported build target.");
#endif
    default:
      ZEN_ASSERT_TODO();
    }
  }

  const llvm::fltSemantics &getFltSemantics() const;

protected:
  Kind _kind : 8;
  unsigned _subClassData : 24;
  static constexpr unsigned SIGNED_BIT = 23;
  static constexpr unsigned SIGNED_CHECK = 1 << SIGNED_BIT;
  static constexpr unsigned BITWIDTH_MASK = 0x7FFFFF;
  static_assert(SIGNED_CHECK + BITWIDTH_MASK == 0xFFFFFF);

public:
  using SubTypeIterator = MType *const *;
};

inline llvm::raw_ostream &operator<<(llvm::raw_ostream &OS, const MType &Type) {
  Type.print(OS);
  return OS;
}

inline llvm::raw_ostream &operator<<(llvm::raw_ostream &OS, const MType *Type) {
  Type->print(OS);
  return OS;
}

} // namespace COMPILER

#endif // COMPILER_IR_TYPE_H
