// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_SINGLEPASS_A64_ASM_REGISTER_H
#define ZEN_SINGLEPASS_A64_ASM_REGISTER_H

// ============================================================================
// a64/register.h
//
// Map asmjit::a64::Reg to integer
//
// ============================================================================
#include "singlepass/a64/asm/datatype.h"
#include "singlepass/common/definitions.h"

#include <asmjit/a64.h>

// ============================================================================
// DECL_ALL_REGISTER
//
// declare all used registers
//
// ============================================================================
#define DECL_WORD_REGISTER()                                                   \
  DECL_REG(w0)                                                                 \
  DECL_REG(w1)                                                                 \
  DECL_REG(w2)                                                                 \
  DECL_REG(w3)                                                                 \
  DECL_REG(w4)                                                                 \
  DECL_REG(w5)                                                                 \
  DECL_REG(w6)                                                                 \
  DECL_REG(w7)                                                                 \
  DECL_REG(w8)                                                                 \
  DECL_REG(w9)                                                                 \
  DECL_REG(w10)                                                                \
  DECL_REG(w11)                                                                \
  DECL_REG(w12)                                                                \
  DECL_REG(w13)                                                                \
  DECL_REG(w14)                                                                \
  DECL_REG(w15)                                                                \
  DECL_REG(w16)                                                                \
  DECL_REG(w17)                                                                \
  DECL_REG(w18)                                                                \
  DECL_REG(w19)                                                                \
  DECL_REG(w20)                                                                \
  DECL_REG(w21)                                                                \
  DECL_REG(w22)                                                                \
  DECL_REG(w23)                                                                \
  DECL_REG(w24)                                                                \
  DECL_REG(w25)                                                                \
  DECL_REG(w26)                                                                \
  DECL_REG(w27)                                                                \
  DECL_REG(w28)                                                                \
  DECL_REG(w29)                                                                \
  DECL_REG(w30)                                                                \
  DECL_REG(wzr)                                                                \
  DECL_REG(wsp)

#define DECL_XWORD_REGISTER()                                                  \
  DECL_REG(x0)                                                                 \
  DECL_REG(x1)                                                                 \
  DECL_REG(x2)                                                                 \
  DECL_REG(x3)                                                                 \
  DECL_REG(x4)                                                                 \
  DECL_REG(x5)                                                                 \
  DECL_REG(x6)                                                                 \
  DECL_REG(x7)                                                                 \
  DECL_REG(x8)                                                                 \
  DECL_REG(x9)                                                                 \
  DECL_REG(x10)                                                                \
  DECL_REG(x11)                                                                \
  DECL_REG(x12)                                                                \
  DECL_REG(x13)                                                                \
  DECL_REG(x14)                                                                \
  DECL_REG(x15)                                                                \
  DECL_REG(x16)                                                                \
  DECL_REG(x17)                                                                \
  DECL_REG(x18)                                                                \
  DECL_REG(x19)                                                                \
  DECL_REG(x20)                                                                \
  DECL_REG(x21)                                                                \
  DECL_REG(x22)                                                                \
  DECL_REG(x23)                                                                \
  DECL_REG(x24)                                                                \
  DECL_REG(x25)                                                                \
  DECL_REG(x26)                                                                \
  DECL_REG(x27)                                                                \
  DECL_REG(x28)                                                                \
  DECL_REG(x29)                                                                \
  DECL_REG(x30)                                                                \
  DECL_REG(xzr)                                                                \
  DECL_REG(sp)

#define DECL_GP_REGISTER()                                                     \
  DECL_WORD_REGISTER()                                                         \
  DECL_XWORD_REGISTER()

#define DECL_VECS_REGISTER()                                                   \
  DECL_REG(s0)                                                                 \
  DECL_REG(s1)                                                                 \
  DECL_REG(s2)                                                                 \
  DECL_REG(s3)                                                                 \
  DECL_REG(s4)                                                                 \
  DECL_REG(s5)                                                                 \
  DECL_REG(s6)                                                                 \
  DECL_REG(s7)                                                                 \
  DECL_REG(s8)                                                                 \
  DECL_REG(s9)                                                                 \
  DECL_REG(s10)                                                                \
  DECL_REG(s11)                                                                \
  DECL_REG(s12)                                                                \
  DECL_REG(s13)                                                                \
  DECL_REG(s14)                                                                \
  DECL_REG(s15)                                                                \
  DECL_REG(s16)                                                                \
  DECL_REG(s17)                                                                \
  DECL_REG(s18)                                                                \
  DECL_REG(s19)                                                                \
  DECL_REG(s20)                                                                \
  DECL_REG(s21)                                                                \
  DECL_REG(s22)                                                                \
  DECL_REG(s23)                                                                \
  DECL_REG(s24)                                                                \
  DECL_REG(s25)                                                                \
  DECL_REG(s26)                                                                \
  DECL_REG(s27)                                                                \
  DECL_REG(s28)                                                                \
  DECL_REG(s29)                                                                \
  DECL_REG(s30)                                                                \
  DECL_REG(s31)

#define DECL_VECD_REGISTER()                                                   \
  DECL_REG(d0)                                                                 \
  DECL_REG(d1)                                                                 \
  DECL_REG(d2)                                                                 \
  DECL_REG(d3)                                                                 \
  DECL_REG(d4)                                                                 \
  DECL_REG(d5)                                                                 \
  DECL_REG(d6)                                                                 \
  DECL_REG(d7)                                                                 \
  DECL_REG(d8)                                                                 \
  DECL_REG(d9)                                                                 \
  DECL_REG(d10)                                                                \
  DECL_REG(d11)                                                                \
  DECL_REG(d12)                                                                \
  DECL_REG(d13)                                                                \
  DECL_REG(d14)                                                                \
  DECL_REG(d15)                                                                \
  DECL_REG(d16)                                                                \
  DECL_REG(d17)                                                                \
  DECL_REG(d18)                                                                \
  DECL_REG(d19)                                                                \
  DECL_REG(d20)                                                                \
  DECL_REG(d21)                                                                \
  DECL_REG(d22)                                                                \
  DECL_REG(d23)                                                                \
  DECL_REG(d24)                                                                \
  DECL_REG(d25)                                                                \
  DECL_REG(d26)                                                                \
  DECL_REG(d27)                                                                \
  DECL_REG(d28)                                                                \
  DECL_REG(d29)                                                                \
  DECL_REG(d30)                                                                \
  DECL_REG(d31)

#define DECL_VECV_REGISTER()                                                   \
  DECL_REG(v0)                                                                 \
  DECL_REG(v1)                                                                 \
  DECL_REG(v2)                                                                 \
  DECL_REG(v3)                                                                 \
  DECL_REG(v4)                                                                 \
  DECL_REG(v5)                                                                 \
  DECL_REG(v6)                                                                 \
  DECL_REG(v7)                                                                 \
  DECL_REG(v8)                                                                 \
  DECL_REG(v9)                                                                 \
  DECL_REG(v10)                                                                \
  DECL_REG(v11)                                                                \
  DECL_REG(v12)                                                                \
  DECL_REG(v13)                                                                \
  DECL_REG(v14)                                                                \
  DECL_REG(v15)                                                                \
  DECL_REG(v16)                                                                \
  DECL_REG(v17)                                                                \
  DECL_REG(v18)                                                                \
  DECL_REG(v19)                                                                \
  DECL_REG(v20)                                                                \
  DECL_REG(v21)                                                                \
  DECL_REG(v22)                                                                \
  DECL_REG(v23)                                                                \
  DECL_REG(v24)                                                                \
  DECL_REG(v25)                                                                \
  DECL_REG(v26)                                                                \
  DECL_REG(v27)                                                                \
  DECL_REG(v28)                                                                \
  DECL_REG(v29)                                                                \
  DECL_REG(v30)                                                                \
  DECL_REG(v31)

#define DECL_FP_REGISTER()                                                     \
  DECL_VECS_REGISTER()                                                         \
  DECL_VECD_REGISTER()                                                         \
  DECL_VECV_REGISTER()

#define DECL_ALL_REGISTER()                                                    \
  DECL_GP_REGISTER()                                                           \
  DECL_FP_REGISTER()

namespace zen::singlepass {

namespace A64 {

// GP
// all supported general purpose register
// the order here must be the same as macros defined above
// the order here is set according to parameter passing order and temporary
// register allocation order:
//  param passing:   x0, x1, x2, x3, x4, x5, x6, x7
//  temp allocation: TBD
// otherwise the register value may be overwritten in preparing call params.
enum GP {
  X0,  // x0, w0
  X1,  // x1, w1
  X2,  // x2, w2
  X3,  // x3, w3
  X4,  // x4, w4
  X5,  // x5, w5
  X6,  // x6, w6
  X7,  // x7, w7
  X8,  // x8, w8
  X9,  // x9, w9
  X10, // x10, w10
  X11, // x11, w11
  X12, // x12, w12
  X13, // x13, w13
  X14, // x14, w14
  X15, // x15, w15
  X16, // x16, w16
  X17, // x17, w17
  X18, // x18, w18
  X19, // x19, w19
  X20, // x20, w20
  X21, // x21, w21
  X22, // x22, w22
  X23, // x23, w23
  X24, // x24, w24
  X25, // x25, w25
  X26, // x26, w26
  X27, // x27, w27
  X28, // x28, w28
  X29, // x29, w29
  X30, // x30, x30
  XZR, // xzr, wzr
  SP,  // sp, wsp
};     // GP

// FP
// all supported floating point registers
// the order here must be the same as macros defined above
// the order here is set according to parameter passing order and temporary
// register allocation order:
//  param passing:   v0, v1, v2, v3, v4, v5, v6, v7
//  temp allocation: TBD
// otherwise the register value may be overwritten in preparing call params.
enum FP {
  V0,  // v0, d0, s0
  V1,  // v1, d1, s1
  V2,  // v2, d2, s2
  V3,  // v3, d3, s3
  V4,  // v4, d4, s4
  V5,  // v5, d5, s5
  V6,  // v6, d6, s6
  V7,  // v7, d7, s7
  V8,  // v8, d8, s8
  V9,  // v9, d9, s9
  V10, // v10, d10, s10
  V11, // v11, d11, s11
  V12, // v12, d12, s12
  V13, // v13, d13, s13
  V14, // v14, d14, s14
  V15, // v15, d15, s15
  V16, // v16, d16, s16
  V17, // v17, d17, s17
  V18, // v18, d18, s18
  V19, // v19, d19, s19
  V20, // v20, d20, s20
  V21, // v21, d21, s21
  V22, // v22, d22, s22
  V23, // v23, d23, s23
  V24, // v24, d24, s24
  V25, // v25, d25, s25
  V26, // v26, d26, s26
  V27, // v27, d27, s27
  V28, // v28, d28, s28
  V29, // v29, d29, s29
  V30, // v30, d30, s30
  V31, // v31, d31, s31
};     // FP

enum RegKind {
  GPR = 0, // general purpose register
  FPR = 1  // floating point/vector register
};

enum RegCount { GP_COUNT = SP - X0 + 1, FP_COUNT = V31 - V0 + 1 };

// regnum for either GP or FP
typedef uint32_t RegNum;

} // namespace A64

// ============================================================================
// A64TypeAttr
// trait to convert A64 type to asmjit register type
// ============================================================================
template <A64::Type type> struct A64TypeAttr;

template <> struct A64TypeAttr<A64::I8> {
  static constexpr A64::Type WidenType = A64::I32;
  static constexpr A64::RegKind Kind = A64::GPR;
  typedef asmjit::a64::GpW Type;
  typedef int8_t ValType;
  typedef A64::GP RegNum;
  static constexpr uint32_t Offset = A64::GP_COUNT * 0;
  static constexpr uint32_t StackAlign = 8;
  static constexpr uint32_t Size = 1;
};

template <> struct A64TypeAttr<A64::I16> {
  static constexpr A64::Type WidenType = A64::I32;
  static constexpr A64::RegKind Kind = A64::GPR;
  typedef asmjit::a64::GpW Type;
  typedef int16_t ValType;
  typedef A64::GP RegNum;
  static constexpr uint32_t Offset = A64::GP_COUNT * 0;
  static constexpr uint32_t StackAlign = 8;
  static constexpr uint32_t Size = 2;
};

template <> struct A64TypeAttr<A64::I32> {
  static constexpr A64::Type WidenType = A64::I32;
  static constexpr A64::RegKind Kind = A64::GPR;
  typedef asmjit::a64::GpW Type;
  typedef int32_t ValType;
  typedef A64::GP RegNum;
  static constexpr uint32_t Offset = A64::GP_COUNT * 0;
  static constexpr uint32_t StackAlign = 8;
  static constexpr uint32_t Size = 4;
};

template <> struct A64TypeAttr<A64::I64> {
  static constexpr A64::Type WidenType = A64::I64;
  static constexpr A64::RegKind Kind = A64::GPR;
  typedef asmjit::a64::GpX Type;
  typedef int64_t ValType;
  typedef A64::GP RegNum;
  static constexpr uint32_t Offset = A64::GP_COUNT * 1;
  static constexpr uint32_t StackAlign = 8;
  static constexpr uint32_t Size = 8;
};

template <> struct A64TypeAttr<A64::F32> {
  static constexpr A64::Type WidenType = A64::F32;
  static constexpr A64::RegKind Kind = A64::FPR;
  typedef asmjit::a64::VecS Type;
  typedef float ValType;
  typedef A64::FP RegNum;
  static constexpr uint32_t Offset = A64::GP_COUNT * 2 + A64::FP_COUNT * 0;
  static constexpr uint32_t StackAlign = 8;
  static constexpr uint32_t Size = 4;
};

template <> struct A64TypeAttr<A64::F64> {
  static constexpr A64::Type WidenType = A64::F64;
  static constexpr A64::RegKind Kind = A64::FPR;
  typedef asmjit::a64::VecD Type;
  typedef double ValType;
  typedef A64::FP RegNum;
  static constexpr uint32_t Offset = A64::GP_COUNT * 2 + A64::FP_COUNT * 1;
  static constexpr uint32_t StackAlign = 8;
  static constexpr uint32_t Size = 8;
};

template <> struct A64TypeAttr<A64::V128> {
  static constexpr A64::Type WidenType = A64::V128;
  static constexpr A64::RegKind Kind = A64::FPR;
  typedef asmjit::a64::VecV Type;
  typedef common::V128 ValType;
  typedef A64::FP RegNum;
  static constexpr uint32_t Offset = A64::GP_COUNT * 2 + A64::FP_COUNT * 2;
  static constexpr uint32_t StackAlign = 16;
  static constexpr uint32_t Size = 16;
};

template <A64::Type type> using A64RegType = typename A64TypeAttr<type>::Type;

template <A64::Type type> using A64RegNum = typename A64TypeAttr<type>::RegNum;

// ============================================================================
// A64Register
//
// manage the map from integer to asmjit::a64::Reg
//
// ============================================================================
class A64Reg {
private:
  // all supported registers in asmjit
  enum Register {
#define DECL_REG(x) x,
    DECL_ALL_REGISTER()
#undef DECL_REG
        LAST_REG,
    FIRST_REG = w0,
    FIRST_GPW = w0, // w0 ~ wsp is GP for word
    LAST_GPW = wsp,
    FIRST_GPX = x0, // x0 ~ sp is GP for extanded-word
    LAST_GPX = sp,
    FIRST_GP = w0, // w0 ~ sp is all GP
    LAST_GP = sp,
    FIRST_VECS = s0, // s0 ~ s31 is F32
    LAST_VECS = s31,
    FIRST_VECD = d0, // d0 ~ d31 is F64
    LAST_VECD = d31,
    FIRST_VECV = v0, // v0 ~ v31 is V128
    LAST_VECV = v31,
    FIRST_FP = s0, // s0 ~ v31 is all FP
    LAST_FP = v31,
  }; // Register

  static const asmjit::a64::Reg *Regs[LAST_REG];

public:
  template <A64::Type Ty, A64::RegNum Reg>
  static constexpr typename A64TypeAttr<Ty>::Type &getRegRef() {
    constexpr uint32_t Index = A64TypeAttr<Ty>::Offset + Reg;
    ZEN_STATIC_ASSERT(Index < LAST_REG);
    return *(typename A64TypeAttr<Ty>::Type *)Regs[Index];
  }

  template <A64::Type Ty>
  static const typename A64TypeAttr<Ty>::Type &getRegRef(A64::RegNum Reg) {
    const uint32_t Index = A64TypeAttr<Ty>::Offset + Reg;
    ZEN_ASSERT(Index < LAST_REG);
    return *(typename A64TypeAttr<Ty>::Type *)Regs[Index];
  }

public:
  static const char *getRegName(A64::Type Ty, A64::RegNum Reg) {
    static const char *Regname[LAST_REG] = {
#define DECL_REG(x) #x,
        DECL_ALL_REGISTER()
#undef DECL_REG
    };
    uint32_t Index;
    switch (Ty) {
    case A64::I8:
    case A64::I16:
    case A64::I32:
      Index = Reg;
      break;
    case A64::I64:
      Index = A64::GP_COUNT + Reg;
      break;
    case A64::F32:
      Index = A64::GP_COUNT * 2 + Reg;
      break;
    case A64::F64:
      Index = A64::GP_COUNT * 2 + A64::FP_COUNT + Reg;
      break;
    case A64::V128:
      Index = A64::GP_COUNT * 2 + A64::FP_COUNT * 2 + Reg;
      break;
    default:
      ZEN_ABORT();
      return "-error-";
    }
    ZEN_ASSERT(Index < LAST_REG);
    return Regname[Index];
  }

}; // A64Reg

template <A64::Type Ty> constexpr bool isMemOffsetValid(int32_t Offset) {
  auto Size = A64TypeAttr<Ty>::Size;
  if (Size == 4 && (Offset % 4) == 0 && Offset >= 0 && Offset <= 16380) {
    return true;
  }
  if (Size == 8 && (Offset % 8) == 0 && Offset >= 0 && Offset <= 32760) {
    return true;
  }
  return Offset >= -256 && Offset <= 255;
}

constexpr bool isArithImmValid(int32_t Imm) {
  if ((Imm & 0xfff) == 0) {
    Imm >>= 12;
  }
  return Imm >= 0 && Imm <= 4095;
}

} // namespace zen::singlepass

#endif // ZEN_SINGLEPASS_A64_ASM_REGISTER_H
