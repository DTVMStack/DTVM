// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_SINGLEPASS_X64_ASM_REGISTER_H
#define ZEN_SINGLEPASS_X64_ASM_REGISTER_H

// ============================================================================
// x64/asm/register.h
//
// Map asmjit::x86::Reg to integer
//
// ============================================================================

#include "singlepass/common/definitions.h"
#include "singlepass/x64/asm/datatype.h"

// ============================================================================
// DECL_ALL_REGISTER
//
// declare all used registers
//
// ============================================================================
#define DECL_BYTE_REGISTER()                                                   \
  DECL_REG(al)                                                                 \
  DECL_REG(bl)                                                                 \
  DECL_REG(cl)                                                                 \
  DECL_REG(dl)                                                                 \
  DECL_REG(spl)                                                                \
  DECL_REG(bpl)                                                                \
  DECL_REG(dil)                                                                \
  DECL_REG(sil)                                                                \
  DECL_REG(r10b)                                                               \
  DECL_REG(r11b)                                                               \
  DECL_REG(r8b)                                                                \
  DECL_REG(r9b)                                                                \
  DECL_REG(r12b)                                                               \
  DECL_REG(r13b)                                                               \
  DECL_REG(r14b)                                                               \
  DECL_REG(r15b)

#define DECL_WORD_REGISTER()                                                   \
  DECL_REG(ax)                                                                 \
  DECL_REG(bx)                                                                 \
  DECL_REG(cx)                                                                 \
  DECL_REG(dx)                                                                 \
  DECL_REG(sp)                                                                 \
  DECL_REG(bp)                                                                 \
  DECL_REG(di)                                                                 \
  DECL_REG(si)                                                                 \
  DECL_REG(r10w)                                                               \
  DECL_REG(r11w)                                                               \
  DECL_REG(r8w)                                                                \
  DECL_REG(r9w)                                                                \
  DECL_REG(r12w)                                                               \
  DECL_REG(r13w)                                                               \
  DECL_REG(r14w)                                                               \
  DECL_REG(r15w)

#define DECL_DWORD_REGISTER()                                                  \
  DECL_REG(eax)                                                                \
  DECL_REG(ebx)                                                                \
  DECL_REG(ecx)                                                                \
  DECL_REG(edx)                                                                \
  DECL_REG(esp)                                                                \
  DECL_REG(ebp)                                                                \
  DECL_REG(edi)                                                                \
  DECL_REG(esi)                                                                \
  DECL_REG(r10d)                                                               \
  DECL_REG(r11d)                                                               \
  DECL_REG(r8d)                                                                \
  DECL_REG(r9d)                                                                \
  DECL_REG(r12d)                                                               \
  DECL_REG(r13d)                                                               \
  DECL_REG(r14d)                                                               \
  DECL_REG(r15d)

#define DECL_QWORD_REGISTER()                                                  \
  DECL_REG(rax)                                                                \
  DECL_REG(rbx)                                                                \
  DECL_REG(rcx)                                                                \
  DECL_REG(rdx)                                                                \
  DECL_REG(rsp)                                                                \
  DECL_REG(rbp)                                                                \
  DECL_REG(rdi)                                                                \
  DECL_REG(rsi)                                                                \
  DECL_REG(r10)                                                                \
  DECL_REG(r11)                                                                \
  DECL_REG(r8)                                                                 \
  DECL_REG(r9)                                                                 \
  DECL_REG(r12)                                                                \
  DECL_REG(r13)                                                                \
  DECL_REG(r14)                                                                \
  DECL_REG(r15)

#define DECL_GP_REGISTER()                                                     \
  DECL_BYTE_REGISTER()                                                         \
  DECL_WORD_REGISTER()                                                         \
  DECL_DWORD_REGISTER()                                                        \
  DECL_QWORD_REGISTER()

#define DECL_XMM_REGISTER()                                                    \
  DECL_REG(xmm0)                                                               \
  DECL_REG(xmm1)                                                               \
  DECL_REG(xmm2)                                                               \
  DECL_REG(xmm8)                                                               \
  DECL_REG(xmm9)                                                               \
  DECL_REG(xmm10)                                                              \
  DECL_REG(xmm3)                                                               \
  DECL_REG(xmm4)                                                               \
  DECL_REG(xmm5)                                                               \
  DECL_REG(xmm6)                                                               \
  DECL_REG(xmm7)                                                               \
  DECL_REG(xmm11)                                                              \
  DECL_REG(xmm12)                                                              \
  DECL_REG(xmm13)                                                              \
  DECL_REG(xmm14)                                                              \
  DECL_REG(xmm15)

#define DECL_FP_REGISTER() DECL_XMM_REGISTER()

#define DECL_ALL_REGISTER()                                                    \
  DECL_GP_REGISTER()                                                           \
  DECL_FP_REGISTER()

namespace zen::singlepass {

namespace X64 {

// GP
// all supported general purpose register
// the order here must be the same as macros defined above
// the order here is set according to parameter passing order and temporary
// register allocation order:
//  param passing:   rdi, rsi, rdx, rcx, r8, r9
//  temp allocation: rdi, rsi, r10, r11, r8, r9
// otherwise the register value may be overwritten in preparing call params.
enum GP {
  RAX, // rax, eax, ax, al
  RBX, // rbx, ebx, bx, bl
  RCX, // rcx, ecx, cx, cl
  RDX, // rdx, edx, dx, dl
  RSP, // rsp, esp, sp, spl
  RBP, // rbp, ebp, bp, dpl
  RDI, // rdi, edi, di, dil
  RSI, // rsi, esi, si, sil
  R10, // r10, r10d, r10w, r10b
  R11, // r11, r11d, r11w, r11b
  R8,  // r8, r8d, r8w, r8b
  R9,  // r9, r9d, r9w, r9b
  R12, // r12, r12d, r12w, r12b
  R13, // r13, r13d, r13w, r13b
  R14, // r14, r14d, r14w, r14b
  R15, // r15, r15d, r15w, r15b
};     // GP

// FP
// all supported floating point registers
// the order here must be the same as macros defined above
// the order here is set according to parameter passing order and temporary
// register allocation order:
//  param passing:   xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8
//  temp allocation: xmm8, xmm9, xmm10,xmm3, xmm4, xmm5, xmm6, xmm7, xmm8
// otherwise the register value may be overwritten in preparing call params.
enum FP {
  XMM0,  // xmm0
  XMM1,  // xmm1
  XMM2,  // xmm2
  XMM8,  // xmm8
  XMM9,  // xmm9
  XMM10, // xmm10
  XMM3,  // xmm3
  XMM4,  // xmm4
  XMM5,  // xmm5
  XMM6,  // xmm6
  XMM7,  // xmm7
  XMM11, // xmm11
  XMM12, // xmm12
  XMM13, // xmm13
  XMM14, // xmm14
  XMM15, // xmm15
};       // FP

enum RegKind {
  GPR = 0, // general purpose register
  FPR = 1  // floating point/vector register
};

enum RegCount { GP_COUNT = R15 - RAX + 1, FP_COUNT = XMM15 - XMM0 + 1 };

// regnum for either GP or FP
typedef uint32_t RegNum;

} // namespace X64

// ============================================================================
// X64TypeAttr
// trait to convert X64 type to asmjit register type
// ============================================================================
template <X64::Type Ty> struct X64TypeAttr;

template <> struct X64TypeAttr<X64::I8> {
  static constexpr X64::Type WidenType = X64::I32;
  static constexpr X64::RegKind Kind = X64::GPR;
  typedef asmjit::x86::GpbLo Type; // register object type in asmjit
  typedef X64::GP RegNum;          // register enum type
  // offset in register array
  static constexpr uint32_t Offset = X64::GP_COUNT * 0;
  static constexpr uint32_t StackAlign = 8; // 8-byte if pass on stack
  static constexpr uint32_t Size = 1;       // 1-byte
};

template <> struct X64TypeAttr<X64::I16> {
  static constexpr X64::Type WidenType = X64::I32;
  static constexpr X64::RegKind Kind = X64::GPR;
  typedef asmjit::x86::Gpw Type;
  typedef X64::GP RegNum;
  static constexpr uint32_t Offset = X64::GP_COUNT * 1;
  static constexpr uint32_t StackAlign = 8;
  static constexpr uint32_t Size = 2;
};

template <> struct X64TypeAttr<X64::I32> {
  static constexpr X64::Type WidenType = X64::I32;
  static constexpr X64::RegKind Kind = X64::GPR;
  typedef asmjit::x86::Gpd Type;
  typedef X64::GP RegNum;
  static constexpr uint32_t Offset = X64::GP_COUNT * 2;
  static constexpr uint32_t StackAlign = 8;
  static constexpr uint32_t Size = 4;
};

template <> struct X64TypeAttr<X64::I64> {
  static constexpr X64::Type WidenType = X64::I64;
  static constexpr X64::RegKind Kind = X64::GPR;
  typedef asmjit::x86::Gpq Type;
  typedef X64::GP RegNum;
  static constexpr uint32_t Offset = X64::GP_COUNT * 3;
  static constexpr uint32_t StackAlign = 8;
  static constexpr uint32_t Size = 8;
};

template <> struct X64TypeAttr<X64::F32> {
  static constexpr X64::Type WidenType = X64::F32;
  static constexpr X64::RegKind Kind = X64::FPR;
  typedef asmjit::x86::Xmm Type;
  typedef X64::FP RegNum;
  static constexpr uint32_t Offset = X64::GP_COUNT * 4; // same XMM registers
  static constexpr uint32_t StackAlign = 8;
  static constexpr uint32_t Size = 4;
};

template <> struct X64TypeAttr<X64::F64> {
  static constexpr X64::Type WidenType = X64::F64;
  static constexpr X64::RegKind Kind = X64::FPR;
  typedef asmjit::x86::Xmm Type;
  typedef X64::FP RegNum;
  static constexpr uint32_t Offset = X64::GP_COUNT * 4; // same XMM registers
  static constexpr uint32_t StackAlign = 8;
  static constexpr uint32_t Size = 8;
};

template <> struct X64TypeAttr<X64::V128> {
  static constexpr X64::Type WidenType = X64::V128;
  static constexpr X64::RegKind Kind = X64::FPR;
  typedef asmjit::x86::Xmm Type;
  typedef X64::FP RegNum;
  static constexpr uint32_t Offset = X64::GP_COUNT * 4; // same XMM registers
  static constexpr uint32_t StackAlign = 16;
  static constexpr uint32_t Size = 16;
};

template <X64::Type Ty> using X64RegType = typename X64TypeAttr<Ty>::Type;

template <X64::Type Ty> using X64RegNum = typename X64TypeAttr<Ty>::RegNum;

// ============================================================================
// X64Register
//
// manage the map from integer to asmjit::x86::Reg
//
// ============================================================================
class X64Reg {
private:
  // all supported registers in asmjit
  enum Register {
#define DECL_REG(x) x,
    DECL_ALL_REGISTER()
#undef DECL_REG
        LAST_REG,
    FIRST_REG = al,
    FIRST_GPB = al, // al ~ r15b is GP for byte
    LAST_GPB = r15b,
    FIRST_GPW = ax, // ax ~ r15w is GP for word
    LAST_GPW = r15w,
    FIRST_GPD = eax, // eax ~ r15d is GP for double-word
    LAST_GPD = r15d,
    FIRST_GPQ = rax, // rax ~ r15 is GP for quad-word
    LAST_GPQ = r15,
    FIRST_GP = al, // al ~ r15 is all GP
    LAST_GP = r15,
    FIRST_XMM = xmm0, // xmm0 ~ xmm31 is FP
    LAST_XMM = xmm15,
    GP_COUNT = r15 - rax + 1,
    FP_COUNT = xmm15 - xmm0 + 1,
  }; // Register

  static const asmjit::x86::Reg *Regs[LAST_REG];

public:
  template <X64::Type Ty, X64::RegNum Reg>
  static constexpr typename X64TypeAttr<Ty>::Type &getRegRef() {
    constexpr uint32_t Index = X64TypeAttr<Ty>::Offset + Reg;
    ZEN_STATIC_ASSERT(Index < LAST_REG);
    return *(typename X64TypeAttr<Ty>::Type *)Regs[Index];
  }

  template <X64::Type Ty>
  static const typename X64TypeAttr<Ty>::Type &getRegRef(X64::RegNum Reg) {
    const uint32_t Index = X64TypeAttr<Ty>::Offset + Reg;
    ZEN_ASSERT(Index < LAST_REG);
    return *(typename X64TypeAttr<Ty>::Type *)Regs[Index];
  }

public:
  static const char *getRegName(X64::Type Ty, X64::RegNum Reg) {
    static const char *Regname[LAST_REG] = {
#define DECL_REG(x) #x,
        DECL_ALL_REGISTER()
#undef DECL_REG
    };
    const uint32_t Index = Ty * GP_COUNT + Reg;
    ZEN_ASSERT(Index < LAST_REG);
    return Regname[Index];
  }

}; // class X64Reg

} // namespace zen::singlepass

#endif // ZEN_SINGLEPASS_X64_ASM_REGISTER_H
