// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_SINGLEPASS_X64_ASSEMBLER_H
#define ZEN_SINGLEPASS_X64_ASSEMBLER_H

// ============================================================================
// x64/assembler.h
//
// wrap asmjit assembler for onepass x64 jit compiler
//
// ============================================================================

#include "singlepass/common/definitions.h"
#include "singlepass/x64/asm/assembler.h"
#include "singlepass/x64/asm/register.h"
#include "singlepass/x64/operand.h"
#include "singlepass/x64/operator.h"

namespace zen::singlepass {

// ============================================================================
// TypedOperatorBase
//
// dummy implementation for null operator
//
// ============================================================================
template <X64::Type Ty> class TypedOperatorBase {
public:
  typedef X64RegType<Ty> Reg;   // asmjit register reference operand
  typedef asmjit::x86::Mem Mem; // asmjit memory operand
  typedef int32_t Imm;          // immediate operand
  typedef X64InstOperand Opnd;  // general operand
};                              // TypedOperatorBase

// ============================================================================
// BinaryOperatorBase<X64::Type type, BinaryOperator opr>
//
// class prototype declaration for binary operator base
// this class must be specialized for given operator
//
// ============================================================================
template <X64::Type Ty, BinaryOperator Opr> class BinaryOperatorBase {
public:
  // emit { reg, mem } -opr- { reg, mem, imm }
  template <typename LHSType, typename RHSType>
  static void emit(X64Assembler &_, LHSType LHS, RHSType RHS) {
    // can't call. this class must be specialized.
    // keep temporarily to avoid compile error. should be removed later
    ZEN_ABORT();
  }
};

// make a macro to simplify the class specialization
#define DECL_BINOP_IMPL(Opr, Asmop)                                            \
  template <X64::Type type>                                                    \
  class BinaryOperatorBase<type, BinaryOperator::Opr>                          \
      : public TypedOperatorBase<type> {                                       \
  public:                                                                      \
    template <typename LHSType, typename RHSType>                              \
    static void emit(X64Assembler &_, LHSType LHS, RHSType RHS) {              \
      _.Asmop<type>(LHS, RHS);                                                 \
    }                                                                          \
  }

template <X64::Type Ty>
class BinaryOperatorBase<Ty, BinaryOperator::BO_DIV_U>
    : public TypedOperatorBase<Ty> {
public:
  template <typename LHSType, typename RHSType>
  static void emit(X64Assembler &_, LHSType LHS, RHSType RHS) {
    _.div<Ty>(LHS); // lhs == rhs
  }
};

template <X64::Type Ty>
class BinaryOperatorBase<Ty, BinaryOperator::BO_DIV_S>
    : public TypedOperatorBase<Ty> {
public:
  template <typename LHSType, typename RHSType>
  static void emit(X64Assembler &_, LHSType LHS, RHSType RHS) {
    _.idiv<Ty>(LHS); // lhs == rhs
  }
};

template <X64::Type Ty>
class BinaryOperatorBase<Ty, BinaryOperator::BO_REM_U>
    : public TypedOperatorBase<Ty> {
public:
  template <typename LHSType, typename RHSType>
  static void emit(X64Assembler &_, LHSType LHS, RHSType RHS) {
    _.div<Ty>(LHS); // lhs == rhs
  }
};

template <X64::Type Ty>
class BinaryOperatorBase<Ty, BinaryOperator::BO_REM_S>
    : public TypedOperatorBase<Ty> {
public:
  template <typename LHSType, typename RHSType>
  static void emit(X64Assembler &_, LHSType LHS, RHSType RHS) {
    _.idiv<Ty>(LHS); // lhs == rhs
  }
};

// specialization more binary operators
// in alphabetical order
DECL_BINOP_IMPL(BO_ADD, add);
DECL_BINOP_IMPL(BO_AND, and_);
DECL_BINOP_IMPL(BO_DIV, div);
DECL_BINOP_IMPL(BO_MAX, max);
DECL_BINOP_IMPL(BO_MIN, min);
DECL_BINOP_IMPL(BO_MOV, mov);
DECL_BINOP_IMPL(BO_MUL, imul);
DECL_BINOP_IMPL(BO_OR, or_);
DECL_BINOP_IMPL(BO_ROTL, rol);
DECL_BINOP_IMPL(BO_ROTR, ror);
DECL_BINOP_IMPL(BO_SHL, shl);
DECL_BINOP_IMPL(BO_SHR_S, sar);
DECL_BINOP_IMPL(BO_SHR_U, shr);
DECL_BINOP_IMPL(BO_SUB, sub);
DECL_BINOP_IMPL(BO_XOR, xor_);

#undef DECL_BINOP_IMPL

// ============================================================================
// BinaryOperatorImpl<X64::Type type, BinaryOperator opr>
//
// real binary operator implementation used by X64OnePassCodeGenImpl
//
// ============================================================================
template <X64::Type Ty, BinaryOperator Opr>
class BinaryOperatorImpl : public BinaryOperatorBase<Ty, Opr> {
public:
  typedef X64RegType<Ty> Reg;   // asmjit register reference operand
  typedef asmjit::x86::Mem Mem; // asmjit memory operand
  typedef int32_t Imm;          // immediate operand
  typedef X64InstOperand Opnd;  // general operand

public:
  // also allow using Emit directly
  using BinaryOperatorBase<Ty, Opr>::emit;

public:
  // emit reg -opr- opnd
  static void emit(X64Assembler &_, const Reg &LHS, const Opnd RHS) {
    if (RHS.isReg()) {
      BinaryOperatorBase<Ty, Opr>::emit(_, LHS, RHS.getRegRef<Ty>());
    } else if (RHS.isMem()) {
      BinaryOperatorBase<Ty, Opr>::emit(_, LHS, RHS.getMem<Ty>());
    } else if (RHS.isImm()) {
      BinaryOperatorBase<Ty, Opr>::emit(_, LHS, RHS.getImm());
    } else {
      ZEN_ABORT();
    }
  }

  // emit mem -opr- opnd
  static void emit(X64Assembler &_, const Mem &LHS, const Opnd RHS) {
    if (RHS.isReg()) {
      BinaryOperatorBase<Ty, Opr>::emit(_, LHS, RHS.getRegRef<Ty>());
    } else if (RHS.isImm()) {
      BinaryOperatorBase<Ty, Opr>::emit(_, LHS, RHS.getImm());
    } else {
      if (Opr != BinaryOperator::BO_DIV_U && Opr != BinaryOperator::BO_DIV_S &&
          Opr != BinaryOperator::BO_REM_U && Opr != BinaryOperator::BO_REM_S) {
        ZEN_ABORT();
      }
    }
  }

  // emit opnd -opr- opnd
  static void emit(X64Assembler &_, const Opnd LHS, const Opnd RHS) {
    if (LHS.isReg()) {
      emit(_, LHS.getRegRef<Ty>(), RHS);
    } else if (LHS.isMem()) {
      emit(_, LHS.getMem<Ty>(), RHS);
    } else {
      ZEN_ABORT();
    }
  }
}; // BinaryOperatorImpl

// ============================================================================
// CompareOperator<X64::Type type, CompareOperator opr>
//
// class prototype declaration for comparison operator base
// this class must be specialized for given operator
//
// ============================================================================
template <X64::Type Ty, CompareOperator Opr> class CompareOperatorBase {
public:
  // emit { reg, mem } -opr- { reg, mem, imm }
  template <typename LHSType, typename RHSType>
  static void emit(X64Assembler &_, LHSType LHS, RHSType RHS) {
    // can't call. this class must be specialized.
    // keep temporarily to avoid compile error. should be removed later
    ZEN_ABORT();
  }
};

// ============================================================================
// CompareOperatorBase<type, CO_EQZ>
// ============================================================================
template <X64::Type Ty>
class CompareOperatorBase<Ty, CompareOperator::CO_EQZ>
    : public TypedOperatorBase<Ty> {
public:
  // emit { reg, mem } -opr- { reg, mem, imm }
  template <typename LHSType, typename RHSType>
  static void emit(X64Assembler &_, LHSType LHS, RHSType RHS) {
    ZEN_ASSERT_TODO();
  }
}; // CompareOperatorBase<type, CO_EQZ>

// make a macro to simplify the class specialization
#define DECL_CMPOP_IMPL(Opr, Asmop)                                            \
  template <X64::Type Ty>                                                      \
  class CompareOperatorBase<Ty, CO_##Opr> : public TypedOperatorBase<Ty> {     \
  public:                                                                      \
    template <typename LHSType, typename RHSType>                              \
    static void emit(X64Assembler &_, LHSType LHS, RHSType RHS) {              \
      _.asmop<type>(LHS, RHS);                                                 \
    }                                                                          \
  }

// TODO: specialization more compare operators
// in alphabetical order
// DECL_CMPOP_IMPL(EQ, test);

// ============================================================================
// CompareOperatorImpl<X64::Type type, CompareOperator opr>
//
// real compare operator implementation used by X64OnePassCodeGenImpl
//
// ============================================================================
template <X64::Type Ty, CompareOperator Opr>
class CompareOperatorImpl : public CompareOperatorBase<Ty, Opr> {
public:
  typedef X64RegType<Ty> Reg;   // asmjit register reference operand
  typedef asmjit::x86::Mem Mem; // asmjit memory operand
  typedef int32_t Imm;          // immediate operand
  typedef X64InstOperand Opnd;  // general operand

public:
  // also allow using Emit directly
  using CompareOperatorBase<Ty, Opr>::emit;

public:
  // emit reg -opr- opnd
  static void emit(X64Assembler &_, const Reg &LHS, const Opnd RHS) {
    if (RHS.isReg()) {
      CompareOperatorBase<Ty, Opr>::emit(_, LHS, RHS.getRegRef<Ty>());
    } else if (RHS.isMem()) {
      CompareOperatorBase<Ty, Opr>::emit(_, LHS, RHS.getMem<Ty>());
    } else if (RHS.isImm()) {
      CompareOperatorBase<Ty, Opr>::emit(_, LHS, RHS.getImm());
    } else {
      ZEN_ABORT();
    }
  }

  // emit mem -opr- opnd
  static void emit(X64Assembler &_, const Mem &LHS, const Opnd RHS) {
    if (RHS.isReg()) {
      CompareOperatorBase<Ty, Opr>::emit(_, LHS, RHS.getRegRef<Ty>());
    } else if (RHS.isImm()) {
      CompareOperatorBase<Ty, Opr>::emit(_, LHS, RHS.getImm());
    } else {
      ZEN_ABORT();
    }
  }

  // emit opnd -opr- opnd
  static void emit(X64Assembler &_, const Opnd LHS, const Opnd RHS) {
    if (LHS.isReg()) {
      emit(_, LHS.getRegRef<Ty>(), RHS);
    } else if (LHS.isMem()) {
      emit(_, LHS.getMem<Ty>(), RHS);
    } else {
      ZEN_ABORT();
    }
  }
};

// ============================================================================
// UnaryOperator<X64::Type type, UnaryOperator opr>
//
// class prototype declaration for unary operator base
// this class must be specialized for given operator
//
// ============================================================================
template <X64::Type Ty, UnaryOperator Opr> class UnaryOperatorBase {
public:
  // emit -opr- { reg, mem }
  template <typename OperandType>
  static void emit(X64Assembler &_, OperandType Op) {
    // can't call. this class must be specialized.
    // keep temporarily to avoid compile error. should be removed later
    ZEN_ABORT();
  }
};

// make a macro to simplify the class specialization
#define DECL_UNAOP_IMPL(Opr, Asmop)                                            \
  template <X64::Type Ty>                                                      \
  class UnaryOperatorBase<Ty, UnaryOperator::Opr>                              \
      : public TypedOperatorBase<Ty> {                                         \
  public:                                                                      \
    template <typename OpndType>                                               \
    static void emit(X64Assembler &_, OpndType Opnd) {                         \
      _.Asmop<Ty>(Opnd);                                                       \
    }                                                                          \
  }

// TODO: specialization more compare operators
// in alphabetical order
DECL_UNAOP_IMPL(UO_NEG, neg);
DECL_UNAOP_IMPL(UO_NOT, not_);

// ============================================================================
// UnaryOperatorImpl<X64::Type type, UnaryOperator opr>
//
// real unary operator implementation used by X64OnePassCodeGenImpl
//
// ============================================================================
template <X64::Type Ty, UnaryOperator Opr>
class UnaryOperatorImpl : public UnaryOperatorBase<Ty, Opr> {
public:
  typedef X64RegType<Ty> Reg;   // asmjit register reference operand
  typedef asmjit::x86::Mem Mem; // asmjit memory operand
  typedef int32_t Imm;          // immediate operand
  typedef X64InstOperand Opnd;  // general operand

public:
  // also allow using Emit directly
  using UnaryOperatorBase<Ty, Opr>::emit;

public:
  // emit -opr- opnd
  static void emit(X64Assembler &_, const Opnd Op) {
    if (Op.isReg()) {
      UnaryOperatorBase<Ty, Opr>::emit(_, Op.getRegRef<Ty>());
    } else if (Op.isMem()) {
      UnaryOperatorBase<Ty, Opr>::emit(_, Op.getMem<Ty>());
    } else {
      ZEN_ABORT();
    }
  }
};

// This is kind of hacky, as we require source and dest register to be the same.
template <X64::Type Ty> class UnaryOperatorImpl<Ty, UnaryOperator::UO_CLZ> {
public:
  static void emit(X64Assembler &_, X64RegType<Ty> Op) {
    if (_.LegacyLZCNT) {
      emitFallback(_, Op);
      return;
    }
    _.lzcnt<Ty>(Op, Op);
  }

  static void emitFallback(X64Assembler &_, X64RegType<Ty> Operand) {
    constexpr unsigned RegSizeInBits = Ty == X64::I32 ? 32 : 64;
    // Scoped temp register except RAX(considering Operand is RAX)
    const auto &TmpReg = X64Reg::template getRegRef<Ty>(X64::RCX);

    _.Assembler().bsr(Operand, Operand);
    _.Assembler().mov(TmpReg, 2 * RegSizeInBits - 1);
    _.Assembler().cmove(Operand, TmpReg);
    _.Assembler().xor_(Operand, RegSizeInBits - 1);
  }
};

template <X64::Type Ty> class UnaryOperatorImpl<Ty, UnaryOperator::UO_CTZ> {
public:
  static void emit(X64Assembler &_, X64RegType<Ty> Op) {
    if (_.LegacyTZCNT) {
      emitFallback(_, Op);
      return;
    }
    _.tzcnt<Ty>(Op, Op);
  }

  static void emitFallback(X64Assembler &_, X64RegType<Ty> Operand) {
    constexpr unsigned RegSizeInBits = Ty == X64::I32 ? 32 : 64;
    // Scoped temp register except RAX(considering Operand is RAX)
    const auto &TmpReg = X64Reg::template getRegRef<Ty>(X64::RCX);

    _.Assembler().bsf(Operand, Operand);
    _.Assembler().mov(TmpReg, RegSizeInBits);
    _.Assembler().cmove(Operand, TmpReg);
  }
};

template <X64::Type Ty> class UnaryOperatorImpl<Ty, UnaryOperator::UO_POPCNT> {
public:
  static void emit(X64Assembler &_, X64RegType<Ty> Op) {
    if (_.LegacyPOPCNT) {
      emitFallback(_, Op);
      return;
    }
    _.popcnt<Ty>(Op, Op);
  }

  /**
   *  SWAR Algorithm for Popcount
   *
   *  int popcount(int n) {
   *      n = n - (n >> 1) & 0x55555555;
   *      n = (n & 0x33333333) + (n >> 2) & 0x33333333;
   *      n = (n + n >> 4) & 0x0F0F0F0F;
   *      return (n * 0x01010101) >> 24;
   *  }
   *
   *  long popcountl(long n) {
   *      n = n - ((n >> 1) & 0x5555555555555555);
   *      n = (n & 0x3333333333333333) + ((n >> 2) & 0x3333333333333333);
   *      n = (n + (n >> 4)) & 0xF0F0F0F0F0F0F0F;
   *      return (n * 0x101010101010101) >> 56;
   *  }
   */
  static void emitFallback(X64Assembler &_, X64RegType<Ty> Operand) {
    constexpr bool Is32Bits = Ty == X64::I32;
    constexpr uint64_t Mask1 = Is32Bits ? 0x55555555 : 0x5555555555555555;
    constexpr uint64_t Mask2 = Is32Bits ? 0x33333333 : 0x3333333333333333;
    constexpr uint64_t Mask3 = Is32Bits ? 0x0f0f0f0f : 0x0f0f0f0f0f0f0f0f;
    constexpr uint64_t IMULImm = Is32Bits ? 0x01010101 : 0x0101010101010101;
    constexpr uint64_t SHRImm1 = 2;
    constexpr uint64_t SHRImm2 = 4;
    constexpr uint64_t SHRImm3 = Is32Bits ? 24 : 56;

    // Scoped temp register except RAX(considering Operand is RAX)
    auto TmpReg1 = X64Reg::template getRegRef<Ty>(X64::RCX);

    _.Assembler().mov(TmpReg1, Operand);
    _.Assembler().shr(TmpReg1, 1);

    if constexpr (Is32Bits) {
      _.Assembler().and_(TmpReg1, Mask1);
      _.Assembler().sub(Operand, TmpReg1);
      _.Assembler().mov(TmpReg1, Operand);
      _.Assembler().and_(TmpReg1, Mask2);
      _.Assembler().shr(Operand, SHRImm1);
      _.Assembler().and_(Operand, Mask2);
      _.Assembler().add(TmpReg1, Operand);
      _.Assembler().mov(Operand, TmpReg1);
      _.Assembler().shr(Operand, SHRImm2);
      _.Assembler().add(TmpReg1, Operand);
      _.Assembler().and_(TmpReg1, Mask3);
      _.Assembler().imul(TmpReg1, IMULImm);
    } else {
      // Move 64-bits Imm to registers since x86_64 didn't support 64-bits
      // Immediate for AND/IMUL instruction
      auto TmpReg2 = X64Reg::template getRegRef<Ty>(X64::RDX);
      _.Assembler().movabs(TmpReg2, Mask1);
      _.Assembler().and_(TmpReg1, TmpReg2);
      _.Assembler().sub(Operand, TmpReg1);
      _.Assembler().movabs(TmpReg2, Mask2);
      _.Assembler().mov(TmpReg1, Operand);
      _.Assembler().and_(TmpReg1, TmpReg2);
      _.Assembler().shr(Operand, SHRImm1);
      _.Assembler().and_(Operand, TmpReg2);
      _.Assembler().add(TmpReg1, Operand);
      _.Assembler().mov(Operand, TmpReg1);
      _.Assembler().shr(Operand, SHRImm2);
      _.Assembler().add(TmpReg1, Operand);
      _.Assembler().movabs(TmpReg2, Mask3);
      _.Assembler().and_(TmpReg1, TmpReg2);
      _.Assembler().movabs(TmpReg2, IMULImm);
      _.Assembler().imul(TmpReg1, TmpReg2);
    }

    _.Assembler().shr(TmpReg1, SHRImm3);
    _.Assembler().mov(Operand, TmpReg1);
  }
};

// ============================================================================
// Load Operator
// ============================================================================

// instruction mapping table for load operator
//-------------+------+------+-------+---------+---------+
//             |rtype |mtype |s/zext |r-r      |r-m      |
//-------------+------+------+-------+---------+---------+
//             |I32   |I8    |true   |movsx    |movsx    |
//-------------+------+------+-------+---------+---------+

#define DECL_ALL_LOADOP()                                                      \
  DECL_LOADOP_IMPL(I32, I8, true, movsx, movsx)                                \
  DECL_LOADOP_IMPL(I32, I8, false, movzx, movzx)                               \
  DECL_LOADOP_IMPL(I32, I16, true, movsx, movsx)                               \
  DECL_LOADOP_IMPL(I32, I16, false, movzx, movzx)                              \
  DECL_LOADOP_IMPL(I32, I32, true, mov, mov)                                   \
  DECL_LOADOP_IMPL(I32, I32, false, mov, mov)                                  \
  DECL_LOADOP_IMPL(I64, I8, true, movsx, movsx)                                \
  DECL_LOADOP_IMPL(I64, I8, false, movzx, movzx)                               \
  DECL_LOADOP_IMPL(I64, I16, true, movsx, movsx)                               \
  DECL_LOADOP_IMPL(I64, I16, false, movzx, movzx)                              \
  DECL_LOADOP_IMPL(I64, I32, true, movsxd, movsxd)                             \
  DECL_LOADOP_IMPL(I64, I64, true, mov, mov)                                   \
  DECL_LOADOP_IMPL(I64, I64, false, mov, mov)                                  \
  DECL_LOADOP_IMPL(F32, F32, true, movss, movss)                               \
  DECL_LOADOP_IMPL(F32, F32, false, movss, movss)                              \
  DECL_LOADOP_IMPL(F64, F64, true, movsd, movsd)                               \
  DECL_LOADOP_IMPL(F64, F64, false, movsd, movsd)                              \
  DECL_LOADOP_IMPL(V128, V128, false, movdqa, movdqa)

// ============================================================================
// LoadOperatorImpl
//
// implementation for load operator from mtype to rtype with s/z ext
//
// ============================================================================
template <X64::Type DestType, X64::Type SrcType, bool Sext>
class LoadOperatorImpl : public TypedOperatorBase<DestType> {
public:
  typedef X64RegType<DestType> Reg; // asmjit register reference operand
  typedef asmjit::x86::Mem Mem;     // asmjit memory operand
  static void emit(X64Assembler &_, const Reg &Reg, const Mem &Memory) {
    ZEN_ABORT();
  };
  static void emit(X64Assembler &_, X64::RegNum Res, const Mem &Mem) {
    ZEN_ABORT();
  };
};

// make a macro to simplify the class specialization
#define DECL_LOADOP_IIMPL(DestType, SrcType, Sext, RROpr, RMOpr)               \
  template <>                                                                  \
  class LoadOperatorImpl<X64::DestType, X64::SrcType, Sext>                    \
      : public TypedOperatorBase<X64::DestType> {                              \
  public:                                                                      \
    static void emit(X64Assembler &_, X64::RegNum Res, const Mem &Memory) {    \
      _.Assembler().RMOpr(X64Reg::getRegRef<X64::DestType>(Res), Memory);      \
    }                                                                          \
    static void emit(X64Assembler &_, const Reg &Reg, const Mem &Memory) {     \
      _.Assembler().RMOpr(Reg, Memory);                                        \
    }                                                                          \
  };

template <>
class LoadOperatorImpl<X64::I64, X64::I32, false>
    : public TypedOperatorBase<X64::I64> {
public:
  static void emit(X64Assembler &_, X64::RegNum Res, const Mem &Memory) {
    _.Assembler().mov(X64Reg::getRegRef<X64::I64>(Res).r32(), Memory);
  }
  static void emit(X64Assembler &_, const Reg &Dest, const Mem &Src) {
    _.Assembler().mov(Dest.r32(), Src);
  }
};

// expand all load operator with sxt/zxt
#define DECL_LOADOP_IMPL(R, M, S, RR, RM) DECL_LOADOP_IIMPL(R, M, S, RR, RM)
DECL_ALL_LOADOP()
#undef DECL_LOADOP_IMPL

template <X64::Type DestType, X64::Type SrcType, bool Sext>
class ExtendOperatorImpl {};

#define DECL_EXTEND_IMPL(DestType, SrcType, Sext, RRop, RMop)                  \
  template <>                                                                  \
  class ExtendOperatorImpl<X64::DestType, X64::SrcType, Sext>                  \
      : public TypedOperatorBase<X64::DestType> {                              \
  public:                                                                      \
    static void emit(X64Assembler &_, const Reg &Dest,                         \
                     const X64RegType<X64::SrcType> &Src) {                    \
      _.Assembler().RRop(Dest, Src);                                           \
    }                                                                          \
    static void emit(X64Assembler &_, const Reg &Dest, const Mem &Src) {       \
      _.Assembler().RRop(Dest, Src);                                           \
    }                                                                          \
  };

template <>
class ExtendOperatorImpl<X64::I64, X64::I32, false>
    : public TypedOperatorBase<X64::I64> {
public:
  static void emit(X64Assembler &_, const Reg &Dest,
                   const X64RegType<X64::I32> &Src) {
    _.Assembler().mov(Dest.r32(), Src);
  }
  static void emit(X64Assembler &_, const Reg &Dest, const Mem &Src) {
    _.Assembler().mov(Dest.r32(), Src);
  }
};

#define DECL_LOADOP_IMPL(R, M, S, RR, RM) DECL_EXTEND_IMPL(R, M, S, RR, RM)
DECL_ALL_LOADOP()
#undef DECL_LOADOP_IMPL

template <X64::Type DestType, X64::Type SrcType, bool Sext> class ConvertOpImpl;

template <X64::Type DestType, bool Sext>
class ConvertOpImpl<DestType, X64::F32, Sext> {
  ZEN_STATIC_ASSERT(DestType == X64::I32 || DestType == X64::I64);

public:
  static void emit(X64Assembler &_, X64RegType<DestType> Dest,
                   X64RegType<X64::F64> Src) {
    _.Assembler().cvttss2si(Dest, Src);
  }
};

template <X64::Type DestType, bool Sext>
class ConvertOpImpl<DestType, X64::F64, Sext> {
  ZEN_STATIC_ASSERT(DestType == X64::I32 || DestType == X64::I64);

public:
  static void emit(X64Assembler &_, X64RegType<DestType> Dest,
                   X64RegType<X64::F64> Src) {
    _.Assembler().cvttsd2si(Dest, Src);
  }
};

template <X64::Type SrcType, bool Sext>
class ConvertOpImpl<X64::F32, SrcType, Sext> {
  ZEN_STATIC_ASSERT(SrcType == X64::I32 || SrcType == X64::I64);

public:
  static void emit(X64Assembler &_, X64RegType<X64::F32> Dest,
                   X64RegType<SrcType> Src) {
    _.Assembler().cvtsi2ss(Dest, Src);
  }
};

template <> class ConvertOpImpl<X64::F32, X64::I32, false> {
public:
  static void emit(X64Assembler &_, X64RegType<X64::F32> Dest,
                   X64RegType<X64::I32> Src) {
    _.Assembler().cvtsi2ss(Dest, Src.r64());
  }
};

template <X64::Type SrcType, bool Sext>
class ConvertOpImpl<X64::F64, SrcType, Sext> {
  ZEN_STATIC_ASSERT(SrcType == X64::I32 || SrcType == X64::I64);

public:
  static void emit(X64Assembler &_, X64RegType<X64::F64> Dest,
                   X64RegType<SrcType> Src) {
    _.Assembler().cvtsi2sd(Dest, Src);
  }
};

template <> class ConvertOpImpl<X64::F64, X64::I32, false> {
public:
  static void emit(X64Assembler &_, X64RegType<X64::F64> Dest,
                   X64RegType<X64::I32> Src) {
    _.Assembler().cvtsi2sd(Dest, Src.r64());
  }
};

template <> class ConvertOpImpl<X64::F32, X64::F64, false> {
public:
  static void emit(X64Assembler &_, X64RegType<X64::F32> Dest,
                   X64RegType<X64::F64> Src) {
    _.Assembler().cvtsd2ss(Dest, Src);
  }
};

template <> class ConvertOpImpl<X64::F64, X64::F32, false> {
public:
  static void emit(X64Assembler &_, X64RegType<X64::F64> Dest,
                   X64RegType<X64::F32> Src) {
    _.Assembler().cvtss2sd(Dest, Src);
  }
};

} // namespace zen::singlepass

#endif // ZEN_SINGLEPASS_X64_ASSEMBLER_H
