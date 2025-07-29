// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_SINGLEPASS_A64_ASSEMBLER_H
#define ZEN_SINGLEPASS_A64_ASSEMBLER_H

// ============================================================================
// a64/assembler.h
//
// wrap asmjit assembler for onepass a64 jit compiler
//
// ============================================================================

#include "singlepass/a64/asm/assembler.h"
#include "singlepass/a64/asm/register.h"
#include "singlepass/a64/operand.h"
#include "singlepass/a64/operator.h"
#include "singlepass/common/definitions.h"

namespace zen::singlepass {

// ============================================================================
// TypedOperatorBase
//
// dummy implementation for null operator
//
// ============================================================================
template <A64::Type Ty> class TypedOperatorBase {
public:
  typedef asmjit::a64::Mem Mem; // asmjit memory operand
  typedef int32_t Imm;          // immediate operand
  typedef A64InstOperand Opnd;  // general operands
  typedef A64RegType<Ty> Reg;   // asmjit register reference operand
};                              // TypedOperatorBase

// ============================================================================
// BinaryOperatorBase<A64::WASMType type, BinaryOperator opr>
//
// class prototype declaration for binary operator base
// this class must be specialized for given operator
//
// ============================================================================
template <A64::Type Ty, BinaryOperator Opr>
class BinaryOperatorBase : public TypedOperatorBase<Ty> {
public:
  typedef A64RegType<Ty> Reg; // asmjit register reference operand
  // emit { reg, reg, reg } -opr- { reg, reg, imm }
  template <typename RHSType>
  static void emit(A64Assembler &_, const Reg &Res, const Reg &LHS,
                   RHSType RHS) {
    // can't call. this class must be specialized.
    // keep temporarily to avoid compile error. should be removed later
    ZEN_ABORT();
  }
};

// make a macro to simplify the class specialization
#define DECL_BINOP_IMPL(opr, asmop)                                            \
  template <A64::Type type>                                                    \
  class BinaryOperatorBase<type, BinaryOperator::opr>                          \
      : public TypedOperatorBase<type> {                                       \
  public:                                                                      \
    typedef A64RegType<type> Reg;                                              \
    template <typename RHSType>                                                \
    static void emit(A64Assembler &_, const Reg &Result, const Reg &LHS,       \
                     RHSType RHS) {                                            \
      _.asmop<type>(Result, LHS, RHS);                                         \
    }                                                                          \
  }

// specialization more binary operators
// in alphabetical order
DECL_BINOP_IMPL(BO_ADD, add);
DECL_BINOP_IMPL(BO_AND, and_);
DECL_BINOP_IMPL(BO_DIV, div);
DECL_BINOP_IMPL(BO_DIV_S, div_s);
DECL_BINOP_IMPL(BO_DIV_U, div_u);
DECL_BINOP_IMPL(BO_MAX, max);
DECL_BINOP_IMPL(BO_MIN, min);
DECL_BINOP_IMPL(BO_MUL, mul);
DECL_BINOP_IMPL(BO_OR, or_);
DECL_BINOP_IMPL(BO_ROTR, ror);
DECL_BINOP_IMPL(BO_SHL, shl);
DECL_BINOP_IMPL(BO_SHR_S, shr_s);
DECL_BINOP_IMPL(BO_SHR_U, shr_u);
DECL_BINOP_IMPL(BO_SUB, sub);
DECL_BINOP_IMPL(BO_XOR, xor_);

#undef DECL_BINOP_IMPL

// ============================================================================
// BinaryOperatorImpl<A64::WASMType type, BinaryOperator opr>
//
// real binary operator implementation used by A64OnePassCodeGenImpl
//
// ============================================================================
template <A64::Type Ty, BinaryOperator Opr>
class BinaryOperatorImpl : public BinaryOperatorBase<Ty, Opr> {
public:
  typedef A64RegType<Ty> Reg;   // asmjit register reference operand
  typedef asmjit::a64::Mem Mem; // asmjit memory operand
  typedef int32_t Imm;          // immediate operand
  typedef A64InstOperand Opnd;  // general operand

public:
  // also allow using Emit directly
  using BinaryOperatorBase<Ty, Opr>::emit;

public:
  // emit reg = reg -opr- opnd
  static void emit(A64Assembler &_, const Reg &Res, const Reg &LHS,
                   const Opnd RHS) {
    if (RHS.isReg()) {
      BinaryOperatorBase<Ty, Opr>::emit(_, Res, LHS, RHS.getRegRef<Ty>());
    } else if (RHS.isImm()) {
      BinaryOperatorBase<Ty, Opr>::emit(_, Res, LHS, RHS.getImm());
    } else {
      ZEN_ABORT();
    }
  }

  // emit reg = opnd -opr- opnd
  static void emit(A64Assembler &_, const Reg &Res, const Opnd LHS,
                   const Opnd RHS) {
    if (LHS.isReg()) {
      emit(_, Res, LHS.getRegRef<Ty>(), RHS);
    } else {
      ZEN_ABORT();
    }
  }

  // emit opnd = opnd -opr- opnd
  static void emit(A64Assembler &_, const Opnd Res, const Opnd LHS,
                   const Opnd RHS) {
    if (Res.isReg()) {
      emit(_, Res.getRegRef<Ty>(), LHS, RHS);
    } else {
      ZEN_ABORT();
    }
  }
}; // BinaryOperatorImpl

// ============================================================================
// UnaryOperatorImpl<A64::WASMType type, UnaryOperator opr>
//
// real unary operator implementation used by A64OnePassCodeGenImpl
//
// ============================================================================

template <A64::Type Ty, UnaryOperator Opr> class UnaryOperatorImpl {
public:
  template <typename OpndType>
  static void emit(A64Assembler &_, OpndType Res, OpndType Opnd) {
    // can't call. this class must be specialized.
    // keep temporarily to avoid compile error. should be removed later
    ZEN_ABORT();
  }
};

// make a macro to simplify the class specialization
#define DECL_UNAOP_IMPL(Opr, Asmop)                                            \
  template <A64::Type Ty> class UnaryOperatorImpl<Ty, UnaryOperator::Opr> {    \
  public:                                                                      \
    template <typename OpndType>                                               \
    static void emit(A64Assembler &_, OpndType Res, OpndType Op) {             \
      _.Asmop<Ty>(Res, Op);                                                    \
    }                                                                          \
  }

// TODO: specialization more compare operators
// in alphabetical order
// DECL_UNAOP_IMPL(UO_NEG, neg);
// DECL_UNAOP_IMPL(UO_NOT, not_);
DECL_UNAOP_IMPL(UO_CLZ, clz);
DECL_UNAOP_IMPL(UO_ABS, abs);
DECL_UNAOP_IMPL(UO_NEG, neg);
DECL_UNAOP_IMPL(UO_CEIL, rintp);
DECL_UNAOP_IMPL(UO_FLOOR, rintm);
DECL_UNAOP_IMPL(UO_TRUNC, rintz);
DECL_UNAOP_IMPL(UO_NEAREST, rintn);
DECL_UNAOP_IMPL(UO_SQRT, sqrt);

template <A64::Type Ty> class UnaryOperatorImpl<Ty, UnaryOperator::UO_CTZ> {
public:
  static void emit(A64Assembler &_, A64RegType<Ty> Res, A64RegType<Ty> Opnd) {
    _.rbit<Ty>(Res, Opnd);
    _.clz<Ty>(Res, Res);
  }
};

/*

template<A64::WASMType type>
class UnaryOperatorImpl<type, UO_POPCNT>{
public:
  static void emit(A64Assembler& _, A64RegType<type> opnd) {
    _.popcnt<type>(opnd, opnd);
  }
};
*/

// ============================================================================
// Load Operator
// ============================================================================

// instruction mapping table for load operator
//-------------+------+------+------+-------+---------+
//             |rtype |reg   |mtype |s/zext |r-m      |
//-------------+------+------+------+-------+---------+
//             |I32   |I32   |I8    |true   |ldrsb    |
//-------------+------+------+------+-------+---------+

#define DECL_ALL_LOADOP()                                                      \
  DECL_LOADOP_IMPL(I8, I8, I8, true, ldrsb)                                    \
  DECL_LOADOP_IMPL(I8, I8, I8, false, ldrb)                                    \
  DECL_LOADOP_IMPL(I16, I16, I16, true, ldrsh)                                 \
  DECL_LOADOP_IMPL(I16, I16, I16, false, ldrh)                                 \
  DECL_LOADOP_IMPL(I32, I32, I8, true, ldrsb)                                  \
  DECL_LOADOP_IMPL(I32, I32, I8, false, ldrb)                                  \
  DECL_LOADOP_IMPL(I32, I32, I16, true, ldrsh)                                 \
  DECL_LOADOP_IMPL(I32, I32, I16, false, ldrh)                                 \
  DECL_LOADOP_IMPL(I32, I32, I32, false, ldr)                                  \
  DECL_LOADOP_IMPL(I64, I64, I8, true, ldrsb)                                  \
  DECL_LOADOP_IMPL(I64, I32, I8, false, ldrb)                                  \
  DECL_LOADOP_IMPL(I64, I64, I16, true, ldrsh)                                 \
  DECL_LOADOP_IMPL(I64, I32, I16, false, ldrh)                                 \
  DECL_LOADOP_IMPL(I64, I64, I32, true, ldrsw)                                 \
  DECL_LOADOP_IMPL(I64, I32, I32, false, ldr)                                  \
  DECL_LOADOP_IMPL(I64, I64, I64, false, ldr)                                  \
  DECL_LOADOP_IMPL(F32, F32, F32, false, ldr)                                  \
  DECL_LOADOP_IMPL(F64, F64, F64, false, ldr)                                  \
  DECL_LOADOP_IMPL(V128, V128, V128, false, ldr)

// ============================================================================
// LoadOperatorImpl
//
// implementation for load operator from SrcType to DestType with s/z ext
//
// ============================================================================
template <A64::Type DestType, A64::Type SrcType, bool Sext>
class LoadOperatorImpl : public TypedOperatorBase<DestType> {
public:
  typedef A64InstOperand Opnd;  // general operand
  typedef asmjit::a64::Mem Mem; // asmjit memory operand
  static void emit(A64Assembler &_, A64::RegNum Res, const Mem &Memory);
  static void emit(A64Assembler &_, const Opnd Res, const Mem &Memory);
};

// make a macro to simplify the class specialization
#define DECL_LOADOP_IMPL(DestType, Reg, SrcType, Sext, RMOp)                   \
  template <>                                                                  \
  class LoadOperatorImpl<A64::DestType, A64::SrcType, Sext>                    \
      : public TypedOperatorBase<A64::DestType> {                              \
  public:                                                                      \
    typedef A64InstOperand Opnd;                                               \
    static void emit(A64Assembler &_, A64::RegNum Res, const Mem &Memory) {    \
      _.Assembler().RMOp(A64Reg::getRegRef<A64::Reg>(Res), Memory);            \
    }                                                                          \
    static void emit(A64Assembler &_, const Opnd Res, const Mem &Memory) {     \
      ZEN_ASSERT(Res.isReg());                                                 \
      _.Assembler().RMOp(Res.getRegRef<A64::Reg>(), Memory);                   \
    }                                                                          \
  };

// expand all load operator with sxt/zxt
DECL_ALL_LOADOP()
#undef DECL_LOADOP_IMPL

// ============================================================================
// Store Operator
// ============================================================================

// instruction mapping table for store operator
// -------------+------+------+------+
//              |reg   |mtype |m-r   |
// -------------+------+------+------+
//              |I32   |I8    |strb  |
// -------------+------+------+------+

#define DECL_ALL_STOREOP()                                                     \
  DECL_STOREOP_IMPL(I32, I8, strb)                                             \
  DECL_STOREOP_IMPL(I32, I16, strh)                                            \
  DECL_STOREOP_IMPL(I32, I32, str)                                             \
  DECL_STOREOP_IMPL(I64, I64, str)                                             \
  DECL_STOREOP_IMPL(F32, F32, str)                                             \
  DECL_STOREOP_IMPL(F64, F64, str)                                             \
  DECL_STOREOP_IMPL(V128, V128, str)

// ============================================================================
// StoreOperatorImpl
//
// implementation for store operator with mtype
//
// ===========================================================================
template <A64::Type Type> class StoreOperatorImpl {
public:
  typedef A64InstOperand Opnd;  // general operand
  typedef asmjit::a64::Mem Mem; // asmjit memory operand
  static void emit(A64Assembler &_, A64::RegNum Res, const Mem &Memory);
  static void emit(A64Assembler &_, const Opnd Res, const Mem &Memory);
};

// make a macro to simplify the class specialization
#define DECL_STOREOP_IMPL(Reg, Type, Rmop)                                     \
  template <> class StoreOperatorImpl<A64::Type> {                             \
  public:                                                                      \
    typedef A64InstOperand Opnd;                                               \
    typedef asmjit::a64::Mem Mem;                                              \
    static void emit(A64Assembler &_, A64::RegNum Res, const Mem &Memory) {    \
      _.Assembler().Rmop(A64Reg::getRegRef<A64::Reg>(Res), Memory);            \
    }                                                                          \
    static void emit(A64Assembler &_, const Opnd Res, const Mem &Memory) {     \
      ZEN_ASSERT(Res.isReg());                                                 \
      _.Assembler().Rmop(Res.getRegRef<A64::Reg>(), Memory);                   \
    }                                                                          \
  };

// expand all store operator
DECL_ALL_STOREOP()
#undef DECL_STOREOP_IMPL

// ============================================================================
// ConstOperatorImpl
//
// implementation for constant operation
//
// ============================================================================
template <A64::Type type> class ConstOperatorImpl {
public:
  typedef typename A64TypeAttr<type>::ValType ValType;
  typedef A64RegType<type> Reg;
  static void emit(A64Assembler &_, const Reg &Res, const ValType Val) {}
  static void emit(A64Assembler &_, A64::RegNum Res, const ValType Val) {}
};

template <> class ConstOperatorImpl<A64::I32> {
public:
  typedef A64RegType<A64::I32> Reg;
  static void emit(A64Assembler &_, const Reg &Result, int32_t Val) {
    _.Assembler().mov(Result, Val & 0xFFFF);
    Val >>= 16;
    if (Val) {
      _.Assembler().movk(Result, Val & 0xFFFF, 16);
    }
  }
  static void emit(A64Assembler &_, A64::RegNum Res, int32_t Val) {
    emit(_, A64Reg::getRegRef<A64::I32>(Res), Val);
  }
};

template <> class ConstOperatorImpl<A64::I64> {
public:
  typedef A64RegType<A64::I64> Reg;
  static void emit(A64Assembler &_, const Reg &Res, int64_t Val) {
    _.Assembler().mov(Res, Val & 0xFFFF);
    Val >>= 16;
    if (Val) {
      _.Assembler().movk(Res, Val & 0xFFFF, 16);
    }

    Val >>= 16;
    if (Val) {
      _.Assembler().movk(Res, Val & 0xFFFF, 32);
    }

    Val >>= 16;
    if (Val) {
      _.Assembler().movk(Res, Val & 0xFFFF, 48);
    }
  }
  static void emit(A64Assembler &_, A64::RegNum Res, int64_t Val) {
    emit(_, A64Reg::getRegRef<A64::I64>(Res), Val);
  }
};

template <A64::Type DestType, A64::Type SrcType, bool Sext>
struct ConvertOpImpl;

#define DECL_CVTOP_IMPL(DestType, SrcType, Sext, Op)                           \
  template <> struct ConvertOpImpl<A64::DestType, A64::SrcType, Sext> {        \
    static void emit(A64Assembler &_, A64RegType<A64::DestType> Dest,          \
                     A64RegType<A64::SrcType> Src) {                           \
      _.Assembler().Op(Dest, Src);                                             \
    }                                                                          \
  }

// int to int conversions
DECL_CVTOP_IMPL(I32, I8, true, sxtb);
DECL_CVTOP_IMPL(I32, I16, true, sxth);
DECL_CVTOP_IMPL(I64, I8, true, sxtb);
DECL_CVTOP_IMPL(I64, I16, true, sxth);
DECL_CVTOP_IMPL(I64, I32, true, sxtw);

// int to float conversions
DECL_CVTOP_IMPL(F32, I32, true, scvtf);
DECL_CVTOP_IMPL(F32, I64, true, scvtf);
DECL_CVTOP_IMPL(F64, I32, true, scvtf);
DECL_CVTOP_IMPL(F64, I64, true, scvtf);
DECL_CVTOP_IMPL(F32, I32, false, ucvtf);
DECL_CVTOP_IMPL(F32, I64, false, ucvtf);
DECL_CVTOP_IMPL(F64, I32, false, ucvtf);
DECL_CVTOP_IMPL(F64, I64, false, ucvtf);

// float to float conversions
DECL_CVTOP_IMPL(F64, F32, false, fcvt);
DECL_CVTOP_IMPL(F32, F64, false, fcvt);

// float to int conversions
DECL_CVTOP_IMPL(I32, F32, true, fcvtzs);
DECL_CVTOP_IMPL(I32, F64, true, fcvtzs);
DECL_CVTOP_IMPL(I64, F32, true, fcvtzs);
DECL_CVTOP_IMPL(I64, F64, true, fcvtzs);
DECL_CVTOP_IMPL(I32, F32, false, fcvtzu);
DECL_CVTOP_IMPL(I32, F64, false, fcvtzu);
DECL_CVTOP_IMPL(I64, F32, false, fcvtzu);
DECL_CVTOP_IMPL(I64, F64, false, fcvtzu);

#undef DECL_CVTOP_IMPL

template <> struct ConvertOpImpl<A64::I64, A64::I32, false> {
  static void emit(A64Assembler &_, A64RegType<A64::I64> Dest,
                   A64RegType<A64::I32> Src) {
    _.Assembler().mov(Dest.w(), Src);
  }
};

} // namespace zen::singlepass

#endif // ZEN_SINGLEPASS_A64_ASSEMBLER_H
