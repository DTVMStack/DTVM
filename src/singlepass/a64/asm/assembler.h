// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_SINGLEPASS_A64_ASM_ASSEMBLER_H
#define ZEN_SINGLEPASS_A64_ASM_ASSEMBLER_H

// ============================================================================
// a64/assembler.h
//
// utilities to provide same interface for same operation on different types
//
// ============================================================================

#include "singlepass/a64/asm/datatype.h"
#include "singlepass/common/definitions.h"
#include <asmjit/a64.h>

namespace zen::singlepass {

namespace A64 {

// for conditional code
enum CondCode {
  AL = (uint8_t)asmjit::a64::CondCode::kAL,
  NA = (uint8_t)asmjit::a64::CondCode::kNA,
  EQ = (uint8_t)asmjit::a64::CondCode::kEQ, // EQual
  NE = (uint8_t)asmjit::a64::CondCode::kNE, // Not Equal
  AE = (uint8_t)asmjit::a64::CondCode::kHS, // Above or Equal
  B = (uint8_t)asmjit::a64::CondCode::kLO,  // Below
  LTZ = (uint8_t)asmjit::a64::CondCode::kMI,
  GEZ = (uint8_t)asmjit::a64::CondCode::kPL,
  VS = (uint8_t)asmjit::a64::CondCode::kVS,
  VC = (uint8_t)asmjit::a64::CondCode::kVC,
  A = (uint8_t)asmjit::a64::CondCode::kHI,  // Above
  BE = (uint8_t)asmjit::a64::CondCode::kLS, // Below or Equal
  GE = (uint8_t)asmjit::a64::CondCode::kGE, // Greater or Equal
  LT = (uint8_t)asmjit::a64::CondCode::kLT, // Less Than
  GT = (uint8_t)asmjit::a64::CondCode::kGT, // Greater Than
  LE = (uint8_t)asmjit::a64::CondCode::kLE, // Less or Equal
};                                          // enum CondCode

} // namespace A64

// for unimplemented binop instructions
template <typename LHSType, typename RHSType>
static inline void rrr_op_todo(LHSType Res, LHSType LHS, RHSType RHS) {
  ZEN_ASSERT_TODO();
}

// for unimplemented binop instructions
template <typename LHSType>
static inline void rri_op_todo(LHSType Res, LHSType LHS, int32_t Imm) {
  ZEN_ASSERT_TODO();
}

// for illegal binop instructions
template <typename LHSType, typename RHSType>
static inline void rrr_op_abort(LHSType Res, LHSType LHS, RHSType RHS) {
  ZEN_ABORT();
}

// for illegal binop instructions
template <typename LHSType>
static inline void rri_op_abort(LHSType Res, LHSType LHS, int32_t Imm) {
  ZEN_ABORT();
}

// for unimplemented unaop instructions
template <typename OpndType>
static inline void rr_op_todo(OpndType Res, OpndType opnd) {
  ZEN_ASSERT_TODO();
}

// for illegal unaop instructions
template <typename OpndType>
static inline void rr_op_abort(OpndType Res, OpndType opnd) {
  ZEN_ABORT();
}

// for unimplemented unaop instructions
template <typename OpndType>
static inline void ri_op_todo(OpndType Res, int32_t Imm) {
  ZEN_ASSERT_TODO();
}

// for illegal unaop instructions
template <typename OpndType>
static inline void ri_op_abort(OpndType Res, int32_t Imm) {
  ZEN_ABORT();
}

// ============================================================================
// instruction mapping table for binary operator
//
// map different type and operand mode to instructions
//
// ============================================================================

//-------------+-----+-----+---------+
//              oper |type |r-r      |
//-------------+-----+-----+---------+
//             |add  |__   |add      |
//-------------+-----+-----+---------+

/* clang-format off */
#define DECL_ALL_RRR_OP() \
DECL_RRR_OP_TMPL(add,   __,  Asm.add  ) \
DECL_RRR_OP_SPEC(add,   F32, Asm.fadd ) \
DECL_RRR_OP_SPEC(add,   F64, Asm.fadd ) \
DECL_RRR_OP_TMPL(and_,  __,  Asm.and_ ) \
DECL_RRR_OP_SPEC(and_,  F32,  NA      ) \
DECL_RRR_OP_SPEC(and_,  F64,  NA      ) \
DECL_RRR_OP_TMPL(div,   __,  Asm.sdiv ) \
DECL_RRR_OP_SPEC(div,   F32, Asm.fdiv ) \
DECL_RRR_OP_SPEC(div,   F64, Asm.fdiv ) \
DECL_RRR_OP_TMPL(div_s, __,  Asm.sdiv ) \
DECL_RRR_OP_SPEC(div_s, F32,  NA      ) \
DECL_RRR_OP_SPEC(div_s, F64,  NA      ) \
DECL_RRR_OP_TMPL(div_u, __,  Asm.udiv ) \
DECL_RRR_OP_SPEC(div_u, F32,  NA      ) \
DECL_RRR_OP_SPEC(div_u, F64,  NA      ) \
DECL_RRR_OP_TMPL(min,   __,   NA      ) \
DECL_RRR_OP_SPEC(min,   F32, Asm.fmin ) \
DECL_RRR_OP_SPEC(min,   F64, Asm.fmin ) \
DECL_RRR_OP_TMPL(max,   __,   NA      ) \
DECL_RRR_OP_SPEC(max,   F32, Asm.fmax ) \
DECL_RRR_OP_SPEC(max,   F64, Asm.fmax ) \
DECL_RRR_OP_TMPL(mul,   __,  Asm.mul  ) \
DECL_RRR_OP_SPEC(mul,   F32, Asm.fmul ) \
DECL_RRR_OP_SPEC(mul,   F64, Asm.fmul ) \
DECL_RRR_OP_TMPL(or_,   __,  Asm.orr  ) \
DECL_RRR_OP_SPEC(or_,   F32,  NA      ) \
DECL_RRR_OP_SPEC(or_,   F64,  NA      ) \
DECL_RRR_OP_TMPL(ror,   __,  Asm.ror  ) \
DECL_RRR_OP_SPEC(ror,   F32,  NA      ) \
DECL_RRR_OP_SPEC(ror,   F64,  NA      ) \
DECL_RRR_OP_TMPL(shl,   __,  Asm.lsl  ) \
DECL_RRR_OP_SPEC(shl,   F32,  NA      ) \
DECL_RRR_OP_SPEC(shl,   F64,  NA      ) \
DECL_RRR_OP_TMPL(shr_s, __,  Asm.asr  ) \
DECL_RRR_OP_SPEC(shr_s, F32,  NA      ) \
DECL_RRR_OP_SPEC(shr_s, F64,  NA      ) \
DECL_RRR_OP_TMPL(shr_u, __,  Asm.lsr  ) \
DECL_RRR_OP_SPEC(shr_u, F32,  NA      ) \
DECL_RRR_OP_SPEC(shr_u, F64,  NA      ) \
DECL_RRR_OP_TMPL(sub,   __,  Asm.sub  ) \
DECL_RRR_OP_SPEC(sub,   F32, Asm.fsub ) \
DECL_RRR_OP_SPEC(sub,   F64, Asm.fsub ) \
DECL_RRR_OP_TMPL(xor_,  __,  Asm.eor  ) \
DECL_RRR_OP_SPEC(xor_,  F32,  NA      ) \
DECL_RRR_OP_SPEC(xor_,  F64,  NA      ) \


//-------------+-----+-----+---------+
//              oper |type |r-r      |
//-------------+-----+-----+---------+
//             |add  |__   |add      |
//-------------+-----+-----+---------+

/* clang-format off */
#define DECL_ALL_RRI_OP() \
DECL_RRI_OP_TMPL(add,   __,  Asm.add  ) \
DECL_RRI_OP_SPEC(add,   F32,  NA      ) \
DECL_RRI_OP_SPEC(add,   F64,  NA      ) \
DECL_RRI_OP_TMPL(and_,  __,  Asm.and_ ) \
DECL_RRI_OP_SPEC(and_,  F32,  NA      ) \
DECL_RRI_OP_SPEC(and_,  F64,  NA      ) \
DECL_RRI_OP_TMPL(div,   __,  Asm.sdiv ) \
DECL_RRI_OP_SPEC(div,   F32,  NA      ) \
DECL_RRI_OP_SPEC(div,   F64,  NA      ) \
DECL_RRI_OP_TMPL(div_s, __,  Asm.sdiv ) \
DECL_RRI_OP_SPEC(div_s, F32,  NA      ) \
DECL_RRI_OP_SPEC(div_s, F64,  NA      ) \
DECL_RRI_OP_TMPL(div_u, __,  Asm.udiv ) \
DECL_RRI_OP_SPEC(div_u, F32,  NA      ) \
DECL_RRI_OP_SPEC(div_u, F64,  NA      ) \
DECL_RRI_OP_TMPL(min,   __,   NA      ) \
DECL_RRI_OP_SPEC(min,   F32,  NA      ) \
DECL_RRI_OP_SPEC(min,   F64,  NA      ) \
DECL_RRI_OP_TMPL(max,   __,   NA      ) \
DECL_RRI_OP_SPEC(max,   F32,  NA      ) \
DECL_RRI_OP_SPEC(max,   F64,  NA      ) \
DECL_RRI_OP_TMPL(mul,   __,  Asm.mul  ) \
DECL_RRI_OP_SPEC(mul,   F32,  NA      ) \
DECL_RRI_OP_SPEC(mul,   F64,  NA      ) \
DECL_RRI_OP_TMPL(or_,   __,  Asm.orr  ) \
DECL_RRI_OP_SPEC(or_,   F32,  NA      ) \
DECL_RRI_OP_SPEC(or_,   F64,  NA      ) \
DECL_RRI_OP_TMPL(ror,   __,  Asm.ror  ) \
DECL_RRI_OP_SPEC(ror,   F32,  NA      ) \
DECL_RRI_OP_SPEC(ror,   F64,  NA      ) \
DECL_RRI_OP_TMPL(shl,   __,  Asm.shl  ) \
DECL_RRI_OP_SPEC(shl,   F32,  NA      ) \
DECL_RRI_OP_SPEC(shl,   F64,  NA      ) \
DECL_RRI_OP_TMPL(shr_s, __,  Asm.asr  ) \
DECL_RRI_OP_SPEC(shr_s, F32,  NA      ) \
DECL_RRI_OP_SPEC(shr_s, F64,  NA      ) \
DECL_RRI_OP_TMPL(shr_u, __,  Asm.lsr  ) \
DECL_RRI_OP_SPEC(shr_u, F32,  NA      ) \
DECL_RRI_OP_SPEC(shr_u, F64,  NA      ) \
DECL_RRI_OP_TMPL(sub,   __,  Asm.sub  ) \
DECL_RRI_OP_SPEC(sub,   F32,  NA      ) \
DECL_RRI_OP_SPEC(sub,   F64,  NA      ) \
DECL_RRI_OP_TMPL(xor_,  __,  Asm.eor  ) \
DECL_RRI_OP_SPEC(xor_,  F32,  NA      ) \
DECL_RRI_OP_SPEC(xor_,  F64,  NA      ) \

// ============================================================================
// instruction mapping table for unary operator
//
// map different type and operand mode to instructions
//
// ============================================================================

//-------------+-----+-----+---------+
//              oper |type |r        |
//-------------+-----+-----+---------+
//             |neg  |__   |neg      |
//-------------+-----+-----+---------+

/* clang-format off */
#define DECL_ALL_RR_OP() \
DECL_RR_OP_TMPL(abs,  __,  Asm.fabs ) \
DECL_RR_OP_TMPL(clz,  __,  Asm.clz  ) \
DECL_RR_OP_SPEC(clz,  F32,  NA      ) \
DECL_RR_OP_SPEC(clz,  F64,  NA      ) \
DECL_RR_OP_TMPL(cmp,  __,  Asm.cmp  ) \
DECL_RR_OP_SPEC(cmp,  F32, Asm.fcmp ) \
DECL_RR_OP_SPEC(cmp,  F64, Asm.fcmp ) \
DECL_RR_OP_TMPL(mov,  __,  Asm.mov  ) \
DECL_RR_OP_SPEC(mov,  F32, Asm.fmov ) \
DECL_RR_OP_SPEC(mov,  F64, Asm.fmov ) \
DECL_RR_OP_SPEC(mov,  V128,Asm.fmov ) \
DECL_RR_OP_TMPL(neg,  __,  Asm.neg  ) \
DECL_RR_OP_SPEC(neg,  F32, Asm.fneg ) \
DECL_RR_OP_SPEC(neg,  F64, Asm.fneg ) \
DECL_RR_OP_TMPL(rbit, __,  Asm.rbit ) \
DECL_RR_OP_SPEC(rbit, F32,  NA      ) \
DECL_RR_OP_SPEC(rbit, F64,  NA      ) \
DECL_RR_OP_TMPL(rintm, __,Asm.frintm) \
DECL_RR_OP_TMPL(rintn, __,Asm.frintn) \
DECL_RR_OP_TMPL(rintp, __,Asm.frintp) \
DECL_RR_OP_TMPL(rintz, __,Asm.frintz) \
DECL_RR_OP_TMPL(sqrt, __,  Asm.fsqrt) \

/* clang-format off */
#define DECL_ALL_RI_OP() \
DECL_RI_OP_TMPL(cmp,  __,  Asm.cmp  ) \
DECL_RI_OP_SPEC(cmp,  F32,  NA      ) \
DECL_RI_OP_SPEC(cmp,  F64,  NA      ) \
DECL_RI_OP_TMPL(mov,  __,  Asm.mov  ) \
DECL_RI_OP_SPEC(mov,  F32,  NA      ) \
DECL_RI_OP_SPEC(mov,  F64,  NA      ) \
DECL_RI_OP_SPEC(mov,  V128, NA      ) \
DECL_RI_OP_TMPL(neg,  __,  Asm.neg  ) \
DECL_RI_OP_SPEC(neg,  F32,  NA      ) \
DECL_RI_OP_SPEC(neg,  F64,  NA      ) \


// ============================================================================
// A64Assembler
//
// wrap asmjit::a64::Assembler and hide the type differences
//
// ============================================================================
class A64Assembler {
private:
  typedef asmjit::a64::GpW   GpW;
  typedef asmjit::a64::GpX   GpX;
  typedef asmjit::a64::VecB  VecB;
  typedef asmjit::a64::VecH  VecH;
  typedef asmjit::a64::VecS  VecS;
  typedef asmjit::a64::VecS  VecD;
  typedef asmjit::a64::VecV  VecV;
  typedef asmjit::a64::Mem   Mem;
  typedef asmjit::Label      Label;

private:
  asmjit::a64::Assembler Asm;

public:
  A64Assembler(asmjit::CodeHolder *Code) : Asm(Code) {}

  asmjit::a64::Assembler &Assembler() { return Asm; }

public:
  // label related
  uint32_t newLabel() {
    Label L = Asm.newLabel();
    ZEN_ASSERT(L.isValid());
    return L.id();
  }

  void bind(uint32_t Id) {
    Label L(Id);
    ZEN_ASSERT(Asm.isLabelValid(L));
    Asm.bind(L);
  }

public:
  //
  // generate all templated binary operation instructions
  //

  // define macro to generate methods for generic type inside class definition
  #define DECL_ASM_RRR_OP_IMPL(Method, r_r) \
    template<A64::Type Ty> \
    void Method(const typename A64TypeAttr<Ty>::Type &Res, \
                const typename A64TypeAttr<Ty>::Type &LHS, \
                const typename A64TypeAttr<Ty>::Type &RHS) { \
      r_r(Res, LHS, RHS); \
    }

  // define DECL_RRR_OP_TMPL to DECL_ASM_RRR_OP_IMPL to expand functions
  #define DECL_RRR_OP_TMPL(n, t, rr) \
          DECL_ASM_RRR_OP_IMPL(n, rr)
  // define DECL_RRR_OP_SPEC to nothing
  #define DECL_RRR_OP_SPEC(n, t, rr)
  // define TODO to rrr_op_todo
  #define TODO(Res, l, r) rrr_op_todo(Res, l, r)
  // define NA to rrr_op_abort
  #define NA(Res, l, r) rrr_op_abort(Res, l, r)
    DECL_ALL_RRR_OP()
  #undef TODO
  #undef NA
  #undef DECL_RRR_OP_SPEC
  #undef DECL_RRR_OP_TMPL
  #undef DECL_ASM_RRR_OP_IMPL

  // define macro to generate methods for generic type inside class definition
  #define DECL_ASM_RRI_OP_IMPL(Method, r_r_i) \
    template<A64::Type Ty> \
    void Method(const typename A64TypeAttr<Ty>::Type &Res, \
                const typename A64TypeAttr<Ty>::Type &LHS, \
                int32_t Imm) { \
      r_r_i(Res, LHS, Imm); \
    }

  // define DECL_RR_OP_TMPL to DECL_ASM_RR_OP_IMPL to expand functions
  #define DECL_RRI_OP_TMPL(n, t, r) \
          DECL_ASM_RRI_OP_IMPL(n, r)
  // define DECL_RRI_OP_SPEC to nothing
  #define DECL_RRI_OP_SPEC(n, t, r)
  // define TODO to rr_op_todo
  #define TODO(Res, l, r) rri_op_todo(Res, l, r)
  // define NA to rrr_op_abort
  #define NA(Res, l, r) rri_op_abort(Res, l, r)
    DECL_ALL_RRI_OP()
  #undef TODO
  #undef NA
  #undef DECL_RRI_OP_SPEC
  #undef DECL_RRI_OP_TMPL
  #undef DECL_ASM_RRI_OP_IMPL


  //
  // generate all templated unary operation instructions
  //

  // define macro to generate methods for generic type inside class definition
  #define DECL_ASM_RR_OP_IMPL(Method, r) \
    template<A64::Type Ty> \
    void Method(const typename A64TypeAttr<Ty>::Type &Res, \
                const typename A64TypeAttr<Ty>::Type &Opnd) { \
      r(Res, Opnd); \
    }

  // define DECL_RR_OP_TMPL to DECL_ASM_RR_OP_IMPL to expand functions
  #define DECL_RR_OP_TMPL(n, t, r) \
          DECL_ASM_RR_OP_IMPL(n, r)
  // define DECL_RR_OP_SPEC to nothing
  #define DECL_RR_OP_SPEC(n, t, r)
  // define TODO to rr_op_todo
  #define TODO(Opnd) rr_op_todo(Opnd)
  // define NA to rr_op_abort
  #define NA(Opnd) rr_op_abort(Opnd)
    DECL_ALL_RR_OP()
  #undef TODO
  #undef NA
  #undef DECL_RR_OP_SPEC
  #undef DECL_RR_OP_TMPL
  #undef DECL_ASM_RR_OP_IMPL

  //
  // generate all templated unary operation instructions
  //

  // define macro to generate methods for generic type inside class definition
  #define DECL_ASM_RI_OP_IMPL(Method, r) \
    template<A64::Type Ty> \
    void Method(const typename A64TypeAttr<Ty>::Type &Res, \
                int64_t Imm) { \
      r(Res, Imm); \
    }

  // define DECL_RI_OP_TMPL to DECL_ASM_RI_OP_IMPL to expand functions
  #define DECL_RI_OP_TMPL(n, t, r) \
          DECL_ASM_RI_OP_IMPL(n, r)
  // define DECL_RI_OP_SPEC to nothing
  #define DECL_RI_OP_SPEC(n, t, r)
  // define TODO to ri_op_todo
  #define TODO(Opnd) ri_op_todo(Opnd)
  // define NA to ri_op_abort
  #define NA(Opnd) ri_op_abort(Opnd)
    DECL_ALL_RI_OP()
  #undef TODO
  #undef NA
  #undef DECL_RI_OP_SPEC
  #undef DECL_RI_OP_TMPL
  #undef DECL_ASM_RI_OP_IMPL

  template <typename DestType, typename SrcType>
  void fmov(DestType Dest, SrcType Src)
  {
    Asm.fmov(Dest, Src);
  }

}; // A64Assembler

//
// generate all specialized binary operation instructions
//

// define macro to generate methods for specialized types outside class definition
#define DECL_ASM_RRR_OP_SPEC_IMPL(Method, SrcType, r_r) \
  template<> inline void \
  A64Assembler::Method<A64::SrcType>(const typename A64TypeAttr<A64::SrcType>::Type &Res, \
                                   const typename A64TypeAttr<A64::SrcType>::Type &LHS, \
                                   const typename A64TypeAttr<A64::SrcType>::Type &RHS) { \
    r_r(Res, LHS, RHS); \
  }

// define DECL_RRR_OP_TMPL to nothing
#define DECL_RRR_OP_TMPL(n, t, rr) \
// define DECL_RRR_OP_SPEC to DECL_ASM_RRR_OP_SPEC_IMPL
#define DECL_RRR_OP_SPEC(n, t, rr) \
        DECL_ASM_RRR_OP_SPEC_IMPL(n, t, rr)
// define TODO to rrr_op_todo
#define TODO(Res, LHS, RHS) rrr_op_todo(Res, LHS, RHS)
// define NA to rrr_op_abort
#define NA(Res, LHS, RHS) rrr_op_abort(Res, LHS, RHS)
  DECL_ALL_RRR_OP()
#undef NA
#undef TODO
#undef DECL_RRR_OP_SPEC
#undef DECL_RRR_OP_TMPL
#undef DECL_ASM_RRR_OP_SPEC_IMPL

//
// generate all specialized rri operation instructions
//

// define macro to generate methods for specialized types outside class definition
#define DECL_ASM_RRI_OP_SPEC_IMPL(Method, SrcType, r_r) \
  template<> inline void \
  A64Assembler::Method<A64::SrcType>(const typename A64TypeAttr<A64::SrcType>::Type &Res, \
                                   const typename A64TypeAttr<A64::SrcType>::Type &LHS, \
                                   int32_t Imm) { \
    r_r(Res, LHS, Imm); \
  }

// define DECL_RRI_OP_TMPL to nothing
#define DECL_RRI_OP_TMPL(n, t, rr)
// define DECL_RRI_OP_SPEC to DECL_ASM_RRI_OP_SPEC_IMPL
#define DECL_RRI_OP_SPEC(n, t, rr) \
        DECL_ASM_RRI_OP_SPEC_IMPL(n, t, rr)
// define TODO to rri_op_todo
#define TODO(Res, LHS, RHS) rri_op_todo(Res, LHS, RHS)
// define NA to rrr_op_abort
#define NA(Res, LHS, RHS) rri_op_abort(Res, LHS, RHS)
  DECL_ALL_RRI_OP()
#undef NA
#undef TODO
#undef DECL_RRI_OP_SPEC
#undef DECL_RRI_OP_TMPL
#undef DECL_ASM_RRI_OP_SPEC_IMPL

//
// generate all specialized unary operation instructions
//

// define macro to generate methods for specialized types outside class definition
#define DECL_ASM_RR_OP_SPEC_IMPL(Method, SrcType, r) \
  template<> inline void \
  A64Assembler::Method<A64::SrcType>(const typename A64TypeAttr<A64::SrcType>::Type &Res, \
                                   const typename A64TypeAttr<A64::SrcType>::Type &Opnd) { \
    r(Res, Opnd); \
  }

// define DECL_RR_OP_TMPL to nothing
#define DECL_RR_OP_TMPL(n, t, r) \
// define DECL_RR_OP_SPEC to DECL_ASM_RR_OP_SPEC_IMPL
#define DECL_RR_OP_SPEC(n, t, r) \
        DECL_ASM_RR_OP_SPEC_IMPL(n, t, r)
// define TODO to rr_op_todo
#define TODO(Res, Opnd) rr_op_todo(Res, Opnd)
// define NA to rr_op_abort
#define NA(Res, Opnd) rr_op_abort(Res, Opnd)
  DECL_ALL_RR_OP()
#undef NA
#undef TODO
#undef DECL_RR_OP_SPEC
#undef DECL_RR_OP_TMPL
#undef DECL_ASM_RR_OP_SPEC_IMPL

//
// generate all specialized unary operation instructions
//

// define macro to generate methods for specialized types outside class definition
#define DECL_ASM_RI_OP_SPEC_IMPL(Method, SrcType, r) \
  template<> inline void \
  A64Assembler::Method<A64::SrcType>(const typename A64TypeAttr<A64::SrcType>::Type &Res, \
                                   int64_t Imm) { \
    r(Res, Imm); \
  }

// define DECL_RI_OP_TMPL to nothing
#define DECL_RI_OP_TMPL(n, t, r) \
// define DECL_RI_OP_SPEC to DECL_ASM_RI_OP_SPEC_IMPL
#define DECL_RI_OP_SPEC(n, t, r) \
        DECL_ASM_RI_OP_SPEC_IMPL(n, t, r)
// define TODO to rr_op_todo
#define TODO(Res, Opnd) ri_op_todo(Res, Opnd)
// define NA to rr_op_abort
#define NA(Res, Opnd) ri_op_abort(Res, Opnd)
  DECL_ALL_RI_OP()
#undef NA
#undef TODO
#undef DECL_RI_OP_SPEC
#undef DECL_RI_OP_TMPL
#undef DECL_ASM_RI_OP_SPEC_IMPL

} // namespace zen::singlepass

#endif // ZEN_SINGLEPASS_A64_ASM_ASSEMBLER_H
