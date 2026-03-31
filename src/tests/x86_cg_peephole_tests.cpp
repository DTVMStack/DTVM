// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/context.h"
#include "compiler/llvm-prebuild/Target/X86/X86Subtarget.h"
#include "compiler/mir/function.h"
#include "compiler/mir/module.h"
#include "compiler/target/x86/x86_cg_peephole.h"

#include <array>
#include <cstdint>
#include <gtest/gtest.h>
#include <random>

namespace {

using namespace COMPILER;
using namespace llvm;

MFunctionType *createVoidFunctionType(CompileContext &Context) {
  return MFunctionType::create(Context, Context.VoidType, {});
}

struct X86CmpFlags {
  bool Overflow = false;
  bool Sign = false;
  bool Zero = false;
  bool Carry = false;
  bool Parity = false;
};

X86CmpFlags computeCmpFlags(uint64_t Lhs, uint64_t Rhs) {
  const uint64_t Result = Lhs - Rhs;
  X86CmpFlags Flags;
  Flags.Overflow = ((Lhs ^ Rhs) & (Lhs ^ Result) & (1ULL << 63)) != 0;
  Flags.Sign = (Result >> 63) != 0;
  Flags.Zero = Result == 0;
  Flags.Carry = Lhs < Rhs;
  Flags.Parity =
      (__builtin_popcount(static_cast<unsigned>(Result & 0xff)) % 2) == 0;
  return Flags;
}

bool evaluateCondCode(int64_t CondCode, const X86CmpFlags &Flags) {
  switch (CondCode) {
  case X86::COND_O:
    return Flags.Overflow;
  case X86::COND_NO:
    return !Flags.Overflow;
  case X86::COND_B:
    return Flags.Carry;
  case X86::COND_AE:
    return !Flags.Carry;
  case X86::COND_E:
    return Flags.Zero;
  case X86::COND_NE:
    return !Flags.Zero;
  case X86::COND_BE:
    return Flags.Carry || Flags.Zero;
  case X86::COND_A:
    return !Flags.Carry && !Flags.Zero;
  case X86::COND_S:
    return Flags.Sign;
  case X86::COND_NS:
    return !Flags.Sign;
  case X86::COND_P:
    return Flags.Parity;
  case X86::COND_NP:
    return !Flags.Parity;
  case X86::COND_L:
    return Flags.Sign != Flags.Overflow;
  case X86::COND_GE:
    return Flags.Sign == Flags.Overflow;
  case X86::COND_LE:
    return Flags.Zero || (Flags.Sign != Flags.Overflow);
  case X86::COND_G:
    return !Flags.Zero && (Flags.Sign == Flags.Overflow);
  default:
    ADD_FAILURE() << "unexpected cond code " << CondCode;
    return false;
  }
}

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
struct X86ExecutionHarnessCase {
  const char *Name = nullptr;
  int64_t CondCode = X86::COND_INVALID;
  uint64_t (*Original)(uint64_t, uint64_t) = nullptr;
  uint64_t (*Rewritten)(uint64_t, uint64_t) = nullptr;
};

struct X86ZeroShiftHarnessResult {
  uint64_t Value = 0;
  uint64_t Flags = 0;
};

struct X86ZeroShiftExecutionHarnessCase {
  const char *Name = nullptr;
  X86ZeroShiftHarnessResult (*Original)(uint64_t, uint64_t, uint64_t) = nullptr;
  X86ZeroShiftHarnessResult (*Rewritten)(uint64_t, uint64_t,
                                         uint64_t) = nullptr;
  uint64_t ValueMask = 0;
};

struct X86SelfMoveExecutionHarnessCase {
  const char *Name = nullptr;
  X86ZeroShiftHarnessResult (*Original)(uint64_t, uint64_t, uint64_t) = nullptr;
  X86ZeroShiftHarnessResult (*Rewritten)(uint64_t, uint64_t,
                                         uint64_t) = nullptr;
  uint64_t ValueMask = 0;
};

struct X86FallthroughJccExecutionHarnessCase {
  const char *Name = nullptr;
  int64_t CondCode = X86::COND_INVALID;
  X86ZeroShiftHarnessResult (*Original)(uint64_t, uint64_t, uint64_t) = nullptr;
  X86ZeroShiftHarnessResult (*Rewritten)(uint64_t, uint64_t,
                                         uint64_t) = nullptr;
};

#define DEFINE_SETCC_TEST_JNE_EXEC_CASE(Name, CondCodeValue, SetccMnemonic,    \
                                        JccMnemonic)                           \
  static uint64_t execOriginal_##Name(uint64_t Lhs, uint64_t Rhs) {            \
    uint64_t Out;                                                              \
    asm volatile("cmpq %[rhs], %[lhs]\n\t" SetccMnemonic " %%al\n\t"           \
                 "testb %%al, %%al\n\t"                                        \
                 "jne 1f\n\t"                                                  \
                 "xorq %[out], %[out]\n\t"                                     \
                 "jmp 2f\n\t"                                                  \
                 "1:\n\t"                                                      \
                 "movq $1, %[out]\n\t"                                         \
                 "2:\n\t"                                                      \
                 : [out] "=&r"(Out)                                            \
                 : [lhs] "r"(Lhs), [rhs] "r"(Rhs)                              \
                 : "cc", "rax");                                               \
    return Out;                                                                \
  }                                                                            \
  static uint64_t execRewritten_##Name(uint64_t Lhs, uint64_t Rhs) {           \
    uint64_t Out;                                                              \
    asm volatile("cmpq %[rhs], %[lhs]\n\t" JccMnemonic " 1f\n\t"               \
                 "xorq %[out], %[out]\n\t"                                     \
                 "jmp 2f\n\t"                                                  \
                 "1:\n\t"                                                      \
                 "movq $1, %[out]\n\t"                                         \
                 "2:\n\t"                                                      \
                 : [out] "=&r"(Out)                                            \
                 : [lhs] "r"(Lhs), [rhs] "r"(Rhs)                              \
                 : "cc");                                                      \
    return Out;                                                                \
  }                                                                            \
  static constexpr X86ExecutionHarnessCase ExecCase_##Name = {                 \
      #Name, CondCodeValue, execOriginal_##Name, execRewritten_##Name}

DEFINE_SETCC_TEST_JNE_EXEC_CASE(O, X86::COND_O, "seto", "jo");
DEFINE_SETCC_TEST_JNE_EXEC_CASE(NO, X86::COND_NO, "setno", "jno");
DEFINE_SETCC_TEST_JNE_EXEC_CASE(B, X86::COND_B, "setb", "jb");
DEFINE_SETCC_TEST_JNE_EXEC_CASE(AE, X86::COND_AE, "setae", "jae");
DEFINE_SETCC_TEST_JNE_EXEC_CASE(E, X86::COND_E, "sete", "je");
DEFINE_SETCC_TEST_JNE_EXEC_CASE(NE, X86::COND_NE, "setne", "jne");
DEFINE_SETCC_TEST_JNE_EXEC_CASE(BE, X86::COND_BE, "setbe", "jbe");
DEFINE_SETCC_TEST_JNE_EXEC_CASE(A, X86::COND_A, "seta", "ja");
DEFINE_SETCC_TEST_JNE_EXEC_CASE(S, X86::COND_S, "sets", "js");
DEFINE_SETCC_TEST_JNE_EXEC_CASE(NS, X86::COND_NS, "setns", "jns");
DEFINE_SETCC_TEST_JNE_EXEC_CASE(P, X86::COND_P, "setp", "jp");
DEFINE_SETCC_TEST_JNE_EXEC_CASE(NP, X86::COND_NP, "setnp", "jnp");
DEFINE_SETCC_TEST_JNE_EXEC_CASE(L, X86::COND_L, "setl", "jl");
DEFINE_SETCC_TEST_JNE_EXEC_CASE(GE, X86::COND_GE, "setge", "jge");
DEFINE_SETCC_TEST_JNE_EXEC_CASE(LE, X86::COND_LE, "setle", "jle");
DEFINE_SETCC_TEST_JNE_EXEC_CASE(G, X86::COND_G, "setg", "jg");

const std::array<X86ExecutionHarnessCase, 16> ExecutionHarnessCases = {
    ExecCase_O,  ExecCase_NO, ExecCase_B,  ExecCase_AE, ExecCase_E, ExecCase_NE,
    ExecCase_BE, ExecCase_A,  ExecCase_S,  ExecCase_NS, ExecCase_P, ExecCase_NP,
    ExecCase_L,  ExecCase_GE, ExecCase_LE, ExecCase_G,
};

#define DEFINE_ZERO_SHIFT_EXEC_CASE_8(Name, Mnemonic)                          \
  static X86ZeroShiftHarnessResult execOriginal_##Name(                        \
      uint64_t Value, uint64_t FlagLhs, uint64_t FlagRhs) {                    \
    const uint8_t Input = static_cast<uint8_t>(Value);                         \
    uint64_t Out;                                                              \
    uint64_t Flags;                                                            \
    asm volatile(                                                              \
        "cmpq %[flag_rhs], %[flag_lhs]\n\t"                                    \
        "movb %[value], %%al\n\t" Mnemonic " $0, %%al\n\t"                     \
        "pushfq\n\t"                                                           \
        "popq %[flags]\n\t"                                                    \
        "movzbq %%al, %[out]\n\t"                                              \
        : [out] "=&r"(Out), [flags] "=&r"(Flags)                               \
        : [value] "q"(Input), [flag_lhs] "r"(FlagLhs), [flag_rhs] "r"(FlagRhs) \
        : "cc", "rax");                                                        \
    return {.Value = Out, .Flags = Flags};                                     \
  }                                                                            \
  static X86ZeroShiftHarnessResult execRewritten_##Name(                       \
      uint64_t Value, uint64_t FlagLhs, uint64_t FlagRhs) {                    \
    const uint8_t Input = static_cast<uint8_t>(Value);                         \
    uint64_t Out;                                                              \
    uint64_t Flags;                                                            \
    asm volatile(                                                              \
        "cmpq %[flag_rhs], %[flag_lhs]\n\t"                                    \
        "movb %[value], %%al\n\t"                                              \
        "pushfq\n\t"                                                           \
        "popq %[flags]\n\t"                                                    \
        "movzbq %%al, %[out]\n\t"                                              \
        : [out] "=&r"(Out), [flags] "=&r"(Flags)                               \
        : [value] "q"(Input), [flag_lhs] "r"(FlagLhs), [flag_rhs] "r"(FlagRhs) \
        : "cc", "rax");                                                        \
    return {.Value = Out, .Flags = Flags};                                     \
  }                                                                            \
  static constexpr X86ZeroShiftExecutionHarnessCase ZeroShiftCase_##Name = {   \
      #Name, execOriginal_##Name, execRewritten_##Name, 0xffULL}

#define DEFINE_ZERO_SHIFT_EXEC_CASE_16(Name, Mnemonic)                         \
  static X86ZeroShiftHarnessResult execOriginal_##Name(                        \
      uint64_t Value, uint64_t FlagLhs, uint64_t FlagRhs) {                    \
    const uint16_t Input = static_cast<uint16_t>(Value);                       \
    uint64_t Out;                                                              \
    uint64_t Flags;                                                            \
    asm volatile(                                                              \
        "cmpq %[flag_rhs], %[flag_lhs]\n\t"                                    \
        "movw %[value], %%ax\n\t" Mnemonic " $0, %%ax\n\t"                     \
        "pushfq\n\t"                                                           \
        "popq %[flags]\n\t"                                                    \
        "movzwq %%ax, %[out]\n\t"                                              \
        : [out] "=&r"(Out), [flags] "=&r"(Flags)                               \
        : [value] "r"(Input), [flag_lhs] "r"(FlagLhs), [flag_rhs] "r"(FlagRhs) \
        : "cc", "rax");                                                        \
    return {.Value = Out, .Flags = Flags};                                     \
  }                                                                            \
  static X86ZeroShiftHarnessResult execRewritten_##Name(                       \
      uint64_t Value, uint64_t FlagLhs, uint64_t FlagRhs) {                    \
    const uint16_t Input = static_cast<uint16_t>(Value);                       \
    uint64_t Out;                                                              \
    uint64_t Flags;                                                            \
    asm volatile(                                                              \
        "cmpq %[flag_rhs], %[flag_lhs]\n\t"                                    \
        "movw %[value], %%ax\n\t"                                              \
        "pushfq\n\t"                                                           \
        "popq %[flags]\n\t"                                                    \
        "movzwq %%ax, %[out]\n\t"                                              \
        : [out] "=&r"(Out), [flags] "=&r"(Flags)                               \
        : [value] "r"(Input), [flag_lhs] "r"(FlagLhs), [flag_rhs] "r"(FlagRhs) \
        : "cc", "rax");                                                        \
    return {.Value = Out, .Flags = Flags};                                     \
  }                                                                            \
  static constexpr X86ZeroShiftExecutionHarnessCase ZeroShiftCase_##Name = {   \
      #Name, execOriginal_##Name, execRewritten_##Name, 0xffffULL}

#define DEFINE_ZERO_SHIFT_EXEC_CASE_64(Name, Mnemonic)                         \
  static X86ZeroShiftHarnessResult execOriginal_##Name(                        \
      uint64_t Value, uint64_t FlagLhs, uint64_t FlagRhs) {                    \
    uint64_t Out;                                                              \
    uint64_t Flags;                                                            \
    asm volatile(                                                              \
        "cmpq %[flag_rhs], %[flag_lhs]\n\t"                                    \
        "movq %[value], %%rax\n\t" Mnemonic " $0, %%rax\n\t"                   \
        "pushfq\n\t"                                                           \
        "popq %[flags]\n\t"                                                    \
        "movq %%rax, %[out]\n\t"                                               \
        : [out] "=&r"(Out), [flags] "=&r"(Flags)                               \
        : [value] "r"(Value), [flag_lhs] "r"(FlagLhs), [flag_rhs] "r"(FlagRhs) \
        : "cc", "rax");                                                        \
    return {.Value = Out, .Flags = Flags};                                     \
  }                                                                            \
  static X86ZeroShiftHarnessResult execRewritten_##Name(                       \
      uint64_t Value, uint64_t FlagLhs, uint64_t FlagRhs) {                    \
    uint64_t Out;                                                              \
    uint64_t Flags;                                                            \
    asm volatile(                                                              \
        "cmpq %[flag_rhs], %[flag_lhs]\n\t"                                    \
        "movq %[value], %%rax\n\t"                                             \
        "pushfq\n\t"                                                           \
        "popq %[flags]\n\t"                                                    \
        "movq %%rax, %[out]\n\t"                                               \
        : [out] "=&r"(Out), [flags] "=&r"(Flags)                               \
        : [value] "r"(Value), [flag_lhs] "r"(FlagLhs), [flag_rhs] "r"(FlagRhs) \
        : "cc", "rax");                                                        \
    return {.Value = Out, .Flags = Flags};                                     \
  }                                                                            \
  static constexpr X86ZeroShiftExecutionHarnessCase ZeroShiftCase_##Name = {   \
      #Name, execOriginal_##Name, execRewritten_##Name, ~0ULL}

DEFINE_ZERO_SHIFT_EXEC_CASE_8(SHL8, "shlb");
DEFINE_ZERO_SHIFT_EXEC_CASE_16(SHL16, "shlw");
DEFINE_ZERO_SHIFT_EXEC_CASE_64(SHL64, "shlq");
DEFINE_ZERO_SHIFT_EXEC_CASE_8(SHR8, "shrb");
DEFINE_ZERO_SHIFT_EXEC_CASE_16(SHR16, "shrw");
DEFINE_ZERO_SHIFT_EXEC_CASE_64(SHR64, "shrq");
DEFINE_ZERO_SHIFT_EXEC_CASE_8(SAR8, "sarb");
DEFINE_ZERO_SHIFT_EXEC_CASE_16(SAR16, "sarw");
DEFINE_ZERO_SHIFT_EXEC_CASE_64(SAR64, "sarq");

const std::array<X86ZeroShiftExecutionHarnessCase, 9> ZeroShiftHarnessCases = {
    ZeroShiftCase_SHL8, ZeroShiftCase_SHL16, ZeroShiftCase_SHL64,
    ZeroShiftCase_SHR8, ZeroShiftCase_SHR16, ZeroShiftCase_SHR64,
    ZeroShiftCase_SAR8, ZeroShiftCase_SAR16, ZeroShiftCase_SAR64,
};

static X86ZeroShiftHarnessResult
execOriginalSelfMove8(uint64_t Value, uint64_t FlagLhs, uint64_t FlagRhs) {
  const uint8_t Input = static_cast<uint8_t>(Value);
  uint64_t Out;
  uint64_t Flags;
  asm volatile(
      "cmpq %[flag_rhs], %[flag_lhs]\n\t"
      "movb %[value], %%al\n\t"
      "movb %%al, %%al\n\t"
      "pushfq\n\t"
      "popq %[flags]\n\t"
      "movzbq %%al, %[out]\n\t"
      : [out] "=&r"(Out), [flags] "=&r"(Flags)
      : [value] "q"(Input), [flag_lhs] "r"(FlagLhs), [flag_rhs] "r"(FlagRhs)
      : "cc", "rax");
  return {.Value = Out, .Flags = Flags};
}

static X86ZeroShiftHarnessResult
execRewrittenSelfMove8(uint64_t Value, uint64_t FlagLhs, uint64_t FlagRhs) {
  const uint8_t Input = static_cast<uint8_t>(Value);
  uint64_t Out;
  uint64_t Flags;
  asm volatile(
      "cmpq %[flag_rhs], %[flag_lhs]\n\t"
      "movb %[value], %%al\n\t"
      "pushfq\n\t"
      "popq %[flags]\n\t"
      "movzbq %%al, %[out]\n\t"
      : [out] "=&r"(Out), [flags] "=&r"(Flags)
      : [value] "q"(Input), [flag_lhs] "r"(FlagLhs), [flag_rhs] "r"(FlagRhs)
      : "cc", "rax");
  return {.Value = Out, .Flags = Flags};
}

static X86ZeroShiftHarnessResult
execOriginalSelfMove16(uint64_t Value, uint64_t FlagLhs, uint64_t FlagRhs) {
  const uint16_t Input = static_cast<uint16_t>(Value);
  uint64_t Out;
  uint64_t Flags;
  asm volatile(
      "cmpq %[flag_rhs], %[flag_lhs]\n\t"
      "movw %[value], %%ax\n\t"
      "movw %%ax, %%ax\n\t"
      "pushfq\n\t"
      "popq %[flags]\n\t"
      "movzwq %%ax, %[out]\n\t"
      : [out] "=&r"(Out), [flags] "=&r"(Flags)
      : [value] "r"(Input), [flag_lhs] "r"(FlagLhs), [flag_rhs] "r"(FlagRhs)
      : "cc", "rax");
  return {.Value = Out, .Flags = Flags};
}

static X86ZeroShiftHarnessResult
execRewrittenSelfMove16(uint64_t Value, uint64_t FlagLhs, uint64_t FlagRhs) {
  const uint16_t Input = static_cast<uint16_t>(Value);
  uint64_t Out;
  uint64_t Flags;
  asm volatile(
      "cmpq %[flag_rhs], %[flag_lhs]\n\t"
      "movw %[value], %%ax\n\t"
      "pushfq\n\t"
      "popq %[flags]\n\t"
      "movzwq %%ax, %[out]\n\t"
      : [out] "=&r"(Out), [flags] "=&r"(Flags)
      : [value] "r"(Input), [flag_lhs] "r"(FlagLhs), [flag_rhs] "r"(FlagRhs)
      : "cc", "rax");
  return {.Value = Out, .Flags = Flags};
}

static X86ZeroShiftHarnessResult
execOriginalSelfMove64(uint64_t Value, uint64_t FlagLhs, uint64_t FlagRhs) {
  uint64_t Out;
  uint64_t Flags;
  asm volatile(
      "cmpq %[flag_rhs], %[flag_lhs]\n\t"
      "movq %[value], %%rax\n\t"
      "movq %%rax, %%rax\n\t"
      "pushfq\n\t"
      "popq %[flags]\n\t"
      "movq %%rax, %[out]\n\t"
      : [out] "=&r"(Out), [flags] "=&r"(Flags)
      : [value] "r"(Value), [flag_lhs] "r"(FlagLhs), [flag_rhs] "r"(FlagRhs)
      : "cc", "rax");
  return {.Value = Out, .Flags = Flags};
}

static X86ZeroShiftHarnessResult
execRewrittenSelfMove64(uint64_t Value, uint64_t FlagLhs, uint64_t FlagRhs) {
  uint64_t Out;
  uint64_t Flags;
  asm volatile(
      "cmpq %[flag_rhs], %[flag_lhs]\n\t"
      "movq %[value], %%rax\n\t"
      "pushfq\n\t"
      "popq %[flags]\n\t"
      "movq %%rax, %[out]\n\t"
      : [out] "=&r"(Out), [flags] "=&r"(Flags)
      : [value] "r"(Value), [flag_lhs] "r"(FlagLhs), [flag_rhs] "r"(FlagRhs)
      : "cc", "rax");
  return {.Value = Out, .Flags = Flags};
}

static X86ZeroShiftHarnessResult
execOriginalSelfMove32(uint64_t Value, uint64_t FlagLhs, uint64_t FlagRhs) {
  uint64_t Out;
  uint64_t Flags;
  asm volatile(
      "cmpq %[flag_rhs], %[flag_lhs]\n\t"
      "movq %[value], %%rax\n\t"
      "movl %%eax, %%eax\n\t"
      "pushfq\n\t"
      "popq %[flags]\n\t"
      "movq %%rax, %[out]\n\t"
      : [out] "=&r"(Out), [flags] "=&r"(Flags)
      : [value] "r"(Value), [flag_lhs] "r"(FlagLhs), [flag_rhs] "r"(FlagRhs)
      : "cc", "rax");
  return {.Value = Out, .Flags = Flags};
}

static X86ZeroShiftHarnessResult
execRewrittenSelfMove32(uint64_t Value, uint64_t FlagLhs, uint64_t FlagRhs) {
  uint64_t Out;
  uint64_t Flags;
  asm volatile(
      "cmpq %[flag_rhs], %[flag_lhs]\n\t"
      "movq %[value], %%rax\n\t"
      "pushfq\n\t"
      "popq %[flags]\n\t"
      "movq %%rax, %[out]\n\t"
      : [out] "=&r"(Out), [flags] "=&r"(Flags)
      : [value] "r"(Value), [flag_lhs] "r"(FlagLhs), [flag_rhs] "r"(FlagRhs)
      : "cc", "rax");
  return {.Value = Out, .Flags = Flags};
}

const std::array<X86SelfMoveExecutionHarnessCase, 3> SelfMoveHarnessCases = {
    X86SelfMoveExecutionHarnessCase{"MOV8rr", execOriginalSelfMove8,
                                    execRewrittenSelfMove8, 0xffULL},
    X86SelfMoveExecutionHarnessCase{"MOV16rr", execOriginalSelfMove16,
                                    execRewrittenSelfMove16, 0xffffULL},
    X86SelfMoveExecutionHarnessCase{"MOV64rr", execOriginalSelfMove64,
                                    execRewrittenSelfMove64, ~0ULL},
};

#define DEFINE_FALLTHROUGH_JCC_EXEC_CASE(Name, CondCodeValue, JccMnemonic)     \
  static X86ZeroShiftHarnessResult execOriginalFallthroughJcc_##Name(          \
      uint64_t Value, uint64_t FlagLhs, uint64_t FlagRhs) {                    \
    uint64_t Out;                                                              \
    uint64_t Flags;                                                            \
    asm volatile(                                                              \
        "cmpq %[flag_rhs], %[flag_lhs]\n\t" JccMnemonic " 1f\n\t"              \
        "1:\n\t"                                                               \
        "movq %[value], %[out]\n\t"                                            \
        "pushfq\n\t"                                                           \
        "popq %[flags]\n\t"                                                    \
        : [out] "=&r"(Out), [flags] "=&r"(Flags)                               \
        : [value] "r"(Value), [flag_lhs] "r"(FlagLhs), [flag_rhs] "r"(FlagRhs) \
        : "cc");                                                               \
    return {.Value = Out, .Flags = Flags};                                     \
  }                                                                            \
  static X86ZeroShiftHarnessResult execRewrittenFallthroughJcc_##Name(         \
      uint64_t Value, uint64_t FlagLhs, uint64_t FlagRhs) {                    \
    uint64_t Out;                                                              \
    uint64_t Flags;                                                            \
    asm volatile(                                                              \
        "cmpq %[flag_rhs], %[flag_lhs]\n\t"                                    \
        "movq %[value], %[out]\n\t"                                            \
        "pushfq\n\t"                                                           \
        "popq %[flags]\n\t"                                                    \
        : [out] "=&r"(Out), [flags] "=&r"(Flags)                               \
        : [value] "r"(Value), [flag_lhs] "r"(FlagLhs), [flag_rhs] "r"(FlagRhs) \
        : "cc");                                                               \
    return {.Value = Out, .Flags = Flags};                                     \
  }                                                                            \
  static constexpr X86FallthroughJccExecutionHarnessCase                       \
      FallthroughJccCase_##Name = {#Name, CondCodeValue,                       \
                                   execOriginalFallthroughJcc_##Name,          \
                                   execRewrittenFallthroughJcc_##Name}

DEFINE_FALLTHROUGH_JCC_EXEC_CASE(O, X86::COND_O, "jo");
DEFINE_FALLTHROUGH_JCC_EXEC_CASE(NO, X86::COND_NO, "jno");
DEFINE_FALLTHROUGH_JCC_EXEC_CASE(B, X86::COND_B, "jb");
DEFINE_FALLTHROUGH_JCC_EXEC_CASE(AE, X86::COND_AE, "jae");
DEFINE_FALLTHROUGH_JCC_EXEC_CASE(E, X86::COND_E, "je");
DEFINE_FALLTHROUGH_JCC_EXEC_CASE(NE, X86::COND_NE, "jne");
DEFINE_FALLTHROUGH_JCC_EXEC_CASE(BE, X86::COND_BE, "jbe");
DEFINE_FALLTHROUGH_JCC_EXEC_CASE(A, X86::COND_A, "ja");
DEFINE_FALLTHROUGH_JCC_EXEC_CASE(S, X86::COND_S, "js");
DEFINE_FALLTHROUGH_JCC_EXEC_CASE(NS, X86::COND_NS, "jns");
DEFINE_FALLTHROUGH_JCC_EXEC_CASE(P, X86::COND_P, "jp");
DEFINE_FALLTHROUGH_JCC_EXEC_CASE(NP, X86::COND_NP, "jnp");
DEFINE_FALLTHROUGH_JCC_EXEC_CASE(L, X86::COND_L, "jl");
DEFINE_FALLTHROUGH_JCC_EXEC_CASE(GE, X86::COND_GE, "jge");
DEFINE_FALLTHROUGH_JCC_EXEC_CASE(LE, X86::COND_LE, "jle");
DEFINE_FALLTHROUGH_JCC_EXEC_CASE(G, X86::COND_G, "jg");

const std::array<X86FallthroughJccExecutionHarnessCase, 16>
    FallthroughJccHarnessCases = {
        FallthroughJccCase_O,  FallthroughJccCase_NO, FallthroughJccCase_B,
        FallthroughJccCase_AE, FallthroughJccCase_E,  FallthroughJccCase_NE,
        FallthroughJccCase_BE, FallthroughJccCase_A,  FallthroughJccCase_S,
        FallthroughJccCase_NS, FallthroughJccCase_P,  FallthroughJccCase_NP,
        FallthroughJccCase_L,  FallthroughJccCase_GE, FallthroughJccCase_LE,
        FallthroughJccCase_G,
};

static X86ZeroShiftHarnessResult execOriginalRedundantTest64(uint64_t Value,
                                                             uint64_t FlagLhs,
                                                             uint64_t FlagRhs) {
  uint64_t Out;
  uint64_t Flags;
  asm volatile(
      "movq %[value], %%rax\n\t"
      "testq %%rax, %%rax\n\t"
      "testq %%rax, %%rax\n\t"
      "pushfq\n\t"
      "popq %[flags]\n\t"
      "movq %%rax, %[out]\n\t"
      : [out] "=&r"(Out), [flags] "=&r"(Flags)
      : [value] "r"(Value), [flag_lhs] "r"(FlagLhs), [flag_rhs] "r"(FlagRhs)
      : "cc", "rax");
  return {.Value = Out, .Flags = Flags};
}

static X86ZeroShiftHarnessResult
execRewrittenRedundantTest64(uint64_t Value, uint64_t FlagLhs,
                             uint64_t FlagRhs) {
  uint64_t Out;
  uint64_t Flags;
  asm volatile(
      "movq %[value], %%rax\n\t"
      "testq %%rax, %%rax\n\t"
      "pushfq\n\t"
      "popq %[flags]\n\t"
      "movq %%rax, %[out]\n\t"
      : [out] "=&r"(Out), [flags] "=&r"(Flags)
      : [value] "r"(Value), [flag_lhs] "r"(FlagLhs), [flag_rhs] "r"(FlagRhs)
      : "cc", "rax");
  return {.Value = Out, .Flags = Flags};
}

static X86ZeroShiftHarnessResult execOriginalRedundantTest32(uint64_t Value,
                                                             uint64_t FlagLhs,
                                                             uint64_t FlagRhs) {
  uint64_t Out;
  uint64_t Flags;
  const uint32_t Input = static_cast<uint32_t>(Value);
  asm volatile("movq %[value], %%rax\n\t"
               "testl %%eax, %%eax\n\t"
               "testl %%eax, %%eax\n\t"
               "pushfq\n\t"
               "popq %[flags]\n\t"
               "movl %%eax, %k[out]\n\t"
               : [out] "=&r"(Out), [flags] "=&r"(Flags)
               : [value] "r"(static_cast<uint64_t>(Input)),
                 [flag_lhs] "r"(FlagLhs), [flag_rhs] "r"(FlagRhs)
               : "cc", "rax");
  return {.Value = Out, .Flags = Flags};
}

static X86ZeroShiftHarnessResult
execRewrittenRedundantTest32(uint64_t Value, uint64_t FlagLhs,
                             uint64_t FlagRhs) {
  uint64_t Out;
  uint64_t Flags;
  const uint32_t Input = static_cast<uint32_t>(Value);
  asm volatile("movq %[value], %%rax\n\t"
               "testl %%eax, %%eax\n\t"
               "pushfq\n\t"
               "popq %[flags]\n\t"
               "movl %%eax, %k[out]\n\t"
               : [out] "=&r"(Out), [flags] "=&r"(Flags)
               : [value] "r"(static_cast<uint64_t>(Input)),
                 [flag_lhs] "r"(FlagLhs), [flag_rhs] "r"(FlagRhs)
               : "cc", "rax");
  return {.Value = Out, .Flags = Flags};
}

static X86ZeroShiftHarnessResult
execOriginalRedundantTest8(uint64_t Value, uint64_t FlagLhs, uint64_t FlagRhs) {
  uint64_t Out;
  uint64_t Flags;
  asm volatile("movb %[value8], %%al\n\t"
               "testb %%al, %%al\n\t"
               "testb %%al, %%al\n\t"
               "pushfq\n\t"
               "popq %[flags]\n\t"
               "movzbq %%al, %[out]\n\t"
               : [out] "=&r"(Out), [flags] "=&r"(Flags)
               : [value8] "q"(static_cast<uint8_t>(Value)),
                 [flag_lhs] "r"(FlagLhs), [flag_rhs] "r"(FlagRhs)
               : "cc", "rax");
  return {.Value = Out, .Flags = Flags};
}

static X86ZeroShiftHarnessResult execRewrittenRedundantTest8(uint64_t Value,
                                                             uint64_t FlagLhs,
                                                             uint64_t FlagRhs) {
  uint64_t Out;
  uint64_t Flags;
  asm volatile("movb %[value8], %%al\n\t"
               "testb %%al, %%al\n\t"
               "pushfq\n\t"
               "popq %[flags]\n\t"
               "movzbq %%al, %[out]\n\t"
               : [out] "=&r"(Out), [flags] "=&r"(Flags)
               : [value8] "q"(static_cast<uint8_t>(Value)),
                 [flag_lhs] "r"(FlagLhs), [flag_rhs] "r"(FlagRhs)
               : "cc", "rax");
  return {.Value = Out, .Flags = Flags};
}

static X86ZeroShiftHarnessResult execOriginalFallthroughJump(uint64_t Value,
                                                             uint64_t FlagLhs,
                                                             uint64_t FlagRhs) {
  uint64_t Out;
  uint64_t Flags;
  asm volatile(
      "cmpq %[flag_rhs], %[flag_lhs]\n\t"
      "jmp 1f\n\t"
      "1:\n\t"
      "movq %[value], %[out]\n\t"
      "pushfq\n\t"
      "popq %[flags]\n\t"
      : [out] "=&r"(Out), [flags] "=&r"(Flags)
      : [value] "r"(Value), [flag_lhs] "r"(FlagLhs), [flag_rhs] "r"(FlagRhs)
      : "cc");
  return {.Value = Out, .Flags = Flags};
}

static X86ZeroShiftHarnessResult
execRewrittenFallthroughJump(uint64_t Value, uint64_t FlagLhs,
                             uint64_t FlagRhs) {
  uint64_t Out;
  uint64_t Flags;
  asm volatile(
      "cmpq %[flag_rhs], %[flag_lhs]\n\t"
      "movq %[value], %[out]\n\t"
      "pushfq\n\t"
      "popq %[flags]\n\t"
      : [out] "=&r"(Out), [flags] "=&r"(Flags)
      : [value] "r"(Value), [flag_lhs] "r"(FlagLhs), [flag_rhs] "r"(FlagRhs)
      : "cc");
  return {.Value = Out, .Flags = Flags};
}
#endif

TEST(X86CgPeephole, FoldsSetccTestJneChain) {
  CompileContext Context;
  Context.initialize();

  MModule Mod(Context);
  MFunctionType *FuncType = createVoidFunctionType(Context);
  Mod.addFuncType(FuncType);

  MFunction MirFunc(Context, 0);
  MirFunc.setFunctionType(FuncType);
  CgFunction MF(Context, MirFunc);

  CgBasicBlock *BB = MF.createCgBasicBlock();
  CgBasicBlock *TargetBB = MF.createCgBasicBlock();
  MF.appendCgBasicBlock(BB);
  MF.appendCgBasicBlock(MF.createCgBasicBlock());
  MF.appendCgBasicBlock(TargetBB);

  const auto &TII = MF.getTargetInstrInfo();
  std::array<CgOperand, 2> CmpOps = {
      CgOperand::createRegOperand(X86::RAX, false),
      CgOperand::createRegOperand(X86::RBX, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::CMP64rr), CmpOps);

  std::array<CgOperand, 2> SetccOps = {
      CgOperand::createRegOperand(X86::AL, true),
      CgOperand::createImmOperand(X86::COND_E),
  };
  MF.createCgInstruction(*BB, TII.get(X86::SETCCr), SetccOps);

  std::array<CgOperand, 2> TestOps = {
      CgOperand::createRegOperand(X86::AL, false),
      CgOperand::createRegOperand(X86::AL, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::TEST8rr), TestOps);

  std::array<CgOperand, 2> JccOps = {
      CgOperand::createMBB(TargetBB),
      CgOperand::createImmOperand(X86::COND_NE),
  };
  MF.createCgInstruction(*BB, TII.get(X86::JCC_1), JccOps);

  X86CgPeephole Peephole(MF);

  ASSERT_EQ(std::distance(BB->begin(), BB->end()), 2);
  auto It = BB->begin();
  EXPECT_EQ(It->getOpcode(), X86::CMP64rr);
  ++It;
  ASSERT_NE(It, BB->end());
  EXPECT_EQ(It->getOpcode(), X86::JCC_1);
  EXPECT_EQ(It->getOperand(1).getImm(), X86::COND_E);
}

TEST(X86CgPeephole, RemovesSelfMove64) {
  CompileContext Context;
  Context.initialize();

  MModule Mod(Context);
  MFunctionType *FuncType = createVoidFunctionType(Context);
  Mod.addFuncType(FuncType);

  MFunction MirFunc(Context, 0);
  MirFunc.setFunctionType(FuncType);
  CgFunction MF(Context, MirFunc);

  CgBasicBlock *BB = MF.createCgBasicBlock();
  MF.appendCgBasicBlock(BB);

  const auto &TII = MF.getTargetInstrInfo();
  std::array<CgOperand, 2> MoveOps = {
      CgOperand::createRegOperand(X86::RAX, true),
      CgOperand::createRegOperand(X86::RAX, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::MOV64rr), MoveOps);

  X86CgPeephole Peephole(MF);

  EXPECT_TRUE(BB->empty());
}

TEST(X86CgPeephole, KeepsSelfMove32) {
  CompileContext Context;
  Context.initialize();

  MModule Mod(Context);
  MFunctionType *FuncType = createVoidFunctionType(Context);
  Mod.addFuncType(FuncType);

  MFunction MirFunc(Context, 0);
  MirFunc.setFunctionType(FuncType);
  CgFunction MF(Context, MirFunc);

  CgBasicBlock *BB = MF.createCgBasicBlock();
  MF.appendCgBasicBlock(BB);

  const auto &TII = MF.getTargetInstrInfo();
  std::array<CgOperand, 2> MoveOps = {
      CgOperand::createRegOperand(X86::EAX, true),
      CgOperand::createRegOperand(X86::EAX, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::MOV32rr), MoveOps);

  X86CgPeephole Peephole(MF);

  ASSERT_EQ(std::distance(BB->begin(), BB->end()), 1);
  EXPECT_EQ(BB->begin()->getOpcode(), X86::MOV32rr);
}

TEST(X86CgPeephole, RemovesZeroShift64) {
  CompileContext Context;
  Context.initialize();

  MModule Mod(Context);
  MFunctionType *FuncType = createVoidFunctionType(Context);
  Mod.addFuncType(FuncType);

  MFunction MirFunc(Context, 0);
  MirFunc.setFunctionType(FuncType);
  CgFunction MF(Context, MirFunc);

  CgBasicBlock *BB = MF.createCgBasicBlock();
  MF.appendCgBasicBlock(BB);

  const auto &TII = MF.getTargetInstrInfo();
  std::array<CgOperand, 3> ShiftOps = {
      CgOperand::createRegOperand(X86::RAX, true),
      CgOperand::createRegOperand(X86::RAX, false),
      CgOperand::createImmOperand(0),
  };
  MF.createCgInstruction(*BB, TII.get(X86::SHL64ri), ShiftOps);

  X86CgPeephole Peephole(MF);

  EXPECT_TRUE(BB->empty());
}

TEST(X86CgPeephole, KeepsZeroShift32) {
  CompileContext Context;
  Context.initialize();

  MModule Mod(Context);
  MFunctionType *FuncType = createVoidFunctionType(Context);
  Mod.addFuncType(FuncType);

  MFunction MirFunc(Context, 0);
  MirFunc.setFunctionType(FuncType);
  CgFunction MF(Context, MirFunc);

  CgBasicBlock *BB = MF.createCgBasicBlock();
  MF.appendCgBasicBlock(BB);

  const auto &TII = MF.getTargetInstrInfo();
  std::array<CgOperand, 3> ShiftOps = {
      CgOperand::createRegOperand(X86::EAX, true),
      CgOperand::createRegOperand(X86::EAX, false),
      CgOperand::createImmOperand(0),
  };
  MF.createCgInstruction(*BB, TII.get(X86::SHL32ri), ShiftOps);

  X86CgPeephole Peephole(MF);

  ASSERT_EQ(std::distance(BB->begin(), BB->end()), 1);
  EXPECT_EQ(BB->begin()->getOpcode(), X86::SHL32ri);
}

TEST(X86CgPeephole, KeepsMixedOperandTestChain) {
  CompileContext Context;
  Context.initialize();

  MModule Mod(Context);
  MFunctionType *FuncType = createVoidFunctionType(Context);
  Mod.addFuncType(FuncType);

  MFunction MirFunc(Context, 0);
  MirFunc.setFunctionType(FuncType);
  CgFunction MF(Context, MirFunc);

  CgBasicBlock *BB = MF.createCgBasicBlock();
  CgBasicBlock *TargetBB = MF.createCgBasicBlock();
  MF.appendCgBasicBlock(BB);
  MF.appendCgBasicBlock(MF.createCgBasicBlock());
  MF.appendCgBasicBlock(TargetBB);

  const auto &TII = MF.getTargetInstrInfo();
  std::array<CgOperand, 2> CmpOps = {
      CgOperand::createRegOperand(X86::RAX, false),
      CgOperand::createRegOperand(X86::RBX, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::CMP64rr), CmpOps);

  std::array<CgOperand, 2> SetccOps = {
      CgOperand::createRegOperand(X86::AL, true),
      CgOperand::createImmOperand(X86::COND_E),
  };
  MF.createCgInstruction(*BB, TII.get(X86::SETCCr), SetccOps);

  std::array<CgOperand, 2> TestOps = {
      CgOperand::createRegOperand(X86::AL, false),
      CgOperand::createRegOperand(X86::BL, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::TEST8rr), TestOps);

  std::array<CgOperand, 2> JccOps = {
      CgOperand::createMBB(TargetBB),
      CgOperand::createImmOperand(X86::COND_NE),
  };
  MF.createCgInstruction(*BB, TII.get(X86::JCC_1), JccOps);

  X86CgPeephole Peephole(MF);

  EXPECT_EQ(std::distance(BB->begin(), BB->end()), 4);
}

TEST(X86CgPeephole, FuzzFoldSetccTestJneToJccSemantics) {
  const std::array<int64_t, 16> CondCodes = {
      X86::COND_O, X86::COND_NO, X86::COND_B,  X86::COND_AE,
      X86::COND_E, X86::COND_NE, X86::COND_BE, X86::COND_A,
      X86::COND_S, X86::COND_NS, X86::COND_P,  X86::COND_NP,
      X86::COND_L, X86::COND_GE, X86::COND_LE, X86::COND_G,
  };
  std::mt19937_64 Rng(0xD7A12025ULL);

  for (int64_t CondCode : CondCodes) {
    for (int Iter = 0; Iter < 20000; ++Iter) {
      const uint64_t Lhs = Rng();
      const uint64_t Rhs = Rng();
      const X86CmpFlags Flags = computeCmpFlags(Lhs, Rhs);
      const uint8_t SetccResult =
          evaluateCondCode(CondCode, Flags) ? uint8_t{1} : uint8_t{0};
      const bool OriginalBranches = SetccResult != 0;
      const bool RewrittenBranches = evaluateCondCode(CondCode, Flags);
      EXPECT_EQ(OriginalBranches, RewrittenBranches)
          << "cond=" << CondCode << " lhs=" << Lhs << " rhs=" << Rhs;
    }
  }
}

TEST(X86CgPeephole, ExecutionHarnessFoldSetccTestJneToJcc) {
#if !defined(__x86_64__) || !(defined(__GNUC__) || defined(__clang__))
  GTEST_SKIP() << "execution harness requires x86_64 GNU-style inline asm";
#else
  const std::array<uint64_t, 12> EdgeValues = {
      0ULL,
      1ULL,
      2ULL,
      0x7fffffffffffffffULL,
      0x8000000000000000ULL,
      0x8000000000000001ULL,
      0xffffffffffffffffULL,
      0xfffffffffffffffeULL,
      0xaaaaaaaaaaaaaaaaULL,
      0x5555555555555555ULL,
      0x00000000ffffffffULL,
      0xffffffff00000000ULL,
  };
  std::mt19937_64 Rng(0xE8EC2025ULL);

  for (const auto &HarnessCase : ExecutionHarnessCases) {
    for (uint64_t Lhs : EdgeValues) {
      for (uint64_t Rhs : EdgeValues) {
        const bool Original = HarnessCase.Original(Lhs, Rhs) != 0;
        const bool Rewritten = HarnessCase.Rewritten(Lhs, Rhs) != 0;
        const bool Modeled =
            evaluateCondCode(HarnessCase.CondCode, computeCmpFlags(Lhs, Rhs));
        EXPECT_EQ(Original, Rewritten)
            << "case=" << HarnessCase.Name << " lhs=" << Lhs << " rhs=" << Rhs;
        EXPECT_EQ(Original, Modeled)
            << "case=" << HarnessCase.Name << " lhs=" << Lhs << " rhs=" << Rhs;
      }
    }

    for (int Iter = 0; Iter < 10000; ++Iter) {
      const uint64_t Lhs = Rng();
      const uint64_t Rhs = Rng();
      const bool Original = HarnessCase.Original(Lhs, Rhs) != 0;
      const bool Rewritten = HarnessCase.Rewritten(Lhs, Rhs) != 0;
      EXPECT_EQ(Original, Rewritten)
          << "case=" << HarnessCase.Name << " lhs=" << Lhs << " rhs=" << Rhs;
    }
  }
#endif
}

TEST(X86CgPeephole, ExecutionHarnessRemoveZeroShift) {
#if !defined(__x86_64__) || !(defined(__GNUC__) || defined(__clang__))
  GTEST_SKIP() << "execution harness requires x86_64 GNU-style inline asm";
#else
  const std::array<uint64_t, 12> EdgeValues = {
      0ULL,
      1ULL,
      2ULL,
      0x7fffffffffffffffULL,
      0x8000000000000000ULL,
      0x8000000000000001ULL,
      0xffffffffffffffffULL,
      0xfffffffffffffffeULL,
      0xaaaaaaaaaaaaaaaaULL,
      0x5555555555555555ULL,
      0x00000000ffffffffULL,
      0xffffffff00000000ULL,
  };
  const std::array<std::pair<uint64_t, uint64_t>, 6> FlagSeeds = {
      std::pair<uint64_t, uint64_t>{0ULL, 0ULL},
      std::pair<uint64_t, uint64_t>{0ULL, 1ULL},
      std::pair<uint64_t, uint64_t>{1ULL, 0ULL},
      std::pair<uint64_t, uint64_t>{0x8000000000000000ULL, 1ULL},
      std::pair<uint64_t, uint64_t>{0x7fffffffffffffffULL,
                                    0xffffffffffffffffULL},
      std::pair<uint64_t, uint64_t>{0xaaaaaaaaaaaaaaaaULL,
                                    0x5555555555555555ULL},
  };
  std::mt19937_64 Rng(0xA0C02026ULL);

  for (const auto &HarnessCase : ZeroShiftHarnessCases) {
    for (const auto &[FlagLhs, FlagRhs] : FlagSeeds) {
      for (uint64_t Value : EdgeValues) {
        const auto Original = HarnessCase.Original(Value, FlagLhs, FlagRhs);
        const auto Rewritten = HarnessCase.Rewritten(Value, FlagLhs, FlagRhs);
        EXPECT_EQ(Original.Value & HarnessCase.ValueMask,
                  Rewritten.Value & HarnessCase.ValueMask)
            << "case=" << HarnessCase.Name << " value=" << Value
            << " flag_lhs=" << FlagLhs << " flag_rhs=" << FlagRhs;
        EXPECT_EQ(Original.Flags, Rewritten.Flags)
            << "case=" << HarnessCase.Name << " value=" << Value
            << " flag_lhs=" << FlagLhs << " flag_rhs=" << FlagRhs;
      }
    }

    for (int Iter = 0; Iter < 4000; ++Iter) {
      const uint64_t Value = Rng();
      const uint64_t FlagLhs = Rng();
      const uint64_t FlagRhs = Rng();
      const auto Original = HarnessCase.Original(Value, FlagLhs, FlagRhs);
      const auto Rewritten = HarnessCase.Rewritten(Value, FlagLhs, FlagRhs);
      EXPECT_EQ(Original.Value & HarnessCase.ValueMask,
                Rewritten.Value & HarnessCase.ValueMask)
          << "case=" << HarnessCase.Name << " value=" << Value
          << " flag_lhs=" << FlagLhs << " flag_rhs=" << FlagRhs;
      EXPECT_EQ(Original.Flags, Rewritten.Flags)
          << "case=" << HarnessCase.Name << " value=" << Value
          << " flag_lhs=" << FlagLhs << " flag_rhs=" << FlagRhs;
    }
  }
#endif
}

TEST(X86CgPeephole, ExecutionHarnessRemoveSelfMove) {
#if !defined(__x86_64__) || !(defined(__GNUC__) || defined(__clang__))
  GTEST_SKIP() << "execution harness requires x86_64 GNU-style inline asm";
#else
  const std::array<uint64_t, 12> EdgeValues = {
      0ULL,
      1ULL,
      2ULL,
      0x7fffffffffffffffULL,
      0x8000000000000000ULL,
      0x8000000000000001ULL,
      0xffffffffffffffffULL,
      0xfffffffffffffffeULL,
      0xaaaaaaaaaaaaaaaaULL,
      0x5555555555555555ULL,
      0x00000000ffffffffULL,
      0xffffffff00000000ULL,
  };
  const std::array<std::pair<uint64_t, uint64_t>, 6> FlagSeeds = {
      std::pair<uint64_t, uint64_t>{0ULL, 0ULL},
      std::pair<uint64_t, uint64_t>{0ULL, 1ULL},
      std::pair<uint64_t, uint64_t>{1ULL, 0ULL},
      std::pair<uint64_t, uint64_t>{0x8000000000000000ULL, 1ULL},
      std::pair<uint64_t, uint64_t>{0x7fffffffffffffffULL,
                                    0xffffffffffffffffULL},
      std::pair<uint64_t, uint64_t>{0xaaaaaaaaaaaaaaaaULL,
                                    0x5555555555555555ULL},
  };
  std::mt19937_64 Rng(0x51F2026ULL);

  for (const auto &HarnessCase : SelfMoveHarnessCases) {
    for (const auto &[FlagLhs, FlagRhs] : FlagSeeds) {
      for (uint64_t Value : EdgeValues) {
        const auto Original = HarnessCase.Original(Value, FlagLhs, FlagRhs);
        const auto Rewritten = HarnessCase.Rewritten(Value, FlagLhs, FlagRhs);
        EXPECT_EQ(Original.Value & HarnessCase.ValueMask,
                  Rewritten.Value & HarnessCase.ValueMask)
            << "case=" << HarnessCase.Name << " value=" << Value
            << " flag_lhs=" << FlagLhs << " flag_rhs=" << FlagRhs;
        EXPECT_EQ(Original.Flags, Rewritten.Flags)
            << "case=" << HarnessCase.Name << " value=" << Value
            << " flag_lhs=" << FlagLhs << " flag_rhs=" << FlagRhs;
      }
    }

    for (int Iter = 0; Iter < 4000; ++Iter) {
      const uint64_t Value = Rng();
      const uint64_t FlagLhs = Rng();
      const uint64_t FlagRhs = Rng();
      const auto Original = HarnessCase.Original(Value, FlagLhs, FlagRhs);
      const auto Rewritten = HarnessCase.Rewritten(Value, FlagLhs, FlagRhs);
      EXPECT_EQ(Original.Value & HarnessCase.ValueMask,
                Rewritten.Value & HarnessCase.ValueMask)
          << "case=" << HarnessCase.Name << " value=" << Value
          << " flag_lhs=" << FlagLhs << " flag_rhs=" << FlagRhs;
      EXPECT_EQ(Original.Flags, Rewritten.Flags)
          << "case=" << HarnessCase.Name << " value=" << Value
          << " flag_lhs=" << FlagLhs << " flag_rhs=" << FlagRhs;
    }
  }
#endif
}

TEST(X86CgPeephole, ExecutionHarnessSelfMove32ChangesUpperBits) {
#if !defined(__x86_64__) || !(defined(__GNUC__) || defined(__clang__))
  GTEST_SKIP() << "execution harness requires x86_64 GNU-style inline asm";
#else
  const std::array<uint64_t, 6> Values = {
      0xffffffff00000000ULL, 0xffffffff00000001ULL, 0xaaaaaaaa55555555ULL,
      0x8000000000000001ULL, 0x7fffffff00000000ULL, 0x1234567800000000ULL,
  };
  const std::array<std::pair<uint64_t, uint64_t>, 4> FlagSeeds = {
      std::pair<uint64_t, uint64_t>{0ULL, 0ULL},
      std::pair<uint64_t, uint64_t>{0ULL, 1ULL},
      std::pair<uint64_t, uint64_t>{1ULL, 0ULL},
      std::pair<uint64_t, uint64_t>{0x8000000000000000ULL, 1ULL},
  };

  for (const auto &[FlagLhs, FlagRhs] : FlagSeeds) {
    for (uint64_t Value : Values) {
      const auto Original = execOriginalSelfMove32(Value, FlagLhs, FlagRhs);
      const auto Rewritten = execRewrittenSelfMove32(Value, FlagLhs, FlagRhs);
      EXPECT_NE(Original.Value, Rewritten.Value)
          << "value=" << Value << " flag_lhs=" << FlagLhs
          << " flag_rhs=" << FlagRhs;
      EXPECT_EQ(Original.Value, Value & 0xffffffffULL)
          << "value=" << Value << " flag_lhs=" << FlagLhs
          << " flag_rhs=" << FlagRhs;
      EXPECT_EQ(Rewritten.Value, Value)
          << "value=" << Value << " flag_lhs=" << FlagLhs
          << " flag_rhs=" << FlagRhs;
      EXPECT_EQ(Original.Flags, Rewritten.Flags)
          << "value=" << Value << " flag_lhs=" << FlagLhs
          << " flag_rhs=" << FlagRhs;
    }
  }
#endif
}

TEST(X86CgPeephole, ExecutionHarnessRemoveFallthroughConditionalJump) {
#if !defined(__x86_64__) || !(defined(__GNUC__) || defined(__clang__))
  GTEST_SKIP() << "execution harness requires x86_64 GNU-style inline asm";
#else
  const std::array<uint64_t, 12> EdgeValues = {
      0ULL,
      1ULL,
      2ULL,
      0x7fffffffffffffffULL,
      0x8000000000000000ULL,
      0x8000000000000001ULL,
      0xffffffffffffffffULL,
      0xfffffffffffffffeULL,
      0xaaaaaaaaaaaaaaaaULL,
      0x5555555555555555ULL,
      0x00000000ffffffffULL,
      0xffffffff00000000ULL,
  };
  const std::array<std::pair<uint64_t, uint64_t>, 6> FlagSeeds = {
      std::pair<uint64_t, uint64_t>{0ULL, 0ULL},
      std::pair<uint64_t, uint64_t>{0ULL, 1ULL},
      std::pair<uint64_t, uint64_t>{1ULL, 0ULL},
      std::pair<uint64_t, uint64_t>{0x8000000000000000ULL, 1ULL},
      std::pair<uint64_t, uint64_t>{0x7fffffffffffffffULL,
                                    0xffffffffffffffffULL},
      std::pair<uint64_t, uint64_t>{0xaaaaaaaaaaaaaaaaULL,
                                    0x5555555555555555ULL},
  };
  std::mt19937_64 Rng(0xF4112026ULL);

  for (const auto &HarnessCase : FallthroughJccHarnessCases) {
    for (const auto &[FlagLhs, FlagRhs] : FlagSeeds) {
      for (uint64_t Value : EdgeValues) {
        const auto Original = HarnessCase.Original(Value, FlagLhs, FlagRhs);
        const auto Rewritten = HarnessCase.Rewritten(Value, FlagLhs, FlagRhs);
        EXPECT_EQ(Original.Value, Rewritten.Value)
            << "case=" << HarnessCase.Name << " value=" << Value
            << " flag_lhs=" << FlagLhs << " flag_rhs=" << FlagRhs;
        EXPECT_EQ(Original.Flags, Rewritten.Flags)
            << "case=" << HarnessCase.Name << " value=" << Value
            << " flag_lhs=" << FlagLhs << " flag_rhs=" << FlagRhs;
      }
    }

    for (int Iter = 0; Iter < 4000; ++Iter) {
      const uint64_t Value = Rng();
      const uint64_t FlagLhs = Rng();
      const uint64_t FlagRhs = Rng();
      const auto Original = HarnessCase.Original(Value, FlagLhs, FlagRhs);
      const auto Rewritten = HarnessCase.Rewritten(Value, FlagLhs, FlagRhs);
      EXPECT_EQ(Original.Value, Rewritten.Value)
          << "case=" << HarnessCase.Name << " value=" << Value
          << " flag_lhs=" << FlagLhs << " flag_rhs=" << FlagRhs;
      EXPECT_EQ(Original.Flags, Rewritten.Flags)
          << "case=" << HarnessCase.Name << " value=" << Value
          << " flag_lhs=" << FlagLhs << " flag_rhs=" << FlagRhs;
    }
  }
#endif
}

TEST(X86CgPeephole, ExecutionHarnessRemoveFallthroughJump) {
#if !defined(__x86_64__) || !(defined(__GNUC__) || defined(__clang__))
  GTEST_SKIP() << "execution harness requires x86_64 GNU-style inline asm";
#else
  const std::array<uint64_t, 12> EdgeValues = {
      0ULL,
      1ULL,
      2ULL,
      0x7fffffffffffffffULL,
      0x8000000000000000ULL,
      0x8000000000000001ULL,
      0xffffffffffffffffULL,
      0xfffffffffffffffeULL,
      0xaaaaaaaaaaaaaaaaULL,
      0x5555555555555555ULL,
      0x00000000ffffffffULL,
      0xffffffff00000000ULL,
  };
  const std::array<std::pair<uint64_t, uint64_t>, 6> FlagSeeds = {
      std::pair<uint64_t, uint64_t>{0ULL, 0ULL},
      std::pair<uint64_t, uint64_t>{0ULL, 1ULL},
      std::pair<uint64_t, uint64_t>{1ULL, 0ULL},
      std::pair<uint64_t, uint64_t>{0x8000000000000000ULL, 1ULL},
      std::pair<uint64_t, uint64_t>{0x7fffffffffffffffULL,
                                    0xffffffffffffffffULL},
      std::pair<uint64_t, uint64_t>{0xaaaaaaaaaaaaaaaaULL,
                                    0x5555555555555555ULL},
  };
  std::mt19937_64 Rng(0xF4122026ULL);

  for (const auto &[FlagLhs, FlagRhs] : FlagSeeds) {
    for (uint64_t Value : EdgeValues) {
      const auto Original =
          execOriginalFallthroughJump(Value, FlagLhs, FlagRhs);
      const auto Rewritten =
          execRewrittenFallthroughJump(Value, FlagLhs, FlagRhs);
      EXPECT_EQ(Original.Value, Rewritten.Value)
          << "value=" << Value << " flag_lhs=" << FlagLhs
          << " flag_rhs=" << FlagRhs;
      EXPECT_EQ(Original.Flags, Rewritten.Flags)
          << "value=" << Value << " flag_lhs=" << FlagLhs
          << " flag_rhs=" << FlagRhs;
    }
  }

  for (int Iter = 0; Iter < 4000; ++Iter) {
    const uint64_t Value = Rng();
    const uint64_t FlagLhs = Rng();
    const uint64_t FlagRhs = Rng();
    const auto Original = execOriginalFallthroughJump(Value, FlagLhs, FlagRhs);
    const auto Rewritten =
        execRewrittenFallthroughJump(Value, FlagLhs, FlagRhs);
    EXPECT_EQ(Original.Value, Rewritten.Value)
        << "value=" << Value << " flag_lhs=" << FlagLhs
        << " flag_rhs=" << FlagRhs;
    EXPECT_EQ(Original.Flags, Rewritten.Flags)
        << "value=" << Value << " flag_lhs=" << FlagLhs
        << " flag_rhs=" << FlagRhs;
  }
#endif
}

TEST(X86CgPeephole, RemovesFallthroughConditionalJump) {
  CompileContext Context;
  Context.initialize();

  MModule Mod(Context);
  MFunctionType *FuncType = createVoidFunctionType(Context);
  Mod.addFuncType(FuncType);

  MFunction MirFunc(Context, 0);
  MirFunc.setFunctionType(FuncType);
  CgFunction MF(Context, MirFunc);

  CgBasicBlock *BB0 = MF.createCgBasicBlock();
  CgBasicBlock *BB1 = MF.createCgBasicBlock();
  MF.appendCgBasicBlock(BB0);
  MF.appendCgBasicBlock(BB1);

  const auto &TII = MF.getTargetInstrInfo();
  std::array<CgOperand, 2> JccOps = {
      CgOperand::createMBB(BB1),
      CgOperand::createImmOperand(X86::COND_NE),
  };
  MF.createCgInstruction(*BB0, TII.get(X86::JCC_1), JccOps);

  X86CgPeephole Peephole(MF);

  EXPECT_TRUE(BB0->empty());
}

TEST(X86CgPeephole, RemovesFallthroughJump) {
  CompileContext Context;
  Context.initialize();

  MModule Mod(Context);
  MFunctionType *FuncType = createVoidFunctionType(Context);
  Mod.addFuncType(FuncType);

  MFunction MirFunc(Context, 0);
  MirFunc.setFunctionType(FuncType);
  CgFunction MF(Context, MirFunc);

  CgBasicBlock *BB0 = MF.createCgBasicBlock();
  CgBasicBlock *BB1 = MF.createCgBasicBlock();
  MF.appendCgBasicBlock(BB0);
  MF.appendCgBasicBlock(BB1);

  const auto &TII = MF.getTargetInstrInfo();
  std::array<CgOperand, 1> JmpOps = {CgOperand::createMBB(BB1)};
  MF.createCgInstruction(*BB0, TII.get(X86::JMP_1), JmpOps);

  X86CgPeephole Peephole(MF);

  EXPECT_TRUE(BB0->empty());
}

TEST(X86CgPeephole, RemovesRedundantTest64rr) {
  CompileContext Context;
  Context.initialize();

  MModule Mod(Context);
  MFunctionType *FuncType = createVoidFunctionType(Context);
  Mod.addFuncType(FuncType);

  MFunction MirFunc(Context, 0);
  MirFunc.setFunctionType(FuncType);
  CgFunction MF(Context, MirFunc);

  CgBasicBlock *BB = MF.createCgBasicBlock();
  MF.appendCgBasicBlock(BB);

  const auto &TII = MF.getTargetInstrInfo();
  std::array<CgOperand, 2> TestOps1 = {
      CgOperand::createRegOperand(X86::RAX, false),
      CgOperand::createRegOperand(X86::RAX, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::TEST64rr), TestOps1);
  std::array<CgOperand, 2> TestOps2 = {
      CgOperand::createRegOperand(X86::RAX, false),
      CgOperand::createRegOperand(X86::RAX, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::TEST64rr), TestOps2);

  X86CgPeephole Peephole(MF);

  ASSERT_EQ(std::distance(BB->begin(), BB->end()), 1);
  EXPECT_EQ(BB->begin()->getOpcode(), X86::TEST64rr);
}

TEST(X86CgPeephole, KeepsNonRedundantTest64rr) {
  CompileContext Context;
  Context.initialize();

  MModule Mod(Context);
  MFunctionType *FuncType = createVoidFunctionType(Context);
  Mod.addFuncType(FuncType);

  MFunction MirFunc(Context, 0);
  MirFunc.setFunctionType(FuncType);
  CgFunction MF(Context, MirFunc);

  CgBasicBlock *BB = MF.createCgBasicBlock();
  MF.appendCgBasicBlock(BB);

  const auto &TII = MF.getTargetInstrInfo();
  std::array<CgOperand, 2> TestOps1 = {
      CgOperand::createRegOperand(X86::RAX, false),
      CgOperand::createRegOperand(X86::RAX, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::TEST64rr), TestOps1);
  std::array<CgOperand, 2> TestOps2 = {
      CgOperand::createRegOperand(X86::RBX, false),
      CgOperand::createRegOperand(X86::RBX, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::TEST64rr), TestOps2);

  X86CgPeephole Peephole(MF);

  EXPECT_EQ(std::distance(BB->begin(), BB->end()), 2);
}

TEST(X86CgPeephole, RemovesRedundantTest32rr) {
  CompileContext Context;
  Context.initialize();

  MModule Mod(Context);
  MFunctionType *FuncType = createVoidFunctionType(Context);
  Mod.addFuncType(FuncType);

  MFunction MirFunc(Context, 0);
  MirFunc.setFunctionType(FuncType);
  CgFunction MF(Context, MirFunc);

  CgBasicBlock *BB = MF.createCgBasicBlock();
  MF.appendCgBasicBlock(BB);

  const auto &TII = MF.getTargetInstrInfo();
  std::array<CgOperand, 2> TestOps1 = {
      CgOperand::createRegOperand(X86::EAX, false),
      CgOperand::createRegOperand(X86::EAX, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::TEST32rr), TestOps1);
  std::array<CgOperand, 2> TestOps2 = {
      CgOperand::createRegOperand(X86::EAX, false),
      CgOperand::createRegOperand(X86::EAX, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::TEST32rr), TestOps2);

  X86CgPeephole Peephole(MF);

  ASSERT_EQ(std::distance(BB->begin(), BB->end()), 1);
  EXPECT_EQ(BB->begin()->getOpcode(), X86::TEST32rr);
}

TEST(X86CgPeephole, KeepsNonRedundantTest32rr) {
  CompileContext Context;
  Context.initialize();

  MModule Mod(Context);
  MFunctionType *FuncType = createVoidFunctionType(Context);
  Mod.addFuncType(FuncType);

  MFunction MirFunc(Context, 0);
  MirFunc.setFunctionType(FuncType);
  CgFunction MF(Context, MirFunc);

  CgBasicBlock *BB = MF.createCgBasicBlock();
  MF.appendCgBasicBlock(BB);

  const auto &TII = MF.getTargetInstrInfo();
  std::array<CgOperand, 2> TestOps1 = {
      CgOperand::createRegOperand(X86::EAX, false),
      CgOperand::createRegOperand(X86::EAX, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::TEST32rr), TestOps1);
  std::array<CgOperand, 2> TestOps2 = {
      CgOperand::createRegOperand(X86::ECX, false),
      CgOperand::createRegOperand(X86::ECX, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::TEST32rr), TestOps2);

  X86CgPeephole Peephole(MF);

  EXPECT_EQ(std::distance(BB->begin(), BB->end()), 2);
}

TEST(X86CgPeephole, RemovesRedundantTest8rr) {
  CompileContext Context;
  Context.initialize();

  MModule Mod(Context);
  MFunctionType *FuncType = createVoidFunctionType(Context);
  Mod.addFuncType(FuncType);

  MFunction MirFunc(Context, 0);
  MirFunc.setFunctionType(FuncType);
  CgFunction MF(Context, MirFunc);

  CgBasicBlock *BB = MF.createCgBasicBlock();
  MF.appendCgBasicBlock(BB);

  const auto &TII = MF.getTargetInstrInfo();
  std::array<CgOperand, 2> TestOps1 = {
      CgOperand::createRegOperand(X86::AL, false),
      CgOperand::createRegOperand(X86::AL, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::TEST8rr), TestOps1);
  std::array<CgOperand, 2> TestOps2 = {
      CgOperand::createRegOperand(X86::AL, false),
      CgOperand::createRegOperand(X86::AL, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::TEST8rr), TestOps2);

  X86CgPeephole Peephole(MF);

  ASSERT_EQ(std::distance(BB->begin(), BB->end()), 1);
  EXPECT_EQ(BB->begin()->getOpcode(), X86::TEST8rr);
}

TEST(X86CgPeephole, KeepsNonRedundantTest8rr) {
  CompileContext Context;
  Context.initialize();

  MModule Mod(Context);
  MFunctionType *FuncType = createVoidFunctionType(Context);
  Mod.addFuncType(FuncType);

  MFunction MirFunc(Context, 0);
  MirFunc.setFunctionType(FuncType);
  CgFunction MF(Context, MirFunc);

  CgBasicBlock *BB = MF.createCgBasicBlock();
  MF.appendCgBasicBlock(BB);

  const auto &TII = MF.getTargetInstrInfo();
  std::array<CgOperand, 2> TestOps1 = {
      CgOperand::createRegOperand(X86::AL, false),
      CgOperand::createRegOperand(X86::AL, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::TEST8rr), TestOps1);
  std::array<CgOperand, 2> TestOps2 = {
      CgOperand::createRegOperand(X86::BL, false),
      CgOperand::createRegOperand(X86::BL, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::TEST8rr), TestOps2);

  X86CgPeephole Peephole(MF);

  EXPECT_EQ(std::distance(BB->begin(), BB->end()), 2);
}

TEST(X86CgPeephole, RemovesRedundantCmp64rr) {
  CompileContext Context;
  Context.initialize();

  MModule Mod(Context);
  MFunctionType *FuncType = createVoidFunctionType(Context);
  Mod.addFuncType(FuncType);

  MFunction MirFunc(Context, 0);
  MirFunc.setFunctionType(FuncType);
  CgFunction MF(Context, MirFunc);

  CgBasicBlock *BB = MF.createCgBasicBlock();
  MF.appendCgBasicBlock(BB);

  const auto &TII = MF.getTargetInstrInfo();
  std::array<CgOperand, 2> CmpOps1 = {
      CgOperand::createRegOperand(X86::RAX, false),
      CgOperand::createRegOperand(X86::RAX, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::CMP64rr), CmpOps1);
  std::array<CgOperand, 2> CmpOps2 = {
      CgOperand::createRegOperand(X86::RAX, false),
      CgOperand::createRegOperand(X86::RAX, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::CMP64rr), CmpOps2);

  X86CgPeephole Peephole(MF);

  ASSERT_EQ(std::distance(BB->begin(), BB->end()), 1);
  EXPECT_EQ(BB->begin()->getOpcode(), X86::CMP64rr);
}

TEST(X86CgPeephole, KeepsNonRedundantCmp64rr) {
  CompileContext Context;
  Context.initialize();

  MModule Mod(Context);
  MFunctionType *FuncType = createVoidFunctionType(Context);
  Mod.addFuncType(FuncType);

  MFunction MirFunc(Context, 0);
  MirFunc.setFunctionType(FuncType);
  CgFunction MF(Context, MirFunc);

  CgBasicBlock *BB = MF.createCgBasicBlock();
  MF.appendCgBasicBlock(BB);

  const auto &TII = MF.getTargetInstrInfo();
  std::array<CgOperand, 2> CmpOps1 = {
      CgOperand::createRegOperand(X86::RAX, false),
      CgOperand::createRegOperand(X86::RAX, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::CMP64rr), CmpOps1);
  std::array<CgOperand, 2> CmpOps2 = {
      CgOperand::createRegOperand(X86::RBX, false),
      CgOperand::createRegOperand(X86::RAX, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::CMP64rr), CmpOps2);

  X86CgPeephole Peephole(MF);

  EXPECT_EQ(std::distance(BB->begin(), BB->end()), 2);
}

TEST(X86CgPeephole, RemovesRedundantCmp32rr) {
  CompileContext Context;
  Context.initialize();

  MModule Mod(Context);
  MFunctionType *FuncType = createVoidFunctionType(Context);
  Mod.addFuncType(FuncType);

  MFunction MirFunc(Context, 0);
  MirFunc.setFunctionType(FuncType);
  CgFunction MF(Context, MirFunc);

  CgBasicBlock *BB = MF.createCgBasicBlock();
  MF.appendCgBasicBlock(BB);

  const auto &TII = MF.getTargetInstrInfo();
  std::array<CgOperand, 2> CmpOps1 = {
      CgOperand::createRegOperand(X86::EAX, false),
      CgOperand::createRegOperand(X86::EAX, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::CMP32rr), CmpOps1);
  std::array<CgOperand, 2> CmpOps2 = {
      CgOperand::createRegOperand(X86::EAX, false),
      CgOperand::createRegOperand(X86::EAX, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::CMP32rr), CmpOps2);

  X86CgPeephole Peephole(MF);

  ASSERT_EQ(std::distance(BB->begin(), BB->end()), 1);
  EXPECT_EQ(BB->begin()->getOpcode(), X86::CMP32rr);
}

TEST(X86CgPeephole, KeepsNonRedundantCmp32rr) {
  CompileContext Context;
  Context.initialize();

  MModule Mod(Context);
  MFunctionType *FuncType = createVoidFunctionType(Context);
  Mod.addFuncType(FuncType);

  MFunction MirFunc(Context, 0);
  MirFunc.setFunctionType(FuncType);
  CgFunction MF(Context, MirFunc);

  CgBasicBlock *BB = MF.createCgBasicBlock();
  MF.appendCgBasicBlock(BB);

  const auto &TII = MF.getTargetInstrInfo();
  std::array<CgOperand, 2> CmpOps1 = {
      CgOperand::createRegOperand(X86::EAX, false),
      CgOperand::createRegOperand(X86::EAX, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::CMP32rr), CmpOps1);
  std::array<CgOperand, 2> CmpOps2 = {
      CgOperand::createRegOperand(X86::EBX, false),
      CgOperand::createRegOperand(X86::EAX, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::CMP32rr), CmpOps2);

  X86CgPeephole Peephole(MF);

  EXPECT_EQ(std::distance(BB->begin(), BB->end()), 2);
}

TEST(X86CgPeephole, RemovesRedundantCmp8rr) {
  CompileContext Context;
  Context.initialize();

  MModule Mod(Context);
  MFunctionType *FuncType = createVoidFunctionType(Context);
  Mod.addFuncType(FuncType);

  MFunction MirFunc(Context, 0);
  MirFunc.setFunctionType(FuncType);
  CgFunction MF(Context, MirFunc);

  CgBasicBlock *BB = MF.createCgBasicBlock();
  MF.appendCgBasicBlock(BB);

  const auto &TII = MF.getTargetInstrInfo();
  std::array<CgOperand, 2> CmpOps1 = {
      CgOperand::createRegOperand(X86::AL, false),
      CgOperand::createRegOperand(X86::AL, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::CMP8rr), CmpOps1);
  std::array<CgOperand, 2> CmpOps2 = {
      CgOperand::createRegOperand(X86::AL, false),
      CgOperand::createRegOperand(X86::AL, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::CMP8rr), CmpOps2);

  X86CgPeephole Peephole(MF);

  ASSERT_EQ(std::distance(BB->begin(), BB->end()), 1);
  EXPECT_EQ(BB->begin()->getOpcode(), X86::CMP8rr);
}

TEST(X86CgPeephole, KeepsNonRedundantCmp8rr) {
  CompileContext Context;
  Context.initialize();

  MModule Mod(Context);
  MFunctionType *FuncType = createVoidFunctionType(Context);
  Mod.addFuncType(FuncType);

  MFunction MirFunc(Context, 0);
  MirFunc.setFunctionType(FuncType);
  CgFunction MF(Context, MirFunc);

  CgBasicBlock *BB = MF.createCgBasicBlock();
  MF.appendCgBasicBlock(BB);

  const auto &TII = MF.getTargetInstrInfo();
  std::array<CgOperand, 2> CmpOps1 = {
      CgOperand::createRegOperand(X86::AL, false),
      CgOperand::createRegOperand(X86::AL, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::CMP8rr), CmpOps1);
  std::array<CgOperand, 2> CmpOps2 = {
      CgOperand::createRegOperand(X86::BL, false),
      CgOperand::createRegOperand(X86::AL, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::CMP8rr), CmpOps2);

  X86CgPeephole Peephole(MF);

  EXPECT_EQ(std::distance(BB->begin(), BB->end()), 2);
}

TEST(X86CgPeephole, RemovesRedundantCmp16rr) {
  CompileContext Context;
  Context.initialize();

  MModule Mod(Context);
  MFunctionType *FuncType = createVoidFunctionType(Context);
  Mod.addFuncType(FuncType);

  MFunction MirFunc(Context, 0);
  MirFunc.setFunctionType(FuncType);
  CgFunction MF(Context, MirFunc);

  CgBasicBlock *BB = MF.createCgBasicBlock();
  MF.appendCgBasicBlock(BB);

  const auto &TII = MF.getTargetInstrInfo();
  std::array<CgOperand, 2> CmpOps1 = {
      CgOperand::createRegOperand(X86::AX, false),
      CgOperand::createRegOperand(X86::AX, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::CMP16rr), CmpOps1);
  std::array<CgOperand, 2> CmpOps2 = {
      CgOperand::createRegOperand(X86::AX, false),
      CgOperand::createRegOperand(X86::AX, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::CMP16rr), CmpOps2);

  X86CgPeephole Peephole(MF);

  ASSERT_EQ(std::distance(BB->begin(), BB->end()), 1);
  EXPECT_EQ(BB->begin()->getOpcode(), X86::CMP16rr);
}

TEST(X86CgPeephole, KeepsNonRedundantCmp16rr) {
  CompileContext Context;
  Context.initialize();

  MModule Mod(Context);
  MFunctionType *FuncType = createVoidFunctionType(Context);
  Mod.addFuncType(FuncType);

  MFunction MirFunc(Context, 0);
  MirFunc.setFunctionType(FuncType);
  CgFunction MF(Context, MirFunc);

  CgBasicBlock *BB = MF.createCgBasicBlock();
  MF.appendCgBasicBlock(BB);

  const auto &TII = MF.getTargetInstrInfo();
  std::array<CgOperand, 2> CmpOps1 = {
      CgOperand::createRegOperand(X86::AX, false),
      CgOperand::createRegOperand(X86::AX, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::CMP16rr), CmpOps1);
  std::array<CgOperand, 2> CmpOps2 = {
      CgOperand::createRegOperand(X86::BX, false),
      CgOperand::createRegOperand(X86::AX, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::CMP16rr), CmpOps2);

  X86CgPeephole Peephole(MF);

  EXPECT_EQ(std::distance(BB->begin(), BB->end()), 2);
}

TEST(X86CgPeephole, RemovesRedundantTest16rr) {
  CompileContext Context;
  Context.initialize();

  MModule Mod(Context);
  MFunctionType *FuncType = createVoidFunctionType(Context);
  Mod.addFuncType(FuncType);

  MFunction MirFunc(Context, 0);
  MirFunc.setFunctionType(FuncType);
  CgFunction MF(Context, MirFunc);

  CgBasicBlock *BB = MF.createCgBasicBlock();
  MF.appendCgBasicBlock(BB);

  const auto &TII = MF.getTargetInstrInfo();
  std::array<CgOperand, 2> TestOps1 = {
      CgOperand::createRegOperand(X86::AX, false),
      CgOperand::createRegOperand(X86::AX, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::TEST16rr), TestOps1);
  std::array<CgOperand, 2> TestOps2 = {
      CgOperand::createRegOperand(X86::AX, false),
      CgOperand::createRegOperand(X86::AX, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::TEST16rr), TestOps2);

  X86CgPeephole Peephole(MF);

  ASSERT_EQ(std::distance(BB->begin(), BB->end()), 1);
  EXPECT_EQ(BB->begin()->getOpcode(), X86::TEST16rr);
}

TEST(X86CgPeephole, KeepsNonRedundantTest16rr) {
  CompileContext Context;
  Context.initialize();

  MModule Mod(Context);
  MFunctionType *FuncType = createVoidFunctionType(Context);
  Mod.addFuncType(FuncType);

  MFunction MirFunc(Context, 0);
  MirFunc.setFunctionType(FuncType);
  CgFunction MF(Context, MirFunc);

  CgBasicBlock *BB = MF.createCgBasicBlock();
  MF.appendCgBasicBlock(BB);

  const auto &TII = MF.getTargetInstrInfo();
  std::array<CgOperand, 2> TestOps1 = {
      CgOperand::createRegOperand(X86::AX, false),
      CgOperand::createRegOperand(X86::AX, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::TEST16rr), TestOps1);
  std::array<CgOperand, 2> TestOps2 = {
      CgOperand::createRegOperand(X86::BX, false),
      CgOperand::createRegOperand(X86::BX, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::TEST16rr), TestOps2);

  X86CgPeephole Peephole(MF);

  EXPECT_EQ(std::distance(BB->begin(), BB->end()), 2);
}

TEST(X86CgPeephole, ExecutionHarnessRemoveRedundantTest64rr) {
#if !defined(__x86_64__) || !(defined(__GNUC__) || defined(__clang__))
  GTEST_SKIP() << "execution harness requires x86_64 GNU-style inline asm";
#else
  const std::array<uint64_t, 8> EdgeValues = {
      0ULL,
      1ULL,
      0x7fffffffffffffffULL,
      0x8000000000000000ULL,
      0xffffffffffffffffULL,
      0xaaaaaaaaaaaaaaaaULL,
      0x5555555555555555ULL,
      0x00000000ffffffffULL,
  };
  const std::array<std::pair<uint64_t, uint64_t>, 4> FlagSeeds = {
      std::pair<uint64_t, uint64_t>{0ULL, 0ULL},
      std::pair<uint64_t, uint64_t>{0ULL, 1ULL},
      std::pair<uint64_t, uint64_t>{1ULL, 0ULL},
      std::pair<uint64_t, uint64_t>{0x8000000000000000ULL, 1ULL},
  };
  std::mt19937_64 Rng(0xBB112026ULL);

  for (const auto &[FlagLhs, FlagRhs] : FlagSeeds) {
    for (uint64_t Value : EdgeValues) {
      const auto Original =
          execOriginalRedundantTest64(Value, FlagLhs, FlagRhs);
      const auto Rewritten =
          execRewrittenRedundantTest64(Value, FlagLhs, FlagRhs);
      EXPECT_EQ(Original.Value, Rewritten.Value)
          << "value=" << Value << " flag_lhs=" << FlagLhs
          << " flag_rhs=" << FlagRhs;
      EXPECT_EQ(Original.Flags, Rewritten.Flags)
          << "value=" << Value << " flag_lhs=" << FlagLhs
          << " flag_rhs=" << FlagRhs;
    }
  }
  for (int Iter = 0; Iter < 4000; ++Iter) {
    const uint64_t Value = Rng();
    const uint64_t FlagLhs = Rng();
    const uint64_t FlagRhs = Rng();
    const auto Original = execOriginalRedundantTest64(Value, FlagLhs, FlagRhs);
    const auto Rewritten =
        execRewrittenRedundantTest64(Value, FlagLhs, FlagRhs);
    EXPECT_EQ(Original.Value, Rewritten.Value)
        << "value=" << Value << " flag_lhs=" << FlagLhs
        << " flag_rhs=" << FlagRhs;
    EXPECT_EQ(Original.Flags, Rewritten.Flags)
        << "value=" << Value << " flag_lhs=" << FlagLhs
        << " flag_rhs=" << FlagRhs;
  }
#endif
}

TEST(X86CgPeephole, ExecutionHarnessRemoveRedundantTest32rr) {
#if !defined(__x86_64__) || !(defined(__GNUC__) || defined(__clang__))
  GTEST_SKIP() << "execution harness requires x86_64 GNU-style inline asm";
#else
  const std::array<uint32_t, 8> EdgeValues = {
      0UL,          1UL,          0x7fffffffUL, 0x80000000UL,
      0xffffffffUL, 0xaaaaaaaaUL, 0x55555555UL, 0x0000ffffUL,
  };
  const std::array<std::pair<uint64_t, uint64_t>, 4> FlagSeeds = {
      std::pair<uint64_t, uint64_t>{0ULL, 0ULL},
      std::pair<uint64_t, uint64_t>{0ULL, 1ULL},
      std::pair<uint64_t, uint64_t>{1ULL, 0ULL},
      std::pair<uint64_t, uint64_t>{0x8000000000000000ULL, 1ULL},
  };
  std::mt19937_64 Rng(0xCC122026ULL);

  for (const auto &[FlagLhs, FlagRhs] : FlagSeeds) {
    for (uint32_t Value : EdgeValues) {
      const auto Original =
          execOriginalRedundantTest32(Value, FlagLhs, FlagRhs);
      const auto Rewritten =
          execRewrittenRedundantTest32(Value, FlagLhs, FlagRhs);
      EXPECT_EQ(Original.Value, Rewritten.Value)
          << "value=" << Value << " flag_lhs=" << FlagLhs
          << " flag_rhs=" << FlagRhs;
      EXPECT_EQ(Original.Flags, Rewritten.Flags)
          << "value=" << Value << " flag_lhs=" << FlagLhs
          << " flag_rhs=" << FlagRhs;
    }
  }
  for (int Iter = 0; Iter < 4000; ++Iter) {
    const uint32_t Value = static_cast<uint32_t>(Rng());
    const uint64_t FlagLhs = Rng();
    const uint64_t FlagRhs = Rng();
    const auto Original = execOriginalRedundantTest32(Value, FlagLhs, FlagRhs);
    const auto Rewritten =
        execRewrittenRedundantTest32(Value, FlagLhs, FlagRhs);
    EXPECT_EQ(Original.Value, Rewritten.Value)
        << "value=" << Value << " flag_lhs=" << FlagLhs
        << " flag_rhs=" << FlagRhs;
    EXPECT_EQ(Original.Flags, Rewritten.Flags)
        << "value=" << Value << " flag_lhs=" << FlagLhs
        << " flag_rhs=" << FlagRhs;
  }
#endif
}

TEST(X86CgPeephole, ExecutionHarnessRemoveRedundantTestrr) {
#if !defined(__x86_64__) || !(defined(__GNUC__) || defined(__clang__))
  GTEST_SKIP() << "execution harness requires x86_64 GNU-style inline asm";
#else
  const std::array<uint8_t, 6> EdgeValues = {
      0, 1, 0x7f, 0x80, 0xff, 0xaa,
  };
  const std::array<std::pair<uint64_t, uint64_t>, 4> FlagSeeds = {
      std::pair<uint64_t, uint64_t>{0ULL, 0ULL},
      std::pair<uint64_t, uint64_t>{0ULL, 1ULL},
      std::pair<uint64_t, uint64_t>{1ULL, 0ULL},
      std::pair<uint64_t, uint64_t>{0x8000000000000000ULL, 1ULL},
  };
  std::mt19937_64 Rng(0xDD132026ULL);

  for (const auto &[FlagLhs, FlagRhs] : FlagSeeds) {
    for (uint8_t Value : EdgeValues) {
      const auto Original = execOriginalRedundantTest8(Value, FlagLhs, FlagRhs);
      const auto Rewritten =
          execRewrittenRedundantTest8(Value, FlagLhs, FlagRhs);
      EXPECT_EQ(Original.Value, Rewritten.Value)
          << "value=" << static_cast<int>(Value) << " flag_lhs=" << FlagLhs
          << " flag_rhs=" << FlagRhs;
      EXPECT_EQ(Original.Flags, Rewritten.Flags)
          << "value=" << static_cast<int>(Value) << " flag_lhs=" << FlagLhs
          << " flag_rhs=" << FlagRhs;
    }
  }
  for (int Iter = 0; Iter < 4000; ++Iter) {
    const uint8_t Value = static_cast<uint8_t>(Rng());
    const uint64_t FlagLhs = Rng();
    const uint64_t FlagRhs = Rng();
    const auto Original = execOriginalRedundantTest8(Value, FlagLhs, FlagRhs);
    const auto Rewritten = execRewrittenRedundantTest8(Value, FlagLhs, FlagRhs);
    EXPECT_EQ(Original.Value, Rewritten.Value)
        << "value=" << static_cast<int>(Value) << " flag_lhs=" << FlagLhs
        << " flag_rhs=" << FlagRhs;
    EXPECT_EQ(Original.Flags, Rewritten.Flags)
        << "value=" << static_cast<int>(Value) << " flag_lhs=" << FlagLhs
        << " flag_rhs=" << FlagRhs;
  }
#endif
}

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
static uint64_t execOriginalMovzxSubreg(uint64_t Input) {
  uint64_t Out;
  uint8_t In8 = static_cast<uint8_t>(Input);
  asm volatile("movzbl %[in], %%eax\n\t"
               "movq %%rax, %[out]\n\t"
               : [out] "=r"(Out)
               : [in] "q"(In8)
               : "rax");
  return Out;
}

static uint64_t execRewrittenMovzxSubreg(uint64_t Input) {
  uint64_t Out;
  uint8_t In8 = static_cast<uint8_t>(Input);
  asm volatile("movzbq %[in], %%rax\n\t"
               "movq %%rax, %[out]\n\t"
               : [out] "=r"(Out)
               : [in] "q"(In8)
               : "rax");
  return Out;
}
#endif

TEST(X86CgPeephole, FoldsMovzxSubregToReg) {
  CompileContext Context;
  Context.initialize();

  MModule Mod(Context);
  MFunctionType *FuncType = createVoidFunctionType(Context);
  Mod.addFuncType(FuncType);

  MFunction MirFunc(Context, 0);
  MirFunc.setFunctionType(FuncType);
  CgFunction MF(Context, MirFunc);

  CgBasicBlock *BB = MF.createCgBasicBlock();
  MF.appendCgBasicBlock(BB);

  const auto &TII = MF.getTargetInstrInfo();
  std::array<CgOperand, 2> MovzxOps = {
      CgOperand::createRegOperand(X86::EAX, true),
      CgOperand::createRegOperand(X86::AL, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::MOVZX32rr8), MovzxOps);

  std::array<CgOperand, 4> SubregOps = {
      CgOperand::createRegOperand(X86::RAX, true),
      CgOperand::createImmOperand(0),
      CgOperand::createRegOperand(X86::EAX, false),
      CgOperand::createImmOperand(6), // sub_32bit
  };
  MF.createCgInstruction(*BB, TII.get(TargetOpcode::SUBREG_TO_REG), SubregOps);

  X86CgPeephole Peephole(MF);

  ASSERT_EQ(std::distance(BB->begin(), BB->end()), 1);
  auto It = BB->begin();
  EXPECT_EQ(It->getOpcode(), X86::MOVZX64rr8);
  EXPECT_EQ(It->getOperand(0).getReg(), X86::RAX);
}

TEST(X86CgPeephole, KeepsMovzxSubregToRegWhenMismatch) {
  CompileContext Context;
  Context.initialize();

  MModule Mod(Context);
  MFunctionType *FuncType = createVoidFunctionType(Context);
  Mod.addFuncType(FuncType);

  MFunction MirFunc(Context, 0);
  MirFunc.setFunctionType(FuncType);
  CgFunction MF(Context, MirFunc);

  CgBasicBlock *BB = MF.createCgBasicBlock();
  MF.appendCgBasicBlock(BB);

  const auto &TII = MF.getTargetInstrInfo();
  // MOVZX32rr8 defines EAX, but SUBREG_TO_REG uses EBX - mismatch, no fold.
  std::array<CgOperand, 2> MovzxOps = {
      CgOperand::createRegOperand(X86::EAX, true),
      CgOperand::createRegOperand(X86::AL, false),
  };
  MF.createCgInstruction(*BB, TII.get(X86::MOVZX32rr8), MovzxOps);

  std::array<CgOperand, 4> SubregOps = {
      CgOperand::createRegOperand(X86::RBX, true),
      CgOperand::createImmOperand(0),
      CgOperand::createRegOperand(X86::EBX, false),
      CgOperand::createImmOperand(6), // sub_32bit
  };
  MF.createCgInstruction(*BB, TII.get(TargetOpcode::SUBREG_TO_REG), SubregOps);

  X86CgPeephole Peephole(MF);

  EXPECT_EQ(std::distance(BB->begin(), BB->end()), 2);
}

TEST(X86CgPeephole, ExecutionHarnessFoldMovzxSubregToReg) {
#if !defined(__x86_64__) || !(defined(__GNUC__) || defined(__clang__))
  GTEST_SKIP() << "execution harness requires x86_64 GNU-style inline asm";
#else
  const std::array<uint8_t, 6> EdgeValues = {0, 1, 0x7f, 0x80, 0xff, 0xaa};
  std::mt19937_64 Rng(0xEE442026ULL);

  for (uint8_t Value : EdgeValues) {
    EXPECT_EQ(execOriginalMovzxSubreg(Value), execRewrittenMovzxSubreg(Value))
        << "value=" << static_cast<int>(Value);
  }
  for (int Iter = 0; Iter < 16; ++Iter) {
    const uint8_t Value = static_cast<uint8_t>(Rng());
    EXPECT_EQ(execOriginalMovzxSubreg(Value), execRewrittenMovzxSubreg(Value))
        << "value=" << static_cast<int>(Value);
  }
#endif
}

} // namespace
