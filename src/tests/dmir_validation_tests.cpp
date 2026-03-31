// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/context.h"
#include "compiler/mir/constants.h"
#include "compiler/mir/function.h"
#include "compiler/mir/instructions.h"
#include "compiler/mir/pass/dmir_rewrite.h"
#include "compiler/mir/pointer.h"
#include "intx/intx.hpp"

#include <array>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

using namespace COMPILER;
using namespace llvm;

MFunctionType *createVoidFunctionType(CompileContext &Context) {
  return MFunctionType::create(Context, Context.VoidType, {});
}

class DMirTestBuilder {
public:
  DMirTestBuilder() : Func(Context, 0) {
    Context.initialize();
    Func.setFunctionType(createVoidFunctionType(Context));
    BB = Func.createBasicBlock();
    Func.appendBlock(BB);
    I64PtrType = MPointerType::create(Context, Context.I64Type);
  }

  ConstantInstruction *createConstI8(uint64_t Value) {
    return createConst(Context.I8Type, Value);
  }

  ConstantInstruction *createConstI32(uint64_t Value) {
    return createConst(Context.I32Type, Value);
  }

  ConstantInstruction *createConstI64(uint64_t Value) {
    return createConst(Context.I64Type, Value);
  }

  template <class T, typename... Arguments> T *createExpr(Arguments &&...Args) {
    return Func.createInstruction<T>(false, *BB,
                                     std::forward<Arguments>(Args)...);
  }

  template <class T, typename... Arguments> T *createStmt(Arguments &&...Args) {
    return Func.createInstruction<T>(true, *BB,
                                     std::forward<Arguments>(Args)...);
  }

  Variable *createVariable(MType *Type) { return Func.createVariable(Type); }

  MBasicBlock &getBlock() { return *BB; }

  CompileContext Context;
  MFunction Func;
  MPointerType *I64PtrType = nullptr;

private:
  ConstantInstruction *createConst(MType &Type, uint64_t Value) {
    return createExpr<ConstantInstruction>(
        &Type, *MConstantInt::get(Context, Type, Value));
  }

  MBasicBlock *BB = nullptr;
};

class DMirFragmentInterpreter {
public:
  void setVariableValue(VariableIdx VarIdx, const APInt &Value) {
    Variables[VarIdx] = Value;
  }

  APInt evaluate(const MInstruction *Inst) {
    switch (Inst->getOpcode()) {
    case OP_const:
      return evaluateConstant(cast<ConstantInstruction>(Inst));
    case OP_dread:
      return evaluateDread(cast<DreadInstruction>(Inst));
    case OP_not:
      return ~evaluate(Inst->getOperand<0>());
    case OP_clz:
      return createScalarResult(
          *Inst->getType(),
          evaluate(Inst->getOperand<0>()).countLeadingZeros());
    case OP_ctz:
      return createScalarResult(
          *Inst->getType(),
          evaluate(Inst->getOperand<0>()).countTrailingZeros());
    case OP_popcnt:
      return createScalarResult(
          *Inst->getType(), evaluate(Inst->getOperand<0>()).countPopulation());
    case OP_bswap:
      return evaluate(Inst->getOperand<0>()).byteSwap();
    case OP_add:
      return evaluate(Inst->getOperand<0>()) + evaluate(Inst->getOperand<1>());
    case OP_sub:
      return evaluate(Inst->getOperand<0>()) - evaluate(Inst->getOperand<1>());
    case OP_mul:
      return evaluate(Inst->getOperand<0>()) * evaluate(Inst->getOperand<1>());
    case OP_sdiv:
      return evaluateDiv(Inst, true, false);
    case OP_udiv:
      return evaluateDiv(Inst, false, false);
    case OP_srem:
      return evaluateDiv(Inst, true, true);
    case OP_urem:
      return evaluateDiv(Inst, false, true);
    case OP_and:
      return evaluate(Inst->getOperand<0>()) & evaluate(Inst->getOperand<1>());
    case OP_or:
      return evaluate(Inst->getOperand<0>()) | evaluate(Inst->getOperand<1>());
    case OP_xor:
      return evaluate(Inst->getOperand<0>()) ^ evaluate(Inst->getOperand<1>());
    case OP_shl:
      return evaluateShift(Inst, ShiftKind::Left);
    case OP_sshr:
      return evaluateShift(Inst, ShiftKind::ArithmeticRight);
    case OP_ushr:
      return evaluateShift(Inst, ShiftKind::LogicalRight);
    case OP_rotl:
      return evaluateRotate(Inst, true);
    case OP_rotr:
      return evaluateRotate(Inst, false);
    case OP_trunc:
      return evaluate(Inst->getOperand<0>())
          .trunc(getBitWidth(*Inst->getType()));
    case OP_sext:
      return evaluate(Inst->getOperand<0>())
          .sext(getBitWidth(*Inst->getType()));
    case OP_uext:
      return evaluate(Inst->getOperand<0>())
          .zext(getBitWidth(*Inst->getType()));
    case OP_inttoptr:
    case OP_ptrtoint:
    case OP_bitcast:
      return evaluate(Inst->getOperand<0>())
          .zextOrTrunc(getBitWidth(*Inst->getType()));
    case OP_cmp:
      return evaluateCmp(cast<CmpInstruction>(Inst));
    case OP_select:
      return evaluateSelect(cast<SelectInstruction>(Inst));
    case OP_adc:
      return evaluateAdc(cast<AdcInstruction>(Inst));
    case OP_sbb:
      return evaluateSbb(cast<SbbInstruction>(Inst));
    case OP_evm_umul128_lo:
      return createScalarResult(
          *Inst->getType(),
          evaluateUmul128(cast<EvmUmul128Instruction>(Inst)).first);
    case OP_evm_umul128_hi:
      return createScalarResult(
          *Inst->getType(),
          evaluateUmul128Hi(cast<EvmUmul128HiInstruction>(Inst)));
    case OP_evm_udiv128_by64:
      return createScalarResult(
          *Inst->getType(),
          evaluateUdiv128By64(cast<EvmUdiv128By64Instruction>(Inst)).first);
    case OP_evm_urem128_by64:
      return createScalarResult(
          *Inst->getType(),
          evaluateUrem128By64(cast<EvmUrem128By64Instruction>(Inst)));
    default:
      throw std::runtime_error("unsupported dMIR opcode: " +
                               getOpcodeString(Inst->getOpcode()));
    }
  }

  std::optional<APInt> execute(MBasicBlock &BB) {
    for (auto *Inst : BB) {
      switch (Inst->getOpcode()) {
      case OP_dassign: {
        auto *Dassign = cast<DassignInstruction>(Inst);
        Variables[Dassign->getVarIdx()] = evaluate(Dassign->getOperand<0>());
        break;
      }
      case OP_return:
        if (Inst->getType()->isVoid()) {
          return std::nullopt;
        }
        return evaluate(Inst->getOperand<0>());
      default:
        throw std::runtime_error("unsupported dMIR statement: " +
                                 getOpcodeString(Inst->getOpcode()));
      }
    }
    return std::nullopt;
  }

private:
  enum class ShiftKind : uint8_t {
    Left,
    ArithmeticRight,
    LogicalRight,
  };

  static unsigned getBitWidth(const MType &Type) {
    if (Type.isInteger()) {
      return Type.getBitWidth();
    }
    if (Type.isPointer()) {
      return Type.getNumBytes() * 8;
    }
    throw std::runtime_error("unsupported dMIR value type");
  }

  static APInt createScalarResult(const MType &Type, uint64_t Value) {
    return APInt(getBitWidth(Type), Value, Type.isInteger() && Type.isSigned());
  }

  APInt evaluateConstant(const ConstantInstruction *Inst) {
    const auto &Constant = Inst->getConstant();
    if (!Constant.getType().isInteger()) {
      throw std::runtime_error("unsupported non-integer dMIR constant");
    }
    return cast<MConstantInt>(&Constant)->getValue();
  }

  APInt evaluateDread(const DreadInstruction *Inst) {
    auto It = Variables.find(Inst->getVarIdx());
    if (It == Variables.end()) {
      throw std::runtime_error("dMIR variable was read before assignment");
    }
    return It->second;
  }

  APInt evaluateDiv(const MInstruction *Inst, bool Signed, bool Remainder) {
    APInt Lhs = evaluate(Inst->getOperand<0>());
    APInt Rhs = evaluate(Inst->getOperand<1>());
    if (Rhs.isZero()) {
      throw std::runtime_error("division by zero in dMIR fragment");
    }
    if (Signed) {
      return Remainder ? Lhs.srem(Rhs) : Lhs.sdiv(Rhs);
    }
    return Remainder ? Lhs.urem(Rhs) : Lhs.udiv(Rhs);
  }

  APInt evaluateShift(const MInstruction *Inst, ShiftKind Kind) {
    APInt Value = evaluate(Inst->getOperand<0>());
    const unsigned BitWidth = Value.getBitWidth();
    const uint64_t Amount = evaluate(Inst->getOperand<1>()).getLimitedValue();
    if (Amount >= BitWidth) {
      if (Kind == ShiftKind::ArithmeticRight && Value.isNegative()) {
        return APInt::getAllOnes(BitWidth);
      }
      return APInt::getZero(BitWidth);
    }
    switch (Kind) {
    case ShiftKind::Left:
      return Value.shl(Amount);
    case ShiftKind::ArithmeticRight:
      return Value.ashr(Amount);
    case ShiftKind::LogicalRight:
      return Value.lshr(Amount);
    }
    llvm_unreachable("unknown shift kind");
  }

  APInt evaluateRotate(const MInstruction *Inst, bool Left) {
    APInt Value = evaluate(Inst->getOperand<0>());
    const unsigned BitWidth = Value.getBitWidth();
    const uint64_t Amount = evaluate(Inst->getOperand<1>()).getLimitedValue();
    const unsigned EffectiveAmount =
        BitWidth == 0 ? 0 : static_cast<unsigned>(Amount % BitWidth);
    return Left ? Value.rotl(EffectiveAmount) : Value.rotr(EffectiveAmount);
  }

  APInt evaluateCmp(const CmpInstruction *Inst) {
    APInt Lhs = evaluate(Inst->getOperand<0>());
    APInt Rhs = evaluate(Inst->getOperand<1>());
    bool Result = false;
    switch (Inst->getPredicate()) {
    case CmpInstruction::ICMP_EQ:
      Result = Lhs == Rhs;
      break;
    case CmpInstruction::ICMP_NE:
      Result = Lhs != Rhs;
      break;
    case CmpInstruction::ICMP_UGT:
      Result = Lhs.ugt(Rhs);
      break;
    case CmpInstruction::ICMP_UGE:
      Result = Lhs.uge(Rhs);
      break;
    case CmpInstruction::ICMP_ULT:
      Result = Lhs.ult(Rhs);
      break;
    case CmpInstruction::ICMP_ULE:
      Result = Lhs.ule(Rhs);
      break;
    case CmpInstruction::ICMP_SGT:
      Result = Lhs.sgt(Rhs);
      break;
    case CmpInstruction::ICMP_SGE:
      Result = Lhs.sge(Rhs);
      break;
    case CmpInstruction::ICMP_SLT:
      Result = Lhs.slt(Rhs);
      break;
    case CmpInstruction::ICMP_SLE:
      Result = Lhs.sle(Rhs);
      break;
    default:
      throw std::runtime_error("unsupported dMIR predicate");
    }
    return createScalarResult(*Inst->getType(), Result ? 1 : 0);
  }

  APInt evaluateSelect(const SelectInstruction *Inst) {
    APInt Cond = evaluate(Inst->getOperand<0>());
    return evaluate(Cond.isZero() ? Inst->getOperand<2>()
                                  : Inst->getOperand<1>());
  }

  APInt evaluateAdc(const AdcInstruction *Inst) {
    APInt Lhs = evaluate(Inst->getOperand<0>());
    APInt Rhs = evaluate(Inst->getOperand<1>());
    APInt Carry =
        evaluate(Inst->getOperand<2>()).zextOrTrunc(Lhs.getBitWidth());
    return Lhs + Rhs + Carry;
  }

  APInt evaluateSbb(const SbbInstruction *Inst) {
    APInt Lhs = evaluate(Inst->getOperand<0>());
    APInt Rhs = evaluate(Inst->getOperand<1>());
    APInt Borrow =
        evaluate(Inst->getOperand<2>()).zextOrTrunc(Lhs.getBitWidth());
    return Lhs - Rhs - Borrow;
  }

  std::pair<uint64_t, uint64_t>
  evaluateUmul128(const EvmUmul128Instruction *Inst) {
    const uint64_t Lhs = evaluateUnsigned64(Inst->getOperand<0>());
    const uint64_t Rhs = evaluateUnsigned64(Inst->getOperand<1>());
    const unsigned __int128 Product = static_cast<unsigned __int128>(Lhs) *
                                      static_cast<unsigned __int128>(Rhs);
    return {static_cast<uint64_t>(Product),
            static_cast<uint64_t>(Product >> 64)};
  }

  uint64_t evaluateUmul128Hi(const EvmUmul128HiInstruction *Inst) {
    return evaluateUmul128(cast<EvmUmul128Instruction>(Inst->getOperand<0>()))
        .second;
  }

  std::pair<uint64_t, uint64_t>
  evaluateUdiv128By64(const EvmUdiv128By64Instruction *Inst) {
    const uint64_t Hi = evaluateUnsigned64(Inst->getOperand<0>());
    const uint64_t Lo = evaluateUnsigned64(Inst->getOperand<1>());
    const uint64_t Divisor = evaluateUnsigned64(Inst->getOperand<2>());
    if (Divisor == 0) {
      throw std::runtime_error("128/64 division by zero in dMIR fragment");
    }
    const unsigned __int128 Dividend =
        (static_cast<unsigned __int128>(Hi) << 64) | Lo;
    return {static_cast<uint64_t>(Dividend / Divisor),
            static_cast<uint64_t>(Dividend % Divisor)};
  }

  uint64_t evaluateUrem128By64(const EvmUrem128By64Instruction *Inst) {
    return evaluateUdiv128By64(
               cast<EvmUdiv128By64Instruction>(Inst->getOperand<0>()))
        .second;
  }

  uint64_t evaluateUnsigned64(const MInstruction *Inst) {
    return evaluate(Inst).zextOrTrunc(64).getZExtValue();
  }

  std::unordered_map<VariableIdx, APInt> Variables;
};

intx::uint256 composeU256(const std::array<uint64_t, 4> &Limbs) {
  intx::uint256 Value = Limbs[0];
  Value |= intx::uint256(Limbs[1]) << 64;
  Value |= intx::uint256(Limbs[2]) << 128;
  Value |= intx::uint256(Limbs[3]) << 192;
  return Value;
}

struct BinaryInputCase {
  uint64_t Lhs = 0;
  uint64_t Rhs = 0;
};

struct TernaryInputCase {
  uint64_t First = 0;
  uint64_t Second = 0;
  uint64_t Third = 0;
};

const std::array<uint64_t, 12> &getBoundaryU64Values() {
  static const std::array<uint64_t, 12> Values = {
      0ULL,
      1ULL,
      2ULL,
      3ULL,
      0x7fffffffULL,
      0x80000000ULL,
      0xffffffffULL,
      0x100000000ULL,
      0x7fffffffffffffffULL,
      0x8000000000000000ULL,
      0xfffffffffffffffeULL,
      0xffffffffffffffffULL,
  };
  return Values;
}

const std::vector<uint64_t> &getInterestingU64Values() {
  static const std::vector<uint64_t> Values = []() {
    std::vector<uint64_t> Result = {
        0ULL,
        1ULL,
        2ULL,
        3ULL,
        7ULL,
        8ULL,
        15ULL,
        16ULL,
        31ULL,
        32ULL,
        63ULL,
        64ULL,
        65ULL,
        127ULL,
        128ULL,
        255ULL,
        256ULL,
        0xaaaaaaaaaaaaaaaaULL,
        0x5555555555555555ULL,
        0x8000000000000000ULL,
        0x7fffffffffffffffULL,
        0xfffffffffffffffeULL,
        0xffffffffffffffffULL,
    };

    std::mt19937_64 Rng(0x44d7a5f3e219c8b1ULL);
    for (size_t I = 0; I < 8; ++I) {
      Result.push_back(Rng());
    }
    return Result;
  }();
  return Values;
}

std::vector<BinaryInputCase> getInterestingBinaryInputCases() {
  std::vector<BinaryInputCase> Cases;
  for (uint64_t Lhs : getBoundaryU64Values()) {
    for (uint64_t Rhs : getBoundaryU64Values()) {
      Cases.push_back({Lhs, Rhs});
    }
  }

  std::mt19937_64 Rng(0x93ad71b6ce204f55ULL);
  for (size_t I = 0; I < 96; ++I) {
    Cases.push_back({Rng(), Rng()});
  }
  return Cases;
}

std::vector<TernaryInputCase> getInterestingTernaryInputCases() {
  std::vector<TernaryInputCase> Cases;
  for (uint64_t First : getBoundaryU64Values()) {
    for (uint64_t Second : getBoundaryU64Values()) {
      for (uint64_t Third : getBoundaryU64Values()) {
        Cases.push_back({First, Second, Third});
      }
    }
  }

  std::mt19937_64 Rng(0x7bf8c9ae1304d261ULL);
  for (size_t I = 0; I < 128; ++I) {
    Cases.push_back({Rng(), Rng(), Rng()});
  }
  return Cases;
}

void expectI64Equivalent(const APInt &Original, const APInt &Rewritten,
                         const std::string &Context) {
  ASSERT_EQ(Original.getBitWidth(), 64U) << Context;
  ASSERT_EQ(Rewritten.getBitWidth(), 64U) << Context;
  EXPECT_TRUE(Original == Rewritten)
      << Context << " original=" << Original.getZExtValue()
      << " rewritten=" << Rewritten.getZExtValue();
}

template <typename OriginalBuilder, typename RewrittenBuilder>
void expectUnaryI64RewriteEquivalent(const std::vector<uint64_t> &Values,
                                     OriginalBuilder &&BuildOriginal,
                                     RewrittenBuilder &&BuildRewritten) {
  for (uint64_t Value : Values) {
    DMirTestBuilder Builder;
    Variable *InputVar = Builder.createVariable(&Builder.Context.I64Type);
    auto *Input = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                       InputVar->getVarIdx());
    auto *Original = BuildOriginal(Builder, Input);
    auto *Rewritten = BuildRewritten(Builder, Input);

    DMirFragmentInterpreter Interpreter;
    Interpreter.setVariableValue(InputVar->getVarIdx(), APInt(64, Value));
    expectI64Equivalent(Interpreter.evaluate(Original),
                        Interpreter.evaluate(Rewritten),
                        "value=" + std::to_string(Value));
  }
}

template <typename OriginalBuilder, typename RewrittenBuilder>
void expectBinaryI64RewriteEquivalent(const std::vector<BinaryInputCase> &Cases,
                                      OriginalBuilder &&BuildOriginal,
                                      RewrittenBuilder &&BuildRewritten) {
  for (const auto &InputCase : Cases) {
    DMirTestBuilder Builder;
    Variable *LhsVar = Builder.createVariable(&Builder.Context.I64Type);
    Variable *RhsVar = Builder.createVariable(&Builder.Context.I64Type);
    auto *Lhs = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                     LhsVar->getVarIdx());
    auto *Rhs = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                     RhsVar->getVarIdx());
    auto *Original = BuildOriginal(Builder, Lhs, Rhs);
    auto *Rewritten = BuildRewritten(Builder, Lhs, Rhs);

    DMirFragmentInterpreter Interpreter;
    Interpreter.setVariableValue(LhsVar->getVarIdx(), APInt(64, InputCase.Lhs));
    Interpreter.setVariableValue(RhsVar->getVarIdx(), APInt(64, InputCase.Rhs));
    expectI64Equivalent(Interpreter.evaluate(Original),
                        Interpreter.evaluate(Rewritten),
                        "lhs=" + std::to_string(InputCase.Lhs) +
                            " rhs=" + std::to_string(InputCase.Rhs));
  }
}

bool runDMirRewritePass(DMirTestBuilder &Builder) {
  DMirRewritePass RewritePass;
  return RewritePass.runOnMFunction(Builder.Func);
}

MInstruction *rewriteReturnedValue(DMirTestBuilder &Builder,
                                   MInstruction *ReturnedValue) {
  auto *Return = Builder.createStmt<ReturnInstruction>(ReturnedValue->getType(),
                                                       ReturnedValue);
  runDMirRewritePass(Builder);
  return Return->getOperand<0>();
}

void expectBinaryOperandsMatch(MInstruction *Inst, Opcode Opc, MInstruction *A,
                               MInstruction *B) {
  ASSERT_EQ(Inst->getOpcode(), Opc);
  auto *Binary = llvm::cast<BinaryInstruction>(Inst);
  const bool Matches =
      (Binary->getOperand<0>() == A && Binary->getOperand<1>() == B) ||
      (Binary->getOperand<0>() == B && Binary->getOperand<1>() == A);
  EXPECT_TRUE(Matches);
}

TEST(DMirValidation, EvaluatesIntegerExpressionDag) {
  DMirTestBuilder Builder;
  auto *Value = Builder.createConstI64(0x0f0f0f0f0f0f0f0fULL);
  auto *Mask = Builder.createConstI64(0xf0f0f0f0f0f0f0f0ULL);
  auto *Xor = Builder.createExpr<BinaryInstruction>(
      OP_xor, &Builder.Context.I64Type, Value, Mask);
  auto *Shift = Builder.createExpr<BinaryInstruction>(
      OP_ushr, &Builder.Context.I64Type, Xor, Builder.createConstI64(4));
  auto *Rot = Builder.createExpr<BinaryInstruction>(
      OP_rotl, &Builder.Context.I64Type, Shift, Builder.createConstI64(8));
  auto *Popcnt = Builder.createExpr<UnaryInstruction>(
      OP_popcnt, &Builder.Context.I64Type, Rot);

  DMirFragmentInterpreter Interpreter;
  const APInt Result = Interpreter.evaluate(Popcnt);
  EXPECT_EQ(Result.getZExtValue(), 60ULL);
}

TEST(DMirValidation, FuzzesAddZeroRewrite) {
  expectUnaryI64RewriteEquivalent(
      getInterestingU64Values(),
      [](DMirTestBuilder &Builder, MInstruction *Input) {
        return Builder.createExpr<BinaryInstruction>(
            OP_add, &Builder.Context.I64Type, Input, Builder.createConstI64(0));
      },
      [](DMirTestBuilder &, MInstruction *Input) { return Input; });
}

TEST(DMirValidation, FuzzesSubZeroRewrite) {
  expectUnaryI64RewriteEquivalent(
      getInterestingU64Values(),
      [](DMirTestBuilder &Builder, MInstruction *Input) {
        return Builder.createExpr<BinaryInstruction>(
            OP_sub, &Builder.Context.I64Type, Input, Builder.createConstI64(0));
      },
      [](DMirTestBuilder &, MInstruction *Input) { return Input; });
}

TEST(DMirValidation, FuzzesAndZeroRewrite) {
  expectUnaryI64RewriteEquivalent(
      getInterestingU64Values(),
      [](DMirTestBuilder &Builder, MInstruction *Input) {
        return Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, Input, Builder.createConstI64(0));
      },
      [](DMirTestBuilder &Builder, MInstruction *) {
        return Builder.createConstI64(0);
      });
}

TEST(DMirValidation, FuzzesAndAllOnesRewrite) {
  expectUnaryI64RewriteEquivalent(
      getInterestingU64Values(),
      [](DMirTestBuilder &Builder, MInstruction *Input) {
        return Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, Input,
            Builder.createConstI64(0xffffffffffffffffULL));
      },
      [](DMirTestBuilder &, MInstruction *Input) { return Input; });
}

TEST(DMirValidation, FuzzesAndSelfRewrite) {
  expectUnaryI64RewriteEquivalent(
      getInterestingU64Values(),
      [](DMirTestBuilder &Builder, MInstruction *Input) {
        return Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, Input, Input);
      },
      [](DMirTestBuilder &, MInstruction *Input) { return Input; });
}

TEST(DMirValidation, FuzzesAndNotSelfRewrite) {
  expectUnaryI64RewriteEquivalent(
      getInterestingU64Values(),
      [](DMirTestBuilder &Builder, MInstruction *Input) {
        auto *NotInput =
            Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Input);
        return Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, NotInput, Input);
      },
      [](DMirTestBuilder &Builder, MInstruction *) {
        return Builder.createConstI64(0);
      });
}

TEST(DMirValidation, FuzzesOrZeroRewrite) {
  expectUnaryI64RewriteEquivalent(
      getInterestingU64Values(),
      [](DMirTestBuilder &Builder, MInstruction *Input) {
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, Input, Builder.createConstI64(0));
      },
      [](DMirTestBuilder &, MInstruction *Input) { return Input; });
}

TEST(DMirValidation, FuzzesOrAllOnesRewrite) {
  expectUnaryI64RewriteEquivalent(
      getInterestingU64Values(),
      [](DMirTestBuilder &Builder, MInstruction *Input) {
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, Input,
            Builder.createConstI64(0xffffffffffffffffULL));
      },
      [](DMirTestBuilder &Builder, MInstruction *) {
        return Builder.createConstI64(0xffffffffffffffffULL);
      });
}

TEST(DMirValidation, FuzzesOrSelfRewrite) {
  expectUnaryI64RewriteEquivalent(
      getInterestingU64Values(),
      [](DMirTestBuilder &Builder, MInstruction *Input) {
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, Input, Input);
      },
      [](DMirTestBuilder &, MInstruction *Input) { return Input; });
}

TEST(DMirValidation, FuzzesAndAbsorbOrRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *Or = Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, Lhs, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, Or, Lhs);
      },
      [](DMirTestBuilder &, MInstruction *Lhs, MInstruction *) { return Lhs; });
}

TEST(DMirValidation, FuzzesAndFactorNotSelfRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *And = Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, Lhs, Rhs);
        auto *NotLhs =
            Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Lhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, And, NotLhs);
      },
      [](DMirTestBuilder &Builder, MInstruction *, MInstruction *) {
        return Builder.createConstI64(0);
      });
}

TEST(DMirValidation, FuzzesAndFactorOrRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *And = Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, Lhs, Rhs);
        auto *Or = Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, Lhs, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, And, Or);
      },
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        return Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, Lhs, Rhs);
      });
}

TEST(DMirValidation, FuzzesAndFactorLhsRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *And = Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, Lhs, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, And, Lhs);
      },
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        return Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, Lhs, Rhs);
      });
}

TEST(DMirValidation, FuzzesAndFactorRhsRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *And = Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, Lhs, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, And, Rhs);
      },
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        return Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, Lhs, Rhs);
      });
}

TEST(DMirValidation, FuzzesAndFactorNotRhsRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *And = Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, Lhs, Rhs);
        auto *NotRhs =
            Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, And, NotRhs);
      },
      [](DMirTestBuilder &Builder, MInstruction *, MInstruction *) {
        return Builder.createConstI64(0);
      });
}

TEST(DMirValidation, FuzzesAndAndXorZeroRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *And = Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, Lhs, Rhs);
        auto *Xor = Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, Lhs, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, And, Xor);
      },
      [](DMirTestBuilder &Builder, MInstruction *, MInstruction *) {
        return Builder.createConstI64(0);
      });
}

TEST(DMirValidation, FuzzesAndOrXorRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *Or = Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, Lhs, Rhs);
        auto *Xor = Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, Lhs, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, Or, Xor);
      },
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        return Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, Lhs, Rhs);
      });
}

TEST(DMirValidation, FuzzesAndOrRhsRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *Or = Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, Lhs, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, Or, Rhs);
      },
      [](DMirTestBuilder &, MInstruction *, MInstruction *Rhs) { return Rhs; });
}

TEST(DMirValidation, FuzzesAndNotOrRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *NotLhs =
            Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Lhs);
        auto *Or = Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, Lhs, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, NotLhs, Or);
      },
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *NotLhs =
            Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Lhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, NotLhs, Rhs);
      });
}

TEST(DMirValidation, FuzzesAndNotXorRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *NotLhs =
            Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Lhs);
        auto *Xor = Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, Lhs, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, NotLhs, Xor);
      },
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *NotLhs =
            Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Lhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, NotLhs, Rhs);
      });
}

TEST(DMirValidation, FuzzesOrAbsorbAndRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *And = Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, Lhs, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, And, Lhs);
      },
      [](DMirTestBuilder &, MInstruction *Lhs, MInstruction *) { return Lhs; });
}

TEST(DMirValidation, FuzzesOrAndOrRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *And = Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, Lhs, Rhs);
        auto *Or = Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, Lhs, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, And, Or);
      },
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, Lhs, Rhs);
      });
}

TEST(DMirValidation, FuzzesOrAndRhsRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *And = Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, Lhs, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, And, Rhs);
      },
      [](DMirTestBuilder &, MInstruction *, MInstruction *Rhs) { return Rhs; });
}

TEST(DMirValidation, FuzzesOrAndXorRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *And = Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, Lhs, Rhs);
        auto *Xor = Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, Lhs, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, And, Xor);
      },
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, Lhs, Rhs);
      });
}

TEST(DMirValidation, FuzzesOrFactorLhsRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *Or = Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, Lhs, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, Or, Lhs);
      },
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, Lhs, Rhs);
      });
}

TEST(DMirValidation, FuzzesOrFactorRhsRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *Or = Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, Lhs, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, Or, Rhs);
      },
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, Lhs, Rhs);
      });
}

TEST(DMirValidation, FuzzesOrXorLhsRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *Xor = Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, Lhs, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, Xor, Lhs);
      },
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, Lhs, Rhs);
      });
}

TEST(DMirValidation, FuzzesOrXorRhsRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *Xor = Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, Lhs, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, Xor, Rhs);
      },
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, Lhs, Rhs);
      });
}

TEST(DMirValidation, FuzzesOrNotSelfRewrite) {
  expectUnaryI64RewriteEquivalent(
      getInterestingU64Values(),
      [](DMirTestBuilder &Builder, MInstruction *Input) {
        auto *NotInput =
            Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Input);
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, NotInput, Input);
      },
      [](DMirTestBuilder &Builder, MInstruction *) {
        return Builder.createConstI64(0xffffffffffffffffULL);
      });
}

TEST(DMirValidation, FuzzesOrAndNotLhsRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *And = Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, Lhs, Rhs);
        auto *NotLhs =
            Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Lhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, And, NotLhs);
      },
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *NotLhs =
            Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Lhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, NotLhs, Rhs);
      });
}

TEST(DMirValidation, FuzzesOrAndNotRhsRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *And = Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, Lhs, Rhs);
        auto *NotRhs =
            Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, And, NotRhs);
      },
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *NotRhs =
            Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, NotRhs, Lhs);
      });
}

TEST(DMirValidation, FuzzesOrOrXorRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *Or = Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, Lhs, Rhs);
        auto *Xor = Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, Lhs, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, Or, Xor);
      },
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, Lhs, Rhs);
      });
}

TEST(DMirValidation, FuzzesOrNotOrRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *NotLhs =
            Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Lhs);
        auto *Or = Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, Lhs, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, NotLhs, Or);
      },
      [](DMirTestBuilder &Builder, MInstruction *, MInstruction *) {
        return Builder.createConstI64(0xffffffffffffffffULL);
      });
}

TEST(DMirValidation, FuzzesDoubleNotRewrite) {
  expectUnaryI64RewriteEquivalent(
      getInterestingU64Values(),
      [](DMirTestBuilder &Builder, MInstruction *Input) {
        auto *Inner =
            Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Input);
        return Builder.createExpr<NotInstruction>(&Builder.Context.I64Type,
                                                  Inner);
      },
      [](DMirTestBuilder &, MInstruction *Input) { return Input; });
}

TEST(DMirValidation, ExecutesDassignCmpSelectAndConversions) {
  DMirTestBuilder Builder;
  Variable *Var = Builder.createVariable(&Builder.Context.I64Type);
  auto *Assigned = Builder.createConstI64(0xfffffffffffffff0ULL);
  Builder.createStmt<DassignInstruction>(&Builder.Context.VoidType, Assigned,
                                         Var->getVarIdx());

  auto *Read = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                    Var->getVarIdx());
  auto *Cmp = Builder.createExpr<CmpInstruction>(CmpInstruction::ICMP_SLT,
                                                 &Builder.Context.I64Type, Read,
                                                 Builder.createConstI64(0));
  auto *Truncated = Builder.createExpr<ConversionInstruction>(
      OP_trunc, &Builder.Context.I32Type, Read);
  auto *Extended = Builder.createExpr<ConversionInstruction>(
      OP_sext, &Builder.Context.I64Type, Truncated);
  auto *Pointer = Builder.createExpr<ConversionInstruction>(
      OP_inttoptr, Builder.I64PtrType, Extended);
  auto *RoundTrip = Builder.createExpr<ConversionInstruction>(
      OP_ptrtoint, &Builder.Context.I64Type, Pointer);
  auto *Selected = Builder.createExpr<SelectInstruction>(
      &Builder.Context.I64Type, Cmp, RoundTrip, Builder.createConstI64(0));
  Builder.createStmt<ReturnInstruction>(&Builder.Context.I64Type, Selected);

  DMirFragmentInterpreter Interpreter;
  const auto Result = Interpreter.execute(Builder.getBlock());
  ASSERT_TRUE(Result.has_value());
  EXPECT_EQ(Result->getSExtValue(), -16);
}

TEST(DMirValidation, FuzzesSelectSameArmRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Cond, MInstruction *Value) {
        return Builder.createExpr<SelectInstruction>(&Builder.Context.I64Type,
                                                     Cond, Value, Value);
      },
      [](DMirTestBuilder &, MInstruction *, MInstruction *Value) {
        return Value;
      });
}

// Verify select-same-arm for i8 and i32 value types.  The rule is structural
// (both arms are the same SSA value), so it must hold for any integer width.
template <typename ValTypeSelector>
void fuzzSelectSameArmNarrow(ValTypeSelector &&GetValType,
                             unsigned ExpectedWidth) {
  for (const auto &InputCase : getInterestingBinaryInputCases()) {
    DMirTestBuilder Builder;
    MType *ValType = GetValType(Builder);
    Variable *CondVar = Builder.createVariable(&Builder.Context.I64Type);
    Variable *ValVar = Builder.createVariable(ValType);
    auto *Cond = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                      CondVar->getVarIdx());
    auto *Val =
        Builder.createExpr<DreadInstruction>(ValType, ValVar->getVarIdx());
    auto *Original =
        Builder.createExpr<SelectInstruction>(ValType, Cond, Val, Val);

    DMirFragmentInterpreter Interpreter;
    Interpreter.setVariableValue(CondVar->getVarIdx(),
                                 APInt(64, InputCase.Lhs));
    Interpreter.setVariableValue(ValVar->getVarIdx(),
                                 APInt(ExpectedWidth, InputCase.Rhs));
    APInt OrigResult = Interpreter.evaluate(Original);
    APInt ValResult = Interpreter.evaluate(Val);
    ASSERT_EQ(OrigResult.getBitWidth(), ExpectedWidth);
    EXPECT_TRUE(OrigResult == ValResult)
        << "cond=" << InputCase.Lhs << " val=" << InputCase.Rhs
        << " original=" << OrigResult.getZExtValue()
        << " rewritten=" << ValResult.getZExtValue();
  }
}

TEST(DMirValidation, FuzzesSelectSameArmRewriteI8) {
  fuzzSelectSameArmNarrow(
      [](DMirTestBuilder &B) -> MType * { return &B.Context.I8Type; }, 8U);
}

TEST(DMirValidation, FuzzesSelectSameArmRewriteI32) {
  fuzzSelectSameArmNarrow(
      [](DMirTestBuilder &B) -> MType * { return &B.Context.I32Type; }, 32U);
}

TEST(DMirRewritePass, RewritesReturnedAddZeroToInput) {
  DMirTestBuilder Builder;
  Variable *InputVar = Builder.createVariable(&Builder.Context.I64Type);
  auto *Input = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                     InputVar->getVarIdx());
  auto *Add = Builder.createExpr<BinaryInstruction>(
      OP_add, &Builder.Context.I64Type, Input, Builder.createConstI64(0));

  MInstruction *Rewritten = rewriteReturnedValue(Builder, Add);
  EXPECT_EQ(Rewritten, Input);
}

TEST(DMirRewritePass, RewritesNestedTreeBottomUp) {
  DMirTestBuilder Builder;
  Variable *InputVar = Builder.createVariable(&Builder.Context.I64Type);
  auto *Input = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                     InputVar->getVarIdx());
  auto *DoubleNot =
      Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Input);
  DoubleNot =
      Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, DoubleNot);
  auto *Masked = Builder.createExpr<BinaryInstruction>(
      OP_and, &Builder.Context.I64Type, DoubleNot,
      Builder.createConstI64(0xffffffffffffffffULL));
  auto *Add = Builder.createExpr<BinaryInstruction>(
      OP_add, &Builder.Context.I64Type, Masked, Builder.createConstI64(0));

  MInstruction *Rewritten = rewriteReturnedValue(Builder, Add);
  EXPECT_EQ(Rewritten, Input);
}

TEST(DMirRewritePass, RewritesSelectSameArmByStructure) {
  DMirTestBuilder Builder;
  Variable *CondVar = Builder.createVariable(&Builder.Context.I64Type);
  Variable *ValueVar = Builder.createVariable(&Builder.Context.I64Type);
  auto *Cond = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                    CondVar->getVarIdx());
  auto *TrueValue = Builder.createExpr<DreadInstruction>(
      &Builder.Context.I64Type, ValueVar->getVarIdx());
  auto *FalseValue = Builder.createExpr<DreadInstruction>(
      &Builder.Context.I64Type, ValueVar->getVarIdx());
  auto *Select = Builder.createExpr<SelectInstruction>(
      &Builder.Context.I64Type, Cond, TrueValue, FalseValue);

  MInstruction *Rewritten = rewriteReturnedValue(Builder, Select);
  EXPECT_EQ(Rewritten, TrueValue);
}

TEST(DMirRewritePass, MaterializesTypedAllOnesForOrNotSelf) {
  DMirTestBuilder Builder;
  Variable *InputVar = Builder.createVariable(&Builder.Context.I32Type);
  auto *Input = Builder.createExpr<DreadInstruction>(&Builder.Context.I32Type,
                                                     InputVar->getVarIdx());
  auto *NotInput =
      Builder.createExpr<NotInstruction>(&Builder.Context.I32Type, Input);
  auto *Or = Builder.createExpr<BinaryInstruction>(
      OP_or, &Builder.Context.I32Type, NotInput, Input);

  MInstruction *Rewritten = rewriteReturnedValue(Builder, Or);
  ASSERT_EQ(Rewritten->getOpcode(), OP_const);
  const auto &Constant =
      llvm::cast<ConstantInstruction>(Rewritten)->getConstant();
  EXPECT_EQ(llvm::cast<MConstantInt>(&Constant)->getValue().getBitWidth(), 32U);
  EXPECT_TRUE(llvm::cast<MConstantInt>(&Constant)->getValue() ==
              llvm::APInt(32, ~0U));
}

TEST(DMirRewritePass, RewritesAdcZeroCarryToAdd) {
  // adc(lhs, rhs, const(0)) → add(lhs, rhs) when carry is dead
  DMirTestBuilder Builder;
  Variable *LhsVar = Builder.createVariable(&Builder.Context.I64Type);
  Variable *RhsVar = Builder.createVariable(&Builder.Context.I64Type);
  auto *Lhs = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                   LhsVar->getVarIdx());
  auto *Rhs = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                   RhsVar->getVarIdx());
  auto *Adc = Builder.createExpr<AdcInstruction>(
      &Builder.Context.I64Type, Lhs, Rhs, Builder.createConstI64(0));
  auto *Return =
      Builder.createStmt<ReturnInstruction>(&Builder.Context.I64Type, Adc);

  EXPECT_TRUE(runDMirRewritePass(Builder));
  auto *Result = Return->getOperand<0>();
  EXPECT_NE(Result, Adc);
  EXPECT_EQ(Result->getOpcode(), OP_add);
}

TEST(DMirRewritePass, RewritesAdcZeroOperandsToInput) {
  // adc(input, 0, const(0)) → input when carry is dead and RHS is zero
  DMirTestBuilder Builder;
  Variable *InputVar = Builder.createVariable(&Builder.Context.I64Type);
  auto *Input = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                     InputVar->getVarIdx());
  auto *Adc = Builder.createExpr<AdcInstruction>(
      &Builder.Context.I64Type, Input, Builder.createConstI64(0),
      Builder.createConstI64(0));
  auto *Return =
      Builder.createStmt<ReturnInstruction>(&Builder.Context.I64Type, Adc);

  EXPECT_TRUE(runDMirRewritePass(Builder));
  EXPECT_EQ(Return->getOperand<0>(), Input);
}

TEST(DMirRewritePass, RewritesSbbZeroOperandsToInput) {
  // sbb(input, 0, const(0)) → input when borrow is dead and RHS is zero
  DMirTestBuilder Builder;
  Variable *InputVar = Builder.createVariable(&Builder.Context.I64Type);
  auto *Input = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                     InputVar->getVarIdx());
  auto *Sbb = Builder.createExpr<SbbInstruction>(
      &Builder.Context.I64Type, Input, Builder.createConstI64(0),
      Builder.createConstI64(0));
  auto *Return =
      Builder.createStmt<ReturnInstruction>(&Builder.Context.I64Type, Sbb);

  EXPECT_TRUE(runDMirRewritePass(Builder));
  EXPECT_EQ(Return->getOperand<0>(), Input);
}

TEST(DMirRewritePass, RewritesSbbSelfZeroBorrowToZero) {
  // sbb(input, input, const(0)) → 0 when borrow is dead and LHS==RHS
  DMirTestBuilder Builder;
  Variable *InputVar = Builder.createVariable(&Builder.Context.I64Type);
  auto *Input = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                     InputVar->getVarIdx());
  auto *Sbb = Builder.createExpr<SbbInstruction>(
      &Builder.Context.I64Type, Input,
      Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                           InputVar->getVarIdx()),
      Builder.createConstI64(0));
  auto *Return =
      Builder.createStmt<ReturnInstruction>(&Builder.Context.I64Type, Sbb);

  EXPECT_TRUE(runDMirRewritePass(Builder));
  auto *Result = Return->getOperand<0>();
  EXPECT_NE(Result, Sbb);
  EXPECT_TRUE(llvm::isa<ConstantInstruction>(Result));
}

TEST(DMirRewritePass, RewritesAndAbsorbOrToExistingOperand) {
  DMirTestBuilder Builder;
  Variable *LhsVar = Builder.createVariable(&Builder.Context.I64Type);
  Variable *RhsVar = Builder.createVariable(&Builder.Context.I64Type);
  auto *Lhs = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                   LhsVar->getVarIdx());
  auto *Rhs = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                   RhsVar->getVarIdx());
  auto *Or = Builder.createExpr<BinaryInstruction>(
      OP_or, &Builder.Context.I64Type, Lhs, Rhs);
  auto *And = Builder.createExpr<BinaryInstruction>(
      OP_and, &Builder.Context.I64Type, Or, Lhs);

  MInstruction *Rewritten = rewriteReturnedValue(Builder, And);
  EXPECT_EQ(Rewritten, Lhs);
}

TEST(DMirRewritePass, RewritesAndOrXorToExistingXorSubtree) {
  DMirTestBuilder Builder;
  Variable *LhsVar = Builder.createVariable(&Builder.Context.I64Type);
  Variable *RhsVar = Builder.createVariable(&Builder.Context.I64Type);
  auto *Lhs = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                   LhsVar->getVarIdx());
  auto *Rhs = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                   RhsVar->getVarIdx());
  auto *Or = Builder.createExpr<BinaryInstruction>(
      OP_or, &Builder.Context.I64Type, Lhs, Rhs);
  auto *Xor = Builder.createExpr<BinaryInstruction>(
      OP_xor, &Builder.Context.I64Type,
      Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                           LhsVar->getVarIdx()),
      Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                           RhsVar->getVarIdx()));
  auto *And = Builder.createExpr<BinaryInstruction>(
      OP_and, &Builder.Context.I64Type, Or, Xor);

  MInstruction *Rewritten = rewriteReturnedValue(Builder, And);
  EXPECT_EQ(Rewritten, Xor);
}

TEST(DMirRewritePass, RewritesOrNotOrToAllOnes) {
  DMirTestBuilder Builder;
  Variable *LhsVar = Builder.createVariable(&Builder.Context.I64Type);
  Variable *RhsVar = Builder.createVariable(&Builder.Context.I64Type);
  auto *Lhs = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                   LhsVar->getVarIdx());
  auto *Rhs = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                   RhsVar->getVarIdx());
  auto *NotLhs =
      Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Lhs);
  auto *Or = Builder.createExpr<BinaryInstruction>(
      OP_or, &Builder.Context.I64Type,
      Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                           LhsVar->getVarIdx()),
      Rhs);
  auto *Root = Builder.createExpr<BinaryInstruction>(
      OP_or, &Builder.Context.I64Type, NotLhs, Or);

  MInstruction *Rewritten = rewriteReturnedValue(Builder, Root);
  ASSERT_EQ(Rewritten->getOpcode(), OP_const);
  const auto Value =
      llvm::cast<MConstantInt>(
          &llvm::cast<ConstantInstruction>(Rewritten)->getConstant())
          ->getValue();
  EXPECT_TRUE(Value.isAllOnes());
}

TEST(DMirRewritePass, RewritesXorCancelToSiblingOperand) {
  DMirTestBuilder Builder;
  Variable *LhsVar = Builder.createVariable(&Builder.Context.I64Type);
  Variable *RhsVar = Builder.createVariable(&Builder.Context.I64Type);
  auto *Lhs = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                   LhsVar->getVarIdx());
  auto *Rhs = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                   RhsVar->getVarIdx());
  auto *NestedXor = Builder.createExpr<BinaryInstruction>(
      OP_xor, &Builder.Context.I64Type, Lhs, Rhs);
  auto *Root = Builder.createExpr<BinaryInstruction>(
      OP_xor, &Builder.Context.I64Type, NestedXor,
      Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                           LhsVar->getVarIdx()));

  MInstruction *Rewritten = rewriteReturnedValue(Builder, Root);
  EXPECT_EQ(Rewritten, Rhs);
}

TEST(DMirRewritePass, RewritesXorNotAllOnesToOperand) {
  DMirTestBuilder Builder;
  Variable *InputVar = Builder.createVariable(&Builder.Context.I64Type);
  auto *Input = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                     InputVar->getVarIdx());
  auto *NotInput =
      Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Input);
  auto *Root = Builder.createExpr<BinaryInstruction>(
      OP_xor, &Builder.Context.I64Type, NotInput,
      Builder.createConstI64(0xffffffffffffffffULL));

  MInstruction *Rewritten = rewriteReturnedValue(Builder, Root);
  EXPECT_EQ(Rewritten, Input);
}

TEST(DMirRewritePass, RewritesAndNotOrToNewAndNode) {
  DMirTestBuilder Builder;
  Variable *LhsVar = Builder.createVariable(&Builder.Context.I64Type);
  Variable *RhsVar = Builder.createVariable(&Builder.Context.I64Type);
  auto *Lhs = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                   LhsVar->getVarIdx());
  auto *Rhs = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                   RhsVar->getVarIdx());
  auto *NotLhs =
      Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Lhs);
  auto *Or = Builder.createExpr<BinaryInstruction>(
      OP_or, &Builder.Context.I64Type,
      Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                           LhsVar->getVarIdx()),
      Rhs);
  auto *Root = Builder.createExpr<BinaryInstruction>(
      OP_and, &Builder.Context.I64Type, NotLhs, Or);

  MInstruction *Rewritten = rewriteReturnedValue(Builder, Root);
  expectBinaryOperandsMatch(Rewritten, OP_and, NotLhs, Rhs);
}

TEST(DMirRewritePass, RewritesOrXorLhsToNewOrNode) {
  DMirTestBuilder Builder;
  Variable *LhsVar = Builder.createVariable(&Builder.Context.I64Type);
  Variable *RhsVar = Builder.createVariable(&Builder.Context.I64Type);
  auto *Lhs = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                   LhsVar->getVarIdx());
  auto *Rhs = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                   RhsVar->getVarIdx());
  auto *NestedXor = Builder.createExpr<BinaryInstruction>(
      OP_xor, &Builder.Context.I64Type, Lhs, Rhs);
  auto *Root = Builder.createExpr<BinaryInstruction>(
      OP_or, &Builder.Context.I64Type, NestedXor,
      Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                           LhsVar->getVarIdx()));

  MInstruction *Rewritten = rewriteReturnedValue(Builder, Root);
  expectBinaryOperandsMatch(Rewritten, OP_or, Lhs, Rhs);
}

TEST(DMirRewritePass, RewritesOrAndNotToNewOrNode) {
  DMirTestBuilder Builder;
  Variable *LhsVar = Builder.createVariable(&Builder.Context.I64Type);
  Variable *RhsVar = Builder.createVariable(&Builder.Context.I64Type);
  auto *Lhs = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                   LhsVar->getVarIdx());
  auto *Rhs = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                   RhsVar->getVarIdx());
  auto *And = Builder.createExpr<BinaryInstruction>(
      OP_and, &Builder.Context.I64Type, Lhs, Rhs);
  auto *NotLhs = Builder.createExpr<NotInstruction>(
      &Builder.Context.I64Type,
      Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                           LhsVar->getVarIdx()));
  auto *Root = Builder.createExpr<BinaryInstruction>(
      OP_or, &Builder.Context.I64Type, And, NotLhs);

  MInstruction *Rewritten = rewriteReturnedValue(Builder, Root);
  expectBinaryOperandsMatch(Rewritten, OP_or, NotLhs, Rhs);
}

TEST(DMirRewritePass, RewritesXorNotNotToNewXorNode) {
  DMirTestBuilder Builder;
  Variable *LhsVar = Builder.createVariable(&Builder.Context.I64Type);
  Variable *RhsVar = Builder.createVariable(&Builder.Context.I64Type);
  auto *Lhs = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                   LhsVar->getVarIdx());
  auto *Rhs = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                   RhsVar->getVarIdx());
  auto *Root = Builder.createExpr<BinaryInstruction>(
      OP_xor, &Builder.Context.I64Type,
      Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Lhs),
      Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Rhs));

  MInstruction *Rewritten = rewriteReturnedValue(Builder, Root);
  expectBinaryOperandsMatch(Rewritten, OP_xor, Lhs, Rhs);
}

TEST(DMirRewritePass, RewritesXorAndXorToNewOrNode) {
  DMirTestBuilder Builder;
  Variable *LhsVar = Builder.createVariable(&Builder.Context.I64Type);
  Variable *RhsVar = Builder.createVariable(&Builder.Context.I64Type);
  auto *Lhs = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                   LhsVar->getVarIdx());
  auto *Rhs = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                   RhsVar->getVarIdx());
  auto *And = Builder.createExpr<BinaryInstruction>(
      OP_and, &Builder.Context.I64Type, Lhs, Rhs);
  auto *Xor = Builder.createExpr<BinaryInstruction>(
      OP_xor, &Builder.Context.I64Type,
      Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                           LhsVar->getVarIdx()),
      Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                           RhsVar->getVarIdx()));
  auto *Root = Builder.createExpr<BinaryInstruction>(
      OP_xor, &Builder.Context.I64Type, And, Xor);

  MInstruction *Rewritten = rewriteReturnedValue(Builder, Root);
  expectBinaryOperandsMatch(Rewritten, OP_or, Lhs, Rhs);
}

TEST(DMirRewritePass, RewritesXorOrXorToNewAndNode) {
  DMirTestBuilder Builder;
  Variable *LhsVar = Builder.createVariable(&Builder.Context.I64Type);
  Variable *RhsVar = Builder.createVariable(&Builder.Context.I64Type);
  auto *Lhs = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                   LhsVar->getVarIdx());
  auto *Rhs = Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                                   RhsVar->getVarIdx());
  auto *Or = Builder.createExpr<BinaryInstruction>(
      OP_or, &Builder.Context.I64Type, Lhs, Rhs);
  auto *Xor = Builder.createExpr<BinaryInstruction>(
      OP_xor, &Builder.Context.I64Type,
      Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                           LhsVar->getVarIdx()),
      Builder.createExpr<DreadInstruction>(&Builder.Context.I64Type,
                                           RhsVar->getVarIdx()));
  auto *Root = Builder.createExpr<BinaryInstruction>(
      OP_xor, &Builder.Context.I64Type, Or, Xor);

  MInstruction *Rewritten = rewriteReturnedValue(Builder, Root);
  expectBinaryOperandsMatch(Rewritten, OP_and, Lhs, Rhs);
}

TEST(DMirValidation, FuzzesAdcWithoutCarryRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        return Builder.createExpr<AdcInstruction>(
            &Builder.Context.I64Type, Lhs, Rhs, Builder.createConstI64(0));
      },
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        return Builder.createExpr<BinaryInstruction>(
            OP_add, &Builder.Context.I64Type, Lhs, Rhs);
      });
}

TEST(DMirValidation, FuzzesAdcZeroOperandsRewrite) {
  expectUnaryI64RewriteEquivalent(
      getInterestingU64Values(),
      [](DMirTestBuilder &Builder, MInstruction *Input) {
        return Builder.createExpr<AdcInstruction>(
            &Builder.Context.I64Type, Input, Builder.createConstI64(0),
            Builder.createConstI64(0));
      },
      [](DMirTestBuilder &, MInstruction *Input) { return Input; });
}

TEST(DMirValidation, FuzzesSbbWithoutBorrowRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        return Builder.createExpr<SbbInstruction>(
            &Builder.Context.I64Type, Lhs, Rhs, Builder.createConstI64(0));
      },
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        return Builder.createExpr<BinaryInstruction>(
            OP_sub, &Builder.Context.I64Type, Lhs, Rhs);
      });
}

TEST(DMirValidation, FuzzesSbbZeroOperandsRewrite) {
  expectUnaryI64RewriteEquivalent(
      getInterestingU64Values(),
      [](DMirTestBuilder &Builder, MInstruction *Input) {
        return Builder.createExpr<SbbInstruction>(
            &Builder.Context.I64Type, Input, Builder.createConstI64(0),
            Builder.createConstI64(0));
      },
      [](DMirTestBuilder &, MInstruction *Input) { return Input; });
}

TEST(DMirValidation, FuzzesXorZeroRewrite) {
  expectUnaryI64RewriteEquivalent(
      getInterestingU64Values(),
      [](DMirTestBuilder &Builder, MInstruction *Input) {
        return Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, Input, Builder.createConstI64(0));
      },
      [](DMirTestBuilder &, MInstruction *Input) { return Input; });
}

TEST(DMirValidation, FuzzesXorSelfRewrite) {
  expectUnaryI64RewriteEquivalent(
      getInterestingU64Values(),
      [](DMirTestBuilder &Builder, MInstruction *Input) {
        return Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, Input, Input);
      },
      [](DMirTestBuilder &Builder, MInstruction *) {
        return Builder.createConstI64(0);
      });
}

TEST(DMirValidation, FuzzesXorCancelRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *Inner = Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, Lhs, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, Inner, Lhs);
      },
      [](DMirTestBuilder &, MInstruction *, MInstruction *Rhs) { return Rhs; });
}

TEST(DMirValidation, FuzzesXorCancelRhsRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *Inner = Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, Lhs, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, Inner, Rhs);
      },
      [](DMirTestBuilder &, MInstruction *Lhs, MInstruction *) { return Lhs; });
}

TEST(DMirValidation, FuzzesXorNotCancelRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *NotLhs =
            Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Lhs);
        auto *Xor = Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, Lhs, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, NotLhs, Xor);
      },
      [](DMirTestBuilder &Builder, MInstruction *, MInstruction *Rhs) {
        return Builder.createExpr<NotInstruction>(&Builder.Context.I64Type,
                                                  Rhs);
      });
}

TEST(DMirValidation, FuzzesXorNotSelfRewrite) {
  expectUnaryI64RewriteEquivalent(
      getInterestingU64Values(),
      [](DMirTestBuilder &Builder, MInstruction *Input) {
        auto *NotInput =
            Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Input);
        return Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, NotInput, Input);
      },
      [](DMirTestBuilder &Builder, MInstruction *) {
        return Builder.createConstI64(0xffffffffffffffffULL);
      });
}

TEST(DMirValidation, FuzzesXorNotNotRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *NotLhs =
            Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Lhs);
        auto *NotRhs =
            Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, NotLhs, NotRhs);
      },
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        return Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, Lhs, Rhs);
      });
}

TEST(DMirValidation, FuzzesXorNotOrRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *NotLhs =
            Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Lhs);
        auto *Or = Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, Lhs, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, NotLhs, Or);
      },
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *NotRhs =
            Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, NotRhs, Lhs);
      });
}

TEST(DMirValidation, FuzzesXorNotAllOnesRewrite) {
  expectUnaryI64RewriteEquivalent(
      getInterestingU64Values(),
      [](DMirTestBuilder &Builder, MInstruction *Input) {
        auto *NotInput =
            Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Input);
        return Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, NotInput,
            Builder.createConstI64(0xffffffffffffffffULL));
      },
      [](DMirTestBuilder &, MInstruction *Input) { return Input; });
}

TEST(DMirValidation, FuzzesXorAndOrRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *And = Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, Lhs, Rhs);
        auto *Or = Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, Lhs, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, And, Or);
      },
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        return Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, Lhs, Rhs);
      });
}

TEST(DMirValidation, FuzzesXorAndNotLhsRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *And = Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, Lhs, Rhs);
        auto *NotLhs =
            Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Lhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, And, NotLhs);
      },
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *NotLhs =
            Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Lhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, NotLhs, Rhs);
      });
}

TEST(DMirValidation, FuzzesXorAndNotRhsRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *And = Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, Lhs, Rhs);
        auto *NotRhs =
            Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, And, NotRhs);
      },
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *NotRhs =
            Builder.createExpr<NotInstruction>(&Builder.Context.I64Type, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, NotRhs, Lhs);
      });
}

TEST(DMirValidation, FuzzesXorAndXorRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *And = Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, Lhs, Rhs);
        auto *Xor = Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, Lhs, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, And, Xor);
      },
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, Lhs, Rhs);
      });
}

TEST(DMirValidation, FuzzesXorOrXorRewrite) {
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        auto *Or = Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, Lhs, Rhs);
        auto *Xor = Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, Lhs, Rhs);
        return Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, Or, Xor);
      },
      [](DMirTestBuilder &Builder, MInstruction *Lhs, MInstruction *Rhs) {
        return Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, Lhs, Rhs);
      });
}

TEST(DMirValidation, FuzzesSubSelfRewrite) {
  expectUnaryI64RewriteEquivalent(
      getInterestingU64Values(),
      [](DMirTestBuilder &Builder, MInstruction *Input) {
        return Builder.createExpr<BinaryInstruction>(
            OP_sub, &Builder.Context.I64Type, Input, Input);
      },
      [](DMirTestBuilder &Builder, MInstruction *) {
        return Builder.createConstI64(0);
      });
}

TEST(DMirValidation, FuzzesShlZeroRewrite) {
  expectUnaryI64RewriteEquivalent(
      getInterestingU64Values(),
      [](DMirTestBuilder &Builder, MInstruction *Input) {
        return Builder.createExpr<BinaryInstruction>(
            OP_shl, &Builder.Context.I64Type, Input, Builder.createConstI64(0));
      },
      [](DMirTestBuilder &, MInstruction *Input) { return Input; });
}

TEST(DMirValidation, FuzzesSshrZeroRewrite) {
  expectUnaryI64RewriteEquivalent(
      getInterestingU64Values(),
      [](DMirTestBuilder &Builder, MInstruction *Input) {
        return Builder.createExpr<BinaryInstruction>(
            OP_sshr, &Builder.Context.I64Type, Input,
            Builder.createConstI64(0));
      },
      [](DMirTestBuilder &, MInstruction *Input) { return Input; });
}

TEST(DMirValidation, FuzzesUshrZeroRewrite) {
  expectUnaryI64RewriteEquivalent(
      getInterestingU64Values(),
      [](DMirTestBuilder &Builder, MInstruction *Input) {
        return Builder.createExpr<BinaryInstruction>(
            OP_ushr, &Builder.Context.I64Type, Input,
            Builder.createConstI64(0));
      },
      [](DMirTestBuilder &, MInstruction *Input) { return Input; });
}

TEST(DMirValidation, FuzzesSbbSelfWithoutBorrowRewrite) {
  expectUnaryI64RewriteEquivalent(
      getInterestingU64Values(),
      [](DMirTestBuilder &Builder, MInstruction *Input) {
        return Builder.createExpr<SbbInstruction>(
            &Builder.Context.I64Type, Input, Input, Builder.createConstI64(0));
      },
      [](DMirTestBuilder &Builder, MInstruction *) {
        return Builder.createConstI64(0);
      });
}

TEST(DMirValidation, EvaluatesAdcAndSbbLimbChains) {
  DMirTestBuilder Builder;
  std::array<uint64_t, 4> LhsLimbs = {
      0xffffffffffffffffULL,
      0x0000000000000000ULL,
      0x1234567890abcdefULL,
      0x0fedcba987654321ULL,
  };
  std::array<uint64_t, 4> RhsLimbs = {
      0x0000000000000002ULL,
      0xffffffffffffffffULL,
      0x1111111111111111ULL,
      0x2222222222222222ULL,
  };

  std::array<MInstruction *, 4> Sum = {};
  std::array<MInstruction *, 4> Diff = {};
  MInstruction *Carry = Builder.createConstI64(0);
  MInstruction *Borrow = Builder.createConstI64(0);
  for (size_t I = 0; I < LhsLimbs.size(); ++I) {
    auto *Lhs = Builder.createConstI64(LhsLimbs[I]);
    auto *Rhs = Builder.createConstI64(RhsLimbs[I]);
    if (I == 0) {
      Sum[I] = Builder.createExpr<BinaryInstruction>(
          OP_add, &Builder.Context.I64Type, Lhs, Rhs);
      Diff[I] = Builder.createExpr<BinaryInstruction>(
          OP_sub, &Builder.Context.I64Type, Lhs, Rhs);
    } else {
      Sum[I] = Builder.createExpr<AdcInstruction>(&Builder.Context.I64Type, Lhs,
                                                  Rhs, Carry);
      Diff[I] = Builder.createExpr<SbbInstruction>(&Builder.Context.I64Type,
                                                   Lhs, Rhs, Borrow);
    }
    auto *CarryInNonZero = Builder.createExpr<CmpInstruction>(
        CmpInstruction::ICMP_NE, &Builder.Context.I64Type, Carry,
        Builder.createConstI64(0));
    auto *BorrowInNonZero = Builder.createExpr<CmpInstruction>(
        CmpInstruction::ICMP_NE, &Builder.Context.I64Type, Borrow,
        Builder.createConstI64(0));
    auto *SumCmp = Builder.createExpr<CmpInstruction>(
        CmpInstruction::ICMP_ULT, &Builder.Context.I64Type, Sum[I], Lhs);
    auto *SumEq = Builder.createExpr<CmpInstruction>(
        CmpInstruction::ICMP_EQ, &Builder.Context.I64Type, Sum[I], Lhs);
    auto *CarryInOverflow = Builder.createExpr<BinaryInstruction>(
        OP_and, &Builder.Context.I64Type, CarryInNonZero, SumEq);
    auto *DiffCmp = Builder.createExpr<CmpInstruction>(
        CmpInstruction::ICMP_UGT, &Builder.Context.I64Type, Diff[I], Lhs);
    auto *DiffEq = Builder.createExpr<CmpInstruction>(
        CmpInstruction::ICMP_EQ, &Builder.Context.I64Type, Diff[I], Lhs);
    auto *BorrowInOverflow = Builder.createExpr<BinaryInstruction>(
        OP_and, &Builder.Context.I64Type, BorrowInNonZero, DiffEq);
    Carry = Builder.createExpr<BinaryInstruction>(
        OP_or, &Builder.Context.I64Type, SumCmp, CarryInOverflow);
    Borrow = Builder.createExpr<BinaryInstruction>(
        OP_or, &Builder.Context.I64Type, DiffCmp, BorrowInOverflow);
  }

  DMirFragmentInterpreter Interpreter;
  std::array<uint64_t, 4> SumLimbs = {};
  std::array<uint64_t, 4> DiffLimbs = {};
  for (size_t I = 0; I < Sum.size(); ++I) {
    SumLimbs[I] = Interpreter.evaluate(Sum[I]).getZExtValue();
    DiffLimbs[I] = Interpreter.evaluate(Diff[I]).getZExtValue();
  }

  const intx::uint256 ExpectedSum =
      composeU256(LhsLimbs) + composeU256(RhsLimbs);
  const intx::uint256 ExpectedDiff =
      composeU256(LhsLimbs) - composeU256(RhsLimbs);
  EXPECT_EQ(composeU256(SumLimbs), ExpectedSum);
  EXPECT_EQ(composeU256(DiffLimbs), ExpectedDiff);
}

TEST(DMirValidation, EvaluatesEvm128Helpers) {
  DMirTestBuilder Builder;
  auto *MulLhs = Builder.createConstI64(0xffffffffffffffffULL);
  auto *MulRhs = Builder.createConstI64(3ULL);
  auto *MulLo = Builder.createExpr<EvmUmul128Instruction>(
      OP_evm_umul128_lo, &Builder.Context.I64Type, MulLhs, MulRhs);
  auto *MulHi = Builder.createExpr<EvmUmul128HiInstruction>(
      &Builder.Context.I64Type, MulLo);

  auto *DividendHi = Builder.createConstI64(1ULL);
  auto *DividendLo = Builder.createConstI64(0ULL);
  auto *Divisor = Builder.createConstI64(3ULL);
  auto *Quotient = Builder.createExpr<EvmUdiv128By64Instruction>(
      OP_evm_udiv128_by64, &Builder.Context.I64Type, DividendHi, DividendLo,
      Divisor);
  auto *Remainder = Builder.createExpr<EvmUrem128By64Instruction>(
      &Builder.Context.I64Type, Quotient);

  DMirFragmentInterpreter Interpreter;
  EXPECT_EQ(Interpreter.evaluate(MulLo).getZExtValue(), 0xfffffffffffffffdULL);
  EXPECT_EQ(Interpreter.evaluate(MulHi).getZExtValue(), 2ULL);
  EXPECT_EQ(Interpreter.evaluate(Quotient).getZExtValue(),
            0x5555555555555555ULL);
  EXPECT_EQ(Interpreter.evaluate(Remainder).getZExtValue(), 1ULL);
}

TEST(DMirValidation, FuzzesEvm128HelpersAgainstHostArithmetic) {
  const auto Values = getInterestingU64Values();
  for (uint64_t Lhs : Values) {
    for (uint64_t Rhs : Values) {
      DMirTestBuilder Builder;
      auto *MulLhs = Builder.createConstI64(Lhs);
      auto *MulRhs = Builder.createConstI64(Rhs);
      auto *MulLo = Builder.createExpr<EvmUmul128Instruction>(
          OP_evm_umul128_lo, &Builder.Context.I64Type, MulLhs, MulRhs);
      auto *MulHi = Builder.createExpr<EvmUmul128HiInstruction>(
          &Builder.Context.I64Type, MulLo);

      const unsigned __int128 Product = static_cast<unsigned __int128>(Lhs) *
                                        static_cast<unsigned __int128>(Rhs);
      DMirFragmentInterpreter Interpreter;
      EXPECT_EQ(Interpreter.evaluate(MulLo).getZExtValue(),
                static_cast<uint64_t>(Product))
          << "lhs=" << Lhs << " rhs=" << Rhs;
      EXPECT_EQ(Interpreter.evaluate(MulHi).getZExtValue(),
                static_cast<uint64_t>(Product >> 64))
          << "lhs=" << Lhs << " rhs=" << Rhs;
    }
  }

  for (const auto &InputCase : getInterestingTernaryInputCases()) {
    if (InputCase.Third == 0) {
      continue;
    }
    DMirTestBuilder Builder;
    auto *Quotient = Builder.createExpr<EvmUdiv128By64Instruction>(
        OP_evm_udiv128_by64, &Builder.Context.I64Type,
        Builder.createConstI64(InputCase.First),
        Builder.createConstI64(InputCase.Second),
        Builder.createConstI64(InputCase.Third));
    auto *Remainder = Builder.createExpr<EvmUrem128By64Instruction>(
        &Builder.Context.I64Type, Quotient);

    const unsigned __int128 Dividend =
        (static_cast<unsigned __int128>(InputCase.First) << 64) |
        InputCase.Second;
    DMirFragmentInterpreter Interpreter;
    EXPECT_EQ(Interpreter.evaluate(Quotient).getZExtValue(),
              static_cast<uint64_t>(Dividend / InputCase.Third))
        << "hi=" << InputCase.First << " lo=" << InputCase.Second
        << " divisor=" << InputCase.Third;
    EXPECT_EQ(Interpreter.evaluate(Remainder).getZExtValue(),
              static_cast<uint64_t>(Dividend % InputCase.Third))
        << "hi=" << InputCase.First << " lo=" << InputCase.Second
        << " divisor=" << InputCase.Third;
  }
}

TEST(DMirValidation, FuzzesMulZeroRewrite) {
  // (mul x 0) -> 0
  expectUnaryI64RewriteEquivalent(
      getInterestingU64Values(),
      [](DMirTestBuilder &Builder, MInstruction *Input) {
        return Builder.createExpr<BinaryInstruction>(
            OP_mul, &Builder.Context.I64Type, Input, Builder.createConstI64(0));
      },
      [](DMirTestBuilder &Builder, MInstruction *) {
        return Builder.createConstI64(0);
      });
  // (mul 0 x) -> 0
  expectUnaryI64RewriteEquivalent(
      getInterestingU64Values(),
      [](DMirTestBuilder &Builder, MInstruction *Input) {
        return Builder.createExpr<BinaryInstruction>(
            OP_mul, &Builder.Context.I64Type, Builder.createConstI64(0), Input);
      },
      [](DMirTestBuilder &Builder, MInstruction *) {
        return Builder.createConstI64(0);
      });
}

TEST(DMirValidation, FuzzesMulOneRewrite) {
  // (mul x 1) -> x
  expectUnaryI64RewriteEquivalent(
      getInterestingU64Values(),
      [](DMirTestBuilder &Builder, MInstruction *Input) {
        return Builder.createExpr<BinaryInstruction>(
            OP_mul, &Builder.Context.I64Type, Input, Builder.createConstI64(1));
      },
      [](DMirTestBuilder &, MInstruction *Input) { return Input; });
  // (mul 1 x) -> x
  expectUnaryI64RewriteEquivalent(
      getInterestingU64Values(),
      [](DMirTestBuilder &Builder, MInstruction *Input) {
        return Builder.createExpr<BinaryInstruction>(
            OP_mul, &Builder.Context.I64Type, Builder.createConstI64(1), Input);
      },
      [](DMirTestBuilder &, MInstruction *Input) { return Input; });
}

TEST(DMirValidation, FuzzesAddSelfToShl1Rewrite) {
  // (add x x) -> (shl x 1)
  expectUnaryI64RewriteEquivalent(
      getInterestingU64Values(),
      [](DMirTestBuilder &Builder, MInstruction *Input) {
        return Builder.createExpr<BinaryInstruction>(
            OP_add, &Builder.Context.I64Type, Input, Input);
      },
      [](DMirTestBuilder &Builder, MInstruction *Input) {
        return Builder.createExpr<BinaryInstruction>(
            OP_shl, &Builder.Context.I64Type, Input, Builder.createConstI64(1));
      });
}

TEST(DMirValidation, FuzzesAddNegToSubRewrite) {
  // (add (sub 0 x) y) -> (sub y x)
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *X, MInstruction *Y) {
        auto *NegX = Builder.createExpr<BinaryInstruction>(
            OP_sub, &Builder.Context.I64Type, Builder.createConstI64(0), X);
        return Builder.createExpr<BinaryInstruction>(
            OP_add, &Builder.Context.I64Type, NegX, Y);
      },
      [](DMirTestBuilder &Builder, MInstruction *X, MInstruction *Y) {
        return Builder.createExpr<BinaryInstruction>(
            OP_sub, &Builder.Context.I64Type, Y, X);
      });
  // (add y (sub 0 x)) -> (sub y x)
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *X, MInstruction *Y) {
        auto *NegX = Builder.createExpr<BinaryInstruction>(
            OP_sub, &Builder.Context.I64Type, Builder.createConstI64(0), X);
        return Builder.createExpr<BinaryInstruction>(
            OP_add, &Builder.Context.I64Type, Y, NegX);
      },
      [](DMirTestBuilder &Builder, MInstruction *X, MInstruction *Y) {
        return Builder.createExpr<BinaryInstruction>(
            OP_sub, &Builder.Context.I64Type, Y, X);
      });
}

TEST(DMirValidation, FuzzesAddAndXorToOrRewrite) {
  // (add (and x y) (xor x y)) -> (or x y)
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *X, MInstruction *Y) {
        auto *And = Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, X, Y);
        auto *Xor = Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, X, Y);
        return Builder.createExpr<BinaryInstruction>(
            OP_add, &Builder.Context.I64Type, And, Xor);
      },
      [](DMirTestBuilder &Builder, MInstruction *X, MInstruction *Y) {
        return Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, X, Y);
      });
}

TEST(DMirValidation, FuzzesAddAndOrToAddRewrite) {
  // (add (and x y) (or x y)) -> (add x y)
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *X, MInstruction *Y) {
        auto *And = Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, X, Y);
        auto *Or = Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, X, Y);
        return Builder.createExpr<BinaryInstruction>(
            OP_add, &Builder.Context.I64Type, And, Or);
      },
      [](DMirTestBuilder &Builder, MInstruction *X, MInstruction *Y) {
        return Builder.createExpr<BinaryInstruction>(
            OP_add, &Builder.Context.I64Type, X, Y);
      });
}

TEST(DMirValidation, FuzzesSubAndOrToNegXorRewrite) {
  // (sub (and x y) (or x y)) -> (sub 0 (xor x y))
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *X, MInstruction *Y) {
        auto *And = Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, X, Y);
        auto *Or = Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, X, Y);
        return Builder.createExpr<BinaryInstruction>(
            OP_sub, &Builder.Context.I64Type, And, Or);
      },
      [](DMirTestBuilder &Builder, MInstruction *X, MInstruction *Y) {
        auto *Xor = Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, X, Y);
        return Builder.createExpr<BinaryInstruction>(
            OP_sub, &Builder.Context.I64Type, Builder.createConstI64(0), Xor);
      });
}

TEST(DMirValidation, FuzzesSubOrAndToXorRewrite) {
  // (sub (or x y) (and x y)) -> (xor x y)
  expectBinaryI64RewriteEquivalent(
      getInterestingBinaryInputCases(),
      [](DMirTestBuilder &Builder, MInstruction *X, MInstruction *Y) {
        auto *Or = Builder.createExpr<BinaryInstruction>(
            OP_or, &Builder.Context.I64Type, X, Y);
        auto *And = Builder.createExpr<BinaryInstruction>(
            OP_and, &Builder.Context.I64Type, X, Y);
        return Builder.createExpr<BinaryInstruction>(
            OP_sub, &Builder.Context.I64Type, Or, And);
      },
      [](DMirTestBuilder &Builder, MInstruction *X, MInstruction *Y) {
        return Builder.createExpr<BinaryInstruction>(
            OP_xor, &Builder.Context.I64Type, X, Y);
      });
}

} // namespace
