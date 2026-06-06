// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifdef ZEN_ENABLE_DMIR_SHADOW_AUDIT

#include "compiler/context.h"
#include "compiler/mir/constants.h"
#include "compiler/mir/function.h"
#include "compiler/mir/instructions.h"
#include "compiler/mir/pass/dmir_shadow_runtime.h"
#include <gtest/gtest.h>
#include <stdexcept>

using namespace COMPILER;

TEST(ShadowParser, ParseAtomVariable) {
  auto N = parseShadowLhs("x");
  ASSERT_TRUE(N->IsAtom);
  EXPECT_EQ(N->AtomKind, ShadowAtomKind::Variable);
  EXPECT_EQ(N->AtomName, "x");
}

TEST(ShadowParser, ParseAtomConstZero) {
  auto N = parseShadowLhs("0:i64");
  ASSERT_TRUE(N->IsAtom);
  EXPECT_EQ(N->AtomKind, ShadowAtomKind::ConstZero);
}

TEST(ShadowParser, ParseAtomConstOne) {
  auto N = parseShadowLhs("1:i64");
  ASSERT_TRUE(N->IsAtom);
  EXPECT_EQ(N->AtomKind, ShadowAtomKind::ConstOne);
}

TEST(ShadowParser, ParseAtomAllOnes) {
  auto N = parseShadowLhs("all_ones:i64");
  ASSERT_TRUE(N->IsAtom);
  EXPECT_EQ(N->AtomKind, ShadowAtomKind::ConstAllOnes);
}

TEST(ShadowParser, ParseAtomConstInteger) {
  auto N = parseShadowLhs("123:i64");
  ASSERT_TRUE(N->IsAtom);
  EXPECT_EQ(N->AtomKind, ShadowAtomKind::ConstInteger);
  EXPECT_EQ(N->AtomConstValue, 123u);
}

TEST(ShadowParser, ParseSimpleBinary) {
  auto N = parseShadowLhs("(add x y)");
  ASSERT_FALSE(N->IsAtom);
  EXPECT_EQ(N->Op, OP_add);
  ASSERT_EQ(N->Children.size(), 2u);
  EXPECT_EQ(N->Children[0]->AtomName, "x");
  EXPECT_EQ(N->Children[1]->AtomName, "y");
}

TEST(ShadowParser, ParseNested) {
  auto N = parseShadowLhs("(and (and x y) (xor x y))");
  ASSERT_FALSE(N->IsAtom);
  EXPECT_EQ(N->Op, OP_and);
  ASSERT_EQ(N->Children.size(), 2u);
  EXPECT_EQ(N->Children[0]->Op, OP_and);
  EXPECT_EQ(N->Children[1]->Op, OP_xor);
}

TEST(ShadowParser, RejectUnsupportedOpcode) {
  EXPECT_THROW(parseShadowLhs("(adc x y c)"), std::runtime_error);
  EXPECT_THROW(parseShadowLhs("(select c x y)"), std::runtime_error);
}

TEST(ShadowParser, RejectMalformed) {
  EXPECT_THROW(parseShadowLhs("(add x"), std::runtime_error);
  EXPECT_THROW(parseShadowLhs("add x)"), std::runtime_error);
  EXPECT_THROW(parseShadowLhs(""), std::runtime_error);
}

namespace {

// Mirror of DMirTestBuilder from dmir_validation_tests.cpp, scoped down to
// what the matcher tests need (constants, dread, binary).
class ShadowFixture {
public:
  ShadowFixture() : Func(Context, 0) {
    Context.initialize();
    Func.setFunctionType(MFunctionType::create(Context, Context.VoidType, {}));
    BB = Func.createBasicBlock();
    Func.appendBlock(BB);
  }

  ConstantInstruction *makeConstI64(uint64_t Value) {
    return Func.createInstruction<ConstantInstruction>(
        false, *BB, &Context.I64Type,
        *MConstantInt::get(Context, Context.I64Type, Value));
  }

  // A "variable" atom is bound to whatever MInstruction we hand the matcher.
  // Use Dread on a fresh Variable to model a distinct SSA value per call.
  DreadInstruction *makeDread() {
    Variable *Var = Func.createVariable(&Context.I64Type);
    return Func.createInstruction<DreadInstruction>(
        false, *BB, &Context.I64Type, Var->getVarIdx());
  }

  // Dread reading an arbitrary VarIdx, allowing the test to construct two
  // distinct DreadInstruction pointers that read the SAME variable.
  DreadInstruction *makeDreadOfVar(uint32_t VarIdx) {
    return Func.createInstruction<DreadInstruction>(false, *BB,
                                                    &Context.I64Type, VarIdx);
  }

  BinaryInstruction *makeBinary(Opcode Op, MInstruction *L, MInstruction *R) {
    return Func.createInstruction<BinaryInstruction>(false, *BB, Op,
                                                     &Context.I64Type, L, R);
  }

private:
  CompileContext Context;
  MFunction Func;
  MBasicBlock *BB = nullptr;
};

} // namespace

TEST(ShadowMatcher, MatchVariableAtom) {
  ShadowFixture F;
  auto Lhs = parseShadowLhs("x");
  auto *V = F.makeDread();
  EXPECT_TRUE(matchShadowLhs(*Lhs, *V));
}

TEST(ShadowMatcher, MatchAddXY) {
  ShadowFixture F;
  auto Lhs = parseShadowLhs("(add x y)");
  auto *Inst = F.makeBinary(OP_add, F.makeDread(), F.makeDread());
  EXPECT_TRUE(matchShadowLhs(*Lhs, *Inst));
}

TEST(ShadowMatcher, RejectWrongOpcode) {
  ShadowFixture F;
  auto Lhs = parseShadowLhs("(add x y)");
  auto *Inst = F.makeBinary(OP_sub, F.makeDread(), F.makeDread());
  EXPECT_FALSE(matchShadowLhs(*Lhs, *Inst));
}

TEST(ShadowMatcher, MatchSelfBinding) {
  ShadowFixture F;
  auto Lhs = parseShadowLhs("(and x x)");
  auto *V = F.makeDread();
  auto *Match = F.makeBinary(OP_and, V, V);
  EXPECT_TRUE(matchShadowLhs(*Lhs, *Match));
  auto *NoMatch = F.makeBinary(OP_and, F.makeDread(), F.makeDread());
  EXPECT_FALSE(matchShadowLhs(*Lhs, *NoMatch));
}

TEST(ShadowMatcher, MatchConstZero) {
  ShadowFixture F;
  auto Lhs = parseShadowLhs("(add x 0:i64)");
  auto *WithZero = F.makeBinary(OP_add, F.makeDread(), F.makeConstI64(0));
  EXPECT_TRUE(matchShadowLhs(*Lhs, *WithZero));
  auto *WithOne = F.makeBinary(OP_add, F.makeDread(), F.makeConstI64(1));
  EXPECT_FALSE(matchShadowLhs(*Lhs, *WithOne));
}

TEST(ShadowMatcher, MatchNested) {
  ShadowFixture F;
  auto Lhs = parseShadowLhs("(xor (and x y) (and x y))");
  auto *X = F.makeDread();
  auto *Y = F.makeDread();
  auto *L = F.makeBinary(OP_and, X, Y);
  auto *R = F.makeBinary(OP_and, X, Y);
  auto *Outer = F.makeBinary(OP_xor, L, R);
  EXPECT_TRUE(matchShadowLhs(*Lhs, *Outer));
}

TEST(ShadowMatcher, MatchSelfBindingViaSeparateDreads) {
  // Two distinct DreadInstruction pointers reading the SAME variable must
  // satisfy `(and x x)`. Mirrors production structurallyEqual's OP_dread
  // case (dmir_rewrite.h:869-871).
  ShadowFixture F;
  auto Lhs = parseShadowLhs("(and x x)");
  auto *V1 = F.makeDreadOfVar(0);
  auto *V2 = F.makeDreadOfVar(0);
  EXPECT_NE(V1, V2);
  auto *Inst = F.makeBinary(OP_and, V1, V2);
  EXPECT_TRUE(matchShadowLhs(*Lhs, *Inst));
}

TEST(ShadowBucket, EmptyBucketYieldsNoHits) {
  ShadowRuleBucket B;
  ShadowFixture F;
  auto *Inst = F.makeBinary(OP_add, F.makeDread(), F.makeDread());
  size_t Count = 0;
  B.matchAll(*Inst, [&](const std::string &) { ++Count; });
  EXPECT_EQ(Count, 0u);
}

TEST(ShadowBucket, SingleRuleMatches) {
  ShadowRuleBucket B;
  ShadowRule R;
  R.Name = "test-add";
  R.Lhs = parseShadowLhs("(add x y)");
  R.RootOp = OP_add;
  B.add(std::move(R));

  ShadowFixture F;
  auto *Inst = F.makeBinary(OP_add, F.makeDread(), F.makeDread());
  std::vector<std::string> Hits;
  B.matchAll(*Inst, [&](const std::string &N) { Hits.push_back(N); });
  ASSERT_EQ(Hits.size(), 1u);
  EXPECT_EQ(Hits[0], "test-add");
}

TEST(ShadowBucket, OpcodeDispatchPrunesIrrelevantRules) {
  ShadowRuleBucket B;
  ShadowRule Add;
  Add.Name = "add-rule";
  Add.Lhs = parseShadowLhs("(add x y)");
  Add.RootOp = OP_add;
  B.add(std::move(Add));
  ShadowRule Sub;
  Sub.Name = "sub-rule";
  Sub.Lhs = parseShadowLhs("(sub x y)");
  Sub.RootOp = OP_sub;
  B.add(std::move(Sub));

  ShadowFixture F;
  auto *AddInst = F.makeBinary(OP_add, F.makeDread(), F.makeDread());
  std::vector<std::string> Hits;
  B.matchAll(*AddInst, [&](const std::string &N) { Hits.push_back(N); });
  ASSERT_EQ(Hits.size(), 1u);
  EXPECT_EQ(Hits[0], "add-rule");

  auto *XorInst = F.makeBinary(OP_xor, F.makeDread(), F.makeDread());
  Hits.clear();
  B.matchAll(*XorInst, [&](const std::string &N) { Hits.push_back(N); });
  EXPECT_EQ(Hits.size(), 0u);
}

TEST(ShadowBucket, BucketSizeAccessor) {
  ShadowRuleBucket B;
  ShadowRule R;
  R.Name = "x";
  R.Lhs = parseShadowLhs("(add x y)");
  R.RootOp = OP_add;
  B.add(std::move(R));
  EXPECT_EQ(B.bucketSize(OP_add), 1u);
  EXPECT_EQ(B.bucketSize(OP_sub), 0u);
  EXPECT_EQ(B.totalRules(), 1u);
}

#include <cstdlib>
#include <fstream>
#include <unistd.h>

TEST(ShadowLoader, LoadsTwoCandidatesFromTempJson) {
  char Path[] = "/tmp/shadow_test_XXXXXX.json";
  int Fd = mkstemps(Path, 5);
  ASSERT_GE(Fd, 0);
  close(Fd);
  std::ofstream F(Path);
  F << R"JSON({"version":1,"rules":[
    {"name":"rule-a","status":"candidate","inputs":["x","y"],
     "ir_width":64,"lhs":"(add x y)","rhs":"y",
     "cost":{"lhs":{"dmir_inst":1,"select_depth":0,"adc_chain":0,
                    "runtime_calls":0},
             "rhs":{"dmir_inst":0,"select_depth":0,"adc_chain":0,
                    "runtime_calls":0},
             "delta":{"dmir_inst":-1,"select_depth":0,"adc_chain":0,
                      "runtime_calls":0}},
     "validation":{"modes":["smt"],"coverage":["t"]}},
    {"name":"rule-b","status":"candidate","inputs":["x"],
     "ir_width":64,"lhs":"(not (not x))","rhs":"x",
     "cost":{"lhs":{"dmir_inst":2,"select_depth":0,"adc_chain":0,
                    "runtime_calls":0},
             "rhs":{"dmir_inst":0,"select_depth":0,"adc_chain":0,
                    "runtime_calls":0},
             "delta":{"dmir_inst":-2,"select_depth":0,"adc_chain":0,
                      "runtime_calls":0}},
     "validation":{"modes":["smt"],"coverage":["t"]}}
  ]})JSON";
  F.close();
  ::setenv("DTVM_SHADOW_RULES_JSON", Path, 1);
  const ShadowRuleBucket *B = getShadowRuleBucket();
  ASSERT_NE(B, nullptr);
  EXPECT_EQ(B->totalRules(), 2u);
  EXPECT_EQ(B->bucketSize(OP_add), 1u);
  EXPECT_EQ(B->bucketSize(OP_not), 1u);
  ::unsetenv("DTVM_SHADOW_RULES_JSON");
  ::unlink(Path);
}

#endif // ZEN_ENABLE_DMIR_SHADOW_AUDIT
