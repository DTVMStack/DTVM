// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifdef ZEN_ENABLE_DMIR_SHADOW_AUDIT

#include "compiler/mir/pass/dmir_shadow_runtime.h"

#include "compiler/mir/constants.h"
#include "compiler/mir/structural_equality.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

#include <llvm/Support/Casting.h>

namespace COMPILER {

namespace {

// Tokenize an s-expression: parens are single tokens, others are
// whitespace-separated atoms. No string-literal support (not needed).
std::vector<std::string> tokenize(const std::string &Sexpr) {
  std::vector<std::string> Tokens;
  std::string Cur;
  for (char C : Sexpr) {
    if (C == '(' || C == ')') {
      if (!Cur.empty()) {
        Tokens.push_back(Cur);
        Cur.clear();
      }
      Tokens.push_back(std::string(1, C));
    } else if (std::isspace(static_cast<unsigned char>(C))) {
      if (!Cur.empty()) {
        Tokens.push_back(Cur);
        Cur.clear();
      }
    } else {
      Cur += C;
    }
  }
  if (!Cur.empty())
    Tokens.push_back(Cur);
  return Tokens;
}

Opcode opcodeFromName(const std::string &Name) {
  if (Name == "add")
    return OP_add;
  if (Name == "sub")
    return OP_sub;
  if (Name == "mul")
    return OP_mul;
  if (Name == "and")
    return OP_and;
  if (Name == "or")
    return OP_or;
  if (Name == "xor")
    return OP_xor;
  if (Name == "not")
    return OP_not;
  if (Name == "shl")
    return OP_shl;
  if (Name == "sshr")
    return OP_sshr;
  if (Name == "ushr")
    return OP_ushr;
  // adc/sbb/select are filtered out at Phase 0b conversion time.
  throw std::runtime_error("shadow: unsupported opcode in LHS: " + Name);
}

ShadowNodePtr parseAtomToken(const std::string &Tok) {
  auto Node = std::make_unique<ShadowNode>();
  Node->IsAtom = true;
  size_t Colon = Tok.find(':');
  if (Colon == std::string::npos) {
    Node->AtomKind = ShadowAtomKind::Variable;
    Node->AtomName = Tok;
    return Node;
  }
  std::string Value = Tok.substr(0, Colon);
  if (Value == "0") {
    Node->AtomKind = ShadowAtomKind::ConstZero;
  } else if (Value == "1") {
    Node->AtomKind = ShadowAtomKind::ConstOne;
  } else if (Value == "all_ones" || Value == "18446744073709551615") {
    Node->AtomKind = ShadowAtomKind::ConstAllOnes;
  } else {
    Node->AtomKind = ShadowAtomKind::ConstInteger;
    Node->AtomConstValue = std::strtoull(Value.c_str(), nullptr, 0);
  }
  return Node;
}

ShadowNodePtr parseFrom(const std::vector<std::string> &Tokens, size_t &Idx) {
  if (Idx >= Tokens.size())
    throw std::runtime_error("shadow: unexpected end of LHS");
  const std::string &Tok = Tokens[Idx];
  if (Tok == "(") {
    ++Idx;
    if (Idx >= Tokens.size())
      throw std::runtime_error("shadow: unterminated paren in LHS");
    auto Node = std::make_unique<ShadowNode>();
    Node->IsAtom = false;
    Node->Op = opcodeFromName(Tokens[Idx++]);
    while (Idx < Tokens.size() && Tokens[Idx] != ")") {
      Node->Children.push_back(parseFrom(Tokens, Idx));
    }
    if (Idx >= Tokens.size() || Tokens[Idx] != ")")
      throw std::runtime_error("shadow: missing close-paren in LHS");
    ++Idx;
    return Node;
  }
  if (Tok == ")")
    throw std::runtime_error("shadow: unexpected ')' in LHS");
  ++Idx;
  return parseAtomToken(Tok);
}

} // namespace

ShadowNodePtr parseShadowLhs(const std::string &Sexpr) {
  auto Tokens = tokenize(Sexpr);
  if (Tokens.empty())
    throw std::runtime_error("shadow: empty LHS");
  size_t Idx = 0;
  auto Node = parseFrom(Tokens, Idx);
  if (Idx != Tokens.size())
    throw std::runtime_error("shadow: trailing tokens in LHS");
  return Node;
}

namespace {

// Read the integer constant payload of an MInstruction. Returns nullopt when
// the instruction is not an OP_const integer.
std::optional<llvm::APInt> constantIntValue(const MInstruction &Inst) {
  if (Inst.getOpcode() != OP_const)
    return std::nullopt;
  const auto &CI = llvm::cast<ConstantInstruction>(Inst);
  const auto *Int = llvm::dyn_cast<MConstantInt>(&CI.getConstant());
  if (!Int)
    return std::nullopt;
  return Int->getValue();
}

bool matchAtom(
    const ShadowNode &Atom, const MInstruction &Inst,
    std::unordered_map<std::string, const MInstruction *> &Bindings) {
  switch (Atom.AtomKind) {
  case ShadowAtomKind::Variable: {
    auto It = Bindings.find(Atom.AtomName);
    if (It == Bindings.end()) {
      Bindings[Atom.AtomName] = &Inst;
      return true;
    }
    // Same variable used twice in LHS means same MIR value. Production's
    // structurallyEqual treats two distinct DreadInstruction pointers reading
    // the same variable as equal; we mirror that to avoid underreporting hits
    // when frontend lowering emits separate dread instructions per use.
    return structurallyEqualMInstruction(*It->second, Inst);
  }
  case ShadowAtomKind::ConstZero: {
    auto V = constantIntValue(Inst);
    return V && V->isZero();
  }
  case ShadowAtomKind::ConstOne: {
    auto V = constantIntValue(Inst);
    return V && V->isOne();
  }
  case ShadowAtomKind::ConstAllOnes: {
    auto V = constantIntValue(Inst);
    return V && V->isAllOnes();
  }
  case ShadowAtomKind::ConstInteger: {
    auto V = constantIntValue(Inst);
    return V && V->getZExtValue() == Atom.AtomConstValue;
  }
  }
  return false;
}

bool matchNode(
    const ShadowNode &Node, const MInstruction &Inst,
    std::unordered_map<std::string, const MInstruction *> &Bindings) {
  if (Node.IsAtom)
    return matchAtom(Node, Inst, Bindings);
  if (Inst.getOpcode() != Node.Op)
    return false;
  if (Inst.getNumOperands() != Node.Children.size())
    return false;
  for (OperandNum I = 0; I < Inst.getNumOperands(); ++I) {
    if (!matchNode(*Node.Children[I], *Inst.getOperand(I), Bindings))
      return false;
  }
  return true;
}

} // namespace

bool matchShadowLhs(const ShadowNode &LhsRoot, const MInstruction &Inst) {
  std::unordered_map<std::string, const MInstruction *> Bindings;
  return matchNode(LhsRoot, Inst, Bindings);
}

void ShadowRuleBucket::add(ShadowRule Rule) {
  Opcode Op = Rule.RootOp;
  ByOp[Op].push_back(std::move(Rule));
  ++Total;
}

void ShadowRuleBucket::matchAll(
    const MInstruction &Inst,
    const std::function<void(const std::string &)> &OnHit) const {
  auto It = ByOp.find(Inst.getOpcode());
  if (It == ByOp.end())
    return;
  for (const auto &R : It->second) {
    if (matchShadowLhs(*R.Lhs, Inst))
      OnHit(R.Name);
  }
}

size_t ShadowRuleBucket::bucketSize(Opcode Op) const {
  auto It = ByOp.find(Op);
  return It == ByOp.end() ? 0u : It->second.size();
}

size_t ShadowRuleBucket::totalRules() const { return Total; }

namespace {

// Lightweight extractor: from the bytes between `{...}` of one rule object
// pull out the value of "name" and "lhs". Both are expected to be JSON
// strings whose contents do not include embedded escapes — the converter
// emits names from `[A-Za-z0-9_-]` and LHS S-exprs that use only
// `(`, `)`, ` `, `:`, and the same character set, so a `\"` inside a
// value would round-trip incorrectly here. This avoids a JSON dependency;
// if the corpus ever grows escape sequences, swap in a real parser.
bool extractField(const std::string &Obj, const std::string &Key,
                  std::string &Out) {
  std::string Needle = "\"" + Key + "\"";
  size_t I = 0;
  while (true) {
    I = Obj.find(Needle, I);
    if (I == std::string::npos)
      return false;
    // A `"Key"` token only counts as a JSON key if followed (after optional
    // whitespace) by `:`. Otherwise it is a string value and we keep
    // searching — this prevents collisions like an `"inputs":["name", ...]`
    // array element shadowing the real `"name":` key.
    size_t After = I + Needle.size();
    while (After < Obj.size() &&
           std::isspace(static_cast<unsigned char>(Obj[After])))
      ++After;
    if (After < Obj.size() && Obj[After] == ':') {
      I = After + 1;
      while (I < Obj.size() && std::isspace(static_cast<unsigned char>(Obj[I])))
        ++I;
      break;
    }
    I = After;
  }
  if (I >= Obj.size() || Obj[I] != '"')
    return false;
  size_t Start = I + 1;
  size_t J = Obj.find('"', Start);
  if (J == std::string::npos)
    return false;
  Out = Obj.substr(Start, J - Start);
  return true;
}

std::vector<std::string> splitRuleObjects(const std::string &Body) {
  std::vector<std::string> Out;
  int Depth = 0;
  size_t Start = std::string::npos;
  for (size_t I = 0; I < Body.size(); ++I) {
    char C = Body[I];
    if (C == '{') {
      if (Depth == 0)
        Start = I;
      ++Depth;
    } else if (C == '}') {
      --Depth;
      if (Depth == 0 && Start != std::string::npos) {
        Out.push_back(Body.substr(Start, I - Start + 1));
        Start = std::string::npos;
      }
    }
  }
  return Out;
}

std::unique_ptr<ShadowRuleBucket> buildBucketFromFile(const std::string &Path) {
  auto Bucket = std::make_unique<ShadowRuleBucket>();
  std::ifstream F(Path);
  if (!F)
    return Bucket;
  std::stringstream Ss;
  Ss << F.rdbuf();
  std::string Body = Ss.str();

  size_t RulesPos = 0;
  while (true) {
    RulesPos = Body.find("\"rules\"", RulesPos);
    if (RulesPos == std::string::npos)
      return Bucket;
    size_t After = RulesPos + 7; // length of "\"rules\""
    while (After < Body.size() &&
           std::isspace(static_cast<unsigned char>(Body[After])))
      ++After;
    if (After < Body.size() && Body[After] == ':')
      break;
    RulesPos = After;
  }
  size_t LBracket = Body.find('[', RulesPos);
  if (LBracket == std::string::npos)
    return Bucket;
  size_t RBracket = std::string::npos;
  int Depth = 0;
  for (size_t I = LBracket; I < Body.size(); ++I) {
    if (Body[I] == '[') {
      ++Depth;
    } else if (Body[I] == ']') {
      --Depth;
      if (Depth == 0) {
        RBracket = I;
        break;
      }
    }
  }
  if (RBracket == std::string::npos)
    return Bucket;
  std::string Array = Body.substr(LBracket + 1, RBracket - LBracket - 1);

  for (const std::string &ObjStr : splitRuleObjects(Array)) {
    std::string Name, Lhs;
    if (!extractField(ObjStr, "name", Name))
      continue;
    if (!extractField(ObjStr, "lhs", Lhs))
      continue;
    try {
      ShadowRule R;
      R.Name = Name;
      R.Lhs = parseShadowLhs(Lhs);
      if (R.Lhs->IsAtom)
        continue;
      R.RootOp = R.Lhs->Op;
      Bucket->add(std::move(R));
    } catch (const std::exception &) {
      continue;
    }
  }
  return Bucket;
}

} // namespace

const ShadowRuleBucket *getShadowRuleBucket() {
  // C++11 magic-static: the lambda runs exactly once, race-free, even under
  // concurrent first-call.
  static const std::unique_ptr<ShadowRuleBucket> Cache = []() {
    const char *Path = std::getenv("DTVM_SHADOW_RULES_JSON");
    if (!Path || !*Path)
      return std::unique_ptr<ShadowRuleBucket>(nullptr);
    auto Bucket = buildBucketFromFile(Path);
    if (std::getenv("DTVM_SHADOW_DEBUG") && Bucket) {
      std::fprintf(stderr, "[dmir-shadow] loaded %zu rules from %s\n",
                   Bucket->totalRules(), Path);
    }
    return Bucket;
  }();
  return Cache.get();
}

} // namespace COMPILER

#endif // ZEN_ENABLE_DMIR_SHADOW_AUDIT
