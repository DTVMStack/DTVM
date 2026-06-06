// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#ifdef ZEN_ENABLE_DMIR_SHADOW_AUDIT

#include "compiler/mir/instructions.h"
#include "compiler/mir/opcode.h"
#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace COMPILER {

// Atom kinds recognized by the shadow LHS interpreter.
enum class ShadowAtomKind : uint8_t {
  Variable,     // unbound name; first occurrence binds
  ConstZero,    // 0:i64
  ConstOne,     // 1:i64
  ConstAllOnes, // all_ones:i64 / 0xFFFFFFFFFFFFFFFF
  ConstInteger, // any other N:i64 — matched via constant value comparison
};

struct ShadowNode;
using ShadowNodePtr = std::unique_ptr<ShadowNode>;

// One node of a parsed LHS S-expression tree.
// If `IsAtom` is true, atom fields are valid; else children + Op are valid.
struct ShadowNode {
  bool IsAtom;
  // Atom payload
  ShadowAtomKind AtomKind = ShadowAtomKind::Variable;
  std::string AtomName;        // variable name, valid iff AtomKind==Variable
  uint64_t AtomConstValue = 0; // valid iff AtomKind==ConstInteger
  // Inner-node payload
  Opcode Op = OP_placeholder;
  std::vector<ShadowNodePtr> Children;
};

// Parse an S-expression string into a ShadowNode tree.
// Throws std::runtime_error on malformed input or unsupported opcode.
// Inputs come from a curated 1432-rule corpus, so the type-suffix portion of
// `N:i64` atoms is consumed but not validated; non-i64 widths never appear.
ShadowNodePtr parseShadowLhs(const std::string &Sexpr);

// Match a parsed LHS tree against an MInstruction subtree.
// Returns true iff Inst matches LhsRoot. Variable bindings (first occurrence
// binds; subsequent occurrence requires structural equality with the bound
// value, mirroring production's per-opcode comparison in
// DMirRewritePass::structurallyEqual) are kept in a per-call scratch map.
bool matchShadowLhs(const ShadowNode &LhsRoot, const MInstruction &Inst);

struct ShadowRule {
  std::string Name; // candidate name, e.g. "synth-and-xor-000"
  ShadowNodePtr Lhs;
  Opcode RootOp;
};

// Buckets candidate matchers by their LHS root opcode.
class ShadowRuleBucket {
public:
  // Register a parsed rule. Caller transfers ownership.
  void add(ShadowRule Rule);

  // Iterate all candidate rules whose RootOp == Inst.getOpcode() and
  // try matching each. Calls OnHit(name) for every match. Atom-rooted
  // candidate rules are not in any bucket (those don't exist in the
  // 1432 corpus — verified — but the API guards against future schema).
  void matchAll(const MInstruction &Inst,
                const std::function<void(const std::string &)> &OnHit) const;

  size_t bucketSize(Opcode Op) const;
  size_t totalRules() const;

private:
  std::unordered_map<Opcode, std::vector<ShadowRule>> ByOp;
  size_t Total = 0;
};

// Process-singleton loader. First call reads DTVM_SHADOW_RULES_JSON,
// parses every candidate, populates a ShadowRuleBucket, and returns it.
// Subsequent calls return the same instance. Returns nullptr when the
// env var is unset (shadow disabled at runtime).
const ShadowRuleBucket *getShadowRuleBucket();

// Per-candidate hit counters, indexed by AuditPhase ([0]=OrigIR, [1]=PostProd).
// Keyed by candidate name. Atomic counters allow lock-free increments,
// but the maps themselves are NOT safe under concurrent insertion —
// shadow audit currently runs single-threaded inside the multipass JIT.
using ShadowHitMap = std::unordered_map<std::string, std::atomic<uint64_t>>;
inline std::array<ShadowHitMap, 2> g_dmirShadowHits;

} // namespace COMPILER

#endif // ZEN_ENABLE_DMIR_SHADOW_AUDIT
