// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#ifdef ZEN_ENABLE_DMIR_SHADOW_AUDIT

#include "compiler/mir/function.h"
#include "compiler/mir/pass/dmir_shadow_runtime.h"
#include <cstdio>
#include <cstdlib>
#include <unordered_set>

namespace COMPILER {

// Audit phase tag for which counter table receives hits.
//   OrigIR   — pre-rewrite snapshot (run before DMirRewritePass).
//   PostProd — post-production snapshot (run after DMirRewritePass).
enum class AuditPhase : uint8_t { OrigIR = 0, PostProd = 1 };

// Match-only pass: walks the expression tree rooted at every basic-block
// statement, dispatches through ShadowRuleBucket, and increments per-
// candidate hit counters in g_dmirShadowHits[Phase]. The pass never mutates
// IR. When DTVM_SHADOW_RULES_JSON is unset the loader returns nullptr and
// runOnMFunction is a no-op.
//
// Why recursive: MBasicBlock::Statements only contains opcodes for which
// OpcodeDesc::isStatement returns true (dassign / phi / return / store).
// Expression instructions like OP_or, OP_and, OP_const, OP_dread are
// reached only through operand pointers. Production's DMirRewritePass
// mirrors this by recursing through operands in rewriteExprTree
// (dmir_rewrite.h:194). To match production's "138 dmir_or_zero hits on
// sha1" we walk the same tree and dedupe by instruction pointer.
class DMirShadowAuditPass {
public:
  void runOnMFunction(MFunction &F, AuditPhase Phase) {
    const ShadowRuleBucket *Bucket = getShadowRuleBucket();
    if (!Bucket) {
      return;
    }
    auto &Counters = g_dmirShadowHits[static_cast<size_t>(Phase)];

    bool DebugEnabled = std::getenv("DTVM_SHADOW_DEBUG") != nullptr;
    uint64_t Visited = 0;
    uint64_t OnHits = 0;
    uint64_t StatementsSeen = 0;

    // Per-BB Seen set mirrors production's RewriteCache.clear() at each
    // BB boundary (dmir_rewrite.h:176). Cross-BB DAG sharing is counted
    // separately per BB visit, matching production's tryRewrite cadence
    // so prod_hits and shadow_*_hits are directly comparable.
    for (MBasicBlock *BB : F) {
      std::unordered_set<const MInstruction *> Seen;
      for (MInstruction *Stmt : *BB) {
        ++StatementsSeen;
        visit(*Stmt, *Bucket, Counters, Seen, Visited, OnHits);
      }
    }

    if (DebugEnabled) {
      std::fprintf(stderr,
                   "[shadow] runOnMFunction phase=%d func=%u stmts=%llu "
                   "visited=%llu on_hits=%llu\n",
                   static_cast<int>(Phase), F.getFuncIdx(),
                   static_cast<unsigned long long>(StatementsSeen),
                   static_cast<unsigned long long>(Visited),
                   static_cast<unsigned long long>(OnHits));
    }
  }

private:
  // Depth-first walk over an expression tree rooted at Inst. Dedupes by
  // pointer within a single BB so DAG sharing (one dread feeding multiple
  // statements within the BB) does not double-count, matching production's
  // per-BB RewriteCache cadence.
  void visit(MInstruction &Inst, const ShadowRuleBucket &Bucket,
             ShadowHitMap &Counters,
             std::unordered_set<const MInstruction *> &Seen, uint64_t &Visited,
             uint64_t &OnHits) {
    if (!Seen.insert(&Inst).second) {
      return;
    }
    ++Visited;

    // Recurse first to mirror production's post-order traversal in
    // rewriteExprTree (operands rewritten before parent). Atom-rooted
    // candidates would be impossible to match anyway since the LHS root
    // must have an opcode, but operand recursion is what makes us see
    // every OR / ADD / ... node nested under a statement.
    for (uint32_t I = 0; I < Inst.getNumOperands(); ++I) {
      MInstruction *Operand = Inst.getOperand(I);
      if (Operand) {
        visit(*Operand, Bucket, Counters, Seen, Visited, OnHits);
      }
    }

    Bucket.matchAll(Inst, [&](const std::string &Name) {
      // unordered_map uses node storage, so operator[] default-constructs
      // std::atomic<uint64_t> (zero-initialized) on first insert.
      // Subsequent calls return a reference to the same node. P0 verified
      // the multipass JIT compile path is single-threaded; the only
      // hazard would be cross-MFunction concurrency, which does not
      // occur in the current pipeline.
      Counters[Name].fetch_add(1, std::memory_order_relaxed);
      ++OnHits;
    });
  }
};

} // namespace COMPILER

#endif // ZEN_ENABLE_DMIR_SHADOW_AUDIT
