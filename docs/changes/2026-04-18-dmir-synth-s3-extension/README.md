# Change: dMIR synth S3 extension — auto-synthesize all 70 production dMIR rules

- **Status**: Implemented
- **Date**: 2026-04-18
- **Tier**: Light

## Overview

Extend the dMIR rule synthesizer (`tools/synthesize_dmir_rules.py`) so that its
output covers 100% of the 70 hand-written production rewrite rules in
`src/compiler/mir/dmir_rewrite_rules.json`. The changes are all in the Python
tooling layer: richer enumeration, a pattern-config import path reusing the
seed-miner config, always-on Z3 verification for pattern pairs, and canonical
dedup against existing rules and commute-variant twins. No C++ or production
compiler pipeline is touched.

## Motivation

The M1-B feasibility study
(`docs/research/directions/peephole-optimization/submissions/experiments/m1b-70rules-synth/report.md`)
found **0/70** alpha-normalized LHS overlap between the 458 synth survivors
and the 70 production rules. Root cause was mechanical, not fundamental:
signature dedup in `ExprBank` discarded structural-equality LHS (`(and x x)`
collapses to `x`), `CONSTANTS` lacked small integers like `2`, and
`BINARY_OPS` excluded `not` / `select` / `shl` / `ushr` / `sshr` as LHS tops.
Each gap is a small, local pipeline addition — Strategy S3 ("Extended
enumeration") from the report, extended with a pattern-config import path
for the structural-equality family that the pure enumerator cannot express.

## Impact

Single module: `tools/` (Python synthesis tooling). No runtime, no C++
compiler code, no header files. Synth output JSON gains a `source` field
(`enumerator` or `pattern_config`) — already accepted by the duck-typed
validator in `tools/test_check_dmir_rewrite_rules.py`.

### Scope changed

**Primary files (3)**:
- `tools/synthesize_dmir_rules.py` (+370 LOC) — expanded LHS tops, depth-2 RHS
  patterns, Z3 select encoder, `expand_pattern_config` integration, always-Z3
  path for pattern pairs, `--no-z3` scope restricted to enumerator, provenance
  `source` field, commute-variant collapse, dedup-against-existing pass.
- `tools/mine_dmir_seed_rules.py` (+13 LOC) — added `__all__` and docstring so
  `synthesize_dmir_rules.py` can import the miner's pattern config as a library.
- `tools/measure_prod_overlap.py` (+120 LOC, new file) — measures prod-70
  coverage on synth output using `canonicalize_expr` for alpha-normalized LHS
  comparison; counts by unique canonical pattern (69 unique of 70 — one
  commutative twin pair).

**New tests (3)**:
- `tools/test_synth_pattern_struct_eq.py` — structural-equality LHS
  (`(and x x)`, `(or x x)`, `(xor x x)`) must survive.
- `tools/test_synth_pattern_coverage.py` — ≥12 specific prod-rule names must
  be discovered end-to-end (regression pin from Task 7).
- `tools/test_synth_commute_dedup.py` — no commute-variant duplicates in final
  output.

## Metrics

### Before (M1-B baseline)

- `0/70` alpha-normalized LHS overlap between synth output and production rules.
- 458 synth candidates, 318 Algorithm-A survivors, none matched a prod rule.

### After (Task 10 final run)

- **Matched prod unique patterns: 69/69 = 100%**
- **Matched prod names: 70/70** (one commutative-twin pair — `or x y` vs
  `or y x` — collapses to a single canonical pattern, which both rules match).
- Total synth rules: 1966 (unique canonical LHS keys: 1964, since two pairs
  share canonical form after alpha-normalization).
- Source split: **1856 enumerator + 110 pattern_config** = 1966.
- Z3 verification: always on for pattern-config pairs. `--no-z3` only skips
  the enumerator's Z3 pass (pattern-config cross-product emits invalid pairs
  that only Z3 can filter, so this path is non-optional).
- Pattern-config pairs: 2964 candidates → 349 Z3-verified → 110 new after
  dedup against enumerator output and the existing `dmir_rewrite_rules.json`.
- Elapsed: ~140s at `--max-depth 2`.

### Test coverage

All 7 Python unit tests pass:

| Test | Status |
|------|--------|
| `tools/test_mine_dmir_seed_rules.py` | PASS |
| `tools/test_mine_dmir_novel_rules.py` | PASS |
| `tools/test_mine_dmir_bootstrap_config.py` | PASS |
| `tools/test_check_dmir_rewrite_rules.py` | PASS (accepts new `source` field) |
| `tools/test_synth_pattern_struct_eq.py` | PASS (new) |
| `tools/test_synth_pattern_coverage.py` | PASS — 12/12 required rules, 69 total matches |
| `tools/test_synth_commute_dedup.py` | PASS — 0 commute duplicates in 1966 rules |

## Risk / Rollback

**Risk: Low.**

- All changes live in `tools/` (Python tooling). No C++ source is touched, no
  production compiler pipeline is changed, no header APIs shift.
- The `source` field is additive. `tools/check_dmir_rewrite_rules.py`
  duck-types it and remains green.
- Z3 always-on for pattern pairs means `--no-z3` no longer produces unverified
  output for the pattern-config path — explicit (reported as a stderr line in
  synth output), not silent.
- The hand-written `src/compiler/mir/dmir_rewrite.h` C++ switch is untouched.
  Synth output remains advisory tooling data, not compiled-in rewrites — the
  same invariant `reference_dmir_rule_spec_vs_runtime.md` documents.

**Rollback**: `git revert` the 11 tool commits on this branch (or
`git reset --hard 04f2c8a` to the branch base). No persistent state change.

## Follow-ups

1. **Not in scope**: integrating the `pattern_config`-sourced 110 rules into
   the hand-coded `src/compiler/mir/dmir_rewrite.h` C++ switch. That is a
   separate code-generation effort and was never part of this tooling change.
2. **Not currently needed**: widening `DEFAULT_SEARCH_CONFIG.base_terms`
   beyond the present set. 100% prod-70 coverage is reached with the current
   terms; adding more would inflate the search space without adding matches.

## References

- Plan: `docs/superpowers/plans/2026-04-18-dmir-synth-s3-extension.md`
- Feasibility study (motivation):
  `docs/research/directions/peephole-optimization/submissions/experiments/m1b-70rules-synth/report.md`
- Direction: `docs/research/directions/peephole-optimization/`
- Related invariant:
  `~/.claude/projects/-home-abmcar-DTVM/memory/reference_dmir_rule_spec_vs_runtime.md`
  (synth output is tooling-layer; runtime rewrites are hand-coded in
  `dmir_rewrite.h`).

## Checklist

- [x] Implementation complete
- [x] Tests added/updated (3 new tests, all green)
- [ ] Module specs in `docs/modules/` updated (N/A — tooling only, no module
      contract change)
- [x] Build and tests pass (7/7 Python tests pass; `tools/format.sh check`
      clean; no C++ touched so no cmake build required)

## Current Branch Note

This change originally covered the 70 scalar-limb dMIR production rules. The
later `u256-xor-self-zero` production rule extends the branch to 71 dMIR rules
and is validated through a separate U256 composite lane:

- scalar synthesis coverage: 70/70 production names
- scalar canonical-pattern coverage: 69/69 because one commutative-twin pair
  shares a canonical representative
- U256 synthesis coverage: 1/1 production names after the U256 lane is added
- total dMIR production coverage: 71/71 names across two synthesis modes after
  both coverage tests pass
