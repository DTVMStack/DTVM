# Change: reduce private tiering cold work and fold scalar loads

- **Status**: Implemented; performance review in progress
- **Date**: 2026-11-07
- **Tier**: Light

## Overview

Combine demand-driven private tiering bookkeeping with conservative scalar SSE
load folding. Keep existing opt-in controls, heat/benefit thresholds, compilation
budgets and monotonic publication. Do not globally enable private promotion.

## Motivation

Post-645 experiments locate pi(1000) in a spilling FastRA private helper; existing
promotion recovers about 11% but costs a few percent on pi(1) even without
admission. bicg's Greedy steady-state kernel remains about 5% behind Wasmtime45;
its generated code uses separate scalar loads where WT folds memory operands.

## Implementation and validation plan

1. Defer private eligibility/bookkeeping and spill metadata until a demanded
   function can actually use it; skip irrelevant EVM high-multiply traversal
   through conservative creation-time presence information.
2. Fold adjacent, uniquely consumed f32/f64 loads into matching SSE arithmetic,
   preserving operand order, trap order, exact width and register use lists.
3. Build separate cold-only/combined artifacts against fixed main.
   Verify CgIR structure, arithmetic edge cases, side effects and OOB traps;
   exercise private policy budgets and concurrent publication tests.
4. Measure main, candidate and WT45, with allocation-mode/feature ablations;
   repeat pi cold/hot and bicg same-instance phases, then WAPM/PolyBench regression
   coverage. Profiles, builds and tests run separately from formal timing.
5. Review final changes, publish evidence and create an upstream PR.

## Checklist

- [x] Implement both components
- [x] Correctness and publication tests pass
- [x] Confirm native mechanism and independent timing
- [x] Review and document limits
- [ ] Create upstream PR

## Results and current merge blocker

See [REPORT.md](REPORT.md) and `evidence/` for process-level samples,
artifact/input hashes and full-suite tables. Native bicg instructions decreased
22 -> 20, but its warm kernel has no established timing gain and remains behind
Wasmtime 45. The 31-process syr2k follow-up shows a small regression, but the independent
21-process ablation does not reproduce it and the hottest native loop is
byte-identical. Both outcomes are retained as a draft performance concern.

An upstream PR creation attempt with both the GitHub connector and configured
`gh` credential returned HTTP/GraphQL 403, `Resource not accessible by
integration`. Branch is pushed to `zoowii:perf/private-tiering-load-folding`;
no PR number has been assigned. Repository permissions alone do not grant the
integration permission to create pull requests.
