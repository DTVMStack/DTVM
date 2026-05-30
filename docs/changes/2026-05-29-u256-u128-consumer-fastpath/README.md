# Change: U128 consumer fast-path — measurement and decision (de-scoped)

- **Status**: Implemented (measurement + decision; no consumer fast path added)
- **Date**: 2026-05-29
- **Tier**: Light

## Overview

The audit recommended adding U128 half-width consumer fast paths (e.g. 128×128→256
MUL, 128/64 DIV) only after counters prove that analyzer-proven `U128` operands
actually reach those consumers at hot sites. This change adds the measurement
instrumentation, runs it, and records the data-driven decision: **do not add the
U128 consumer fast paths now** — the opportunity essentially never occurs.

## Motivation

The u256 fast-path audit (2026-05-29) found the `U128` lattice tier "nearly
inert — only AND consumes a proven-U128 operand". A U128 half-width MUL/DIV/MOD
path is a larger change with real multi-limb half-width correctness surface, so
the audit's priority ranking placed it last, gated on empirical confirmation.

## Instrumentation added

`MemoryCompileStats` gains `MulU128OpportunityCount` / `DivU128OpportunityCount`
/ `ModU128OpportunityCount` (`evm_mir_compiler.h:1290-1292`), incremented at the
full-limb fallback of `handleMul` / `handleDiv` / `handleMod`
(`evm_mir_compiler.cpp:1984 / 2149 / 2280`) when one operand has proven range
`U128` and the other is `<= U128` — i.e. a half-width path could have applied.
All `#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING`-gated (zero default-build impact);
reported in `[EVM-ARITH-SUMMARY]`.

## Measurement (logging build, `build-arithlog/`)

| Workload | mul_u128_opp | div_u128_opp | mod_u128_opp |
|---|---|---|---|
| snailtracer | 0 | 0 | 0 |
| blake2b_shifts | 0 | 0 | 0 |
| weierstrudel | 0 | 0 | 0 |
| swap_math | 0 | 0 | 0 |
| sha1_divs | 1 | 0 | 0 |
| 10 micro benchmarks (incl. narrow_compare_u128 / _u64) | 0 | 0 | 0 |

Totals across 15 workloads: **mul = 1, div = 0, mod = 0.** Even
`narrow_compare_u128`, which explicitly produces U128 ranges, shows 0 — those
U128 values feed comparisons, not arithmetic.

## Decision: de-scope

A proven-`U128` operand reaches a MUL/DIV/MOD full-limb fallback exactly once
across all workloads; DIV/MOD never. A U128 half-width consumer fast path would
not pay off, confirming the audit's static finding (only AND consumes a
proven-U128 operand today). The instrumentation is retained so the decision can
be revisited if future workloads change the picture.

## Checklist

- [x] Implementation complete (measurement instrumentation; no consumer path)
- [x] Tests added/updated — covered by regression; counters are macro-gated
- [x] Module specs in `docs/modules/` updated (if affected) — none affected
- [x] Build and tests pass — default (logging OFF) multipass `evmone-unittests`
      223/223, `evmone-statetest -k fork_Cancun` 2723/2723; logging build emits
      the `*_u128_opportunity` counts above.
