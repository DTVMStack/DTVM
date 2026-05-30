# Change: u256 result-range narrowing for DIV/MOD/ADD/MUL/ADDMOD/MULMOD

- **Status**: Implemented
- **Date**: 2026-05-29
- **Tier**: Light

## Overview

Narrow the result `ValueRange` of several u256 arithmetic fast paths that were
conservatively returning `U256` despite a provably tighter bound, so downstream
`bothFitU64` / narrow fast paths fire more often. All narrowings are sound and
purely additive (they only set result metadata; lowering is unchanged).

## Motivation

The u256 fast-path audit (2026-05-29) found the largest missed-precision gap was
builder result ranges left at the default `U256` even though the `EVMRangeAnalyzer`
already proves tighter bounds (`evm_analyzer.h:1537-1560`). The builder and
analyzer were asymmetric — most notably ADDMOD. This change brings the builder
in line with the analyzer's already-proven transfer functions.

## Impact

Module `src/compiler/evm_frontend` (`handleDiv`/`handleMod` helpers, `handleMul`,
`handleAddU64Const`, `handleAddMod`, `handleMulMod`). Each narrowing is sound:

| Path | New result range | Soundness |
|---|---|---|
| `handleModU64Divisor` (MOD by u64 const) | `U64` | remainder < divisor ≤ 2⁶⁴-1 |
| `handleDivU64Dividend` / `handleModU64Dividend` | `U64` | result ≤ u64 dividend |
| `handleDivU64Divisor` + DIV-by-u64-const CFG join | dividend's range | quotient ≤ dividend (d≥1) |
| MUL 4×1 (u64 const × value) | `U128` if other operand `U64`, else `U256` | u64×u64 < 2¹²⁸ |
| `handleAddU64Const` (value + u64 const) | `U128` if value `U64`, else `U256` | u64+u64 < 2⁶⁵ |
| ADDMOD / MULMOD | modulus operand's range | result < modulus |

SDIV/SMOD are deliberately **not** narrowed — a negative signed result occupies
the full 256 bits, so no narrowing is sound.

## Notes

- The DIV-by-u64-const path for a non-constant dividend uses a `KnownU64BB`/`SlowBB`
  CFG split and returns the merged result via `loadResult()`; the narrowing had to
  be applied at that join return, not only at `handleDivU64Divisor`'s own return.

## Measurement (counter before/after, logging build)

> Note: the `[EVM-ARITH-SUMMARY]` counters used below are added by the separate
> `evm-arith-fastpath-counters` change. The numbers were measured with both
> changes applied and are not reproducible from this PR alone.

Probe `MOD(calldata_x, 7) + MOD(calldata_y, 11)`: both MOD-by-u64-const producers
now narrow to `U64`, so the downstream ADD takes the `bothFitU64` range path —
`[EVM-ARITH-SUMMARY]` reports `add_fast_range_u64=1, add_full=0`. The
logically-equivalent un-narrowed shape `ADD(calldata_x, calldata_y)` (raw U256
operands, mirroring pre-narrowing where MOD→U256) reports `add_full=1,
add_fast_range_u64=0`. The narrowing flips the same downstream ADD from the
full-limb path to the single-instruction range path.

## Checklist

- [x] Implementation complete (9 narrowing sites)
- [x] Tests added/updated — analyzer transfer-rule tests (see hardening change);
      builder-side ranges exercised end-to-end by the multipass `evmone` suites
- [x] Module specs in `docs/modules/` updated (if affected) — none affected
- [x] Build and tests pass — multipass `evmone-unittests` 223/223, multipass
      `evmone-statetest -k fork_Cancun` 2723/2723, `evmRangeAnalyzerTests` 49/49.
      Counter before/after downstream-hit
      comparison: see measurement note below.
