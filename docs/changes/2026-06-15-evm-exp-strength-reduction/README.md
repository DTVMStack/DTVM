# Change: Strength-reduce EXP for constant power-of-two bases

- **Status**: Proposed
- **Date**: 2026-06-15
- **Tier**: Light

## Overview

Add compile-time fast paths to `handleExp` for a constant base:

- `EXP(base, 0) -> 1` (dynamic base, constant exponent 0; including `0 ** 0 == 1`)
- `EXP(base, 1) -> base` (dynamic base, constant exponent 1)
- `EXP(2^k, x) -> (k*x >= 256) ? 0 : 1 << (k*x)` for any constant power-of-two
  base with a dynamic exponent

Previously every EXP whose operands were not both constant emitted the inline
square-and-multiply loop.

## Motivation

The general path runs a square-and-multiply loop whose cost grows with the
exponent's bit width. For a constant power-of-two base the result is a single
shift, so the loop is replaceable by one shift plus a bounds select. This covers
the `2 ** x` and `256 ** x` forms (the latter is the Solidity storage-packing
idiom).

## Impact

- Module: `src/compiler/evm_frontend` (EVM MIR builder, `handleExp`).
- Semantics preserved: `(2^k)^x = 2^(k*x) mod 2^256`. For `k >= 2`, `k*x` wraps
  modulo `2^256` on large `x`, so the result is guarded by an explicit
  `x >= ceil(256/k) -> 0` test rather than the shift primitive's own `>= 256`
  check; below that threshold `k*x` is exact and `< 256`.
- EIP-160 dynamic gas unchanged: it depends only on the exponent and is charged
  by the unchanged general path, so gas is byte-for-byte identical.
- No effect on other EXP forms or other opcodes.

## Tests

No dedicated unit test ships with this change. During development the rewrite was
checked with a differential harness — multipass JIT output against the
interpreter and against an independent bit-placement `1 << x` table, across
power-of-two bases `2` to `2^255`, exponents straddling each `k*x = 256`
threshold, the overflow-guard case (base `256`, `x = 2^253` wraps `8*x` to 0),
and offset-free EIP-160 gas deltas across Cancun and pre-Spurious-Dragon — with
no divergence. Regression coverage relies on the EEST state-test corpus and the
multipass unit suite.

Validation: 223 multipass unit tests, 2723 state tests (`-k fork_Cancun`),
`tools/format.sh check` clean, 0 new compiler warnings.

## Checklist

- [x] Implementation complete
- [ ] Tests added/updated — verified by a differential harness during
  development; no unit test retained (see Tests)
- [ ] Module specs in `docs/modules/` updated (if affected) — not affected
- [x] Build and tests pass
