# Change: Regression hardening for u256 value-range narrowing

- **Status**: Implemented
- **Date**: 2026-05-29
- **Tier**: Light

## Overview

Lock in the soundness and precision of the u256 value-range machinery with
tests and a compile-time invariant, and repair the orphan-`.evm.hex` hazard that
let an `evmInterpTests` regression fail invisibly.

## Motivation

The u256 fast-path audit (2026-05-29) found three real but local gaps:
- No MIR-builder unit test pinned the *result* range of the consumer-side
  DIV/MOD/MUL/ADD fast paths — a regression that widened a narrowed range back to
  `U256` would pass every existing test (the analyzer tests never invoke the MIR
  builder).
- The `EVMValueRange` enum-ordering invariant (`U64 < U128 < U256`), on which
  `std::min`/`std::max` and the dataflow meet depend, had no `static_assert`.
- Several analyzer transfer rules sit in their own switch case with no pinned
  sibling (genuinely silent if their range assignment regresses).

## Impact

- `src/compiler/evm_frontend/evm_value_range.h` — `static_assert` pinning the
  enum width ordering.
- `src/tests/evm_jit_frontend_tests.cpp` — `EVMMirBuilderConsumerRangeTest`
  pinning the DIV/MOD/MUL/ADD/ADDMOD/MULMOD result ranges (validates the
  narrowing change). This test caught that the DIV-by-u64-const CFG-join path was
  not narrowed before any suite ran.
- `src/tests/evm_range_analyzer_tests.cpp` — transfer-rule tests for
  `BYTE`(→U64), `NOT`/`EXP`/`SIGNEXTEND`/`SHL`(→U256).
- `tests/evm_asm/` — the `.easm`/`.expected` sources were present but their
  generated `.evm.hex` (gitignored) were missing for 7 fixtures, so the
  `Issue488_PCAsAddmodAugend` regression test failed to open its hex. Regenerated
  all `.evm.hex` via `tools/easm2bytecode.sh` (the standard pre-test step). The
  new `u256_iszero_add_loop` `.easm`/`.expected` sources should be committed with
  this change (they are interpreter-level coverage; the multipass producer-range
  guard remains the C++ unit tests).

## Checklist

- [x] Implementation complete
- [x] Tests added/updated — MIR-builder + analyzer transfer tests
- [x] Module specs in `docs/modules/` updated (if affected) — none affected
- [x] Build and tests pass — `evmJitFrontendTests` 17/17, `evmRangeAnalyzerTests`
      49/49, `evmInterpTests` 169/169; `static_assert` compiles.
