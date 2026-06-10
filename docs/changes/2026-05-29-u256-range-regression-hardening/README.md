# Change: Regression hardening for u256 value-range narrowing

- **Status**: Implemented
- **Date**: 2026-05-29
- **Tier**: Light

## Overview

Lock in the soundness and precision of the u256 value-range machinery with
tests and a compile-time invariant, and repair the orphan-`.evm.hex` hazard that
let an `evmInterpTests` regression fail invisibly.

## Motivation

The u256 fast-path audit (2026-05-29) found two local gaps:
- The `EVMValueRange` enum-ordering invariant (`U64 < U128 < U256`), on which
  `std::min`/`std::max` and the dataflow meet depend, had no `static_assert`.
- Several analyzer transfer rules sit in their own switch case with no pinned
  sibling (genuinely silent if their range assignment regresses).

## Impact

- `src/compiler/evm_frontend/evm_value_range.h` — `static_assert` pinning the
  enum width ordering.
- `src/tests/evm_range_analyzer_tests.cpp` — transfer-rule tests for
  `BYTE`(→U64), `NOT`/`EXP`/`SIGNEXTEND`/`SHL`(→U256). The analyzer transfer rules
  mirror the builder's narrowings, and the builder-side ranges are additionally
  exercised end-to-end by the full multipass `evmone` suites (a wrong narrowing
  would surface as a state-test miscompile). A standalone MIR-builder unit test
  was prototyped but dropped: calling the lowering handlers outside the full
  compilation pipeline trips an AddressSanitizer use-after-poison in the function
  arena allocator, so it is not a supported test pattern.
- `tests/evm_asm/` — the `.easm`/`.expected` sources were present but their
  generated `.evm.hex` (gitignored) were missing for 7 fixtures, so the
  `Issue488_PCAsAddmodAugend` regression test failed to open its hex. Regenerated
  all `.evm.hex` via `tools/easm2bytecode.sh` (the standard pre-test step). The
  new `u256_iszero_add_loop` `.easm`/`.expected` sources are committed with this
  change (interpreter-level coverage).

## Checklist

- [x] Implementation complete
- [x] Tests added/updated — analyzer transfer-rule tests + `static_assert`
- [x] Module specs in `docs/modules/` updated (if affected) — none affected
- [x] Build and tests pass — `evmRangeAnalyzerTests` 49/49, `evmInterpTests`
      169/169, multipass `evmone-unittests` 223/223; `static_assert` compiles.
