# Change: Arithmetic fast-path hit counters for the EVM MIR builder

- **Status**: Implemented
- **Date**: 2026-05-29
- **Tier**: Light

## Overview

Add compile-time hit counters for the u256 arithmetic fast paths (ADD, SUB,
MUL, DIV, MOD), so the value-range / u64-fast-path effort becomes measurable.
Each opcode gets a `{FastRangeU64, FastConstU64, Full}` counter triple,
incremented at the corresponding lowering return site and emitted as an
`[EVM-ARITH-SUMMARY]` line, mirroring the existing `[EVM-MEM-SUMMARY]`
memory-stats mechanism.

## Motivation

The u256 fast-path audit (2026-05-29) found that **no** arithmetic fast-path hit
is instrumented today: `MemoryCompileStats` is entirely memory-domain, and the
similarly-named `LinearU64*FastPathCount` fields are MLOAD/MSTORE address fast
paths — a naming trap, not arithmetic. With neither a numerator (sites that hit
the narrow path) nor a denominator (total sites lowered), every claim about
which arithmetic paths "fire often" is currently a guess. Instrumentation is the
prerequisite for prioritizing and defending the result-range narrowing (DIV/MOD
u64, ADDMOD, MUL) and U128-consumer work.

## Impact

- Module: `src/compiler/evm_frontend` — `MemoryCompileStats` (counter fields),
  `handleBinaryArithmetic` (ADD/SUB, header), `handleMul`/`handleDiv`/`handleMod`
  (`.cpp`), `hasArithCompileStats` (new, arith-domain gate), `dumpMemoryCompileStats`.
- Counter triples: ADD/MUL/DIV/MOD get `FastRangeU64` (non-const `bothFitU64`
  path), `FastConstU64` (`isConstU64` path), `Full` (multi-limb fallback); SUB
  gets `FastConstU64` + `Full` (no range path exists for SUB).
- All increments are wrapped in `#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING`, so
  the default and CI builds compile them out — **no change to lowering,
  generated code, or execution results in any build**. The counter fields
  themselves are always present in the transient per-compile
  `MemoryCompileStats`, so the only unconditional cost is a small fixed
  increase in that diagnostic struct's size (no effect on generated code,
  runtime EVM state, or any public ABI).
- Measurement requires a `-DZEN_ENABLE_JIT_LOGGING=ON` build; the
  summary is logged via `ZEN_LOG_DEBUG`.

## Checklist

- [x] Implementation complete (14 counters; 17 `#ifdef`-gated increment sites;
      `[EVM-ARITH-SUMMARY]` dump gated by a dedicated `hasArithCompileStats`,
      keeping `hasMemoryCompileStats` memory-domain-only)
- [x] Tests added/updated — covered by regression; no new unit test (counters
      are macro-gated diagnostics with no codegen/behavior change)
- [x] Module specs in `docs/modules/` updated (if affected) — none affected
- [x] Build and tests pass — default (logging OFF) build: multipass
      `evmone-unittests` 223/223, `evmone-statetest -k fork_Cancun` 2723/2723.
      Logging build (`build-arithlog/`, `-DZEN_ENABLE_JIT_LOGGING=ON`) emits
      `[EVM-ARITH-SUMMARY] ... add_fast_const_u64=1 ... mul_fast_const_u64=1
      ... div_fast_const_u64=1 ... mod_fast_const_u64=1 ...` (non-zero).

## Notes

- The CMake option that defines the `ZEN_ENABLE_MULTIPASS_JIT_LOGGING` macro is
  `ZEN_ENABLE_JIT_LOGGING` (`src/CMakeLists.txt:119`). `ZEN_LOG_DEBUG` is
  surfaced via the `dtvm` CLI `--log-level debug`; the evmone EVMC path installs
  no logger.
- `build-arithlog/` (Ninja, logging ON) is retained for measurement reuse by the
  result-range narrowing and U128 tasks.
