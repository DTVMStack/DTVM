# Change: Consolidate EVM interp-vs-multipass differential suites into one target

- **Status**: Implemented
- **Date**: 2026-06-11
- **Tier**: Light

## Overview

Consolidate the interpreter-vs-multipass differential tests into one test-only
gtest target, `evmDifferentialTests`
(`src/tests/evm_differential_tests.cpp`); the suite passes 44/44 on
upstream/main with no runtime or codegen change. The target collects the tests
into a single self-contained file.

The suite has two parts:

- **Fixture-based differential cases (40)** — one parameterized fixture loads a
  hex bytecode from `tests/evm_asm/`, runs it through both the interpreter and
  the multipass JIT, and asserts identical status and output. The cases are
  grouped into `RangeNarrowing` (21), `ConstShiftPruning` (13), and
  `SubWrapU64` (6), each feeding a dynamic operand that drives a value-range
  lowering path.
- **Adversarial-matrix harness (4)** — `EVMRangeDifferential` builds bytecode
  programmatically and sweeps an 11-value operand matrix (value-range
  boundaries plus high-sparse words) across 20 binary opcodes, the three shifts
  on limb-boundary amounts, and the AND-u64 narrow fast path, asserting the JIT
  agrees with the interpreter on every pair.

A single executor underpins both parts. It forces synchronous multipass
compilation (`DisableMultipassMultithread`) so the JIT side actually executes
compiled code, and asserts `JITCompiled` under `ZEN_ENABLE_JIT` so a multipass
run that fell back to the interpreter cannot pass vacuously.

## Motivation

The differential JIT tests previously lived in the interpreter test file. Three
in-flight optimization PRs each appended a near-identical copy of the
differential suite plus its fixtures to `src/tests/evm_interp_tests.cpp`, and a
fourth added the programmatic matrix harness to the same file. Every one of
these would conflict with the others on merge.

A single target removes both problems: the copied suites collapse
into one parameterized fixture with one executor, and the shared file no longer
forces a merge conflict between the optimization PRs.

The invariant holds on plain `main`, independent of the optimization PRs the
fixtures were written alongside, so the suite guards it before and after those
optimizations merge.

## Impact

- **New file**: `src/tests/evm_differential_tests.cpp` (test-only).
- **New fixtures**: 40 `.easm`/`.expected` pairs under `tests/evm_asm/`.
- **Build**: `src/tests/CMakeLists.txt` registers the `evmDifferentialTests`
  target inside the existing `ZEN_ENABLE_MULTIPASS_JIT` blocks.
- **Runtime / codegen**: none. `libdtvmapi` is unaffected.
- `src/tests/evm_interp_tests.cpp` is not modified.

## Verification

- `evmDifferentialTests`: **44 / 44 pass** (40 fixture + 4 matrix) on
  upstream/main with no optimization PR applied.
- `ctest` (`SPEC_TESTS_ARGS="-m multipass --format evm --enable-evm-gas"`): the
  suite passes with no new failures. `evmInterpTests` now runs the 40 new
  fixtures through its golden sample test as well.
- `tools/format.sh check`: pass.
- No new compiler warnings for the new file.

## Checklist

- [x] Implementation complete
- [x] Tests added/updated
- [ ] Module specs in `docs/modules/` updated (if affected)
- [x] Build and tests pass
