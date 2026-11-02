# Change: Unify paper-bench wall/TTFI schema; optional Wasmtime

- **Status**: Implemented
- **Date**: 2026-11-01
- **Tier**: Light

## Overview

Follow-up to `2026-11-01-paper-bench-harness`. Bump the harness JSON to
`paper-bench-v1`: one mode vocabulary for wall and TTFI, separate compilation reports and lazy estimates from measured first-invocation
latency without substituting wall time, and run the same-`.wasm`
Wasmtime column **only when a Wasmtime binary exists**. Missing Wasmtime or
Wasmer yields `skipped` cells / `skipped_runtimes`, never invented ms.

## Motivation

Phase 2 infra follow-up: the wall harness (`phase15-v1`) and the older
`scripts/run_*_ttfi_*.sh` profiles (`lazy`, `multipass`, `default`) did not
share names. Boxes without Wasmtime/Wasmer must still produce a DTVM-only
JSON rather than failing or filling comparison columns.

## Impact

- **Modules**: none (`src/` unchanged)
- **Paths**: `benchmarks/paper/harness/run.py`, `SCHEMA.md`, `README.md`,
  `smoke.sh`
- **Compatibility**: additive JSON fields; `--runtimes wasmtime` no longer
  fatal when the binary is absent (use `--require-wasmtime` to fail)

## Checklist

- [x] Implementation complete
- [x] Tests added/updated (`run.py --selftest`; skip path with `WASMTIME=` /
      missing binary)
- [x] Module specs in `docs/modules/` updated (if affected) — N/A
- [x] Build and tests pass (harness only; `src/` untouched)

## Rebase review (2026-11-02)

Rebased onto main after #630–#634, retaining the reviewed harness failure
handling and separate wall/statistics passes. This PR remains useful for
canonical mode names, explicit missing-runtime records, and shared output.
It changes measurement infrastructure, not VM execution speed.

Compilation time is now `ttfi.compile_ms`, and the legacy statistics formula
is `ttfi.ttfi_est_ms`. Neither is published as measured `ttfi_ms`. The estimate
requires every input stage; diagnostic medians require all repetitions.
Regression tests cover aliases, optional/required runtimes, partial metric
coverage, units, and absence of measured TTFI. A dedicated CI job runs the
Python tests and harness selftest without requiring VM binaries.
