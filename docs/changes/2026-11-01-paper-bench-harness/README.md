# Change: Paper-bench harness (DTVM vs Wasmtime)

- **Status**: Implemented
- **Date**: 2026-11-01
- **Tier**: Light

## Overview

Add a reusable, in-repo wall-clock harness under `benchmarks/paper/harness/`
for PolyBench, fib, overflow, and WAPM. The harness pins DTVM modes to the
Phase 1.5 names (`interp` / `singlepass` / `multipass-G-ST` / `lazy-F-ST`),
pins a CPU with `taskset`, emits a `phase15-v1` JSON schema, and compares
Wasmtime 45 on the **same `.wasm`** when that comparison is fair.

## Motivation

`benchmarks/paper/scripts/` already has per-suite CSV/TTFI drivers, but they
do not share one timing schema, default to mixed historical runtime pins, and
do not encode fairness (DTVM overflow hostapi vs Wasmtime builtin overflow).
Phase 1.5 measurements had to be assembled out of tree. A single catalog +
JSON runner makes those comparisons copy-pasteable without touching compiler
code or DTVMStack #626–#629.

## Impact

- **Modules**: none (`src/` unchanged)
- **Contracts**: none
- **New paths**: `benchmarks/paper/harness/` (catalog, `run.py`, build/fetch
  helpers, schema doc)
- **Docs**: `benchmarks/paper/README.md`, `REPRODUCE.md`, `scripts/README.md`,
  this change proposal
- **Compatibility**: additive; older `scripts/*.sh` keep their CSV/TTFI roles

## Checklist

- [x] Implementation complete
- [x] Tests added/updated (`python3 benchmarks/paper/harness/run.py --selftest`;
      smoke matrix against Release `dtvm` + Wasmtime 45)
- [x] Module specs in `docs/modules/` updated (if affected) — N/A
- [x] Build and tests pass (harness selftest + smoke; core `src/` untouched)
