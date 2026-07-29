# Change: Add opt-in EVM compiler observation

- **Status**: Implemented
- **Date**: 2026-07-28
- **Tier**: Full

## Overview

Add an opt-in, structured observation record for the EVM multipass compiler.
The record attributes compile time and intermediate-representation growth
across frontend, MIR, CgIR, Phi elimination, register allocation, machine-code
emission, and code publication.

## Motivation

Total JIT time and mapped executable size cannot explain which compiler stage
caused a regression. Diagnosing stack-SSA compile growth required reproducible
per-stage timing, before/after IR snapshots, and counters for stack lifting,
Phi elimination, register allocation, fallback coverage, and emitted bytes.

The observation must remain disabled by default and must separate its own
measurement overhead from compiler work.

## Impact

### Affected Modules

- `compiler`: phase timers, MIR/CgIR snapshots, lift/Phi/RA counters, structured
  record emission, and feature-coverage aggregation.
- `runtime`: retain actual emitted code bytes and dynamic-entry fallback counts
  on the EVM module.
- `tools`: collect paired S0/S1 records for a deduplicated fixture set.
- `tests`: validate parsing, fingerprint selection, comparison, and summary
  behavior of the observation runner.

### Affected Contracts

Setting `DTVM_EVM_COMPILER_OBSERVE` to a non-empty value other than `0` emits
one `[DTVM_EVM_COMPILER_OBSERVATION]` JSON line per attempted EVM compilation.
No record is emitted when the variable is unset or `0`.

`EVMModule::getEmittedJITCodeSize()` reports actual emitted bytes, while
`getJITCodeSize()` continues to report the executable mapping size.

### Compatibility

The feature is additive. Default compilation, generated code, and EVM execution
semantics are unchanged.

## Implementation Plan

### Phase 1: Capture compiler structure

- [x] Add opt-in phase timing with explicit observation-overhead accounting.
- [x] Capture MIR and CgIR snapshots around lowering, Phi elimination, and
  register allocation.
- [x] Capture stack-lift, Phi-copy, spill, fallback, feature-coverage, and
  emitted-code metrics.

### Phase 2: Emit and consume structured records

- [x] Emit schema-versioned records with deterministic bytecode fingerprints.
- [x] Add an atomic, resumable S0/S1 collection and comparison tool.
- [x] Add unit tests for parsing, target selection, comparison, and aggregation.

### Phase 3: Verify

- [x] Update affected module specifications.
- [x] Run formatting checks.
- [x] Build stack-SSA off and on configurations.
- [x] Run frontend and Python tool tests.
- [x] Verify observation-off emits no records and both modes preserve execution
  output.

### Validation

- Strict `clang-format` dry run on every changed C++ source and header.
- `git diff --check`.
- Stack-SSA off and on release multipass builds with LLVM 15.
- `evmJitFrontendTests`: 108/108 passed in each configuration.
- `python3 -m unittest tests/tools/test_run_ssa_compiler_observation.py`:
  4/4 passed.
- `double_mod_origin.evm.hex`: successful execution with identical output in
  both configurations; zero observation records by default and exactly one
  schema-versioned record when enabled.

## Compatibility Notes

Consumers should treat unknown JSON fields as forward-compatible additions and
key records by `schema_version`.

## Risks

- Observation can perturb timings. The record reports observation overhead
  separately, and performance measurements must run with observation disabled.
- Snapshot walks add work only when observation is enabled.
- Logging-only feature counters are reported as zero when the corresponding
  build instrumentation is unavailable.
