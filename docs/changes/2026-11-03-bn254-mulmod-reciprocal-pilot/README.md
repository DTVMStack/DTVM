# Change: BN254 MULMOD reciprocal reuse pilot

- **Status**: Accepted (frozen experimental candidate; production gate pending)
- **Date**: 2026-11-03
- **Tier**: Light

## Overview

Add a fixed-BN254-modulus branch to the direct-EVM JIT `MULMOD` helper. It
keeps `intx`'s Knuth reduction steps but precomputes the reciprocal of the
normalized divisor's top two words. Other moduli retain `intx::mulmod`.

## Motivation

GenerativeNFT and Poseidon use the same BN254 modulus and spend substantial
JIT time in repeated modular multiplication. The general `intx::mulmod`
recomputes this reciprocal for each operation.

## Impact

Only `src/compiler/evm_frontend/evm_imported.cpp` changes. EVM gas charging,
the interpreter, Wasm, and the non-BN254 helper path are unchanged. The
implementation deliberately remains a pilot: it duplicates `intx` internal
division code and needs a dedicated in-tree unit test and broader validation
before production acceptance.

## Verification so far

- The separate arithmetic pilot checked 49 boundary pairs and 100,000 random
  256-bit pairs against `intx::mulmod`.
- The EVMC fixture pilot compared 36,000 status/output/gas/state/log fields
  for GenerativeNFT and Poseidon; all matched. A three-case non-BN254 smoke
  compared another 1,800 fields; all matched.
- The benchmark target builds, and eight transaction-rule tests pass.
- The aggregate `evmStateTests` CTest target is not green in this build: its
  parameterized suite is uninstantiated, triggering GoogleTest verification.
- Exact baseline/candidate source snapshots were frozen under
  `/tmp/pldi_bn254_source_freeze_20261103.PjigiY/`; the paper-data pilot
  document records archive and binary SHA-256 values. The pre-existing
  `evmStateTests` registration failure is not a decision gate for this pilot.
- A quick A–B–B–A rerun from newly built frozen snapshots found about 12%
  lower post-JIT time for GenerativeNFT and Poseidon, with 96,000/96,000 EVMC
  field comparisons matching. Poseidon's 1,000-call cumulative time did not
  improve. The full predeclared matrix remains pending.
- A separate Poseidon R4 × 6,000 probe located the median cumulative
  DTVM/evmone crossover near call 4,992, with 144,000/144,000 EVMC fields
  matching. This is exploratory; the five-case figure is predeclared in the
  paper-data repository before its formal collection.

## Checklist

- [x] Exploratory implementation and arithmetic pilot
- [ ] In-tree unit tests for BN254 and fallback moduli
- [ ] Full build and relevant test suite
- [x] Quick frozen-source A–B–B–A performance replication
- [ ] Formal predeclared five-case figure matrix
- [ ] Module spec update (only if the implementation contract changes)
