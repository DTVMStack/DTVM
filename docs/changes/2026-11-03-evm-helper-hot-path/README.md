# Change: reduce direct-EVM Keccak and modular-multiplication helper cost

- **Status**: Implemented
- **Date**: 2026-11-03
- **Tier**: Light

## Overview

Replace the 16-entry linear Keccak result cache with a 256-entry direct-mapped
cache. Hash and compare the complete input before reusing a cached result, and
bypass the cache for inputs longer than 128 bytes. Use `intx::mulmod` for the
dynamic EVM `MULMOD` helper.

## Motivation

A direct-EVM GenerativeNFT probe repeatedly hashes more distinct short round
inputs than the old cache can hold, producing zero hits. The larger
direct-mapped cache avoids that thrashing without making unique-input lookup
linear in the cache size. `intx::mulmod` retains full-width arithmetic while
reducing helper cost compared with explicit `uint512` multiplication and `%`.

## Impact

Only `src/compiler/evm_frontend/evm_imported.cpp` changes. EVM output, gas,
state, and logs remain unchanged. The cache remains thread-local and checks
exact bytes after its index hash, so hash collisions cannot change results.
The compiler module interface and module specifications do not change.

## Verification

- Built `dtvmapi` in the existing Release EVM benchmark build.
- Ran `evmFallbackExecutionTests`, `evmModuleCacheTests`, and
  `evmProfileGuidedJITTests` (3/3 passed).
- Compared the original and candidate with the same-source shared-EVMC
  harness on GenerativeNFT and Poseidon, balanced R3 × 1,000 calls per side;
  each run passed 36,000 EVMC field comparisons.
- Checked corrected Merkle and ECDSA at R2 × 500 calls, with 12,000 matching
  field comparisons, and the final source at R1 × 1,000 calls for Counter,
  GenerativeNFT, and Poseidon, with 18,000 matching field comparisons.
- The GenerativeNFT last-100-call median improved from 2,476 to 1,404 µs in
  the R3 same-tree A/B. These are exploratory performance results, not a
  paper-ready replacement for the predeclared M3 matrix.

## Checklist

- [x] Implementation complete
- [x] Existing semantic differential tests exercised across JIT transition;
  no new API or EVM behavior added, so no new behavior test was needed
- [x] Module specs reviewed; no contract update needed
- [x] EVM library build and focused tests pass
- [ ] Full build and full test suite (not run for this focused optimization)
