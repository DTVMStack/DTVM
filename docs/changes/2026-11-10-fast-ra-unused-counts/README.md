# Change: Remove unused FastRA register-class counts

- **Status**: Implemented
- **Date**: 2026-11-10
- **Tier**: Light

## Overview

Remove register-class definition counting from FastRA's tied-operand path. The resulting counts were never read after being populated, and the allocation decisions and their ordering are unchanged. This affects the multipass FastRA path; singlepass and Greedy RA do not use this code.

## Motivation

Cold, fresh-process contract experiments identified register allocation as a material part of lazy JIT demand-compilation time. An independent scratch build using the same core and compiler as the control, differing only in this calculation, reduced paired-median end-to-end time for `rpow_pilot` and `uniswap_v3_tickmath_pilot` in two independent randomized cohorts. The current host calls into native arithmetic, so Merkle/NFT timings are host dominated and must not be used as pure guest compiler measurements. Wasmtime 45 is included as an external point of reference, not the paired control. See the accompanying benchmark evidence for the setup, boundaries, full samples and confidence intervals.

## Impact

The unused scratch vector, its initialization and the per-def scan over register classes and aliases are removed. Runtime configuration, allocator heuristics, code publication and Wasm semantics are unchanged. No module-spec contract changes are required.

## Checklist

- [x] Implementation complete
- [x] Existing focused allocator and contract correctness tests pass
- [x] Module specs reviewed; no contract changes
- [x] Release build and appropriate tests pass
- [x] Two independent exploratory benchmark cohorts recorded

## Verification

- Release build with singlepass and multipass; 65 contract engine/case checks.
- `mirPeepholeTests`: 111 passed; `lazyJitGreedyOndemandTests`: 24 passed.
- Twelve selected multipass WAST units with FastRA and single-threaded compilation, including tied operands, arithmetic, memory and load folding.
- Two research cohorts, a production contract cohort, and a paired WAPM follow-up; see [evidence](evidence/README.md).
