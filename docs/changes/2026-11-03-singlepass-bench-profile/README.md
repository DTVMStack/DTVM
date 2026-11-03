# Change: Dedicated Singlepass paper-bench build

- **Status**: Implemented
- **Date**: 2026-11-03
- **Tier**: Light

## Overview

Add a reproducible Release Singlepass-only CLI build entry point. Disable unused Multipass/LLVM features and document the required harness mode selection. No runtime or compiler behavior changes.

## Motivation

Same-source paired WAPM measurements show reduced fixed startup overhead when LLVM/Multipass is excluded. This is a separate deployment configuration; do not merge results with Singlepass mode in the mixed-feature executable or claim faster guest kernels.

## Validation

- Built using the new entry point; binary SHA-256 matches the measured dedicated build.
- WAPM20 R10: 19 workloads execute successfully; the pre-existing invalid SAM fixture is excluded and left for a separate change.
- Empty-module R20: process-wall median 5.113 ms (mixed) vs 3.358 ms (dedicated) on the measurement host.
- Five short workloads independently rechecked against official Wasmtime 49.0.5.
- Existing harness unit tests: 26 passed. Shell syntax and git whitespace checks passed.
