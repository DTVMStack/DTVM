# Change: Run only the JIT suitability pass at EVM module load

- **Status**: Proposed
- **Date**: 2026-10-11
- **Tier**: Light

## Overview

In a JIT mode, `EVMModule::newEVMModule` runs `EVMAnalyzer` on every module to
set `ShouldFallbackToInterp`. It now calls `analyzeSuitabilityOnly()` instead
of `analyze()`. The verdict comes from the suitability pass either way; the
CFG, liftability and range passes of a full analysis were computed and then
discarded with the analyzer.

## Motivation

The JIT front end runs its own full analysis when it compiles a module, so the
full analysis at load bought nothing. It was most of the cost of a cold module
load in profile-guided JIT mode, where modules are loaded long before (and
usually without ever) being compiled.

Loading 338 mainnet contracts in profile-guided JIT mode, Release build:

| | Before | After |
|---|---:|---:|
| `loadEVMModule`, total | 2004 ms | 113 ms |

## Impact

- `runtime`: `newEVMModule` only. `ShouldFallbackToInterp`, and every decision
  taken from it, is unchanged.
- No API or contract change.

## Checklist

- [x] Implementation complete
- [x] Existing test suites pass
- [x] Module specs reviewed; no contract update required
- [x] Build and tests pass
