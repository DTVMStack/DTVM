# Change: R1 cross-block absinterp feeding existing SPP

- **Status**: Accepted
- **Date**: 2026-10-08
- **Tier**: Full

## Overview

Add a cross-block worklist abstract interpreter (`Const` / `ConstSet` / `Top`)
that narrows dynamic JUMP/JUMPI to a sound over-approx JUMPDEST set, then
feeds the existing `buildCFGEdges` / `lemma614Update` pipeline. Fail-closed:
Top or non-convergence keeps today's `ImplicitDynamicPredCount` semantics.
Does not rewrite GasSection or interpreter `GasChunkCost`.

## Motivation

Phase-1 baseline (`artifacts/r1-baseline-report.md`): 11/12 paper contracts
have ≥1 unresolved jump, which stamps **all** JUMPDESTs with implicit dynamic
preds and blocks SPP into those nodes. Solidity internal returns (`SWAP1;
JUMP`) are the intended ConstSet case. This change implements that analysis.

## Impact

### Affected Modules

- `docs/modules/evm/cache-build.md` — new pass before `buildCFGEdges`
- `src/evm/evm_cache.{h,cpp}` — Resolved multi-target map + worklist
- `src/tests/evm_cache_tests.cpp` / `evm_cache_complexity_demo.cpp`

### Affected Contracts

- `EVMBytecodeCache` gains `ResolvedJumpMultiTargets`
- `buildBytecodeCache(..., EnableSPP, EnableR1=true)`
- Interpreter `GasChunkCost` unchanged
- SSA still reads the single-target map only (multi stays non-lifted)

### Compatibility

Non-breaking. `ZEN_EVM_DISABLE_R1=1` restores Phase-1 resolution.

## Implementation Plan

### Phase 1: Classify + Const/Top worklist

- [x] Classify unresolved PCs on 12 runtime hexes
- [x] Cross-block Const+Top fixpoint; fail-closed on Top / non-converge

### Phase 2: ConstSet + multi-target

- [x] Interned ConstSet (cap 16); multi-target edges in `buildCFGEdges`
- [x] `invalidate_suspect`: any Top jump ⇒ do not commit ConstSet

### Phase 3: Tests + A/B

- [x] Over-approx / gas-identical / Top-stays-dynamic tests
- [ ] 2×2 absinterp × SPP on the 12 hexes

## Compatibility Notes

None. Default on; disable via env or demo flag.

## Risks

- ConstSet explosion: hard cap 16 → Top
- Unsound under-approx: fail-closed if any Top or iteration cap
- Compile-time cost: worklist only on SPP/JIT cache builds (`CacheNeedsSPP` / EnableR1)
