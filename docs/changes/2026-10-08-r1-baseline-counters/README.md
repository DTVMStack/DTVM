# Change: R1 baseline counters on existing cache demo

- **Status**: Implemented
- **Date**: 2026-10-08
- **Tier**: Light

## Overview

Add an opt-in `--dump-r1-stats` path to `evmCacheComplexityDemo` plus
scripts that replay the paper contract hex corpus. This measures today's
block-local jump resolution and SPP-blocked JUMPDEST surface. It does
**not** implement cross-block abstract interpretation (R1).

## Motivation

R1 (cross-block Const/ConstSet absinterp feeding `lemma614Update`) needs
a real baseline before a month of work: unresolved JUMP/JUMPI after the
current block-local pass, JUMPDESTs stamped with
`ImplicitDynamicPredCount > 0`, and nonzero gas-chunk / `meterGas` sites
before vs after SPP. The public `EVMBytecodeCache` already exposes the
inputs; the demo reconstructs the same decision `buildCFGEdges` uses.

## Impact

- `src/tests/evm_cache_complexity_demo.cpp` — new flags; default CSV
  timing row is unchanged
- `tools/r1_baseline_stats.sh`, `tools/run_r1_baseline.sh` — reproduction
- `docs/modules/evm/cache-build.md` — not changed (no cache contract change)

## Checklist

- [x] Implementation complete
- [x] Tests added/updated (demo flag + synthetic sanity in the runner)
- [x] Module specs in `docs/modules/` updated (if affected) — cache contract unchanged
- [x] Build and tests pass (`evmCacheTests` 16/16; RelWithDebInfo EVM+multipass)
