# Change: Gas check placement optimization with mixed CFG support

- **Status**: Implemented
- **Date**: 2026-04-05
- **Tier**: Full

## Overview

Remove the all-or-nothing dynamic-jump fallback in the EVM bytecode cache's
SPP gas-metering pipeline. Previously, any unresolved dynamic jump caused the
entire contract to fall back to per-block gas metering (zero SPP benefit).
The cache now always builds a CFG with mixed-precision edges and runs the
SPP shifting pass, while keeping the unshifted per-block cost available for
the interpreter.

The final design has three pieces:

- **Mixed-precision CFG**: static jumps (`PUSH → JUMP`) get a single precise
  edge to the resolved `JUMPDEST`; every other dynamic jump gets
  over-approximated edges to all `JUMPDEST` blocks. The over-approximation
  is intentional — narrowing dynamic-jump edges with partially-resolved
  call-site information would under-approximate the CFG and let the SPP
  pass shift gas along edges that don't exist at runtime, producing unsafe
  metering. See `buildCFGEdges` in `src/evm/evm_cache.cpp` (lines 386–429,
  in particular the dynamic-jump branch at line 419).
- **SPP-shifted gas cost on a separate array**: the interpreter's gas-chunk
  fast path requires unshifted per-block costs (PR #371). To preserve those
  semantics while enabling SPP for the JIT, the cache exposes two parallel
  arrays. `EVMBytecodeCache::GasChunkCost` keeps the unshifted base cost
  (written from `Blocks[Id].Cost` at `evm_cache.cpp:1161`), and a new
  `EVMBytecodeCache::GasChunkCostSPP` carries the SPP-shifted value
  (written from the metering function `Metering[Id]` at
  `evm_cache.cpp:1165`). The interpreter (`src/evm/interpreter.cpp:382`)
  reads only `GasChunkCost`; the multipass JIT prefers `GasChunkCostSPP`
  when non-null and falls back to `GasChunkCost` otherwise
  (`src/compiler/evm_frontend/evm_mir_compiler.cpp:534, 578`).
- **Interpreter-mode gating**: the SPP pipeline (CFG construction + metering
  pass) is expensive and only useful for the JIT consumer. `buildBytecodeCache`
  takes an `EnableSPP` parameter; when false, it emits unshifted per-block
  costs and skips the CFG/metering work entirely. `EVMModule::CacheNeedsSPP`
  is set to `true` immediately before `performEVMJITCompile` runs, so
  interpreter-only modules never pay the SPP pipeline cost. When the JIT
  somehow runs without SPP being built, `evm_compiler.cpp` passes `nullptr`
  for `GasChunkCostSPP` so the JIT falls back to the unshifted array.

## Motivation

The existing all-or-nothing fallback meant any contract with unresolvable
dynamic jumps got zero benefit from SPP. Real-world Solidity contracts mix
static and dynamic jumps, so a mixed-edge CFG is needed to let the SPP pass
do useful work on the resolved portion of the CFG while staying sound on
the unresolved portion.

## Scope

This PR is scoped to the cache-side CFG and JIT-cost wiring:

- Remove the `HasDynamicJump` early-exit bailout in `buildGasChunksSPP`.
- Factor out `buildCFGEdges()` with over-approximation for all unresolved
  dynamic jumps (sound for SPP metering).
- Add `EVMBytecodeCache::GasChunkCostSPP` and write SPP-shifted costs into
  it, leaving `GasChunkCost` unshifted for the interpreter.
- Plumb the SPP pointer through `EVMFrontendContext::setGasChunkInfo` and
  `EVMMirBuilder`; swap the JIT's chunk-cost reads (`meterOpcode`,
  `meterOpcodeRange`, JUMPDEST-run suffix-sum precompute) to prefer
  `GasChunkCostSPP` when non-null.
- Add an `EnableSPP` parameter to `buildBytecodeCache` and gate the
  pipeline on JIT-consumer modules only.
- Tighten the SPP shifting guards to bail out of the shift when a successor
  is a `isGasChunkTerminator` — prevents masking gas cost across chunk
  boundaries.

No frontend/MIR changes beyond the cost-source swap are included.

## Impact

### Affected Modules

- `docs/modules/evm/` — EVM bytecode cache, CFG construction, SPP metering

### Compatibility

No breaking changes. Interpreter semantics are preserved (`GasChunkCost`
remains the unshifted per-block cost, matching PR #371). JIT semantics are
preserved when SPP is enabled (the JIT now reads SPP-shifted costs from a
separate array instead of overwriting the interpreter's table).

### Metrics

Numbers are from the CI Performance Regression Check (baseline
`perf-baseline-*-a14a9de...`, 5 repetitions, 25% threshold) — the
gate-of-record for this PR. The full 194-bench multipass table lives in
the github-actions perf-check comment on the PR; this section
summarizes the design-relevant subset.

**Wins (jump-light / cost-shift opportunities):**

- `micro/signextend/{one,zero}`: 0.13 → 0.07 μs (≈ −42.7%)
- `micro/memory_grow_mstore/nogrow`: −6.8%
- `main/structarray_alloc/nfts_rank`: −6.2%
- `main/blake2b_huff/8415nulls`: −5.3%

**Regressions (jump-heavy contracts — predicted cost of mixed-CFG
over-approximation):**

- `micro/jump_around/empty`: 0.04 → 0.05 μs (+22.8%)
- `main/weierstrudel/1`: 0.20 → 0.24 μs (+19.5%)
- `main/weierstrudel/15`: 2.22 → 2.60 μs (+17.5%)
- `main/snailtracer/benchmark`: 28.49 → 31.58 μs (+10.9%)

The +17–23% regressions on jump-heavy contracts are the design tradeoff
of over-approximating dynamic-jump edges to all `JUMPDEST` blocks in
order to keep the SPP shift sound (narrowing those edges with partial
call-site resolution would under-approximate the CFG and break per-path
total invariants — see Phase 5 / `buildCFGEdges` in
`src/evm/evm_cache.cpp:389-429`). All 194 benches stay within the 25%
gate, but `jump_around` has tight headroom.

Earlier drafts of this section cited a 27-bench local `evmone-bench`
run (3 reps) that drifted from the CI baseline; the CI bot table is the
authoritative source.

Correctness: 223/223 multipass evmone-unittests, 215/215 interpreter
evmone-unittests, 2723/2723 evmone-statetests on `fork_Cancun` for both
multipass and interpreter modes.

## Implementation Plan

### Mixed CFG construction

- [x] Remove the all-or-nothing fallback that disabled SPP on any unresolved
      dynamic jump
- [x] Factor `buildCFGEdges()` so static jumps get precise single-target
      edges and unresolved dynamic jumps get over-approximated edges to
      every `JUMPDEST`

### JIT cost wiring

- [x] Add `EVMBytecodeCache::GasChunkCostSPP` parallel array, populated from
      the SPP metering function in `buildGasChunksSPP`
- [x] Plumb the SPP pointer through `EVMFrontendContext::setGasChunkInfo`
      and `EVMMirBuilder`
- [x] In `meterOpcode`, `meterOpcodeRange`, and the JUMPDEST-run suffix-sum
      precompute, prefer `GasChunkCostSPP` when non-null
- [x] Interpreter continues reading the unshifted `GasChunkCost` — no change

### SPP pipeline gating

- [x] Add `buildBytecodeCache(..., bool EnableSPP)` parameter
- [x] When `EnableSPP == false`, skip the CFG / metering pipeline and emit
      unshifted per-block costs only
- [x] `EVMModule::CacheNeedsSPP` is flipped to `true` immediately before
      `performEVMJITCompile` runs, so interpreter-only modules never pay
      the SPP pipeline cost
- [x] `evm_compiler.cpp` passes `nullptr` for `GasChunkCostSPP` when the
      array is empty, so the JIT falls back to the unshifted array if a
      module is JIT-compiled without SPP being built

### Soundness guards

- [x] Tighten `lemma614Update` to set `MinSucc = 0` when encountering
      excluded successors or gas-chunk terminators

## Changed Files

- `src/evm/evm_cache.h` — add `GasChunkCostSPP` array, document
  interpreter vs JIT consumer split
- `src/evm/evm_cache.cpp` — mixed-CFG `buildCFGEdges`, SPP-shifted cost
  export, `EnableSPP` gating
- `src/compiler/evm_frontend/evm_mir_compiler.h` — plumb SPP pointer
  through context and builder
- `src/compiler/evm_frontend/evm_mir_compiler.cpp` — prefer SPP-shifted
  cost at the three chunk-cost read sites
- `src/compiler/evm_compiler.cpp` — pass the new pointer via
  `setGasChunkInfo`, with `nullptr` fallback when the SPP array is empty
- `src/runtime/evm_module.h` — `CacheNeedsSPP` flag

## Risks

- Over-approximated edges for unresolved jumps may pessimize gas placement
  for pathological contracts with many unresolved targets. Acceptable
  because the alternative (narrowed edges from partial resolution) is
  unsound for SPP.
