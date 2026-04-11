# Change: Gas check placement optimization with mixed CFG support

- **Status**: Implemented
- **Date**: 2026-04-05
- **Tier**: Full

## Overview

Remove all-or-nothing dynamic jump fallback — previously any unresolved dynamic
jump caused the entire contract to fall back to per-block gas metering (zero SPP
benefit). Now always builds a CFG with mixed edges: precise for resolved jumps,
over-approximated for unresolved ones.

Add call-site enumeration for function returns: resolves `SWAPn→JUMP` patterns
(Solidity internal function returns) by identifying call sites
(`PUSH ret → PUSH func → JUMP`) and collecting return addresses via reverse
reachability. Achieves high jump resolution rate on typical Solidity contracts.

`GasChunkCost` continues to write the original `Blocks[Id].Cost` (not the
SPP-shifted `Metering[Id]`) — the interpreter's gas chunk fast path requires
unshifted per-block costs, as established by PR #371. A second parallel array
`GasChunkCostSPP` is added to `EVMBytecodeCache` specifically for the multipass
JIT: the SPP metering pass writes shifted values into it, and the JIT prefers
it over the unshifted table when emitting gas checks. The interpreter never
reads the new array, preserving #371 semantics.

## Motivation

The existing all-or-nothing fallback meant that any contract with unresolvable
dynamic jumps got zero benefit from SPP. Real-world contracts mix static and
dynamic jumps, so a mixed-edge CFG approach is needed to let the pass do useful
work on the resolved portion of the CFG.

## Scope

This PR is scoped to the cache-side CFG improvements only:

- Remove the `HasDynamicJump` early-exit bailout in `buildGasChunksSPP`.
- Factor out `buildCFGEdges()` so the CFG can be built twice: once with
  over-approximation, once with call-site-resolved targets mixed in.
- Add `resolveCallSiteTargets()` — identifies `SWAPn→JUMP` return patterns and
  walks predecessors to find the enclosing function entry, then collects valid
  return addresses from matching call sites.
- Introduce `decodePushAsJumpDest()` as a shared helper, and add `Prev2Pc` /
  `Prev2Opcode` tracking on `GasBlock` to support the 3-instruction call-site
  window lookup.
- Tighten the SPP shifting guards to bail out of the shift when a successor is
  a `isGasChunkTerminator` — prevents masking gas cost across chunk boundaries.

No frontend/MIR changes are included in this PR.

## Impact

### Affected Modules

- `docs/modules/evm/` — EVM bytecode cache, CFG construction, jump resolution

### Compatibility

No breaking changes. Interpreter semantics are preserved (`GasChunkCost`
unchanged). JIT semantics are preserved (no frontend changes).

### Metrics

Measured via `evmone-bench` against `upstream/main@a14a9de` on the
`external/total/(main|micro)/*` benchmark set (3 repetitions, median).

- **Geometric mean: −10.13%** across 27 benchmarks.
- Large wins on memory-growth and signextend chunks:
  - `micro/memory_grow_mload/*`: −19% to −24%
  - `micro/memory_grow_mstore/*`: −19% to −20%
  - `micro/signextend/{one,zero}`: −19% to −20%
- Headline contract: `main/snailtracer/benchmark`: −7.53%
- A handful of small regressions remain (≤ +6%) on
  `sha1_shifts/5311`, `structarray_alloc/nfts_rank`, `weierstrudel/1`,
  `blake2b_shifts/8415nulls` — these are jump-heavy Solidity patterns where
  the added CFG edges apparently perturb chunk layout slightly.

Correctness: 223/223 multipass evmone-unittests, 215/215 interpreter
evmone-unittests, 2723/2723 evmone-statetests on `fork_Cancun`.

## Implementation Plan

### Phase 1: Remove all-or-nothing fallback

- [x] Remove the fallback that disabled SPP when any dynamic jump was unresolved
- [x] Build mixed CFG with over-approximated edges for unresolved jumps

### Phase 2: Call-site enumeration

- [x] Add `resolveCallSiteTargets()` for `SWAPn→JUMP` patterns
- [x] Identify call sites and collect return addresses via reverse reachability

### Phase 3: JIT integration

- [x] Add `EVMBytecodeCache::GasChunkCostSPP` parallel array populated from
      `Metering[]` in `buildGasChunksSPP`
- [x] Plumb through `EVMFrontendContext::setGasChunkInfo` and `EVMMirBuilder`
- [x] Swap reads in `meterOpcode`, `meterOpcodeRange`, and the JUMPDEST-run
      suffix-sum precompute to prefer `GasChunkCostSPP` when non-null
- [x] Interpreter continues reading the unshifted `GasChunkCost` — no change

### Phase 4: SPP pipeline gating

- [x] Add `buildBytecodeCache(..., bool EnableSPP)` parameter
- [x] When `EnableSPP == false`, skip the expensive CFG / call-site /
      metering pipeline entirely and emit unshifted per-block costs
- [x] `EVMModule::CacheNeedsSPP` is flipped to `true` only immediately
      before `performEVMJITCompile` runs, so interpreter-only modules never
      pay the SPP pipeline cost
- [x] `evm_compiler.cpp` passes `nullptr` for `GasChunkCostSPP` when the
      cache array is empty, so the JIT falls back to the unshifted array if
      a module somehow ends up JIT-compiled without SPP being built

## Changed Files

- `src/evm/evm_cache.h` — add `GasChunkCostSPP` field
- `src/evm/evm_cache.cpp` — mixed-CFG, call-site enumeration, SPP export
- `src/compiler/evm_frontend/evm_mir_compiler.h` — plumb SPP pointer through
  context and builder
- `src/compiler/evm_frontend/evm_mir_compiler.cpp` — prefer SPP-shifted cost
  at the three chunk-cost read sites
- `src/compiler/evm_compiler.cpp` — pass the new pointer via `setGasChunkInfo`

## Risks

- Over-approximated edges for unresolved jumps may pessimize gas placement for
  pathological contracts with many unresolved targets.
- Call-site enumeration assumes the Solidity-style
  `PUSH ret → PUSH func → JUMP` pattern; non-standard compilers may not match.
- Reverse-reachability walk is bounded by `MAX_REVERSE_REACHABILITY_DEPTH` to
  cap worst-case compile-time cost.
