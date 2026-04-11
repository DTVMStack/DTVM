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
unshifted per-block costs, as established by PR #371. The SPP pipeline still
runs so that mixed-CFG gains benefit the downstream `isGasChunkTerminator`
shifting guards, but shifted values are not exported back to the chunk tables.
Wiring shifted values into the JIT via a separate JIT-only output path is left
as a follow-up.

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

Metrics need to be re-measured on top of current `upstream/main` (which
includes true-SSA stack lifting from PR #395). Previous numbers reported on a
stale base are no longer comparable and have been dropped from this document.

## Implementation Plan

### Phase 1: Remove all-or-nothing fallback

- [x] Remove the fallback that disabled SPP when any dynamic jump was unresolved
- [x] Build mixed CFG with over-approximated edges for unresolved jumps

### Phase 2: Call-site enumeration

- [x] Add `resolveCallSiteTargets()` for `SWAPn→JUMP` patterns
- [x] Identify call sites and collect return addresses via reverse reachability

### Phase 3: JIT integration (deferred)

- [ ] Plumb SPP-shifted metering into a JIT-only output path without perturbing
      the interpreter chunk tables

## Changed Files

- `src/evm/evm_cache.cpp`

## Risks

- Over-approximated edges for unresolved jumps may pessimize gas placement for
  pathological contracts with many unresolved targets.
- Call-site enumeration assumes the Solidity-style
  `PUSH ret → PUSH func → JUMP` pattern; non-standard compilers may not match.
- Reverse-reachability walk is bounded by `MAX_REVERSE_REACHABILITY_DEPTH` to
  cap worst-case compile-time cost.
