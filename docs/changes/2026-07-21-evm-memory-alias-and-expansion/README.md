# Change: EVM Memory Alias and Expansion Optimization Roadmap

- **Status**: Implemented
- **Date**: 2026-07-21
- **Tier**: Full

## Overview

Extend the CFG-aware EVM memory framework with stronger interval and alias
proofs, then use those proofs to relax block-local precheck and expansion
elision restrictions. The same analysis will subsequently support conservative
dead-store elimination, load forwarding, better memory grouping, and MCOPY
optimization.

The work is intentionally split into six commits. Analysis infrastructure lands
before behavior-changing consumers, and every consumer remains behind
`ZEN_ENABLE_EVM_MEMORY_PLAN_FRAMEWORK` until differential testing shows that it
is safe and useful.

## Implementation Result

The six-commit implementation delivers the conservative first stage of each
area in this roadmap:

- exact and bounded interval/alias queries plus block-local clobber queries;
- one safe precheck window per block, explicit covered operation IDs, and
  per-operation guaranteed-byte facts;
- expansion grouping across gaps and overlaps;
- block-local exact full-overwrite DSE that removes only the write;
- block-local exact `MSTORE -> MLOAD` forwarding that retains load expansion;
- constant `MCOPY` source/destination expansion proofs with zero-length and
  overlap semantics preserved.

The deliberately deferred extensions remain multiple windows per block,
symbolic-bound propagation from general EVM arithmetic, cross-region DSE/load
forwarding, partial-byte value reconstruction, and MCOPY data elimination.

## Motivation

The current 200-transaction sample shows that widening straight-line
LinearRegion discovery is no longer the highest-value direction:

| Counter | Current result |
|---|---:|
| `memory_expansion_plan_linear_region` | 2 |
| `memory_expansion_plan_covered_ops` | 14 |
| `linear_region_head_selected_non_entry_block` | 0 |
| `mload_expand` | 9 |
| `mstore_expand` | 87 |
| `mstore8_expand` | 0 |

The remaining expansion checks are mostly in short or block-local memory
sequences. The current implementation rejects many useful cases because:

- interval reasoning requires exact constant addresses and sizes;
- alias analysis only distinguishes `NoAlias` from `MayAlias`;
- grouping requires adjacent disjoint and exactly contiguous intervals;
- a block precheck is rejected when any covered direct operation has an
  unknown interval;
- `ProvenRange` requires at least three covered operations;
- only one constant-size plan can be consumed per block;
- guaranteed-byte expansion elision is rediscovered from a constant MIR
  operand rather than queried by `MemoryOp` proof;
- MCOPY is represented in facts but is not handled by cross-block guaranteed
  byte transfer or LinearRegion planning.

## Goals

1. Build one authoritative interval and alias query API for all memory
   consumers.
2. Increase safe block-local precheck coverage without moving expansion across
   observable effects.
3. Elide more per-operation expansion checks using per-op and CFG guarantees.
4. Enable conservative DSE and load forwarding without requiring full
   MemorySSA in the first version.
5. Add expansion-aware MCOPY optimization while preserving overlap and
   zero-length semantics.
6. Keep feature-off behavior and existing PR572 APIs compatible.

## Non-Goals

- No speculative expansion across branches or merges.
- No expansion hoisting across `GAS`, `MSIZE`, external calls, storage effects,
  logs, termination, escape, or unknown effects.
- No full MemorySSA, dominator, or post-dominator framework in the first six
  PRs.
- No DSE or load forwarding across arbitrary CFG joins or loops.
- No optimization based on unbounded dynamic addresses or sizes.
- No removal of EVM opcode gas charges.
- No change to memory expansion cost, overflow, OOG, or `MSIZE` semantics.

## Impact

### Affected Modules

- `src/compiler/evm_frontend/evm_memory_facts.h`
- `src/compiler/evm_frontend/evm_memory_analysis.h`
- `src/compiler/evm_frontend/evm_memory_precheck.h`
- `src/compiler/evm_frontend/evm_memory_grouping.h`
- `src/compiler/evm_frontend/evm_mir_compiler.{h,cpp}`
- `src/tests/evm_jit_frontend_tests.cpp`
- `docs/modules/compiler/spec.md`

### Affected Contracts

- Extend `AddressExpr`/`MemoryInterval` with bounded symbolic information while
  preserving existing exact-constant constructors.
- Extend alias results to distinguish `NoAlias`, `MustAlias`, partial overlap,
  and conservative `MayAlias`.
- Add per-operation expansion proof queries to `MemoryAnalysisView`.
- Evolve `MemoryExpansionPlan` from an implicit PC range to an explicit list of
  covered operation IDs before multiple plans per block are enabled.
- Preserve the flat `MemoryFacts::Ops` API and existing plan-provider facade.

### Compatibility

- No bytecode or public runtime API changes.
- Existing behavior remains the fallback whenever a proof is unavailable.
- All new lowering behavior remains behind
  `ZEN_ENABLE_EVM_MEMORY_PLAN_FRAMEWORK`.
- Feature-off builds must remain byte-for-byte unaffected by the planner data
  structures at runtime.

## Analysis Design

### Stronger Interval Lattice

Represent only forms with a deterministic, checkable bound:

```text
Unknown
ExactConst(address)
BaseValue(value_id) + ExactOffset
BaseValue(value_id) + [min_offset, max_offset]
```

Sizes use:

```text
Unknown
ExactSize(u64)
BoundedSize(min, max)
```

All arithmetic must use checked u64/i64 operations. Overflow, base mismatch,
unknown upper bounds, or inconsistent CFG meets produce `Unknown`. Do not infer
wraparound ranges.

### Alias Relation

Use the following result lattice:

```text
NoAlias
MustAlias
PartialAlias
MayAlias
```

Required proofs:

- Different address spaces are `NoAlias`.
- Exact or bounded disjoint intervals with the same proven base are `NoAlias`.
- Equal exact intervals with the same base are `MustAlias`.
- Proven intersecting intervals are `PartialAlias`.
- Different or unknown symbolic bases remain `MayAlias`.

The existing boolean-style consumers may continue treating every result except
`NoAlias` as aliasing until they are individually upgraded.

### Bounded Clobber Queries

Add a simple ordered scan over one analyzer block or an already accepted
single-entry straight-line region:

```text
hasMayAliasRead(begin_op, end_op, location)
hasMayAliasWrite(begin_op, end_op, location)
findReachingMustAliasStore(load_op)
findOverwritingMustAliasStore(store_op)
```

This is not MemorySSA. The scan stops at CFG joins, branches, backedges, hard
barriers, escape effects, or unknown effects.

### Expansion Proof

Introduce a proof object keyed by `MemoryOp::Id`:

```text
RequiredUpperBound
GuaranteedBytesBeforeOp
CoveredByPlan
OverflowProvenImpossible
ZeroSizeProven
```

Lowering may skip an expansion check only when:

```text
RequiredUpperBound <= GuaranteedBytesBeforeOp
```

or when the exact operation ID is covered by an already emitted precheck.
Lowering must not infer coverage from a broad PC range alone.

## Implementation Plan

### Commit 1: Stronger Intervals, Alias Analysis, and Diagnostics

This commit changes analysis only and does not change lowering.

- [ ] Add exact and bounded base-plus-offset interval forms.
- [ ] Add checked interval union, containment, equality, overlap, and disjoint
      queries.
- [ ] Extend alias results with `MustAlias` and `PartialAlias`.
- [ ] Add bounded block/linear-region clobber queries.
- [ ] Preserve old `NoAlias/MayAlias` behavior through compatibility helpers.
- [ ] Add rejection counters for unknown base, unknown upper bound, overflow,
      base mismatch, may-alias clobber, and barrier clobber.
- [ ] Add unit tests for constants, same-base offsets, bounded ranges,
      overlapping writes, different spaces, overflow, and CFG entry meets.

Build gate:

- `EVMMemory*` and `evmJitFrontendTests` pass with unchanged expansion/store
  counters on the 200-transaction sample.

### Commit 2: Relax Block Precheck and Expansion Elision

- [ ] Compute `GuaranteedBytesBeforeOp`, including growth caused by earlier
      operations in the same block and predecessor guarantees.
- [ ] Split a block into maximal safe precheck windows instead of rejecting the
      whole block after one unknown operation or barrier.
- [ ] Accept safe prefixes and suffixes with at least two covered expansion
      checks; use an explicit cost model instead of the fixed three-op
      `ProvenRange` threshold.
- [ ] Allow gaps and overlaps between constant intervals when only expansion
      coverage is being planned. Alias restrictions remain required for data
      transformations.
- [ ] Allow side-effect-free non-memory instructions between covered memory
      operations.
- [ ] Keep the precheck at the first covered memory operation. Do not move it
      above the window.
- [ ] Replace PC-range consumption with explicit covered operation IDs.
- [ ] Add one best safe window per block first. Multiple windows per block are
      a separate follow-up within this PR series.
- [ ] Elide expansion for bounded symbolic intervals only when their checked
      upper bound is already guaranteed.
- [ ] Keep the 128 MiB planning cap initially; add telemetry for candidates
      rejected only by the cap. Change the cap only in a later measured patch,
      never by bypassing runtime OOG checks.

Required tests:

- safe prefix before unknown address;
- safe suffix after a barrier starts a new window;
- gaps and overlapping intervals share an expansion precheck;
- pure arithmetic between memory operations is accepted;
- `GAS`, `MSIZE`, CALL, LOG, storage, RETURN, and REVERT split windows;
- per-op local guarantee removes a later expansion check;
- bounded symbolic upper bound accepted/rejected cases;
- explicit operation IDs prevent accidental coverage of an intervening op.

### Commit 3: Better Memory Grouping

- [ ] Separate `ExpansionGroup` from `DataDependenceGroup`; expansion grouping
      must not require `NoAlias` when no load/store value is transformed.
- [ ] Group non-contiguous and overlapping intervals by maximum required end.
- [ ] Permit read-only or proven non-clobbering memory operations between group
      members.
- [ ] Select groups by estimated removed expansion checks and emitted precheck
      cost, not only operation count.
- [ ] Add support for multiple non-overlapping safe windows in one block after
      explicit operation-ID consumption is stable.
- [ ] Retain the current contiguous grouping path as fallback during rollout.

### Commit 4: Conservative Dead Store Elimination

- [ ] Start with exact `MustAlias` full-overwrite stores in one block.
- [ ] Extend only to accepted straight-line regions after block-local tests and
      telemetry are stable.
- [ ] Reject when any intervening read, may-alias access, barrier, escape, CFG
      split, merge, or backedge exists.
- [ ] Eliminate only the data write. Preserve operand evaluation, static opcode
      gas, overflow behavior, and the original expansion effect unless a
      separate expansion proof covers it.
- [ ] Do not implement partial-byte DSE in the first version.
- [ ] Add counters for candidates, full-overwrite proofs, alias rejection,
      read-clobber rejection, expansion-preserved stores, and eliminated writes.

### Commit 5: Conservative Load Forwarding

- [ ] Start with exact 32-byte `MSTORE -> MLOAD` forwarding in one block.
- [ ] Require a reaching `MustAlias` store and no intervening may-alias write,
      escape, barrier, or CFG boundary.
- [ ] Preserve MLOAD gas charging and emit its expansion check unless a separate
      expansion proof removes it.
- [ ] Handle byte order explicitly; defer mixed `MSTORE8` reconstruction and
      partial-overlap forwarding.
- [ ] Extend to accepted straight-line regions only after block-local
      differential tests pass.
- [ ] Add counters for candidates, forwarded loads, alias rejection, clobber
      rejection, and expansion retained/elided.

### Commit 6: MCOPY Expansion and Data Optimization

- [ ] Model MCOPY source read and destination write intervals independently.
- [ ] Compute required expansion as
      `max(src + size, dst + size)` with checked arithmetic.
- [ ] Preserve the EVM rule that zero size causes no memory expansion even for
      otherwise invalid-looking offsets.
- [ ] Allow constant or bounded MCOPY expansion checks to consume per-op entry
      guarantees and safe prechecks.
- [ ] Preserve overlap semantics equivalent to `memmove`; never rewrite an
      overlapping MCOPY as a non-overlapping copy.
- [ ] Initially optimize expansion only. Add copy elimination or forwarding in
      a separate patch after alias and clobber proofs are exercised.
- [ ] Add exact, disjoint, overlap, zero-size, overflow, and barrier tests.

## Correctness Invariants

1. Memory expansion cost and OOG behavior remain EVM-equivalent.
2. `MSIZE` observes exactly the memory size required by the original opcode
   order.
3. `GAS` cannot observe expansion moved from a later operation.
4. Prechecks never cross externally visible effects or exceptional operations.
5. Removing a store write does not remove its required expansion or gas.
6. Forwarding a load value does not remove its required expansion or gas.
7. Unknown, overflowed, or inconsistent proofs always fall back.
8. Merge predecessors contribute only facts guaranteed on every incoming edge.
9. MCOPY preserves source-before-write overlap behavior and zero-size rules.
10. Analysis and telemetry are deterministic and independent of host pointer
    values or container iteration accidents.

## Telemetry

Add counters in the PR that owns each behavior. At minimum track:

```text
memory_alias_no_alias
memory_alias_must_alias
memory_alias_partial_alias
memory_alias_may_alias
memory_interval_rejected_unknown_base
memory_interval_rejected_unknown_upper_bound
memory_interval_rejected_overflow
memory_precheck_safe_windows
memory_precheck_partial_windows
memory_precheck_covered_ops
memory_precheck_rejected_barrier
memory_precheck_rejected_cost
memory_expand_elided_entry_guarantee
memory_expand_elided_local_guarantee
memory_expand_elided_bounded_interval
memory_dse_eliminated_writes
memory_load_forwarded
memory_mcopy_expand_elided
```

Continue reporting the existing counters so before/after comparisons remain
valid:

```text
memory_expansion_plan_covered_ops
small_frame_prechecked_total
mload_expand
mstore_expand
mstore8_expand
mcopy_expand
```

## Verification Plan

For every PR:

1. Run new unit tests and all `EVMMemory*` tests.
2. Run all `evmJitFrontendTests`.
3. Build with `ZEN_ENABLE_EVM_MEMORY_PLAN_FRAMEWORK` both ON and OFF.
4. Run relevant MIR/compiler tests.
5. Run EVM spec/state tests for affected opcodes in interpreter and multipass
   modes where available.
6. Differentially execute randomized memory-operation sequences against the
   feature-off build, comparing status, return bytes, gas left, and final
   memory-observable output.
7. Rerun the fixed 200-transaction suite and compare return code, output,
   timeout count, plan coverage, and expansion counters.
8. Run `git diff --check` and manually review barrier and gas ordering.

## Success Criteria

- Zero return-code, output, gas, or timeout mismatches.
- Existing PR572 and CFG-aware memory tests continue to pass.
- `memory_expansion_plan_covered_ops` or per-op guaranteed-byte elision
  increases on the fixed sample.
- `mload_expand`, `mstore_expand`, or `mcopy_expand` decreases without merely
  moving the same expansion to an unsafe earlier position.
- DSE and forwarding counters correspond to independently verified
  MustAlias/no-clobber proofs.
- Compile-time and generated-code growth are measured; regressions without
  meaningful coverage gains block rollout.

## Stop Conditions

Stop the current PR and leave a TODO instead of widening scope when:

- correctness requires arbitrary CFG joins or loop reasoning;
- a proof requires full MemorySSA or dominator/post-dominator construction;
- expansion would need to move across a hard barrier;
- dynamic address/size lacks a finite checked upper bound;
- DSE cannot preserve expansion, gas, or exceptional behavior;
- MCOPY overlap cannot be proven safe.

If real-transaction telemetry remains flat after PR 2 and PR 3, prioritize
block-local DSE/load forwarding evidence before investing in full CFG MemorySSA.

## Risks

- **Incorrect alias proof:** may change loaded or returned bytes. Mitigate with
  conservative `MayAlias`, checked arithmetic, and differential fuzzing.
- **Expansion moved too early:** may change `GAS`, `MSIZE`, OOG timing, or
  external effects. Mitigate with safe windows and hard barrier splitting.
- **DSE removes expansion:** a dead write may still be the first expanding
  operation. Mitigate by separating write elimination from expansion elision.
- **Load forwarding removes observable work:** the load still charges gas and
  may expand memory. Preserve both independently of value forwarding.
- **MCOPY overlap regression:** source and destination can overlap. Preserve
  memmove semantics and reject uncertain transformations.
- **Compile-time growth:** pairwise alias scans can become quadratic. Bound
  scans to one block or an accepted straight-line region and add candidate
  limits before wider CFG work.
