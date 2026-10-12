# EVM Bytecode Cache Build Specification

> Directory: `src/evm/evm_cache.cpp`

This spec covers the **cache-build pipeline internals** that populate
`EVMBytecodeCache` (JumpDestMap / PushValueMap / GasChunkEnd /
GasChunkCost / GasChunkCostSPP). For the consumer-side contract of those
fields and how the interpreter/JIT read them, see `evm/spec.md` §2 and
`evm/data-model.md` `EVMBytecodeCache`.

## Boundaries and Responsibilities

- **In scope**: bytecode walk, CFG construction, dominator/loop/SCC
  analysis, SPP (Structured Precharging Pass) gas-chunk scheduling,
  and the cache-build phase ordering that produces a populated
  `EVMBytecodeCache` for downstream consumers.
- **Out of scope**: opcode dispatch (in `evm/spec.md`), JIT lowering
  (in `compiler/`), and the consumer-side gas accounting that uses
  the chunk arrays at execution time.

## Entry Point

```cpp
void buildBytecodeCache(EVMBytecodeCache &Cache,
                        const common::Byte *Code,
                        size_t CodeSize,
                        evmc_revision Rev,
                        bool EnableSPP,
                        bool EnableR1 = true);
```

Single entry that zero-initialises the cache vectors, populates the
JUMPDEST and PUSH-value maps, and delegates the rest to
`buildGasChunksSPP`. `EnableSPP=true` selects the SPP-scheduled
chunk-cost path (`GasChunkCostSPP` filled); `EnableSPP=false` runs the
straight-line fallback only. `EnableR1=true` (default) runs the
cross-block Const/ConstSet worklist after the block-local jump pass;
`ZEN_EVM_DISABLE_R1=1` force-disables it.

## Pipeline (in shipped execution order)

| # | Phase | Purpose |
|---:|---|---|
| 0 | `buildJumpDestMapAndPushCache` | Single bytecode walk: mark valid JUMPDESTs (skipping PUSH-data regions); decode PUSHn immediates into `PushValueMap` |
| 0b | `resolveJumpTargetsByAbstractStack` | Block-local Const resolution (PUSH/DUP/SWAP within one block) |
| 0c | `resolveJumpTargetsCrossBlock` | Worklist Const/ConstSet/Top fixpoint. Fail-closed on Top or non-convergence (local map unchanged, no multi-targets). Commits single-target `ResolvedJumpTargets` and multi-target `ResolvedJumpMultiTargets` |
| 1 | `buildGasBlocks` | Single bytecode walk: emit one `GasBlock` per basic block, record `JumpDestBlocks` inline, compute per-block straight-line gas |
| 2 | `buildCFGEdges` | Single sweep: emit resolved (single + multi) and fallthrough Succs/Preds edges into `EdgeTables`; for remaining unresolved dynamic JUMP/JUMPI, mark the source with `HasUnresolvedDynamicSuccessor` and stamp possible JUMPDEST targets with `ImplicitDynamicPredCount` |
| 3 | `splitCriticalEdges` | Insert empty synthetic blocks on `multi-succ → multi-pred` edges; appends new entries onto `Blocks` and `EdgeTables` |
| 4 | `buildAdjacencyCSR` | Flatten `EdgeTables.Succs` and `.Preds` into two read-only `CSRGraph`s after the graph is frozen |
| 5 | `computeReachable` | DFS from block 0 over `SuccsCSR`; produce `Reachable` bitset |
| 6 | `computeDomInfo` | Cooper-Harvey-Kennedy fixpoint over `PredsCSR` for `IDom`, then Tarjan DFS over the dominator tree for `Enter`/`Exit` Euler tour stamps; produce `RPO` from the forward DFS |
| 7 | `findBackEdgesUsingDominators` | Iterate edges; emit back-edges where successor `dominates(succ, curr)` |
| 8 | `computeReverseTopo` | Return `reverse(DomInfo::RPO)` |
| 9 | `buildLoopsUsingDominance` | Gather natural-loop bodies from dominance back-edges whose source is reachable; return `false` if a detected body violates header dominance or detected loops overlap without nesting. A `true` result validates only the detected loop set, not general CFG reducibility |
| 10 | `computeInCycle` | **Conditional**: when `UseLinearSPP=true`, set `InCycle = union(Loops[].NodeMask)`; when `UseLinearSPP=false`, run a two-pass Kosaraju-style SCC traversal over `SuccsCSR` and `PredsCSR`. The traversal therefore runs only for a rejected detected-loop set |
| 11 | `meteringInit` | Copy per-block `Cost` into the `Metering` working array used by lemma614 |
| 12 | `lemma614Schedule` | SPP gas-shifting in reverse-topo order: for each block, try to shift its gas charge onto its successors via `lemma614Update`, gated on `HasUnresolvedDynamicSuccessor == 0`, `effectivePredCount`, and `InCycle` |
| 13 | `writeback` | Project per-block `Metering` back onto `GasChunkEnd` / `GasChunkCost` / `GasChunkCostSPP` |

`EVM_PROFILE_BEGIN(<phase>) / EVM_PROFILE_END(<phase>)` chrono pairs
bracket each phase when `ZEN_EVM_CACHE_PROFILE=ON`; they macro-elide
to `(void)0` in release builds.

## Core Types

### `GasBlock` — 32 bytes (`static_assert`-locked)

Per-block scalars used by every downstream pass.

| Offset | Field | Type | Meaning |
|---:|---|---|---|
| 0 | `Start` | `uint32_t` | PC of first byte in the block |
| 4 | `End` | `uint32_t` | PC one past the last byte |
| 8 | `LastPc` | `uint32_t` | PC of the terminating opcode |
| 12 | `PrevPc` | `uint32_t` | PC of the opcode immediately before `LastPc` (`UINT32_MAX` if none) |
| 16 | `ImplicitDynamicPredCount` | `uint32_t` | Count of dynamic-JUMP blocks that could land on this JUMPDEST (carried separately to avoid `D×J` materialised over-approximation edges) |
| 20 | `LastOpcode` | `uint8_t` | Terminator opcode |
| 21 | `PrevOpcode` | `uint8_t` | Opcode before terminator |
| 22 | `HasUnresolvedDynamicSuccessor` | `uint8_t` | Nonzero when an unresolved dynamic JUMP/JUMPI has runtime targets omitted from this source's explicit successor list |
| 23 | _pad[1]_ | — | Alignment to 8-byte `Cost` |
| 24 | `Cost` | `uint64_t` | Straight-line gas cost of the block |

The 32-byte stride is load-bearing for the cache-density gains; the
`static_assert(sizeof(GasBlock) == 32)` traps accidental field
additions so any layout drift is caught at build time. Re-tuning the
layout requires re-measuring with `evmCacheComplexityDemo`.

### `EdgeTables` — mutable CFG adjacency during build

```cpp
struct EdgeTables {
  std::vector<std::vector<uint32_t>> Succs;
  std::vector<std::vector<uint32_t>> Preds;
};
```

Written by `buildCFGEdges` and `splitCriticalEdges`; deduplicating
edge insertion is provided by the `addEdge` helper (linear scan over
the per-block vectors). Consumed by `buildAdjacencyCSR` and not read
directly by any downstream pass.

Edges for unresolved dynamic jumps are deliberately absent from both
tables and the resulting CSR graphs. `ImplicitDynamicPredCount`
represents those omitted incoming edges on each possible JUMPDEST,
while `HasUnresolvedDynamicSuccessor` marks the source whose runtime
successor set is incomplete. For an unresolved JUMPI, its fallthrough
edge remains explicit; only its taken-target edges are omitted.

### `CSRGraph` — read-only flat adjacency

```cpp
struct CSRGraph {
  std::vector<uint32_t> Off;   // size = NumNodes + 1
  std::vector<uint32_t> Data;  // size = total edges
};
```

Compressed-sparse-row layout: `Off[i]..Off[i+1]` is the neighbour
slice of node `i` inside `Data`. Built **once** after
`splitCriticalEdges` freezes the graph; every downstream pass reads
through `CSRGraph::operator[]` returning a `Range{B, E}` view, which
removes the per-node heap chase of the prior `vector<vector<uint32_t>>`
layout.

The build uses the templated `buildAdjacencyCSR<bool SelectSuccs>` so
the same code projects both Succs and Preds.

### `DomInfo` — dominator-tree query layer

```cpp
struct DomInfo {
  std::vector<uint32_t> IDom;   // CHK fixpoint result
  std::vector<uint32_t> Enter;  // Tarjan DFS enter time on the idom tree
  std::vector<uint32_t> Exit;   // Tarjan DFS exit time
  std::vector<uint32_t> RPO;    // forward DFS reverse-postorder
};

bool DomInfo::dominates(A, B) const;  // O(1) via Enter/Exit Euler tour
```

`computeDomInfo` runs CHK until `IDom` stabilises (a
`chkFixpointRounds` counter tracks how many sweeps it takes — see
Diagnostic Counters below), then a single Tarjan DFS over the
dominator tree fills `Enter` / `Exit`. After this phase every
downstream pass uses `dominates(A, B)` as an O(1) range query.

`RPO` is exposed so passes needing a topo order over the non-back-edge
sub-DAG (`computeReverseTopo`, `lemma614Schedule`) reuse this single
DFS instead of running their own.

## Invariants

### Loop-set selection and per-update soundness

`UseLinearSPP=true` means that the dominance-based natural loops found
by `buildLoopsUsingDominance` passed its body-dominance and nesting
checks. It does not prove that the CFG is reducible. A multi-entry SCC
with no dominance back-edge produces no `LoopInfo` and can therefore
return `true` with that SCC absent from `InCycle`. The two-pass SCC
traversal runs only when the detected loop set fails validation.

Soundness does not require complete SCC classification. For updates
that can occur on a runtime path, it follows from these local
conditions:

```cpp
if (Node.HasUnresolvedDynamicSuccessor != 0) {
  return false;
}

if (effectivePredCount(Succ, Blocks, PredsCSR) != 1) {
  MinSucc = 0;
  continue;
}
```

`effectivePredCount` folds `ImplicitDynamicPredCount` into the
structural pred count. A possible dynamic target with an explicit
incoming edge therefore has count greater than one, so the lemma
cannot move its cost onto only that explicit predecessor. A target
with only implicit incoming edges is not present in any source's
`SuccsCSR` slice and cannot be selected for a shift.

Independently, no block with `HasUnresolvedDynamicSuccessor != 0` may
act as a lemma614 shift source. Moving explicit-successor cost onto
such a source would increase the charge on every runtime exit while
compensating only successors represented in `SuccsCSR`; an omitted
taken target would receive no compensating reduction. The guard makes
the represented successor list complete for every accepted source.

A runtime-reachable source of a recorded dominance back-edge belongs
to the corresponding natural-loop mask and is skipped before
`lemma614Update`. The `BackEdges` branch therefore omits no executable
edge for a reachable source that is actually updated. In particular,
an updated reachable source in an unrecognized SCC has no recorded
outgoing back-edge, so the branch is a no-op. If `AllowedMask` excludes
any other represented successor, the first scan sets `MinSucc` to zero
and rejects the whole update.

For a successful update on a reachable source, every represented
runtime successor is therefore included, and the source passes the
gas-sensitive boundary check. Each successor has one effective
predecessor, is not the program entry, has no implicit dynamic
predecessor, and passes the gas-chunk boundary check. The update
subtracts the same common cost from every such successor that it adds
to the source. Every source execution selects one compensated
successor, and every execution of that successor arrives from the
source, so the costs balance on complete paths even when an SCC was
not added to `InCycle`.

`RPO` and the schedule can still contain unreachable blocks, while
`buildLoopsUsingDominance` skips an unreachable back-edge source.
`lemma614Update` may therefore update such a source and skip one of its
recorded back-edges. This does not affect runtime gas because no
executable path reaches the source. The local path-balance claim above
is intentionally limited to runtime-reachable sources.

**Future-contributor warning**: `InCycle`, the dynamic-edge guards,
`effectivePredCount`, and the schedule masks enforce different parts of
this invariant. None can be removed on the assumption that
`UseLinearSPP=true` proves reducibility.

### Conditional two-pass SCC fallback

When `buildLoopsUsingDominance` returns `false`, `UseLinearSPP=false`
and a two-pass Kosaraju-style traversal runs over `SuccsCSR` and
`PredsCSR` to fill `InCycle`. A `true` result does not trigger the
fallback and may leave an SCC without dominance back-edges unmarked.
Both paths retain the same local source, successor, and schedule checks
described above.

### Regression scope

The permanent cache and execution regressions added for the dynamic-jump
fix directly cover the `HasUnresolvedDynamicSuccessor` behavior. They do
not execute an unrecognized SCC or a synthetic critical edge through the
complete SPP pipeline. Changes to loop discovery, back-edge filtering, or
synthetic-block writeback require dedicated regression coverage for those
paths.

### Block-vector reserve

`buildGasBlocks` calls `Blocks.reserve(CodeSize)` once up front so the
single-pass `emplace_back` never reallocates. `splitCriticalEdges`
appends additional synthetic blocks via `Blocks.push_back`; the
no-realloc guarantee applies to the **block-construction** loop only.
In practice the split count is bounded by the number of critical edges,
and no `GasBlock&` reference is taken across a `splitCriticalEdges`
append, so no use-after-move bug exists today. The
`Blocks.reserve(CodeSize)` wording is intentionally conservative.

## Diagnostic Counters

`ZEN_EVM_CACHE_PROFILE=ON` (CMake option, off by default and macro-elided in
release builds) enables two probes used by `evmCacheComplexityDemo` and
to anchor PR-time perf measurements:

- **Per-phase chrono pairs**: each `EVM_PROFILE_BEGIN(<phase>) /
  EVM_PROFILE_END(<phase>)` records wall-clock for the phase and
  accumulates into per-phase totals reported at process exit.
- **`chkFixpointRounds`**: counts how many CHK sweeps the dominator
  fixpoint takes to settle. Used to validate that adding SemiNCA would
  not save a measurable number of rounds on representative workloads.

The counters add ~0.5-1 µs per phase boundary; the 13 phase pairs
inside `buildGasChunksSPP` (plus phase 0 in `buildBytecodeCache`)
accumulate to ~1-1.3 ms of overhead at the N=100k synthetic stress.
Treat per-phase columns as approximate share, not exact decomposition.

## Cross-References

- `evm/spec.md` §2 — consumer-side contract of `EVMBytecodeCache`
- `evm/data-model.md` — `EVMBytecodeCache` field schema
- `docs/changes/2026-05-17-evm-cache-build-fusion/` — change doc + per-phase
  perf deltas (R2 PASS)
- `docs/changes/2026-05-16-evm-spp-overhaul/` — PR A foundation (CHK
  dominator, dom-CHK + Tarjan E/E, `ZEN_EVM_CACHE_PROFILE` instrumentation)
