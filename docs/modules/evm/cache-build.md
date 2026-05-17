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
                        bool EnableSPP);
```

Single entry that zero-initialises the cache vectors, populates the
JUMPDEST and PUSH-value maps, and delegates the rest to
`buildGasChunksSPP`. `EnableSPP=true` selects the SPP-scheduled
chunk-cost path (`GasChunkCostSPP` filled); `EnableSPP=false` runs the
straight-line fallback only.

## Pipeline (in shipped execution order)

| # | Phase | Purpose |
|---:|---|---|
| 0 | `buildJumpDestMapAndPushCache` | Single bytecode walk: mark valid JUMPDESTs (skipping PUSH-data regions); decode PUSHn immediates into `PushValueMap` |
| 1 | `buildGasBlocks` | Single bytecode walk: emit one `GasBlock` per basic block, record `JumpDestBlocks` inline, compute per-block straight-line gas |
| 2 | `buildCFGEdges` | Single sweep: emit Succs/Preds edges into `EdgeTables`; stamp `ImplicitDynamicPredCount` on JUMPDEST blocks reachable by unresolved dynamic JUMP |
| 3 | `splitCriticalEdges` | Insert empty synthetic blocks on `multi-succ → multi-pred` edges; appends new entries onto `Blocks` and `EdgeTables` |
| 4 | `buildAdjacencyCSR` | Flatten `EdgeTables.Succs` and `.Preds` into two read-only `CSRGraph`s after the graph is frozen |
| 5 | `computeReachable` | DFS from block 0 over `SuccsCSR`; produce `Reachable` bitset |
| 6 | `computeDomInfo` | Cooper-Harvey-Kennedy fixpoint over `PredsCSR` for `IDom`, then Tarjan DFS over the dominator tree for `Enter`/`Exit` Euler tour stamps; produce `RPO` from the forward DFS |
| 7 | `findBackEdgesUsingDominators` | Iterate edges; emit back-edges where successor `dominates(succ, curr)` |
| 8 | `computeReverseTopo` | Return `reverse(DomInfo::RPO)` |
| 9 | `buildLoopsUsingDominance` | From dominator-based back-edges, gather natural-loop body sets; returns `true` if every node's back-edge target dominates it (reducible) |
| 10 | `computeInCycle` | **Conditional**: when `UseLinearSPP=true` (reducible result from 9), set `InCycle = union(Loops[].NodeMask)`; when `UseLinearSPP=false`, fall back to Tarjan SCC over `SuccsCSR` for `InCycle` |
| 11 | `meteringInit` | Copy per-block `Cost` into the `Metering` working array used by lemma614 |
| 12 | `lemma614Schedule` | SPP gas-shifting in reverse-topo order: for each block, try to shift its gas charge onto its successors via `lemma614Update`, gated on `effectivePredCount` and `InCycle` |
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
| 22 | _pad[2]_ | — | Alignment to 8-byte `Cost` |
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

### Reducible-CFG fast-path soundness

The R2 reviewers established the soundness story explicitly. When
`UseLinearSPP=true` (i.e. `buildLoopsUsingDominance` reported reducible),
`computeInCycle` is a **performance optimisation**, not the safety
mechanism. The actual safety invariant lives in `lemma614Update`'s
multi-predecessor guard:

```cpp
if (effectivePredCount(Succ, Blocks, PredsCSR) != 1) {
  // refuse shift
}
```

`effectivePredCount` folds `ImplicitDynamicPredCount` into the
structural pred count, so any JUMPDEST that could be reached by an
unresolved dynamic JUMP sees count > 1 and the lemma refuses to shift
gas across that edge. Every node inside any SCC of size ≥ 2 has at
least one in-cycle predecessor on top of any out-of-cycle entry, so
its `effectivePredCount` is ≥ 2 and the shift is refused even on
irreducible CFGs the fast-path filter misses.

**Future-contributor warning**: do **not** remove the multi-pred guard
on the assumption that `InCycle` covers it. On an irreducible 2-entry
cycle `A ↔ B` where neither node dominates the other, the dominator-based
back-edge set is empty, `buildLoopsUsingDominance` returns `true` with
`Loops` empty, and `InCycle = union(empty) = all-zeros`. Without the
multi-pred guard, lemma614 would mis-charge such a CFG; with the guard,
correctness is preserved.

### Irreducible-CFG fallback

When `buildLoopsUsingDominance` returns `false`, `UseLinearSPP=false`
and the Tarjan SCC pass runs over `SuccsCSR` to fill `InCycle`. The
`effectivePredCount` guard remains active in this path too, so Tarjan
SCC is defence-in-depth, not the only safety net.

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
