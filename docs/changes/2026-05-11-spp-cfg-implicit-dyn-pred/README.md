# Change: SPP CFG over-approximation via implicit dyn-pred count

- **Status**: Implemented
- **Date**: 2026-05-11
- **Tier**: Light
- **Parent PR**: builds on `feat/gas-check-placement` (PR #446)

## Overview

Replace the `O(D * J)` explicit over-approximation edges in
`buildCFGEdges` (where `D` = #unresolved dynamic jumps and `J` = #JUMPDEST
blocks) with an `O(D + J)` implicit predecessor count. The SPP shifting
pass `lemma614Update` makes its single-vs-multi-predecessor decision via
the new `effectivePredCount`, so behavior is equivalent for every pair
(parent, JUMPDEST-successor) that the explicit representation would have
materialized — without ever building the dense edge set.

The static-only reachability gap that this creates (dyn-only JUMPDESTs
become unreachable from the entry block) is closed by an explicit
reachability stitch that seeds every JUMPDEST as a root before the
dominator and loop analyses run.

## Motivation

The current `feat/gas-check-placement` representation builds a dense
over-approximate CFG: every unresolved dynamic `JUMP`/`JUMPI` adds one
edge to every JUMPDEST in the contract. This is `O(D * J)` edges, and
`addEdge`'s `std::find` dedup makes each insertion `O(deg)`, so the
total cost is `O(D * J^2 + J * D^2) = O(D * J * (D + J))`. For
pathological dyn-heavy contracts the asymptotic blow-up is third-order.

Independently, `splitCriticalEdges` then processes those same edges
and (because every JUMPDEST has many predecessors in the over-approx
graph) splits each one with another `O(deg)` erase + insert pair —
contributing the same asymptotic cost a second time. PR #446 already
gates the SPP pipeline on JIT-consumer modules to bound the runtime
impact, but the per-module cost is still material when a large
contract is JIT-compiled.

The dense edges contribute nothing to SPP's local shift decision:
`lemma614Update` refuses to shift into any successor with
`effectivePredCount > 1`, and every JUMPDEST that the dynamic jump
could reach has many predecessors after over-approximation. The edges
are pure compile-time tax.

## Design

### Implicit predecessor count (replaces `D * J` edges)

`GasBlock` gains one field:

```cpp
uint32_t ImplicitDynamicPredCount = 0;
```

Set on every JUMPDEST when the contract has at least one unresolved
dynamic jump. The count equals `D`, matching the number of
predecessors the explicit over-approximation would have produced.

`effectivePredCount` folds the count in:

```cpp
static size_t effectivePredCount(const GasBlock &Block) {
  size_t Count = Block.Preds.size();
  if (Block.Start == 0) ++Count;
  Count += Block.ImplicitDynamicPredCount;
  return Count;
}
```

`lemma614Update` reads `effectivePredCount` for every shift decision,
so it sees an identical "multi-pred?" answer to the explicit case.
`buildCFGEdges` no longer adds any edge from a dynamic-jump block; the
SPP graph carries only static fall-through and resolved static-jump
edges.

### Reachability stitch (closes the dom/loop gap)

After `computeReachable` runs from the entry block, every JUMPDEST is
seeded into the reachable set and forward-propagated via `Succs`.
Without this step, dyn-only JUMPDESTs (e.g. Solidity function return
addresses, reached at runtime only via `PUSH ret; ... JUMP`) would
remain unreachable in the static-only CFG, and `computeDominators` /
`buildLoopsUsingDominance` would skip them — letting their static
successor chains miss SPP shifting opportunities.

The stitch is purely additive (sets only `Reachable[x] = 1`) and
maintains the dominator monotonicity property required by SPP.

### Compile-time complexity

| Pass                  | Before (over-approx)        | After (implicit count)       |
|-----------------------|-----------------------------|------------------------------|
| `buildCFGEdges`       | `O(D * J^2 + J * D^2)`      | `O(N)`                       |
| `splitCriticalEdges`  | `O(D * J^2)` on dyn edges   | `O(N)` (no dyn edges to split) |
| `computeReachable`    | `O(N + E_dense)`            | `O(N) + reachability stitch` |
| `computeDominators`   | Bitset width up by `+1` per JUMPDEST extra Pred | Same width, sparser graph |

## Alternatives considered

### Super-node (DynDispatch hub) — rejected

A virtual `DynDispatch` block routing all dynamic jumps into one hub,
then fanning out to all JUMPDESTs. `O(D + J)` edges, preserves
reachability without a stitch, every standard pass sees a "real" CFG.

Implemented and benchmarked side-by-side. Result on
`evmone-unittests` for the `loop_full_of_jumpdests` test (single test,
multipass mode):

| Implementation | Wall time |
|----------------|-----------|
| `feat/gas-check-placement` (over-approx)  | 7.3 s |
| **A** (implicit count, this PR)           | 3.3 s |
| **B** (super-node)                        | 275 s |

B's blow-up traces to `computeDominators` / `buildLoopsUsingDominance`
on the dispatch hub: the hub creates a deeply irreducible CFG where
the iterative dataflow takes super-linear passes to converge, and
every back-edge into the hub triggers a `collectNaturalLoop` walk
over every block transitively reachable from it. Patching the loop
passes to special-case the hub re-introduces the structural
asymmetry that motivated A in the first place. **B is unusable.**

### Edge-budget fallback — rejected

Keep the explicit over-approx but skip SPP when
`D * J > kBudget`. Trades a complexity ceiling for an SPP cliff; on
contracts that sit just over the budget the gas-check density jumps
discontinuously. Solves a symptom rather than the root cause.

## Impact

### Performance (27 paper benches, `--benchmark_min_time=3x`, 5 reps)

vs `feat/gas-check-placement` (PR #446) baseline:

- **Geomean: 0.9727× (-2.73%)**
- Arithmetic mean: -1.48%

**Wins** (regressions from PR #446 reversed):

| Benchmark | PR #446 vs upstream | A v2 vs PR #446 |
|---|---|---|
| `micro/jump_around/empty`       | +22.8% | **-53.1%** |
| `micro/signextend/zero`         | -42.7% | -24.6% (further) |
| `main/blake2b_huff/8415nulls`   | -5.3%  | -14.7% (further) |
| `main/structarray_alloc/nfts_rank` | -6.2% | -4.9% (further) |
| `main/snailtracer/benchmark`    | -      | -1.3% |
| `main/weierstrudel/15`          | +17.5% | -2.5% |

**Worst-case regressions** (vs PR #446):

| Benchmark | A v2 vs PR #446 | Note |
|---|---|---|
| `main/sha1_shifts/empty`  | +27.0% (mean) | Single-outlier noise; median delta +2.7% |
| `micro/memory_grow_mstore/by16` | +13.98% | Real |
| `micro/memory_grow_mload/by32`  | +10.64% | Real |
| `micro/loop_with_many_jumpdests/empty` | +6.81% | Real (was +48.5% in A v1 without reachability stitch) |

All real regressions are well under the 25% CI gate. The
`sha1_shifts/empty` mean is pulled up by one rep that hit 8.87us out
of 5; the median is +2.7%.

### Correctness

- `evmone-unittests` multipass: **223/223 pass**, 8.4 s wall time
  (vs 13 s baseline, 305 s for scheme B).
- `tools/format.sh check`: clean.

## Changed files

- `src/evm/evm_cache.cpp` — `GasBlock::ImplicitDynamicPredCount` field;
  `effectivePredCount` folds it in; `buildCFGEdges` stamps the count
  on every JUMPDEST and skips the `D * J` edge-add loop; reachability
  stitch in `buildGasChunksSPP` seeds every JUMPDEST as a root after
  `computeReachable`.

## Out of scope

- The peripheral diagnostics about `GasChunkCostSPP` in clangd are
  pre-existing for the PR #446 branch and unrelated to this change.
- Re-introducing super-node / DynDispatch later — would require
  rewriting `computeDominators` and `buildLoopsUsingDominance` to
  treat dispatch hubs structurally, which is invasive and gives no
  measurable benefit over the implicit-count representation.
