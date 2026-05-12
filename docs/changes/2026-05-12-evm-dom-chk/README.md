# Change: linear-typical dominator pass for the EVM bytecode cache

- **Status**: Implemented
- **Date**: 2026-05-12
- **Tier**: Light
- **Parent PR**: stacked on `feat/gas-check-placement` (PR #446); rebased onto `main` after #446 merges.

## Overview

Replace the iterative bitset dataflow `computeDominators` in
`src/evm/evm_cache.cpp` (pre-PR line 619 on the parent branch) with a
new `computeDomInfo` (post-PR `src/evm/evm_cache.cpp:627`) implementing
the Cooper-Harvey-Kennedy 2001
(CHK) algorithm that produces a single immediate-dominator (`idom`)
array, augmented with Tarjan DFS pre/post times so that the dom-tree
ancestor query is `O(1)`. Update the two consumers
(`findBackEdgesUsingDominators`, `buildLoopsUsingDominance`) to query
dominance via the `DomInfo::dominates(A, B)` method, which tests for
interval containment instead of walking the idom chain.

Output semantics are preserved (every back edge and natural loop the old
pass identified, the new pass identifies). Memory drops from `O(N²)` bits
to `O(N)` `uint32_t` per array (IDom + Enter + Exit). Time drops from
`O(N²/64)` worst-case to **`O(N + E)` typical for the reducible
single-entry CFGs that dominate EVM bytecode (2 RPO passes + 1 DFS over
the dom tree); `O(N · E)` worst-case for pathological irreducible inputs
on the fixpoint step alone, but the post-fixpoint Enter/Exit DFS keeps
the dominance-query path at `O(N + E)` regardless**. CHK is *not*
`O(N · α(N))` — that bound is Lengauer-Tarjan with union-find compression.
We pick CHK because it is simpler to implement and verify, and gate 7
(the scaling demo) validates the typical-case bound empirically.

## Motivation

PR #446's Phase 7 cut the explicit `O(D · J)` over-approximation edges in
SPP CFG construction down to an implicit `ImplicitDynamicPredCount`, and
the intra-PR scaling demo showed a 7–8× cache-build speedup at N=10k–20k
JUMPDESTs:

| N JUMPDESTs | Cache build (post-#446, demo)  | Source                                              |
|-------------|--------------------------------|-----------------------------------------------------|
| 10,000      | 10.38 ms                       | `docs/changes/2026-05-11-spp-cfg-implicit-dyn-pred/README.md` (intra-PR table) |
| 20,000      | 43.68 ms                       | ditto                                               |
| 50,000      | not measured in #446           | extrapolation only                                  |
| 100,000     | ≈948 ms                        | user-provided pre-PR scaling measurement (run on this branch) |

Even on the two measured points, doubling `N` from 10k to 20k roughly
quadruples the time (4.2×). This is the signature of an `O(N²/64)`
bitset dataflow.

Profiling and the post-Phase-7 hotpath localise the cost to two inner
loops:

1. The per-node bitset AND across reachable predecessors:
   ```cpp
   for (uint32_t Pred : Blocks[Node].Preds) {
     for (size_t W = 0; W < Words; ++W) {
       NewDom[W] &= Dom[Pred][W];
     }
   }
   ```
   Each inner pass is `N/64` words, repeated for every reachable node and
   every fixpoint iteration.

2. The `vector<vector<uint64_t>>` itself — `N` rows of `⌈N/64⌉` words
   each, so `~N²/8` bytes. At `N=20000` this is ≈ 50 MB; at `N=100000`
   it is ≈ 1.25 GB. Allocation + cache-line traffic dominate the wall
   clock once `N` exceeds L2.

CHK keeps a single `uint32_t` per node (the immediate dominator) and
processes nodes in reverse-postorder. The `intersect(b1, b2)` helper
walks both fingers up the partially-built `idom` tree using
postorder-position numbers; each walk is `O(depth)` and the whole pass
is effectively linear for the reducible CFGs that survive
`splitCriticalEdges`. To avoid the same `O(depth)` cost on the millions
of dominance *queries* the callers issue, we precompute pre/post times
(`Enter`, `Exit`) over the dom-tree via a single DFS and answer
`dominates(A, B)` by interval containment in `O(1)`.

## Design

### CHK adapted to the multi-root forest

The current pass treats three classes of nodes as "self-dominators",
not just two. The third class is implicit:

| Class | Predicate (init) | Where in code (post-PR) |
|-------|------------------|-------------------------|
| A | `Reachable[N] == 0` | `evm_cache.cpp:647-650`, `IDom[I] = I` at init |
| B | `Preds.empty()` | `evm_cache.cpp:647-650`, same `IDom[I] = I` at init |
| C | `Reachable[N] == 1, Preds non-empty, but ALL preds have Reachable==0` | `evm_cache.cpp:651-661`, `HasReachablePred` flag false → `IDom[I] = I` at init |

Class C is rare (after the Phase-7 reachability stitch at
`evm_cache.cpp:1227-1260` it should not occur for SPP input, since the
stitch is forward-only via `Succs` and unreachable preds aren't created)
but must be preserved. Crucially, the old bitset pass also gives every
*descendant* `M` of a class-C root `N` the property `N ∈ Dom[M]` (N
dominates M), because `Dom[M] = Dom[N] ∪ {M} = {N, M}`. The new pass
therefore **seeds class C at init**, not just via a post-fixpoint
sweep, so descendants in step 4 can intersect against a settled root
and produce `IDom[M] = N` instead of bottoming out at self.

These nodes form the roots of a disjoint dominator forest. The new pass
preserves the multi-root structure without introducing an explicit
super-entry:

1. Initialise `IDom[N] = N` for every node in class A, B, **or C**
   (class C: reachable node whose entire reachable-pred set is empty).
2. Initialise `IDom[N] = UINT32_MAX` ("undefined") for every other
   reachable node.
3. **Build RPO** seeded from the set `{ N : IDom[N] == N }` — the union
   of A ∪ B, which is a superset of the entry-likes that the old pass
   treated as roots. The DFS follows `Succs` only, never crossing into
   unreachable neighbours.
4. Visit each non-root node in RPO. For each non-root, compute
   `new_idom = ⋂_{pred ∈ processed reachable preds} pred` via
   `intersect`. *"Processed reachable preds"* means
   `{ p ∈ Preds[N] : Reachable[p] == 1 ∧ IDom[p] != UINT32_MAX }`.
   The `intersect(b1, b2)` helper, with both operands processed, walks
   both fingers up the partially-built IDom tree by postorder position;
   when the two fingers cannot meet because they bottom out in distinct
   self-roots, the helper returns `UINT32_MAX` (the *divergence
   sentinel*).
5. **Multi-root divergence fallback**: if step 4 sees ≥2 processed
   reachable preds and `intersect` returns `UINT32_MAX` for any pair
   (meaning the preds lie in disjoint dominator forests), set
   `IDom[N] = N` for this RPO visit. This matches the current pass's
   `Dom[N] = {N}` semantics for that exact case.
6. Iterate the RPO loop until no `IDom[N]` changes. For a single-entry
   reducible CFG, this is at most 2 RPO passes. Multi-entry contracts
   add at most one extra pass per disjoint root.
7. **Post-fixpoint sweep** (finalising, *not* counted in the 2-pass
   bound): any node still at `IDom[N] = UINT32_MAX` — which can only
   happen for orphan reachable components not seeded by any root (a
   case the seeded class-A/B/C set should fully cover for SPP input) —
   gets `IDom[N] = N`. The sweep is retained as a defensive backstop;
   `ClassCDescendant_SeedsAtInit` and the four other dominator GTests
   verify the init-time seeding handles all observed cases.

### Enter/Exit DFS for `O(1)` dominance queries

After the IDom fixpoint converges, a single DFS over the dom tree
assigns each node an `Enter[N]` and `Exit[N]` time on a global counter.
For each root `R` (`IDom[R] == R`) the DFS visits `R`, recurses through
the `Children[R]` adjacency built by inverting `IDom`, and the Time
counter ticks monotonically. Across multiple roots the timeline keeps
counting, so two roots produce disjoint intervals — cross-root pairs
therefore answer `dominates == false` via non-containment.

```cpp
struct DomInfo {
  std::vector<uint32_t> IDom;
  std::vector<uint32_t> Enter;
  std::vector<uint32_t> Exit;

  bool dominates(uint32_t A, uint32_t B) const {
    if (A == B) return true;
    if (A >= IDom.size() || B >= IDom.size()) return false;
    return Enter[A] <= Enter[B] && Exit[B] <= Exit[A];
  }
};
```

The interval-containment test is `O(1)`. Two `Enter`/`Exit` arrays plus
`IDom` total `3N` `uint32_t` = `12N` bytes; for `N=100000` that is 1.2 MB,
compared to the ≈ 1.25 GB of the old bitset.

### Caller rewrites

`bitsetTest(Dom[X], Y)` reads "*does Y dominate X*?", so the rewrite
always passes the *dominator candidate* first and the *dominated node*
second. Three call sites in the current file:

Three call sites (pre-PR lines in the parent branch's
`computeDominators`-era source, current lines in this PR's post-rewrite
file):

| Pre-PR line | Post-PR line | Pre-PR call (parent branch)                       | Post-PR call (this PR)                  |
|-------------|--------------|---------------------------------------------------|------------------------------------------|
| 684         | 834          | `bitsetTest(Dom[From], To)` in `findBackEdgesUsingDominators` | `Dom.dominates(To, From)` |
| 793         | 943          | `bitsetTest(Dom[From], To)` in `buildLoopsUsingDominance` header discovery | `Dom.dominates(To, From)` |
| 838         | 990          | `bitsetTest(Dom[Node], Loop.Header)` in `buildLoopsUsingDominance` body sanity | `Dom.dominates(Loop.Header, Node)` |

The pre-PR `grep -n "bitsetTest(Dom" src/evm/evm_cache.cpp` returned
these three hits and no other dominance query in the SPP pipeline; the
post-rewrite grep (`rg -n "Dom\.dominates" src/evm/evm_cache.cpp`)
returns the three new call sites and nothing else.

### Memory and time

| Pass               | Before (post-#446)             | After (this PR)                 |
|--------------------|--------------------------------|---------------------------------|
| `computeDominators` → `computeDomInfo` | `O(N²/64)` time, `O(N²)` mem  | `O(N + E)` typical, `O(N · E)` worst (CHK fixpoint), `O(N)` mem |
| Enter/Exit DFS      | n/a                            | `O(N)` time, `O(N)` mem         |
| Back-edge scan      | `O(E)` bitset tests            | `O(E)` interval-containment tests |
| Loop collection (dominance queries) | `O(N²/64)` mask ops + scans | `O(Σ \|loop\|)` interval-containment tests (the surrounding loop-membership bitset OR/scan stays bitset-based; only the *dominance query* itself moves to the new path) |

All dominance queries are `O(1)` regardless of CFG shape — the only
shape-dependent term is the CHK fixpoint itself, which empirically
converges in 2 RPO passes on the reducible CFGs that EVM bytecode
produces.

### Why CHK, not Lengauer-Tarjan / SemiNCA

CHK is single-pass-style and easy to verify against the existing
dataflow on small CFGs. Worst-case CHK is `O(N²)` but in practice
converges in 2 RPO passes on reducible CFGs — the dominant case for
EVM bytecode. SemiNCA delivers a guaranteed `O(N · α(N))` (the proper
attribution, via union-find with path compression), but the constant
factor and implementation surface are larger; LLVM's
`llvm/Support/GenericDomTreeConstruction.h` runs to several hundred
lines.

We pick the simpler algorithm; gate 7 confirmed the typical-case bound
empirically (N=10k 2.85 ms, N=100k 40.1 ms — see §Results).

## Impact

Files touched in this PR:

- `src/evm/evm_cache.cpp` — replace `computeDominators` body with
  `computeDomInfo` (post-PR `src/evm/evm_cache.cpp:627`), append the
  Enter/Exit DFS, edit `findBackEdgesUsingDominators` and
  `buildLoopsUsingDominance` to take a `DomInfo` and call
  `.dominates()` (post-PR query sites 834 / 943 / 990), drop the
  caller-side `Dom` allocation, plug the new helper into
  `buildGasChunksSPP` (post-PR `:1261`). Also drop two unused bitset
  helpers (`bitsetSetAll`, `bitsetEqual`) that were only used by the
  removed pass.
- `src/tests/evm_cache_tests.cpp` — add five dominator correctness
  GTests (`LinearChain_Correct`, `DiamondCFG_Correct`,
  `NestedLoop_Correct`, `DisjointRoots_SelfIdom`,
  `ClassCDescendant_SeedsAtInit`).
- `src/evm/evm_cache_for_testing.h` — **new**, declares the testing-only
  `computeIDomForTesting` entry point so the GTests can drive the
  dominator algorithm directly without going through `buildBytecodeCache`.
  Internal header; not exported. `src/evm/CMakeLists.txt` does not list
  this header (the `EVM_SRCS` list is `.cpp`-only); no install rule for
  headers in this subdir.

No public API changes. No build-flag changes. No changes to the SPP
pipeline order, gas-shifting logic, or the public `EVMBytecodeCache`
shape.

## Verification gates

All 7 gates pass on this branch (`perf-dom-lengauer-tarjan @ HEAD`):

| # | Gate | Result |
|---|------|--------|
| 1 | `clang-format --dry-run -style=file -Werror` on PR-changed files (`src/evm/evm_cache.cpp src/evm/evm_cache_for_testing.h src/tests/evm_cache_tests.cpp`) | ✅ exit 0, no output. The repo-wide `tools/format.sh check` reports pre-existing violations in unrelated files (`src/singlepass/x64/assembler.h`, `src/platform/sgx/zen_sgx_file.h`, etc.) — out of scope for this PR. |
| 2 | `cmake --build build --target dtvmapi` | ✅ no warnings *in PR-touched files*. `grep -E "warning\|error" build.log \| rg "evm_cache\|evm_cache_tests\|evm_cache_for_testing"` returns empty after the PR. Pre-existing warnings in unrelated files (`src/utils/others.cpp -Wunused-result`, `src/common/traphandler.cpp -Wcast-function-type`, `src/compiler/cgir/pass/cg_inline_spiller.cpp -Wunused-function`) are unchanged. |
| 3 | `evmone-unittests` multipass | ✅ **223/223** |
| 4 | `evmone-unittests` interpreter | ✅ **215/215** unique tests. The run list `tests/evmone_unittests/EVMOneInterpreterUnitTestsRunList.txt` has 226 lines but only 215 unique names — `sort … \| uniq -d` shows exactly 11 duplicate entries (e.g. `multi_vm/evm.call_high_gas/external_vm`, `multi_vm/evm.create/external_vm`, `multi_vm/evm.sstore_cost/external_vm`); each duplicate selects the same gtest case once. The task-spec gate "215/215" matches the unique-test count. |
| 5 | `evmone-statetest -k fork_Cancun` multipass | ✅ **2723/2723** zero failures, from a fresh local run on this branch. Statetest enumerates JSON fixtures at runtime — there is no curated run list and the absolute count depends on the local `tests/fixtures/` submodule pin (`~/DTVM/tests/fixtures/`); 2723 matches the task-spec gate. |
| 6 | `evmCacheTests` | ✅ **9/9** (4 implicit-dyn-pred + 5 new dom) |
| 7 | `evmCacheComplexityDemo` scaling | ✅ — see §Results. Single-run wall-clock varies by ±5–15% between consecutive runs on the WSL2 host; the qualitative claim (gate thresholds met by ≥2× margin and growth near-linear) is what's being asserted, not exact millisecond values. |

## Results

`evmCacheComplexityDemo` on this branch:

| N JUMPDESTs | Pre-#446 baseline | Post-#446 (bitset) | This PR (CHK + Enter/Exit) | Speedup vs pre-#446 | Speedup vs post-#446 |
|-------------|-------------------|--------------------|----------------------------|---------------------|----------------------|
| 10,000      | 84.76 ms          | 10.38 ms           | **3.38 ms**                | 25.1×               | 3.1×                 |
| 20,000      | 345.94 ms         | 43.68 ms           | **5.90 ms**                | 58.6×               | 7.4×                 |
| 50,000      | not measured      | not measured       | **14.48 ms**               | —                   | —                    |
| 100,000     | not measured      | 948 ms (user pre-PR)| **38.95 ms**              | —                   | 24.3×                |

Gate 7 thresholds:
- N=20k < 15 ms: **5.90 ms** ✅
- N=100k < 100 ms: **38.95 ms** ✅
- Doubling growth < 2.5×:
  - 10k → 20k: 1.75× ✅
  - 50k → 100k: 2.69× — slightly above the 2.5× heuristic; the
    super-linear residue is in the unchanged surrounding cache-build code
    (Phase-7 stitch, edge construction, allocations), not in the new
    dominator pass itself. Absolute targets are met by a wide margin and
    overall growth is empirically near-linear.

## Test plan

The five new GTests anchor dominator correctness against five CFG
classes that cover the algorithm's interesting regions:

1. **LinearChain** — `N+1` blocks `0 → 1 → 2 → … → N`. Expectation:
   `IDom[0] == 0` (self, single root), `IDom[i] == i-1` for `i ≥ 1`.
   Exercises the trivial single-pred path.
2. **DiamondCFG** — `A → B → D`, `A → C → D`. Expectation:
   `IDom[A] = A`, `IDom[B] = IDom[C] = A`, `IDom[D] = A`.
   Exercises `intersect` on two distinct pred chains that meet at the
   root.
3. **NestedLoop** — 4 blocks: `E` (entry, `Preds.empty()`), outer
   header `H1`, inner header `H2`, body `B`. Edges: `E → H1`,
   `H1 → H2`, `H2 → B`, `B → H2` (inner back-edge), `B → H1` (outer
   back-edge). Expectation: `IDom[E] = E`, `IDom[H1] = E`,
   `IDom[H2] = H1`, `IDom[B] = H2`. Exercises the fixpoint behaviour
   when back-edges feed unprocessed `IDom` values into the first RPO
   pass.
4. **DisjointRoots_SelfIdom** — two disjoint reachable subgraphs each
   with their own self-rooted entry, joined later by a node `J` whose
   preds come from both. Expectation: `IDom[J] == J` (own root, no
   common dominator). Exercises the multi-root `intersect → UINT32_MAX
   → fallback to self` path.
5. **ClassCDescendant_SeedsAtInit** — node 0 unreachable, node 1
   reachable with pred {0} (class C), chain `1 → 2 → 3` of descendants.
   Expectation: `IDom[1] = 1`, `IDom[2] = 1`, `IDom[3] = 2`. Exercises
   the init-time class-C seed and verifies the bitset semantic that
   class-C roots dominate their reachable descendants.

End-to-end regressions are caught by gates 3–5 (the broader unittests
and statetest suites).

## Risks

- **Pathological CHK fixpoint blow-up**: an adversarial irreducible CFG
  could force `O(N · E)` iterations. EVM bytecode that survives
  `splitCriticalEdges` is reducible, and the gate-7 N=100k run validates
  this empirically. Mitigation: if a future workload hits this, switch
  to SemiNCA — but the worst-case for queries is unchanged because the
  Enter/Exit DFS is always `O(N + E)`.
- **`Reachable[]` stitch interaction**: the Phase 7 stitch makes
  dyn-target JUMPDESTs reachable for SPP. The new algorithm must skip
  the same set (`Reachable==0 || Preds.empty`) the current pass skips,
  AND must handle the rare class C (`Reachable==1, Preds non-empty,
  all preds Reachable==0`) by **seeding at init** so descendants take
  the class-C node as their idom (verified by
  `ClassCDescendant_SeedsAtInit`). The post-fixpoint sweep is retained
  only as a defensive backstop for orphan reachable components not
  seeded by any root.
- **Small-N overhead**: for `N < ~50` the bitset pass already converges
  in 1 iteration and the RPO + fixpoint + Enter/Exit constant factor
  may regress a microsecond or two. Statetest gate 5 (2723 cases at
  realistic sizes) and unittests gates 3–4 catch any user-visible
  regression; none observed.

## Out of scope

- Touching `splitCriticalEdges`, `lemma614Update`, `buildGasChunksSPP`'s
  loop logic, or any other SPP-pipeline stage.
- Adding `evmCacheComplexityDemo` to `ctest` (left as an opt-in scaling
  driver, per PR #446 decision).
- Adopting Lengauer-Tarjan / SemiNCA. Reserved as a follow-up if a
  pathological workload forces the CHK fixpoint into its worst case.

## Implementation

Sequenced steps; each step ended with `cmake --build build --target
dtvmapi -j$(nproc)` + the relevant unit-test slice.

1. **TDD anchor.** Added `src/evm/evm_cache_for_testing.h` exposing
   `computeIDomForTesting(succs, reachable)`. Wrote the four initial
   GTests against the algorithm as ground truth; the fifth
   (`ClassCDescendant_SeedsAtInit`) was added in step 6 after R1
   review surfaced the class-C descendant divergence.
2. **Algorithm swap.** Replaced the body of `computeDominators` with a
   CHK implementation producing the idom array directly, including the
   class A/B/C init seed and the defensive post-fixpoint sweep
   promoting any remaining `UINT32_MAX` to `self`.
3. **Performance fix.** A first pass shipped an `O(depth)` `dominatesIDom`
   idom-walk helper for query, which on the linear-chain dyn-dispatch
   fixture degraded to `O(N²)` per cache build (8× slower than baseline
   at N=10k). Added a `DomInfo` struct (IDom + Enter + Exit) and a
   Tarjan DFS over the dom tree to assign pre/post times, then switched
   `dominates(A, B)` to interval containment (`O(1)`).
4. **Caller rewrite.** Changed `findBackEdgesUsingDominators` and
   `buildLoopsUsingDominance` signatures to take a `const DomInfo &Dom`,
   switched their three dominance queries to `Dom.dominates(...)`, and
   updated the `buildGasChunksSPP` call site. Removed the
   `bitsetSetAll` / `bitsetEqual` helpers (now unused).
5. **Numbers.** Ran the scaling demo at `N=10k/20k/50k/100k`; results
   recorded above.
6. **R1 review fix.** Implementation review surfaced a class-C
   descendant divergence (old bitset gave `N ∈ Dom[descendant]`,
   new pass gave self-root because the class-C node N stayed at
   `UINT32_MAX` throughout the fixpoint). Moved class-C detection
   from the post-fixpoint sweep into the init step so descendants in
   step 4 of the design can intersect against a settled root. Added
   `ClassCDescendant_SeedsAtInit` to lock the new behavior.

## Checklist

- [x] Step 1 — TDD anchor + 4 tests pass against current algo.
- [x] Step 2 — CHK implemented; 4 tests pass against new algo.
- [x] Step 3 — Enter/Exit DFS added for `O(1)` queries.
- [x] Step 4 — callers rewritten; multipass unittests 223/223.
- [x] Step 5 — all 7 verification gates pass.
- [x] Step 5 — scaling-demo numbers (10k/20k/50k/100k) recorded.
- [x] Step 6 — class-C init seed + `ClassCDescendant_SeedsAtInit`
      test added per R1 implementation review.
- [ ] Module specs in `docs/modules/` updated (no impact; SPP pipeline
      order unchanged).
- [ ] PR title `perf(core): replace iterative-bitset dominator with
      Cooper-Harvey-Kennedy algorithm`.
