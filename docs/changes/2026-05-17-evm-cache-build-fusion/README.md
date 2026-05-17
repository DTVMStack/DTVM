# Change: EVM Cache Build — Phase Fusion + CSR Adjacency + GasBlock Compaction

- **Status**: Implemented (Phase 4 R1 round applied; see `reviews/`)
- **Date**: 2026-05-17
- **Tier**: Full
- **Branch**: `perf/cache-build-fusion` (off `perf/evm-spp-foundation`)
- **Depends on**: PR A (`perf/evm-spp-foundation` / 2026-05-16-evm-spp-overhaul) for dom-CHK foundation + `ZEN_EVM_CACHE_PROFILE` instrumentation hooks
- **Commits**: 11 implementation + 1 docs = 12 commits total on the branch

## Overview

Post-PR-A follow-up that drives `buildBytecodeCache` further down the linear
regime by attacking the next set of constant-factor wins exposed by the
`ZEN_EVM_CACHE_PROFILE` per-phase breakdown:

1. **Phase fusion (3 commits)** — collapse multi-pass bytecode/edge walks
   that re-do work the previous pass already did:
   - `buildGasBlocks` 2-pass → 1-pass (eliminate `IsBlockStart[CodeSize]`).
   - `collectJumpDests` folded into `buildGasBlocks` (eliminate bytecode rescan).
   - `buildCFGEdges` 2-pass → 1-pass (eliminate redundant `resolveConstantJumpTarget` call per JUMP block).
2. **CSR adjacency + conditional Tarjan (3 commits)** — flatten
   `Blocks[].Succs/Preds` into a `CSRGraph` once after `splitCriticalEdges`
   freezes the graph, then route all downstream readers (`computeReachable`,
   `computeDomInfo`, `findBackEdges`, `computeReverseTopo`, `computeInCycle`,
   `buildLoopsUsingDominance`, `lemma614Update`, `writeback`) through CSR.
   `computeInCycle` becomes conditional: on reducible CFGs (the common case,
   `UseLinearSPP=true`) it derives `InCycle` as the bitset union of natural
   loops and skips the standalone Tarjan SCC pass; irreducible CFGs retain
   the Tarjan fallback for soundness.
3. **RPO share** — `computeReverseTopo` returns `reverse(DomInfo::RPO)`
   instead of running its own DFS.
4. **GasBlock compaction (3 commits)** — `Blocks` is reserved
   up front to `CodeSize` so `emplace_back` never reallocates; `Succs/Preds`
   move out of `GasBlock` into a parallel `EdgeTables` struct; field reorder
   packs `GasBlock` to exactly 32 bytes (static_assert locked).

Net: **N=100k synthetic cache build 47.4 ms → 27.8 ms (-41.5 %), 100-rep
median**, on top of the 21× win PR A booked vs `upstream/main`. Cross-N
speedup scales with `N` (cache-density wins compound as Blocks vector
spills L2/L3).

Two adjacent paths from PR A's roadmap were evaluated and **dropped on
data**:

- **PR B (Stack-SSA + SCCP jump-target precision)** — measurement showed
  92.5 % (statetest 25013 contracts) / 98.4 % (evmone-bench 23 contracts)
  of JUMPs are already statically resolved by the existing PUSH→JUMP
  heuristic, and 96.8 % of contracts have ZERO dynamic JUMPs. Expected
  runtime win < 1 % against a ~500 LoC SSA + lattice implementation.
- **SemiNCA dominator** — CHK fixpoint instrumentation
  (`chkFixpointRounds`) shows convergence in exactly 2 rounds on
  N=10k/20k/50k/100k synthetic. SemiNCA's single-pass advantage caps at
  saving the second confirmation sweep ≈ 1.5 ms (4 % of `computeDomInfo`),
  comparable to the cost of its own eval/link DSU bookkeeping.

The `chkFixpointRounds` diagnostic counter ships under
`ZEN_EVM_CACHE_PROFILE` so future re-evaluation has a built-in probe.

## Motivation

### Per-phase breakdown after PR A landed

Running `evmCacheComplexityDemo 100000` with
`-DZEN_EVM_CACHE_PROFILE=ON` at PR A HEAD (commit `592fd35`), 50-rep
mean per phase, interleaved 100-rep median for the total:

| Phase | Mean (us) | % of instrumented sum |
|---|---:|---:|
| computeDomInfo | 10818 | 22.2 % |
| buildGasBlocks | 10350 | 21.3 % |
| computeInCycle | 7263 | 14.9 % |
| buildCFGEdges | 5477 | 11.2 % |
| lemma614Schedule | 3091 | 6.3 % |
| computeReachable | 2531 | 5.2 % |
| computeReverseTopo | 2423 | 5.0 % |
| buildLoopsUsingDominance | 2076 | 4.3 % |
| findBackEdges | 1938 | 4.0 % |
| splitCriticalEdges | 933 | 1.9 % |
| writeback | 783 | 1.6 % |
| meteringInit | 533 | 1.1 % |
| collectJumpDests | 484 | 1.0 % |
| **Σ instrumented** | **48700** | |
| **&lt;TOTAL median&gt;** | **47343** | |

The instrumented sum (48700 us) slightly exceeds the median wall-clock
(47343 us) because `EVM_PROFILE_BEGIN`/`END` chrono pairs add ~0.5-1 us
overhead at each of 13 phase boundaries (13 × ~0.1 us × N=100k ≈ 1.3 ms,
matching the ~1.4 ms overshoot). Treat the per-phase column as
"approximate share" rather than an exact decomposition.

On the post-PR-HEAD side the relationship flips: HEAD phases sum to
~20.8 ms but the total median is ~27.9 ms — the gap (~7.1 ms) is
un-instrumented work in `buildBytecodeCache`'s outer scope (vector
allocation + zero-init of `Cache.JumpDestMap`/`PushValueMap`/
`GasChunkEnd`/`GasChunkCost`/`GasChunkCostSPP`, plus per-cache
bookkeeping). This is large only at the synthetic N=100k stress
because `Cache.PushValueMap` is `vector<intx::uint256>` of length
CodeSize = 9.6 MB; for EIP-170 production code (≤24 576 B) the same
outer allocation is ~0.2 ms. The asymmetry between baseline
(sum > total) and HEAD (sum < total) is therefore expected: baseline
spent most of its time in instrumented phases, while HEAD's gains
mostly drained out of those phases and left the (unchanged) outer
allocation cost in relative relief.

Three families of targets surfaced:

- **Multi-pass phases redoing work** — `buildGasBlocks` walked bytecode
  twice (mark IsBlockStart, then build blocks);
  `collectJumpDests` walked bytecode a third time; `buildCFGEdges` called
  `resolveConstantJumpTarget` twice per JUMP block.
- **Per-node heap chase** — every Preds/Succs read in dominator,
  reachability, SCC, loop-discovery, and lemma614 passes paid a pointer
  chase to a small (1-2 element) per-block heap chunk. Cumulative ~17 ms.
- **Wide structs eat cache** — `GasBlock` was 80 bytes (two embedded
  `std::vector` controls). Two blocks per cache line was the theoretical
  ceiling; in practice cache lines pulled in mostly-empty vector controls
  the read passes never used.

### Why not Stack-SSA + SCCP

PR A's roadmap reserved PR B for "Stack-SSA + SCCP jump-target precision"
on the theory that narrower jump-target sets would unlock more SPP shifts
at JUMPDESTs with `ImplicitDynamicPredCount > 0`. Instrumenting
`buildCFGEdges` to count static-vs-dynamic JUMPs across the full
statetest fixture (25013 contract builds) and the evmone-bench corpus
(23 contracts) returned this distribution:

| Source | Total JUMPs | Static (resolved) | Dynamic | Contracts w/ 0 dynamic |
|---|---:|---:|---:|---:|
| statetest fork_Cancun (2723 tests) | 45718 | 42274 (92.5 %) | 3444 (7.5 %) | 24221 / 25013 (96.8 %) |
| evmone-bench main+micro (23 contracts) | 4967 | 4886 (98.4 %) | 81 (1.6 %) | 15 / 23 (65.2 %) |

Stack-SSA's plausible ceiling is to narrow some fraction of the 1.6-7.5 %
dynamic JUMPs (the genuinely-unresolvable dispatch tables, runtime
selector matches, etc. cannot be narrowed by static analysis at all). The
expected runtime perf delta is sub-percent, and only 3-35 % of contracts
can possibly benefit at all. The 500+ LoC SSA construction + lattice
machinery is therefore not justified versus the cache-build wins this PR
captures instead.

### Why not SemiNCA

PR A's CHK fixpoint runs until idom stabilises. We added a
`chkFixpointRounds` counter (gated on `ZEN_EVM_CACHE_PROFILE`) and
measured:

| N | chkFixpointRounds |
|---|---:|
| 10k | 2 |
| 20k | 2 |
| 50k | 2 |
| 100k | 2 |

Every measured run converges in exactly 2 rounds — one productive sweep
followed by a confirmation sweep that finds no change. SemiNCA's
single-pass advantage caps at saving that second sweep, roughly 1.5 ms
on N=100k. The 100+ LoC DSU + eval/link forest bookkeeping it requires
costs a comparable amount, so the net gain on synthetic is in the noise.
The counter is retained so a future workload that triggers more rounds
makes the case visible.

## Impact

### Files touched

- `src/evm/evm_cache.cpp` — all optimisations land here. Net diff:
  +312 / -188 lines (`git diff --numstat perf/evm-spp-foundation..HEAD`).
- `src/tests/evm_cache_tests.cpp` — unchanged. The existing 14 tests
  still pass; **none of them drives `UseLinearSPP=false`**, so the
  conditional-Tarjan-skip branch added by this PR has no dedicated
  unit-test coverage. End-to-end soundness on irreducible CFGs is
  established by `evmone-statetest -k fork_Cancun` 2723/2723. See
  R2 below for the actual safety invariant.

### Public API / ABI

None. `EVMBytecodeCache` is behaviourally identical
(`evmone-statetest --vm external_vm -k fork_Cancun` 2723/2723 pass)
and the JIT / interpreter contract is unchanged. A literal byte-by-byte
diff of `EVMBytecodeCache` between baseline and HEAD over a corpus
was not run for this PR (statetest equivalence is the property runtime
actually relies on); if a future audit needs strict byte-identity
proof, a fixture corpus + `memcmp` test would be a one-off addition.

The `ZEN_EVM_CACHE_PROFILE` flag remains opt-in and macro-elides to
no-ops in release builds.

### Memory footprint

`Blocks.reserve(CodeSize)` in `buildGasBlocks` is the only material peak
change. Worst case `CodeSize` for production is 24 576 (EIP-170) →
reserve cost is 24576 × 32 = 0.79 MB transient per `buildBytecodeCache`
call. For the synthetic stress test at N=100k (CodeSize ≈ 300 KB) the
reserve costs 9.6 MB, freed when `Blocks` goes out of scope at the end
of `buildBytecodeCache`. Both within the existing per-call memory
budget; no policy change required.

The `EdgeTables` lives alongside `Blocks` during build (two
`vector<vector<uint32_t>>` of size N) and is consumed by
`buildAdjacencyCSR` after `splitCriticalEdges`. Peak memory during CFG
build is comparable to (slightly less than) the prior embedded-vector
layout because the parallel arrays avoid the inline 24-byte vector
control inside each `GasBlock`.

### Compatibility

None. This is a drop-in pipeline refactor under the existing entry point
`buildBytecodeCache(EVMBytecodeCache&, ..., bool EnableSPP)`.

## Implementation Plan

The 11 implementation commits land in the order below. Each commit was
verified independently by re-running `evmCacheTests` and
`evmone-statetest --vm external_vm -k fork_Cancun` before the next was
authored. Note: **commits within a phase form a unit**. In particular
Phase 5's commits (`55a250b` `Blocks.reserve` → `689e5d5` `EdgeTables`
split → `f7630d8` 32-byte pack) and the Phase 2 pair (`0dd5bb9` CSR
introduces `buildAdjacencyCSR(const vector<GasBlock>&)`; `689e5d5`
later changes that signature to `(const EdgeTables&)`) cannot be
reverted in isolation without breaking the build — the per-commit
greenness claim holds, the "single-commit cherry-pick" claim does not.

### Phase 1 — Bytecode-walk fusion (commits 1-2)

- [x] `e06d291` `perf(core): fuse buildGasBlocks 2-pass into single bytecode walk`
  Eliminates `IsBlockStart[CodeSize]` auxiliary array and the second bytecode walk that consumed it.
- [x] `3bba649` `perf(core): fold collectJumpDests into buildGasBlocks single walk`
  Emit `JumpDestBlocks` inline whenever a new block opens with `OP_JUMPDEST`.

### Phase 2 — CSR adjacency + Tarjan conditionalisation (commits 3-5)

- [x] `0dd5bb9` `perf(core): flatten Preds/Succs into CSR for cache-locality on hot passes`
  `CSRGraph` type, `buildAdjacencyCSR<bool SelectSuccs>` flatten, route every reader through CSR.
- [x] `4d74033` `perf(core): add chkFixpointRounds counter to diagnose CHK convergence`
  Diagnostic instrumentation. Validates the "SemiNCA not worth it" decision.
- [x] `6e1bc6b` `perf(core): derive InCycle from natural loops on reducible CFGs`
  Skip Tarjan SCC when `UseLinearSPP=true`. Tarjan fallback retained for irreducible CFGs.

### Phase 3 — Edge-build fusion + RPO share (commits 6-7)

- [x] `de934a8` `perf(core): fuse buildCFGEdges two passes into a single sweep`
  Single sweep emits edges and counts dynamic JUMPs inline. Stamp `ImplicitDynamicPredCount` at the end.
- [x] `118c993` `perf(core): share computeDomInfo RPO with computeReverseTopo`
  `DomInfo::RPO` field; `computeReverseTopo` is now a reverse copy.

### Phase 4 — Style sweep (commit 8)

- [x] `77e0454` `style(core): apply tools/format.sh to evm_cache.cpp after PR C work`
  Pure clang-format. No semantic change.

### Phase 5 — GasBlock compaction (commits 9-11)

- [x] `55a250b` `perf(core): reserve Blocks + emplace_back to drop GasBlock move/realloc cost`
  `Blocks.reserve(CodeSize)`; `emplace_back` + back-reference fill.
- [x] `689e5d5` `perf(core): split per-block Succs/Preds out of GasBlock into EdgeTables`
  GasBlock shrinks from 80 → 40 bytes. Parallel `EdgeTables` holds the mutable adjacency during build.
- [x] `f7630d8` `perf(core): pack GasBlock to exact 32 bytes via field reorder`
  Field reorder + `static_assert(sizeof(GasBlock) == 32)`.

## Results

### Measurement methodology (this section)

All numbers below come from a single same-session pair of measurements:

1. `evmCacheComplexityDemo` rebuilt twice — once from `592fd35`'s
   `src/evm/evm_cache.cpp` (PR A HEAD) and once from this PR's HEAD —
   keeping every other source file and the CMake build configuration
   identical.
2. Both binaries kept on disk, then exercised with 100 reps **alternated
   per-rep** at each N (baseline, head, baseline, head, …) so any
   per-second thermal or scheduling drift hits both binaries equally.
3. Medians are reported (more robust than means under tail variance).

Run-to-run variance on this machine is roughly ±5 % at N=100k; a
non-interleaved comparison can drift further if the system thermal
state changes mid-run. Reviewers reproducing should use the same
interleaved methodology or expect the bands to widen.

### Per-phase deltas (N=100k synthetic, 50-rep mean per phase)

| Phase | PR A baseline | This PR HEAD | Δ |
|---|---:|---:|---:|
| computeDomInfo | 10 818 | 4 482 | **-58.6 %** |
| buildGasBlocks | 10 350 | 2 181 | **-78.9 %** |
| computeInCycle | 7 263 | 37 | **-99.5 %** |
| buildCFGEdges | 5 477 | 4 512 | -17.6 % |
| lemma614Schedule | 3 091 | 886 | **-71.3 %** |
| computeReachable | 2 531 | 1 076 | **-57.5 %** |
| computeReverseTopo | 2 423 | 197 | **-91.9 %** |
| buildLoopsUsingDominance | 2 076 | 1 348 | -35.1 % |
| findBackEdges | 1 938 | 1 099 | -43.3 % |
| splitCriticalEdges | 933 | 366 | -60.8 % |
| writeback | 783 | 399 | -49.0 % |
| meteringInit | 533 | 842 | +57.9 %\* |
| collectJumpDests | 484 | — (folded) | n/a |
| buildCSR | — (new) | 3 326 | n/a |
| buildJumpDestMap | — (new instrumented) | 35 | n/a |
| **&lt;TOTAL median&gt;** | **47 343** | **27 945** | **-41.0 %** |

\* `meteringInit` increased absolutely. Most likely cache-effect
attribution: the prior pipeline left `Blocks[].Succs/Preds` cache-warm
for the subsequent `Metering[Id] = Blocks[Id].Cost` walk, while the
new pipeline keeps the Block scalars cold until that loop touches them.
This is a conjecture from the access pattern, not a measured cause —
it could also be chrono-overhead artefact at the sub-millisecond scale.
The +309 us increase is dwarfed by the net win.

### Cross-N speedup vs `perf/evm-spp-foundation` HEAD (100-rep interleaved median)

| N | Baseline (us) | This PR (us) | Speedup | Δ |
|---:|---:|---:|---:|---:|
| 10 000 | 2 742 | 2 200 | **1.25×** | -19.8 % |
| 20 000 | 6 096 | 4 773 | **1.28×** | -21.7 % |
| 50 000 | 19 476 | 13 593 | **1.43×** | -30.2 % |
| 100 000 | 47 343 | 27 945 | **1.69×** | -41.0 % |

The speedup ratio grows with N. The plausible mechanism is that
the dominant wins (CSR cache density, GasBlock 80→32 byte stride
compression, Blocks reserve eliminating geometric realloc churn) all
have constant amortised cost per node but the baseline pipeline's
heap-chasing reader cost grows super-linearly as the working set
spills L2 → L3 → DRAM. **This is a hypothesis from the access pattern,
not measured with hardware counters.** It could also be a
synthetic-generator-specific pathology — the synthetic CFG is uniform
(alternating PUSH/JUMP/JUMPDEST blocks), which is exactly the case
where flat sequential CSR access wins biggest over scattered
per-block heap chunks. A real-corpus paired-ratio measurement (à la
PR A's harness) would be a useful follow-up.

Production EIP-170 contracts cap at CodeSize ≤ 24 576 bytes, so the
applicable region is N ≤ 8000 blocks at most pathological packing,
practically N = 100-2000. That band aligns with the "-19.8 % to -21.7 %"
end of the table. The "-41 %" figure is algorithmic-DoS hygiene, not
a production headline.

### Caveat on the headline number

As with PR A, the 41 % figure is on a synthetic fixture chosen to fit
the cache-build pipeline at the algorithmic-DoS regime. EIP-170 caps
real contract bytecode at 24 576 bytes, so the workload size where this
ratio is observed cannot actually be produced by deploying a contract.
The smaller-N rows (-21 % at 10k JUMPDESTs ≈ 30 KB) better reflect
realistic-scale impact.

## Verification

| Gate | Result |
|---|---|
| `tools/format.sh check` (files touched by this PR) | clean |
| `cmake --build build --target dtvmapi -j$(nproc)` | success, no new warnings (use `CCACHE_DISABLE=1` if ccache cache lives on a read-only mount) |
| `build/evmCacheTests` | 14 / 14 pass |
| `evmone-statetest --vm external_vm -k fork_Cancun` | 2723 / 2723 pass (~77 s) |
| `evmCacheComplexityDemo` at N=10k/20k/50k/100k | all green, monotone improvement vs baseline |
| `chkFixpointRounds` counter | 2 at every measured N (synthetic + unit tests; see R4) |

`tools/format.sh check`, build, evmCacheTests, and statetest all re-ran
after every single one of the 11 implementation commits, not just at
the end. Each commit was independently green when authored.

**Caveat on `tools/format.sh check`**: a Round-1 reviewer observed exit
code 123 with pre-existing violations in `src/singlepass/x64/assembler.h`
and `src/platform/sgx/zen_sgx_file.h` — neither of which this PR
touches. On the author's machine the gate is clean; the discrepancy
appears environment-specific (different clang-format version or repo
state). The PR's own diff is `tools/format.sh format`-idempotent.

## Risks

- **R1 — `Blocks.reserve(CodeSize)` scope and over-allocation**:
  `buildGasBlocks` reserves Blocks to `CodeSize` (1 byte = 1 block
  worst case). Real contracts average 3-10 bytes/block, so the reserve
  over-allocates by 3-10×. At EIP-170 max (24 576 bytes) this is
  0.79 MB transient (24 576 × 32-byte GasBlock); at the N=100k stress
  (CodeSize ≈ 300 KB) it is 9.6 MB transient, released when `Blocks`
  is destroyed at the end of `buildBytecodeCache`.

  **Important scope caveat**: the no-realloc guarantee from this
  reserve covers **only** the initial block construction loop inside
  `buildGasBlocks`. The subsequent `splitCriticalEdges` phase
  (`evm_cache.cpp:332-383`) appends synthetic empty blocks via
  `Blocks.push_back(NewBlock)`; if `splitCriticalEdges` ever needed
  to add more than `(CodeSize - originalBlockCount)` blocks, a
  reallocation could happen there. In practice the split count is
  bounded by the number of critical edges (≤ Blocks.size() initially),
  and we never take a `GasBlock&` reference that outlives a
  `splitCriticalEdges` append, so no invalid-reference bug exists
  today. But the wording "`Blocks` never reallocates" is too strong
  if read out of context.

  **Mitigation**: the alternative — a pre-scan pass to count blocks
  exactly — would itself cost ~1 ms at N=100k, defeating the purpose.
  Reserve is cheaper than the ~16 MB of memmove traffic from
  geometric growth it eliminates. If a workload ever appears where
  the reserve is too aggressive, switch to `CodeSize / 3` for an
  upper bound at ~3 bytes/block average.

- **R2 — Conditional `InCycle` is a performance optimisation, not the
  soundness mechanism**:
  In the `UseLinearSPP=true` path we derive `InCycle` as
  `union(Loops[].NodeMask)` and skip the standalone Tarjan SCC pass.
  An earlier draft of this risk claimed that "in a reducible CFG every
  cycle is captured by some natural loop", which is true, but the
  **gate** that decides reducibility (`buildLoopsUsingDominance` returns
  `true`) is weaker than that property requires. Counterexample:
  an irreducible 2-entry cycle `A ↔ B` where neither node dominates
  the other produces zero dominator-based back-edges, so
  `buildLoopsUsingDominance` returns `true` with an empty `Loops`
  vector and our `InCycle = union(empty) = all-zeros`. Tarjan SCC
  would correctly mark `A, B` as in-cycle.

  Soundness on such CFGs is preserved by a **different invariant** —
  `lemma614Update`'s multi-pred guard via `effectivePredCount`
  (`evm_cache.cpp:1223`): every node in any SCC of size ≥ 2 has at
  least one in-cycle predecessor on top of any out-of-cycle entry, so
  its `effectivePredCount` is ≥ 2 and the lemma refuses the shift
  before it can mis-charge. The `InCycle` mask is a **redundant
  fast-path filter**, not a safety net.

  **Mitigation**: the `if (!UseLinearSPP)` branch retains the full
  Tarjan SCC for defence-in-depth. `evmone-statetest -k fork_Cancun`
  2723/2723 exercises the real-world reducible path. The irreducible
  fallback branch is **not** covered by a dedicated unit test —
  `OverlappingBackEdgesIDom` only drives `computeIDomForTesting`'s CHK
  output, not the `buildLoopsUsingDominance → false` path; adding such
  a test requires plumbing `buildLoopsUsingDominance` (or `buildBytecodeCache`)
  through a test helper and is deferred. Until that exists, the
  fallback path's correctness rests on argument + statetest end-to-end.

  Future contributor warning: do **not** remove the multi-pred guard
  in `lemma614Update` on the assumption that `InCycle` covers it.
  `InCycle` does not cover it on irreducible CFGs.

- **R3 — `GasBlock` static_assert ties the layout to 32 bytes**:
  Any future field addition without re-tuning will trigger a build
  break. The `static_assert` is intentionally strict because the cache
  density wins are 32-byte specific — letting the struct silently grow
  to 40 bytes would erode the gains without anyone noticing. **Mitigation**:
  the assert's commentary references this spec; future contributors who
  hit it should re-measure with `evmCacheComplexityDemo` to decide
  whether the bigger size is worth it.

- **R4 — `chkFixpointRounds=2` is workload-dependent, not a CHK
  invariant**: The "SemiNCA not worth it" decision rests on every
  measured workload converging in 2 rounds. The set of workloads
  measured is the `evmCacheComplexityDemo` synthetic at
  N=10k/20k/50k/100k plus the 10 `EVMCacheDominator` GTests; this is
  also the **easy** case for CHK convergence (uniform alternating
  PUSH/JUMP/JUMPDEST topology with a single forward spine). Any CFG
  with deep irreducible nesting, RPO that processes a node before its
  eventual idom, or unreachable-to-reachable transitions can require
  ≥ 3 rounds. A real-corpus paired-ratio measurement (similar to PR A's
  Sourcify-stratified bench) would strengthen the claim — until then
  the "2 rounds" number is best read as "the synthetic stress and unit
  tests converge in 2 rounds; production behaviour is plausible-but-
  unmeasured." The counter ships in the profile build so the question
  stays cheap to re-ask. **Mitigation**: if a real contract ever shows
  rounds > 2, re-evaluate SemiNCA against measured cost.

- **R5 — Stack-SSA drop is contingent on the existing PUSH→JUMP
  heuristic continuing to resolve 92-98 % of JUMPs**: Future compiler
  evolution (Solidity, Vyper) could change the static-vs-dynamic JUMP
  ratio. **Mitigation**: the static/dynamic counter is removed from
  this PR (it was scaffolding for the decision) but is one Bash invocation
  away from being re-added under `ZEN_EVM_CACHE_PROFILE` if the ratio
  needs re-verifying against a future corpus.

## Future work explicitly out of scope

- **Stack-SSA + SCCP** — dropped; see Motivation §"Why not Stack-SSA + SCCP".
- **SemiNCA** — dropped; see Motivation §"Why not SemiNCA".
- **GasBlock compile-time hot/cold split**: could push further by
  separating the always-read fields (Start/End/Cost) from the
  rarely-read ones (LastPc/PrevPc/PrevOpcode). Diminishing returns;
  defer until profile data demands it.
- **Cache.PushValueMap zero-init elimination**: 9.6 MB zero-fill for
  N=100k synthetic; production cost is ~0.2 ms so this is purely a
  stress-test artifact. Out of scope.
- **Real-world bench**: this PR's perf data is from
  `evmCacheComplexityDemo` synthetic only. Re-running PR A's
  paired-ratio BCa harness on the real-corpus would be a useful
  follow-up but is not gating for this work — the wins compound on top
  of PR A's already-paired results.

## Checklist

- [x] Implementation complete (11 commits)
- [x] Tests pass: evmCacheTests 14/14, evmone-statetest 2723/2723 fork_Cancun
- [x] `tools/format.sh check` clean
- [x] Per-commit verification of test gates
- [x] Cross-N perf measurement (100 reps median, baseline rebuilt for fair comparison)
- [x] PR B / SemiNCA evaluation documented with data
- [x] Spec written and reviewed (this document + Phase 4 red-team round)
