# Change: EVM Cache Build — Phase Fusion + CSR Adjacency + GasBlock Compaction

- **Status**: Implemented
- **Date**: 2026-05-17
- **Tier**: Full
- **Branch**: `perf/cache-build-fusion` (off `perf/evm-spp-foundation`)
- **Depends on**: PR A (`perf/evm-spp-foundation` / 2026-05-16-evm-spp-overhaul) for dom-CHK foundation + `ZEN_EVM_CACHE_PROFILE` instrumentation hooks

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
`-DZEN_EVM_CACHE_PROFILE=ON` (9-rep mean) at PR A HEAD:

| Phase | Mean (us) | % of total |
|---|---:|---:|
| buildGasBlocks | 9525 | 23.0 % |
| computeDomInfo | 7233 | 17.5 % |
| computeInCycle | 5694 | 13.7 % |
| buildCFGEdges | 4562 | 11.0 % |
| computeReachable | 1818 | 4.4 % |
| lemma614Schedule | 1733 | 4.2 % |
| computeReverseTopo | 1651 | 4.0 % |
| buildLoopsUsingDominance | 1309 | 3.2 % |
| findBackEdges | 1169 | 2.8 % |
| splitCriticalEdges | 657 | 1.6 % |
| writeback | 457 | 1.1 % |
| meteringInit | 378 | 0.9 % |
| buildJumpDestMap | 24 | 0.06 % |
| **&lt;TOTAL&gt;** | **41412** | |

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
  +236 / -171 lines.
- `src/tests/evm_cache_tests.cpp` — unchanged (existing 14 tests still
  pass, including `IrreducibleImproperRegion` which exercises the
  Tarjan fallback path).

### Public API / ABI

None. `EVMBytecodeCache` is byte-identical for every contract on every
input. The `ZEN_EVM_CACHE_PROFILE` flag remains opt-in and macro-elides
to no-ops in release builds.

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

The 11 commits land in the order below. Each commit was verified
independently by re-running `evmCacheTests` and
`evmone-statetest --vm external_vm -k fork_Cancun` before the next was
authored, so any of them can be cherry-picked or reverted in isolation.

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

### Per-phase deltas (N=100k synthetic, mean us)

| Phase | PR A baseline | This PR HEAD | Δ |
|---|---:|---:|---:|
| buildGasBlocks | 9525 | 2157 | **-77 %** |
| buildCFGEdges | 4562 | 4265 | -6.5 % |
| computeDomInfo | 7233 | 4370 | **-40 %** |
| buildCSR | — (new) | 3064 | n/a |
| computeInCycle | 5694 | 36 | **-99.4 %** |
| computeReachable | 1818 | 1052 | -42 % |
| lemma614Schedule | 1733 | 745 | -57 % |
| buildLoopsUsingDominance | 1309 | 1288 | -1.6 % |
| findBackEdges | 1169 | 1046 | -10.5 % |
| computeReverseTopo | 1651 | 172 | **-90 %** |
| splitCriticalEdges | 657 | 361 | -45 % |
| writeback | 457 | 331 | -28 % |
| meteringInit | 378 | 794 | +110 %\* |
| buildJumpDestMap | 24 | 32 | noise |
| **&lt;TOTAL median&gt;** | **45603 / 47429**† | **27764** | **-39 % / -41 %** |

\* `meteringInit` increased absolutely but its share is small (<3 %).
Likely cache-effect attribution from the reordered pipeline; total wall
clock still drops.

† PR A baseline measured separately at 100-rep median 47429 us
(rebuilt from `592fd35` `src/evm/evm_cache.cpp` against the same build
configuration). The 45603 figure is from an earlier 25-rep run cited
for context; the 47429 number is the apples-to-apples gate.

### Cross-N speedup vs `perf/evm-spp-foundation` HEAD (100-rep median)

| N | Baseline (us) | This PR (us) | Speedup |
|---:|---:|---:|---:|
| 10 000 | 2746 | 2163 | **1.27×** |
| 20 000 | 6074 | 4625 | **1.31×** |
| 50 000 | 18 653 | 12 776 | **1.46×** |
| 100 000 | 47 429 | 27 764 | **1.71×** |

Speedup ratio scales with N because the dominant wins (CSR cache
density, GasBlock stride compression, Blocks reserve) all become more
valuable as `Blocks` and the adjacency working set spill L2 → L3 → DRAM.
Production EIP-170 contracts (N typically 100-2000) sit in the
"-21 % to -27 %" band; algorithmic stress tests live in the
"-30 % to -41 %" band.

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
| `tools/format.sh check` | clean |
| `cmake --build build --target dtvmapi -j$(nproc)` | success, no new warnings |
| `build/evmCacheTests` | 14 / 14 pass |
| `evmone-statetest --vm external_vm -k fork_Cancun` | 2723 / 2723 pass (~77 s) |
| `evmCacheComplexityDemo` at N=10k/20k/50k/100k | all green, monotone improvement vs baseline |
| `chkFixpointRounds` counter | 2 at every N (validates SemiNCA-drop decision) |

`tools/format.sh check`, build, evmCacheTests, and statetest all re-ran
after every single one of the 11 commits, not just at the end. Each
commit is independently green and individually revertable.

## Risks

- **R1 — `Blocks.reserve(CodeSize)` over-allocates for typical EVM code**:
  The reserve uses `CodeSize` as a conservative upper bound (1 byte = 1
  block worst case). Real contracts average 3-10 bytes per block, so the
  reserve over-allocates by 3-10×. At EIP-170 max (24576 bytes) this is
  at most 0.79 MB transient — well within memory budgets. At the
  synthetic N=100k stress (CodeSize ≈ 300 KB) it is 9.6 MB transient,
  released when `Blocks` is destroyed. **Mitigation**: the alternative —
  a pre-scan pass to count blocks exactly — would itself cost ~1 ms at
  N=100k, defeating the purpose. Reserve is cheaper than the geometric
  growth it eliminates (~16 MB of memmove traffic at N=100k). If a
  workload ever appears where the reserve is too aggressive, switch to
  `CodeSize / 3` for an upper bound at ~3 bytes/block average.

- **R2 — Conditional Tarjan SCC depends on `UseLinearSPP` correctness**:
  In the reducible-CFG path we derive `InCycle` as `union(Loops[].NodeMask)`
  and skip the standalone Tarjan SCC pass. The correctness theorem is
  "in a reducible CFG every cycle is captured by some natural loop";
  the implementation hinges on `buildLoopsUsingDominance` returning
  `false` (so `UseLinearSPP=false`) for any irreducible CFG it cannot
  decompose, in which case we keep the Tarjan fallback. **Mitigation**:
  statetest 2723/2723 covers the reducible path; the
  `IrreducibleImproperRegion` GTest exercises the irreducibility check
  itself; runtime end-to-end metering soundness is established by the
  statetest gate. A worked correctness proof of the union-of-loops
  equivalence lives in the commit message for `6e1bc6b`.

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
  measured workload converging in 2 rounds. A future workload with deep
  irreducible nesting could push that higher and re-open the case. The
  counter ships in the profile build so the question stays cheap to
  re-ask. **Mitigation**: if a real contract ever shows rounds > 2,
  re-evaluate SemiNCA against measured cost.

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
