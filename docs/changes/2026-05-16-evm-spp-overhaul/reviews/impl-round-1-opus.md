REVISE

## Findings

### MAJOR — Step 5 GTests cover IDom only; spec promises broader pipeline assertions

severity: MAJOR

evidence: `src/tests/evm_cache_tests.cpp:246-362` adds the five structural
tests (SelfLoop, IrreducibleSCC, NestedSharedExit, CriticalEdgeEmptySplit,
DynTargetInStaticLoop). Every one of them calls only
`zen::evm::for_testing::computeIDomForTesting(Succs, Reachable)` and asserts
on the returned `IDom[]` array; none of them invokes `buildBytecodeCache` /
exercises `buildLoopsUsingDominance`, `UseLinearSPP`, `GasChunkCostSPP`,
`InCycle`, or `splitCriticalEdges` write-back. The spec `README.md:129-138`
explicitly promised: SelfLoop → `InCycle[1]==1`, `UseLinearSPP=true`,
1 loop containing node 1; IrreducibleSCC → behavioural invariants on
`buildLoopsUsingDominance`/`UseLinearSPP` and `GasChunkCostSPP[] ≡
GasChunkCost[]` on fallback; NestedSharedExit → both loops detected, exits
in metering; CriticalEdgeEmptySplit → `GasChunkCost[split_block.Start] ==
0`; DynTargetInStaticLoop → reachability stitch + `UseLinearSPP` gate +
`GasChunkCostSPP` validity. README.md:254-269 "Step 5 Scope Reduction" only
acknowledges the path-total fuzz being deferred — it does NOT acknowledge
that the five structural tests were also reduced to dominator-only stubs.

recommendation: Either (a) extend each test with an end-to-end
`buildBytecodeCache(...)` companion fixture that observes the promised
SPP/loop signals, or (b) amend §"Step 5 Scope Reduction" to enumerate
exactly what was reduced and why, and downgrade the spec's Step 5 wording
to "5 dominator-tree correctness GTests".

### MAJOR — Test for "irreducible SCC" does not actually exercise the irreducibility fallback

severity: MAJOR

evidence: `EVMCacheDominator.IrreducibleSCC_TwoEntryLoop` at
`src/tests/evm_cache_tests.cpp:264-283` builds `Succs = {{1,2},{2,3},{1,3},{}}`.
With entry 0 reaching both 1 and 2 directly, `IDom[1]=IDom[2]=0`. Back-edge
discovery at `src/evm/evm_cache.cpp:864-871` only flags edges where the
target dominates the source. For edge 1→2: does 2 dominate 1? No. For
edge 2→1: does 1 dominate 2? No. So
`findBackEdgesUsingDominators` returns no back-edges and
`buildLoopsUsingDominance` (lines 970-993) discovers zero loops, returning
`true` (`UseLinearSPP=true`). The reducibility fallback at lines 1019-1042
is not entered. The test passes, but it only confirms that two cycle
entries collapse to the entry's idom — it never observes "neither
dominates the other in a *cycle*" exercising fallback. R2-style
acknowledgement of this gap is missing from the spec.

recommendation: Add a real irreducible CFG where the dominator pass IS
forced to a fallback (e.g., shared back-edge target with two header
candidates), or rename the test to reflect what it actually checks
(`MultiEntryNoBackEdge_*`).

### MINOR — `computeIDomForTesting` accepts arbitrary `Reachable` decoupled from `Succs`

severity: MINOR

evidence: `src/evm/evm_cache.cpp:1463-1481` lets the caller pass any
`Reachable` mask regardless of what `Succs` implies. Tests can construct
inconsistent inputs (e.g., a node with reachable preds marked
unreachable) that would never appear from `computeReachable`. The harness
also bypasses the dyn-target reachability stitch in `buildGasChunksSPP`
(lines 1259-1285), so `DynTargetInStaticLoop`'s comment about "stitch
roots" is decorative — the test just sets `Reachable[2]=1` manually.

recommendation: Either (a) document that the helper is the dominator
pass in isolation, with the caller responsible for stitching, or
(b) add a second helper that runs `computeReachable` from a given
entry to validate the stitch coverage.

### MINOR — `DomInfo::dominates` returns `true` for out-of-range equal arguments

severity: MINOR

evidence: `src/evm/evm_cache.cpp:639-647`. The `A == B` shortcut at line
640 returns `true` before the bounds check at line 643. If two callers
accidentally pass the same out-of-range id (e.g., `UINT32_MAX, UINT32_MAX`),
the function reports them as mutually dominating. No current call site
hits this, but the contract is surprising.

recommendation: Move the `A == B` shortcut below the bounds check, or
add `A < IDom.size()` to the early-return condition.

### NIT — Production gate FAIL acknowledged but Checklist line 250 still says `[x] Step 7`

severity: NIT

evidence: `README.md:316-323` and `README.md:377-397` now explicitly
report "FAIL" for the production gate, with an explicit user-approved
override. Good. However the §Checklist `README.md:250` still ticks
"Step 7 — baseline + treatment bench; Results table populated" without
flagging that the strict gate clause from Step 9 is unmet. Step 9 is
`[ ]` correctly.

recommendation: Annotate the Step 7 tick with "(production gate FAIL,
override approved — see §Gate Recalibration)" so Phase 4 readers see
the failure flag at checklist scan time.

### NIT — `evmCacheTests` total is 14 (4 + 10) but README §Step 5 expects "5 existing dom + 5 new"

severity: NIT

evidence: `README.md:142` originally specified "4 existing implicit-dyn-pred
+ 5 existing dom + 5 new = 14". Actual is 4 implicit + 10 dom (5 existing
+ 5 new = 10) = 14. The arithmetic matches but the bookkeeping in the
spec doesn't separate the new dom tests from the existing ones in the
final count. Cosmetic.

recommendation: None or trivial wording update.

## Sanity Checks Performed

- `cmake --build build --target evmCacheTests -j$(nproc)` — no-op (already built).
- `build/evmCacheTests` → `[==========] 14 tests from 2 test suites ran. [  PASSED  ] 14 tests.`
- `nm -D build/lib/libdtvmapi.so | grep -iE 'chrono|EVM_CACHE_PROFILE'` → empty (no leakage from PROFILE macros into OFF build; the `chrono` symbols in the .so come from the unrelated `zen::utils::StatisticPhase` subsystem). Spot-checks `buildGasChunksSPP` disassembly: no `steady_clock`/`fprintf` references. Macro elision works.
- `tools/format.sh check` → exit 0.
- multipass `evmone-unittests` 223/223 PASS.
- `intersect` UINT32_MAX path traced for NestedSharedExit (returns common dominator 1, never UINT32_MAX) and DisjointRoots (returns UINT32_MAX → self-root fallback). Path is sound.
- All 9 PR commit subjects pass commitlint (`docs/test/chore/perf` × `core/docs/tools`); Codex round-1's "Commit Hygiene MAJOR" no longer applies after the rewrite.

## Disagreements with Codex

1. **Spec Honesty (Codex MAJOR)** — stale. The current HEAD `b00efa1`
   ("Phase 4 R1 Codex review fixes") rewrites the §Results gate column
   to "**FAIL**" (line 314) and §Gate Recalibration to
   "**Production gate** ... : **FAIL**" (line 377). Codex's evidence
   quotes "borderline" wording that no longer exists. I downgrade this
   to my NIT above (Checklist line not annotated).

2. **Commit Hygiene (Codex MAJOR)** — stale. Codex parsed
   `tools(evm)`, `test(evm)`, `docs(evm)` which are not in the
   commitlint enum. Current HEAD's nine commits use `docs(docs)`,
   `docs(core)`, `test(core)`, `chore(tools)`, `perf(core)` — all pass
   the locally reinstalled commitlint (`@commitlint/cli` + parser).
   Drop entirely.

3. **Dominator Correctness NIT (Codex)** — I agree on the
   `dominates(A,B)` out-of-range edge case and surface it as my own
   MINOR. We agree on the algorithmic mapping to CHK Figure 3.

4. **Bench Harness MINOR (Codex)** — Verified Efron-Tibshirani 1993
   citation is now in `tools/analyze_evm_cache_bench.py:15`. Stale.

5. **GTests MAJOR (Codex)** — fully agree, surfaced independently
   as my first MAJOR above. This is the load-bearing finding.

## Verdict

REVISE. Two MAJORs (test scope vs spec, irreducible-test mislabel),
two MINORs (testing-helper looseness, `dominates` out-of-range), two
NITs. None of the MAJORs block the dom-CHK algorithm change itself
(algorithm + production-path tests + statetest 223/223 are sound) — they
block the spec ↔ implementation honesty contract. Cheapest path to
PASS: amend §"Step 5 Scope Reduction" to enumerate exactly which
dom-pass-only assertions stand in for the broader pipeline claims, and
either fix the IrreducibleSCC test name or replace it with a CFG that
forces fallback.
