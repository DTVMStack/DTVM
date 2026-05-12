Verdict: REVISE — interpreter gate count is wrong (215 vs actual 226), and the proposed init rule has an unhandled edge case (`Reachable==1` with all preds `Reachable==0`) that drifts from the current pass's `Dom[N]={N}` semantics.

## Findings

### 1. BLOCKER — Wrong interpreter gate count
Location: `README.md` §Verification gates, gate 4.
What: Doc claims `evmone-unittests` interpreter run list yields **215/215**. The curated run list `tests/evmone_unittests/EVMOneInterpreterUnitTestsRunList.txt` has **226 lines** (`wc -l` confirmed), matching `.claude/rules/dtvm-local-test.md` which explicitly cites "interpreter (226 tests)".
Why: A wrong gate number means the implementer either reports a fake pass (215/215 invented) or aborts at a "shortfall" that is actually the real count. Both are bad.
Fix: Change gate 4 to `215/215` → `226/226`. Multipass (223/223) and statetest gate counts are not stated by the rule, but they should be verified by an actual run before being treated as authoritative.

### 2. HIGH — Init rule diverges from current pass on `Reachable==1, all preds unreachable`
Location: `README.md` §Design step 1–2; `src/evm/evm_cache.cpp:630-637, 644-664`.
What: Current pass treats a node as a self-root iff `Reachable[N]==0 || Preds.empty()`. But inside the fixpoint, a node with `Reachable[N]==1, Preds non-empty, all preds Reachable==0` also degenerates to `Dom[N] = {N}` (line 660-664: `HasPred=false` → zero NewDom → set Node bit). The new init rule (entry-like iff `Reachable[N]==0 || Preds.empty()`) leaves such a node at `IDom[N]=UINT32_MAX`, never reached by RPO (no entry-like root has it as a Succ-descendant). It stays undefined.
Why: After the Phase-7 reachability stitch (`evm_cache.cpp:1087-1108`) this class should be rare, but it is the precise multi-root corner the doc routes to gates 3+5. If the algorithm just silently mishandles it (UINT32_MAX leaking into `dominatesIDom`), tests will OOB-read `IDom[UINT32_MAX]`. The unit tests in §Test plan do not cover this.
Fix: Either (a) extend the entry-like predicate to include "all reachable preds are non-existent", OR (b) after the fixpoint, sweep nodes still at `UINT32_MAX` and assign `IDom[N]=N`, with an assertion that such N has zero reachable preds. Add a test fixture.

### 3. HIGH — `dominatesIDom` lacks a guard for `IDom[B]==UINT32_MAX`
Location: `README.md` §`dominatesIDom` helper, lines 105-117.
What: If finding 2 above is not addressed, the helper indexes `IDom[Finger]` without bounds-checking sentinels. Even after fix 2, defensive coding matters because `IDom[N]=UINT32_MAX` is the "undefined" state at any unfinished fixpoint step.
Why: Out-of-bounds vector read under ASAN; silent UB in release.
Fix: Either initialize `IDom[N]=N` for every node (treating reachable-but-undefined as self-root and letting the fixpoint refine), or assert `Finger != UINT32_MAX` at loop top.

### 4. MED — Test plan does not exercise the multi-root divergence case
Location: `README.md` §Test plan + §Risks bullet 3.
What: The doc acknowledges DiamondCFG does not cover "preds in disjoint roots → idom[N]=N" and routes it to gates 3/5. Those gates exercise live contracts where this corner is empirically rare (Solidity-emitted dispatchers are reducible single-entry). Relying on them is bench-only coverage; a targeted GTest is cheap.
Why: Without a unit fixture, an algorithmic regression here will only surface as a `buildLoopsUsingDominance` sanity-check return-false in a statetest somewhere, far from the change. Hard to bisect.
Fix: Add `Dominators_DisjointRoots_SelfIdom` test: build a `GasBlock` vector by hand with two disjoint reachable subgraphs joined later via a node whose preds come from both — assert `IDom[joinNode] == joinNode`.

### 5. MED — Statetest gate count `2723/2723` is unsourced
Location: `README.md` gate 5.
What: `.claude/rules/dtvm-local-test.md` mandates `-k fork_Cancun` for statetest but does not state a pass count. Hard-coding `2723/2723` without a fresh local run risks the same drift as finding 1.
Fix: Either (a) replace with "all selected tests pass, zero new failures vs baseline run from the same fixture commit", or (b) run statetest now and cite the count with the fixtures SHA.

### 6. MED — RPO seeding undercount when reachable set has only-back-edge entries
Location: `README.md` §Design step 3.
What: "RPO seeded from each entry-like root" covers nodes reachable via Succs from those roots. After the Phase-7 stitch, dyn-target JUMPDESTs become `Reachable=1` with `Preds.empty()` *only if no static pred*; if a JUMPDEST has both a dyn-pred (implicit) and a static fall-through pred, it's *not* entry-like, and RPO must reach it from its static pred. Confirm by reading the stitch at `evm_cache.cpp:1087-1108`: the stitch sets `Reachable[]=1` but doesn't add explicit edges, so the static-pred path remains. Good — but the doc should state this invariant explicitly so the implementer doesn't drop the stitch order.
Fix: Add a one-liner: "RPO seeding starts from every node where `IDom[N]==N` after init; this set is a superset of `Reachable[]==0` entries and Phase-7-stitched JUMPDESTs with empty static preds."

### 7. NIT — Caller rewrite count: doc says 3 sites, task prompt says 4
Location: `README.md` §Caller rewrites.
What: `grep -n "bitsetTest(Dom"` returns 3 hits (lines 684, 793, 838). Doc enumerates all 3 correctly. Argument-swap rationale ("Dom[X].test(Y) reads 'Y dominates X'") is right. No fix needed; the task prompt was off-by-one.

### 8. NIT — Risks section omits small-CFG overhead and ASAN
Location: `README.md` §Risks.
What: For tiny contracts (`N < ~50`), the bitset pass converges in 1 iteration and the new algorithm's RPO + fixpoint constant factor can lose. Also no mention of ASAN coverage for `dominatesIDom` walks.
Fix: Add bullet: "Small-N overhead — for `N < ~50` the bitset pass is already linear; gate 7's N=20k threshold doesn't catch a regression on the median real contract. Mitigation: a 27-bench geomean check at PR time (no formal gate)." Add: "ASAN run on `evmCacheTests` per `.claude/rules/dtvm-build-config.md`."

Reviewed by: opus
