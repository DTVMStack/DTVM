REVISE

## Round 2 Verification

Build: `cmake --build build --target evmCacheTests dtvmapi -j$(nproc)` →
ninja no-op (already built clean on HEAD `8a95175`).
Tests: `build/evmCacheTests` → `[==========] 14 tests from 2 test suites
ran. [  PASSED  ] 14 tests.` All 14/14 green.

R1 fix surface (`git diff b00efa1..HEAD`): 19-line spec edit + 6-line
`dominates` reorder + 3-line testing-header comment + 30-line test
rewrite + the R1-opus review appended. Production-code change is the
`dominates(A,B)` reorder only; all three call sites
(`evm_cache.cpp:867,976,1023`) pass in-range block indices, so the
behavioural change is internal-cleanup-only and statetest coverage from
R1 (2723/2723 fork_Cancun) carries forward unchanged.

## Remaining concerns

### MINOR — IrreducibleImproperRegion comment + spec note misrepresent loop bodies

severity: MINOR

evidence: `src/tests/evm_cache_tests.cpp:266-268` claims "Loop A
discovered from back-edge 3->1 has body {1,2,3}; loop B from back-edge
4->2 has body {2,3,4}. The two share {2,3} but neither contains the
other". Trace of `collectNaturalLoop` in `src/evm/evm_cache.cpp:930-953`
on the new CFG (`0->{1}, 1->{2}, 2->{3}, 3->{1,4}, 4->{2,5}, 5->{}`,
hence `preds[2]={1,4}`):
- Loop A (from=3, header=1): start LoopBits={1,3}, stack=[3]. Pop 3,
  preds={2}, add 2. Pop 2, preds={1 (header barrier), 4}, add 4. Pop 4,
  preds={3} (in). Body = **{1,2,3,4}**, not {1,2,3}.
- Loop B (from=4, header=2): Body = {2,3,4} (as claimed).
- {2,3,4} ⊂ {1,2,3,4}, so `BInA` at `evm_cache.cpp:1037` is true, and
  the nest-or-disjoint check at lines 1036-1040 **passes**. The
  reducibility fallback is NOT entered.

Cross-check with Codex R2 §A: Codex also concludes "{1,2,3} and {2,3,4}",
matching the test comment; my trace differs because Codex's walk omits
the backward step from node 2 to its predecessor 4.

This is a comment/spec-narrative drift, not a correctness bug: the test
helper `computeIDomForTesting` only exercises `computeDomInfo` (line
1481), so `buildLoopsUsingDominance` is never invoked by this test
regardless. The asserted IDom values [0,0,1,2,3,4] are independently
correct (CHK on RPO 0,1,2,3,4,5; confirmed by Codex R2 §A hand-trace
and 14/14 PASS).

recommendation: Rename the test to `OverlappingBackEdgesIDom` (or
`NestedLoopsTwoBackEdges`) and update the comment to "CHK must converge
to correct IDom on a CFG with two overlapping back-edges 3->1 and 4->2;
the natural loop {2,3,4} is properly nested inside {1,2,3,4} (reducible)
— this CFG exercises CHK's intersect finger-walk over a non-trivial
back-edge set, but does NOT trigger the SPP reducibility fallback".
Spec §"Step 5 implementation downgrade" line about "genuinely forces the
dominator pass to compute IDom on an irreducible loop nest" should be
softened or dropped.

### NIT — Structural unreachability of SPP fallback via pure-CFG fuzz

severity: NIT

evidence: DTVM's loop discovery is dominator-based — only edges where
target dominates source are back-edges (`evm_cache.cpp:864-871`). Under
this construction, all discovered natural loops form a properly nested
forest by definition. Classical irreducible CFGs (two-entry single
cycle) produce ZERO back-edges and ZERO loops; the
`!AInB && !BInA` branch at `evm_cache.cpp:1038-1040` is hard,
possibly impossible, to reach from a `computeIDomForTesting`-shaped
input. This means Opus R1's recommendation "add a real irreducible CFG
where the dominator pass IS forced to a fallback" was likely
unachievable through this helper. The current downgrade note correctly
defers behavioural fallback coverage to `evmone-statetest` and PR B/C,
so the spec contract is honest.

recommendation: Note for PR B authors — exercising
`buildLoopsUsingDominance` fallback requires `buildBytecodeCache` plumb,
not `computeIDomForTesting`.

## Sanity Checks

- `dominates(A,B)` reorder verified at `evm_cache.cpp:639-647`:
  out-of-range returns false, in-range A==B returns true. Three
  production call sites all pass in-range ids; no behavioural change.
- `evm_cache_for_testing.h:15-23` doc accurately states the helper is
  the dominator pass in isolation.
- Spec Checklist Step 7 annotation `(production gate FAIL, override
  approved)` visible at line 267.
- Spec §"Step 5 implementation downgrade" at lines 129-143 enumerates
  exactly the per-fixture behavioural claims deferred to PR B/C. This
  is intellectually honest about the scope reduction.

## Verdict

REVISE with **1 MINOR + 1 NIT**. The MINOR is doc/comment drift that a
careful reader would flag in cold review (the test's irreducibility
narrative is false); the algorithm, IDom assertions, and spec downgrade
prose are all sound. Cheapest path to PASS: rename
`IrreducibleImproperRegion` and update both its comment and the spec
downgrade note's last sentence. No code, build, or test re-run needed.
