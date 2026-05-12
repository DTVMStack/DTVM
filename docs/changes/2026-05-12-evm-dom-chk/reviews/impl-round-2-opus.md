# R2 implementation review - Opus

Worktree: `/home/abmcar/DTVM/.worktrees/perf-dom-lengauer-tarjan`
R2 diff: `/home/abmcar/.claude/jobs/3d8995d3/dom-chk-impl-r2.diff`

Verifying R1 blocker resolution and doc-integrity fixes; not re-checking
what R1 already passed (CHK intersect, multi-root divergence sentinel,
Enter/Exit DFS shape, caller argument orders).

## 1. R1 BLOCKER — class-C descendant — RESOLVED

Init-time class-C seeding lives at `src/evm/evm_cache.cpp:646-661`.
Logic: every reachable node whose `Preds` is non-empty but contains no
reachable predecessor is seeded as `IDom[I] = I`. The loop also seeds
class A (`Reachable==0`, line 647) and class B (`Preds.empty()`, line
647) in the same pass.

Consequence for the divergent case from R1 (node N class-C, descendant
M with only-reachable-pred N): at RPO time, `IDom[N]=N` is already
settled, so M's intersect picks up `NewIDom = N` (single processed pred
path at `src/evm/evm_cache.cpp:755-756`) and sets `IDom[M] = N`. The
post-fixpoint sweep at `src/evm/evm_cache.cpp:778-782` is now reached
only by orphan reachable components not seeded by any root — its role
is correctly downgraded to defensive backstop, matching the §Design
text at `README.md:132-138`.

## 2. GTest coverage — PASSES, exercises the init seed path

`ClassCDescendant_SeedsAtInit` at `src/tests/evm_cache_tests.cpp:241-266`.
Fixture:
- Node 0: `Reachable=0`, `Succs={1}` → class A self-root.
- Node 1: `Reachable=1`, `Preds={0}` (all unreachable) → class C, must
  seed at init.
- Node 2: `Reachable=1`, `Preds={1}` → descendant.
- Node 3: `Reachable=1`, `Preds={2}` → descendant chain.

Without the init seed at `src/evm/evm_cache.cpp:651-660`, node 1 stays
at `UINT32_MAX` through the entire RPO fixpoint (its only pred is
`Reachable=0`, filtered at `:749`), so when node 2 is visited
(`src/evm/evm_cache.cpp:748-764`), `IDom[Pred=1] == UINT32_MAX` triggers
the skip at `:752-753`, `NewIDom` stays `UINT32_MAX`, and the
post-fixpoint sweep at `:778-782` collapses both 1 and 2 to self —
producing `IDom[2]=2` instead of the asserted `IDom[2]=1`.

So this test directly anchors the init-time class-C seed, not the
multi-root in-fixpoint divergence path (which `DisjointRoots_SelfIdom`
at `:215-239` covers separately). R1 MED finding 5 (sweep / class-C
unexercised) is addressed.

## 3. Doc integrity — mostly clean, two residual stale items

### Caller-rewrites table line numbers — VERIFIED

`README.md:178-182` lists post-PR sites 834 / 943 / 990. Fresh
`grep -n "Dom\.dominates" src/evm/evm_cache.cpp`:
```
834:      if (Dom.dominates(To, static_cast<uint32_t>(From))) {
943:      if (!Dom.dominates(To, static_cast<uint32_t>(From))) {
990:      if (!Dom.dominates(Loop.Header, Node)) {
```
All three match; `computeDomInfo` is at `src/evm/evm_cache.cpp:627`
(README:12, :222), and `buildGasChunksSPP` invocation at `:1261`
(README:226). All cited line numbers are accurate against the current
worktree.

### "four/five GTests" — RESOLVED

- README:230, :283 say "five" — match the five tests at
  `src/tests/evm_cache_tests.cpp:162,178,196,215,241`.
- README:137 says "ClassCDescendant_SeedsAtInit and the four other
  dominator GTests" — arithmetic consistent (1+4=5).
- README:352-353, :383-384 say "four initial GTests" / "Step 1 — TDD
  anchor + 4 tests" / "Step 2 — CHK implemented; 4 tests pass" — these
  refer to the historical step-1/step-2 milestones before step 6 added
  the fifth, narrative at README:352-355 makes this explicit.

No remaining "four vs five" mismatch.

### Risks section — RESOLVED

`README.md:322-330` now correctly says class C is handled "by **seeding
at init**" and the post-fixpoint sweep is a "defensive backstop only".
Codex R1 finding 8 bullet 2 addressed.

### NIT — Stale citations in Class A/B/C table at README:89-91

The table cites `evm_cache.cpp:631` for class A/B and `:660-664` for
class C, with descriptions in old-bitset terminology (`Dom[N]={N}`,
`HasPred=false zeroes NewDom`, `bitsetSet(NewDom, N)`). At current line
631 the code is `Info.IDom.assign(N, UINT32_MAX);` — not class A/B
init. Class C init in the new code is at `:651-660`. The descriptions
also describe the *removed* bitset pass. The framing text at
README:84-86 says "The current pass treats three classes" without
explicitly tagging "old" vs "new", which makes the table read as if
describing the post-PR code.

This is cosmetic — the §Design body at README:107-128 correctly
describes the new init seeding — but the table is misleading on first
read. Suggest either (a) retitle as "Pre-PR class definitions
(motivation)" with old line numbers, or (b) refresh to new line
numbers and remove `Dom[N]={N}` phrasing.

### NIT — `evm_cache.cpp:1231-1260` Phase-7 citation off by 4 lines

README:94 cites the Phase-7 stitch at `:1231-1260`. The reachability
re-compute is at `:1227` and the actual seed-and-propagate block is
`:1239-1260` (line 1231 is a comment line). Off-by-4 in the start
line, but the range correctly covers the stitch. Cosmetic.

## 4. NIT triage — implementation

- **Header comment at `evm_cache.cpp:606-610`**: 5 lines. Acceptable
  under cpp-code-style.md (R1 NIT 7 raised this against a 12-line
  version; the current trimmed comment looks fine).
- **`DfsFrame &Top = Stack.back()` reference invalidation at
  `evm_cache.cpp:684,138`**: R1 NIT 8 noted this is safe because
  increment happens before push and `reserve(N)` prevents realloc. No
  inline comment was added per R1's suggestion. Optional cosmetic.
- **`bitsetWordCount` still used at `evm_cache.cpp:928`**: only used
  by `buildLoopsUsingDominance`'s loop-membership bitset — expected,
  per README:196 parenthetical. Not dead code.
- **`for_testing::computeIDomForTesting` Preds reconstruction order**
  at `src/evm/evm_cache.cpp:1421-1438`: R1 NIT 9 — pred order is
  node-id ascending, may differ from production. The fixpoint is
  order-insensitive for correctness; the testing-shim ordering does
  not get documented but is harmless. Cosmetic.
- **`evm_cache_for_testing.h` not in `EVM_SRCS`**: README:236-239
  acknowledges this is internal-only. The include in
  `src/evm/evm_cache.cpp:7` and `src/tests/evm_cache_tests.cpp:10`
  resolves via the include path. No action.

## Verdict

Verdict: **PASS** — only cosmetic notes.

R1's class-C-descendant blocker is correctly fixed at the init seed
(verified by file:line reading of `src/evm/evm_cache.cpp:646-661` and
the dedicated `ClassCDescendant_SeedsAtInit` GTest). Doc-integrity
issues from R1 codex (test count, caller-rewrites line numbers, risks
section staleness) are resolved. Two minor stale citations remain in
the README (class A/B/C table at :89-91 and Phase-7 line range at :94);
both are cosmetic and do not affect the implementation or the
verification gates.

Recommend proceeding to commit / push. Optional follow-up: refresh the
two README citations noted in §3 NIT before final PR submission.

Reviewed by: opus (impl R2)
