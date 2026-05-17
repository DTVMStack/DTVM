# Round 1 Review — Opus (cold-read, adversarial)

**Doc:** `docs/changes/2026-05-17-evm-cache-build-fusion/README.md`
**Branch:** `perf/cache-build-fusion` (11 commits over `perf/evm-spp-foundation`)
**Mode:** Adversarial; skeptic of doc's correctness/measurement claims.

VERDICT: REVISE

The implementation lands a real, measurable cache-build win and the code is empirically sound on the suites tested. However, two **factual defects in the documentation** undermine the correctness story it sells (R2 cites a test that does not exist; the same R2 mitigates against a failure mode that the algorithm does not actually defend against — the runtime is sound by a *different* invariant than the doc claims). The "Implementation Plan" header claim that every commit is independently revertable is also overstated for the CSR/EdgeTables pair. None of these are runtime bugs, but each is the kind of false reassurance a reviewer two months from now would rely on. Worth a clean second pass before merging.

## Critical issues (BLOCK if any apply)

None. The dom-CHK pipeline, 14/14 `evmCacheTests`, the 32-byte `GasBlock` layout, and the chkFixpointRounds=2 reading all reproduce on a freshly rebuilt local binary. No correctness regression observed.

## Major issues (REVISE if any apply)

### M-1 — R2 references a GTest that does not exist
severity: MAJOR
evidence:
- `docs/changes/2026-05-17-evm-cache-build-fusion/README.md:317` claims:
  *"the `IrreducibleImproperRegion` GTest exercises the irreducibility check itself"*
- `build/evmCacheTests --gtest_list_tests` enumerates exactly 14 tests across 2 suites (`EVMCacheImplicitDynPred.*` ×4, `EVMCacheDominator.*` ×10). No test named `IrreducibleImproperRegion` exists.
- `grep -rn "Irreducible" src/tests/` returns one hit — a *comment* at `src/tests/evm_cache_tests.cpp:271` that is part of the **`OverlappingBackEdgesIDom`** test, and the comment goes out of its way to **disclaim** any irreducibility coverage:
  > "the SPP reducibility fallback is NOT entered. This test exercises only the IDom output of CHK on the irreducible-shaped predecessor graph […]. Exercising the SPP reducibility fallback itself requires end-to-end buildBytecodeCache plumb and is deferred to PR B / PR C"

recommendation:
Replace the R2 sentence "the `IrreducibleImproperRegion` GTest exercises the irreducibility check itself" with the truth: there is currently **no test that drives `UseLinearSPP=false`** in `evm_cache_tests.cpp`. Either (a) add such a test as part of this PR (a synthetic CFG class that produces a multi-entry cycle through `for_testing::computeIDomForTesting` plus a `buildBytecodeCache` smoke check on hand-crafted bytecode), or (b) acknowledge the gap and downgrade R2 from "established by gates" to "established by argument only — the fallback path is not currently covered by a regression test." Either is acceptable; the present text is just wrong.

### M-2 — R2's correctness argument leans on the wrong invariant
severity: MAJOR
evidence:
- `evm_cache.cpp:1378` sets `UseLinearSPP = buildLoopsUsingDominance(...)`. The function returns `true` whenever (a) every detected loop body is dominated by its header (line 1090) and (b) loops are nest-or-disjoint (line 1105).
- These two checks are **necessary but not sufficient** for "every cycle in this CFG is a natural loop." Specifically, the natural-loop construction at line 1043 only fires when `Dom.dominates(To, From)`. In an *irreducible 2-entry cycle* `A↔B` (each pred-set includes one cycle-internal predecessor plus one outside entry), neither `dominates(A,B)` nor `dominates(B,A)` holds — so **no back-edge is found, no natural loop is built for the cycle, the function returns `true` with zero loops covering the cycle, `UseLinearSPP=true`, and the `computeInCycle` Tarjan-fallback is skipped (line 1407).** The doc's bald claim "in a reducible CFG every cycle is captured by some natural loop" is true; the **gate that decides 'reducible'** is weaker than the claim requires.
- Empirically the pipeline still produces correct metering on such CFGs, because `lemma614Update`'s independent multi-pred guard (line 1223, `effectivePredCount(Succ) != 1`) blocks shifts both into and within the SCC: every node in any SCC of size ≥2 has at least one in-cycle pred, so its effective pred count is ≥2, so shifts are dropped before they can mis-charge. Soundness on irreducible CFGs is therefore **a coincidence of the multi-pred guard, not of the InCycle masking the doc invokes.**

recommendation:
Re-write R2 to state the actual invariant the runtime relies on. Concretely:
- The conditional `if (UseLinearSPP) { InCycle = union(Loops[].NodeMask); }` is a **performance** optimisation, not a soundness mechanism.
- Soundness against missed cycles is provided by `effectivePredCount` in `lemma614Update`: every SCC-internal node has cycle-internal preds, which push the count ≥2 and inhibit shifts. The InCycle mask is a redundant guard.
- Add a sentence saying the Tarjan fallback is retained **as a defence-in-depth** layer, not as the primary safety net.
Without this clarification the doc reads like "the union-of-loops is correct on every CFG `UseLinearSPP` decides is reducible," which is not what the gate actually guarantees, and a future contributor relying on it could remove the multi-pred guard thinking InCycle has them covered.

### M-3 — "each [commit] independently revertable" is overstated for the CSR/EdgeTables pair
severity: MAJOR
evidence:
- `git show 0dd5bb9 -- src/evm/evm_cache.cpp` introduces `buildAdjacencyCSR(const std::vector<GasBlock>&)` and reads `Blocks[I].Succs / Blocks[I].Preds` inside it.
- `git show 689e5d5 -- src/evm/evm_cache.cpp` then *removes* `Succs`/`Preds` from `GasBlock`, introduces the parallel `EdgeTables`, and changes `buildAdjacencyCSR`'s signature to `(const EdgeTables&)`. Every downstream writer (`addEdge`, `buildCFGEdges`, `splitCriticalEdges`) is migrated to `EdgeTables` in the same commit.
- Reverting **only** `689e5d5` while keeping `0dd5bb9`'s CSR reads is therefore a compile failure (the readers expect CSR built from `Blocks[].Succs`, but the `GasBlock` no longer has those fields and the helper signature is gone). To revert `689e5d5` cleanly you have to revert `0dd5bb9` as well, or manually re-apply 0dd5bb9's `buildAdjacencyCSR` overload by hand.

recommendation:
Soften the Implementation Plan line at README.md:180-182 from "any of them can be cherry-picked or reverted in isolation" to something honest: "each commit passed `evmCacheTests` and `evmone-statetest -k fork_Cancun` before the next was authored; the commits within a phase form a unit (notably the CSR/EdgeTables pair) and reverting a single commit from a phase is generally not buildable without reverting the rest of the phase." Or just drop the "independently revertable" bullet — the per-commit-greenness claim is the part reviewers actually care about, and it's already supported.

## Minor issues / nits (informational)

### N-1 — Per-phase table totals don't agree with the row sum
severity: MINOR
evidence: README.md:65-80 lists 13 phase rows for the "PR A baseline" column and a `<TOTAL>` of 41412 us. Hand-summing the column: 9525+7233+5694+4562+1818+1733+1651+1309+1169+657+457+378+24 = **36210 us**, ~5200 us short of the 41412 stated. The doc's footnote `†` acknowledges that 45603 was an earlier 25-rep run while 47429 is the apples-to-apples 100-rep, but doesn't explain the 41412 figure in the phase-breakdown table itself.
recommendation: Either re-run the per-phase table from a single 100-rep measurement and replace the column wholesale, or add a note saying "9-rep mean per phase, total drawn from a separate 100-rep gating run; the discrepancy reflects sampling variance + EVM_PROFILE chrono overhead at ~13 phase boundaries." Right now the table looks stitched.

### N-2 — `IrreducibleImproperRegion`-named reference appears twice
severity: MINOR
evidence: README.md:147-148 also says "existing 14 tests still pass, including `IrreducibleImproperRegion` which exercises the Tarjan fallback path." This is the same fabrication as M-1; flagging separately so a quick search-and-replace catches both sites.
recommendation: Fix in lockstep with M-1.

### N-3 — `EVMBytecodeCache` byte-identical claim is not test-covered
severity: MINOR
evidence: README.md:152 states "`EVMBytecodeCache` is byte-identical for every contract on every input." The four `EVMCacheImplicitDynPred` tests check `GasChunkCost`/`GasChunkCostSPP` at specific PCs, but no test diffs the **full** `EVMBytecodeCache` (`JumpDestMap`, `PushValueMap`, `GasChunkEnd`, `GasChunkCost`, `GasChunkCostSPP`) byte-by-byte against a baseline run. The 2723/2723 statetest gate establishes runtime-observable equivalence (which is the property that actually matters for ABI), so "byte-identical" is plausible but not directly verified.
recommendation: Either downgrade to "behaviourally identical (statetest 2723/2723 confirms)" or add a short test that runs `buildBytecodeCache` against a fixture corpus on both `perf/evm-spp-foundation` and this PR and `memcmp`s the resulting cache structs.

### N-4 — Comment offset table has a small terminology quirk
severity: MINOR
evidence: `evm_cache.cpp:230` comment lists `22 pad uint16`. The actual layout (verified via `offsetof` on a standalone reproduction with the same field order) puts `LastOpcode` at offset 20, `PrevOpcode` at 21, and pads byte offsets 22-23 to align the following `uint64_t Cost` at offset 24. So "pad uint16" is technically accurate as "2 bytes of pad", but reads as if the struct had a `uint16` field there.
recommendation: Change `22 pad uint16` to `22 pad[2]` or `22 pad (2 bytes for 8-byte alignment of Cost)`. Cosmetic.

### N-5 — `chkFixpointRounds=2` cap is workload-shape-dependent
severity: MINOR (R4 already partly acknowledges this)
evidence: All 10 `EVMCacheDominator` tests print `chkFixpointRounds=2`; so does `evmCacheComplexityDemo` at every N. R4 already calls this out, but doesn't construct or describe a CFG class that would force >2 rounds. Concretely: any CFG where the RPO order processes a node *before* its eventual idom (e.g. a deep irreducible nest, or unreachable-to-reachable transitions) will require ≥3 rounds. The current synthetic generator's "flat alternating PUSH/JUMP" pattern is the easiest possible case for CHK; production contracts have not been measured.
recommendation: R4 is fine but a sentence noting "the synthetic stress pattern is also the easy case for CHK convergence — measurements on a real-corpus contract sample would strengthen this claim" would be honest.

### N-6 — `meteringInit +110%` is dismissed as cache-effect without measurement
severity: MINOR
evidence: README.md:239 marks `meteringInit` as +110% (378 → 794 us) and the footnote attributes it to "cache-effect attribution from the reordered pipeline". This is plausible (the prior pipeline left `Blocks[].Succs/Preds` cache-warm, so the next-phase `Cost` reads were free; now the CSR-only readers don't pre-warm `Blocks`, so `meteringInit`'s `Metering[Id] = Blocks[Id].Cost` walk takes the cache miss instead). But the attribution is not measured — could also be a chrono-overhead artefact at the ~800us scale.
recommendation: Note that the +110% is a measurement attribution conjecture, not a verified diagnosis. Mostly cosmetic since the net win swamps it.

## Sanity checks performed

- Read `src/evm/evm_cache.cpp` end-to-end (1610 lines) in the perf-cache-build-fusion worktree.
- Ran `build/evmCacheTests` — 14/14 pass; printed `chkFixpointRounds=2` on every test that exercises CHK.
- Reproduced the `sizeof(GasBlock) == 32` and field offsets via standalone `g++ -std=c++17 -O2` compile of a struct copy: offsets {Start=0, End=4, LastPc=8, PrevPc=12, ImplicitDynamicPredCount=16, LastOpcode=20, PrevOpcode=21, Cost=24, sizeof=32}. Matches the doc.
- `grep -rn "Irreducible"` in `src/tests/` — only the disclaimer comment in `OverlappingBackEdgesIDom`. No `IrreducibleImproperRegion` test exists.
- Hand-summed the doc's "PR A baseline" column: 36210 vs the doc's 41412.
- Read `git show 0dd5bb9` and `git show 689e5d5` to confirm the inter-commit API dependency that breaks the "independently revertable" claim.
- Traced `buildLoopsUsingDominance` → `Dom.dominates(To, From)` back-edge gate and confirmed the irreducible 2-entry cycle scenario where `UseLinearSPP=true` despite the cycle being unrepresented in the natural-loop union.
- Traced `lemma614Update` → `effectivePredCount` to confirm soundness on the irreducible scenario is via the multi-pred guard, not the InCycle mask.

## Verdict reasoning

The 11-commit body is real engineering work and the headline 47ms → 28ms result on the synthetic N=100k fixture reproduces. None of the issues I found amount to a runtime bug — the pipeline is correct on every workload exercised by the 14 unit tests and the 2723-contract statetest gate. What pushes this to REVISE rather than PASS is the change doc's correctness story: R2 mitigates a failure mode by appeal to a test that does not exist, and the underlying soundness on irreducible CFGs comes from a different mechanism (`effectivePredCount`'s multi-pred guard) than the one R2 names (`InCycle` mask via Tarjan fallback). Combined with the overstated revertability claim and the stitched-looking phase totals, the document does not yet meet the standard of "future contributor can trust every claim here without re-deriving." Fixing M-1, M-2, M-3, N-1 (and propagating to N-2) should be a single editing pass; no code changes required other than optionally a new test to actually drive `UseLinearSPP=false`.
