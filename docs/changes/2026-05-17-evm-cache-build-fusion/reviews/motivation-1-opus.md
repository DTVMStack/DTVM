# Motivation red-team — internal-consistency lens (Phase 0.5)

**Plan reviewed:** A (ship `perf/cache-build-fusion`) → B (real-corpus validation) → C (4 micro-opts gated on B).
**Mode:** Internal consistency. Not re-checking the perf data or correctness story — both R2 reviewers PASSed those.

## Headline

The macro direction A→B→C is reasonable, but the plan has three concrete internal-consistency defects that will cost a round trip if shipped as written:

1. **A's "add a `UseLinearSPP=false` GTest" silently invalidates the R2 PASS branch.**
2. **C has no numeric trigger from B — the gate is rhetorical, not operational.**
3. **C's ~1ms/0.5ms/0.5-1ms estimates are *phase-cost* numbers, not *fold-delta* numbers. They overstate ROI by a factor that materially flips the EIP-170 argument.**

A residual fourth point: R2's soundness PASS verified the **doc edit**, not the **invariant** — that gap is not fatal for shipping A but is relevant if C ever wants to remove a guard.

Verdict reasoning at the bottom.

## 1 — Problem statement: A is real, B is well-defined, C is under-specified

- **A** is well-posed. R2 PASS is on file (Opus + Codex). Codex re-measured 1.67× reproducing the claimed 1.69× (round-2-codex.md:18). What ships is what was reviewed. PASS branch going stale is a real cost.
- **B** is well-posed. PR A's paired-ratio BCa cluster-bootstrap harness exists and was used on `perf/evm-spp-foundation`; re-running it on this branch's HEAD is a mechanical re-invocation.
- **C** is **not** well-posed as currently framed. The 4 micro-opts have estimates but no acceptance criterion. The plan says "gated on B's data" without naming the production-speedup threshold that flips C from "do it" to "drop it." Without a number, B's data will arrive, the question will re-open, and the decision will be punted to a third /dev-cycle. (See §4 for the concrete defect.)

## 2 — A's R1-fix completeness is not the live issue. The live issue is the test-add.

The plan's A-scope explicitly lists: *"Add `UseLinearSPP=false` GTest under `src/tests/evm_cache_tests.cpp` to fill R1-cited coverage gap on the irreducible-CFG fallback path."*

This **reopens** the R2 PASS verdict. Read the R1 ladder:

- R1 Opus M-1 offered the author a binary choice: *"(a) add such a test as part of this PR ... or (b) acknowledge the gap and downgrade R2 from 'established by gates' to 'established by argument only'"* (round-1-opus.md:27).
- The R2-PASSed README took option **(b)**. README:172 reads *"none of them drives `UseLinearSPP=false`"* and README:425-428 explicitly defers the test plumbing.
- R2 Opus PASS cited this exact deferral as the reason M-1 is closed (round-2-opus.md:8).

Adding the test now means **what ships is no longer what was R2-PASSed**. Options:

- **(i) Ship strictly verbatim** (just the docs/spec adds + push). Honors the R2 PASS, honors the "ship before PR goes stale" urgency. Defers the test to a follow-up PR. This is consistent.
- **(ii) Add the test, accept R3.** Run an R3 round (Opus + Codex) on the new test. R3 is cheap (one test, one file, one CMake stanza) but it is **not** a free addition to a R2-PASS branch. R3 must inspect: does the new test actually exercise `buildLoopsUsingDominance → false`? Does it pass on HEAD? Is it deterministic across platforms?
- **(iii) Drop the test, also drop the README's "deferred" framing.** The current text reads correctly only if no test is being added in the same PR.

The plan currently proposes (ii) in scope while quoting (i)'s urgency. Pick one.

**Recommendation:** Prefer (i). The R2 PASS is on the doc-text plus the statetest 2723/2723 end-to-end gate. The unit test is genuinely a follow-up — it requires a `buildLoopsUsingDominance` test hook the codebase doesn't have, and the README itself flagged it as "plumbing required." Adding it under time pressure to ship NOW is exactly the case where it gets rushed and the test ends up not actually driving the fallback path (a known failure mode — see R1 Opus M-1's evidence that `OverlappingBackEdgesIDom` claims to exercise irreducibility but doesn't).

## 3 — A's doc update is fine; the docs/changes promotion is the silent risk

`docs/modules/evm_cache.md` updates are uncontroversial. The hazard is in the change-doc-promotion step (per CLAUDE.shared.md and DTVM CLAUDE.md): the project requires `docs/changes/YYYY-MM-DD-<slug>/README.md` *inside the repo* at PR time, but the worktree already has it at the right path (`/home/abmcar/DTVM/.claude/worktrees/perf-cache-build-fusion/docs/changes/2026-05-17-evm-cache-build-fusion/`). Promotion is a no-op here. State that explicitly in the push-gate so it doesn't get accidentally copied from `~/changes/` and double-staged.

## 4 — C's estimates are phase-cost numbers, not delta numbers

This is the most material internal-consistency defect. Per `perf-summary.md` HEAD per-phase column:

| C-opt | C-estimate | HEAD phase cost | What the fold can actually save |
|---|---|---|---|
| Fold `computeReachable` into `computeDomInfo`'s DFS | ~1ms / N=100k | computeReachable HEAD = **1.076ms** | The fold saves only the *duplicated traversal* portion. `computeDomInfo` still needs its own DFS for postorder. Realistic save ≤ ~0.3-0.5ms; the estimate assumes the whole phase disappears. |
| `buildCFGEdges` dedup skip | ~0.5ms / N=100k | buildCFGEdges HEAD = **4.512ms** | The 2-pass→1-pass fusion already landed in `de934a8`. "Dedup skip" needs concrete definition — what is being deduplicated that the single sweep doesn't already cover? |
| `buildCSR` prefetch hints | ~0.5ms / N=100k | buildCSR HEAD = **3.326ms** | `buildCSR` is sequential streaming over `Off`/`Data` arrays (see `evm_cache.cpp:268-289`). HW prefetcher already saturates this access pattern. Software prefetch typically yields 0-5%, not 15%. Realistic save ≤ ~0.1-0.2ms. |
| `GasBlock` hot/cold field split | ~0.5-1ms / N=100k | distributed across readers | README:472-474 already evaluated this and concluded *"Diminishing returns; defer until profile data demands it."* C resurrects it with **no new profile data**. |

**Aggregate consequence:** the "~3ms / N=100k = 29ms → 26ms" headline is built on optimistic ceilings. A more honest range is ~1-1.5ms at N=100k, i.e. 29ms → ~27.5ms ≈ 5%. That is below the chrono-overhead noise floor the README itself acknowledges (~1.3ms across 13 phase boundaries — README:86-88).

## 5 — The EIP-170 argument is double-edged and kills C, not B

The plan's own rationale (per README:331-333 and `perf-summary.md`:34) is that EIP-170 caps production at N ≲ 8000 blocks, practically N=100-2000. At N=2000 the HEAD-vs-baseline speedup is ~1.20× (interpolating Cross-N table). The 41% headline applies only to algorithmic-DoS regime.

Apply this consistently:

- The same lens that says "don't chase Stack-SSA because production wins are sub-1%" (README:138-140) also says **C's ~3ms at N=100k scales to ~60μs at N=2000 production**, i.e. effectively zero on real contracts.
- If B's paired-ratio confirms a "real but small" gain (say 10-20% on production contracts vs `upstream/main`), then C is not worth a second PR by the project's own ROI rubric. The plan's "if production speedup is already >50% at small N, the ~3ms incremental at N=100k may not warrant the 2nd PR cost" implicitly acknowledges this but does not commit to a number.

**This is the missing acceptance criterion (§1).** Concretely, pre-commit to:

> *"If B's paired-ratio gain at the production stratum (median contract size ≤ 8KB) is < 25% relative to `upstream/main`, kill C entirely. If 25-50%, ship only opts (1) and (4) — the two with the most defensible delta math — as a single small PR. If > 50%, ship all four."*

(Numbers illustrative; the author can pick — but they must be **picked now**, not after B's data.)

## 6 — The C opts are not the highest-ROI candidates

Going down the HEAD per-phase column ranked by remaining time:

| Phase | HEAD time | In C list? | Why bigger leverage |
|---|---:|---|---|
| computeDomInfo | 4482 | no | Already heavily optimized; further wins need algorithmic change (SemiNCA, which README ruled out — but at 4.5ms it's still the largest single phase) |
| buildCFGEdges | 4512 | partially | -17.6% in this PR, smallest improvement margin; **C's "dedup skip" doesn't name what dedup is being skipped** |
| buildCSR | 3326 | yes (prefetch) | New cost introduced by this PR; nobody questioned whether 3.3ms is reasonable for the flatten work |
| meteringInit | 842 | no | **+0.3ms regression vs PR A baseline** (README:295-308 calls it cache-effect conjecture); a 30-line touch could plausibly recover this for cheap |
| buildLoopsUsingDominance | 1348 | no | -35.1% improvement, but still 1.35ms — room remains |

**Sleeper opts the plan ignores:**

- **buildCSR scrutiny.** Is 3.3ms for flatten work at N=100k actually optimal? The Off/Data twin-array layout is good for *readers* but the *build* phase still does two passes (one to count Off, one to fill Data). Could be a single-pass with `Off[i+1] = Off[i] + len(succs(i))` running prefix-sum, but only if edge counts are known up-front. Worth at least bench-profiling before assuming prefetch is the right lever.
- **meteringInit regression recovery.** The +57.9% (+309us) is small absolute but the README itself flags it as un-debugged. If the cache-effect conjecture is right, a `__builtin_prefetch(&Blocks[Id+8].Cost)` in the metering loop would be the cheapest 200us in this PR's footprint. This is missing from C.
- **PushValueMap zero-init.** README:476-478 calls it stress-test-only (9.6MB at N=100k synthetic, 0.2ms at EIP-170 production). It is correctly out of scope for production, but if the C goalpost is "drive the N=100k synthetic number further down," this is a 7ms+ leftover the C list ignores. The plan needs to clarify whether C optimizes for synthetic (then PushValueMap dominates) or production (then C is unnecessary).

The current C list reads like opportunistic additions, not a data-driven prioritization. Either re-derive from the HEAD profile, or rename C to "constant-factor cleanup" and drop the speedup target.

## 7 — Residual R2 soundness gap (not a blocker, but a flag)

R2 PASS verified the README **text** for M-2. Both R2 reviewers (Opus + Codex) checked that the README now names `effectivePredCount` as the soundness invariant. Neither constructed an arbitrary irreducible CFG and traced whether the multi-pred guard actually fires on every SCC-internal node.

The README claim (R2 §, README:397-403) is: *"every node in any SCC of size ≥ 2 has at least one in-cycle predecessor on top of any out-of-cycle entry, so its `effectivePredCount` is ≥ 2."*

The hidden assumption: *every SCC has an out-of-cycle entry*. For an SCC reachable from outside, the entry node satisfies this (cycle-internal pred from the back-edge + external pred from the entry). But an SCC-internal node with **only** SCC-internal predecessors satisfies it only if at least one of those preds is from the SCC, which is trivially true for size-≥2 SCCs — every node in a size-≥2 SCC has at least one in-cycle pred by definition of strong-connectivity.

OK, so the invariant holds. But the proof requires a one-line lemma the README doesn't state: *"node ∈ SCC of size ≥ 2 ⇒ |Preds ∩ SCC| ≥ 1."* This is trivially true, but R2 didn't verify it formally and the README doesn't write it down. If a future contributor adds a code path that masks SCC-internal preds (e.g. a back-edge filter for some unrelated reason), the guard could silently fail.

This is **not a blocker for shipping A.** It is a flag for whether C (or any future work that touches `lemma614Update`) is allowed to weaken the multi-pred guard. The README's existing "do not remove the multi-pred guard" warning (README:431-432) handles the immediate risk.

## 8 — Is "ship NOW before B" the right call?

**Yes**, but for a different reason than the plan states.

The plan's stated reason: *"avoid R2 PASS branch going stale."* This is real (review momentum decays) but is not the strongest argument.

The stronger reason: **A's perf claim is on a synthetic fixture and is honestly framed as such.** The README itself (README:331-345) calls 41% "algorithmic-DoS hygiene, not a production headline" and points to the 10k row (-19.8%) as production-relevant. There is no false promise to retract if B comes back smaller. B's job is **production validation**, not **headline correction**. Therefore the PR description for A should:

- Lead with the 10k row (production-relevant), not the 100k row.
- Note that real-corpus validation is in flight as PR B follow-up.
- Drop or footnote the 41% / 1.69× headline. Lead with the production-relevant 1.20-1.25× at N=2000-10k.

If the PR description is reframed this way, "ship A before B" is just standard parallelization. If the PR description keeps the 41% headline, B coming back with 10% will look like a retraction.

**Recommendation:** ship A, but in the same push, re-anchor the PR description on the production-relevant range.

## 9 — Hidden ambiguities summary

| Ambiguity | Current plan state | Required resolution |
|---|---|---|
| Test-add scope in A | "Add `UseLinearSPP=false` GTest" | Pick (i) drop or (ii) accept R3 |
| C acceptance criterion | "gated on B's data" | Pre-commit numeric thresholds for kill / partial / full C |
| C optimization target | unspecified | "Production EIP-170" (kills C) or "synthetic N=100k" (C is still wrong opts) |
| PR A description framing | unclear | Lead with production-relevant row, not 100k synthetic |
| C opt selection | ad-hoc | Re-derive from HEAD profile; replace at least 2 of the 4 |

## 10 — Verdict reasoning

The macro direction A→B→C is sound and well-motivated. None of the §1-§7 defects are reasons to **abandon** the direction. But shipping A as currently scoped will hit at least one round trip:

- Either the test-add forces R3 (planned-by-default, not flagged in the plan), or
- The PR description's 1.69× headline gets pushed back by a reviewer who knows EIP-170, or
- C kicks off with no acceptance criterion, B's data arrives, the criterion is invented post-hoc to fit, and the whole "gated on data" claim is a fiction.

These are all **fixable before** Phase 1 by:

1. Dropping the test-add from A (defer to a separate small PR or just accept R3 explicitly).
2. Re-anchoring A's PR description on the production-relevant N=10k row.
3. Pre-committing C's numeric trigger from B.
4. Re-deriving C's 4 opts from the HEAD profile, not from the original draft.

(1)-(3) are doc-only edits, all of them. (4) is a half-day of profile-reading.

Direction is correct. Plan scope is not yet shippable.

VERDICT: REFINE
