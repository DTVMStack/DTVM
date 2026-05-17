# Round 2 Review — Opus (adversarial verify of c5db655)

VERDICT: PASS

## R1 items addressed

- **M-1 (R2 cites nonexistent GTest)**: PASS.
  `grep -rn "IrreducibleImproperRegion" docs/changes/2026-05-17-evm-cache-build-fusion/ src/` shows zero hits in the README and zero in `src/tests/`. README:153-158 now states "**none of them drives `UseLinearSPP=false`**" and "End-to-end soundness on irreducible CFGs is established by `evmone-statetest -k fork_Cancun` 2723/2723." R2's old fabricated test reference is gone (README:408-413 acknowledges the gap explicitly: "The irreducible fallback branch is **not** covered by a dedicated unit test — `OverlappingBackEdgesIDom` only drives `computeIDomForTesting`'s CHK output, not the `buildLoopsUsingDominance → false` path; adding such a test... is deferred").

- **M-2 (R2 leans on wrong invariant)**: PASS.
  README:383-417 (the entire R2 block) is rewritten. Concrete edits cited:
  - Line 385: "Conditional `InCycle` is a **performance optimisation, not the soundness mechanism**".
  - Lines 388-396: Counterexample of irreducible 2-entry cycle producing empty `Loops` with `UseLinearSPP=true` is now explicit.
  - Lines 397-403: "Soundness on such CFGs is preserved by a **different invariant** — `lemma614Update`'s multi-pred guard via `effectivePredCount` ... The `InCycle` mask is a **redundant fast-path filter**, not a safety net."
  - Lines 415-417: Future-contributor warning "do **not** remove the multi-pred guard in `lemma614Update` on the assumption that `InCycle` covers it" matches my R1 recommendation verbatim in intent.

- **M-3 (independently revertable overstated)**: PASS.
  README:200-206 now reads "**commits within a phase form a unit**" and "cannot be reverted in isolation without breaking the build — the per-commit greenness claim holds, the 'single-commit cherry-pick' claim does not." Both the Phase 5 trio and the Phase 2 0dd5bb9/689e5d5 CSR signature pair are named.

- **N-1 (phase table totals don't sum)**: PASS.
  README:67-83 PR-A baseline column now hand-sums to **48700** (10818+10350+7263+5477+3091+2531+2423+2076+1938+933+783+533+484) — exactly the `Σ instrumented = 48700` row. Lines 86-88 explain why 48700 > 47343 (chrono overhead at 13 phase boundaries). The earlier stitched 41412 figure is gone.

- **N-2 (second `IrreducibleImproperRegion` site)**: PASS. Covered by M-1 grep above.

- **N-3 (byte-identical claim not test-covered)**: PASS.
  README:162-168 downgraded to "behaviourally identical (`evmone-statetest --vm external_vm -k fork_Cancun` 2723/2723 pass)" plus "A literal byte-by-byte diff... was not run for this PR... if a future audit needs strict byte-identity proof, a fixture corpus + `memcmp` test would be a one-off addition."

- **N-4 (`22 pad uint16` terminology)**: PASS.
  `src/evm/evm_cache.cpp:231` now reads `22 pad[2]  (2 alignment bytes before Cost)`.

- **N-5 (chkFixpointRounds=2 workload-dependent)**: PASS.
  README:429-444 now says: "the set of workloads measured is the `evmCacheComplexityDemo` synthetic at N=10k/20k/50k/100k plus the 10 `EVMCacheDominator` GTests; this is also the **easy** case for CHK convergence (uniform alternating PUSH/JUMP/JUMPDEST topology... )". The "easy case" phrasing tracks my recommendation.

- **N-6 (meteringInit +110% dismissed without measurement)**: PASS.
  README:286-292 now reads "Most likely cache-effect attribution... This is a conjecture from the access pattern, not a measured cause — it could also be chrono-overhead artefact at the sub-millisecond scale."

## New issues introduced

None substantive. One residual observation, not a blocker:

- The Results per-phase HEAD column (README:269-284) sums to 20786 while the stated TOTAL median is 27945, a ~7.2 ms gap. The existing footnote at README:86-88 only explains the baseline-side (chrono overhead inflates the *Σ* above TOTAL), and inverts the sign of the HEAD-side gap. Most plausible cause: the per-phase column is 50-rep means while the TOTAL is the 100-rep interleaved median (per README:249-260's methodology stipulation), and small-phase work outside instrumented regions accumulates. Not flagged by R1 and not a falsifiable claim — flagging only for future polish if the doc is revised again.

## Verdict reasoning

All three MAJOR items (M-1/M-2/M-3) and all six MINOR items (N-1..N-6) are addressed at the specific file:line evidence I cited in R1. Source-side sanity checks pass: `build/evmCacheTests` 14/14 green; `assert(Edges.Succs.size() == Blocks.size() && Edges.Preds.size() == Blocks.size() && ...)` exists at `src/evm/evm_cache.cpp:1326-1328` immediately before `EVM_PROFILE_BEGIN(buildCSR)` at `src/evm/evm_cache.cpp:1329`; zero remaining `IrreducibleImproperRegion` references in README/src. M-2's rewrite reproduces the multi-pred-guard mechanism I traced in R1, including the irreducible 2-entry-cycle counterexample. The doc is now internally consistent on the correctness story, and the revertability claim is honest. Sibling Codex R2 also PASS independently. Clear to merge.
