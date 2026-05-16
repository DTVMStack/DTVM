# Round-1 Spec Review — Opus, DTVM senior reviewer

Scope: `README.md` (spec) + `problem-statement.md` (v3) for PR A. Focus: gate
ambiguity, test-spec executability, project-rule cross-check.

## A. Internal cross-document inconsistencies (REVISE-grade)

1. **evmCacheTests count contradicts itself in Step 1.**
   `README.md:69` says verification = "9/9 evmCacheTests + multipass 223/223
   仍过" *before* Step 5 adds the 5 new tests. But `README.md:173`
   (Checklist) says "Step 1 — worktree + cherry-pick; **14/14**
   evmCacheTests pre-instrumentation pass". Pre-Step-5 there are only 9
   GTests (confirmed `src/tests/evm_cache_tests.cpp:49,63,80,91,116,132,
   150,169,195`). Either the Checklist line or Step 1 prose is wrong — pin
   to 9/9 at Step 1 and 14/14 from Step 5 onward.

2. **Strata-dimension count mismatch (4 vs 7).**
   `README.md:102` (Step 6 gate) says "distribution 表覆盖 **4 个 strata
   维度**". `README.md:110` (Step 7) lists 4 again: "code size / JD
   density / optimizer-runs / Solidity version". But `problem-statement.md:62-67`
   (A3) defines **7**: code-size decile, JD-density quartile, dyn-jump-ratio
   quartile, Solidity major version, optimizer (enabled×runs), viaIR,
   proxy/impl. Pick one source of truth and reconcile, or split into
   "primary strata = 4" vs "metadata fields collected = 7" — the spec
   isn't implementable until §A3 and §Step 6/7 agree.

3. **Risk 1 fallback cites the wrong artifact.**
   `README.md:139` says "if lower bound 5-15% → still merge if **distribution.md**
   shows `buildLoopsUsingDominance` is the bottleneck". But `problem-statement.md:74-76`
   defines `distribution.md` as a **corpus shape** report (code size / JD count /
   dyn-jump ratio / SCC count histograms) — phase wall-clock breakdown comes
   from the bench-harness CSV in Step 7 (`README.md:108-110`). Concrete
   replacement: "if Step 7 per-phase table shows median
   `buildLoopsUsingDominance` ≥ 30% of total cache-build wall-clock". Until
   the signal-cell is named, "still merge" is unfalsifiable.

## B. Verification-gate ambiguity

4. **`objdump` diff has two unrelated baselines.**
   `README.md:74` (Step 2 verification) says "OFF build 与现状字节级一致"
   (OFF vs pre-instrumentation `main`). `README.md:154-155` (Risk 3)
   says "ON vs OFF diff must only show chrono-related functions". These
   are *different* invariants and the spec asserts both without picking.
   Also no concrete pipeline — needs:
   `objdump -d --no-show-raw-insn build/lib/libdtvmapi.so | c++filt | diff -u`
   plus an allow-list grep (`std::chrono::|steady_clock|operator-`).
   Without that, "diff must only show chrono-related" is subjective.

5. **"No new warning" baseline undefined.**
   `README.md:117` (Step 9) says "no new warnings on PR-changed files".
   Against what baseline build? `upstream/main` rebuilt with the same
   flags? The currently-checked-out HEAD before cherry-pick? Spec needs:
   "vs `~/dtvm-baseline/build-baseline/` last full rebuild at
   `upstream/main` HEAD" or equivalent.

## C. Test-matrix executability (Step 5 / A5)

6. **5 GTest names have no concrete `Succs/Reachable` examples.**
   Existing tests (`evm_cache_tests.cpp:116-220`) hand-write the
   adjacency vector inline. The spec gives only narrative descriptors
   ("两个外部入口进同一环") — fine for `SelfLoop` but `IrreducibleSCC` has
   no canonical 2-entry shape. Each test needs the explicit `Succs`
   vector and `Reachable` mask in the spec, e.g. for `IrreducibleSCC`:
   `Succs = {{1,2},{2,3},{1,3},{}}; Reachable={1,1,1,1};` and the
   *expected* idom output. Otherwise the implementer reinvents the
   shape and Step 5's "14/14 pass" gate is vacuous.

7. **Fuzz invariant uses an undefined symbol.**
   `README.md:91` and `problem-statement.md:100` write
   `sum(Cost[path]) == sum(CostSPP[path]) + tracked_shifts` but
   `tracked_shifts` is not defined anywhere in the spec. Where does the
   harness read shifts from — `lemma614Update` writeback log? A new
   instrumentation channel? Risk 5 (`README.md:165-168`) admits the
   invariant may itself be wrong, but ships it as the gate.

## D. Corpus-pipeline executability (Step 6 / A3)

8. **Sourcify BigQuery details missing — script not writable from spec.**
   `problem-statement.md:48-58` lists three table names but omits:
   (a) dataset prefix (Sourcify's own export project? `bigquery-public-data.crypto_ethereum`?);
   (b) join keys — `(chain_id, address)`? `(chain_id, address, block_number)`?;
   (c) **pinned block range** — "Cancun activation 后 ~1 month"
   (`problem-statement.md:68`) is *not* a range. Cancun activated at
   mainnet block 19426587; pin both endpoints (e.g., 19426587 to
   ~19638000). The `~1 month` wording also nicks the "no macro durations"
   rule even though it's pin-context not plan-step (see point 13).

9. **"Stratified to 80-120" lacks an algorithm.**
   `problem-statement.md:60`, `README.md:99` specify N=80-120 with multi-dim
   strata, but no allocation rule: reservoir per stratum? Proportional?
   Max-per-stratum cap? With 7 strata each with ≥3 buckets, the product
   space is hundreds of cells — without an allocation rule the script is
   not implementable. Pick one: "proportional allocation with a 3-sample
   floor per non-empty cell, downsample uniformly to 120 if total
   exceeds".

## E. Bootstrap-CI methodology (A4)

10. **BCa requires three things the spec doesn't specify.**
    `problem-statement.md:80-92` says "paired-ratio per contract, 1000-resample
    BCa bootstrap 95% CI on median". Implementer needs:
    (a) **paired-comparison unit** — is the paired observation
    `(median_branch[i], median_main[i])` over 20 runs, or per-run
    `(t_branch[i,k], t_main[i,k])`? The spec wording is ambiguous.
    (b) **resample level** — bootstrap over **contracts** (recommended for
    "speedup on a corpus"), runs, or both?
    (c) **BCa acceleration `a`** — jackknife formula (Efron 1987) over the
    resample unit, but the unit must first be defined per (a)/(b).
    Without all three, "BCa 95% CI" is shorthand, not a spec.

## F. PR-scope hygiene

11. **`proxy/impl` strata field is pure PR-B fuel.**
    `problem-statement.md:67` lists "proxy vs implementation" as a
    strata dimension. Code-size / JD-density / SCC count drive dom-CHK
    triage (PR A) and the SCC-DAG triage (PR C). `proxy/impl` correlates
    with `delegatecall`/dynamic-jump patterns — useful for PR B
    jump-target precision triage, **not** for PR A. Either justify as
    dual-use in §Out of Scope or drop from PR A strata. Same caveat for
    `viaIR` (`problem-statement.md:66`).

## G. Project-rule cross-check

12. **Interpreter unittest count mismatch with run list.**
    `README.md:120` says "interpreter unittests 215/215" in Step 9
    gate. But `.claude/rules/dtvm-local-test.md:32` and the run list
    (`tests/evmone_unittests/EVMOneInterpreterUnitTestsRunList.txt`, 226
    lines) both indicate 226. Spec either has stale data or filters
    further; either way reconcile. Note: per
    `.claude/rules/dtvm-local-test.md:69-73`, `src/evm/` touches
    require **interpreter** unittests + statetest; Step 9 covers both,
    good — but the 215 number needs source.

13. **Macro-duration drift (one survivor).**
    `grep -niE "天|周|day|week|month|quick|fast|hour|minute"` over both
    docs hits `problem-statement.md:68` "Cancun activation 后 ~1 month"
    and `:159` "(P3, **multi-month**, 未来项目)". The latter is
    Out-of-Scope project-scale framing (consistent with motivation-2-opus
    closure of finding #7) — acceptable. The former is a plan-step pin
    that needs a concrete block number (see point 8). Fix `:68`, keep
    `:159`.

## H. Items NOT flagged (verified clean)

- Commit conventions: spec doesn't dictate commit titles, deferred to
  `.claude/rules/commit-conventions.md`. Fine.
- Step 9 test-suite selection: `src/evm/` + `src/tests/` + `tools/` all
  matched against `dtvm-local-test.md:69-73` "Test Selection by Touched
  Path" — multipass unittests + multipass statetest are the safe-default
  cross-module bucket, plus interpreter (per `src/evm/` row). Coverage is
  correct modulo point 12's number.
- iter-2 motivation findings (motivation-2-codex 1-6, motivation-2-opus
  a-c): items (a) "PR A fallback if < 15%" *is* attempted at README:138-141
  but lands on point 3 (wrong artifact). Item (b) N≥80 raise: closed
  (README:99 says 80-120). Item (c) bench-infra ROI: not addressed in
  spec but documentation-tier only.

## Verdict

Points 1, 2, 3, 6, 8, 9, 10 each independently block a clean
implementation hand-off (someone other than the author cannot write
the code or gate the merge without re-asking). 12 and 13 are
fact-fixes. 4, 5, 7, 11 are gate-tightening. Most are mechanical
spec edits, not redesign — but until 1-3 reconcile, the spec is
internally inconsistent.

REVISE
