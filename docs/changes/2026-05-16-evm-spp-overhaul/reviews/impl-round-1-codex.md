REVISE

## Spec Honesty

severity: MAJOR

evidence: `docs/changes/2026-05-16-evm-spp-overhaul/README.md:350-359` admits the gate moved from `improvement_lo >= 15 %` to `improvement_lo > 0`, and admits the observed CI lower edge is `-1.5 %`, so the strict production clause "does not hold pointwise". But `README.md:356-363` labels this "borderline" and `README.md:368-371` says "ship PR A"; the analyzer rerun says `| total | 79 | 0.9892 | 0.9670 | 1.0146 | -1.5% | +3.3% | FAIL |` and `Overall gate (total phase): FAIL` from command `tools/analyze_evm_cache_bench.py --baseline "$CLAUDE_JOB_DIR"/corpus/baseline.csv --treatment "$CLAUDE_JOB_DIR"/corpus/treatment.csv --n-boot 1000 --alpha 0.05 --gate-r-upper 1.0`.

recommendation: Call the production gate **FAIL**, then separately argue user-approved override / algorithmic gate PASS. Current prose mostly admits reality, but "borderline" softens a failed strict gate.

## Dominator Correctness

severity: NIT

evidence: CHK seeding uses `UINT32_MAX`, self-roots unreachable/no-reachable-pred nodes, RPO DFS, and skips unprocessed preds at `src/evm/evm_cache.cpp:653-681` and `src/evm/evm_cache.cpp:721-779`. This matches Cooper-Harvey-Kennedy Figure 3 mechanics: initialize doms undefined, root self, visit reverse postorder, choose first processed predecessor, and `intersect` walks the finger with smaller postorder upward (`dom14.pdf` lines 241-263, opened from `https://www.cs.tufts.edu/comp/150FP/archive/keith-cooper/dom14.pdf`). Enter/Exit DFS writes enter on push and exit after all children at `src/evm/evm_cache.cpp:823-849`; `dominates(A,B)` checks interval containment at `src/evm/evm_cache.cpp:639-647`. Back-edge and loop code use target-dominates-source order at `src/evm/evm_cache.cpp:864-868` and `src/evm/evm_cache.cpp:970-977`, matching old `bitsetTest(Dom[From], To)` at command `git show upstream/main:src/evm/evm_cache.cpp | nl -ba | sed -n '675,688p'` output lines 682-685.

recommendation: No correctness change requested from this review. Optional: guard `dominates(A,B)` bounds before `A == B` because current out-of-range equal args return true (`src/evm/evm_cache.cpp:639-645`).

## GTests

severity: MAJOR

evidence: All 5 requested tests pass (`build/evmCacheTests --gtest_filter=...` output: `[  PASSED  ] 5 tests.`), but they only exercise `computeIDomForTesting`: calls at `src/tests/evm_cache_tests.cpp:253-254`, `272-273`, `296-297`, `325-326`, `354-355`; helper returns only `computeDomInfo(...).IDom` at `src/evm/evm_cache.cpp:1463-1481`, and its header says "only the dominator pass is exercised" at `src/evm/evm_cache_for_testing.h:20-23`. The spec promised loop / SPP assertions: SelfLoop `InCycle`/loop count, CriticalEdge split `Cost=0`, DynTarget `UseLinearSPP` and `GasChunkCostSPP` (`README.md:129-138`), but `rg -n "buildLoopsUsingDominance|UseLinearSPP|Cost=0|InCycle" src/tests/evm_cache_tests.cpp` finds no implementation references beyond comments.

evidence: `IrreducibleSCC_TwoEntryLoop` is graph-theoretically multi-entry (`src/tests/evm_cache_tests.cpp:261-282`), but DTVM's reducibility fallback is not exercised: loop discovery only creates loops for edges where target dominates source (`src/evm/evm_cache.cpp:970-991`), and sanity/fallback only checks discovered loop nodes (`src/evm/evm_cache.cpp:1019-1040`). With the test's own expected `IDom[1]=0`, `IDom[2]=0` (`src/tests/evm_cache_tests.cpp:279-282`), neither cycle edge is a dominating back-edge.

recommendation: Add a test entry point or end-to-end bytecode fixture that observes `buildLoopsUsingDominance` / `UseLinearSPP` / split costs, or narrow the spec claim to IDom-only tests.

## Bench Harness

severity: MINOR

evidence: `tools/bench_evm_cache.sh:44-52` invokes `"$DEMO" --bytecode ...` inside the repetition loop, so each repetition is a fresh process. BCa implementation uses per-contract medians and paired ratios at `tools/analyze_evm_cache_bench.py:49-74`; bootstrap medians at `100-104`; `z0` from `sum(b < theta_hat)` at `106-113`; jackknife `a` at `115-122`; adjusted alpha quantiles at `124-133`. The docstring still says "Efron 1987" at `tools/analyze_evm_cache_bench.py:11-14`, while the change doc's accepted nit says the correct citation is Efron-Tibshirani 1993 §14.3 at `README.md:387-389`.

recommendation: Fix the analyzer docstring citation; optionally align `<` vs spec's `<=` wording for `z0`.

## Results Reproduction

severity: MAJOR

evidence: Algorithmic stress command output: `/home/abmcar/dtvm-baseline/build-baseline/evmCacheComplexityDemo 100000 -> synthetic,100000,1408186.402`; `build/evmCacheComplexityDemo 100000 -> synthetic,100000,47401.392`; ratio command output `ratio=29.71x treatment/baseline=0.0337`. This sanity-checks the claimed >=10x but does not reproduce table value 22.84x (`README.md:332-340`).

evidence: Corpus CSVs exist under `$CLAUDE_JOB_DIR/corpus`: command `find "$CLAUDE_JOB_DIR"/corpus -maxdepth 1 -type f` showed `baseline.csv`, `treatment.csv`, `report.json`, `manifest_top.json`; `wc -l` showed 1581 lines each, and label-count command output `baseline.csv rows 1580 total_labels 79` / `treatment.csv rows 1580 total_labels 79`. Analyzer rerun reproduced `r_median=0.9892`, `r_lo=0.9670`, `r_hi=1.0146`, `improvement_lo=-1.5%`, `improvement_hi=+3.3%`.

recommendation: Keep the production numbers, but mark production gate FAIL and algorithmic gate PASS.

## Commit Hygiene

severity: MAJOR

evidence: `commitlint.config.js:15-30` allows types `feat/fix/docs/style/refactor/perf/test/build/ci/chore`; `commitlint.config.js:31-47` allows scopes `core/runtime/compiler/examples/docs/tools/deps/ci/test/other/""`. Command `git log upstream/main..HEAD --pretty=format:'%h %s %an %ae'` produced 8 subjects. Local parser check output: `FAIL docs(changes)... bad-scope=changes`; `FAIL docs(evm)... bad-scope=evm`; `FAIL test(evm)... bad-scope=evm`; `FAIL tools(evm)... bad-type=tools bad-scope=evm`; `FAIL test(evm)... bad-scope=evm`; three `perf(core)` commits PASS.

evidence: [UNVERIFIED] `--no-verify` is not recoverable from commit objects/reflog. Reflog command `git reflog --date=iso --pretty=... -n 80` showed `commit:` entries and one `reset: moving to HEAD`, but no `commit (amend):`; author/committer dates differ for `48fada6` and `1be3f39` in `git log ... --date=iso-strict`, consistent with cherry-pick/date preservation but not proof of no amend.

recommendation: Reword/squash to commitlint-compliant subjects; do not claim `--no-verify` absence.
