# Motivation red-team — outside-lens skeptic (Phase 0.5, iter 2)

## Sources checked

- Local iter-1 reviews:
  - `docs/changes/2026-05-17-evm-cache-build-fusion/reviews/motivation-1-codex.md`
  - `docs/changes/2026-05-17-evm-cache-build-fusion/reviews/motivation-1-opus.md`
- Local change evidence:
  - `docs/changes/2026-05-17-evm-cache-build-fusion/README.md`
  - `docs/changes/2026-05-17-evm-cache-build-fusion/perf-summary.md`
- External sources:
  - evmone README: https://github.com/ethereum/evmone
  - Ethereum Tests GeneralStateTests docs: https://ethereum-tests.readthedocs.io/en/v6.0.0-beta.1/test_types/state_tests.html
  - reth_bench docs: https://reth.rs/docs/reth_bench/index.html
  - Sourcify database docs: https://docs.sourcify.dev/docs/repository/sourcify-database/

## Iter-1 finding resolution

| Iter-1 finding | Resolution | Reasoning |
|---|---|---|
| 33x headline misleading | Mostly resolved, with one wording tweak | A' demotes 33x and front-loads N<=8000, matching the local README caveat that N=100k is synthetic DoS scale, not a production headline (`README.md:331-344`; `perf-summary.md:34`). "algorithmic-DoS hygiene + production-scale pilot" does telegraph the PR honestly. I would still avoid placing "33x" in the first visible PR paragraph; reviewers anchor on the largest number if it appears before the caveat. |
| B methodology too inward-looking | Resolved as a full B plan; partially useful for each layer | B' now names Sourcify as internal, evmone-bench as community, and reth-style payload execution as external. That fixes the credibility gap. Caveat: ethereum/tests are primarily correctness/state-transition fixtures; the docs say GeneralStateTests execute a single transaction and check resulting state/log/output, so timing them is useful as an end-to-end smoke but not a cache-build-specific perf oracle. evmone-bench is the better EVM-perf anchor because evmone documents `evmone-bench test/evm-benchmarks/benchmarks` and positions itself as a fast EVM implementation. reth_bench is a stronger payload-level story because its docs say it converts existing blocks into execution payload streams. |
| Premature A -> B -> C commitment | Mostly resolved for A; not enough to support strong production claims | Dropping the `UseLinearSPP=false` GTest from A preserves the R2 PASS state and directly resolves the Opus scope objection (`motivation-1-opus.md:24-40`). The B-lite pilot is the right pre-PR compromise, but "5-10 Sourcify contracts" is too thin if the PR body says "production-scale numbers" without labeling them pilot-only. Sourcify is a verified-contract repository and database of deployed contract/compilation pairs, but verified contracts are a selected subset, not a representative workload sample by default. |
| C kill thresholds | Partially resolved; one iter-1 kill condition is missing | The GO clauses cover my kill-1 production-size condition and kill-2 end-to-end invisibility condition almost exactly: median >=5% plus p95 >=0.2ms, and evmone-bench median >=1% plus p95 >=3%. But iter-1 kill-3 was first-touch p95 total warm-up reduction >=5%; C currently has no first-touch clause. That means C could still proceed if cache-build microbench improves while total first-touch remains invisible. Add first-touch p95 >=5% or explicitly delete first-touch as a decision axis. |

## New outside-lens issues

1. **B-lite selection bias needs to be named in the PR body.** Sourcify is useful because it exposes verified contract artifacts and bytecode/source metadata, but it is not an unbiased production workload sample. For a 5-10 contract pilot, require strata: small/medium/near-cap bytecode, proxy-heavy vs non-proxy, dynamic-JUMP-present vs absent if the counter is available. Otherwise the pilot can only say "sanity sample", not "production-scale result".

2. **"spread not concentrated at N>=50k" is not yet a rigorous threshold.** Define it before B runs. Example: GO only if at least two production bins, e.g. CodeSize <=4KB and 4-24KB, meet the production-size clause, or if a paired model with `log(CodeSize)` does not put the entire effect in the >50k synthetic bin. Without a rule, this clause is easy to rationalize after seeing the data.

3. **External-anchor wording should separate "benchmark credibility" from "diagnostic specificity."** evmone-bench and reth payloads are credible to outsiders, but they may dilute cache-build into runtime, host-call, storage, and precompile costs. That is fine for GO/KILL, but the plan should say a failure there kills C, not necessarily A. ethereum/tests timing has the same issue and is weaker as a perf benchmark because the official state-test docs frame it as state isolation and expected-output checking.

4. **Recent EVM-perf landscape does not rescue cache-build as the default next bet.** I verified current public anchors only enough to avoid overclaiming: evmone still frames its baseline as minimal JUMPDEST analysis and advanced as expensive bytecode analysis before execution; reth_bench benchmarks execution payload streams; recent public EVM-performance discussion is dominated by execution throughput and parallel execution, not cache-build CFG construction. So A' as DoS hygiene is credible, but C still needs data to beat runtime/JIT/host-call alternatives.

## Required refinements before PROCEED

- In A' PR body, label B-lite as "pilot, n=5-10, selection-biased sanity sample" unless it has explicit strata and raw per-contract rows.
- In C, add the missing first-touch kill: if total first-touch p95 reduction is <5%, kill cache-build micro-opts even if cache-build-only numbers pass.
- Define "spread not concentrated at N>=50k" as a computable rule before any B data is collected.
- Keep 33x out of title, summary bullets, and first paragraph. It can appear only after the N<=8000 caveat and synthetic label.

## Verdict

REFINE, not KILL. The refined plan addresses the core iter-1 objections well enough to keep A moving, but it still lets C proceed without the first-touch kill and without an operational spread definition. Because this is iter=2, that remaining REFINE should be escalated to the user rather than looped again.

VERDICT: REFINE
