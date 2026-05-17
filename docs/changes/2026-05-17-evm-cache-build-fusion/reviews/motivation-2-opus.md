# Motivation red-team — internal-consistency lens (Phase 0.5, iter 2)

**Plan reviewed:** Refined A' → B' → C-rubric.
**Mode:** Did iter=1's REFINE findings get resolved? Internal-consistency check
only; not relitigating the perf data or correctness story (R2 PASS state
holds for the shipped artifact).

## Headline

Three of four iter=1 findings are resolved by the refinement. The fourth
(M-2's numeric trigger) is resolved on three of four sub-thresholds; one
("spread not concentrated at N≥50k") is still rhetorical and must be
turned into a measurable number before B' runs. Two new small leaks
appeared from the refinement itself — the proposed `evm_cache.md` doc
update is actually a *create* (the file does not exist today, so its
content scope is unconstrained); and the ship-pre "B-lite 30 min, 5-10
Sourcify contracts" is sample-floor-violating if its numbers land in the
PR body. Both are one-line fixes at PR-body-write time, not verdict
blockers.

Detailed findings below; verdict at the bottom.

## 1 — M-1 (R2 PASS preservation): RESOLVED with one content-scope caveat

A' drops the `UseLinearSPP=false` GTest from this PR and defers it to a
follow-up PR + R3 round. This cleanly preserves the R2 PASS state for
the test scope.

**Caveat — the `docs/modules/evm_cache.md` update is a new-file create,
not an update.** I checked
`docs/modules/evm/` in this worktree (`spec.md`, `data-model.md`) and
across `docs/modules/` (`grep -l -r "evm_cache\|UseLinearSPP\|effectivePredCount"
docs/modules/`): no `evm_cache.md` exists. The refined plan calls this
an "update" but it's a creation. Net effect: there is no prior R2-reviewed
text to preserve, but also nothing to bound the new file's claims against.

Resolution recipe — already covered by treating the new spec as
**scoped-to-shipped-state**: the file describes what ships (CSR /
EdgeTables / 32B layout + multi-pred guard via `effectivePredCount`) using
verbatim text from README §R2. No new soundness claims. If the spec adds
invariants that R2 reviewers did not see, that re-opens R2 even though
the code didn't change. This is a content-scope rule on the PR-body-write
step, not a structural defect.

**Status:** RESOLVED (with the above content-scope rule).

## 2 — M-2 (C's numeric trigger): MOSTLY RESOLVED — one sub-threshold still rhetorical

The GO / KILL / Partial structure is sound. Three of the four numbers are
measurable with B's three-layer methodology:

| Sub-threshold | Measurable? | Where it lands in B' |
|---|---|---|
| (i) N≲8000 paired median ≥5% AND p95 ≥0.2ms | yes | L1 Sourcify BCa harness |
| (ii) end-to-end evmone-bench median ≥1% AND p95 ≥3% | yes | L2 evmone-bench + statetest timing |
| (iii) "speedup spread not concentrated at N≥50k" | **NO — definition gap** | unclear which layer |
| Partial = (i) holds, (ii)(iii) borderline | depends on (iii) | derived |

(iii) is the leak. "Spread not concentrated" has no operational
definition — concentration ratios, top-decile share, regression slope,
none specified. This is the same defect iter=1 M-2 identified at the
plan level, now relocated into sub-threshold (iii).

**Required fix (one line at C-rubric write time):**
Replace (iii) with a number: e.g.,
*"speedup at N=2000 stratum is ≥ 50% of speedup at N=100k stratum
(paired median ratio)"*. The 50% figure is illustrative; the author
picks the number, but it must be a **number** — not "concentration."
Without this fix, B's data arrives and (iii) gets invented post-hoc to
fit, exactly the failure mode iter=1 §1 warned about.

**Status:** RESOLVED on (i), (ii); REFINE on (iii) — pre-commit a measurable
form of "spread."

## 3 — M-3 (phase-cost vs fold-delta): RESOLVED via threshold structure

iter=1 §4 argued C's micro-opt estimates were *phase-cost* totals (~3ms
aggregate at N=100k from the four items) but realistic *fold-delta* is
~1-1.5ms aggregate, below the ~1.3ms chrono noise floor at N=100k. Scaled
to EIP-170 production (N≲8000), this collapses to tens of microseconds.

The refined plan does not fix the C estimates directly — it makes the
estimates **irrelevant** by gating C on observed paired-ratio data from
B', not on the pre-data ROI math. This is the correct resolution:
threshold (i) requires ≥5% at N≲8000 AND ≥0.2ms p95. A ~1-1.5ms aggregate
at N=100k that scales sub-linearly to N≲8000 will not clear that bar.
The threshold structurally self-kills C if iter=1 §4's pessimistic math
holds, without anyone having to re-litigate the estimate.

This is convergence, not can-kicking — the threshold is the test, and the
test catches the failure mode iter=1 named.

**Status:** RESOLVED (threshold (i) is the operational form of iter=1 §4's
ROI rubric).

## 4 — EIP-170 self-kill: RESOLVED — threshold (i) is exactly the kill mechanism

iter=1 §5 argued that the same lens that says "ship A despite synthetic
ratios because production is N=100-2000" also says C's ~3ms / N=100k
scales to ~60μs / N=2000 — effectively zero. Threshold (i) demands ≥5%
**at N≲8000**. The four C micro-opts (`computeReachable` fold,
`buildCFGEdges` dedup skip, `buildCSR` prefetch, `GasBlock` hot/cold)
each save fractions of a millisecond at N=100k; their N≲8000 aggregate
is bounded by EIP-170 scaling (likely <100μs of a ~5ms total ⇒ ~2%).
Not 5%.

So threshold (i) achieves what iter=1 §5 asked for: C is dead-on-arrival
**if iter=1 §4's pessimistic estimate is correct**. If iter=1 §4 was
wrong and the fold-deltas exceed 5% at N≲8000 paired-ratio, then C is
real and worth doing. Either way the decision is data-driven. This is the
correct shape.

**Status:** RESOLVED.

## 5 — New issue: B-lite "30 min, 5-10 Sourcify contracts pre-ship" is sample-floor-violating IF its numbers go in the PR body

The refinement adds a ship-pre B-lite step: 5-10 Sourcify verified
contracts, paired HEAD vs upstream/main, ~30 min, to populate "PR body's
production-scale numbers."

This is internally inconsistent with B' L1's methodology requirement.
Paired-ratio BCa cluster-bootstrap is designed precisely because n=5-10
contracts cannot deliver a defensible confidence interval — that's why
B' L1 exists as a separate post-merge phase. If B-lite's numbers go in
the PR body as "production-scale pilot result," they will read as
precision the methodology doesn't support. Two options:

- **(a) Reframe B-lite as directional sanity check, not headline data.**
  PR body cites it as *"smoke-tested on 5-10 verified contracts; full
  paired-ratio BCa harness is post-merge B' L1 follow-up"*. No numeric
  ratio claim from B-lite enters the PR body.
- **(b) Drop B-lite pre-ship.** PR body leads with algorithmic-DoS
  framing + N≲8000 caveat front-loaded only. Production-scale pilot
  data deferred entirely to B' L1.

(a) is acceptable; (b) is cleaner. **The current refinement implicitly
assumes B-lite produces headline numbers** ("populate PR body's
production-scale numbers") — that's the failure mode. Pick (a) or (b)
explicitly at PR-body-write time.

**Status:** New must-fix at PR-body-write time. One-line decision, not
a structural blocker.

## 6 — New issue (minor): "why ship at all if production benefit is unknown"

The PR body reframe (33× demoted, N≲8000 caveat front-loaded) raises a
fair reviewer question: *if production benefit is unknown, why ship?*
The refined plan has the answer but doesn't make it the PR body's lead:

- algorithmic-DoS hygiene is a real win (`computeInCycle` -99.5% on
  irreducible-shaped synthetics matters for DoS-attack-shaped bytecode
  even if rare);
- code-locality refactor (CSR, EdgeTables, 32B GasBlock) is its own
  reward even if perf gain is small — diff is +312/-188 lines and
  removes the embedded-vector heap chase pattern;
- linear-regime scaling characterisation (2× N gives 2× time post-A,
  cleanly extrapolatable to any production point) is a regression
  guarantee for future contributors.

If the PR body leads with these three justifications + statetest
2723/2723 + footnoted 33× synthetic, "why ship" is answered. If it
leads with the synthetic ratio and bolts the justifications on, a
reviewer will push back.

**Status:** Editorial guidance for PR body, not a planning defect.

## 7 — Cross-reviewer convergence (anchoring)

iter=1 Codex (motivation-1-codex.md:96-101) listed five required
refinements; the refined plan resolves all five:

| Codex iter=1 ask | A'/B'/C resolution | OK? |
|---|---|---|
| Add `UseLinearSPP=false` test before push | Dropped from this PR + deferred to follow-up + R3 | yes (different but equally consistent path) |
| Update module doc + PR body framing as internal cache-build | `evm_cache.md` create + reframe | yes (with §1 content-scope rule) |
| Small real-corpus pilot pre-PR | B-lite ship-pre | conditional (see §5) |
| Demote 33× to algorithmic-DoS hygiene | done in reframe | yes |
| Gate C on B with measurable thresholds | GO/KILL/Partial | yes (with §2 sub-threshold (iii) fix) |

Codex's six kill conditions (motivation-1-codex.md:75-87) are subsumed
by C-rubric's GO/KILL structure modulo §2's spread-concentration gap.

## 8 — Verdict reasoning

iter=1 was REFINE on four structural defects. Refined plan resolves
M-1 (test drop), M-3 (threshold replaces estimate), M-4/EIP-170
(threshold (i) is the self-kill mechanism), and the bulk of M-2
(thresholds (i) (ii) are measurable). M-2 (iii) is a one-line definition
fix at C-rubric write time.

Two refinement-introduced leaks (§1 caveat on `evm_cache.md`'s
new-file-not-update status, §5 on B-lite's sample-floor risk in the PR
body) are content-scope / editorial fixes at PR-body-write time, not
structural defects.

No new structural critiques are introduced — iter=2's lens is "did
refinement resolve iter=1's findings," and the answer is yes modulo two
one-line edits.

REFINE → PROCEED conditional on three small write-time fixes:

1. C-rubric (iii) replaced with a number (e.g., "N=2000 paired median
   speedup ≥ 50% of N=100k paired median speedup").
2. New `evm_cache.md` scoped to shipped state + R2-verbatim invariants;
   no new soundness claims.
3. Pick (a) or (b) for B-lite (sanity check vs drop), do not put
   B-lite numeric ratios in the PR body as if they were B' L1 data.

These are tracked-by-author fixes during PR-body / docs write, not
plan-revision iterations.

VERDICT: PROCEED
