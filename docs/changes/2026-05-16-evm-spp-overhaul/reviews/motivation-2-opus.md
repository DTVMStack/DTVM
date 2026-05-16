--- BEGIN REVIEW ---

# Motivation Review iter-2 — DTVM EVM SPP Pipeline Overhaul (v2)

Persona: internal-consistency reviewer. Scope: verify v2 closes iter-1
gaps; do not re-discover iter-1 findings.

## Iter-1 finding-by-finding audit

**1. 1-PR → 3-PR split, PR A self-contained.** Closed.
Lines 17-31 define rollback boundaries per PR; A1-A6 (lines 34-72) keep
PR A to dom-CHK + P0 instrumentation + corpus harness + tests +
distribution.md. No P1/P2 code is smuggled in. The "Out of Scope" block
(lines 119-125) explicitly defers P1/P2 to future dev-cycles. PR A is
reviewable in isolation: its acceptance gate (A6) depends on PR A
artifacts only, not on PR B's library.

**2. 5% → ≥15% + bootstrap CI.** Closed.
Line 52 specifies "≥15% wall-clock improvement with 1000-resample
bootstrap 95% CI lower bound > 0". This matches iter-1 opus's
literal ask ("15% geomean with 95% CI not crossing zero"). The
prompt's hypothetical stricter framing ("lower bound > 15%") is
*tighter* than iter-1 actually required; v2 is consistent with what
was asked.

**3. 21× as bound, not motivation.** Closed.
Lines 13-15 explicit caveat ("algorithmic stress hygiene"... "not
production perf headline"). Line 72 makes PR A's acceptance the
real-corpus 15% number, not the synthetic 21×. The 21× is preserved
as a worst-case bound only.

**4. EVMAnalyzer layer inversion → extracted library.** Partial.
Lines 83-85 commit `src/common/evm_jump_resolver.h/.cpp` as PR B's
deliverable. PR A doesn't build it, but PR A's acceptance gate (A6)
doesn't depend on it either, so PR A is coherent. PR A's
`distribution.md` does report dyn-jump-ratio (line 49), which is the
data needed to triage PR B. **Missing**: an explicit "if corpus
dyn-jump-ratio < X then PR B is skipped" rule. v2 has the data
collection but not the decision rule — gap is documentation-tier,
not blocking PR A.

**5. AbstractValue lattice closure.** Not fully closed.
Line 86 says `static_assert 或 commit-message ritual 保证`. The `或`
makes it optional, and "commit-message ritual" is not auditable —
exactly the wishful-thinking pattern the prompt flagged.
Recommended stronger guard: a unit test in `src/tests/` that
enumerates every `AbstractValue` factory/operator at compile time
(reflection over a list maintained alongside the header) and fails
if the count diverges from the documented monotone-over-approx
invariant. This is PR B's deliverable, not PR A's — but PR B's spec
must lock this before PR B's own Phase 0.5.

**6. PR #446 lesson → corpus-level CostSPP[] diff.** Partial.
Line 87 says "any chunk的 cost 上升 = under-approx alarm". Direction
is ambiguous: SPP redistributes gas across edges, so a chunk's
CostSPP can rise legitimately when another chunk falls (gas
shifting). The asymmetric "up = alarm" rule is plausible (P1 only
moves dynamic→static, which can only narrow over-approx) but not
proven in v2. Acceptable as a PR B spec direction, but PR B must
prove the asymmetry before adopting the oracle.

**7. Macro duration estimates removed.** Closed.
`grep -niE "day|week|month|quick|fast|soon|hour|minute"` returns
one hit: line 123 `multi-month` in "Out of Scope" describing P3's
project scale, not a plan-step estimate. Out of scope by
construction; no violation.

## New concerns (fresh-read additions)

**(a) PR A fallback if dom-CHK < 15% on real corpus.** Line 72 says
"否则证明 dom-CHK 在 real workload 上 marginal, 需要更窄 scope".
Undefined: does PR A cancel? Ship with caveat? Re-target to
build-time only? The whole motivation for landing dom-CHK in PR A
rests on this number; v2 needs a concrete branch ("if < 15%: ship
dom-CHK as build-time-only optimization with corpus appendix
acknowledging marginal runtime impact, AND PR B is downgraded to
deferred").

**(b) Corpus N=30-50 statistical adequacy.** Line 44 specifies 30-50
contracts. Bootstrap CI on a median of N=30 has wide intervals —
this could itself undermine the "lower bound > 0" gate. Either
raise to N≥100, or add a power-analysis acceptance sub-criterion
("if CI half-width > target/2 on PR A's first run, expand corpus
before declaring fail"). Not blocking but worth flagging.

**(c) Bench infra ROI if PR B/C never land.** A3+A4 are ~500 LOC of
harness scripts whose primary consumers are PR B/C planning. v2's
framing (distribution.md as standalone deliverable, line 71) is
defensible — the corpus characterization is independently
valuable — but the cost-benefit is sensitive to whether B/C ever
ship. Worth a single sentence in v2 acknowledging this.

## Verdict discriminator

Iter-1's three substantive faults (5% threshold, 1-PR scope, 21×
headline) are all closed. Points 4-6 residuals are PR B's
forward-spec problems, not PR A's gating problems — PR B will get
its own Phase 0.5 review. New concerns (a)-(c) are
documentation-tier within PR A's spec, not motivation-level.

PR A's motivation is now coherent on its own terms: dom-CHK + P0 +
corpus harness justified by "we don't yet have the data to know
whether B/C are worth doing". That's a defensible 1-PR motivation.

Recommend the proposer add (a) as a spec-level branch and (b) as a
flag, but neither blocks proceeding to Phase 1 (motivation→spec).

VERDICT: PROCEED
--- END REVIEW ---
