--- BEGIN REVIEW ---

# Motivation Review — DTVM EVM SPP Pipeline Overhaul (P0+P1+P2)

Persona: internal-consistency reviewer.

## 1. Bundle coherence — P0 conditions P1+P2, but the spec hard-bundles them

The problem statement frames the bundle as "P0 drives P1+P2 priority"
(`problem-statement.md:38`) yet `problem-statement.md:12` says "把 dom-CHK
工作 + 3 个 follow-up phase 打包成 1 个 PR" — unconditionally. These two
statements contradict each other on the load-bearing question: **is the
PR's content fixed before P0 results, or do P0 results gate P1/P2?**

The risk is concrete. The most likely P0 outcome (per the cleanups red-team
at `redteam-cleanups.md:39-46`) is that on the 27-bench *real* corpus the
dominant residual phase is NOT what the synthetic demo suggested. The
plausible candidates are:

- `splitCriticalEdges` (`src/evm/evm_cache.cpp:225`) — quadratic-ish under
  high static fan-in;
- `buildCFGEdges` (`evm_cache.cpp:398`) plus the implicit-pred stamp loop;
- The dom pass *itself* re-traversed by `findBackEdgesUsingDominators`
  (called from `buildLoopsUsingDominance`, per `redteam-precision-plus-
  omitted.md:130-135`).

If any of these dominate, **P2 (Tarjan SCC DAG) is the wrong investment**
because its target (the 4 dom-loop passes) is no longer the bottleneck. The
red-team has already flagged this: "the residual dom time isn't the
algorithm; it's that IDom gets re-walked" (`redteam-precision-plus-
omitted.md:134-135`). The bundle therefore embeds a premature commitment.
A minimally coherent framing is "P0 first, then P1 ∨ P2 conditional on
P0", not "ship all three regardless".

Acknowledgement in the doc: none. This is a substantive omission.

## 2. Acceptance criterion is below the noise floor — unmeasurable as written

`problem-statement.md:22` requires "average wall-clock per-contract ≥ 5%
improvement on the 27-bench corpus." The noise floor on this very corpus
in this WSL2 host is documented at **±5-15% between consecutive runs**
(`docs/changes/2026-05-12-evm-dom-chk/README.md:257`), and PR #446's own
20-rep data shows CVs of 2.09%-21.93% per bench (`docs/changes/2026-05-
11-spp-cfg-implicit-dyn-pred/README.md:242`). A 5% threshold on a
quantity whose noise band spans 5-15% is **structurally unmeasurable** —
the criterion can be passed or failed by re-running the bench, not by
shipping the change.

This isn't a small phrasing fix. It is the load-bearing kill-switch in the
acceptance gate. Either:

- raise the threshold to ≥1.5× noise floor (≈ 15% geomean with 95% CI not
  crossing zero across ≥20 reps), or
- redirect the bench target to *cache-build wall-clock* (not runtime
  geomean), which is what the dom-CHK work actually moved 21× on
  synthetic shape — that quantity has a cleaner signal-to-noise per
  `docs/changes/2026-05-12-evm-dom-chk/README.md:271`.

The current 5% framing also conflates "average wall-clock" — runtime?
build? — without specifying. PR #446's runtime geomean is "within drift
band" (`docs/changes/2026-05-11-spp-cfg-implicit-dyn-pred/README.md:251-
255`); compounding by P1/P2 likely keeps it within drift.

## 3. Review-cost vs land-cost — 1500+ LOC in one PR is not realistic

Three changes bundled:

- Dom rewrite (already 2 commits on `perf/dom-chk-bytecode-cache`).
- P1 jump-target precision (~150-300 LOC per `redteam-precision-plus-
  omitted.md:64`).
- P2 Tarjan SCC DAG, which `redteam-scc-dag.md:92-95` itself flags as
  needing a **separate PR** ("removing `buildLoopsUsingDominance` and the
  `UseLinearSPP` branch is a *separate* PR from 'switch to SCC DAG'. They
  look like one rewrite but are two independent refactors; bundling
  complicates equivalence validation"). The user-prompt section of the
  current proposal silently overrides this red-team recommendation.

Combined this is on the order of 800-1500 LOC plus tests, touching the
correctness-critical SPP path that has just merged a non-trivial PR
(#446) requiring a round-2 revisit (`docs/changes/2026-05-11-spp-cfg-
implicit-dyn-pred/review-fixes-r2.md`). The "Why One PR Not Three"
section (`problem-statement.md:36-41`) gives four reasons — three of them
("组合效应", "等价性证据", "三阶段叠加 bench") are reviewer-facing
*justifications for the proposer*, not reviewer-facing benefits. The
fourth ("用户明确选了") is preference, not evidence. No estimate of
zoowii's actual capacity to review 3-axis change is offered.

## 4. Invariant P1 — over-approx-only stands on the lattice, not on the user's intuition

Tracing through DUP/SWAP/OR/AND/PUSH paths in
`src/compiler/evm_frontend/evm_analyzer.h`:

- `AbstractValue` has only two factories: `unknown()` (line 449) and
  `constFromPush()` (line 451). There is **no `meet`/`join`/`narrow`
  operator** on this lattice. A value can only enter `KnownConst=true`
  via a direct PUSH and propagate via DUP/SWAP (lines 742-751).
- DUP copies an existing slot reference (line 745); SWAP exchanges two
  slots (line 750). Both preserve `KnownConst` exactly.
- The `else` branch at lines 757-768 (which handles **OR, AND, XOR, ADD,
  CALLDATALOAD, MLOAD, etc.**) pops `PopCount` slots and pushes
  `PushCount` instances of `unknown()`. No arithmetic combinator
  produces a `KnownConst` output.
- `ensureAbstractDepth` (line 593) for cross-block underflow inserts
  `unknown()` (line 599). No path narrows dynamic → constant.

So the only way `ConstantJumpTargetPC` is set is: a PUSH provided a u256
that fits u64 *and* maps to a canonical JUMPDEST PC (`evm_analyzer.h:672-
674`). This is monotone-over-approximate: the prepass is intra-block, and
any dynamic input collapses the lattice to `unknown`. **Invariant P1 is
satisfiable** by Option A from `redteam-precision-plus-omitted.md:64`.

Edge case to test: cross-block PUSH-DUP propagation is not modelled
(stack-entry slots are `unknown` per line 599), so a target produced by
"PUSH at block X, JUMP at block Y" remains classified dynamic — correct
over-approximation, no precision loss vs status quo.

Verdict on this point: the invariant is *defensible*, but the proposal
must explicitly state the lattice as *not closed under arithmetic* — a
future contributor adding an `AbstractValue::orValue(A, B)` would
silently violate it. Audit hook proposed in `redteam-precision-plus-
omitted.md:96-100` (post-`buildCFGEdges` assert) is the right belt-and-
suspenders mechanism and must be in P1's deliverable.

## 5. PR #446 incident framing — accurate for the resolver, but the doc dilutes the warning

`problem-statement.md:34` cites `redteam-precision-plus-omitted.md` for
"PR #446's under-approx was in the reachability stitch over-seeding dead
JUMPDESTs". Verifying against `docs/changes/2026-05-11-spp-cfg-implicit-
dyn-pred/review-fixes-r2.md:96-125` and commit `f19c855`: the round-2 fix
**gates the stitch** to dyn-target JUMPDESTs only — the regression class
was "JUMPDESTs that were unreachable pre-Phase-7 are now in `Reachable[]`
and reshape dom/loop input." That is a structural over-/under-
approximation of the *reachable set*, not of *constant resolution*. The
framing in `problem-statement.md` is technically correct on the
classification.

But the *generalization* is unsafe. The PR #446 incident teaches a
broader lesson: **any move that broadens or narrows the input set to
downstream analyses can shift SPP decisions on entire classes of
contracts that the 27-bench corpus does not cover** (review-fixes-r2.md
lines 112-118 say this explicitly). P1's "move a target from dynamic to
static" is in that family — it narrows `JumpDestBlocks`' implicit-pred
stamp footprint. The PR #446 lesson generalizes: **the change must
include a class-specific fixture** (the doc *does* propose
"dyn-target-in-static-loop", per `redteam-cleanups.md:62-67`, which is
the right shape), and a corpus-level diff between pre-P1 and post-P1
`GasChunkCostSPP[]` on the existing 27-bench should be required as a
soundness oracle. Without that, the framing accurately attributes the
prior incident but underplays the precedent.

## Verdict

- (1) Bundle coherence: **fault**. Make P1/P2 conditional on P0 results.
- (2) 5% threshold: **fault**. Either widen to 15% with CI, or move the
  target to cache-build wall-clock.
- (3) PR scope: **fault**. Red-team #scc-dag explicitly recommends splitting.
- (4) Invariant P1: **sound**, conditional on the lattice property being
  spelled out and the audit assert being in scope.
- (5) PR #446 precedent: **partially fair**. Framing is correct, but the
  *generalization* (narrowing inputs to downstream analyses is risky)
  should be explicitly addressed with a corpus-level oracle.

Three of five points are substantive faults in the motivation. The
direction is not wrong; the framing forces a decision (3-phase PR, 5%
threshold, no conditionality) before the evidence (P0 results) exists.
That is the textbook definition of "REFINE before PROCEED."

VERDICT: REFINE
--- END REVIEW ---
