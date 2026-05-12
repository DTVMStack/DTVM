# PR #493 fix-cleanup — Task 7 Post-Rebase Perf Re-run

- **Date**: 2026-05-11
- **Setup**: A-B-A 27-bench, 20 reps, taskset -c 2, single session 19:55–20:15 CST
- **Branch**: `perf/value-range-cfg-join` HEAD `f203bd5` (rebased onto `upstream/main`)
- **Baseline**: `~/dtvm-baseline` upstream/main HEAD `c644fbe`
- **Filter**: `^external/total/(main|micro)/`

## Headline numbers vs pre-rebase run (perf-2026-05-11/summary.md)

| Metric | Pre-rebase (HEAD 5357578) | Post-rebase (HEAD f203bd5) | Delta |
|---|---|---|---|
| Drift (baseline_pingpong / baseline) | −0.84% | **+0.10%** | cleaner noise floor |
| Geomean (branch / baseline) | −1.97% | **−0.57%** | improved 1.4pp |
| 95% bootstrap CI | [−6.69%, +2.82%] | **[−1.97%, +0.76%]** | tighter |
| Per-bench regressions (≥ 0.5pp) | 12 / 27 | **8 / 27** | 4 fewer |

**Acceptance gate (spec §5 step 6): STILL FAIL.** Lower CI = −1.97%, need ≥ +0.8%.

## What rebase fixed

The `memory_grow_*` family — 8 benches that regressed −10 to −21% pre-rebase — now **win** +1 to +5%:

| Bench | Pre-rebase | Post-rebase |
|---|---|---|
| `memory_grow_mstore/nogrow` | −20.50% | **+5.56%** |
| `memory_grow_mload/by32` | −10.71% | **+4.40%** |
| `memory_grow_mload/by1` | −12.34% | **+3.18%** |
| `memory_grow_mstore/by32` | −18.88% | **+2.81%** |
| `memory_grow_mload/nogrow` | −15.70% | **+2.20%** |
| `memory_grow_mstore/by16` | −19.07% | **+1.89%** |
| `memory_grow_mload/by16` | −12.09% | **+0.96%** |
| `memory_grow_mstore/by1` | −21.13% | −1.10% |

Confirms Option A hypothesis: pre-rebase branch lagged on upstream's memory-path optimizations.

## What rebase BROKE

The PR's original headline wins on **arithmetic-heavy / analyzer-target patterns** collapsed:

| Bench | Pre-rebase | Post-rebase | Loss |
|---|---|---|---|
| `swap_math/insufficient_liquidity` | +9.40% | **−0.52%** | −10pp |
| `swap_math/spent` | +7.60% | **−5.74%** | −13pp |
| `swap_math/received` | +6.27% | −0.37% | −7pp |
| `sha1_shifts/5311` | +1.48% | **−6.81%** | −8pp |
| `sha1_shifts/empty` | +5.00% | −2.93% | −8pp |
| `blake2b_huff/empty` | +0.65% | **−6.25%** | −7pp |
| `blake2b_huff/8415nulls` | −0.40% | −4.28% | −4pp |
| `snailtracer/benchmark` | +1.01% | **−7.95%** | −9pp |
| `jump_around/empty` | +5.11% | −4.52% | −10pp |

These are exactly the patterns the value-range analyzer + u64 fast path was supposed to accelerate.

## Root-cause hypothesis: PR #483 dispatch rework conflicts with this PR's fast path

The rebase picked up commits between merge-base and upstream/main:
- `2950664 perf(evm): delegate inline arithmetic/stack opcodes to doExecute handlers (#483)`
- `1d29b78 fix(compiler): improve displacement-addressed bytes32 conversion (#460)`
- 7 others (security audit fixes, EIP-3607, etc.)

**PR #483** reworked inline ADD/SUB/MUL/DIV dispatch to delegate to `doExecute` handlers — likely changing the code path that this PR #493's u64 fast paths sit on top of. After #483, either:

- (a) The fast path's admission point in the new dispatch shape no longer fires for the same operand patterns (the analyzer's classification is correct but the consumer never asks).
- (b) The fast path DOES fire but the new dispatch overhead eats into the gain.
- (c) Some other interaction: the new dispatch introduces a call/dispatch site that breaks register allocation or scheduling in a way that wasn't a problem in the pre-#483 codegen.

Not investigated empirically yet (would require JIT logging + assembly diff between branch pre/post-rebase on, e.g., `swap_math/spent`).

## Implication

The PR #493 design predates #483. Its premise (track ValueRange across CFG joins → activate u64 fast paths on cross-block values) assumed the old inline-dispatch path. With #483 landed, that premise needs re-validation. Tasks 1+2+5 (soundness fixes added in this fix-cleanup work) are independent of this interaction — they fix real soundness gaps regardless.

## Three paths forward (user decision)

### D1 — Verify #483 interaction hypothesis

`git revert 2950664 (#483)` in a scratch branch off `f203bd5`, rebuild, re-run A-B-A. If wins return → confirms #483 is the cause. Then we can either (a) propose an upstream-coordination patch to make #483 + #493 compatible, or (b) defer #493 until #483's design stabilizes.

**Estimated effort**: 30 min (revert + rebuild + 20-min A-B-A).

### D2 — Ship as fix-only, drop perf framing

Keep the rebase. PR title: `perf(...)` → `fix(...)`. Body: lead with the 2 soundness fixes (Tasks 1+2), the white-box test suite (Task 3), the §2b architectural finding, the cleanup (Task 5). Acknowledge perf claim doesn't hold against current upstream and defer that investigation to a separate PR.

**Estimated effort**: 15 min (PR body rewrite + push).

### D3 — Drop the analyzer entirely

Revert the original PR #493 analyzer commits (75ed13c, 981170c, 9f7b073, 1663cb4), keep only Tasks 1+2+5 if those have value standalone (they don't — without the analyzer they're no-ops on the dataflow side). So this collapses to: revert the entire PR #493 fix-cleanup chain. Effectively close PR #493 without merging.

**Estimated effort**: 10 min (force-push or close).

## Recommendation

**D1 first** — cheap to verify, and tells us whether the analyzer concept is still viable post-#483. If D1 confirms #483 is the cause, then user has more options (coordinate with #483 author, or pause #493 until upstream settles). If D1 disconfirms (revert doesn't recover wins), then the analyzer itself has lost value-vs-upstream and D2 or D3 makes sense.

## Raw data

- `branch.json` — branch HEAD f203bd5, 27 benches × 20 reps
- `baseline.json` — upstream/main c644fbe
- `baseline_pingpong.json` — drift control
- `analyze.py` — paired geomean + bootstrap CI
- `run_aba.sh` — driver
- `progress.log`, `run.log` — pass timing
