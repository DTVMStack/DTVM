# PR #493 D1 verification — revert #483 + re-bench

- **Date**: 2026-05-11
- **Setup**: A-B-A 27-bench, 20 reps, taskset -c 2, session 20:24–20:44 CST
- **Branch**: `experimental/d1-revert-483` HEAD `3d273e0` (`f203bd5` with #483 reverted)
- **Baseline**: `~/dtvm-baseline` upstream/main HEAD `c644fbe`

## Three-way comparison

| Metric | Pre-rebase | Post-rebase | **D1 (no #483)** |
|---|---|---|---|
| Branch HEAD | 5357578 | f203bd5 | **3d273e0** |
| Drift (baseline_pingpong / baseline) | −0.84% | +0.10% | **+0.61%** |
| Geomean (branch / baseline) | −1.97% | −0.57% | **+0.95%** |
| 95% bootstrap CI | [−6.69, +2.82] | [−1.97, +0.76] | **[−0.63, +2.60]** |
| Per-bench regressions ≥ 0.5pp | 12 / 27 | 8 / 27 | **9 / 27** |
| Acceptance gate (Lower CI ≥ +0.8%) | FAIL | FAIL | **FAIL (−0.63% lower CI)** |

## Hypothesis: PARTIALLY CONFIRMED

Removing #483 shifts geomean by **+1.5pp** (−0.57 → +0.95). Confirms #483 interacts negatively with PR #493's u64 fast path on a class of patterns. But the gate still fails — D1 recovered some wins but lost others, and a residual regression class (swap_math, snailtracer, weierstrudel) is **independent** of #483.

## Per-bench delta: #483 effect

### Patterns where #483 hurts this PR (post-rebase loss → D1 recovery)

| Bench | Post-rebase | D1 |
|---|---|---|
| `sha1_shifts/5311` | −6.81% | **+3.60%** |
| `signextend/zero` | +3.26% | **+12.36%** |
| `sha1_divs/empty` | +0.11% | **+6.55%** |
| `signextend/one` | +2.79% | +6.46% |
| `structarray_alloc/nfts_rank` | −3.29% | **+2.53%** |
| `blake2b_huff/empty` | −6.25% | **+1.61%** |
| `jump_around/empty` | −4.52% | **+1.66%** |
| `sha1_shifts/empty` | −2.93% | **+3.55%** |

### Patterns where #483 actually helps (post-rebase win → D1 loss)

| Bench | Post-rebase | D1 |
|---|---|---|
| `loop_with_many_jumpdests/empty` | +5.51% | **−2.26%** |
| `memory_grow_mstore/nogrow` | +5.56% | **−3.80%** |
| `memory_grow_mload/nogrow` | +2.20% | **−2.32%** |

### Patterns where neither #483 nor revert helps (residual regressions)

| Bench | Post-rebase | D1 |
|---|---|---|
| `swap_math/spent` | −5.74% | −2.38% |
| `swap_math/received` | −0.37% | −5.37% |
| `snailtracer/benchmark` | −7.95% | −3.36% |
| `weierstrudel/1` | −0.77% | −1.94% |
| `weierstrudel/15` | −0.44% | −1.09% |
| `blake2b_huff/8415nulls` | −4.28% | −10.62% |

The last group is concerning: even without #483, these patterns regress vs upstream. Likely caused by other commits in the rebase range (PR #460 displacement-addressed bytes32, PR #469 security audit, PR #472 macro-fusion bounds check, etc.) interacting with analyzer-introduced codegen.

## What does this mean for the PR?

1. PR #493's original +1.30% geomean was measured against an earlier upstream/main. The interaction landscape has changed.
2. With current upstream, the cleanest configuration (D1, no #483) yields **+0.95% geomean** — directionally correct but fails the strict +0.8% lower-CI gate and has 9 per-bench regressions.
3. **#483 is not deployable to revert** — it's an upstream commit on main; this PR cannot ship while depending on its absence.
4. The soundness fixes (Tasks 1+2: SDIV/SMOD + host-opcode widening) and infrastructure (Task 3: 39 white-box tests; Task 5: ZEN_ASSERT + investigation.md) are **independent of the perf interaction** and have standalone value.

## Recommended next step

**Option D2 — Ship as fix-only**:

- Rebase branch onto current upstream/main (HEAD `f203bd5`) — already done
- Rewrite PR title: `perf(compiler): track Operand::ValueRange across CFG joins` → `fix(compiler): track Operand::ValueRange across CFG joins`
- Rewrite PR body to lead with soundness fixes + 39 white-box tests + §2b architectural finding
- Acknowledge in the perf section: "On current upstream/main this branch is geomean-positive (+0.95% paired bootstrap, CI includes 0) but does not meet the original +1.30% claim due to interactions with subsequent upstream optimizations (notably #483's inline arithmetic dispatch rework). The soundness invariants the analyzer establishes are still worth landing; perf will be revisited in a follow-up PR once upstream stabilizes."
- All 39 analyzer tests + 223/223 unittests + 2723/2723 statetest continue to pass

Alternative D3 (drop the whole PR) is more conservative but discards an investment of 9 commits + a working dataflow analyzer + a soundness fix. D4 (coordinate with #483 author) is open-ended.

## Raw data

- `branch.json` — d1 HEAD 3d273e0, 27 benches × 20 reps
- `baseline.json` — upstream/main c644fbe
- `baseline_pingpong.json` — drift control
- `analyze.py` — paired geomean + bootstrap CI
- `run_aba.sh` — driver
- `progress.log`, `run.log` — pass timing

Companion files:
- `../perf-2026-05-11/summary.md` — pre-rebase run
- `../perf-2026-05-11-rebased/summary.md` — post-rebase run
- `experimental/d1-revert-483` branch in this worktree — preserved per instruction, do NOT delete
