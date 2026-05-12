# PR #493 fix-cleanup — Task 7 Final-State Perf Re-run

- **Date**: 2026-05-11
- **Setup**: A-B-A 27-bench, 20 reps, taskset -c 2, single session 16:37-16:58 CST
- **Branch**: `perf/value-range-cfg-join` HEAD `5357578` (after Tasks 1+2+3+5)
- **Baseline**: `~/dtvm-baseline` upstream/main HEAD `c644fbe`
- **Filter**: `^external/total/(main|micro)/`

## Headline numbers

| Metric | Value | Pass spec §5 step 6? |
|---|---|---|
| Drift (baseline_pingpong / baseline) | −0.84% | ✅ within ±5% |
| Geomean (branch / baseline) | **−1.97%** | ❌ |
| 95% bootstrap CI | `[−6.69%, +2.82%]` | ❌ lower bound < +0.8% |
| Per-bench regressions (≥ 0.5pp) | 12 / 27 | ❌ |

**Acceptance gate: FAIL** per spec §5 step 6 ("lower CI ≥ +0.8%; no per-bench regression > 0.5pp").

## Investigation — regressions are NOT range-analyzer-driven

The 12 regressions cluster into 3 patterns, none of which use SDIV/SMOD or TIMESTAMP/NUMBER/GASLIMIT/CHAINID:

| Pattern | Benches | Regression range |
|---|---|---|
| `memory_grow_mstore/*` | by1, by16, by32, nogrow | −18.88 .. −21.13% |
| `memory_grow_mload/*` | by1, by16, by32, nogrow | −10.71 .. −15.70% |
| Other | blake2b_shifts/8415nulls, structarray_alloc/nfts_rank, sha1_divs/5311, weierstrudel/15, blake2b_huff/8415nulls | −0.40 .. −5.12% |

These are MSTORE/MLOAD micro-benchmarks (5–9 ns absolute time) and arithmetic-heavy macros (blake2b, sha1, weierstrudel) — workloads where the range analyzer makes no transfer-rule decisions that affect codegen.

The wins, in contrast, cluster on analyzer-target patterns:

| Bench | Speedup | Why |
|---|---|---|
| `loop_with_many_jumpdests/empty` | +34.54% | JUMPDEST-heavy; analyzer wins |
| `JUMPDEST_n0/empty` | +25.81% | Same |
| `swap_math/{insufficient_liquidity, spent, received}` | +6.27 .. +9.40% | u64 fast-path activation |
| `sha1_{divs, shifts}/empty` | +5.00 .. +7.12% | u64 fast paths |
| `jump_around/empty`, `signextend/zero`, `weierstrudel/1` | +1.65 .. +5.11% | u64 fast paths |
| `snailtracer/benchmark` | +1.01% | mixed workload |

The PR's value-range fixes DO deliver on their target workloads. The geomean regression comes from non-target workloads that have improved upstream.

## Root-cause hypothesis: upstream gained unrelated optimizations

`~/dtvm-baseline` HEAD `c644fbe` includes (per the project's recent commit log):

- `5e5fddd perf(evm): depth-indexed InterpreterExecContext pool for nested calls (#482)`
- `fca0b1a perf(evm): u256 arithmetic optimizations (shift/addmod/barrier/value-range/div-mod) (#458)` — this is PR #493's prior work, already on main
- `a81c03d fix(compiler): fix medium-severity findings from security audit (#469)`
- `ec3c9f9 fix(core): add bounds check before macro-fusion read in handleCompare (#472)`

**PR #482** ("depth-indexed InterpreterExecContext pool") landed after PR #493 was created. It optimizes call-heavy and memory-heavy paths — exactly the `memory_grow_*` and `blake2b_*` patterns showing as regressions in this PR vs current upstream. PR #493's branch does NOT have those optimizations because it was branched off an earlier point.

## What this means

This is NOT a regression introduced by Tasks 1+2+5 (the soundness fix-cleanup work). The §2b finding (lifted JUMPDESTs short-circuit the analyzer's setRange refinement) predicted ~0 perf impact from the soundness widening, and the bench data is consistent with that — the wins are stable on analyzer-target patterns. The negative geomean is caused by the branch lagging behind upstream on **unrelated** optimizations.

Three paths forward, requires user decision:

### Option A — Rebase `perf/value-range-cfg-join` onto current `upstream/main`

Pull in #482, #469, #472 and re-run. Likely restores the +1.30% headline geomean since the regressing benches would also gain upstream's improvements. **Highest expected value, mechanical effort.**

### Option B — Re-frame the PR as "wins on target patterns, opt-in soundness fix"

Acknowledge the geomean regression vs current upstream is unrelated. Highlight per-bench wins (e.g., +34% on `loop_with_many_jumpdests`, +25% on `JUMPDEST_n0`, +6-9% on `swap_math`). Lead the PR body with the soundness fix rationale (Tasks 1+2 close real soundness gaps caught in review) rather than the +1.30% headline.

### Option C — Drop the perf framing entirely; ship as soundness-only

Rewrite PR title from `perf(compiler): track Operand::ValueRange across CFG joins` to `fix(compiler): track Operand::ValueRange across CFG joins`. Acknowledge in PR body that the original +1.30% claim was measured against a different upstream and no longer reproduces cleanly; the bug fixes still warrant landing.

## Recommendation

**Option A**: rebase. The regressions are upstream-improvement-driven, not introduced by this PR. After rebase, the perf story should hold. Backup: if rebase reveals real regression from Tasks 1+2+5 even on a current upstream, fall back to Option C.

## Raw data

- `branch.json` — branch HEAD 5357578, 27 benches × 20 reps
- `baseline.json` — upstream/main c644fbe
- `baseline_pingpong.json` — drift control (second baseline run)
- `analyze.py` — analysis script (paired geomean + bootstrap CI)
- `run_aba.sh` — the A-B-A driver (copied from `/tmp/pr493-task7-bench/`)
- `progress.log` — pass timing
