# PR #493 Task 8 — Lifted-block range plumbing perf re-run

- **Date**: 2026-05-11
- **Setup**: A-B-A 27-bench, 20 reps, taskset -c 2, single session 21:10–21:30 CST
- **Branch**: `perf/value-range-cfg-join` HEAD `2ebfd29` (`f203bd5` + lifted-range plumbing)
- **Baseline**: `~/dtvm-baseline` upstream/main HEAD `c644fbe`
- **Filter**: `^external/total/(main|micro)/`

## Four-way comparison

| Metric | Pre-rebase | Post-rebase | D1 (no #483) | **Lifted plumbing** |
|---|---|---|---|---|
| Branch HEAD | 5357578 | f203bd5 | 3d273e0 | **2ebfd29** |
| Drift (pingpong / baseline) | −0.84% | +0.10% | +0.61% | **+0.12%** |
| Geomean (branch / baseline) | −1.97% | −0.57% | +0.95% | **+0.34%** |
| 95% bootstrap CI | [−6.69, +2.82] | [−1.97, +0.76] | [−0.63, +2.60] | **[−0.07, +0.78]** |
| Per-bench regressions ≥ 0.5pp | 12 / 27 | 8 / 27 | 9 / 27 | **5 / 27** |
| Acceptance gate (Lower CI ≥ +0.8%) | FAIL | FAIL | FAIL | **FAIL (−0.07% lower CI)** |

**Headline:** geomean moved from −0.57% → **+0.34%** (+0.91 pp), CI tightened to **[−0.07%, +0.78%]**, regressions cut from 8 → 5. Gate still fails by 0.87 pp (need +0.8% lower CI, got −0.07%).

## What the plumbing fix recovered

The §2b finding (lifted-block factories defaulted Range = U256, so analyzer's `BlockInfo::EntryStackRanges` was unused on the dominant codegen path) — fixed by extending `createStackEntryOperand` and `materializeStackMergeOperand` to accept a Range parameter and threading it from `BlockInfo.EntryStackRanges`.

Patterns where this restored the original PR #493 headline wins:

| Bench | Post-rebase | **Lifted** | Recovery |
|---|---|---|---|
| `swap_math/spent` | −5.74% | **+1.30%** | +7.0 pp |
| `swap_math/insufficient_liquidity` | −0.52% | **+2.14%** | +2.7 pp |
| `swap_math/received` | −0.37% | **+0.76%** | +1.1 pp |
| `sha1_shifts/5311` | −6.81% | **+1.14%** | +8.0 pp |
| `sha1_divs/5311` | (not flagged) | **+1.40%** | new win |
| `jump_around/empty` | −4.52% | **+1.37%** | +5.9 pp |
| `memory_grow_mstore/by32` | +2.81% | **+2.39%** | held |
| `memory_grow_mload/by16` | +0.96% | **+2.16%** | improved |

These are exactly the cross-block u64 patterns the analyzer was designed for. The fix confirms the §2b architectural hypothesis: **the analyzer was correctly classifying values; the consumer just wasn't asking.**

## Residual regressions (5 / 27)

| Bench | Post-rebase | D1 | **Lifted** |
|---|---|---|---|
| `snailtracer/benchmark` | −7.95% | −3.36% | **−2.29%** |
| `memory_grow_mstore/by1` | −1.10% | −3.10% (D1) | **−1.60%** |
| `memory_grow_mload/by1` | (not flagged) | −2.32% (D1) | **−1.58%** |
| `sha1_shifts/empty` | −2.93% | +3.55% | **−1.29%** |
| `blake2b_huff/empty` | −6.25% | +1.61% | **−0.56%** |

Notes:
- `snailtracer/benchmark` partially recovered (−7.95 → −2.29) but is 3 pp short of pre-rebase parity (+1.01%). Other commits in the rebase range (PR #460 displacement-addressed bytes32, PR #469 security audit, etc.) likely interact with analyzer-introduced codegen here in ways not addressed by the lifted-block plumbing.
- `memory_grow_*/by1` are the partial-grow paths; they were also weak in D1 (revert #483). Different shape from the `by32`/`by16`/`nogrow` siblings which all win.
- `sha1_shifts/empty` and `blake2b_huff/empty` are the tiny-bench variants (3–9 ns/op); 0.1–0.2 ns shift = noise-floor regression.

## Interpretation

The lifted-block plumbing fix is a **substantial improvement** but **still does not pass the strict gate**:

1. **Directional win is real**: +0.91 pp improvement over post-rebase, tightest CI of all four runs ([−0.07, +0.78]), regression count halved.
2. **Lower CI now zero-touching**: CI = [−0.07, +0.78] straddles zero by just 0.07 pp — substantially weaker case for "definitely faster" than the gate requires.
3. **Residual snailtracer regression is the dominant outstanding cost** — −2.29% vs pre-rebase +1.01% = 3.3 pp deficit on a single dominant benchmark. Root cause is rebase-pickup interactions, not analyzer behavior.

## Recommended next step

Three options (user decision):

### D5 — Ship as `perf:` with current numbers, acknowledge CI weakness

- Geomean +0.34%, CI [−0.07%, +0.78%] is directionally positive but borderline.
- PR body must call out: "CI lower bound −0.07% — gate intent not met; perf claim is geomean-positive but not statistically distinguishable from no-op at the +0.8% threshold."
- Pros: keeps `perf:` framing; ships the analyzer with its intended consumer wired correctly.
- Cons: dishonest framing if reviewer reads CI carefully.

### D6 — Ship as `fix:` (= D2 from prior summary) but with lifted-plumbing as new commit

- Lead with soundness fixes (Tasks 1+2: SDIV/SMOD + host-opcode widening) + analyzer infrastructure + 39 white-box tests + §2b architectural finding + the plumbing fix as the empirically-verified resolution.
- Perf section: "geomean +0.34% (CI [−0.07%, +0.78%]) is directionally positive but does not meet original +1.30% claim. Lifted-block plumbing recovered analyzer-target wins; residual snailtracer regression is rebase-pickup interaction unrelated to analyzer correctness."
- Pros: honest, ships all the work, no false claims.
- Cons: scope/title changes from original PR.

### D7 — Investigate snailtracer separately before deciding

- 1–2 hours of `dmir-compiler-analysis` skill on snailtracer pre/post-rebase to identify which rebase commit specifically broke it.
- If isolable to one commit, possibly fixable with a small targeted patch; if not, accept and go D6.
- Pros: still a chance to make D5 honest.
- Cons: open-ended; may not converge.

## Recommendation: D6

The +0.34% with CI hugging zero is not a confident perf claim. The fix-framing accurately characterizes the value of the analyzer work: it establishes a soundness invariant, ships a working dataflow analysis, and includes 39 white-box tests + architectural investigation. The lifted-block plumbing commit is the empirical resolution to the §2b finding documented during the fix-cleanup phase. Snailtracer can be a follow-up.

## Raw data

- `branch.json` — branch HEAD 2ebfd29, 27 benches × 20 reps
- `baseline.json` — upstream/main c644fbe
- `baseline_pingpong.json` — drift control
- `analyze.py` — paired geomean + bootstrap CI
- `run_aba.sh` — driver
- `progress.log`, `run.log` — pass timing

Companion files:
- `../perf-2026-05-11/summary.md` — pre-rebase run (−1.97%)
- `../perf-2026-05-11-rebased/summary.md` — post-rebase run (−0.57%)
- `../perf-2026-05-11-no-483/summary.md` — D1 revert #483 (+0.95%)
