#!/usr/bin/env python3
"""
A-B-A perf analysis for PR #493 Task 7 final-state verification.

Inputs (in same dir):
  branch.json            - branch HEAD 5357578 on perf/value-range-cfg-join
  baseline.json          - upstream/main c644fbe
  baseline_pingpong.json - second baseline run for drift control

Outputs to stdout:
  - Drift check (baseline_pingpong / baseline geomean)
  - Per-bench branch/baseline ratio, sorted
  - Geomean speedup with bootstrap 95% CI
  - Acceptance gate verdict
"""

import json
import math
import random
import statistics
import sys
from pathlib import Path


def load_runs(path):
    """Return dict: bench_name -> list[real_time(ns) from non-aggregate runs]."""
    data = json.loads(Path(path).read_text())
    runs = {}
    for b in data["benchmarks"]:
        # Only collect raw iterations, not _mean/_median/_stddev/_cv aggregates
        if b.get("run_type") != "iteration":
            continue
        name = b["name"]
        # Strip trailing repetition index (Google Benchmark appends /<idx>)
        runs.setdefault(name, []).append(b["real_time"])
    return runs


def median(values):
    return statistics.median(values)


def geomean(values):
    return math.exp(sum(math.log(v) for v in values) / len(values))


def bootstrap_ci(per_bench_ratios, n_iter=1000, seed=42, alpha=0.05):
    """Resample-with-replacement bootstrap of the geomean over the 27 benches."""
    rng = random.Random(seed)
    n = len(per_bench_ratios)
    means = []
    for _ in range(n_iter):
        sample = [per_bench_ratios[rng.randrange(n)] for _ in range(n)]
        means.append(geomean(sample))
    means.sort()
    lo = means[int(n_iter * alpha / 2)]
    hi = means[int(n_iter * (1 - alpha / 2)) - 1]
    return lo, hi


def main():
    here = Path(__file__).parent
    branch = load_runs(here / "branch.json")
    baseline = load_runs(here / "baseline.json")
    pingpong = load_runs(here / "baseline_pingpong.json")

    common = sorted(set(branch) & set(baseline) & set(pingpong))
    print(f"# Benches: {len(common)}")
    if not common:
        print("ERROR: no common benches", file=sys.stderr)
        sys.exit(1)

    # Drift: pingpong / baseline geomean
    pp_ratios = [median(pingpong[n]) / median(baseline[n]) for n in common]
    pp_geomean = geomean(pp_ratios)
    drift_pct = (pp_geomean - 1.0) * 100
    print(f"\n## Drift check (baseline_pingpong / baseline)")
    print(f"  geomean ratio = {pp_geomean:.4f}  ({drift_pct:+.2f}%)")
    print(f"  within +/-5%: {'YES' if abs(drift_pct) <= 5.0 else 'NO'}")

    # Per-bench: branch/baseline (ratio<1 means branch faster)
    rows = []
    for name in common:
        b_med = median(branch[name])
        base_med = median(baseline[name])
        ratio = b_med / base_med
        speedup_pct = (1.0 / ratio - 1.0) * 100  # positive = branch faster
        rows.append((name, b_med, base_med, ratio, speedup_pct))

    # Geomean speedup = geomean(baseline/branch), i.e., reciprocal of ratio
    speedup_ratios = [r[2] / r[1] for r in rows]  # baseline/branch
    g = geomean(speedup_ratios)
    g_pct = (g - 1.0) * 100
    lo, hi = bootstrap_ci(speedup_ratios, n_iter=1000)
    lo_pct = (lo - 1.0) * 100
    hi_pct = (hi - 1.0) * 100

    print(f"\n## Geomean speedup (baseline/branch)")
    print(f"  geomean = {g:.4f}  ({g_pct:+.2f}%)")
    print(f"  95% bootstrap CI: [{lo_pct:+.2f}%, {hi_pct:+.2f}%]")

    # Per-bench table sorted by speedup
    rows.sort(key=lambda r: r[4], reverse=True)
    print(f"\n## Top 10 wins (branch faster)")
    print(f"{'bench':<70} {'branch_med(ns)':>16} {'base_med(ns)':>16} {'speedup':>10}")
    for name, bm, basem, ratio, sp in rows[:10]:
        print(f"{name:<70} {bm:>16.1f} {basem:>16.1f} {sp:>+9.2f}%")

    print(f"\n## Bottom 10 (regressions if positive numbers absent)")
    print(f"{'bench':<70} {'branch_med(ns)':>16} {'base_med(ns)':>16} {'speedup':>10}")
    for name, bm, basem, ratio, sp in rows[-10:]:
        print(f"{name:<70} {bm:>16.1f} {basem:>16.1f} {sp:>+9.2f}%")

    # Full sorted table for the record
    print(f"\n## Full table (all {len(rows)} benches, sorted by speedup desc)")
    print(f"{'bench':<70} {'speedup':>10}")
    for name, bm, basem, ratio, sp in rows:
        print(f"{name:<70} {sp:>+9.2f}%")

    # Per-bench regression check: any bench with speedup < -0.5pp?
    regressions = [(n, sp) for n, _, _, _, sp in rows if sp < -0.5]
    print(f"\n## Per-bench regression check (speedup < -0.5pp)")
    if regressions:
        for n, sp in regressions:
            print(f"  REGRESSION: {n}: {sp:+.2f}%")
    else:
        print("  None.")

    # Acceptance gate
    print(f"\n## Acceptance gate")
    gate_ci = lo_pct >= 0.8
    gate_regress = not regressions
    gate_drift = abs(drift_pct) <= 5.0
    print(f"  Lower CI >= +0.8%:        {'PASS' if gate_ci else 'FAIL'} ({lo_pct:+.2f}%)")
    print(f"  No per-bench < -0.5pp:    {'PASS' if gate_regress else 'FAIL'} ({len(regressions)} regressions)")
    print(f"  Drift |.| <= 5%:          {'PASS' if gate_drift else 'FAIL'} ({drift_pct:+.2f}%)")
    overall = gate_ci and gate_regress and gate_drift
    print(f"  OVERALL:                  {'PASS' if overall else 'FAIL'}")
    sys.exit(0 if overall else 2)


if __name__ == "__main__":
    main()
