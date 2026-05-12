#!/usr/bin/env python3
"""Compare baseline vs branch evmone-bench JSON with per-bench and geomean
bootstrap CIs. Sign convention: positive Delta = branch faster (= speedup)."""

import json
import math
import random
import sys
from pathlib import Path

OUT_DIR = Path(__file__).parent
BASELINE = OUT_DIR / "baseline.json"
BRANCH = OUT_DIR / "branch.json"
PINGPONG = OUT_DIR / "baseline_pingpong.json"
COMPARISON = OUT_DIR / "comparison.json"

BOOTSTRAP_N = 5000
RNG_SEED = 0xC0FFEE


def load_iters(path):
    """Return dict[bench_name] -> list of per-iteration real_time values (us)."""
    data = json.loads(path.read_text())
    out = {}
    for b in data["benchmarks"]:
        if b.get("run_type") != "iteration":
            continue
        name = b["name"]
        # real_time is in time_unit (us). Convert to ns for stable arithmetic.
        unit = b["time_unit"]
        t = b["real_time"]
        if unit == "us":
            t_ns = t * 1000.0
        elif unit == "ns":
            t_ns = t
        elif unit == "ms":
            t_ns = t * 1e6
        elif unit == "s":
            t_ns = t * 1e9
        else:
            raise RuntimeError(f"unknown time_unit {unit}")
        out.setdefault(name, []).append(t_ns)
    return out


def bootstrap_mean_ci(samples, rng, n=BOOTSTRAP_N, conf=0.95):
    """Return (lo, hi) of bootstrap CI of the mean, in same units as samples."""
    k = len(samples)
    means = []
    for _ in range(n):
        s = 0.0
        for _ in range(k):
            s += samples[rng.randrange(k)]
        means.append(s / k)
    means.sort()
    alpha = (1 - conf) / 2
    lo = means[int(alpha * n)]
    hi = means[int((1 - alpha) * n) - 1]
    return lo, hi


def bootstrap_speedup_ci(base_samples, branch_samples, rng, n=BOOTSTRAP_N,
                         conf=0.95):
    """Return (delta_pct, lo_pct, hi_pct) for speedup = (base/branch - 1) * 100.
    Positive = branch faster."""
    deltas = []
    kb = len(base_samples)
    kr = len(branch_samples)
    for _ in range(n):
        sb = 0.0
        for _ in range(kb):
            sb += base_samples[rng.randrange(kb)]
        sr = 0.0
        for _ in range(kr):
            sr += branch_samples[rng.randrange(kr)]
        mb = sb / kb
        mr = sr / kr
        deltas.append((mb / mr - 1) * 100)
    deltas.sort()
    alpha = (1 - conf) / 2
    lo = deltas[int(alpha * n)]
    hi = deltas[int((1 - alpha) * n) - 1]
    point = (sum(base_samples) / kb / (sum(branch_samples) / kr) - 1) * 100
    return point, lo, hi


def bootstrap_geomean_speedup_ci(per_bench_speedups_paired, rng,
                                 n=BOOTSTRAP_N, conf=0.95):
    """Bootstrap geomean of (1 + delta/100) by resampling per-iteration data
    inside each bench, then geomean across benches. Returns geomean speedup
    in percent and CI."""
    bench_names = list(per_bench_speedups_paired.keys())
    log_geomeans = []
    for _ in range(n):
        log_sum = 0.0
        for name in bench_names:
            base, branch = per_bench_speedups_paired[name]
            kb, kr = len(base), len(branch)
            sb = 0.0
            for _ in range(kb):
                sb += base[rng.randrange(kb)]
            sr = 0.0
            for _ in range(kr):
                sr += branch[rng.randrange(kr)]
            ratio = (sb / kb) / (sr / kr)
            log_sum += math.log(ratio)
        log_geomeans.append(log_sum / len(bench_names))
    log_geomeans.sort()
    alpha = (1 - conf) / 2
    lo_log = log_geomeans[int(alpha * n)]
    hi_log = log_geomeans[int((1 - alpha) * n) - 1]
    # Point estimate from raw means
    log_sum = 0.0
    for name in bench_names:
        base, branch = per_bench_speedups_paired[name]
        ratio = (sum(base) / len(base)) / (sum(branch) / len(branch))
        log_sum += math.log(ratio)
    point_log = log_sum / len(bench_names)
    return ((math.exp(point_log) - 1) * 100,
            (math.exp(lo_log) - 1) * 100,
            (math.exp(hi_log) - 1) * 100)


def verdict_for(delta, lo, hi):
    if delta >= 3 and lo > 0:
        return "STRONG-POS"
    if delta <= -3 or (delta < 0 and abs(delta) > 5 and hi < 0):
        return "STRONG-REG"
    if delta >= 1 or (lo > 0):
        return "WEAK-POS"
    if delta <= -1:
        return "WEAK-REG"
    return "NULL"


def fmt_ns(x):
    """Format mean ns as a short human-readable string."""
    if x >= 1e9:
        return f"{x/1e9:.3f}s"
    if x >= 1e6:
        return f"{x/1e6:.3f}ms"
    if x >= 1e3:
        return f"{x/1e3:.3f}us"
    return f"{x:.1f}ns"


def main():
    base = load_iters(BASELINE)
    branch = load_iters(BRANCH)
    pingpong = load_iters(PINGPONG)

    common = sorted(set(base) & set(branch) & set(pingpong))
    rng = random.Random(RNG_SEED)

    # Combined baseline = baseline run 1 + ping-pong (40 iterations).
    # Branch was run between the two baseline runs, so the combined baseline
    # is the principled ping-pong A-B-A estimator of the platform state at the
    # moment the branch ran. This is the headline.
    combined_base = {n: base[n] + pingpong[n] for n in common}

    # Per-bench against combined baseline
    per_bench = {}
    paired = {}
    for name in common:
        b = combined_base[name]
        r = branch[name]
        bm = sum(b) / len(b)
        rm = sum(r) / len(r)
        d, lo, hi = bootstrap_speedup_ci(b, r, rng)
        per_bench[name] = {
            "combined_baseline_mean_ns": bm,
            "branch_mean_ns": rm,
            "delta_pct": d,
            "ci95_lo_pct": lo,
            "ci95_hi_pct": hi,
            "verdict": verdict_for(d, lo, hi),
            "n_iters_combined_base": len(b),
            "n_iters_branch": len(r),
            "baseline_run1_mean_ns": sum(base[name]) / len(base[name]),
            "baseline_pingpong_mean_ns": (
                sum(pingpong[name]) / len(pingpong[name])
            ),
        }
        paired[name] = (b, r)

    # Geomean across all 27 benches
    g_pt, g_lo, g_hi = bootstrap_geomean_speedup_ci(paired, rng)

    # Drift: ping-pong baseline vs original baseline
    drift_paired = {}
    for name in common:
        drift_paired[name] = (base[name], pingpong[name])
    # Compute geomean of (base / pingpong) - 1 ; positive = pingpong faster
    log_sum = 0.0
    for name in common:
        b1 = sum(base[name]) / len(base[name])
        b2 = sum(pingpong[name]) / len(pingpong[name])
        log_sum += math.log(b2 / b1)
    drift_geomean_pct = (math.exp(log_sum / len(common)) - 1) * 100

    # Per-bench drift extremes
    drift_per = {}
    for name in common:
        b1 = sum(base[name]) / len(base[name])
        b2 = sum(pingpong[name]) / len(pingpong[name])
        drift_per[name] = (b2 / b1 - 1) * 100

    summary = {
        "geomean_speedup_pct": g_pt,
        "geomean_ci95_lo_pct": g_lo,
        "geomean_ci95_hi_pct": g_hi,
        "n_benches": len(common),
        "drift_geomean_pct": drift_geomean_pct,
        "drift_per_bench": drift_per,
        "per_bench": per_bench,
    }
    COMPARISON.write_text(json.dumps(summary, indent=2))

    # ---- Report ----
    print(f"# 27-Bench Compare: branch vs combined baseline (40 reps + 20 reps, multipass)")
    print(f"## Per-bench (sign: positive = branch faster). Baseline = mean(run1, ping-pong) per iteration.\n")
    print(f"| Bench | CombinedBase | Branch | Delta% | 95% CI | Verdict |")
    print(f"|---|---|---|---|---|---|")
    for name in sorted(common):
        v = per_bench[name]
        short = name.replace("external/total/", "")
        print(f"| {short} | {fmt_ns(v['combined_baseline_mean_ns'])} | "
              f"{fmt_ns(v['branch_mean_ns'])} | "
              f"{v['delta_pct']:+.2f}% | "
              f"[{v['ci95_lo_pct']:+.2f}, {v['ci95_hi_pct']:+.2f}]% | "
              f"{v['verdict']} |")
    print(f"\n**Geomean** | -- | -- | **{g_pt:+.3f}%** | "
          f"[{g_lo:+.3f}, {g_hi:+.3f}]% | "
          f"{verdict_for(g_pt, g_lo, g_hi)}")
    print(f"\n## Drift check (ping-pong baseline2 vs baseline1)")
    print(f"Drift geomean = {drift_geomean_pct:+.3f}%")
    extremes = sorted(drift_per.items(), key=lambda kv: kv[1])
    print(f"Top-3 negative drift (ping-pong faster):")
    for name, d in extremes[:3]:
        print(f"  {name.replace('external/total/','')}: {d:+.2f}%")
    print(f"Top-3 positive drift (ping-pong slower):")
    for name, d in extremes[-3:]:
        print(f"  {name.replace('external/total/','')}: {d:+.2f}%")
    print(f"\nMax abs per-bench drift: "
          f"{max(abs(d) for d in drift_per.values()):.2f}%")


if __name__ == "__main__":
    main()
