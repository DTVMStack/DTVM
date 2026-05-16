#!/usr/bin/env python3
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Paired-ratio BCa bootstrap CI analyzer for evm-cache build-time bench.

Inputs: baseline + treatment CSV produced by bench_evm_cache.sh. CSV columns:

    label,n_jumpdests,run_idx,phase,phase_us

Pairing: per (label, phase) take the median over runs, then ratio = T/B.
Resample: cluster bootstrap on contracts (per-contract unit) WITH replacement,
N=1000 by default. BCa: jackknife acceleration `a` (leave-one-contract-out)
and standard z_0 (median-bias correction). The canonical reference for the
BCa interval and its acceleration estimator is Efron & Tibshirani 1993,
An Introduction to the Bootstrap, §14.3.

Gate inversion: since improvement = 1 - r, the spec gate "improvement_lo >=
0.15" is equivalent to "r_upper_CI <= 0.85" on the `total` phase.

Output: markdown table on stdout (per-phase summary), optional JSON via
--json.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import sys
from collections import defaultdict
from statistics import median, NormalDist
from typing import Dict, List, Tuple


def read_csv(path: str) -> Dict[Tuple[str, str], List[float]]:
    """Return {(label, phase): [phase_us, ...]} aggregated over runs."""
    rows: Dict[Tuple[str, str], List[float]] = defaultdict(list)
    with open(path, "r", newline="") as f:
        rdr = csv.DictReader(f)
        for row in rdr:
            try:
                rows[(row["label"], row["phase"])].append(float(row["phase_us"]))
            except (KeyError, ValueError) as e:
                sys.exit(f"error: bad row in {path}: {row} ({e})")
    return rows


def per_contract_medians(rows: Dict[Tuple[str, str], List[float]]) -> Dict[str, Dict[str, float]]:
    """{(label, phase): [us...]} -> {phase: {label: median_us}}."""
    out: Dict[str, Dict[str, float]] = defaultdict(dict)
    for (label, phase), vals in rows.items():
        if vals:
            out[phase][label] = median(vals)
    return out


def paired_ratios(
    base: Dict[str, Dict[str, float]],
    treat: Dict[str, Dict[str, float]],
) -> Dict[str, Dict[str, float]]:
    """Intersect labels per phase; ratio = treatment / baseline."""
    out: Dict[str, Dict[str, float]] = {}
    for phase, b in base.items():
        if phase not in treat:
            continue
        t = treat[phase]
        ratios: Dict[str, float] = {}
        for label in sorted(set(b) & set(t)):
            if b[label] > 0:
                ratios[label] = t[label] / b[label]
        if ratios:
            out[phase] = ratios
    return out


def _percentile(sorted_vals: List[float], q: float) -> float:
    """Index into a pre-sorted list at quantile q in [0, 1]."""
    n = len(sorted_vals)
    idx = max(0, min(n - 1, int(round(q * (n - 1)))))
    return sorted_vals[idx]


def bca_ci(
    ratios: List[float],
    alpha: float,
    n_boot: int,
    rng: random.Random,
) -> Tuple[float, float, float]:
    """Return (theta_hat, ci_lo, ci_hi) on the median of the paired ratios.

    Cluster bootstrap on the contract list; BCa with jackknife `a` and
    median-bias `z_0`.
    """
    n = len(ratios)
    theta_hat = median(ratios)
    if n < 3:
        return (theta_hat, float("nan"), float("nan"))

    boot: List[float] = []
    for _ in range(n_boot):
        sample = [ratios[rng.randrange(n)] for _ in range(n)]
        boot.append(median(sample))
    boot.sort()

    nd = NormalDist()
    below = sum(1 for b in boot if b < theta_hat)
    p0 = below / n_boot
    if p0 <= 0.0:
        p0 = 1.0 / (2.0 * n_boot)
    elif p0 >= 1.0:
        p0 = 1.0 - 1.0 / (2.0 * n_boot)
    z0 = nd.inv_cdf(p0)

    jack: List[float] = []
    for i in range(n):
        sub = ratios[:i] + ratios[i + 1:]
        jack.append(median(sub))
    jmean = sum(jack) / n
    num = sum((jmean - j) ** 3 for j in jack)
    denom_sq = sum((jmean - j) ** 2 for j in jack)
    a = num / (6.0 * (denom_sq ** 1.5)) if denom_sq > 0 else 0.0

    z_lo = nd.inv_cdf(alpha / 2.0)
    z_hi = nd.inv_cdf(1.0 - alpha / 2.0)

    def _bca_q(z: float) -> float:
        denom = 1.0 - a * (z0 + z)
        if denom == 0.0:
            return 0.5
        return nd.cdf(z0 + (z0 + z) / denom)

    return (theta_hat, _percentile(boot, _bca_q(z_lo)), _percentile(boot, _bca_q(z_hi)))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--baseline", required=True, help="baseline CSV path")
    ap.add_argument("--treatment", required=True, help="treatment CSV path")
    ap.add_argument("--n-boot", type=int, default=1000)
    ap.add_argument("--alpha", type=float, default=0.05, help="0.05 -> 95%% CI")
    ap.add_argument("--seed", type=int, default=0xDEADBEEF)
    ap.add_argument(
        "--gate-r-upper", type=float, default=0.85,
        help="gate: total-phase ci_hi <= this (default 0.85 = >=15%% improvement)",
    )
    ap.add_argument("--json", dest="json_out", help="emit JSON report to this path")
    args = ap.parse_args()

    rng = random.Random(args.seed)

    base = per_contract_medians(read_csv(args.baseline))
    treat = per_contract_medians(read_csv(args.treatment))
    by_phase = paired_ratios(base, treat)
    if not by_phase:
        sys.exit("error: no overlapping (label, phase) pairs between baseline and treatment")

    print("# evm-cache build bench — paired-ratio BCa bootstrap report\n")
    print(f"- bootstrap resamples: **{args.n_boot}**")
    print(f"- alpha: **{args.alpha}** (CI = {(1.0 - args.alpha) * 100:.0f}%)")
    print(f"- gate: `total` phase r_upper_CI ≤ **{args.gate_r_upper}**\n")
    print("## Per-phase summary\n")
    print("| phase | n_contracts | r_median | r_lo | r_hi | improvement_lo | improvement_hi | gate |")
    print("|---|---:|---:|---:|---:|---:|---:|:--:|")

    overall_pass = False
    json_phases: Dict[str, Dict[str, float]] = {}
    phase_order = ["total"] + sorted(p for p in by_phase if p != "total")
    for phase in phase_order:
        if phase not in by_phase:
            continue
        ratios = list(by_phase[phase].values())
        theta, lo, hi = bca_ci(ratios, args.alpha, args.n_boot, rng)
        imp_lo = 1.0 - hi
        imp_hi = 1.0 - lo
        gate = "PASS" if hi <= args.gate_r_upper else "FAIL"
        if phase == "total":
            overall_pass = (gate == "PASS")
        print(
            f"| `{phase}` | {len(ratios)} | {theta:.4f} | {lo:.4f} | {hi:.4f} | "
            f"{imp_lo * 100:+.1f}% | {imp_hi * 100:+.1f}% | **{gate}** |"
        )
        json_phases[phase] = {
            "n_contracts": len(ratios),
            "r_median": theta,
            "r_lo": lo,
            "r_hi": hi,
            "improvement_lo": imp_lo,
            "improvement_hi": imp_hi,
            "gate": gate,
        }

    print(f"\n**Overall gate (total phase): {'PASS' if overall_pass else 'FAIL'}**")

    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump(
                {
                    "n_boot": args.n_boot,
                    "alpha": args.alpha,
                    "gate_r_upper": args.gate_r_upper,
                    "seed": args.seed,
                    "phases": json_phases,
                    "overall_gate": "PASS" if overall_pass else "FAIL",
                },
                f,
                indent=2,
            )
            f.write("\n")


if __name__ == "__main__":
    main()
