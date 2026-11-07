#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exact paired sign tests: predeclared nine-constant warm synthetic family."""
import argparse, json, math
from pathlib import Path
from sample_data import load_paired_samples

p = argparse.ArgumentParser()
p.add_argument("folder")
a = p.parse_args()
folder = Path(a.folder)
family = {"rem-" + str(d) for d in [3, 7, 10, 20, 255, 1900, 2100, 65521, 4294967295]}
try:
    samples, manifest = load_paired_samples(folder, ["warm_ms"])
    jobs = {job.get("name"): job for job in manifest.get("jobs", [])}
    if not family <= samples.keys() or any(
        jobs.get(case, {}).get("iterations", 0) <= 0 for case in family
    ):
        raise ValueError(
            "sign tests require the nine declared positive-iteration hot cases"
        )
except (OSError, ValueError) as error:
    p.error(str(error))
g = {
    case: {
        engine: {index: row["warm_ms"] for index, row in rounds.items()}
        for engine, rounds in engines.items()
    }
    for case, engines in samples.items()
}
rows = []
for case in sorted(family):
    groups = g[case]
    diff = [groups["candidate"][i] - groups["main"][i] for i in sorted(groups["main"])]
    wins = sum(x < 0 for x in diff)
    losses = sum(x > 0 for x in diff)
    n = wins + losses
    probability = min(
        1, 2 * sum(math.comb(n, j) for j in range(min(wins, losses) + 1)) / 2**n
    )
    rows.append(
        {
            "case": case,
            "process_pairs": n,
            "candidate_faster_pairs": wins,
            "candidate_slower_pairs": losses,
            "ties": len(diff) - n,
            "sign_test_two_sided_p": probability,
        }
    )
previous = 0
for i, r in enumerate(sorted(rows, key=lambda q: q["sign_test_two_sided_p"])):
    previous = max(previous, min(1, (len(rows) - i) * r["sign_test_two_sided_p"]))
    r["holm_p_9_constants"] = previous
print(
    json.dumps(
        {
            "method": "One warm median per process; exact paired two-sided sign test; Holm adjustment within9 predeclared nonpow2 constants only. Controls excluded. No pooling calls as independent samples.",
            "rows": rows,
        },
        indent=2,
    )
)
