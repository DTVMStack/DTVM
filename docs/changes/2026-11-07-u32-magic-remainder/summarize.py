# SPDX-License-Identifier: Apache-2.0
import argparse, csv, json, random, statistics
from pathlib import Path
from sample_data import load_paired_samples

p = argparse.ArgumentParser()
p.add_argument("folder")
p.add_argument("--micro", action="store_true")
a = p.parse_args()
folder = Path(a.folder)
metrics = (
    ["warm_ms", "first_call_ms", "first_result_ms", "wall_ms"]
    if a.micro
    else ["wall_ms"]
)
try:
    g, _ = load_paired_samples(folder, metrics)
except (OSError, ValueError) as error:
    p.error(str(error))
rng = random.Random(20261107111)
result = []
for case, groups in g.items():
    for metric in metrics:
        for key, rows in groups.items():
            paired = [rows[i][metric] / groups["main"][i][metric] for i in sorted(rows)]
            n = len(paired)
            boots = sorted(
                statistics.median(rng.choices(paired, k=n)) for _ in range(10000)
            )
            result.append(
                {
                    "case": case,
                    "metric": metric,
                    "engine": key,
                    "n": n,
                    "median": statistics.median(r[metric] for r in rows.values()),
                    "paired_ratio": statistics.median(paired),
                    "ci_lo": boots[249],
                    "ci_hi": boots[9749],
                }
            )
(folder / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
with (folder / "summary.csv").open("w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=result[0].keys(), lineterminator="\n")
    w.writeheader()
    w.writerows(result)
for r in result:
    if r["engine"] == "candidate":
        med = {
            q["engine"]: q["median"]
            for q in result
            if q["case"] == r["case"] and q["metric"] == r["metric"]
        }
        print(
            r["case"],
            r["metric"],
            " ".join(f"{k}={v:.6f}" for k, v in med.items()),
            f'ratio={r["paired_ratio"]:.4f} [{r["ci_lo"]:.4f},{r["ci_hi"]:.4f}]',
        )
