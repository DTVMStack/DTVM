#!/usr/bin/env python3
import json
import random
import statistics
import sys
from collections import defaultdict
from pathlib import Path

path = Path(sys.argv[1])
random.seed(6461818)
rows = [json.loads(line) for line in (path / "samples.jsonl").read_text().splitlines()]
groups = defaultdict(list)
for row in rows:
    if row["round"] >= 0:
        groups[row["case"]].append(row)

results = []
for case, group in sorted(groups.items()):
    variants = sorted({r["variant"] for r in group})
    by_variant = {v: {r["round"]: r for r in group if r["variant"] == v} for v in variants}
    bad = [r for r in group if r["exit"] != 0 or r["timeout"]]
    record = {"case": case, "rounds": {v: len(by_variant[v]) for v in variants},
              "nonzero": len(bad),
              "output_hashes": {k: len({r[k] for r in group}) for k in ("stdout_sha256", "stderr_sha256")},
              "medians_ms": {v: statistics.median(r["wall_ms"] for r in by_variant[v].values()) for v in variants}}
    if not bad:
        record["paired"] = {}
        for denominator in ("private", "main", "wt45"):
            if denominator not in by_variant or "combined" not in by_variant:
                continue
            on, other = by_variant["combined"], by_variant[denominator]
            assert set(on) == set(other)
            ratios = [on[i]["wall_ms"] / other[i]["wall_ms"] for i in sorted(on)]
            n = len(ratios)
            boots = sorted(statistics.median(random.choices(ratios, k=n)) for _ in range(10000))
            record["paired"][f"combined/{denominator}"] = {
                "median": statistics.median(ratios), "ci95": [boots[249], boots[9749]]}
    results.append(record)

(path / "summary.json").write_text(json.dumps(results, indent=2) + "\n")
print(json.dumps(results, indent=2))
