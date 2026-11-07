# SPDX-License-Identifier: Apache-2.0
"""Validate complete, successful process pairs before computing statistics."""
import collections
import gzip
import json
import math
from pathlib import Path


def load_paired_samples(folder, metrics):
    folder = Path(folder)
    manifest = json.loads((folder / "manifest.json").read_text())
    rounds = manifest.get("rounds")
    if type(rounds) is not int or rounds <= 0:
        raise ValueError("manifest rounds must be a positive integer")
    engines = set(manifest.get("binaries", {}))
    if not {"main", "candidate"} <= engines:
        raise ValueError("manifest must declare main and candidate binaries")
    cases = manifest.get("cases", manifest.get("jobs", []))
    names = [c.get("id", c.get("name")) for c in cases]
    if (
        not names
        or any(not isinstance(n, str) for n in names)
        or len(set(names)) != len(names)
    ):
        raise ValueError("manifest must declare unique case names")
    declared = set(names)
    path = folder / "samples.jsonl"
    opener = path.open
    if not path.exists():
        path = folder / "samples.jsonl.gz"
        opener = lambda mode: gzip.open(path, mode)
    groups = collections.defaultdict(lambda: collections.defaultdict(dict))
    warmups = collections.defaultdict(dict)
    seen = set()
    with opener("rt") as stream:
        for line in stream:
            row = json.loads(line)
            case = row.get("case")
            engine = row.get("engine", row.get("variant"))
            index = row.get("round")
            if case not in declared or engine not in engines:
                raise ValueError("sample case/engine is absent from manifest")
            if type(index) is not int or not -1 <= index < rounds:
                raise ValueError(f"invalid round for {case}/{engine}: {index}")
            key = (case, engine, index)
            if key in seen:
                raise ValueError(f"duplicate sample: {key}")
            seen.add(key)
            if index == -1:
                warmups[case][engine] = row
                continue
            if (
                type(row.get("exit")) is not int
                or row["exit"] != 0
                or row.get("timeout", False)
            ):
                raise ValueError(f"failed measured process: {key}")
            for metric in metrics:
                value = row.get(metric)
                if (
                    type(value) not in (int, float)
                    or not math.isfinite(value)
                    or value <= 0
                ):
                    raise ValueError(f"invalid positive timing {metric}: {key}")
            groups[case][engine][index] = row
    expected = set(range(rounds))
    for case in names:
        if case not in groups:
            warmup = warmups[case]
            # Canonical runner excludes a case only after all engines' warmups
            # finish and at least one fails; retain that documented behavior.
            if set(warmup) == engines and any(
                r.get("exit") != 0 or r.get("timeout", False) for r in warmup.values()
            ):
                continue
            raise ValueError(f"missing measured case: {case}")
        if set(groups[case]) != engines or any(
            set(rows) != expected for rows in groups[case].values()
        ):
            raise ValueError(f"incomplete process pairs: {case}")
    if not groups:
        raise ValueError("no successful measured cases")
    return groups, manifest
