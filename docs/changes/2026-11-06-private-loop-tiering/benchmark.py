#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run from repository root; randomized paired fresh-process timing."""
import argparse
import hashlib
import importlib.util
import json
import os
import random
import resource
import statistics
import subprocess
import time
from pathlib import Path

root = Path.cwd()
p = argparse.ArgumentParser()
p.add_argument("--out", required=True)
p.add_argument("--main", required=True)
p.add_argument("--candidate", required=True)
p.add_argument("--wasmtime", required=True)
p.add_argument(
    "--extra-variants",
    help="JSON mapping extra budgeted variant names to CLI arguments",
)
p.add_argument("--seed", type=int, default=2026110616)
p.add_argument("--repeats", type=int, default=7)
p.add_argument("--cases", default="pi,pi100,pi1000")
p.add_argument("--variants", default="main,off,calls,loops,budgeted,wt45")
a = p.parse_args()
spec = importlib.util.spec_from_file_location(
    "h", root / "benchmarks/paper/harness/run.py"
)
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
base = Path(a.main).resolve()
candidate = Path(a.candidate).resolve()
wt = Path(a.wasmtime).resolve()
variants = {
    "main": (base, None),
    "off": (candidate, None),
    "calls": (candidate, None),
    "loops": (candidate, None),
    "budgeted": (candidate, None),
    "wt45": (wt, None),
}
extras = json.loads(Path(a.extra_variants).read_text()) if a.extra_variants else {}
variants.update({v: (candidate, None) for v in extras})
variants = {v: variants[v] for v in a.variants.split(",")}
cases = h.load_cases(h.read_json(h.CATALOG_PATH))
pi = next((c for c in cases if c["id"] == "pi"))
cases += [{**pi, "id": "pi" + str(n), "args": [str(n)]} for n in [10, 100, 1000]]
cases = [c for c in cases if c["id"] in a.cases.split(",")]
assert len(cases) == len(a.cases.split(","))
sha = lambda b: hashlib.sha256(b).hexdigest()
out = Path(a.out)
out.mkdir(parents=True, exist_ok=False)
cmds = {
    c["id"]: {
        v: ["taskset", "-c", "0"]
        + (
            h.wasmtime_cmd(b, c)
            if v == "wt45"
            else h.dtvm_cmd(b, c, "lazy-G-MT", False)
        )
        for v, (b, _) in variants.items()
    }
    for c in cases
}
for c in cases:
    for v in variants:
        if v in ["calls", "loops", "budgeted"] or v in extras:
            cmd = cmds[c["id"]][v]
            cmd[4:4] = [
                "--enable-lazy-private-tiering",
                "--lazy-tier-policy",
                "budgeted" if v in extras else v,
            ] + extras.get(v, [])
manifest = {
    "main_commit": "193b8d2e8ddeb54af974bc8a2b9cc52b838de8b2",
    "seed": a.seed,
    "extra_variants": extras,
    "rounds": a.repeats,
    "excluded_warmup_round": -1,
    "boundary": "fresh process pre-spawn through exit; CPU0; warm page cache; Wasmtime cache disabled; diagnostics disabled",
    "hypothesis": "Entry heat, bounded loop sample, estimated profit and serialized per-module compile budget; no diagnostic tracing",
    "variants": {
        v: {
            "binary": str(b),
            "sha256": sha(b.read_bytes()),
            "policy": (
                ("budgeted" if v in extras else v)
                if v in ["calls", "loops", "budgeted"] or v in extras
                else None
            ),
        }
        for v, (b, ids) in variants.items()
    },
    "commands": cmds,
    "inputs": {c["id"]: sha(h.paper_join(c["wasm"]).read_bytes()) for c in cases},
}
(out / "manifest.json").write_text(json.dumps(manifest, indent=2))
rng = random.Random(a.seed)
rows = []
with (out / "samples.jsonl").open("w", buffering=1) as f:
    for c in cases:
        for rnd in range(-1, a.repeats):
            order = list(variants)
            rng.shuffle(order)
            for v in order:
                env = {**os.environ, "LC_ALL": "C", "WASMTIME_CACHE": "0"}
                env.pop("DTVM_TRACE_DIR", None)
                env.pop("DTVM_RESEARCH_GREEDY_FUNCTIONS", None)
                env.pop("DTVM_RESEARCH_PURE_LOOP_GREEDY", None)
                before = resource.getrusage(resource.RUSAGE_CHILDREN)
                t = time.perf_counter_ns()
                r = subprocess.run(
                    cmds[c["id"]][v],
                    cwd=h.case_cwd(c),
                    input=c.get("stdin"),
                    text=True,
                    capture_output=True,
                    env=env,
                    timeout=120,
                )
                wall = (time.perf_counter_ns() - t) / 1000000.0
                after = resource.getrusage(resource.RUSAGE_CHILDREN)
                row = {
                    "case": c["id"],
                    "variant": v,
                    "round": rnd,
                    "wall_ms": wall,
                    "cpu_ms": 1000
                    * (
                        after.ru_utime
                        + after.ru_stime
                        - before.ru_utime
                        - before.ru_stime
                    ),
                    "exit": r.returncode,
                    "stdout_sha256": sha(r.stdout.encode()),
                    "stderr_sha256": sha(r.stderr.encode()),
                }
                assert r.returncode == 0, (c["id"], v, r.stderr)
                rows.append(row)
                f.write(json.dumps(row) + "\n")
                (out / (c["id"] + "." + v + ".stdout")).write_text(r.stdout)
                (out / (c["id"] + "." + v + ".stderr")).write_text(r.stderr)
        if c["id"].startswith("pi"):
            assert len({r["stdout_sha256"] for r in rows if r["case"] == c["id"]}) == 1
        print(
            c["id"],
            {
                v: round(
                    statistics.median(
                        (
                            r["wall_ms"]
                            for r in rows
                            if r["case"] == c["id"]
                            and r["variant"] == v
                            and (r["round"] >= 0)
                        )
                    ),
                    3,
                )
                for v in variants
            },
            flush=True,
        )
