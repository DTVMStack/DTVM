#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Randomized paired fresh-process benchmark; run from repository root."""
import gzip
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

p = argparse.ArgumentParser()
p.add_argument("--out", required=True)
p.add_argument("--rounds", type=int, default=3)
p.add_argument("--cases", default="gemm,2mm")
p.add_argument("--variants", default="main,eager,serial,wt45")
p.add_argument("--candidate")
p.add_argument("--main", default="work/wapm-followup/dtvm-main")
p.add_argument(
    "--wasmtime", default="benchmarks/paper/runtimes/wasmtime-45.0.0/out/wasmtime"
)
p.add_argument("--revert")
p.add_argument("--seed", type=int, default=2026110621)
a = p.parse_args()
root = Path.cwd()
s = importlib.util.spec_from_file_location(
    "h", root / "benchmarks/paper/harness/run.py"
)
h = importlib.util.module_from_spec(s)
s.loader.exec_module(h)
base = Path(a.main).resolve()
wt = Path(a.wasmtime).resolve()
v = {
    "main": (base, "lazy-G-MT"),
    "eager": (base, "multipass-G-ST"),
    "serial": (base, "lazy-G-ST"),
    "wt45": (wt, None),
}
if a.candidate:
    v["candidate"] = (Path(a.candidate).resolve(), "lazy-G-MT")
if a.revert:
    v["revert"] = (Path(a.revert).resolve(), "lazy-G-MT")
v = {k: v[k] for k in a.variants.split(",")}
cases = [
    c
    for c in h.load_cases(h.read_json(h.CATALOG_PATH))
    if c["id"] in a.cases.split(",")
]
assert len(cases) == len(a.cases.split(","))
out = Path(a.out)
out.mkdir(parents=True, exist_ok=False)
sha = lambda b: hashlib.sha256(b).hexdigest()
cmds = {
    c["id"]: {
        k: ["taskset", "-c", "0"]
        + (h.wasmtime_cmd(b, c) if mode is None else h.dtvm_cmd(b, c, mode, False))
        for k, (b, mode) in v.items()
    }
    for c in cases
}
manifest = {
    "main_commit": "193b8d2e8ddeb54af974bc8a2b9cc52b838de8b2",
    "seed": a.seed,
    "rounds": a.rounds,
    "excluded_warmup": -1,
    "boundary": "fresh process through exit, CPU0 incl workers, warm page cache, WT45 cache disabled, no diagnostics",
    "variants": {
        k: {
            "binary": str(b),
            "sha256": sha(b.read_bytes()),
            "mode": m,
            "env": {"DTVM_RESEARCH_REVERT632": "1"} if k == "revert" else {},
        }
        for k, (b, m) in v.items()
    },
    "commands": cmds,
    "inputs": {c["id"]: sha(h.paper_join(c["wasm"]).read_bytes()) for c in cases},
}
(out / "manifest.json").write_text(json.dumps(manifest, indent=2))
rng = random.Random(a.seed)
rows = []
output_refs = {}
with (out / "samples.jsonl").open("w", buffering=1) as f:
    for c in cases:
        for rnd in range(-1, a.rounds):
            order = list(v)
            rng.shuffle(order)
            for k in order:
                env = {**os.environ, "LC_ALL": "C", "WASMTIME_CACHE": "0"}
                for name in [
                    "DTVM_TRACE_DIR",
                    "DTVM_RESEARCH_REVERT632",
                    "DTVM_RESEARCH_DISABLE_LOOP_CHOICE",
                    "DTVM_RESEARCH_GREEDY_FUNCTIONS",
                    "DTVM_RESEARCH_PURE_LOOP_GREEDY",
                ]:
                    env.pop(name, None)
                if k == "revert":
                    env["DTVM_RESEARCH_REVERT632"] = "1"
                before = resource.getrusage(resource.RUSAGE_CHILDREN)
                t = time.perf_counter_ns()
                r = subprocess.run(
                    cmds[c["id"]][k],
                    cwd=h.case_cwd(c),
                    input=c.get("stdin"),
                    text=True,
                    capture_output=True,
                    env=env,
                    timeout=180,
                )
                wall = (time.perf_counter_ns() - t) / 1e6
                after = resource.getrusage(resource.RUSAGE_CHILDREN)
                row = {
                    "case": c["id"],
                    "variant": k,
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
                rows.append(row)
                f.write(json.dumps(row) + "\n")
                for stream, value in [("stdout", r.stdout), ("stderr", r.stderr)]:
                    path = out / f'{c["id"]}.{k}.{rnd}.{stream}.gz'
                    key = sha(value.encode())
                    if key in output_refs:
                        os.link(output_refs[key], path)
                    else:
                        with gzip.open(path, "wb", compresslevel=1) as gz:
                            gz.write(value.encode())
                        output_refs[key] = path
                assert r.returncode == 0, (c["id"], k, r.stderr)
        if c["suite"] == "polybench":
            assert len({r["stdout_sha256"] for r in rows if r["case"] == c["id"]}) == 1
            assert len({r["stderr_sha256"] for r in rows if r["case"] == c["id"]}) == 1
        print(
            c["id"],
            {
                k: round(
                    statistics.median(
                        r["wall_ms"]
                        for r in rows
                        if r["case"] == c["id"]
                        and r["variant"] == k
                        and r["round"] >= 0
                    ),
                    3,
                )
                for k in v
            },
            flush=True,
        )
