#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fresh-process paired benchmark; run from repository root."""
import argparse, hashlib, importlib.util, json, os, random, resource, statistics, subprocess, time, gzip
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("--suite", choices=["wapm", "polybench"])
p.add_argument("--cases")
p.add_argument("--rounds", type=int, default=3)
p.add_argument("--warmups", type=int, choices=[0,1], default=1)
p.add_argument("--seed", type=int, required=True)
p.add_argument("--out", required=True)
p.add_argument("--main", required=True)
p.add_argument("--candidate", required=True)
p.add_argument("--previous")
p.add_argument("--load")
p.add_argument("--private", required=True)
p.add_argument("--variants", default="main,private,combined,wt45")
p.add_argument("--previous-commit")
p.add_argument("--wasmtime", required=True)
p.add_argument("--main-commit")
p.add_argument("--candidate-commit")
p.add_argument("--cpu", type=int, default=0)
a = p.parse_args()
s = importlib.util.spec_from_file_location("h", "benchmarks/paper/harness/run.py")
h = importlib.util.module_from_spec(s)
s.loader.exec_module(h)
cs = h.load_cases(h.read_json(h.CATALOG_PATH))
cs = [
    c
    for c in cs
    if (not a.suite or c["suite"] == a.suite)
    and (not a.cases or c["id"] in a.cases.split(","))
]
if not cs:
    p.error("No cases selected")
if a.cases and {c["id"] for c in cs} != set(a.cases.split(",")):
    p.error("Unknown case or suite/case mismatch")
if any(c['id'] == 'pi' for c in cs):
    pi = dict(next(c for c in cs if c['id'] == 'pi'))
    pi.update(id='pi1000', args=['1000'])
    cs.append(pi)
root = Path.cwd()
out = Path(a.out)
out.mkdir(parents=True, exist_ok=False)
sha = lambda b: hashlib.sha256(b).hexdigest()
bins = {
    'main':Path(a.main).resolve(), 'main_tier':Path(a.main).resolve(),
    'load':Path(a.load).resolve() if a.load else None, 'load_tier':Path(a.load).resolve() if a.load else None,
    'private':Path(a.private).resolve(), 'private_tier':Path(a.private).resolve(),
    'combined':Path(a.candidate).resolve(), 'combined_tier':Path(a.candidate).resolve(), 'off':Path(a.candidate).resolve(),
    'wt45':Path(a.wasmtime).resolve(),
}
bins = {k:v for k,v in bins.items() if v is not None}
if not set(a.variants.split(',')) <= set(bins):
    p.error('unknown variant')
bins = {k:bins[k] for k in a.variants.split(',')}

cmds = {
    c["id"]: {
        k: ["taskset", "-c", str(a.cpu)]
        + (
            h.wasmtime_cmd(b, c)
            if k == "wt45"
            else h.dtvm_cmd(b, c, "lazy-G-MT", False)
        )
        for k, b in bins.items()
    }
    for c in cs
}
for commands in cmds.values():
    for variant, command in commands.items():
        if variant.endswith('_tier'):
            command.insert(4, '--enable-lazy-private-tiering')
        if variant == 'combined':
            command.insert(4, '--enable-greedy-scalar-avx')
env = {**os.environ, "LC_ALL": "C", "WASMTIME_CACHE": "0"}
for k in list(env):
    if (
        k.startswith("DTVM_RESEARCH_")
        or k.startswith("DTVM_PR642_")
        or k == "DTVM_TRACE_DIR"
    ):
        env.pop(k)
manifest = {
    "commits": {
        "main": a.main_commit,
        "candidate": a.candidate_commit,
        "previous": a.previous_commit,
    },
    "variant_meaning": {"main":"pre-646 baseline", "private":"parent with 646", "combined":"candidate with scalar AVX option enabled", "off":"candidate with scalar AVX option disabled", "suffix_tier":"enable existing private promotion with default thresholds/budget"},
    "seed": a.seed,
    "rounds": a.rounds,
    "excluded_warmup": -1 if a.warmups else None,
    "timeout_s": 180,
    "boundary": f"Fresh process pre-spawn through exit; CPU{a.cpu} including workers; warm page cache; WT45 cache disabled; output captured; no concurrent profiles/builds/tests; suffix _tier explicitly enables budgeted private promotion",
    "binaries": {
        k: {"path": str(b), "sha256": sha(b.read_bytes())} for k, b in bins.items()
    },
    "commands": cmds,
    "cases": cs,
    "inputs": {c["id"]: sha(h.paper_join(c["wasm"]).read_bytes()) for c in cs},
}
(out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
rng = random.Random(a.seed)
refs = {}
rows = []
with (out / "samples.jsonl").open("w", buffering=1) as f:
    for c in cs:
        good = True
        for rnd in range(-a.warmups, a.rounds):
            if rnd >= 0 and not good:
                break
            order = list(bins)
            rng.shuffle(order)
            for k in order:
                start = time.perf_counter_ns()
                before = resource.getrusage(resource.RUSAGE_CHILDREN)
                try:
                    r = subprocess.run(
                        cmds[c["id"]][k],
                        cwd=h.case_cwd(c),
                        input=c.get("stdin", "").encode(),
                        capture_output=True,
                        env=env,
                        timeout=180,
                    )
                    code = r.returncode
                    stdout = r.stdout
                    stderr = r.stderr
                    timedout = False
                except subprocess.TimeoutExpired as e:
                    code = None
                    stdout = e.stdout or b""
                    stderr = e.stderr or b""
                    timedout = True
                wall = (time.perf_counter_ns() - start) / 1e6
                after = resource.getrusage(resource.RUSAGE_CHILDREN)
                row = {
                    "case": c["id"],
                    "suite": c["suite"],
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
                    "exit": code,
                    "timeout": timedout,
                    "stdout_sha256": sha(stdout),
                    "stderr_sha256": sha(stderr),
                    "stdout_bytes": len(stdout),
                    "stderr_bytes": len(stderr),
                }
                f.write(json.dumps(row) + "\n")
                rows.append(row)
                for stream, value in [("stdout", stdout), ("stderr", stderr)]:
                    path = out / f'{c["id"]}.{k}.{rnd}.{stream}.gz'
                    key = sha(value)
                    if key in refs:
                        os.link(refs[key], path)
                    else:
                        with gzip.open(path, "wb", compresslevel=1) as z:
                            z.write(value)
                        refs[key] = path
                if code != 0:
                    good = False
            if rnd == -1:
                print(
                    "warmup",
                    c["id"],
                    {
                        k: next(
                            (
                                r["exit"]
                                for r in rows
                                if r["case"] == c["id"]
                                and r["variant"] == k
                                and r["round"] == -1
                            ),
                            None,
                        )
                        for k in bins
                    },
                    flush=True,
                )
        numeric = [r for r in rows if r["case"] == c["id"]]
        match = {
            s: len({r[s + "_sha256"] for r in numeric}) == 1
            for s in ["stdout", "stderr"]
        }
        if c["suite"] == "polybench" and not all(match.values()):
            good = False
        med = (
            {
                k: round(
                    statistics.median(
                        r["wall_ms"]
                        for r in numeric
                        if r["variant"] == k and r["round"] >= 0
                    ),
                    3,
                )
                for k in bins
            }
            if good
            else {}
        )
        print(
            "result",
            c["id"],
            {"success": good, "medians": med, "output_match": match},
            flush=True,
        )
