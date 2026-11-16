#!/usr/bin/env python3
"""Paired production/main/Wasmtime45 measurements using paper harness commands."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import resource
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "benchmarks/paper/harness"))
import run as harness

if not __debug__:
    raise SystemExit("run without Python -O: benchmark output checks are required")


def oracle(n):
    """Independent tuple comparison; only equal-high pairs need 64-bit arithmetic."""
    blocks, rest = divmod(n, 1024)
    total = blocks * 496 + sum((i & 31) < ((i >> 5) & 31) for i in range(rest))
    mask = (1 << 64) - 1
    for block in range(blocks + 1):
        for j in range(32):
            i = block * 1024 + j * 33
            if i >= n:
                continue
            low = (i * -7046029254386353131) & mask
            rotated = ((low << 17) | (low >> 47)) & mask
            total += low < rotated
    return total


def main():
    p = argparse.ArgumentParser(__doc__)
    for name in ["main", "candidate", "wasmtime", "out"]:
        p.add_argument("--" + name, required=True, type=Path)
    p.add_argument(
        "--cases",
        default="wide_compare_zero,wide_compare_dev,wide_compare_paper,bicg,atax,md5,cowsay,base64cli",
    )
    p.add_argument("--rounds", type=int, default=31)
    p.add_argument("--seed", type=int, default=6511601)
    p.add_argument("--cpu", type=int, default=0)
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=False)
    binaries = {k: getattr(a, k).resolve() for k in ["main", "candidate", "wasmtime"]}
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    cases = {
        x["id"]: x for x in harness.load_cases(harness.read_json(harness.CATALOG_PATH))
    }
    cases["wide_compare_zero"] = {
        **cases["wide_compare_dev"],
        "id": "wide_compare_zero",
        "args": ["0"],
    }
    selected = [cases[x] for x in a.cases.split(",")]
    expected = {
        x["id"]: oracle(int(x["args"][0])) for x in selected if x["suite"] == "codegen"
    }
    rng = random.Random(a.seed)
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("DTVM_RESEARCH_", "CONTRACT_CAPTURE_"))
    }
    env.update(LC_ALL="C", WASMTIME_CACHE="0")
    rows, commands = [], {}
    manifest = {
        "main_revision": "aa98c1b712aa27cc23e55216ca7ce2b5e38b8fcf",
        "head": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True
        ).strip(),
        "source_diff_sha256": hashlib.sha256(
            subprocess.check_output(["git", "diff"])
        ).hexdigest(),
        "binaries": {
            k: {"path": str(v), "sha256": sha(v)} for k, v in binaries.items()
        },
        "rounds": a.rounds,
        "warmups": 2,
        "seed": a.seed,
        "cpu": a.cpu,
        "boundary": "fresh process spawn to exit, warm file cache; randomized within-round engine order; WT cache off; no concurrent build/test/profile; AA reuses main executable/inode; production has no research switches",
        "commands": commands,
    }
    for case in selected:
        cid = case["id"]
        modes = ["singlepass", "lazy-G-MT"]
        if case["suite"] == "codegen":
            modes += ["lazy-F-ST", "multipass-G-ST"]
        cmds = {
            f"{engine}/{mode}": harness.dtvm_cmd(binaries[engine], case, mode, False)
            for engine in ["main", "candidate"]
            for mode in modes
        }
        cmds["main-AA/lazy-G-MT"] = cmds["main/lazy-G-MT"]
        cmds["wt45"] = harness.wasmtime_cmd(binaries["wasmtime"], case)
        commands[cid] = {
            "wasm_sha256": sha(harness.paper_join(case["wasm"])),
            "cwd": str(harness.case_cwd(case)),
            "variants": cmds,
        }
        if cid in expected:
            commands[cid]["oracle"] = expected[cid]
        reference = None
        with (a.out / "samples.jsonl").open("a", buffering=1) as f:
            for rnd in range(-2, a.rounds):
                order = list(cmds)
                rng.shuffle(order)
                for name in order:
                    start_cpu = resource.getrusage(resource.RUSAGE_CHILDREN)
                    start = time.perf_counter_ns()
                    r = subprocess.run(
                        ["taskset", "-c", str(a.cpu), *cmds[name]],
                        cwd=harness.case_cwd(case),
                        env=env,
                        input=None,
                        capture_output=True,
                        timeout=180,
                    )
                    wall = (time.perf_counter_ns() - start) / 1e6
                    end_cpu = resource.getrusage(resource.RUSAGE_CHILDREN)
                    assert r.returncode == 0, (
                        cid,
                        name,
                        r.returncode,
                        r.stderr[-1000:],
                    )
                    if cid in expected:
                        value = int(r.stdout.strip().split(b":")[0], 0)
                        assert value == expected[cid], (cid, name, value, expected[cid])
                    else:
                        signature = (r.stdout, r.stderr)
                        reference = reference or signature
                        assert signature == reference, (cid, name, "output mismatch")
                    row = {
                        "case": cid,
                        "round": rnd,
                        "variant": name,
                        "wall_ms": wall,
                        "cpu_ms": 1000
                        * (
                            (end_cpu.ru_utime + end_cpu.ru_stime)
                            - (start_cpu.ru_utime + start_cpu.ru_stime)
                        ),
                        "stdout_sha256": hashlib.sha256(r.stdout).hexdigest(),
                        "stderr_sha256": hashlib.sha256(r.stderr).hexdigest(),
                    }
                    rows.append(row)
                    f.write(json.dumps(row) + "\n")
        (a.out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        print(cid, "completed", a.rounds, flush=True)
    summary = []
    for case in selected:
        cid = case["id"]
        variants = commands[cid]["variants"]
        vals = lambda v: [
            r["wall_ms"]
            for r in rows
            if r["case"] == cid and r["round"] >= 0 and r["variant"] == v
        ]
        result = {
            "case": cid,
            "medians_ms": {v: statistics.median(vals(v)) for v in variants},
            "pairs": {},
        }
        pairs = [("main-AA/lazy-G-MT", "main/lazy-G-MT")]
        pairs += [
            (v, v.replace("candidate/", "main/"))
            for v in variants
            if v.startswith("candidate/")
        ]
        for x, y in pairs:
            ratios = [a / b for a, b in zip(vals(x), vals(y))]
            boot = sorted(
                statistics.median(rng.choices(ratios, k=len(ratios)))
                for _ in range(10000)
            )
            result["pairs"][x + " vs " + y] = {
                "median": statistics.median(ratios),
                "ci95": [boot[250], boot[9750]],
            }
        summary.append(result)
    (a.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
