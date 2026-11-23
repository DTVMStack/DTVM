#!/usr/bin/env python3
"""Measure signed bucket kernels and catalog controls on pinned fresh processes."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import random
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "benchmarks/paper/harness"))
import run as harness

parser = argparse.ArgumentParser(description=__doc__)
for name in ("main", "candidate", "wasmtime", "wasm", "out"):
    parser.add_argument(f"--{name}", type=Path, required=True)
parser.add_argument("--group", choices=["kernel", "catalog"], required=True)
parser.add_argument("--cases", help="comma-separated catalog IDs")
parser.add_argument("--rounds", type=int, required=True)
parser.add_argument("--long-rounds", type=int, default=3)
parser.add_argument("--seed", type=int, required=True)
parser.add_argument("--input-seed", type=int, default=123)
parser.add_argument("--signed-i32-kernels", action="store_true",
                    help="measure signed i32 literal divisors 3, 7, 1009 and 1024")
parser.add_argument("--default-lazy-aa", action="store_true",
                    help="repeat the main default lazy command within each round")
parser.add_argument("--candidate-singlepass", action="store_true")
parser.add_argument("--omit-singlepass", action="store_true")
parser.add_argument("--warmups", type=int, default=2)
parser.add_argument("--cpu", type=int, default=0)
args = parser.parse_args()
if min(args.rounds, args.long_rounds) < 1:
    parser.error("round counts must be positive")
if args.warmups < 0 or (args.candidate_singlepass and args.omit_singlepass):
    parser.error("use nonnegative warmups and compatible singlepass options")
args.out.mkdir(parents=True)
rng = random.Random(args.seed)
env = {k: v for k, v in os.environ.items() if not k.startswith("DTVM_RESEARCH_")}
env["LC_ALL"] = "C"

def digest(data):
    return hashlib.sha256(data).hexdigest()

def signed(raw, width):
    return raw - (1 << width) if raw >> (width - 1) else raw

def remainder(raw, width, divisor):
    value = signed(raw, width)
    return (-1 if value < 0 else 1) * (abs(value) % divisor)

def oracle(name, count, state):
    mask64 = (1 << 64) - 1
    if name == "bucket64":
        for _ in range(count):
            state = (state * 6364136223846793005 + 1442695040888963407) & mask64
            state = remainder(state, 64, 1 << 40) & mask64
        return state
    if args.signed_i32_kernels:
        divisor = int(name.removeprefix("bucket"))
    else:
        divisor = 1024 if name == "bucket32" else 1009
    result = 0
    for _ in range(count):
        state = (state * 1664525 + 1013904223) & 0xffffffff
        result += remainder(state, 32, divisor)
    return result & mask64

if args.group == "kernel":
    if args.signed_i32_kernels:
        inputs = [(f"bucket{d}", 8_000_000, args.input_seed) for d in (3, 7, 1009, 1024)]
        inputs.append(("bucket7", 0, args.input_seed))
    else:
        inputs = [
            ("bucket32", 8_000_000, args.input_seed),
            ("bucket64", 8_000_000, args.input_seed),
            ("bucket32_other", 8_000_000, args.input_seed),
            ("bucket32", 0, args.input_seed),
        ]
    cases = {
        f"{name}/{n}": {
            "kind": "reactor", "function": name, "args": [n, seed],
            "wasm": str(args.wasm.resolve()),
        }
        for name, n, seed in inputs
    }
else:
    catalog = {c["id"]: c for c in harness.load_cases(harness.read_json(harness.CATALOG_PATH))}
    ids = args.cases or (
        "base64cli,chkfont,code-stock,cowsay,echo,erdtree,figlet,fortune,md5,pi,"
        "pkg1,qr2text,suggest,tpl,atax,bicg,gemver,gesummv,jacobi_1d,mvt,trisolv,gemm,2mm"
    )
    cases = {name: catalog[name] for name in ids.split(",")}

modes = {"F": "lazy-F-ST", "D": "lazy-G-MT"}
if args.group == "kernel":
    modes["G"] = "multipass-G-ST"
binaries = {"main": args.main.resolve(), "candidate": args.candidate.resolve()}
wt45 = args.wasmtime.resolve()
manifest = {
    "seed": args.seed,
    "cpu": args.cpu,
    "group": args.group,
    "binaries": {str(p): digest(p.read_bytes()) for p in (*binaries.values(), wt45)},
    "cases": {},
}
summary = {}

with gzip.open(args.out / "samples.jsonl.gz", "wt", encoding="utf-8") as stream:
    for case_id, case in cases.items():
        wasm = harness.paper_join(case["wasm"])
        harness.require_wasm(wasm)
        count = args.long_rounds if case_id in ("gemm", "2mm") else args.rounds
        expected = oracle(case["function"], *case["args"]) if args.group == "kernel" else None
        commands = {
            f"{label}-{mode}": harness.dtvm_cmd(binary, case, flag, False)
            for mode, flag in modes.items() for label, binary in binaries.items()
        }
        commands["main-AA"] = commands["main-F"]
        if args.default_lazy_aa:
            commands["main-D-AA"] = commands["main-D"]
        if not args.omit_singlepass:
            commands["main-SP"] = harness.dtvm_cmd(
                binaries["main"], case, "singlepass", False,
            )
        if args.candidate_singlepass:
            commands["candidate-SP"] = harness.dtvm_cmd(
                binaries["candidate"], case, "singlepass", False,
            )
        commands["WT45"] = harness.wasmtime_cmd(wt45, case)
        cwd = harness.case_cwd(case)
        manifest["cases"][case_id] = {
            "commands": commands, "cwd": str(cwd), "wasm_sha256": digest(wasm.read_bytes()),
            "stdin": case.get("stdin"), "rounds": count, "warmups": args.warmups,
            "expected": expected,
        }
        (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        samples = {label: [] for label in commands}
        output = None
        for round_id in range(-args.warmups, count):
            order = list(commands)
            rng.shuffle(order)
            for label in order:
                cmd = ["taskset", "-c", str(args.cpu), *commands[label]]
                start = time.perf_counter_ns()
                try:
                    proc = subprocess.run(
                        cmd, cwd=cwd, env=env, input=(case.get("stdin") or "").encode(),
                        capture_output=True, timeout=150,
                    )
                except subprocess.TimeoutExpired as error:
                    stream.write(json.dumps({"case":case_id, "variant":label, "round":round_id,
                                             "timeout":True, "wall_ms":(time.perf_counter_ns()-start)/1e6}) + "\n")
                    raise RuntimeError((case_id, label, "timeout")) from error
                wall_ms = (time.perf_counter_ns() - start) / 1e6
                signature = (digest(proc.stdout), digest(proc.stderr))
                stream.write(json.dumps({
                    "case": case_id, "variant": label, "round": round_id,
                    "wall_ms": wall_ms, "exit": proc.returncode, "stdout":signature[0],
                    "stderr":signature[1],
                }) + "\n")
                if proc.returncode:
                    raise RuntimeError((case_id, label, proc.returncode, proc.stderr[-1000:]))
                if expected is not None:
                    result = int(proc.stdout.decode().strip().split(":")[0], 0) & ((1 << 64) - 1)
                    if result != expected:
                        raise RuntimeError(f"{case_id} {label}: expected {expected}, got {result}")
                elif case["suite"] == "polybench" or case_id in {"base64cli","echo","md5","qr2text"}:
                    if output is None:
                        output = signature
                    if output != signature:
                        raise RuntimeError(f"{case_id} {label}: output mismatch")
                if round_id >= 0:
                    samples[label].append(wall_ms)
        pairs = [(f"candidate-{m}", f"main-{m}") for m in modes]
        pairs.append(("main-AA","main-F"))
        if args.default_lazy_aa:
            pairs.append(("main-D-AA", "main-D"))
        if args.candidate_singlepass:
            pairs.append(("candidate-SP","main-SP"))
        paired = {}
        for a, b in pairs:
            ratios = [x/y for x,y in zip(samples[a],samples[b])]
            boot = sorted(statistics.median(rng.choices(ratios, k=count)) for _ in range(10000))
            paired[f"{a}/{b}"] = [statistics.median(ratios), boot[250], boot[9750]]
        summary[case_id] = {
            "rounds": count, "ms": {label:statistics.median(v) for label,v in samples.items()},
            "paired95": paired,
        }
        (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        stream.flush()
        print(case_id, summary[case_id], flush=True)
