"""Paired process benchmarking of DTVM variants and three Wasmtime baselines."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import random
import statistics
import struct
import subprocess
import sys
import time

sys.path.insert(0, "benchmarks/paper/harness")
import run as harness

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--variant", action="append", required=True, metavar="NAME=BINARY")
parser.add_argument("--wasmtime45", type=Path, required=True)
parser.add_argument("--wasmtime51", type=Path, required=True)
parser.add_argument("--cases", required=True)
parser.add_argument("--mode", default="lazy-G-MT")
parser.add_argument("--rounds", type=int, required=True)
parser.add_argument("--seed", type=int, required=True)
parser.add_argument("--out", type=Path, required=True)
affinity = parser.add_mutually_exclusive_group()
affinity.add_argument("--cpu", type=int, default=0)
affinity.add_argument("--cpu-set", type=lambda value: [int(cpu) for cpu in value.split(",")])
parser.add_argument("--phase-inputs", type=Path)
args = parser.parse_args()
binaries = {label: Path(path).resolve() for label, path in
            (variant.split("=", 1) for variant in args.variant)}
assert "main" in binaries and "aa" not in binaries
binaries["aa"] = binaries["main"]
peers = {"wt45-c": args.wasmtime45.resolve(), "wt45-winch": args.wasmtime45.resolve(),
         "wt51-c": args.wasmtime51.resolve()}
os.sched_setaffinity(0, set(args.cpu_set or [args.cpu]))
args.out.mkdir(parents=True)
env = {**os.environ, "LC_ALL": "C", "WASMTIME_CACHE": "0"}
catalog = {c["id"]: c for c in harness.load_cases(harness.read_json(harness.CATALOG_PATH))}
rng = random.Random(args.seed)
manifest = dict(cpu=args.cpu, seed=args.seed, rounds=args.rounds, warmups=1,
                wt_cache="disabled", mode=args.mode, cases={},
                binary_sha256={k: hashlib.sha256(v.read_bytes()).hexdigest()
                               for k, v in {**binaries, **peers}.items()})
if args.cpu_set:
    manifest["cpu_set"] = args.cpu_set

def paired(samples, baseline):
    ratios = [100 * (x / y - 1) for x, y in zip(samples, baseline)]
    rs = random.Random(args.seed)
    boot = sorted(statistics.median(rs.choices(ratios, k=len(ratios))) for _ in range(10000))
    return [statistics.median(ratios), boot[250], boot[9750]]

summary = {}
phase_inputs = json.loads(args.phase_inputs.read_text()) if args.phase_inputs else None
with gzip.open(args.out / "samples.jsonl.gz", "wt", encoding="utf-8") as output:
    for name in args.cases.split(","):
        case = dict(catalog[name])
        if phase_inputs:
            phase = phase_inputs[name + ":8"]
            case["wasm"] = phase["wasm"]
        wasm = harness.paper_join(case["wasm"])
        contents = wasm.read_bytes()
        assert contents[:4] == b"\0asm", wasm
        commands = {k: harness.dtvm_cmd(v, case, args.mode, False)
                    for k, v in binaries.items()}
        for label, binary in peers.items():
            cmd = harness.wasmtime_cmd(binary, case)
            if label == "wt45-winch":
                cmd[2:2] = ["-C", "compiler=winch"]
            if label == "wt51-c" and b"wasi_unstable" in contents:
                cmd[2:2] = ["-S", "preview0=y"]
            commands[label] = cmd
        cwd = harness.case_cwd(case)
        stdin = (case.get("stdin") or "").encode()
        manifest["cases"][name] = dict(input_sha256=hashlib.sha256(contents).hexdigest(),
                                       cwd=str(cwd), stdin=case.get("stdin"), commands=commands)
        (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        timings = {k: [] for k in commands}
        kernel_timings = {k: [] for k in commands}
        first = None
        for round_id in range(-1, args.rounds):
            order = list(commands)
            rng.shuffle(order)
            for label in order:
                start = time.perf_counter_ns()
                result = subprocess.run(commands[label], cwd=cwd, input=stdin, env=env,
                                        capture_output=True, timeout=600)
                ms = (time.perf_counter_ns() - start) / 1e6
                pair = (hashlib.sha256(result.stdout).hexdigest(),
                        hashlib.sha256(result.stderr).hexdigest())
                kernel = None
                if phase_inputs:
                    assert len(result.stdout) == 8 * 56, (name, label, result.returncode)
                    stamps = list(struct.iter_unpack("<7Q", result.stdout))
                    assert all(tuple(sorted(packet)) == packet for packet in stamps)
                    kernel = statistics.median((packet[5] - packet[4]) / 1e6
                                               for packet in stamps[1:])
                    pair = (None, pair[1])
                row = dict(case=name, round=round_id, variant=label, wall_ms=ms,
                           exit=result.returncode, stdout_sha256=pair[0], stderr_sha256=pair[1])
                if kernel is not None:
                    row["warm_kernel_ms"] = kernel
                output.write(json.dumps(row) + "\n")
                output.flush()
                if first is None:
                    first = pair
                if result.returncode or pair != first:
                    (args.out / f"{name}.{label}.stdout").write_bytes(result.stdout)
                    (args.out / f"{name}.{label}.stderr").write_bytes(result.stderr)
                    raise RuntimeError((name, label, row, first))
                if round_id >= 0:
                    timings[label].append(ms)
                    if kernel is not None:
                        kernel_timings[label].append(kernel)
        summary[name] = dict(
            median_ms={k: statistics.median(v) for k, v in timings.items()},
            vs_main_pct={k: paired(v, timings["main"]) for k, v in timings.items() if k != "main"},
        )
        if phase_inputs:
            summary[name]["warm_kernel_ms"] = {k: statistics.median(v)
                                                for k, v in kernel_timings.items()}
            summary[name]["warm_kernel_vs_main_pct"] = {
                k: paired(v, kernel_timings["main"]) for k, v in kernel_timings.items() if k != "main"
            }
        print(name, json.dumps(summary[name], sort_keys=True), flush=True)
        (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
