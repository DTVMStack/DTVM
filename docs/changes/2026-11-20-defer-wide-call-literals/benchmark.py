#!/usr/bin/env python3
"""Compare the standalone lowering change against main and uncached WT45."""
import argparse
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
parser.add_argument("--main", type=Path, required=True)
parser.add_argument("--candidate", type=Path, required=True)
parser.add_argument("--wasmtime", type=Path, required=True)
parser.add_argument("--inputs", type=Path, required=True)
parser.add_argument("--out", type=Path, required=True)
parser.add_argument("--rounds", type=int, default=31)
parser.add_argument("--seed", type=int, default=6542001)
parser.add_argument("--cpu", type=int, default=0)
parser.add_argument("--timeout", type=float, default=90.0)
parser.add_argument("--only", choices=["clang", "canonical", "zero-calls"])
parser.add_argument(
    "--experimental-control", action="store_true",
    help="compare masks 0 and 4 using the earlier c31be94 research build as --candidate",
)
args = parser.parse_args()
if args.rounds < 1 or args.timeout <= 0:
    parser.error("--rounds and --timeout must be positive")
if args.experimental_control and args.only != "zero-calls":
    parser.error("--experimental-control requires --only zero-calls")
args.main = args.main.resolve()
args.candidate = args.candidate.resolve()
args.wasmtime = args.wasmtime.resolve()
args.out.mkdir(parents=True)
rng = random.Random(args.seed)
env = {k: v for k, v in os.environ.items() if not k.startswith("DTVM_RESEARCH_")}
env["LC_ALL"] = "C"

catalog = {entry["id"]: entry for entry in harness.load_cases(harness.read_json(harness.CATALOG_PATH))}
cases = {}
if args.only != "canonical":
    for filename, function, iterations in [
        ("clang-calls", "run_wide24", 1_000_000),
        ("clang-calls", "run_small32", 1_000_000),
        ("clang-inlined", "run_wide24", 1_000_000),
        ("clang-calls", "run_wide24", 0),
    ]:
        if args.only == "zero-calls" and iterations != 0:
            continue
        case_id = f"{filename}/{function}/{iterations}"
        cases[case_id] = {
            "wasm": str((args.inputs / f"{filename}.wasm").resolve()),
            "kind": "reactor",
            "function": function,
            "args": [iterations, 123],
        }
if args.only not in ("clang", "zero-calls"):
    for case_id in ["base64cli", "echo", "md5", "bicg", "atax"]:
        cases[case_id] = catalog[case_id]

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def reference(case):
    if case["function"] == "run_wide24":
        start, step, count = 0x123456789ABCDEF, 329_583_729_514_129_817, 24
    else:
        start, step, count = 123_456_789, 83_517, 32
    constants = [start + i * step for i in range(count)]
    iterations, seed = case["args"]
    for _ in range(iterations):
        for constant in constants:
            seed = (seed * 16777619 & ((1 << 64) - 1)) ^ constant
    return seed

def median_interval(ratios):
    bootstrap = sorted(
        statistics.median(rng.choices(ratios, k=len(ratios))) for _ in range(10000)
    )
    return {
        "median": statistics.median(ratios),
        "ci95": [bootstrap[250], bootstrap[9750]],
    }

manifest = {
    "seed": args.seed,
    "cpu": args.cpu,
    "rounds": args.rounds,
    "warmups": 2,
    "timeout_s": args.timeout,
    "experimental_control": args.experimental_control,
    "binaries": {str(path): sha(path) for path in (args.main, args.candidate, args.wasmtime)},
    "cases": {},
}
summary = {}
for case_id, case in cases.items():
    modes = {"fast": "lazy-F-ST", "lazy": "lazy-G-MT", "greedy": "multipass-G-ST"}
    control = args.candidate if args.experimental_control else args.main
    commands = {
        f"{label}-{mode}": harness.dtvm_cmd(binary, case, flag, False)
        for mode, flag in modes.items()
        for label, binary in (("main", control), ("candidate", args.candidate))
    }
    commands["main-aa"] = commands["main-fast"]
    commands["main-singlepass"] = harness.dtvm_cmd(args.main, case, "singlepass", False)
    commands["WT45"] = harness.wasmtime_cmd(args.wasmtime, case)
    masks = {
        label: "4" if args.experimental_control and label.startswith("candidate-") else "0"
        for label in commands
    }
    expected = reference(case) if "function" in case else None
    cwd = harness.case_cwd(case)
    manifest["cases"][case_id] = {
        "input_sha256": sha(harness.paper_join(case["wasm"])),
        "cwd": str(cwd),
        "commands": commands,
        "research_masks": masks,
        "expected": expected,
    }
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    values = {label: [] for label in commands}
    canonical_output = None
    with (args.out / "samples.jsonl").open("a", buffering=1) as stream:
        for round_id in range(-2, args.rounds):
            order = list(commands)
            rng.shuffle(order)
            for label in order:
                command = ["taskset", "-c", str(args.cpu), *commands[label]]
                before = time.perf_counter_ns()
                sample_env = (
                    {**env, "DTVM_RESEARCH_COMPILER_MASK": masks[label]}
                    if args.experimental_control else env
                )
                try:
                    result = subprocess.run(
                        command, cwd=cwd, env=sample_env, input=b"",
                        capture_output=True, timeout=args.timeout,
                    )
                except subprocess.TimeoutExpired as exc:
                    stream.write(json.dumps({
                        "case": case_id,
                        "round": round_id,
                        "variant": label,
                        "wall_ms": (time.perf_counter_ns() - before) / 1e6,
                        "exit": None,
                        "timeout": True,
                        "stdout_sha256": hashlib.sha256(exc.stdout or b"").hexdigest(),
                        "stderr_sha256": hashlib.sha256(exc.stderr or b"").hexdigest(),
                    }) + "\n")
                    raise RuntimeError((case_id, label, round_id, "timed out")) from exc
                elapsed = (time.perf_counter_ns() - before) / 1e6
                stream.write(json.dumps({
                    "case": case_id,
                    "round": round_id,
                    "variant": label,
                    "wall_ms": elapsed,
                    "exit": result.returncode,
                    "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                    "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
                }) + "\n")
                if result.returncode:
                    raise RuntimeError((case_id, command, result.stderr))
                if expected is not None:
                    actual = int(result.stdout.decode().strip().split(":")[0], 0) & ((1 << 64) - 1)
                    if actual != expected:
                        raise RuntimeError((case_id, label, actual, expected))
                else:
                    # Each selected catalog case has deterministic output.
                    output = (result.stdout, result.stderr)
                    if canonical_output is None:
                        canonical_output = output
                    if output != canonical_output:
                        raise RuntimeError((case_id, label, "output mismatch"))
                if round_id >= 0:
                    values[label].append(elapsed)
    pairs = [(f"candidate-{mode}", f"main-{mode}") for mode in modes]
    pairs.append(("main-aa", "main-fast"))
    summary[case_id] = {
        "median_ms": {label: statistics.median(samples) for label, samples in values.items()},
        "paired": {
            f"{lhs}/{rhs}": median_interval(
                [x / y for x, y in zip(values[lhs], values[rhs])]
            )
            for lhs, rhs in pairs
        },
    }
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(case_id, summary[case_id], flush=True)
