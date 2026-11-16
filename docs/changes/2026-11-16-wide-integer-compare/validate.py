#!/usr/bin/env python3
"""Check the wide-comparison fixture against independent Python integer math."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]


def signed(x):
    return x - (1 << 64) if x >= (1 << 63) else x


def main():
    p = argparse.ArgumentParser(__doc__)
    p.add_argument("--dtvm", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--cpu", type=int, default=0)
    p.add_argument("--random-cases", type=int, default=100)
    p.add_argument("--seed", type=int, default=6461601)
    p.add_argument("--wast2json", default="wast2json")
    a = p.parse_args()
    binary = a.dtvm.resolve()
    fixture = ROOT / "tests/wast/multipass/wide_integer_compare.wast"
    rng = random.Random(a.seed)
    mask = (1 << 64) - 1
    edge = [0, 1, (1 << 63) - 1, 1 << 63, mask]
    vectors = [
        (lo, other, hi, high_other)
        for lo, other in [(0, 0), (0, mask), (mask, 0)]
        for hi in edge
        for high_other in edge
    ]
    vectors += [
        tuple(rng.getrandbits(64) for _ in range(4)) for _ in range(a.random_cases)
    ]
    functions = [
        p + "_" + s + suffix
        for p in ["lt", "le", "gt", "ge"]
        for s in ["u", "s"]
        for suffix in ["", "_ne"]
    ] + ["snapshot", "changed"]
    ops = {
        "lt": lambda x, y: x < y,
        "le": lambda x, y: x <= y,
        "gt": lambda x, y: x > y,
        "ge": lambda x, y: x >= y,
    }
    modes = [
        ("greedy", []),
        ("fast", ["--disable-multipass-greedyra"]),
        ("lazy", ["--enable-multipass-lazy"]),
    ]
    count = 0
    env = {k: v for k, v in os.environ.items() if not k.startswith("DTVM_RESEARCH_")}
    env["LC_ALL"] = "C"
    with tempfile.TemporaryDirectory(prefix="dtvm-wide-oracle-") as tmp:
        path = Path(tmp) / "fixture.json"
        subprocess.run([a.wast2json, str(fixture), "-o", str(path)], check=True)
        wasm = Path(tmp) / json.loads(path.read_text())["commands"][0]["filename"]
        wasm_hash = hashlib.sha256(wasm.read_bytes()).hexdigest()
        for fn in functions:
            for lo, other, hi, high_other in vectors:
                compare = ops.get(fn.split("_")[0], ops["lt"])
                expected = (
                    compare(lo, other)
                    if hi == high_other
                    else compare(
                        signed(hi) if "_s" in fn else hi,
                        signed(high_other) if "_s" in fn else high_other,
                    )
                )
                if fn == "changed":
                    expected = (
                        lo < other
                        if ((hi + 1) & mask) == high_other
                        else hi < high_other
                    )
                for mode, options in modes:
                    cmd = [
                        "taskset",
                        "-c",
                        str(a.cpu),
                        str(binary),
                        "-m",
                        "multipass",
                        *options,
                        "-f",
                        fn,
                        str(wasm),
                        "--args",
                        *[str(signed(x)) for x in [lo, other, hi, high_other]],
                    ]
                    r = subprocess.run(
                        cmd, env=env, capture_output=True, text=True, timeout=60
                    )
                    if (
                        r.returncode
                        or int(r.stdout.strip().split(":")[0], 0) != expected
                    ):
                        raise RuntimeError(
                            (
                                fn,
                                mode,
                                [lo, other, hi, high_other],
                                expected,
                                r.returncode,
                                r.stdout,
                                r.stderr,
                            )
                        )
                    count += 1
            print(fn, "passed", flush=True)
    result = {
        "executions": count,
        "seed": a.seed,
        "random_cases": a.random_cases,
        "cpu": a.cpu,
        "modes": [x[0] for x in modes],
        "binary": str(binary),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "fixture_sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
        "wasm_sha256": wasm_hash,
        "oracle": "independent Python unbounded integers, explicit signed high limb, unsigned low limb; each process fresh",
    }
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(result, indent=2) + "\n")
    print(count, "executions passed", flush=True)


if __name__ == "__main__":
    main()
