#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""No-touch growth control; interval includes first-demand compilation."""
import argparse, hashlib, json, random, struct, subprocess, time
from pathlib import Path

p = argparse.ArgumentParser()
for name in ["main", "candidate", "wasmtime", "out"]:
    p.add_argument("--" + name, required=True)
p.add_argument("--rounds", type=int, default=31)
p.add_argument("--seed", type=int, default=2026110779)
a = p.parse_args()
out = Path(a.out)
out.mkdir(parents=True, exist_ok=False)
wat = Path(__file__).with_name("evidence") / "growth-no-touch" / "input.wat"
wasm = out / "input.wasm"
subprocess.run(["wat2wasm", str(wat), "-o", str(wasm)], check=True)
engines = {
    k: [
        str(Path(getattr(a, k)).resolve()),
        "-m",
        "multipass",
        "--enable-multipass-lazy",
    ]
    for k in ["main", "candidate"]
}
engines["wasmtime"] = [str(Path(a.wasmtime).resolve()), "run", "-C", "cache=n"]
rng = random.Random(a.seed)
(out / "manifest.json").write_text(
    json.dumps(
        {
            "seed": a.seed,
            "rounds": a.rounds,
            "warmup": -1,
            "binaries": {
                k: {
                    "command": v,
                    "sha256": hashlib.sha256(Path(v[0]).read_bytes()).hexdigest(),
                }
                for k, v in engines.items()
            },
            "input_sha256": hashlib.sha256(wasm.read_bytes()).hexdigest(),
            "boundary": "Fresh process; CPU0 all engine/workers; internal call interval includes demand compile;511 successful grows, no extension touches.",
        },
        indent=2,
    )
)
with (out / "samples.jsonl").open("w") as f:
    for rnd in range(-1, a.rounds):
        order = list(engines)
        rng.shuffle(order)
        for k in order:
            cmd = ["taskset", "-c", "0"] + engines[k] + [str(wasm)]
            t = time.perf_counter_ns()
            r = subprocess.run(cmd, capture_output=True, check=True, timeout=60)
            end = time.perf_counter_ns()
            begin, finish, pages = struct.unpack("<QQI", r.stdout)
            assert pages == 512 and finish >= begin and not r.stderr
            f.write(
                json.dumps(
                    {
                        "engine": k,
                        "round": rnd,
                        "grow_call_ms": (finish - begin) / 1e6,
                        "wall_ms": (end - t) / 1e6,
                        "command": cmd,
                    }
                )
                + "\n"
            )
            f.flush()
