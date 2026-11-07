#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Sequential private candidates; marker receipt times, not pure compiler time."""
import argparse, hashlib, json, os, random, select, subprocess, time
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("--out", required=True)
p.add_argument("--rounds", type=int, default=21)
p.add_argument("--n", default="0,128")
p.add_argument("--seed", type=int, default=2026110753)
for name in ["main", "previous", "candidate", "wasmtime"]:
    p.add_argument("--" + name, required=True)
a = p.parse_args()
base = Path(a.out).resolve()
os.sched_setaffinity(0, {1})
engines = {
    k: [str(Path(v).resolve()), "-m", "multipass", "--enable-multipass-lazy"]
    for k, v in [("main", a.main), ("previous", a.previous), ("policy", a.candidate)]
}
for ms in [5, 10]:
    engines[f"budget-{ms}ms"] = engines["policy"] + [
        "--lazy-auto-greedy-budget-ms",
        str(ms),
    ]
engines["wt45"] = [str(Path(a.wasmtime).resolve()), "run", "-C", "cache=n"]
manifest = {
    "seed": a.seed,
    "rounds": a.rounds,
    "warmup": -1,
    "modules": json.loads((base / "modules.json").read_text()),
    "engines": {
        k: {"command": v, "sha256": hashlib.sha256(Path(v[0]).read_bytes()).hexdigest()}
        for k, v in engines.items()
    },
}
(base / "burst-manifest.json").write_text(json.dumps(manifest, indent=2))


def run(k, n):
    cmd = (
        ["taskset", "-c", "0"]
        + engines[k]
        + [str(base / "burst.wasm")]
        + ([str(n)] if k == "wt45" else ["--args", str(n)])
    )
    start = time.perf_counter_ns()
    child = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = b""
    ts = []
    while True:
        if not select.select([child.stdout], [], [], 180)[0]:
            child.kill()
            child.communicate()
            raise TimeoutError(cmd)
        c = os.read(child.stdout.fileno(), 1)
        if not c:
            break
        out += c
        ts.append(time.perf_counter_ns())
    ret = child.wait(timeout=120)
    finish = time.perf_counter_ns()
    err = child.stderr.read()
    m = n**3
    expected = (8 * 105 * m * (2 * n + m + 1)) & 0xFFFFFFFF
    assert ret == 0 and len(out) == 41 and out[0:1] == b"E", (cmd, ret, out, err[:1000])
    assert int.from_bytes(out[17:21], "little") == expected and out[17:21] == out[37:41]
    for i in range(8):
        assert (
            out[1 + 2 * i] == 75 + i
            and out[2 + 2 * i] == 97 + i
            and out[21 + 2 * i] == 107 + i
            and out[22 + 2 * i] == 65 + i
        )
    return {
        "engine": k,
        "n": n,
        "command": cmd,
        "exit": ret,
        "output_sha256": hashlib.sha256(out).hexdigest(),
        "total_ms": (finish - start) / 1e6,
        "first_output_ms": (ts[0] - start) / 1e6,
        "admission_ms": [(ts[1 + 2 * i] - ts[2 * i]) / 1e6 for i in range(8)],
        "first_call_ms": [(ts[2 + 2 * i] - ts[2 * i]) / 1e6 for i in range(8)],
        "warm_ms": [(ts[22 + 2 * i] - ts[21 + 2 * i]) / 1e6 for i in range(8)],
    }


rng = random.Random(a.seed)
with (base / "burst-samples.jsonl").open("w") as f:
    for n in map(int, a.n.split(",")):
        for round_ in range(-1, a.rounds):
            order = list(engines)
            rng.shuffle(order)
            for k in order:
                row = run(k, n)
                row["round"] = round_
                f.write(json.dumps(row) + "\n")
                f.flush()
        print(n, "complete", flush=True)
