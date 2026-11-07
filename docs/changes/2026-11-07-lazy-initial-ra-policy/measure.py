#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import subprocess, time, os, random, json, hashlib, statistics
from pathlib import Path
import argparse, select

p = argparse.ArgumentParser()
p.add_argument("--out", required=True)
for name in ["main", "previous", "candidate", "wasmtime"]:
    p.add_argument("--" + name, required=True)
a = p.parse_args()
base = Path(a.out).resolve()
os.sched_setaffinity(0, {1})
rng = random.Random(2026110751)
candidate = str(Path(a.candidate).resolve())
engines = {
    "main": [str(Path(a.main).resolve()), "-m", "multipass", "--enable-multipass-lazy"],
    "previous": [
        str(Path(a.previous).resolve()),
        "-m",
        "multipass",
        "--enable-multipass-lazy",
    ],
    "policy": [candidate, "-m", "multipass", "--enable-multipass-lazy"],
    "off": [
        candidate,
        "-m",
        "multipass",
        "--enable-multipass-lazy",
        "--disable-lazy-auto-greedy",
    ],
    "module-cap": [
        candidate,
        "-m",
        "multipass",
        "--enable-multipass-lazy",
        "--lazy-auto-greedy-max-module-bytes",
        "65536",
    ],
    "budget-1ms": [
        candidate,
        "-m",
        "multipass",
        "--enable-multipass-lazy",
        "--lazy-auto-greedy-budget-ms",
        "1",
    ],
    "wt45": [str(Path(a.wasmtime).resolve()), "run", "-C", "cache=n"],
}
manifest = {
    k: {"command": v, "sha256": hashlib.sha256(Path(v[0]).read_bytes()).hexdigest()}
    for k, v in engines.items()
}
manifest = {
    "engines": manifest,
    "seed": 2026110751,
    "rounds": {"small": 21, "large": 7},
    "excluded_warmup": -1,
    "modules": json.loads((base / "modules.json").read_text()),
    "boundary": "CPU0 engines/workers, CPU1 pipe reader; fresh processes; warm page cache; timestamp marker receipt, not isolated compiler timings",
}
(base / "manifest.json").write_text(json.dumps(manifest, indent=2))


def run(k, case, n):
    cmd = (
        engines[k]
        + [str(base / (case + ".wasm"))]
        + (["--args", str(n)] if k != "wt45" else [str(n)])
    )
    start = time.perf_counter_ns()
    p = subprocess.Popen(
        ["taskset", "-c", "0"] + cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    out = b""
    ts = []
    while True:
        if not select.select([p.stdout], [], [], 180)[0]:
            p.kill()
            p.communicate()
            raise TimeoutError(cmd)
        c = os.read(p.stdout.fileno(), 1)
        if not c:
            break
        out += c
        ts.append(time.perf_counter_ns())
    ret = p.wait(timeout=120)
    end = time.perf_counter_ns()
    err = p.stderr.read()
    m = n**3
    expected = (105 * m * (2 * n + m + 1)) & 0xFFFFFFFF
    valid = (
        ret == 0
        and len(out) == 13
        and out[:3] == b"EKD"
        and out[7:9] == b"kd"
        and int.from_bytes(out[3:7], "little") == expected
        and out[3:7] == out[9:13]
    )
    if not valid:
        raise RuntimeError((k, case, n, ret, out, err[:1000]))
    return dict(
        engine=k,
        case=case,
        n=n,
        exit=ret,
        command=["taskset", "-c", "0"] + cmd,
        output_sha256=hashlib.sha256(out).hexdigest(),
        first_output_ms=(ts[0] - start) / 1e6,
        admission_ms=(ts[1] - ts[0]) / 1e6,
        first_call_ms=(ts[2] - ts[0]) / 1e6,
        warm_ms=(ts[8] - ts[7]) / 1e6,
        total_ms=(end - start) / 1e6,
    )


with (base / "samples.jsonl").open("w") as f:
    for case, n in [
        ("small", 0),
        ("small", 8),
        ("small", 64),
        ("small", 128),
        ("large", 0),
        ("large", 64),
        ("large", 128),
    ]:
        for round_ in range(-1, 21 if case == "small" else 7):
            keys = list(engines)
            rng.shuffle(keys)
            for k in keys:
                row = run(k, case, n)
                row["round"] = round_
                f.write(json.dumps(row) + "\n")
                f.flush()
        print(case, n, "complete", flush=True)
