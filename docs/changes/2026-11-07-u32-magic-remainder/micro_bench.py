#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import argparse, hashlib, json, os, random, selectors, statistics, struct, subprocess, time
from pathlib import Path

p = argparse.ArgumentParser()
for k in ["main", "candidate", "wasmtime", "out"]:
    p.add_argument("--" + k, required=True)
p.add_argument("--rounds", type=int, default=31)
p.add_argument("--iterations", type=int, default=1000000)
p.add_argument("--calls", type=int, default=8)
p.add_argument(
    "--divisors", default="3,7,10,20,255,1900,2100,65521,4294967295,8,dynamic"
)
p.add_argument("--generate-only", action="store_true")
p.add_argument("--seed", type=int, default=20261107103)
p.add_argument("--dtvm-extra", action="append", default=[])
a = p.parse_args()
if a.calls < 2 or a.iterations < 0 or a.rounds < 1:
    p.error("Require calls>=2, iterations>=0, rounds>=1")
out = Path(a.out)
out.mkdir(parents=True, exist_ok=False)
os.sched_setaffinity(0, {1})
sha = lambda x: hashlib.sha256(x).hexdigest()
bins = {k: Path(getattr(a, k)).resolve() for k in ["main", "candidate", "wasmtime"]}
commands = {
    k: ["taskset", "-c", "0", str(v)]
    + (
        ["run", "-C", "cache=n"]
        if k == "wasmtime"
        else ["-m", "multipass", "--enable-multipass-lazy"] + a.dtvm_extra
    )
    for k, v in bins.items()
}
env = {
    k: v
    for k, v in os.environ.items()
    if not k.startswith(("DTVM_RESEARCH_", "DTVM_PR642_"))
    and k not in ["LD_PRELOAD", "DTVM_TRACE_DIR"]
}
env.update(LC_ALL="C", WASMTIME_CACHE="0")
jobs = []
for spec in a.divisors.split(","):
    d = 7 if spec == "dynamic" else int(spec)
    rhs = "(local.get $d)" if spec == "dynamic" else f"(i32.const {d})"
    name = "rem-" + spec
    wat = out / (name + ".wat")
    wasm = wat.with_suffix(".wasm")
    state = 0x12345678
    for _ in range(a.iterations):
        state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
        state = (state + state % d) & 0xFFFFFFFF
    wat.write_text(
        f"""(module
 (import "wasi_snapshot_preview1" "clock_time_get" (func $clock (param i32 i64 i32) (result i32)))
 (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
 (memory (export "memory") 1)
 (func $kernel (param $x i32) (param $n i32) (param $d i32) (result i32) (local $i i32)
 (block $done (br_if $done (i32.eqz (local.get $n)))
 (loop $loop
 (local.set $x (i32.add (i32.mul (local.get $x) (i32.const 1664525)) (i32.const 1013904223)))
 (local.set $x (i32.add (local.get $x) (i32.rem_u (local.get $x) {rhs})))
 (local.set $i (i32.add (local.get $i) (i32.const 1)))
 (br_if $loop (i32.lt_u (local.get $i) (local.get $n)))))
 (local.get $x))
 (func (export "_start") (local $call i32) (local $value i32)
 (i32.store (i32.const 160) (i32.const 128)) (i32.store (i32.const 164) (i32.const 24))
 (loop $calls
 (if (call $clock (i32.const 1) (i64.const 1) (i32.const 128)) (then unreachable))
 (local.set $value (call $kernel (i32.const 305419896) (i32.const {a.iterations}) (i32.const {d})))
 (if (call $clock (i32.const 1) (i64.const 1) (i32.const 136)) (then unreachable))
 (i32.store (i32.const 144) (local.get $value)) (i32.store (i32.const 148) (local.get $call))
 (if (call $write (i32.const 1) (i32.const 160) (i32.const 1) (i32.const 176)) (then unreachable))
 (local.set $call (i32.add (local.get $call) (i32.const 1)))
 (br_if $calls (i32.lt_u (local.get $call) (i32.const {a.calls}))))
))"""
    )
    subprocess.run(["wat2wasm", str(wat), "-o", str(wasm)], check=True)
    jobs.append(
        {
            "name": name,
            "divisor": d,
            "iterations": a.iterations,
            "calls": a.calls,
            "expected": state,
            "wasm": str(wasm.resolve()),
            "sha256": sha(wasm.read_bytes()),
        }
    )
manifest = {
    "seed": a.seed,
    "rounds": a.rounds,
    "warmup": -1,
    "binaries": {
        k: {"path": str(v), "sha256": sha(v.read_bytes())} for k, v in bins.items()
    },
    "commands": commands,
    "jobs": jobs,
    "boundary": "Fresh process on CPU0, parent CPU1. Packet receipt after each kernel returns; 24-byte WASI begin/end/checksum/call packet. First call includes private demand compile (WT45 compiles before _start); zero-iteration cohort keeps loop code but n is a runtime parameter. Whole process/first packet include engine startup. Calls2..8 aggregate within each process, not independent samples. Each call starts same seed; no allocations/memory growth in kernel. Default lazy tiering unchanged.",
}
(out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
if a.generate_only:
    raise SystemExit(0)


def run(cmd):
    start = time.perf_counter_ns()
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    sel = selectors.DefaultSelector()
    chunks = {"out": bytearray(), "err": bytearray()}
    receipts = []
    for key, stream in [("out", proc.stdout), ("err", proc.stderr)]:
        os.set_blocking(stream.fileno(), False)
        sel.register(stream, selectors.EVENT_READ, key)
    while sel.get_map():
        if time.perf_counter_ns() - start > 120_000_000_000:
            proc.kill()
            proc.wait()
            raise TimeoutError(cmd)
        for key, _ in sel.select(timeout=1):
            b = os.read(key.fd, 24 if key.data == "out" else 65536)
            now = time.perf_counter_ns()
            if not b:
                sel.unregister(key.fileobj)
                key.fileobj.close()
                continue
            chunks[key.data].extend(b)
            if key.data == "out":
                while len(chunks["out"]) >= 24 * (len(receipts) + 1):
                    receipts.append((now - start) / 1e6)
    ret = proc.wait()
    end = time.perf_counter_ns()
    sel.close()
    assert ret == 0 and not chunks["err"], (ret, chunks["err"][-1000:])
    return chunks["out"], receipts, (end - start) / 1e6


rng = random.Random(a.seed)
with (out / "samples.jsonl").open("w") as f:
    for job in jobs:
        for rnd in range(-1, a.rounds):
            order = list(bins)
            rng.shuffle(order)
            for k in order:
                data, receipts, wall = run(commands[k] + [job["wasm"]])
                assert len(data) == 24 * a.calls and len(receipts) == a.calls
                durations = []
                for call in range(a.calls):
                    begin, end, value, index = struct.unpack_from(
                        "<QQII", data, call * 24
                    )
                    assert (
                        begin <= end and value == job["expected"] and index == call
                    ), (job, k, value, index)
                    durations.append((end - begin) / 1e6)
                row = {
                    "case": job["name"],
                    "engine": k,
                    "round": rnd,
                    "wall_ms": wall,
                    "first_result_ms": receipts[0],
                    "first_call_ms": durations[0],
                    "warm_ms": (
                        statistics.median(durations[1:]) if a.calls > 1 else None
                    ),
                    "calls_ms": durations,
                    "receipts_ms": receipts,
                    "checksum": job["expected"],
                    "exit": 0,
                }
                f.write(json.dumps(row) + "\n")
                f.flush()
        print(job["name"], "complete", flush=True)
