#!/usr/bin/env python3
"""Four-engine same-input first-result and same-instance diagnostic phases.

No build/profiler/test should overlap invocation. CPU0 engines, CPU1 collector.
Canonical original outputs are independently checked on all engines before
sampling; no old hardcoded binary paths or timing data are used.
"""
import argparse, hashlib, json, os, random, resource, selectors, struct, subprocess, time
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("--inputs", required=True)
p.add_argument("--out", required=True)
for name in ["main", "previous", "candidate", "wasmtime"]:
    p.add_argument("--" + name, required=name != "previous")

for name in ["main", "previous", "candidate"]:
    p.add_argument("--" + name + "-revision", default="unknown")
p.add_argument("--cases", default="atax,bicg")
p.add_argument("--counts", default="1,8,30")
p.add_argument("--rounds", type=int, default=9)
p.add_argument("--seed", type=int, default=2026110759)
a = p.parse_args()
out = Path(a.out)
out.mkdir(parents=True, exist_ok=False)
inputs = json.loads((Path(a.inputs) / "phase-inputs.json").read_text())
os.sched_setaffinity(0, {1})
sha = lambda x: hashlib.sha256(x).hexdigest()
bins = {
    k: Path(getattr(a, k)).resolve()
    for k in ["main", "previous", "candidate", "wasmtime"]
    if getattr(a, k)
}
env = {
    k: v
    for k, v in os.environ.items()
    if not k.startswith(("DTVM_PR642_", "DTVM_RESEARCH_")) and k != "DTVM_TRACE_DIR"
}
env.update(LC_ALL="C", WASMTIME_CACHE="0")


def command(k, wasm):
    opts = (
        ["run", "-C", "cache=n"]
        if k == "wasmtime"
        else ["-m", "multipass", "--enable-multipass-lazy"]
    )
    if k == "candidate":
        opts.append("--enable-greedy-scalar-avx")
    return ["taskset", "-c", "0", str(bins[k])] + opts + [str(wasm)]


def run(cmd):
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    start = time.perf_counter_ns()
    child = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        env=env,
    )
    chunks = {"stdout": bytearray(), "stderr": bytearray()}
    receipt = []
    sel = selectors.DefaultSelector()
    for key, stream in [("stdout", child.stdout), ("stderr", child.stderr)]:
        os.set_blocking(stream.fileno(), False)
        sel.register(stream, selectors.EVENT_READ, key)
    while sel.get_map():
        if time.perf_counter_ns() - start > 180_000_000_000:
            child.kill()
            child.wait()
            raise TimeoutError(cmd)
        for key, _ in sel.select(timeout=1):
            data = os.read(key.fd, 56 if key.data == "stdout" else 65536)
            observed = time.perf_counter_ns()
            if not data:
                sel.unregister(key.fileobj)
                key.fileobj.close()
                continue
            chunks[key.data].extend(data)
            if key.data == "stdout":
                while len(chunks["stdout"]) >= 56 * (len(receipt) + 1):
                    receipt.append(observed)
    ret = child.wait(timeout=max(1, 180 - (time.perf_counter_ns() - start) / 1e9))
    end = time.perf_counter_ns()
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    sel.close()
    return (
        ret,
        bytes(chunks["stdout"]),
        bytes(chunks["stderr"]),
        receipt,
        start,
        end,
        1000 * (after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime),
    )


# Independently check canonical bytes across all engines, before any sampling.
refs = {}
validation = []
for case in a.cases.split(","):
    info = inputs[f"{case}:1"]
    path = Path(info["canonical"])
    assert sha(path.read_bytes()) == info["canonical_sha256"]
    for k in bins:
        cmd = command(k, path)
        r = subprocess.run(
            cmd, stdin=subprocess.DEVNULL, capture_output=True, env=env, timeout=180
        )
        assert r.returncode == 0, (case, k, r.returncode, r.stderr[-500:])
        if case not in refs:
            refs[case] = (r.stdout, r.stderr)
        assert refs[case] == (r.stdout, r.stderr), (
            case,
            k,
            "canonical output mismatch",
        )
        validation.append(
            {
                "case": case,
                "engine": k,
                "command": cmd,
                "exit": r.returncode,
                "stdout_sha256": sha(r.stdout),
                "stderr_sha256": sha(r.stderr),
                "stderr_bytes": len(r.stderr),
            }
        )
    assert not refs[case][0], (
        "Canonical stdout must be empty before adding timing packets",
        case,
    )
(out / "validation.json").write_text(json.dumps(validation, indent=2) + "\n")
manifest = {
    "source_revisions": {
        k: getattr(a, k + "_revision") for k in ["main", "previous", "candidate"]
    },
    "seed": a.seed,
    "rounds": a.rounds,
    "excluded_warmup": -1,
    "cpu_engines": 0,
    "cpu_collector": 1,
    "binaries": {
        k: {"path": str(v), "sha256": sha(v.read_bytes())} for k, v in bins.items()
    },
    "inputs": inputs,
    "boundary": "Parent pre-spawn through exit, plus parent receipt of each 56-byte packet. Internal WASI monotonic stamps are analyzed separately; do not compare internal epoch to parent epoch. All engines receive same modified Wasm; no new exports; original main repeats with original init/free/reset.",
    "jobs": [],
}
for case in a.cases.split(","):
    for count in map(int, a.counts.split(",")):
        info = inputs[f"{case}:{count}"]
        path = Path(info["wasm"])
        assert sha(path.read_bytes()) == info["wasm_sha256"]
        manifest["jobs"].append(
            {
                "case": case,
                "count": count,
                "commands": {k: command(k, path) for k in bins},
            }
        )
(out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
rng = random.Random(a.seed)
with (out / "samples.jsonl").open("w") as f:
    for job in manifest["jobs"]:
        case, count = job["case"], job["count"]
        expected = refs[case][1] * count
        for round_ in range(-1, a.rounds):
            order = list(bins)
            rng.shuffle(order)
            for k in order:
                ret, stdout, stderr, receipt, start, end, cpu_ms = run(
                    job["commands"][k]
                )
                assert (
                    ret == 0 and len(stdout) == 56 * count and len(receipt) == count
                ), (case, count, k, ret, len(stdout), stderr[-500:])
                assert stderr == expected, (
                    case,
                    count,
                    k,
                    "diagnostic output differs from repeated canonical output",
                )
                stamps = [
                    struct.unpack_from("<7Q", stdout, i * 56) for i in range(count)
                ]
                assert all(list(t) == sorted(t) for t in stamps), (
                    case,
                    count,
                    k,
                    "nonmonotonic clock",
                )
                calls = [
                    {
                        "admission_ms": (t[1] - t[0]) / 1e6,
                        "allocation_ms": (t[2] - t[1]) / 1e6,
                        "vector_init_ms": (t[3] - t[2]) / 1e6,
                        "matrix_init_ms": (t[4] - t[3]) / 1e6,
                        "kernel_ms": (t[5] - t[4]) / 1e6,
                        "output_free_ms": (t[6] - t[5]) / 1e6,
                        "internal_first_to_last_ms": (t[6] - t[0]) / 1e6,
                    }
                    for t in stamps
                ]
                row = {
                    "case": case,
                    "count": count,
                    "engine": k,
                    "round": round_,
                    "exit": ret,
                    "wall_ms": (end - start) / 1e6,
                    "cpu_ms": cpu_ms,
                    "result_receipt_ms": [(t - start) / 1e6 for t in receipt],
                    "post_last_result_ms": (end - receipt[-1]) / 1e6,
                    "stdout_timing_sha256": sha(stdout),
                    "stderr_sha256": sha(stderr),
                    "stderr_bytes": len(stderr),
                    "stamps_ns": stamps,
                    "calls": calls,
                }
                f.write(json.dumps(row) + "\n")
                f.flush()
        print(case, count, "complete", flush=True)
