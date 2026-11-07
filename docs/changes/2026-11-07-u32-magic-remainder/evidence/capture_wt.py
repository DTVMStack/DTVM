# SPDX-License-Identifier: Apache-2.0
import bisect, collections, gzip, hashlib, json, os, re, struct, subprocess, time
from pathlib import Path

base = Path("work/urem-research").resolve()
wt = Path("benchmarks/paper/runtimes/wasmtime-45.0.0/out/wasmtime").resolve()
out = base / "wt-profiles"
out.mkdir(exist_ok=True)
jobs = [
    ("micro-" + d, base / "profile-micro-inputs" / ("rem-" + d + ".wasm"), [])
    for d in ["3", "7", "255", "8", "dynamic"]
]
qr = Path("benchmarks/paper/benchmarks/wapm/qr2text.wasm").resolve()
jobs += [
    ("qr2text", qr, ["https://wapm.io"]),
    ("qr2text-2048", qr, ["".join(chr(33 + (i * 37) % 90) for i in range(2048))]),
]
records = []
for name, wasm, args in jobs:
    folder = out / name
    folder.mkdir(exist_ok=True)
    samples = folder / "samples.bin"
    env = {
        **os.environ,
        "LD_PRELOAD": str(base / "sampler.so"),
        "DTVM_RESEARCH_SAMPLES": str(samples),
        "LC_ALL": "C",
        "WASMTIME_CACHE": "0",
    }
    cmd = [str(wt), "run", "-C", "cache=n", "--profile=perfmap", str(wasm)] + args
    p = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        env=env,
        preexec_fn=lambda: os.sched_setaffinity(0, {0}),
    )
    mapping = Path("/tmp") / f"perf-{p.pid}.map"
    captured = False
    entries = []
    deadline = time.monotonic() + 120
    while p.poll() is None:
        if time.monotonic() > deadline:
            p.kill()
            raise TimeoutError(name)
        if mapping.exists() and not captured:
            text = mapping.read_text()
            lines = text.splitlines()
            wanted = []
            for i, line in enumerate(lines):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    continue
                label = parts[2]
                target = (
                    name.startswith("micro-")
                    and ("function[2]" in label or "kernel" in label)
                ) or (
                    not name.startswith("micro-")
                    and (
                        "QrCode" in label
                        and "new" in label
                        or "qrcode6QrCode3new" in label
                    )
                )
                if target:
                    wanted.append((i, parts))
            if wanted:
                try:
                    with Path(f"/proc/{p.pid}/mem").open("rb", buffering=0) as memory:
                        for i, (address, length, label) in wanted:
                            addr = int(address, 16)
                            size = int(length, 16)
                            memory.seek(addr)
                            data = memory.read(size)
                            assert len(data) == size
                            path = folder / f"code-{i}.bin"
                            path.write_bytes(data)
                            entries.append(
                                {
                                    "address": addr,
                                    "size": size,
                                    "name": label,
                                    "file": path.name,
                                }
                            )
                    (folder / "perf.map").write_text(text)
                    captured = True
                except (ProcessLookupError, FileNotFoundError):
                    pass
        time.sleep(0.0005)
    stdout, stderr = p.communicate(timeout=10)
    assert p.returncode == 0, (name, p.returncode, stderr[-500:])
    assert captured, (
        name,
        mapping.read_text()[:3000] if mapping.exists() else "no map",
    )
    raw = samples.read_bytes()
    pcs = [pc for pc, tid in struct.iter_unpack("<QQ", raw)]
    for e in entries:
        path = folder / e["file"]
        asm = subprocess.check_output(
            ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64", str(path)], text=True
        )
        with gzip.open(path.with_suffix(".asm.gz"), "wb") as z:
            z.write(asm.encode())
        e["samples"] = sum(e["address"] <= pc < e["address"] + e["size"] for pc in pcs)
        e["div_instructions"] = len(re.findall(r"\b(?:div|idiv)[bwlq]?\s", asm))
        e["mul_instructions"] = len(re.findall(r"\b(?:mul|imul|mulx)[bwlq]?\s", asm))
    if name.startswith("micro-"):
        assert len(stdout) == 192
        payload = [struct.unpack_from("<QQII", stdout, i * 24)[2:] for i in range(8)]
        ref = json.load(open(base / "profiles" / (name + "-main") / "profile.json"))
        assert (
            hashlib.sha256(json.dumps(payload).encode()).hexdigest()
            == ref["stdout_sha256"]
        )
    else:
        ref = json.load(open(base / "profiles" / (name + "-main") / "profile.json"))
        assert hashlib.sha256(stdout).hexdigest() == ref["stdout_sha256"]
    row = {
        "case": name,
        "command": cmd,
        "args": args,
        "input_sha256": hashlib.sha256(wasm.read_bytes()).hexdigest(),
        "binary_sha256": hashlib.sha256(wt.read_bytes()).hexdigest(),
        "exit": p.returncode,
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "total_samples": len(pcs),
        "targets": entries,
        "method": "Untimed live child perfmap code capture with same1ms SIGPROF sampler. Sampling counts are descriptive; native bytes read only from our own child. Never used for formal timing.",
    }
    (folder / "capture.json").write_text(json.dumps(row, indent=2) + "\n")
    records.append(row)
    print(
        name,
        [(e["size"], e["div_instructions"], e["samples"], e["name"]) for e in entries],
        flush=True,
    )
(out / "summary.json").write_text(json.dumps(records, indent=2) + "\n")
