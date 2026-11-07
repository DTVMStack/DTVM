# SPDX-License-Identifier: Apache-2.0
import bisect, collections, gzip, hashlib, importlib.util, json, os, re, struct, subprocess, shutil
from pathlib import Path

root = Path.cwd()
base = root / "work/urem-research"
out = base / "profiles"
out.mkdir(exist_ok=True)
s = importlib.util.spec_from_file_location("h", "benchmarks/paper/harness/run.py")
h = importlib.util.module_from_spec(s)
s.loader.exec_module(h)
catalog = {c["id"]: c for c in h.load_cases(h.read_json(h.CATALOG_PATH))}
cases = [dict(catalog[c]) for c in ["qr2text", "suggest", "viu", "bicg", "irb"]]
for length in [512, 1024, 2048]:
    cases.append(
        {
            **catalog["qr2text"],
            "id": "qr2text-" + str(length),
            "args": ["".join(chr(33 + (i * 37) % 90) for i in range(length))],
        }
    )
for d in ["3", "7", "255", "8", "dynamic"]:
    cases.append(
        {
            "id": "micro-" + d,
            "wasm": str(base / "profile-micro-inputs" / ("rem-" + d + ".wasm")),
            "kind": "wasi-main",
        }
    )
summary = []
for case in cases:
    wasm = h.paper_join(case["wasm"])
    labels = {
        int(n): name
        for n, name in re.findall(
            r"- func\[(\d+)\].*<([^\n]+)>",
            subprocess.check_output(["wasm-objdump", "-x", str(wasm)], text=True),
        )
    }
    expected = None
    for engine, binary in [
        ("main", base / "dtvm-main-diagnostic"),
        ("candidate", base / "dtvm-urem-diagnostic"),
    ]:
        folder = out / (case["id"] + "-" + engine)
        if (folder / "profile.json").exists():
            row = json.loads((folder / "profile.json").read_text())
            summary.append({k: v for k, v in row.items() if k != "events"})
            expected = (row["stdout_sha256"], row["stderr_sha256"])
            continue
        if folder.exists():
            shutil.rmtree(folder)
        folder.mkdir()
        pcfile = folder / "samples.bin"
        env = {
            **os.environ,
            "LD_PRELOAD": str(base / "sampler.so"),
            "DTVM_RESEARCH_NATIVE_DIR": str(folder),
            "DTVM_RESEARCH_SAMPLES": str(pcfile),
            "LC_ALL": "C",
        }
        cmd = h.dtvm_cmd(binary, case, "lazy-G-MT", False)
        result = subprocess.run(
            cmd,
            cwd=h.case_cwd(case),
            input=case.get("stdin", "").encode(),
            capture_output=True,
            env=env,
            timeout=180,
            preexec_fn=lambda: os.sched_setaffinity(0, {0}),
        )
        pat = rb"NATIVE (\d+) (\d+) ([0-9a-f]+) (\d+) (\d+)\n"
        events = []
        for m in re.findall(pat, result.stderr):
            idx, tier, address, size, ns = m
            idx = int(idx)
            addr = int(address, 16)
            size = int(size)
            events.append(
                {
                    "index": idx,
                    "greedy": int(tier),
                    "address": addr,
                    "size": size,
                    "compile_ns": int(ns),
                    "name": labels.get(idx, str(idx)),
                    "file": f"func-{idx}-{int(tier)}-{addr:x}.bin",
                }
            )
        clean = re.sub(pat, b"", result.stderr)
        assert result.returncode == 0, (
            case["id"],
            engine,
            result.returncode,
            clean[-1000:],
        )
        observed = result.stdout
        if case["id"].startswith("micro-"):
            assert len(observed) == 24 * 8
            packets = [struct.unpack_from("<QQII", observed, i * 24) for i in range(8)]
            assert all(t[0] <= t[1] and t[3] == i for i, t in enumerate(packets))
            observed = json.dumps([(t[2], t[3]) for t in packets]).encode()
        hashes = (
            hashlib.sha256(observed).hexdigest(),
            hashlib.sha256(clean).hexdigest(),
        )
        if expected is None:
            expected = hashes
        assert expected == hashes, (case["id"], engine, "output mismatch")
        raw = pcfile.read_bytes()
        assert len(raw) % 16 == 0 and len(raw) > 0
        samples = list(struct.iter_unpack("<QQ", raw))
        events.sort(key=lambda x: x["address"])
        starts = [e["address"] for e in events]
        hits = collections.Counter()
        for pc, tid in samples:
            i = bisect.bisect_right(starts, pc) - 1
            if i >= 0 and pc < events[i]["address"] + events[i]["size"]:
                hits[i] += 1
        for i, e in enumerate(events):
            e["samples"] = hits[i]
        targets = [
            e
            for e in events
            if (
                "qrcode6QrCode3new" in e["name"]
                or e["name"] == "main"
                or case["id"].startswith("micro-")
                and e["index"] == 2
            )
        ]
        for e in targets:
            path = folder / e["file"]
            asm = subprocess.check_output(
                ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64", str(path)],
                text=True,
            )
            e["div_instructions"] = len(re.findall(r"\b(?:div|idiv)[bwlq]?\s", asm))
            e["mul_instructions"] = len(re.findall(r"\b(?:mul|imul)[bwlq]?\s", asm))
            with gzip.open(path.with_suffix(".asm.gz"), "wb") as z:
                z.write(asm.encode())
        row = {
            "case": case["id"],
            "engine": engine,
            "command": cmd,
            "stdin": case.get("stdin", ""),
            "args": case.get("args", []),
            "wasm_sha256": hashlib.sha256(wasm.read_bytes()).hexdigest(),
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "stdout_sha256": hashes[0],
            "stderr_sha256": hashlib.sha256(clean).hexdigest(),
            "total_samples": len(samples),
            "jit_samples": sum(hits.values()),
            "events": events,
            "targets": targets,
            "method": "Untimed diagnostic executable with native dump+SIGPROF ITIMER_PROF1ms LD_PRELOAD sampler. Samples include compilation/runtime/startup and may arrive on any thread. Dump instrumentation can perturb compile budgeting. Function sample counts are descriptive, not dynamic operation counts or confidence intervals.",
        }
        (folder / "profile.json").write_text(json.dumps(row, indent=2) + "\n")
        summary.append({k: v for k, v in row.items() if k != "events"})
        print(
            case["id"],
            engine,
            "samples",
            len(samples),
            "jit",
            sum(hits.values()),
            "targets",
            [
                (e["index"], e["samples"], e.get("div_instructions"), e["size"])
                for e in targets
            ],
            flush=True,
        )
(out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
