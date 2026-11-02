#!/usr/bin/env python3
# Copyright (C) 2021-2026 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Reproducible paper-bench harness: PolyBench / fib / overflow / WAPM vs Wasmtime.

Wall time is one process invocation (startup + compile + execute + teardown),
matching Phase 1.5 notes. Wasmtime comparisons use the same .wasm where fair
and disable the module cache. See SCHEMA.md and README.md in this directory.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

HARNESS_DIR = Path(__file__).resolve().parent
PAPER_ROOT = HARNESS_DIR.parent
REPO_ROOT = PAPER_ROOT.parent.parent
CATALOG_PATH = HARNESS_DIR / "catalog.json"
SCHEMA_VERSION = "phase15-v1"

DTVM_MODE_FLAGS = {
    # Phase 1.5 names. GreedyRA is the dtvm default; FastRA is --disable-multipass-greedyra.
    "interp": ["-m", "interpreter"],
    "singlepass": ["-m", "singlepass"],
    "multipass-G-ST": ["-m", "multipass", "--disable-multipass-multithread"],
    "lazy-F-ST": [
        "-m",
        "multipass",
        "--enable-multipass-lazy",
        "--disable-multipass-greedyra",
        "--disable-multipass-multithread",
    ],
    # Paper xlsx "dtvm multipass" inferred CLI (FastRA, serial, eager).
    "multipass-F-ST": [
        "-m",
        "multipass",
        "--disable-multipass-greedyra",
        "--disable-multipass-multithread",
    ],
    "lazy-G-ST": [
        "-m",
        "multipass",
        "--enable-multipass-lazy",
        "--disable-multipass-multithread",
    ],
}

DEFAULT_DTVM_MODES = ["interp", "singlepass", "multipass-G-ST", "lazy-F-ST"]
PAPER_DTVM_MODES = ["multipass-F-ST", "lazy-F-ST"]
WASMTIME_MODE = "cranelift-nocache"

STAT_FIELDS = {
    "load_ms": re.compile(r"Load:\s+\d+ times,.*?total ([\d.]+)ms"),
    "jit_compilation_ms": re.compile(
        r"JIT Compilation:\s+\d+ times,.*?total ([\d.]+)ms"
    ),
    "jit_lazy_precompile_ms": re.compile(
        r"JIT Lazy Precompilation:\s+\d+ times,.*?total ([\d.]+)ms"
    ),
    "jit_lazy_fg_ms": re.compile(
        r"JIT Lazy Compilation\(Fg\):\s+\d+ times,.*?total ([\d.]+)ms"
    ),
    "instantiation_ms": re.compile(
        r"Instantiation:\s+\d+ times,.*?total ([\d.]+)ms"
    ),
    "execution_ms": re.compile(r"Execution:\s+\d+ times,.*?total ([\d.]+)ms"),
    "total_ms": re.compile(r"Total:\s+([\d.]+)ms"),
}


def die(msg: str, code: int = 2) -> None:
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(code)


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=False)
        fh.write("\n")


def median(xs: Sequence[float]) -> Optional[float]:
    if not xs:
        return None
    return float(statistics.median(xs))


def parse_dtvm_stats(text: str) -> Optional[Dict[str, float]]:
    if "ZetaEngine Statistics" not in text and "JIT Compilation:" not in text:
        return None
    out: Dict[str, float] = {}
    for key, cre in STAT_FIELDS.items():
        m = cre.search(text)
        if m:
            out[key] = float(m.group(1))
    return out or None


def host_info() -> Dict[str, str]:
    info = {
        "uname": " ".join(os.uname()),
        "cpu_model": "",
        "cpu_mhz": "",
        "governor": "",
        "no_turbo": "",
    }
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        text = cpuinfo.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            if line.startswith("model name") and not info["cpu_model"]:
                info["cpu_model"] = line.split(":", 1)[1].strip()
            if line.startswith("cpu MHz") and not info["cpu_mhz"]:
                info["cpu_mhz"] = line.split(":", 1)[1].strip()
    gov = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
    turbo = Path("/sys/devices/system/cpu/intel_pstate/no_turbo")
    if gov.is_file():
        info["governor"] = gov.read_text(encoding="utf-8").strip()
    if turbo.is_file():
        info["no_turbo"] = turbo.read_text(encoding="utf-8").strip()
    return info


def warn_if_debug_dtvm(dtvm: Path) -> None:
    cache = dtvm.parent / "CMakeCache.txt"
    if cache.is_file():
        for line in cache.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("CMAKE_BUILD_TYPE"):
                bt = line.split("=", 1)[-1].strip()
                if bt != "Release":
                    print(
                        f"warning: {dtvm} CMAKE_BUILD_TYPE={bt!r}; "
                        "paper timings used Release",
                        file=sys.stderr,
                    )
                return


def resolve_dtvm(explicit: Optional[str]) -> Path:
    chosen = explicit or os.environ.get("DTVM")
    if chosen:
        path = Path(chosen)
        if path.is_file() and os.access(path, os.X_OK):
            return path.resolve()
        die(f"requested dtvm binary is missing or not executable: {chosen}")
    candidates = []
    candidates.extend(
        [
            REPO_ROOT / "build-paper-bench" / "dtvm",
            REPO_ROOT / "build" / "dtvm",
            PAPER_ROOT / "runtimes" / "dtvm_main" / "dtvm",
            PAPER_ROOT / "runtimes" / "dtvm" / "dtvm",
        ]
    )
    for c in candidates:
        if c.is_file() and os.access(c, os.X_OK):
            return c.resolve()
    die(
        "dtvm binary not found. Build with harness/build_dtvm.sh or set --dtvm / $DTVM"
    )
    raise AssertionError("unreachable")


def resolve_wasmtime(explicit: Optional[str]) -> Path:
    chosen = explicit or os.environ.get("WASMTIME")
    if chosen:
        path = Path(chosen)
        if path.is_file() and os.access(path, os.X_OK):
            return path.resolve()
        die(f"requested wasmtime binary is missing or not executable: {chosen}")
    candidates = []
    which = shutil.which("wasmtime")
    if which:
        candidates.append(Path(which))
    candidates.append(PAPER_ROOT / "runtimes" / "wasmtime-45.0.0" / "out" / "wasmtime")
    for c in candidates:
        if c.is_file() and os.access(c, os.X_OK):
            return c.resolve()
    die(
        "wasmtime binary not found. Run harness/fetch_wasmtime.sh or set --wasmtime / $WASMTIME"
    )
    raise AssertionError("unreachable")


def paper_join(rel: str) -> Path:
    return PAPER_ROOT / rel


def wasm_looks_valid(path: Path) -> bool:
    if not path.is_file():
        return False
    with path.open("rb") as fh:
        magic = fh.read(4)
    return magic == b"\x00asm"


def require_wasm(path: Path) -> None:
    if wasm_looks_valid(path):
        return
    if path.is_file() and path.read_bytes()[:7] == b"version":
        die(
            f"{path} is a Git LFS pointer, not a Wasm binary. "
            "Run: git lfs pull --include 'benchmarks/paper/benchmarks/**'"
        )
    die(f"{path} is missing or not a Wasm module (expected \\0asm magic)")


def expand_polybench(catalog: Dict[str, Any]) -> List[Dict[str, Any]]:
    meta = catalog["polybench"]
    pdir = paper_join(meta["dir"])
    skip = set(meta.get("skip_interp") or [])
    cases = []
    for wasm in sorted(pdir.glob("*.wasm")):
        cid = wasm.stem
        cases.append(
            {
                "id": cid,
                "suite": "polybench",
                "wasm": str(Path(meta["dir"]) / wasm.name),
                "kind": meta["kind"],
                "fairness": meta["fairness"],
                "skip_interp": cid in skip,
            }
        )
    return cases


def load_cases(catalog: Dict[str, Any]) -> List[Dict[str, Any]]:
    cases = expand_polybench(catalog)
    cases.extend(catalog["cases"])
    ids = [c["id"] for c in cases]
    if len(ids) != len(set(ids)):
        die(f"duplicate catalog ids: {sorted({i for i in ids if ids.count(i) > 1})}")
    return cases


def select_cases(
    cases: Sequence[Dict[str, Any]],
    preset: str,
    catalog: Dict[str, Any],
    only: Optional[Sequence[str]],
    scale: str,
    suites: Optional[Sequence[str]],
) -> List[Dict[str, Any]]:
    by_id = {c["id"]: c for c in cases}
    wanted: List[str]
    spec = catalog["presets"].get(preset, preset)
    if only:
        wanted = list(only)
    elif spec == "polybench":
        wanted = [c["id"] for c in cases if c["suite"] == "polybench"]
    elif spec == "wapm":
        wanted = [c["id"] for c in cases if c["suite"] == "wapm"]
    elif spec == "all":
        wanted = [c["id"] for c in cases]
    elif isinstance(spec, list):
        wanted = list(spec)
    else:
        die(f"unknown preset {preset!r}")

    if scale == "paper" and preset in ("fib", "overflow") and not only:
        # Rewrite before filtering: these presets name the dev cases.
        wanted = [cid.replace("_dev", "_paper") for cid in wanted]

    out = []
    for cid in wanted:
        if cid not in by_id:
            die(f"unknown case id {cid!r}")
        case = by_id[cid]
        case_scale = case.get("scale")
        if (
            case_scale
            and case_scale != scale
            and not only
            and preset not in ("smoke", "phase15")
        ):
            # scale-tagged cases are included only when --scale matches, except
            # smoke/phase15 which name explicit *_dev ids.
            continue
        if suites and case["suite"] not in suites:
            continue
        out.append(case)
    return out


def dtvm_cmd(
    dtvm: Path,
    case: Dict[str, Any],
    mode: str,
    stats: bool,
) -> List[str]:
    if mode not in DTVM_MODE_FLAGS:
        die(f"unknown dtvm mode {mode!r}")
    wasm = str(paper_join(case["wasm"]))
    cmd = [str(dtvm)]
    cmd.extend(DTVM_MODE_FLAGS[mode])
    if stats:
        cmd.append("--enable-statistics")
    kind = case.get("kind", "wasi-main")
    if kind == "reactor":
        cmd.extend(["-f", case["function"]])
    # INPUT_FILE must precede --dir: CLI11 treats --dir as a vector and will
    # otherwise swallow the wasm path ("INPUT_FILE is required").
    cmd.append(wasm)
    for d in case.get("dirs") or []:
        cmd.append(f"--dir={d}")
    args = case.get("args") or []
    if args:
        cmd.append("--args")
        cmd.extend(str(a) for a in args)
    return cmd


def wasmtime_cmd(wt: Path, case: Dict[str, Any]) -> List[str]:
    wasm = str(paper_join(case["wasm"]))
    cmd = [str(wt), "run", "-C", "cache=n"]
    for d in case.get("dirs") or []:
        cmd.extend(["--dir", d])
    kind = case.get("kind", "wasi-main")
    if kind == "reactor":
        cmd.extend(["--invoke", case["function"]])
        cmd.append(wasm)
        cmd.extend(str(a) for a in (case.get("args") or []))
    else:
        invoke = case.get("wasmtime_invoke")
        if invoke:
            cmd.extend(["--invoke", invoke])
        cmd.append(wasm)
        cmd.extend(str(a) for a in (case.get("args") or []))
    return cmd


def pin_prefix(cpu: Optional[int]) -> List[str]:
    if cpu is None:
        return []
    taskset = shutil.which("taskset")
    if not taskset:
        print("warning: taskset not found; running unpinned", file=sys.stderr)
        return []
    return [taskset, "-c", str(cpu)]


def case_cwd(case: Dict[str, Any]) -> Path:
    rel = case.get("cwd")
    return paper_join(rel) if rel else REPO_ROOT


def allowed_runtime(case: Dict[str, Any], runtime: str) -> bool:
    allowed = case.get("runtimes")
    if allowed:
        return runtime in allowed
    if case.get("fairness") == "dtvm-hostapi-only" and runtime != "dtvm":
        return False
    return True


def time_once(
    cmd: Sequence[str],
    cwd: Path,
    stdin: Optional[str],
    timeout: float,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            list(cmd),
            cwd=str(cwd),
            input=stdin,
            text=True,
            errors="replace",
            capture_output=True,
            timeout=timeout,
            env=merged_env,
        )
        elapsed = time.perf_counter() - t0
        combined = (proc.stdout or "") + (proc.stderr or "")
        return {
            "ok": proc.returncode == 0,
            "exit": proc.returncode,
            "wall_s": elapsed,
            "output": combined,
            "timeout": False,
        }
    except subprocess.TimeoutExpired as exc:
        elapsed = time.perf_counter() - t0
        out = ""
        if exc.stdout:
            out += exc.stdout if isinstance(exc.stdout, str) else exc.stdout.decode(
                "utf-8", "replace"
            )
        if exc.stderr:
            out += exc.stderr if isinstance(exc.stderr, str) else exc.stderr.decode(
                "utf-8", "replace"
            )
        return {
            "ok": False,
            "exit": None,
            "wall_s": elapsed,
            "output": out,
            "timeout": True,
        }
    except OSError as exc:
        return {
            "ok": False,
            "exit": None,
            "wall_s": time.perf_counter() - t0,
            "output": f"{type(exc).__name__}: {exc}",
            "timeout": False,
        }


def run_cell(
    cmd: Sequence[str],
    cwd: Path,
    stdin: Optional[str],
    warmup: int,
    repeats: int,
    timeout: float,
    env: Optional[Dict[str, str]],
    keep_output: bool,
) -> Dict[str, Any]:
    samples: List[float] = []
    exits: List[Optional[int]] = []
    stats_samples: List[Dict[str, float]] = []
    timed_out_samples = 0
    last_output = ""
    last_failure_output = ""
    for _ in range(warmup):
        r = time_once(cmd, cwd, stdin, timeout, env)
        last_output = r["output"]
        if not r["ok"]:
            break
    else:
        r = {"ok": True, "exit": 0, "timeout": False}
    if warmup and not r["ok"]:
        return {
            "ok": False,
            "exit": r.get("exit"),
            "timeout": r.get("timeout", False),
            "sample_exits": [],
            "failed_samples": 0,
            "timed_out_samples": 0,
            "samples_s": [],
            "median_s": None,
            "min_s": None,
            "max_s": None,
            "statistics": None,
            "output_tail": last_output[-4000:],
        }
    for _ in range(repeats):
        r = time_once(cmd, cwd, stdin, timeout, env)
        last_output = r["output"]
        exits.append(r["exit"])
        timed_out_samples += int(r["timeout"])
        if not r["ok"] and r["output"]:
            last_failure_output = r["output"]
        if r["ok"]:
            samples.append(float(r["wall_s"]))
            parsed = parse_dtvm_stats(r["output"])
            if parsed:
                stats_samples.append(parsed)
    stats_med: Optional[Dict[str, float]] = None
    if stats_samples:
        keys = sorted({k for s in stats_samples for k in s})
        stats_med = {
            k: float(statistics.median([s[k] for s in stats_samples if k in s]))
            for k in keys
            if any(k in s for s in stats_samples)
        }
    return {
        "ok": len(samples) == repeats and repeats > 0,
        "exit": exits[-1] if exits else None,
        "timeout": timed_out_samples > 0,
        "sample_exits": exits,
        "failed_samples": len(exits) - len(samples),
        "timed_out_samples": timed_out_samples,
        "samples_s": samples,
        "median_s": median(samples),
        "min_s": min(samples) if samples else None,
        "max_s": max(samples) if samples else None,
        "statistics": stats_med,
        "output_tail": (
            (last_failure_output or last_output)[-4000:]
            if keep_output or len(samples) != repeats else ""
        ),
    }


def markdown_table(runs: Sequence[Dict[str, Any]]) -> str:
    benches = []
    seen = set()
    for r in runs:
        if r["bench"] not in seen:
            seen.add(r["bench"])
            benches.append(r["bench"])
    cols: List[Tuple[str, str]] = []
    col_seen = set()
    for r in runs:
        key = (r["runtime"], r["mode"])
        if key not in col_seen:
            col_seen.add(key)
            cols.append(key)
    header = ["bench", "fairness"] + [f"{rt}/{mode}" for rt, mode in cols]
    lines = [
        "| " + " | ".join(header) + " |",
        "|" + "|".join(["---"] * len(header)) + "|",
    ]
    for bench in benches:
        fairness = next(r["fairness"] for r in runs if r["bench"] == bench)
        row = [bench, fairness]
        for rt, mode in cols:
            cell = next(
                (
                    x
                    for x in runs
                    if x["bench"] == bench and x["runtime"] == rt and x["mode"] == mode
                ),
                None,
            )
            if cell is None:
                row.append("—")
            elif cell.get("skipped"):
                row.append("skip")
            elif not cell.get("ok", True) or cell["median_s"] is None:
                row.append("fail")
            else:
                row.append(f"{cell['median_s']:.4f}")
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")
    lines.append("Values are median wall seconds of successful samples (warmup discarded).")
    return "\n".join(lines) + "\n"


def selftest() -> int:
    catalog = read_json(CATALOG_PATH)
    cases = load_cases(catalog)
    assert any(c["id"] == "atax" for c in cases), "polybench discovery failed"
    assert any(c["id"] == "figlet" for c in cases)
    smoke = select_cases(cases, "smoke", catalog, None, "dev", None)
    assert [c["id"] for c in smoke] == [
        "atax",
        "fib_iter_dev",
        "overflow_dtvm_dev",
        "overflow_non_dtvm_dev",
        "figlet",
    ]

    dtvm = Path("/tmp/fake-dtvm")
    wt = Path("/tmp/fake-wasmtime")
    atax = next(c for c in cases if c["id"] == "atax")
    dcmd = dtvm_cmd(dtvm, atax, "multipass-G-ST", stats=True)
    assert dcmd[:1] == [str(dtvm)]
    assert "-m" in dcmd and "multipass" in dcmd
    assert "--disable-multipass-multithread" in dcmd
    assert "--enable-statistics" in dcmd
    assert dcmd[-1].endswith("atax.wasm")
    wcmd = wasmtime_cmd(wt, atax)
    assert wcmd[1:4] == ["run", "-C", "cache=n"]
    assert "--invoke" not in wcmd
    assert "cache=y" not in wcmd

    fib = next(c for c in cases if c["id"] == "fib_iter_dev")
    fcmd = dtvm_cmd(dtvm, fib, "lazy-F-ST", stats=False)
    assert "-f" in fcmd and "test_fib_iter" in fcmd
    assert "--args" in fcmd and "1000000" in fcmd
    fw = wasmtime_cmd(wt, fib)
    assert "--invoke" in fw and "test_fib_iter" in fw
    assert "500000000" not in fw

    ov_dtvm = next(c for c in cases if c["id"] == "overflow_dtvm_dev")
    assert ov_dtvm["fairness"] == "dtvm-hostapi-only"
    assert not allowed_runtime(ov_dtvm, "wasmtime")
    assert allowed_runtime(ov_dtvm, "dtvm")
    ov_wt = next(c for c in cases if c["id"] == "overflow_non_dtvm_dev")
    assert ov_wt["fairness"] == "different-wasm"
    assert allowed_runtime(ov_wt, "wasmtime")
    assert not allowed_runtime(ov_wt, "dtvm")

    fig = next(c for c in cases if c["id"] == "figlet")
    fdt = dtvm_cmd(dtvm, fig, "singlepass", stats=False)
    assert any(a == "--dir=fonts" or a.startswith("--dir=fonts") for a in fdt)
    assert fdt.index(str(paper_join(fig["wasm"]))) < next(
        i for i, a in enumerate(fdt) if a.startswith("--dir=")
    )
    assert "--args" in fdt and "hello" in fdt
    fwt = wasmtime_cmd(wt, fig)
    assert "--dir" in fwt and "fonts" in fwt and "hello" in fwt

    sample = (
        "================  [Begin] ZetaEngine Statistics  ================\n"
        "Load:\t\t\t1 times, avg 1.000ms, total 1.000ms, 1.00%\n"
        "JIT Compilation:\t\t1 times, avg 87.000ms, total 87.000ms, 54.00%\n"
        "Execution:\t\t1 times, avg 72.100ms, total 72.100ms, 45.00%\n"
        "Total:\t\t160.100ms\n"
        "=================  [End] ZetaEngine Statistics =================\n"
    )
    parsed = parse_dtvm_stats(sample)
    assert parsed is not None
    assert parsed["jit_compilation_ms"] == 87.0
    assert parsed["execution_ms"] == 72.1
    assert parsed["total_ms"] == 160.1

    assert median([3.0, 1.0, 2.0]) == 2.0
    assert median([1.0, 2.0]) == 1.5
    assert median([]) is None

    missing = [
        c["wasm"]
        for c in cases
        if not paper_join(c["wasm"]).is_file()
    ]
    assert not missing, f"catalog wasm missing: {missing[:5]}"
    pointers = [
        c["wasm"]
        for c in cases
        if paper_join(c["wasm"]).is_file()
        and not wasm_looks_valid(paper_join(c["wasm"]))
    ]
    if pointers:
        print(
            f"selftest: note {len(pointers)} wasm files are LFS pointers "
            "(run git lfs pull); command construction still checked"
        )

    fake_runs = [
        {
            "bench": "atax",
            "fairness": "same-wasm",
            "runtime": "dtvm",
            "mode": "singlepass",
            "median_s": 0.0754,
        },
        {
            "bench": "atax",
            "fairness": "same-wasm",
            "runtime": "wasmtime",
            "mode": WASMTIME_MODE,
            "median_s": 0.08,
        },
    ]
    md = markdown_table(fake_runs)
    assert "atax" in md and "same-wasm" in md

    print("selftest: ok")
    print(f"  cases={len(cases)} polybench="
          f"{sum(1 for c in cases if c['suite']=='polybench')} "
          f"wapm={sum(1 for c in cases if c['suite']=='wapm')}")
    return 0


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="DTVM paper-bench harness (PolyBench/fib/overflow/WAPM vs Wasmtime)"
    )
    p.add_argument(
        "--preset",
        default="smoke",
        choices=["smoke", "phase15", "polybench", "fib", "overflow", "wapm", "all"],
    )
    p.add_argument("--cases", help="comma-separated case ids (overrides preset)")
    p.add_argument("--suites", help="comma-separated suite filter")
    p.add_argument(
        "--scale",
        default="dev",
        choices=["dev", "paper"],
        help="fib/overflow iteration scale (dev=1e6, paper=500M/100M)",
    )
    p.add_argument("--runtimes", default="dtvm,wasmtime")
    p.add_argument(
        "--dtvm-modes",
        default=",".join(DEFAULT_DTVM_MODES),
        help="comma-separated dtvm modes",
    )
    p.add_argument(
        "--paper-modes",
        action="store_true",
        help="use paper xlsx dtvm modes (multipass-F-ST, lazy-F-ST) instead of Phase 1.5",
    )
    p.add_argument("--warmup", type=int, default=1)
    p.add_argument("--repeats", type=int, default=3)
    p.add_argument("--cpu", type=int, default=0, help="taskset CPU index; -1 disables")
    p.add_argument("--timeout", type=float, default=600.0)
    p.add_argument(
        "--stats",
        action="store_true",
        help="collect DTVM statistics in a separate instrumented pass",
    )
    p.add_argument("--dtvm")
    p.add_argument("--wasmtime")
    p.add_argument("--out", help="output directory (default raw_data/harness/<stamp>)")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--selftest", action="store_true")
    p.add_argument("--keep-output", action="store_true")
    p.add_argument(
        "--include-interp-heavy",
        action="store_true",
        help="do not skip interp on catalog skip_interp cases (e.g. jacobi-2d)",
    )
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_argparser().parse_args(argv)
    if args.selftest:
        return selftest()
    if args.repeats < 1 or args.warmup < 0 or args.timeout <= 0:
        die("--repeats must be positive, --warmup non-negative, and --timeout positive")

    catalog = read_json(CATALOG_PATH)
    all_cases = load_cases(catalog)
    only = [s.strip() for s in args.cases.split(",") if s.strip()] if args.cases else None
    suites = (
        [s.strip() for s in args.suites.split(",") if s.strip()] if args.suites else None
    )
    selected = select_cases(all_cases, args.preset, catalog, only, args.scale, suites)
    if not selected:
        die("no cases selected")
    if not args.dry_run:
        for case in selected:
            require_wasm(paper_join(case["wasm"]))

    runtimes = [s.strip() for s in args.runtimes.split(",") if s.strip()]
    for rt in runtimes:
        if rt not in ("dtvm", "wasmtime"):
            die(f"unsupported runtime {rt!r} (dtvm|wasmtime)")
    dtvm_modes = (
        list(PAPER_DTVM_MODES)
        if args.paper_modes
        else [s.strip() for s in args.dtvm_modes.split(",") if s.strip()]
    )
    for mode in dtvm_modes:
        if mode not in DTVM_MODE_FLAGS:
            die(f"unknown dtvm mode {mode!r}; known: {sorted(DTVM_MODE_FLAGS)}")

    cpu = None if args.cpu < 0 else args.cpu
    prefix = pin_prefix(cpu)

    dtvm_bin = None
    wt_bin = None
    if "dtvm" in runtimes and not args.dry_run:
        dtvm_bin = resolve_dtvm(args.dtvm)
        warn_if_debug_dtvm(dtvm_bin)
    elif "dtvm" in runtimes:
        dtvm_bin = Path(args.dtvm) if args.dtvm else Path("${DTVM}")
    if "wasmtime" in runtimes and not args.dry_run:
        wt_bin = resolve_wasmtime(args.wasmtime)
    elif "wasmtime" in runtimes:
        wt_bin = Path(args.wasmtime) if args.wasmtime else Path("${WASMTIME}")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = (
        Path(args.out)
        if args.out
        else PAPER_ROOT / "raw_data" / "harness" / f"{args.preset}_{stamp}"
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    plan = []
    for case in selected:
        for rt in runtimes:
            if not allowed_runtime(case, rt):
                continue
            if rt == "dtvm":
                modes = list(dtvm_modes)
                if case.get("skip_interp") and not args.include_interp_heavy:
                    modes = [m for m in modes if m != "interp"]
            else:
                modes = [WASMTIME_MODE]
            for mode in modes:
                if rt == "dtvm":
                    cmd = dtvm_cmd(dtvm_bin, case, mode, stats=False)
                    env = None
                else:
                    cmd = wasmtime_cmd(wt_bin, case)
                    env = {"WASMTIME_CACHE": "0"}
                full = prefix + cmd
                plan.append((case, rt, mode, full, env))

    if args.dry_run:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "preset": args.preset,
            "scale": args.scale,
            "commands": [
                {
                    "bench": case["id"],
                    "suite": case["suite"],
                    "runtime": rt,
                    "mode": mode,
                    "fairness": case.get("fairness", "same-wasm"),
                    "cwd": str(case_cwd(case)),
                    "command": full,
                    "instrumented_command": (
                        prefix + dtvm_cmd(dtvm_bin, case, mode, stats=True)
                        if rt == "dtvm" and args.stats else None
                    ),
                    "stdin": case.get("stdin"),
                }
                for case, rt, mode, full, _env in plan
            ],
        }
        write_json(out_dir / "commands.json", payload)
        print(json.dumps(payload, indent=2))
        print(f"wrote {out_dir / 'commands.json'}")
        return 0

    runs = []
    total = len(plan)
    for i, (case, rt, mode, cmd, env) in enumerate(plan, 1):
        print(
            f"[{i}/{total}] {rt}/{mode} {case['id']}",
            flush=True,
        )
        cell = run_cell(
            cmd,
            case_cwd(case),
            case.get("stdin"),
            args.warmup,
            args.repeats,
            args.timeout,
            env,
            args.keep_output,
        )
        instrumented = None
        if rt == "dtvm" and args.stats and cell["ok"]:
            instrumented_cmd = prefix + dtvm_cmd(dtvm_bin, case, mode, stats=True)
            instrumented = run_cell(
                instrumented_cmd, case_cwd(case), case.get("stdin"),
                args.warmup, args.repeats, args.timeout, env, args.keep_output
            )
            instrumented["command"] = instrumented_cmd
        rec = {
            "bench": case["id"],
            "suite": case["suite"],
            "wasm": case["wasm"],
            "fairness": case.get("fairness", "same-wasm"),
            "runtime": rt,
            "mode": mode,
            "command": cmd,
            "cwd": str(case_cwd(case)),
            "exit": cell["exit"],
            "timeout": cell["timeout"] or bool(instrumented and instrumented["timeout"]),
            "sample_exits": cell["sample_exits"],
            "failed_samples": cell["failed_samples"],
            "timed_out_samples": cell["timed_out_samples"],
            "ok": cell["ok"] and (instrumented is None or instrumented["ok"]),
            "wall_ok": cell["ok"],
            "samples_s": cell["samples_s"],
            "median_s": cell["median_s"],
            "min_s": cell["min_s"],
            "max_s": cell["max_s"],
            "statistics": (instrumented or cell)["statistics"],
            "instrumented": instrumented,
        }
        if cell.get("output_tail") and (args.keep_output or not cell["ok"]):
            rec["output_tail"] = cell["output_tail"]
        if instrumented and instrumented.get("output_tail"):
            rec["output_tail"] = instrumented["output_tail"]
        runs.append(rec)
        med = rec["median_s"] if rec["ok"] else None
        print(
            f"    median_s={med if med is not None else 'fail'} "
            f"n={len(rec['samples_s'])} fairness={rec['fairness']}",
            flush=True,
        )

    result = {
        "schema_version": SCHEMA_VERSION,
        "generated_utc": stamp,
        "host": host_info(),
        "config": {
            "preset": args.preset,
            "scale": args.scale,
            "cpu": cpu,
            "warmup": args.warmup,
            "repeats": args.repeats,
            "timeout_s": args.timeout,
            "stats": bool(args.stats),
            "statistics_separate_pass": bool(args.stats),
            "dtvm": str(dtvm_bin) if dtvm_bin else None,
            "wasmtime": str(wt_bin) if wt_bin else None,
            "dtvm_modes": dtvm_modes,
            "runtimes": runtimes,
            "repo": str(REPO_ROOT),
        },
        "fairness_notes": catalog.get("notes", {}),
        "runs": runs,
    }
    raw_path = out_dir / "results.json"
    md_path = out_dir / "median-table.md"
    write_json(raw_path, result)
    md_path.write_text(markdown_table(runs), encoding="utf-8")
    print(f"wrote {raw_path}")
    print(f"wrote {md_path}")
    print(markdown_table(runs))
    failed = [r for r in runs if not r["ok"]]
    if failed:
        print(f"warning: {len(failed)} failed cells", file=sys.stderr)
        return 1
    if not any(r["ok"] for r in runs):
        print("error: no benchmark cells executed successfully", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
