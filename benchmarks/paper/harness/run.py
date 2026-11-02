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
SCHEMA_VERSION = "paper-bench-v1"

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
    # TTFI scripts' "greedy RA + multithread fully on" (not Phase 1.5 serial).
    "multipass-G-MT": ["-m", "multipass"],
    "lazy-G-MT": ["-m", "multipass", "--enable-multipass-lazy"],
}

DEFAULT_DTVM_MODES = ["interp", "singlepass", "multipass-G-ST", "lazy-F-ST"]
PAPER_DTVM_MODES = ["multipass-F-ST", "lazy-F-ST"]
WASMTIME_MODE = "cranelift-nocache"

# Older CSV/TTFI script profile names → canonical schema modes.
MODE_ALIASES = {
    "interpreter": "interp",
    "interp": "interp",
    "sp": "singlepass",
    "singlepass": "singlepass",
    "lazy": "lazy-F-ST",
    "dtvm multipass + lazy": "lazy-F-ST",
    "lazy-f-st": "lazy-F-ST",
    "multipass": "multipass-F-ST",
    "multipass-f-st": "multipass-F-ST",
    "multipass-g-st": "multipass-G-ST",
    "multipass_greedy_mt": "multipass-G-MT",
    "lazy_greedy_mt": "lazy-G-MT",
    "default": WASMTIME_MODE,
    "wasmtime": WASMTIME_MODE,
    "cranelift": WASMTIME_MODE,
    "cranelift-nocache": WASMTIME_MODE,
    "nocache": WASMTIME_MODE,
}

TTFI_COMPILE_RE = re.compile(
    r"Total compilation time:\s*(\d+)\s*ms\s*\((\d+)\s*[μµ]s\)"
)
TTFI_EXEC_RE = re.compile(r"Execution\s+\d+:\s*([\d.]+)\s*ms")
STAT_COUNT_TOTAL_RE = re.compile(
    r"JIT Lazy Compilation\(Fg\):\s+(\d+) times,.*?total ([\d.]+)ms"
)

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


def canonicalize_mode(name: str) -> str:
    key = name.strip()
    mapped = MODE_ALIASES.get(key) or MODE_ALIASES.get(key.lower())
    if mapped:
        return mapped
    if key in DTVM_MODE_FLAGS or key == WASMTIME_MODE:
        return key
    die(
        f"unknown mode {name!r}; canonical: "
        f"{sorted(set(DTVM_MODE_FLAGS) | {WASMTIME_MODE})}"
    )
    raise AssertionError("unreachable")


def parse_dtvm_stats(text: str) -> Optional[Dict[str, float]]:
    if "ZetaEngine Statistics" not in text and "JIT Compilation:" not in text:
        return None
    out: Dict[str, float] = {}
    for key, cre in STAT_FIELDS.items():
        m = cre.search(text)
        if m:
            out[key] = float(m.group(1))
    fg = STAT_COUNT_TOTAL_RE.search(text)
    if fg:
        out["jit_lazy_fg_count"] = float(fg.group(1))
        out["jit_lazy_fg_ms"] = float(fg.group(2))
        count = int(fg.group(1))
        if count > 0 and all(
            key in out for key in ("load_ms", "jit_lazy_precompile_ms", "instantiation_ms")
        ):
            out["ttfi_est_ms"] = (
                out["load_ms"]
                + out["jit_lazy_precompile_ms"]
                + out["instantiation_ms"]
                + (out["jit_lazy_fg_ms"] / count)
            )
    return out or None


def empty_ttfi(reason: str) -> Dict[str, Any]:
    return {
        "ttfi_ms": None,
        "ttfi_source": None,
        "compile_ms": None,
        "ttfi_est_ms": None,
        "execution_ms": None,
        "ttfi_unavailable": reason,
    }


def parse_ttfi(text: str, stats: Optional[Dict[str, float]]) -> Dict[str, Any]:
    """Keep compilation time and the legacy lazy estimate separate from TTFI.

    Neither total compilation nor average foreground JIT measures the interval
    to the first invocation. No currently supported report measures that
    interval, so ttfi_ms remains null, even when diagnostics are available.
    """
    rec = empty_ttfi("not-instrumented")
    cm = TTFI_COMPILE_RE.search(text)
    if cm:
        rec["compile_ms"] = int(cm.group(2)) / 1000.0
    em = TTFI_EXEC_RE.search(text)
    if em:
        rec["execution_ms"] = float(em.group(1))
    if stats and stats.get("ttfi_est_ms") is not None:
        rec["ttfi_est_ms"] = float(stats["ttfi_est_ms"])
    if rec["compile_ms"] is not None or rec["ttfi_est_ms"] is not None:
        rec["ttfi_unavailable"] = "not-measured"
    return rec


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


def find_executable(explicit: Optional[str], extra: Sequence[Path]) -> Optional[Path]:
    candidates: List[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    for c in extra:
        candidates.append(c)
    for c in candidates:
        if c.is_file() and os.access(c, os.X_OK):
            return c.resolve()
    return None


def find_wasmtime(explicit: Optional[str]) -> Optional[Path]:
    # An explicit or env path that is not executable is a miss (skip, do not
    # silently pick another binary or invent timings).
    if explicit:
        return find_executable(explicit, [])
    env = os.environ.get("WASMTIME")
    if env:
        return find_executable(env, [])
    extra: List[Path] = []
    which = shutil.which("wasmtime")
    if which:
        extra.append(Path(which))
    extra.append(PAPER_ROOT / "runtimes" / "wasmtime-45.0.0" / "out" / "wasmtime")
    return find_executable(None, extra)


def find_wasmer(explicit: Optional[str] = None) -> Optional[Path]:
    if explicit:
        return find_executable(explicit, [])
    env = os.environ.get("WASMER")
    if env:
        return find_executable(env, [])
    extra: List[Path] = []
    which = shutil.which("wasmer")
    if which:
        extra.append(Path(which))
    extra.extend(
        [
            PAPER_ROOT / "runtimes" / "wasmer-7.1.0" / "out" / "bin" / "wasmer",
            PAPER_ROOT / "runtimes" / "wasmer-7.1.0" / "out" / "wasmer",
        ]
    )
    return find_executable(None, extra)


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
    ttfi_samples: List[Dict[str, Any]] = []
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
            "ttfi": empty_ttfi("warmup-failed"),
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
            ttfi_samples.append(parse_ttfi(r["output"], parsed))
    stats_med: Optional[Dict[str, float]] = None
    if stats_samples:
        keys = sorted({k for s in stats_samples for k in s})
        stats_med = {
            k: float(statistics.median([s[k] for s in stats_samples if k in s]))
            for k in keys
            if any(k in s for s in stats_samples)
        }
    ttfi_med = empty_ttfi("not-instrumented")
    metric_samples = {}
    # Do not publish a median from only the subset that emitted a metric.
    # Wall measurements may still succeed when optional diagnostics are absent.
    for key in ("ttfi_ms", "compile_ms", "ttfi_est_ms", "execution_ms"):
        vals = [t[key] for t in ttfi_samples if t.get(key) is not None]
        metric_samples[key] = len(vals)
        if len(vals) == repeats and repeats > 0:
            ttfi_med[key] = float(statistics.median(vals))
    if len(samples) != repeats:
        ttfi_med["ttfi_unavailable"] = "incomplete-measurements"
    elif ttfi_med["compile_ms"] is not None or ttfi_med["ttfi_est_ms"] is not None:
        ttfi_med["ttfi_unavailable"] = "not-measured"
    elif any(metric_samples.values()):
        ttfi_med["ttfi_unavailable"] = "incomplete-metric-samples"
    ttfi_med["metric_samples"] = metric_samples
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
        "ttfi": ttfi_med,
        "output_tail": (
            (last_failure_output or last_output)[-4000:]
            if keep_output or len(samples) != repeats else ""
        ),
    }


def skipped_cell(reason: str) -> Dict[str, Any]:
    return {
        "ok": False,
        "skipped": True,
        "skip_reason": reason,
        "exit": None,
        "timeout": False,
        "sample_exits": [],
        "failed_samples": 0,
        "timed_out_samples": 0,
        "samples_s": [],
        "median_s": None,
        "min_s": None,
        "max_s": None,
        "statistics": None,
        "ttfi": empty_ttfi(reason),
        "output_tail": "",
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

    assert canonicalize_mode("lazy") == "lazy-F-ST"
    assert canonicalize_mode("multipass") == "multipass-F-ST"
    assert canonicalize_mode("multipass_greedy_mt") == "multipass-G-MT"
    assert canonicalize_mode("default") == WASMTIME_MODE

    ttfi_line = "Total compilation time: 12 ms (12345 μs)\nExecution 0: 3.5 ms\n"
    ttfi = parse_ttfi(ttfi_line, None)
    assert ttfi["compile_ms"] == 12.345
    assert ttfi["ttfi_ms"] is None
    assert ttfi["ttfi_unavailable"] == "not-measured"
    assert ttfi["execution_ms"] == 3.5
    stock = parse_ttfi("wasmtime 45.0.0\n", None)
    assert stock["ttfi_ms"] is None
    assert stock["ttfi_unavailable"] == "not-instrumented"
    lazy_stats_txt = (
        "Load:\t\t\t1 times, avg 1.000ms, total 1.200ms, 1.00%\n"
        "JIT Lazy Precompilation:\t1 times, avg 0.400ms, total 0.400ms, 1.00%\n"
        "JIT Lazy Compilation(Fg):\t2 times, avg 3.000ms, total 6.000ms, 1.00%\n"
        "Instantiation:\t\t1 times, avg 0.100ms, total 0.100ms, 1.00%\n"
        "================  [Begin] ZetaEngine Statistics  ================\n"
    )
    lazy_stats = parse_dtvm_stats(lazy_stats_txt)
    assert lazy_stats is not None
    assert abs(lazy_stats["ttfi_est_ms"] - (1.2 + 0.4 + 0.1 + 6.0 / 2)) < 1e-9
    est = parse_ttfi("no compile line", lazy_stats)
    assert est["ttfi_est_ms"] == lazy_stats["ttfi_est_ms"]
    assert est["ttfi_ms"] is None

    assert find_wasmtime("/no-such-wasmtime-binary") is None

    skip = skipped_cell("wasmtime-not-found")
    assert skip["skipped"] is True
    assert skip["median_s"] is None
    assert skip["ttfi"]["ttfi_ms"] is None

    skip_md = markdown_table(
        [
            {
                "bench": "atax",
                "fairness": "same-wasm",
                "runtime": "wasmtime",
                "mode": WASMTIME_MODE,
                "median_s": None,
                "skipped": True,
            }
        ]
    )
    assert "skip" in skip_md
    assert "0.0" not in skip_md

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
    p.add_argument(
        "--runtimes",
        default="dtvm,wasmtime",
        help="comma-separated: dtvm,wasmtime,wasmer (wasmer is skip-only unless present)",
    )
    p.add_argument(
        "--dtvm-modes",
        default=",".join(DEFAULT_DTVM_MODES),
        help="comma-separated dtvm modes (aliases: lazy, multipass, multipass_greedy_mt)",
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
    p.add_argument(
        "--metric",
        default="wall",
        choices=["wall", "ttfi", "both"],
        help="wall = process seconds; ttfi/both also collect compile and lazy-estimate diagnostics; measured TTFI remains unavailable",
    )
    p.add_argument(
        "--require-wasmtime",
        action="store_true",
        help="exit 2 if a Wasmtime binary is required but missing (default: skip, no invented numbers)",
    )
    p.add_argument("--dtvm")
    p.add_argument("--wasmtime")
    p.add_argument("--wasmer")
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

    runtimes = [s.strip() for s in args.runtimes.split(",") if s.strip()]
    for rt in runtimes:
        if rt not in ("dtvm", "wasmtime", "wasmer"):
            die(f"unsupported runtime {rt!r} (dtvm|wasmtime|wasmer)")
    dtvm_modes = (
        list(PAPER_DTVM_MODES)
        if args.paper_modes
        else [
            canonicalize_mode(s.strip())
            for s in args.dtvm_modes.split(",")
            if s.strip()
        ]
    )
    for mode in dtvm_modes:
        if mode not in DTVM_MODE_FLAGS:
            die(f"unknown dtvm mode {mode!r}; known: {sorted(DTVM_MODE_FLAGS)}")

    want_stats = bool(args.stats) or args.metric in ("ttfi", "both")
    cpu = None if args.cpu < 0 else args.cpu
    prefix = pin_prefix(cpu)

    dtvm_bin = None
    wt_bin = None
    skipped_runtimes: List[Dict[str, Any]] = []
    if "dtvm" in runtimes and not args.dry_run:
        dtvm_bin = resolve_dtvm(args.dtvm)
        warn_if_debug_dtvm(dtvm_bin)
    elif "dtvm" in runtimes:
        dtvm_bin = Path(args.dtvm) if args.dtvm else Path("${DTVM}")
    if "wasmtime" in runtimes:
        if args.dry_run:
            found = find_wasmtime(args.wasmtime)
            wt_bin = found if found else (
                Path(args.wasmtime) if args.wasmtime else Path("${WASMTIME}")
            )
        else:
            wt_bin = find_wasmtime(args.wasmtime)
            if wt_bin is None:
                reason = "wasmtime-not-found"
                skipped_runtimes.append({"runtime": "wasmtime", "reason": reason})
                print(
                    "warning: Wasmtime binary not found; skipping Wasmtime cells "
                    "(no invented numbers). Fetch with harness/fetch_wasmtime.sh "
                    "or pass --wasmtime. Use --require-wasmtime to fail instead.",
                    file=sys.stderr,
                )
                if args.require_wasmtime:
                    die(reason)
    if "wasmer" in runtimes:
        wm = find_wasmer(args.wasmer)
        if wm is None:
            skipped_runtimes.append(
                {"runtime": "wasmer", "reason": "wasmer-not-found"}
            )
            print(
                "warning: Wasmer binary not found; skipping Wasmer "
                "(no invented numbers).",
                file=sys.stderr,
            )
        else:
            skipped_runtimes.append(
                {
                    "runtime": "wasmer",
                    "reason": "wasmer-runner-not-in-this-harness",
                    "binary": str(wm),
                }
            )
            print(
                "warning: Wasmer is present but this harness does not emit "
                "Wasmer timings (avoid mixing unrun numbers).",
                file=sys.stderr,
            )

    will_execute = (not args.dry_run) and (
        ("dtvm" in runtimes and dtvm_bin is not None)
        or ("wasmtime" in runtimes and wt_bin is not None)
    )
    if will_execute:
        for case in selected:
            require_wasm(paper_join(case["wasm"]))

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
            if rt == "wasmer":
                continue
            if not allowed_runtime(case, rt):
                continue
            if rt == "dtvm":
                modes = list(dtvm_modes)
                if case.get("skip_interp") and not args.include_interp_heavy:
                    modes = [m for m in modes if m != "interp"]
            elif rt == "wasmtime":
                modes = [WASMTIME_MODE]
            else:
                continue
            for mode in modes:
                skip_reason = None
                env = None
                if rt == "dtvm":
                    # Published wall samples must never include statistics overhead.
                    cmd = dtvm_cmd(dtvm_bin, case, mode, stats=False)
                elif wt_bin is None and not args.dry_run:
                    cmd = []
                    skip_reason = "wasmtime-not-found"
                else:
                    cmd = wasmtime_cmd(wt_bin, case)
                    env = {"WASMTIME_CACHE": "0"}
                full = prefix + cmd if cmd else []
                plan.append((case, rt, mode, full, env, skip_reason))

    if args.dry_run:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "preset": args.preset,
            "scale": args.scale,
            "metric": args.metric,
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
                        if rt == "dtvm" and want_stats else None
                    ),
                    "stdin": case.get("stdin"),
                    "skip_reason": skip_reason,
                }
                for case, rt, mode, full, _env, skip_reason in plan
            ],
        }
        write_json(out_dir / "commands.json", payload)
        print(json.dumps(payload, indent=2))
        print(f"wrote {out_dir / 'commands.json'}")
        return 0

    runs = []
    total = len(plan)
    for i, (case, rt, mode, cmd, env, skip_reason) in enumerate(plan, 1):
        instrumented_cmd = (
            prefix + dtvm_cmd(dtvm_bin, case, mode, stats=True)
            if rt == "dtvm" and want_stats and not skip_reason else None
        )
        print(
            f"[{i}/{total}] {rt}/{mode} {case['id']}",
            flush=True,
        )
        if skip_reason:
            cell = skipped_cell(skip_reason)
        else:
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
        if instrumented_cmd and cell["ok"]:
            instrumented = run_cell(
                instrumented_cmd,
                case_cwd(case),
                case.get("stdin"),
                args.warmup,
                args.repeats,
                args.timeout,
                env,
                args.keep_output,
            )
            instrumented["command"] = instrumented_cmd
        rec = {
            "bench": case["id"],
            "suite": case["suite"],
            "wasm": case["wasm"],
            "fairness": case.get("fairness", "same-wasm"),
            "runtime": rt,
            "mode": mode,
            "command": cmd or None,
            "cwd": str(case_cwd(case)),
            "exit": cell["exit"],
            "timeout": cell["timeout"] or bool(instrumented and instrumented["timeout"]),
            "sample_exits": cell["sample_exits"],
            "failed_samples": cell["failed_samples"],
            "timed_out_samples": cell["timed_out_samples"],
            "ok": cell["ok"] and (instrumented is None or instrumented["ok"]),
            "wall_ok": cell["ok"],
            "skipped": bool(cell.get("skipped")),
            "skip_reason": cell.get("skip_reason"),
            "samples_s": cell["samples_s"],
            "median_s": cell["median_s"],
            "min_s": cell["min_s"],
            "max_s": cell["max_s"],
            "statistics": (instrumented or cell)["statistics"],
            "ttfi": (instrumented or cell).get("ttfi"),
            "instrumented": instrumented,
        }
        if cell.get("output_tail") and (args.keep_output or not cell["ok"]):
            rec["output_tail"] = cell["output_tail"]
        if instrumented and instrumented.get("output_tail"):
            rec["output_tail"] = instrumented["output_tail"]
        runs.append(rec)
        if rec.get("skipped"):
            print(
                f"    skipped ({rec['skip_reason']}) fairness={rec['fairness']}",
                flush=True,
            )
        else:
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
            "metric": args.metric,
            "cpu": cpu,
            "warmup": args.warmup,
            "repeats": args.repeats,
            "timeout_s": args.timeout,
            "stats": want_stats,
            "statistics_separate_pass": want_stats,
            "dtvm": str(dtvm_bin) if dtvm_bin else None,
            "wasmtime": str(wt_bin) if wt_bin else None,
            "wasmtime_present": bool(
                wt_bin and str(wt_bin) != "${WASMTIME}"
            ),
            "dtvm_modes": dtvm_modes,
            "runtimes": runtimes,
            "skipped_runtimes": skipped_runtimes,
            "mode_aliases": MODE_ALIASES,
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
    failed = [r for r in runs if not r["ok"] and not r.get("skipped")]
    skipped = [r for r in runs if r.get("skipped")]
    if skipped:
        print(
            f"note: {len(skipped)} skipped cells (missing runtime / not invented)",
            file=sys.stderr,
        )
    if failed:
        print(f"warning: {len(failed)} failed cells", file=sys.stderr)
        return 1
    if not any(r["ok"] for r in runs):
        print("error: no benchmark cells executed successfully", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
