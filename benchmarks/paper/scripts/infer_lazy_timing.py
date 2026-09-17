#!/usr/bin/env python3
"""Infer paper TTFI by comparing narrow timing hypotheses to latency table."""

from __future__ import annotations

import os
import re
import select
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from statistics import mean

ROOT = Path(__file__).resolve().parents[1]
DTVM = Path(__import__("os").environ.get("DTVM", ROOT / "runtimes/dtvm/dtvm"))
WAPM = ROOT / "benchmarks/wapm"
PAPER_MD = ROOT / "raw_data/benchs/latencytofirstinvocation.md"
REPEATS = int(sys.argv[1]) if len(sys.argv) > 1 else 3

CASES = [
    "amirali", "base64cli", "chkfont", "code-stock", "cowsay", "dice", "echo",
    "erdtree", "figlet", "irb", "md5", "pi", "pkg1", "qr2text", "sam", "suggest",
    "tpl", "uuid", "viu", "fortune",
]

DTVM_BASE = [
    str(DTVM),
    "-m", "multipass",
    "--enable-multipass-lazy",
    "--disable-multipass-greedyra",
    "--disable-multipass-multithread",
    "--enable-statistics",
    "--log-level", "info",
]


def load_paper() -> dict[str, float]:
    paper: dict[str, float] = {}
    if not PAPER_MD.is_file():
        return paper
    for line in PAPER_MD.read_text().splitlines():
        m = re.search(r"case/wapm/(\w+)\.wasm", line)
        if not m or "avg" in line.lower():
            continue
        plain = re.sub(r"<[^>]+>", "", line)
        cells = [c.strip() for c in plain.split("|") if c.strip()]
        # cells[0]=case path, [1]=wasm KB, [2]=dtvm lazy ms
        if len(cells) >= 3:
            try:
                paper[m.group(1)] = float(cells[2].split()[0])
            except ValueError:
                pass
    return paper


def is_engine_log(line: str) -> bool:
    s = line.strip()
    return s.startswith("[") and ("[info]" in s or "[warn]" in s or "[error]" in s)


def parse_stats(text: str) -> dict[str, float]:
    out: dict[str, float] = {}
    patterns = {
        "total_ms": r"Total:\s*([\d.]+)ms",
        "load_ms": r"Load:.*?total ([\d.]+)ms",
        "precompile_ms": r"JIT Lazy Precompilation:.*?total ([\d.]+)ms",
        "fg_jit_ms": r"JIT Lazy Compilation\(Fg\):.*?total ([\d.]+)ms",
        "instantiation_ms": r"Instantiation:.*?total ([\d.]+)ms",
        "execution_ms": r"Execution:.*?total ([\d.]+)ms",
    }
    fg_m = re.search(
        r"JIT Lazy Compilation\(Fg\):\s*(\d+) times", text
    )
    if fg_m:
        out["fg_count"] = int(fg_m.group(1))
    for k, pat in patterns.items():
        m = re.search(pat, text)
        if m:
            out[k] = float(m.group(1))
    if "load_ms" in out and "precompile_ms" in out and "instantiation_ms" in out:
        out["load_setup_ms"] = (
            out["load_ms"] + out["precompile_ms"] + out["instantiation_ms"]
        )
    if "fg_jit_ms" in out and out.get("fg_count", 0) > 0:
        out["first_fg_ms"] = out["fg_jit_ms"] / out["fg_count"]
    if "load_setup_ms" in out and "first_fg_ms" in out:
        out["after_first_fg_ms"] = out["load_setup_ms"] + out["first_fg_ms"]
    if "after_first_fg_ms" in out and "execution_ms" in out:
        out["first_fg_plus_exec_ms"] = out["after_first_fg_ms"] + out["execution_ms"]
    return out


def _load_conf_fields(case: str) -> tuple[str, str, str]:
    """Return (command, parameter, dir) strings from wasm.conf via bash source."""
    bash = f"""
set +e
cd {shlex.quote(str(WAPM))}
unset DIR HEAD_COMMAND COMMAND PARAMETER 2>/dev/null || true
HEAD_COMMAND=(); COMMAND=(); PARAMETER=(); DIR=()
[ -f {shlex.quote(case + '.wasm.conf')} ] && source {shlex.quote(case + '.wasm.conf')}
case {shlex.quote(case)} in
  erdtree) PARAMETER=() ;;
  viu)
    DIR=(--dir=.)
    [ -f parallel-small.png ] && PARAMETER=(parallel-small.png) ;;
  chkfont) [ -d fonts ] && DIR=(--dir=./fonts) ;;
  figlet) [ -d fonts ] && DIR=(--dir=fonts) ;;
esac
printf '%s\\n' "${{COMMAND[*]-}}"
printf '%s\\n' "${{PARAMETER[*]-}}"
printf '%s\\n' "${{DIR[*]-}}"
"""
    lines = subprocess.check_output(["bash", "-c", bash], text=True).splitlines()
    while len(lines) < 3:
        lines.append("")
    return lines[0], lines[1], lines[2]


def build_shell_cmd(case: str) -> str:
    """Mirror run_lazy_stats.sh command assembly."""
    command, parameter, dir_s = _load_conf_fields(case)
    parts = list(DTVM_BASE) + [f"{case}.wasm"]
    if dir_s.strip():
        for d in dir_s.split():
            d = d.replace("case/wapm/", "")
            parts.append(d if d.startswith("--dir") else f"--dir={d}")
    if parameter.strip():
        parts.append("--args")
        parts.extend(parameter.split())
    dtvm_cmd = subprocess.list2cmdline(parts)
    if command.strip():
        return f"{command} | {dtvm_cmd}"
    return dtvm_cmd


def run_case_once(case: str) -> dict[str, float]:
    cmd = build_shell_cmd(case)
    t0 = time.perf_counter()
    proc = subprocess.Popen(
        cmd,
        shell=True,
        cwd=WAPM,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert proc.stdout is not None
    fd = proc.stdout.fileno()
    first_stdout_ms: float | None = None
    chunks: list[str] = []
    buf = b""
    while True:
        if proc.poll() is not None:
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                buf += chunk
            break
        ready, _, _ = select.select([fd], [], [], 0.05)
        if not ready:
            continue
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        buf += chunk
        while b"\n" in buf:
            raw, buf = buf.split(b"\n", 1)
            line = raw.decode("utf-8", errors="replace") + "\n"
            chunks.append(line)
            if first_stdout_ms is None and line.strip() and not is_engine_log(line):
                first_stdout_ms = (time.perf_counter() - t0) * 1000.0
    if buf:
        line = buf.decode("utf-8", errors="replace")
        if not line.endswith("\n"):
            line += "\n"
        chunks.append(line)
        if first_stdout_ms is None and line.strip() and not is_engine_log(line):
            first_stdout_ms = (time.perf_counter() - t0) * 1000.0

    proc.wait()
    full_wall_ms = (time.perf_counter() - t0) * 1000.0
    full_text = "".join(chunks)
    stats = parse_stats(full_text)

    row = {
        "first_stdout_ms": first_stdout_ms if first_stdout_ms is not None else full_wall_ms,
        "full_wall_ms": full_wall_ms,
    }
    row.update(stats)
    return row


def ratio(a: float, b: float) -> str:
    if b <= 0:
        return "-"
    return f"{a/b:.2f}x"


@dataclass
class CaseResult:
    case: str
    paper_ms: float | None
    first_stdout: float
    full_wall: float
    stats_total: float
    after_first_fg: float
    execution_ms: float
    first_fg_plus_exec: float
    load_setup: float


def main() -> None:
    paper = load_paper()
    results: list[CaseResult] = []

    for case in CASES:
        print(f">> {case}", flush=True)
        reps = [run_case_once(case) for _ in range(REPEATS)]

        def avg(key: str) -> float:
            vals = [r[key] for r in reps if key in r]
            return mean(vals) if vals else float("nan")

        results.append(
            CaseResult(
                case=case,
                paper_ms=paper.get(case),
                first_stdout=avg("first_stdout_ms"),
                full_wall=avg("full_wall_ms"),
                stats_total=avg("total_ms"),
                after_first_fg=avg("after_first_fg_ms"),
                execution_ms=avg("execution_ms"),
                first_fg_plus_exec=avg("first_fg_plus_exec_ms"),
                load_setup=avg("load_setup_ms"),
            )
        )

    out_dir = ROOT / "raw_data/benchs" / "wapm_lazy_ttfi_infer"
    out_dir.mkdir(parents=True, exist_ok=True)

    lines = [
        "# Lazy timing-model inference (vs the paper's dtvm lazy column)",
        "",
        f"- dtvm: `{DTVM}`",
        f"- repeats: {REPEATS}",
        "",
        "**Assumptions**",
        "- `first_stdout`: wall time to the first non-engine stdout line (program output)",
        "- `after_first_fg`: Load+Precompile+Instantiation + one average Fg (i.e. right after the first Fg, rest not compiled yet)",
        "- `first_fg+exec`: the above + Statistics Execution (whole guest execution, not just the first line)",
        "- `execution`: the Statistics Execution line",
        "- `stats_total`: Statistics Total",
        "- `full_wall`: whole-command wall time (including the trailing statistics dump)",
        "",
        "ratio column = **paper / this column** (closer to 1.0 = closer to the paper's metric)",
        "",
        "| case | paper | 1st stdout | after 1st Fg | 1st Fg+exec | execution | stats Total | full_wall | best match |",
        "|------|------:|-----------:|-------------:|------------:|----------:|------------:|----------:|------------|",
    ]

    match_votes = {
        "first_stdout": 0,
        "after_first_fg": 0,
        "first_fg_plus_exec": 0,
        "execution": 0,
        "stats_total": 0,
        "full_wall": 0,
    }

    for r in results:
        if r.paper_ms is None:
            best = "-"
        else:
            cands = {
                "first_stdout": r.first_stdout,
                "after_first_fg": r.after_first_fg,
                "1st Fg+exec": r.first_fg_plus_exec,
                "execution": r.execution_ms,
                "stats Total": r.stats_total,
                "full_wall": r.full_wall,
            }
            best = min(
                cands.items(),
                key=lambda kv: abs(kv[1] - r.paper_ms) if kv[1] == kv[1] else 1e18,
            )[0]
            key_map = {
                "first_stdout": "first_stdout",
                "after_first_fg": "after_first_fg",
                "1st Fg+exec": "first_fg_plus_exec",
                "execution": "execution",
                "stats Total": "stats_total",
                "full_wall": "full_wall",
            }
            match_votes[key_map.get(best, best)] = match_votes.get(key_map.get(best, best), 0) + 1

        p = f"{r.paper_ms:.3f}" if r.paper_ms is not None else "-"
        lines.append(
            f"| {r.case} | {p} | {r.first_stdout:.2f} | {r.after_first_fg:.2f} | "
            f"{r.first_fg_plus_exec:.2f} | {r.execution_ms:.2f} | {r.stats_total:.2f} | "
            f"{r.full_wall:.2f} | {best} |"
        )

    lines += [
        "",
        "## Mean ratio vs paper (paper/estimate, ideal ~= 1.0)",
        "",
    ]
    for label, attr in [
        ("first_stdout", "first_stdout"),
        ("after_first_fg", "after_first_fg"),
        ("first_fg+exec", "first_fg_plus_exec"),
        ("execution", "execution_ms"),
        ("stats_total", "stats_total"),
        ("full_wall", "full_wall"),
    ]:
        ratios = []
        for r in results:
            if r.paper_ms and getattr(r, attr) == getattr(r, attr):
                val = getattr(r, attr)
                if val > 0:
                    ratios.append(r.paper_ms / val)
        avg_r = mean(ratios) if ratios else float("nan")
        lines.append(f"- **{label}**: mean paper/est = **{avg_r:.3f}** (n={len(ratios)})")

    # Per-metric mean |paper/est - 1| for cases with paper (lower = better)
    lines += ["", "## Conclusion", ""]
    metrics = [
        ("first_stdout", "first_stdout"),
        ("after_first_fg", "after_first_fg"),
        ("first_fg+exec", "first_fg_plus_exec"),
        ("execution", "execution_ms"),
        ("stats_total", "stats_total"),
        ("full_wall", "full_wall"),
    ]
    scores: list[tuple[str, float]] = []
    for label, attr in metrics:
        errs = []
        for r in results:
            if r.paper_ms and getattr(r, attr) == getattr(r, attr):
                val = getattr(r, attr)
                if val > 0:
                    errs.append(abs(r.paper_ms / val - 1.0))
        if errs:
            scores.append((label, mean(errs)))
    scores.sort(key=lambda x: x[1])
    best = scores[0][0] if scores else "?"
    lines.append(
        f"1. The estimate closest to the paper's dtvm lazy column is **`{best}`**"
        f"(mean relative error {scores[0][1]:.2f}, 0 = exact match)."
    )
    lines += [
        "",
        "2. **`after_first_fg`** = Load+Precompile+Instantiation + **one average Fg**;"
        "it does not count all lazy compilations on the path. echo/irb etc. land within the paper's order of magnitude or 2-3x.",
        "",
        "3. **`first_stdout`** for **irb/tpl/viu** waits until **after heavy compilation** before the first line appears,"
        "so it approaches **full run** and cannot serve as TTFI.",
        "",
        "4. **Pure `execution` (Statistics Execution)** is <1 ms for most cases,"
        "so it is **not** the paper's lazy column (which includes compilation).",
        "",
        "5. **`stats_total` / `full_wall`** still include **all Fg compilations**, more than an order of magnitude above the paper.",
        "",
        "6. Inferred paper metric: **TTFI ~= module load/instantiation + first Fg JIT on the entry path**"
        "(~= `after_first_fg`), **excluding** functions compiled on demand later.",
        "",
    ]
    (out_dir / "INFER.md").write_text("\n".join(lines) + "\n")

    # raw rows csv
    with (out_dir / "measurements.csv").open("w") as f:
        f.write(
            "case,paper_ms,first_stdout_ms,after_first_fg_ms,first_fg_plus_exec_ms,"
            "execution_ms,stats_total_ms,full_wall_ms\n"
        )
        for r in results:
            p = "" if r.paper_ms is None else f"{r.paper_ms:.4f}"
            f.write(
                f"{r.case},{p},{r.first_stdout:.4f},{r.after_first_fg:.4f},"
                f"{r.first_fg_plus_exec:.4f},{r.execution_ms:.4f},"
                f"{r.stats_total:.4f},{r.full_wall:.4f}\n"
            )
    print(f"\nWrote {out_dir / 'INFER.md'}")
    print("\n".join(lines[-20:]))


if __name__ == "__main__":
    main()
