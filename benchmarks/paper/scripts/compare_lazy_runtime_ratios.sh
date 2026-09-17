#!/usr/bin/env bash
# Compare baseline/dtvm ratios vs paper (wall-clock + optional dtvm ttfi_est denominator).
# Usage:
#   ./compare_lazy_runtime_ratios.sh [repeats]
#   WALL_CSV=path/to/results.csv ./compare_lazy_runtime_ratios.sh 0   # skip wall run
set -euo pipefail

REPEATS="${1:-3}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PAPER="$ROOT/raw_data/benchs/latencytofirstinvocation.md"
TTFI_CSV="${TTFI_CSV:-$ROOT/raw_data/benchs/wapm_lazy_ttfi_est_20260528/summary.csv}"
OUT="${OUT:-$ROOT/raw_data/benchs/wapm_lazy_ratio_compare_$(date +%Y%m%d)}"
mkdir -p "$OUT"

if [[ "$REPEATS" -gt 0 && -z "${WALL_CSV:-}" ]]; then
  echo "==> Wall-clock run (all runtimes), repeats=$REPEATS"
  WALL_DIR="$OUT/wall_run"
  "$ROOT/scripts/run_lazy_paper.sh" "$REPEATS" "$WALL_DIR"
  WALL_CSV="$WALL_DIR/results.csv"
elif [[ -z "${WALL_CSV:-}" ]]; then
  WALL_CSV="$ROOT/raw_data/benchs/wapm_lazy_20260527/results.csv"
  echo "==> Using existing wall CSV: $WALL_CSV"
fi

export WALL_CSV TTFI_CSV PAPER OUT
python3 <<'PY'
import csv
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from statistics import mean

wall_csv = Path(os.environ["WALL_CSV"])
if not wall_csv.is_file():
    sys.exit(f"error: wall CSV not found: {wall_csv} (run run_lazy_paper.sh first or pass WALL_CSV=)")
ttfi_csv = Path(os.environ["TTFI_CSV"])
paper_md = Path(os.environ["PAPER"])
out = Path(os.environ["OUT"])

# paper[case][runtime] = ms; ratios[case][rt] = baseline/dtvm
paper_ms: dict[str, dict[str, float]] = {}
paper_ratio: dict[str, dict[str, float]] = {}

paper_lines = paper_md.read_text().splitlines() if paper_md.is_file() else []
if not paper_lines:
    print(f"note: paper reference table not found at {paper_md}; paper columns will be blank")
for line in paper_lines:
    if "avg" in line.lower():
        continue
    m = re.search(r"case/wapm/([\w-]+)\.wasm", line)
    if not m:
        continue
    case = m.group(1)
    plain = re.sub(r"<[^>]+>", "", line)
    cells = [c.strip() for c in plain.split("|") if c.strip()]
    if len(cells) < 8:
        continue
    try:
        dtvm = float(cells[2].split()[0])
        wt = float(cells[3].split()[0])
        cr = float(cells[4].split()[0])
        ll = float(cells[5].split()[0])
        sp = float(cells[6].split()[0])
    except ValueError:
        continue
    paper_ms[case] = {
        "dtvm": dtvm,
        "wasmtime": wt,
        "wasmer_cranelift": cr,
        "wasmer_llvm": ll,
        "wasmer_singlepass": sp,
    }
    if dtvm > 0:
        paper_ratio[case] = {
            "wasmtime": wt / dtvm,
            "wasmer_cranelift": cr / dtvm,
            "wasmer_llvm": ll / dtvm,
            "wasmer_singlepass": sp / dtvm,
        }

# wall averages
by = defaultdict(list)
with wall_csv.open() as f:
    for row in csv.DictReader(f):
        by[(row["case"], row["runtime"])].append(float(row["wall_ms"]))

def avg(key):
    v = by.get(key, [])
    return mean(v) if v else float("nan")

cases = sorted({k[0] for k in by})
rts = ["dtvm", "wasmtime", "wasmer_cranelift", "wasmer_llvm", "wasmer_singlepass"]
baselines = [r for r in rts if r != "dtvm"]

ttfi: dict[str, float] = {}
if ttfi_csv.is_file():
    with ttfi_csv.open() as f:
        for row in csv.DictReader(f):
            if row.get("ttfi_est_avg_ms"):
                ttfi[row["case"]] = float(row["ttfi_est_avg_ms"])

lines = [
    "# WAPM lazy: runtime ratios vs the paper",
    "",
    f"- Wall-clock: `{wall_csv}`",
    f"- DTVM TTFI est: `{ttfi_csv}` (formula: load+pre+inst+fg/n)",
    f"- Paper: `{paper_md}`",
    "",
    "**ratio** = baseline / dtvm (>1 means the baseline is slower).",
    "",
    "## 1. Absolute time (ms) and ratios",
    "",
    "| case | | paper dtvm | wall dtvm | ttfi_est dtvm | paper wt | wall wt | wall wt/dtvm | paper wt/dtvm |",
    "|------|--|----------:|---------:|-------------:|---------:|--------:|------------:|-------------:|",
]

ratio_err_wall = defaultdict(list)  # baseline -> list of |wall_ratio/paper_ratio - 1|
ratio_err_ttfi = defaultdict(list)

for case in cases:
    if case == "fortune":
        pcase = "zuk"  # paper row for fortune substitute
    else:
        pcase = case
    p = paper_ms.get(pcase, {})
    z_wall = avg((case, "dtvm"))
    z_ttfi = ttfi.get(case, float("nan"))
    z_paper = p.get("dtvm", float("nan"))

  # wasmtime row as primary example in combined table - also write full section below
    wt_w = avg((case, "wasmtime"))
    pr = p.get("wasmtime", float("nan"))
    wr = wt_w / z_wall if z_wall and z_wall == z_wall else float("nan")
    pr_ratio = paper_ratio.get(pcase, {}).get("wasmtime", float("nan"))
    note = " (fortune)" if case == "fortune" else ""
    lines.append(
        f"| {case}{note} | wasmtime | {z_paper:.3f} | {z_wall:.1f} | "
        f"{z_ttfi:.3f} | {pr:.1f} | {wt_w:.1f} | {wr:.2f} | {pr_ratio:.2f} |"
    )
    if pr_ratio == pr_ratio and wr == wr and pr_ratio > 0:
        ratio_err_wall["wasmtime"].append(abs(wr / pr_ratio - 1.0))

lines += [
    "",
    "### All-baseline ratio comparison (wall/dtvm vs paper/dtvm)",
    "",
    "| case | paper w/t | wall w/t | Δ% | paper cr/dtvm | wall cr/dtvm | Δ% | paper llvm/dtvm | wall llvm/dtvm | Δ% | paper sp/dtvm | wall sp/dtvm | Δ% |",
    "|------|----------:|---------:|---:|-------------:|------------:|---:|---------------:|--------------:|---:|-------------:|------------:|---:|",
]

def pct_delta(ours, paper):
    if paper != paper or ours != ours or paper == 0:
        return "-"
    return f"{(ours / paper - 1) * 100:+.0f}%"

for case in cases:
    pcase = "zuk" if case == "fortune" else case
    pr = paper_ratio.get(pcase, {})
    z = avg((case, "dtvm")) or 1.0
    cols = []
    for bl, pk in [
        ("wasmtime", "wasmtime"),
        ("wasmer_cranelift", "cr"),
        ("wasmer_llvm", "llvm"),
        ("wasmer_singlepass", "sp"),
    ]:
        p_rat = pr.get(bl, float("nan"))
        w_rat = avg((case, bl)) / z if z else float("nan")
        cols.extend([f"{p_rat:.2f}" if p_rat == p_rat else "-", f"{w_rat:.2f}" if w_rat == w_rat else "-", pct_delta(w_rat, p_rat)])
        if p_rat == p_rat and w_rat == w_rat and p_rat > 0:
            ratio_err_wall[bl].append(abs(w_rat / p_rat - 1.0))
    note = "†" if case == "fortune" else ""
    lines.append(f"| {case}{note} | " + " | ".join(cols) + " |")

# ttfi_est denominator ratios
if ttfi:
    lines += [
        "",
        "## 2. Ratios (dtvm denominator uses ttfi_est)",
        "",
        "Only dtvm is replaced by the formula estimate; baselines stay wall-clock.",
        "",
        "| case | paper wt/dtvm | wall wt/ttfi_est | paper llvm/dtvm | wall llvm/ttfi_est |",
        "|------|-------------:|-----------------:|---------------:|-------------------:|",
    ]
    for case in cases:
        pcase = "zuk" if case == "fortune" else case
        pr = paper_ratio.get(pcase, {})
        zt = ttfi.get(case, 0) or float("nan")
        if zt != zt or zt <= 0:
            continue
        w_wt = avg((case, "wasmtime")) / zt
        w_ll = avg((case, "wasmer_llvm")) / zt
        lines.append(
            f"| {case} | {pr.get('wasmtime', 0):.2f} | {w_wt:.2f} | "
            f"{pr.get('wasmer_llvm', 0):.2f} | {w_ll:.2f} |"
        )
        for bl, pkey in [("wasmtime", "wasmtime"), ("wasmer_llvm", "wasmer_llvm")]:
            p_r = pr.get(pkey, float("nan"))
            w_r = avg((case, bl)) / zt
            if p_r == p_r and w_r == w_r and p_r > 0:
                ratio_err_ttfi[bl].append(abs(w_r / p_r - 1.0))

lines += [
    "",
    "## 3. Summary: do the ratio shapes match",
    "",
]

lines.append("| baseline | mean |paper/ours−1| (wall dtvm) | mean |paper/ours−1| (ttfi dtvm) |")
lines.append("|----------|---------------------------|---------------------------|")
for bl in baselines:
    ew = mean(ratio_err_wall[bl]) if ratio_err_wall[bl] else float("nan")
    et = mean(ratio_err_ttfi[bl]) if ratio_err_ttfi[bl] else float("nan")
    lines.append(f"| {bl} | {ew:.2f} | {et:.2f} |")

# direction agreement: paper ratio > 1 and wall ratio > 1
lines += ["", "### Direction agreement (paper>1 and wall>1, or both<1)", ""]
for bl in baselines:
    agree = total = 0
    for case in cases:
        if case == "fortune":
            continue
        pcase = case
        pr = paper_ratio.get(pcase, {}).get(bl, float("nan"))
        z = avg((case, "dtvm"))
        wr = avg((case, bl)) / z if z else float("nan")
        if pr != pr or wr != wr:
            continue
        total += 1
        if (pr > 1) == (wr > 1):
            agree += 1
    lines.append(f"- **{bl}**: {agree}/{total} cases same slow-vs-fast direction")

lines += [
    "",
    "## 4. Interpretation",
    "",
    "- **Paper**: dtvm (lazy) is generally fastest; baseline/dtvm is mostly **>>1** (mean wasmtime/dtvm ~= **18.9**).",
    "- **Local wall**: dtvm is often slower than wasmtime/wasmer; ratios are mostly **<1** -> **relative ranking reversed vs the paper**, i.e. not the same absolute time.",
    "- **Ratio values**: a few cases are close (e.g. tpl, erdtree), but overall **|wall/paper-1| is large** -> the proportional relationship **cannot** be considered consistent.",
    "- **ttfi_est as dtvm denominator**: on small cases wasmtime/ttfi_est sometimes lands closer to the paper's magnitude, but **irb etc. still deviate**.",
    "",
]

(out / "RATIO_COMPARE.md").write_text("\n".join(lines))
print((out / "RATIO_COMPARE.md").read_text())
PY
