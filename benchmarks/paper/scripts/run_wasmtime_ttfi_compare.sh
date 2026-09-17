#!/usr/bin/env bash
# Run patched wasmtime on WAPM cases; compare Total compilation / Execution vs paper logs.
set -euo pipefail

REPEATS="${1:-3}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${2:-$ROOT/raw_data/benchs/wasmtime_ttfi_compare_$(date +%Y%m%d_%H%M%S)}"
[[ "$OUT" != /* ]] && OUT="$ROOT/$OUT"
WAPM="$ROOT/benchmarks/wapm"
WT="${WASMTIME:-$ROOT/runtimes/wasmtime-31.0.0/out/wasmtime}"
PAPER_LOG="$ROOT/reference_logs/py_tools/wasmtime_compile_time.txt"
PAPER_MD="$ROOT/raw_data/benchs/latencytofirstinvocation.md"

export WASMTIME_CACHE=0
WASMTIME_CACHE_DIR="${WASMTIME_CACHE_DIR:-$HOME/.cache/wasmtime}"
CLEAR_WASMTIME_CACHE="${CLEAR_WASMTIME_CACHE:-1}"

clear_wasmtime_cache() {
  if [[ "$CLEAR_WASMTIME_CACHE" == "1" ]]; then
    rm -rf "$WASMTIME_CACHE_DIR"
  fi
}

CASES=(
  amirali base64cli chkfont code-stock cowsay dice echo erdtree figlet
  irb md5 pi pkg1 qr2text sam suggest tpl uuid viu fortune
)

mkdir -p "$OUT/logs"

cd "$WAPM"
load_conf() {
  local case="$1"
  unset DIR HEAD_COMMAND COMMAND PARAMETER 2>/dev/null || true
  HEAD_COMMAND=()
  COMMAND=()
  PARAMETER=()
  DIR=()
  if [[ -f "$WAPM/${case}.wasm.conf" ]]; then
    # shellcheck source=/dev/null
    source "$WAPM/${case}.wasm.conf"
  fi
  if [[ "$case" == erdtree ]]; then PARAMETER=(); fi
  if [[ "$case" == chkfont ]] && [[ -d "$WAPM/fonts" ]]; then
    DIR=(--dir=./fonts)
  elif [[ "$case" == figlet ]] && [[ -d "$WAPM/fonts" ]]; then
    DIR=(--dir=fonts)
  elif [[ "$case" == viu ]]; then
    DIR=(--dir=.)
    [[ -f "$WAPM/parallel-small.png" ]] && PARAMETER=(parallel-small.png)
  fi
}

fix_path() { local s="$1"; s="${s//case\/wapm\//}"; printf '%s' "$s"; }

build_cmd() {
  local case="$1"
  local -n _cmd=$2
  local -a params=()
  if [[ -n "${PARAMETER:-}" ]]; then
    if declare -p PARAMETER 2>/dev/null | grep -q 'declare \-a'; then
      local item
      for item in "${PARAMETER[@]}"; do
        read -r -a w <<< "$item"
        params+=("${w[@]}")
      done
    else
      read -r -a params <<< "$PARAMETER"
    fi
  fi
  _cmd=("$WT")
  if [[ -n "${DIR:-}" ]]; then
    local d
    for d in "${DIR[@]}"; do
      d="$(fix_path "$d")"
      if [[ "$d" == --dir=* ]]; then _cmd+=("$d"); else _cmd+=(--dir "$d"); fi
    done
  fi
  _cmd+=("${case}.wasm" "${params[@]}")
}

run_case() {
  local case="$1"
  local log="$2"
  local cmd=()
  build_cmd "$case" cmd
  if [[ ${#COMMAND[@]} -gt 0 && -n "${COMMAND[0]:-}" ]]; then
    if [[ "$case" == dice ]]; then
      echo help | "${cmd[@]}" >"$log" 2>&1 || true
    elif [[ "$case" == tpl ]]; then
      echo 'Δ is 123456-123455.' | "${cmd[@]}" >"$log" 2>&1 || true
    elif [[ ${#HEAD_COMMAND[@]} -gt 0 && "${HEAD_COMMAND[0]}" == eval ]]; then
      eval "${COMMAND[*]}" | "${cmd[@]}" >"$log" 2>&1 || true
    else
      "${COMMAND[@]}" | "${cmd[@]}" >"$log" 2>&1 || true
    fi
  else
    "${cmd[@]}" >"$log" 2>&1 || true
  fi
}

echo "wasmtime TTFI compare -> $OUT"
echo "  binary: $WT"
echo "  repeats: $REPEATS  WASMTIME_CACHE=$WASMTIME_CACHE"
echo "  clear cache: $CLEAR_WASMTIME_CACHE ($WASMTIME_CACHE_DIR)"
echo ""

for case in "${CASES[@]}"; do
  load_conf "$case"
  echo ">> $case"
  for ((r = 1; r <= REPEATS; r++)); do
    clear_wasmtime_cache
    run_case "$case" "$OUT/logs/${case}_${r}.log"
  done
done

ROOT="$ROOT" OUT="$OUT" PAPER_LOG="$PAPER_LOG" PAPER_MD="$PAPER_MD" REPEATS="$REPEATS" python3 <<'PY'
import re
import sys
from collections import defaultdict
from pathlib import Path
from statistics import mean

root = Path(__import__("os").environ["ROOT"])
out = Path(__import__("os").environ["OUT"])
paper_log = Path(__import__("os").environ["PAPER_LOG"])
paper_md = Path(__import__("os").environ["PAPER_MD"])
repeats = int(__import__("os").environ["REPEATS"])

compile_re = re.compile(
    r"Total compilation time: \d+ ms \((\d+) [μµ]s\)"
)
exec_re = re.compile(r"Execution \d+: ([\d.]+) ms")

# Paper latency table (wasmtime column, ms); optional reference input
latency_wt = {}
if paper_md.is_file():
    for line in paper_md.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.search(r"case/wapm/([\w-]+)\.wasm", line)
        if not m or "avg" in line.lower():
            continue
        plain = re.sub(r"<[^>]+>", "", line)
        cells = [c.strip() for c in plain.split("|") if c.strip()]
        if len(cells) >= 4:
            latency_wt[m.group(1)] = float(cells[3])

# Paper compile-time log averages (10 runs per case block); optional reference input
paper_compile = defaultdict(list)
current_cmd = None
paper_log_lines = (
    paper_log.read_text(encoding="utf-8", errors="replace").splitlines()
    if paper_log.is_file() else []
)
for line in paper_log_lines:
    if line.startswith("Executing command:"):
        current_cmd = line
        continue
    m = compile_re.search(line)
    if m and current_cmd:
        case_m = re.search(r"case/wapm/([\w-]+)\.wasm", current_cmd)
        if case_m:
            paper_compile[case_m.group(1)].append(int(m.group(1)) / 1000.0)

paper_compile_avg = {k: mean(v) for k, v in paper_compile.items()}

cases = sorted({p.stem.rsplit("_", 1)[0] for p in out.glob("logs/*.log")})
rows = []
for case in cases:
    compiles, execs, walls = [], [], []
    for r in range(1, repeats + 1):
        log = out / "logs" / f"{case}_{r}.log"
        if not log.exists():
            continue
        text = log.read_text(encoding="utf-8", errors="replace")
        cm = compile_re.search(text)
        if cm:
            compiles.append(int(cm.group(1)) / 1000.0)
        em = exec_re.search(text)
        if em:
            execs.append(float(em.group(1)))
        # wall: first line with guest output timing not available; use compile+exec approx
    if not compiles:
        continue
    c_avg = mean(compiles)
    e_avg = mean(execs) if execs else float("nan")
    p_comp = paper_compile_avg.get(case)
    p_lat = latency_wt.get(case)
    rows.append((case, c_avg, e_avg, p_comp, p_lat))
rows.sort(key=lambda r: r[0])

csv = out / "results.csv"
ratios = []
with csv.open("w") as f:
    f.write(
        "case,compile_ms,execution_ms,paper_compile_ms,paper_latency_wt_ms,ratio_compile\n"
    )
    for case, c, e, pc, pl in rows:
        ratio = c / pc if pc else None
        if ratio is not None:
            ratios.append(ratio)
        ratio_s = f"{ratio:.2f}" if ratio is not None else ""
        f.write(
            f"{case},{c:.3f},{e:.3f},{pc or ''},{pl or ''},{ratio_s}\n"
        )

md = [
    "# Wasmtime TTFI compare (patched `out/wasmtime`)\n",
    f"- Repeats: **{repeats}** per case\n",
    "- `WASMTIME_CACHE=0`\n",
    "- **compile**: `Total compilation time` in stdout\n",
    "- **exec**: `Execution 1` (instantiate+invoke)\n",
    "- **paper compile**: avg from `wasmtime_compile_time.txt` (10 runs/case)\n",
    "- **paper latency**: wasmtime column in `latencytofirstinvocation.md` (different metric)\n",
    "\n| case | compile ms | paper compile | C ratio | exec ms | paper latency wt |\n",
    "|---|---:|---:|---:|---:|---:|\n",
]
for case, c, e, pc, pl in rows:
    if pc and pl:
        md.append(
            f"| {case} | {c:.3f} | {pc:.3f} | {c/pc:.2f} | {e:.3f} | {pl:.1f} |\n"
        )
    else:
        md.append(f"| {case} | {c:.3f} | n/a | n/a | {e:.3f} | n/a |\n")
if ratios:
    md.append(f"\n**Mean compile ratio (this/paper):** {mean(ratios):.2f}\n")
md.append("\n## Notes\n")
md.append(
    "- `paper latency wt` is the paper table wall/TTFI (~21ms echo), not `Total compilation time`.\n"
)
md.append(
    "- `paper compile` is from `wasmtime_compile_time.txt` (~2ms amirali, ~20ms echo).\n"
)

summary = out / "COMPARE.md"
summary.write_text("".join(md))
print(f"Wrote {csv}")
print(f"Wrote {summary}")
PY

echo ""
echo "Done: $OUT/COMPARE.md"
