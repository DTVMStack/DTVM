#!/usr/bin/env bash
# WAPM lazy + DTVM --enable-statistics (ZetaEngine Statistics Total / phases).
# Paper 20 cases with zuk replaced by fortune (same as run_lazy_20.sh).
set -euo pipefail

REPEATS="${1:-3}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DTVM="${DTVM:-$ROOT/runtimes/dtvm/dtvm}"
source "$ROOT/scripts/common.sh"
warn_if_debug_dtvm "$DTVM"
WAPM="${WAPM:-$ROOT/benchmarks/wapm}"
OUT_DIR="${OUT_DIR:-$ROOT/raw_data/benchs/wapm_lazy_stats_$(date +%Y%m%d_%H%M%S)}"
CASES=(
  amirali base64cli chkfont code-stock cowsay dice echo erdtree figlet
  irb md5 pi pkg1 qr2text sam suggest tpl uuid viu fortune
)

mkdir -p "$OUT_DIR/logs"

if [[ ! -x "$DTVM" ]]; then
  echo "error: dtvm not executable: $DTVM" >&2
  exit 1
fi

# Parse "Phase: N times, avg Xms, total Yms" from statistics report (last match).
parse_phase_total() {
  local log="$1" phase="$2"
  grep -a "$phase" "$log" 2>/dev/null | tail -1 | sed -n 's/.*total \([0-9.]*\)ms.*/\1/p'
}

parse_total() {
  grep -a 'Total:' "$1" 2>/dev/null | tail -1 | sed -n 's/.*Total:[[:space:]]*\([0-9.]*\)ms.*/\1/p'
}

parse_fg_count() {
  grep -a 'JIT Lazy Compilation(Fg):' "$1" 2>/dev/null | tail -1 | sed -n 's/^\[.*\] \(.*\):[[:space:]]*\([0-9]*\) times.*/\2/p'
}

cd "$WAPM"

build_dtvm_cmd() {
  local case="$1"
  local conf="$WAPM/${case}.wasm.conf"
  unset DIR HEAD_COMMAND COMMAND PARAMETER 2>/dev/null || true
  HEAD_COMMAND=()
  COMMAND=()
  PARAMETER=()
  DIR=()

  if [[ -f "$conf" ]]; then
    # shellcheck source=/dev/null
    source "$conf"
  fi
  if [[ "$case" == erdtree ]]; then
    PARAMETER=()
  fi
  if [[ "$case" == chkfont || "$case" == figlet ]]; then
    if [[ -d "$WAPM/fonts" ]]; then
      DIR=(./fonts)
    fi
  fi
  if [[ "$case" == viu ]]; then
    DIR=('--dir=.')
    if [[ -f "$WAPM/parallel-small.png" ]]; then
      PARAMETER=(parallel-small.png)
    fi
  fi

  DTVM_TAIL=("$DTVM" -m multipass --enable-multipass-lazy
    --disable-multipass-greedyra --disable-multipass-multithread
    --enable-statistics --log-level info
    "${case}.wasm")

  if [[ -n "${DIR:-}" ]]; then
    local d
    for d in "${DIR[@]}"; do
      d="${d//case\/wapm\//}"
      if [[ "$d" == --dir=* ]]; then
        DTVM_TAIL+=("$d")
      else
        DTVM_TAIL+=(--dir "$d")
      fi
    done
  fi
  if [[ -n "${PARAMETER:-}" ]]; then
    DTVM_TAIL+=(--args)
    local item
    local -a pargs=()
    if declare -p PARAMETER 2>/dev/null | grep -q 'declare \-a'; then
      for item in "${PARAMETER[@]}"; do
        read -r -a w <<< "$item"
        pargs+=("${w[@]}")
      done
    else
      read -r -a pargs <<< "$PARAMETER"
    fi
    DTVM_TAIL+=("${pargs[@]}")
  fi
}

run_dtvm_logged() {
  local log="$1"
  if [[ ${#COMMAND[@]} -gt 0 && -n "${COMMAND[0]:-}" ]]; then
    # wasm.conf often uses shell pipelines (echo ... | wasm); always eval.
    eval "${COMMAND[*]}" \| "${DTVM_TAIL[@]}" >"$log" 2>&1 || true
  else
    "${DTVM_TAIL[@]}" >"$log" 2>&1 || true
  fi
}

run_one_rep() {
  local case="$1" rep="$2"
  local log="$OUT_DIR/logs/${case}_rep${rep}.log"
  build_dtvm_cmd "$case"

  run_dtvm_logged "$log"

  local total load pre fg inst exe fg_n
  total=$(parse_total "$log")
  load=$(parse_phase_total "$log" 'Load:')
  pre=$(parse_phase_total "$log" 'JIT Lazy Precompilation:')
  fg=$(parse_phase_total "$log" 'JIT Lazy Compilation(Fg):')
  inst=$(parse_phase_total "$log" 'Instantiation:')
  exe=$(parse_phase_total "$log" 'Execution:')
  fg_n=$(parse_fg_count "$log")
  echo "${total:-},${load:-},${pre:-},${fg:-},${inst:-},${exe:-},${fg_n:-}"
}

avg_col() {
  awk -F, -v col="$1" '
    { s+=$col; n++ }
    END { if (n>0) printf "%.3f", s/n; else print "" }
  '
}

echo "WAPM lazy + statistics"
echo "  dtvm=$DTVM"
echo "  repeats=$REPEATS"
echo "  out=$OUT_DIR"
echo ""

{
  echo "case,rep,total_ms,load_ms,precompile_ms,fg_jit_ms,instantiation_ms,execution_ms,fg_compile_count"
} >"$OUT_DIR/results.csv"

for case in "${CASES[@]}"; do
  if [[ "$case" == zuk && "$SKIP_ZUK" == 1 ]]; then
    echo ">> skip $case (SKIP_ZUK=1)"
    continue
  fi
  echo ">> $case"
  for ((rep = 1; rep <= REPEATS; rep++)); do
    row=$(run_one_rep "$case" "$rep")
    echo "$case,$rep,$row" >>"$OUT_DIR/results.csv"
  done
done

# Build summary with paper comparison
PAPER="$ROOT/raw_data/benchs/latencytofirstinvocation.md"
python3 - "$OUT_DIR" "$PAPER" <<'PY'
import csv
import re
import sys
from pathlib import Path

out_dir = Path(sys.argv[1])
paper_md = Path(sys.argv[2])

paper = {}
if paper_md.is_file():
    for line in paper_md.read_text().splitlines():
        m = re.search(r"case/wapm/(\w+)\.wasm", line)
        if not m:
            continue
        cols = [c.strip() for c in line.split("|")]
        if len(cols) < 4:
            continue
        if "avg" in line.lower():
            continue
        nums = []
        for x in re.findall(r"\d+\.?\d*", line):
            try:
                nums.append(float(x))
            except ValueError:
                pass
        if len(nums) >= 2:
            paper[m.group(1)] = nums[1]  # wasm size, then dtvm lazy

by_case = {}
with (out_dir / "results.csv").open() as f:
    r = csv.DictReader(f)
    for row in r:
        c = row["case"]
        by_case.setdefault(c, []).append(float(row["total_ms"] or 0))

lines = [
    "# WAPM lazy + `--enable-statistics`",
    "",
    f"- dtvm: `{out_dir}` run",
    "- Metric: **Statistics Total** (ms), not wall-clock",
    "",
    "| case | avg Total (ms) | paper dtvm lazy (ms) | ratio paper/stat | fg compiles (avg) |",
    "|------|----------------|------------------------|------------------|-------------------|",
]
ratios = []
for case in sorted(by_case.keys()):
    totals = by_case[case]
    avg = sum(totals) / len(totals)
    p = paper.get(case)
    ratio = f"{p/avg:.2f}" if p and avg > 0 else "-"
    if p and avg > 0:
        ratios.append(p / avg)
    # fg count from last rep average - read from csv
    fg_counts = []
    with (out_dir / "results.csv").open() as f:
        r = csv.DictReader(f)
        for row in r:
            if row["case"] == case and row.get("fg_compile_count"):
                try:
                    fg_counts.append(int(row["fg_compile_count"]))
                except ValueError:
                    pass
    fg_avg = int(sum(fg_counts) / len(fg_counts)) if fg_counts else "-"
    pstr = f"{p:.3f}" if p is not None else "-"
    lines.append(f"| {case} | {avg:.3f} | {pstr} | {ratio} | {fg_avg} |")

if ratios:
    lines.extend([
        "",
        f"- Mean paper/stat ratio (cases with paper data): **{sum(ratios)/len(ratios):.2f}**",
    ])
lines.append("")
(out_dir / "SUMMARY.md").write_text("\n".join(lines))
print((out_dir / "SUMMARY.md").read_text())
PY

echo ""
echo "Done. Results: $OUT_DIR/results.csv"
echo "Summary:  $OUT_DIR/SUMMARY.md"
