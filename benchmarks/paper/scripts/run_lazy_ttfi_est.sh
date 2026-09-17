#!/usr/bin/env bash
# WAPM lazy TTFI estimate (paper_lazy formula):
#   ttfi_est = load + precompile + instantiation + (fg_jit / fg_count)
# Requires dtvm with --enable-statistics. 20 cases: fortune replaces zuk.
set -euo pipefail

REPEATS="${1:-3}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DTVM="${DTVM:-$ROOT/runtimes/dtvm/dtvm}"
source "$ROOT/scripts/common.sh"
warn_if_debug_dtvm "$DTVM"
WAPM="${WAPM:-$ROOT/benchmarks/wapm}"
PAPER="${PAPER:-$ROOT/raw_data/benchs/latencytofirstinvocation.md}"
OUT_DIR="${OUT_DIR:-$ROOT/raw_data/benchs/wapm_lazy_ttfi_est_$(date +%Y%m%d)}"

CASES=(
  amirali base64cli chkfont code-stock cowsay dice echo erdtree figlet
  irb md5 pi pkg1 qr2text sam suggest tpl uuid viu fortune
)

mkdir -p "$OUT_DIR/logs"

if [[ ! -x "$DTVM" ]]; then
  echo "error: dtvm not executable: $DTVM" >&2
  exit 1
fi

parse_phase_total() {
  local log="$1" phase="$2"
  grep -a "$phase" "$log" 2>/dev/null | tail -1 | sed -n 's/.*total \([0-9.]*\)ms.*/\1/p'
}

parse_fg_count() {
  grep -a 'JIT Lazy Compilation(Fg):' "$1" 2>/dev/null | tail -1 \
    | sed -n 's/.*Compilation(Fg):[[:space:]]*\([0-9]*\) times.*/\1/p'
}

calc_ttfi_est() {
  awk -v load="${1:-0}" -v pre="${2:-0}" -v inst="${3:-0}" -v fg="${4:-0}" -v n="${5:-0}" '
    BEGIN {
      if (n + 0 <= 0) { printf "0"; exit }
      printf "%.4f", load + pre + inst + (fg / n)
    }'
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
  if [[ "$case" == chkfont ]]; then
    [[ -d "$WAPM/fonts" ]] && DIR=(--dir=./fonts)
  elif [[ "$case" == figlet ]]; then
    [[ -d "$WAPM/fonts" ]] && DIR=(--dir=fonts)
  fi
  if [[ "$case" == viu ]]; then
    DIR=(--dir=.)
    [[ -f "$WAPM/parallel-small.png" ]] && PARAMETER=(parallel-small.png)
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

  local load pre fg inst exe fg_n ttfi stats_total
  load=$(parse_phase_total "$log" 'Load:')
  pre=$(parse_phase_total "$log" 'JIT Lazy Precompilation:')
  fg=$(parse_phase_total "$log" 'JIT Lazy Compilation(Fg):')
  inst=$(parse_phase_total "$log" 'Instantiation:')
  exe=$(parse_phase_total "$log" 'Execution:')
  fg_n=$(parse_fg_count "$log")
  stats_total=$(grep -a 'Total:' "$log" 2>/dev/null | tail -1 | sed -n 's/.*Total:[[:space:]]*\([0-9.]*\)ms.*/\1/p')

  load=${load:-0}
  pre=${pre:-0}
  fg=${fg:-0}
  inst=${inst:-0}
  exe=${exe:-0}
  fg_n=${fg_n:-0}
  stats_total=${stats_total:-0}

  ttfi=$(calc_ttfi_est "$load" "$pre" "$inst" "$fg" "$fg_n")

  echo "${ttfi},${load},${pre},${inst},${fg},${fg_n},${exe},${stats_total}"
}

echo "WAPM lazy TTFI estimate"
echo "  formula: load + precompile + instantiation + (fg_jit / fg_count)"
echo "  dtvm=$DTVM"
echo "  repeats=$REPEATS"
echo "  out=$OUT_DIR"
echo ""

{
  echo "case,rep,ttfi_est_ms,load_ms,precompile_ms,instantiation_ms,fg_jit_ms,fg_count,execution_ms,stats_total_ms"
} >"$OUT_DIR/results.csv"

for case in "${CASES[@]}"; do
  echo ">> $case"
  for ((rep = 1; rep <= REPEATS; rep++)); do
    row=$(run_one_rep "$case" "$rep")
    echo "$case,$rep,$row" >>"$OUT_DIR/results.csv"
  done
done

python3 - "$OUT_DIR" "$PAPER" <<'PY'
import csv
import re
import sys
from pathlib import Path
from statistics import mean

out_dir = Path(sys.argv[1])
paper_md = Path(sys.argv[2])

paper: dict[str, float] = {}
if paper_md.is_file():
    for line in paper_md.read_text().splitlines():
        if "avg" in line.lower():
            continue
        m = re.search(r"case/wapm/(\w+)\.wasm", line)
        if not m:
            continue
        plain = re.sub(r"<[^>]+>", "", line)
        cells = [c.strip() for c in plain.split("|") if c.strip()]
        if len(cells) >= 3:
            try:
                paper[m.group(1)] = float(cells[2].split()[0])
            except ValueError:
                pass

rows_by_case: dict[str, list[dict]] = {}
with (out_dir / "results.csv").open() as f:
    for row in csv.DictReader(f):
        rows_by_case.setdefault(row["case"], []).append(row)

lines = [
    "# WAPM lazy TTFI estimate vs paper",
    "",
    "**Formula:** `ttfi_est = load + precompile + instantiation + (fg_jit / fg_count)`",
    "",
    f"- Output: `{out_dir}`",
    f"- dtvm: paper commit (see `runtimes/dtvm/version.txt`)",
    "- `paper_lazy`: `latencytofirstinvocation.md` dtvm lazy column",
    "- `ratio`: paper / ttfi_est (1.0 = match)",
    "",
    "| case | ttfi_est (avg) | paper_lazy | ratio | fg_count | stats_total |",
    "|------|---------------:|-----------:|------:|---------:|------------:|",
]

ratios = []
for case in sorted(rows_by_case.keys()):
    reps = rows_by_case[case]
    ttfi_vals = [float(r["ttfi_est_ms"]) for r in reps if r.get("ttfi_est_ms")]
    if not ttfi_vals:
        continue
    avg_ttfi = mean(ttfi_vals)
    avg_total = mean(float(r["stats_total_ms"]) for r in reps if r.get("stats_total_ms"))
    fg_n = int(mean(float(r["fg_count"]) for r in reps if r.get("fg_count")))
    p = paper.get(case)
    if case == "fortune":
        p = paper.get("zuk")  # paper table used zuk
    ratio_s = f"{p/avg_ttfi:.3f}" if p and avg_ttfi > 0 else "-"
    if p and avg_ttfi > 0:
        ratios.append(p / avg_ttfi)
    p_s = f"{p:.3f}" if p is not None else "-"
    note = " (paper=zuk)" if case == "fortune" and p else ""
    lines.append(
        f"| {case}{note} | {avg_ttfi:.3f} | {p_s} | {ratio_s} | {fg_n} | {avg_total:.1f} |"
    )

if ratios:
    abs_err = [abs(r - 1.0) for r in ratios]
    lines += [
        "",
        f"- Cases with paper data: **{len(ratios)}** (fortune compared to zuk)",
        f"- Mean paper/ttfi_est: **{mean(ratios):.3f}**",
        f"- Mean |paper/ttfi_est − 1|: **{mean(abs_err):.3f}**",
    ]

lines += ["", "## Per-rep raw data", "", "See `results.csv` and `logs/`.", ""]
(out_dir / "SUMMARY.md").write_text("\n".join(lines))

# machine-readable summary for scripts
with (out_dir / "summary.csv").open("w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["case", "ttfi_est_avg_ms", "paper_lazy_ms", "paper_over_est", "fg_count_avg", "stats_total_avg_ms"])
    for case in sorted(rows_by_case.keys()):
        reps = rows_by_case[case]
        ttfi_vals = [float(r["ttfi_est_ms"]) for r in reps if r.get("ttfi_est_ms")]
        if not ttfi_vals:
            continue
        avg_ttfi = mean(ttfi_vals)
        p = paper.get(case)
        if case == "fortune":
            p = paper.get("zuk")
        w.writerow([
            case,
            f"{avg_ttfi:.4f}",
            "" if p is None else f"{p:.4f}",
            "" if not p or avg_ttfi <= 0 else f"{p/avg_ttfi:.4f}",
            int(mean(float(r["fg_count"]) for r in reps if r.get("fg_count"))),
            f"{mean(float(r['stats_total_ms']) for r in reps if r.get('stats_total_ms')):.4f}",
        ])

print((out_dir / "SUMMARY.md").read_text())
PY

echo ""
echo "Done."
echo "  $OUT_DIR/results.csv"
echo "  $OUT_DIR/summary.csv"
echo "  $OUT_DIR/SUMMARY.md"
