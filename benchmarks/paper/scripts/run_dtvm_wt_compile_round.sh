#!/usr/bin/env bash
# One round: dtvm (instrumented dtvm) + wasmtime (cold cache) compile lines vs paper.
set -euo pipefail

REPEATS="${1:-3}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${2:-$ROOT/raw_data/benchs/wapm_dtvm_wt_compile_$(date +%Y%m%d_%H%M%S)}"
[[ "$OUT" != /* ]] && OUT="$ROOT/$OUT"

DTVM="${DTVM:-$(cd "$ROOT/../.." && pwd)/build/dtvm}"
source "$ROOT/scripts/common.sh"
warn_if_debug_dtvm "$DTVM"
WT="${WASMTIME:-$ROOT/runtimes/wasmtime-31.0.0/out/wasmtime}"
WAPM="$ROOT/benchmarks/wapm"
PAPER_MD="$ROOT/raw_data/benchs/latencytofirstinvocation.md"

export WASMTIME_CACHE=0
export CLEAR_WASMTIME_CACHE=1

mkdir -p "$OUT/logs/dtvm" "$OUT/logs/wasmtime"

CASES=(
  amirali base64cli chkfont code-stock cowsay dice echo erdtree figlet
  irb md5 pi pkg1 qr2text sam suggest tpl uuid viu fortune
)

echo "dtvm+wasmtime compile round -> $OUT"
echo "  dtvm: $DTVM (--enable-statistics)"
echo "  wasmtime: $WT (rm -rf ~/.cache/wasmtime each run)"
echo "  repeats: $REPEATS"
echo ""

# wasmtime via existing script (writes under OUT/wt)
WT_OUT="$OUT/wt"
CLEAR_WASMTIME_CACHE=1 WASMTIME_CACHE=0 \
  "$(dirname "$0")/run_wasmtime_ttfi_compare.sh" "$REPEATS" "$WT_OUT"

# dtvm: same case driver as wasmtime script
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

run_dtvm_case() {
  local case="$1" log="$2"
  local -a params=() cmd=()
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
  # wasm path must precede flags (--dir etc.), or CLI11 drops INPUT_FILE.
  cmd=("$DTVM" "${case}.wasm" -m multipass --enable-multipass-lazy
    --disable-multipass-greedyra --disable-multipass-multithread --enable-statistics)
  if [[ -n "${DIR:-}" ]]; then
    local d
    for d in "${DIR[@]}"; do
      d="$(fix_path "$d")"
      if [[ "$d" == --dir=* ]]; then cmd+=("$d"); else cmd+=(--dir "$d"); fi
    done
  fi
  if ((${#params[@]})); then cmd+=(--args "${params[@]}"); fi

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

for case in "${CASES[@]}"; do
  load_conf "$case"
  echo ">> dtvm $case"
  for ((r = 1; r <= REPEATS; r++)); do
    run_dtvm_case "$case" "$OUT/logs/dtvm/${case}_${r}.log"
  done
done

OUT="$OUT" WT_OUT="$WT_OUT" PAPER_MD="$PAPER_MD" REPEATS="$REPEATS" python3 <<'PY'
import csv, re
from collections import defaultdict
from pathlib import Path
from statistics import mean

out = Path(__import__("os").environ["OUT"])
wt_out = Path(__import__("os").environ["WT_OUT"])
paper_md = Path(__import__("os").environ["PAPER_MD"])
repeats = int(__import__("os").environ["REPEATS"])

compile_re = re.compile(r"Total compilation time: \d+ ms \((\d+) [μµ]s\)")

paper = {}
if paper_md.is_file():
    for line in paper_md.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.search(r"case/wapm/([\w-]+)\.wasm", line)
        if not m or "avg" in line.lower():
            continue
        plain = re.sub(r"<[^>]+>", "", line)
        cells = [c.strip() for c in plain.split("|") if c.strip()]
        if len(cells) >= 4:
            paper[m.group(1)] = {"dtvm": float(cells[2]), "wasmtime": float(cells[3])}

def avg_compile(log_dir: Path):
    by = defaultdict(list)
    for log in sorted(log_dir.glob("*.log")):
        case = log.name.rsplit("_", 1)[0]
        text = log.read_text(encoding="utf-8", errors="replace")
        m = compile_re.search(text)
        if m:
            by[case].append(int(m.group(1)) / 1000.0)
    return {c: mean(v) for c, v in by.items() if v}

dtvm = avg_compile(out / "logs/dtvm")
wt = {}
with (wt_out / "results.csv").open() as f:
    for r in csv.DictReader(f):
        wt[r["case"]] = float(r["compile_ms"])

cases = sorted(set(dtvm) & set(wt))
rows = []
for c in cases:
    z, w = dtvm[c], wt[c]
    p = paper.get(c) or {}
    pz, pw = p.get("dtvm"), p.get("wasmtime")
    rows.append((c, z, w, pz, pw, w / z if z else 0,
                 z / pz if pz else None, w / pw if pw else None))

def fmt(x, nd=3):
    return f"{x:.{nd}f}" if x is not None else ""

def cell(x):
    return f"{x:.2f}" if x is not None else "n/a"

csv_path = out / "compile_compare.csv"
with csv_path.open("w") as f:
    f.write("case,dtvm_compile_ms,wt_compile_ms,paper_dtvm,paper_wt,wt_over_dtvm,dtvm_over_paper,wt_over_paper\n")
    for r in rows:
        f.write(",".join([r[0], fmt(r[1]), fmt(r[2]), fmt(r[3]), fmt(r[4]),
                          fmt(r[5], 2), fmt(r[6], 2), fmt(r[7], 2)]) + "\n")

md = [
    "# DTVM vs Wasmtime compile round (cold wasmtime cache)\n\n",
    f"- Repeats: {repeats}\n",
    "- **dtvm**: `build/dtvm` + `--enable-statistics`, `Total compilation time`\n",
    "- **wasmtime**: patched `out/wasmtime`, `rm -rf ~/.cache/wasmtime` each run, `WASMTIME_CACHE=0`\n",
]
if paper:
    md.append("- **paper**: `latencytofirstinvocation.md` lazy / wasmtime columns\n\n")
else:
    md.append("- **paper**: latency table not shipped; paper columns left blank\n\n")
md += [
    "| case | dtvm compile | wt compile | paper dtvm | paper wt | wt/dtvm | dtvm/paper | wt/paper |\n",
    "|---|---:|---:|---:|---:|---:|---:|---:|\n",
]
for c, z, w, pz, pw, ratio, zr_, wr_ in rows:
    md.append(
        f"| {c} | {z:.3f} | {w:.3f} | {fmt(pz)} | {fmt(pw, 1)} | {ratio:.2f} | {cell(zr_)} | {cell(wr_)} |\n"
    )

zr = [r[6] for r in rows if r[6] is not None]
wr = [r[7] for r in rows if r[7] is not None]
rat = [r[5] for r in rows]
if rat:
    md.append(f"\n**Mean wt/dtvm:** {mean(rat):.2f}\n")
if zr:
    md.append(f"\n**Mean dtvm/paper:** {mean(zr):.2f}  ")
    md.append(f"**Mean wt/paper:** {mean(wr):.2f}\n")
    md.append(
        f"\n**wt/paper in 0.5–2.0×:** {sum(0.5 <= x <= 2 for x in wr)}/{len(wr)} cases\n"
    )
    md.append(
        f"**dtvm/paper in 0.5–2.0×:** {sum(0.5 <= x <= 2 for x in zr)}/{len(zr)} cases\n"
    )

(out / "COMPILE_ROUND.md").write_text("".join(md))
print(f"Wrote {csv_path}")
print(f"Wrote {out / 'COMPILE_ROUND.md'}")
if rat:
    summary = f"mean wt/dtvm={mean(rat):.2f}"
    if zr:
        summary += f" mean wt/paper={mean(wr):.2f} mean dtvm/paper={mean(zr):.2f}"
    print(summary)
PY

# wall clock dtvm+wt with cache clear
RUNTIMES_OVERRIDE="dtvm wasmtime" CLEAR_WASMTIME_CACHE=1 \
  "$(dirname "$0")/run_lazy_paper.sh" "$REPEATS" "$OUT/wall"

echo ""
echo "Done: $OUT/COMPILE_ROUND.md  (wall: $OUT/wall/SUMMARY.md)"
