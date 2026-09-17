#!/usr/bin/env bash
# Paper-style WAPM lazy Time-to-First-Invocation (20 cases, zuk -> fortune).
# Usage: ./run_lazy_paper.sh [repeats] [output_dir]
set -euo pipefail

REPEATS="${1:-5}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${2:-$ROOT/raw_data/benchs/wapm_lazy_runs_$(date +%Y%m%d_%H%M%S)}"
[[ "$OUT" != /* ]] && OUT="$ROOT/$OUT"
WAPM="$ROOT/benchmarks/wapm"

DTVM="${DTVM:-$ROOT/runtimes/dtvm/dtvm}"
source "$ROOT/scripts/common.sh"
warn_if_debug_dtvm "$DTVM"
WASMTIME="${WASMTIME:-$ROOT/runtimes/wasmtime-31.0.0/out/wasmtime}"
WASMER="${WASMER:-$ROOT/runtimes/wasmer-5.0.4/out/bin/wasmer}"
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

RUNTIMES=(dtvm wasmtime wasmer_cranelift wasmer_llvm wasmer_singlepass)
if [[ -n "${RUNTIMES_OVERRIDE:-}" ]]; then
  # shellcheck disable=SC2206
  RUNTIMES=(${RUNTIMES_OVERRIDE})
fi

mkdir -p "$OUT"
CSV="$OUT/results.csv"
echo "case,runtime,run,wall_ms,exit_code" >"$CSV"

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
  if [[ "$case" == erdtree ]]; then
    PARAMETER=()
  fi
  if [[ "$case" == chkfont ]] && [[ -d "$WAPM/fonts" ]]; then
    DIR=(--dir=./fonts)
  elif [[ "$case" == figlet ]] && [[ -d "$WAPM/fonts" ]]; then
    DIR=(--dir=fonts)
  elif [[ "$case" == viu ]]; then
    DIR=(--dir=.)
    [[ -f "$WAPM/parallel-small.png" ]] && PARAMETER=(parallel-small.png)
  fi
}

fix_path() {
  local s="$1"
  s="${s//case\/wapm\//}"
  printf '%s' "$s"
}

append_dir_args() {
  local -n cmd_ref=$1
  if [[ -z "${DIR:-}" ]]; then
    return
  fi
  local d
  for d in "${DIR[@]}"; do
    d="$(fix_path "$d")"
    if [[ "$d" == --dir=* ]]; then
      cmd_ref+=("$d")
    else
      cmd_ref+=(--dir "$d")
    fi
  done
}

expand_params() {
  local -n _out=$1
  _out=()
  if [[ -z "${PARAMETER:-}" ]]; then
    return
  fi
  if declare -p PARAMETER 2>/dev/null | grep -q 'declare \-a'; then
    local item
    for item in "${PARAMETER[@]}"; do
      read -r -a w <<< "$item"
      _out+=("${w[@]}")
    done
  else
    read -r -a _out <<< "$PARAMETER"
  fi
}

build_runtime_cmd() {
  local runtime="$1"
  local case="$2"
  local -n _cmd=$3
  local wasm="${case}.wasm"
  local -a params=()
  expand_params params

  _cmd=()
  case "$runtime" in
    dtvm)
      _cmd=("$DTVM" -m multipass --enable-multipass-lazy
        --disable-multipass-greedyra --disable-multipass-multithread "$wasm")
      append_dir_args _cmd
      if ((${#params[@]})); then _cmd+=(--args "${params[@]}"); fi
      ;;
    wasmtime)
      # Paper / polybench: disable wasmtime module cache (see bench_polybench_timing.sh).
      export WASMTIME_CACHE="${WASMTIME_CACHE:-0}"
      _cmd=("$WASMTIME")
      append_dir_args _cmd
      _cmd+=("$wasm" "${params[@]}")
      ;;
    wasmer_cranelift|wasmer_llvm|wasmer_singlepass)
      local engine="${runtime#wasmer_}"
      _cmd=("$WASMER" run "--${engine}" --cache-dir=/dev/null)
      append_dir_args _cmd
      if ((${#params[@]})); then
        _cmd+=("$wasm" "--" "${params[@]}")
      else
        _cmd+=("$wasm")
      fi
      ;;
    *)
      echo "unknown runtime: $runtime" >&2
      return 1
      ;;
  esac
}

run_with_pipe() {
  local -n _cmd=$1
  local out="$2"
  if [[ ${#COMMAND[@]} -gt 0 && -n "${COMMAND[0]:-}" ]]; then
    if [[ "$case_name" == dice ]]; then
      echo help | "${_cmd[@]}" >"$out" 2>&1 || true
    elif [[ "$case_name" == tpl ]]; then
      echo 'Δ is 123456-123455.' | "${_cmd[@]}" >"$out" 2>&1 || true
    elif [[ ${#HEAD_COMMAND[@]} -gt 0 && "${HEAD_COMMAND[0]}" == eval ]]; then
      eval "${COMMAND[*]}" | "${_cmd[@]}" >"$out" 2>&1 || true
    else
      "${COMMAND[@]}" | "${_cmd[@]}" >"$out" 2>&1 || true
    fi
  else
    "${_cmd[@]}" >"$out" 2>&1 || true
  fi
}

echo "WAPM lazy paper reproduction"
echo "  repeats=$REPEATS  output=$OUT"
echo "  cases: ${CASES[*]}"
echo "  note: zuk replaced by fortune"
echo "  wasmtime cache: CLEAR=$CLEAR_WASMTIME_CACHE dir=$WASMTIME_CACHE_DIR"
echo ""

for case_name in "${CASES[@]}"; do
  load_conf "$case_name"
  for runtime in "${RUNTIMES[@]}"; do
    cmd=()
    build_runtime_cmd "$runtime" "$case_name" cmd
    echo ">> $case_name / $runtime"
    for ((r = 1; r <= REPEATS; r++)); do
      if [[ "$runtime" == wasmtime ]]; then
        clear_wasmtime_cache
      fi
      s=$(date +%s%3N)
      out="/tmp/wapm_${case_name}_${runtime}_${r}.out"
      run_with_pipe cmd "$out"
      ec=$?
      e=$(date +%s%3N)
      ms=$((e - s))
      echo "$case_name,$runtime,$r,$ms,$ec" >>"$CSV"
    done
  done
done

ROOT="$ROOT" python3 - "$OUT" "$CSV" "$REPEATS" "$ROOT" <<'PY'
import csv
import sys
from collections import defaultdict
from pathlib import Path

out_dir = Path(sys.argv[1])
csv_path = Path(sys.argv[2])
repeats = int(sys.argv[3])
root = Path(sys.argv[4])


rows = list(csv.DictReader(csv_path.open()))
by = defaultdict(list)
for row in rows:
    by[(row["case"], row["runtime"])].append(int(row["wall_ms"]))

def avg(vals):
    return sum(vals) / len(vals) if vals else float("nan")

cases = sorted({r["case"] for r in rows})
runtimes = ["dtvm", "wasmtime", "wasmer_cranelift", "wasmer_llvm", "wasmer_singlepass"]

md = []
md.append("# WAPM Lazy Benchmark (paper workflow)\n")
md.append(f"- Repeats per case/runtime: **{repeats}**")
md.append("- Cases: 20 (original latency set with **zuk → fortune**)")
md.append("- DTVM: `dtvm -m multipass --enable-multipass-lazy --disable-multipass-greedyra --disable-multipass-multithread`")
md.append("- Wasmtime: `WASMTIME_CACHE=0` (module cache off, paper/polybench alignment)")
md.append("- Wall-clock ms (shell); paper used missing `test_lazy.sh` (likely different instrumentation)\n")
md.append("## Summary (avg ms)\n")
hdr = "| case | wasm KB | dtvm | wasmtime | wasmer-cranelift | wasmer-llvm | wasmer-singlepass | wt/dtvm | cr/dtvm | llvm/dtvm | sp/dtvm |"
md.append(hdr)
md.append("|" + "---|" * (len(hdr.split("|")) - 1))

import os
wapm = root / "benchmarks" / "wapm"

for case in cases:
    wasm = wapm / f"{case}.wasm"
    kb = wasm.stat().st_size / 1024 if wasm.exists() else 0
    vals = {}
    for rt in runtimes:
        vals[rt] = avg(by.get((case, rt), []))
    z = vals["dtvm"] or 1.0
    def ratio(x):
        return f"{x/z:.2f}" if z and x == x else "n/a"
    md.append(
        f"| {case} | {kb:.1f} | {vals['dtvm']:.1f} | {vals['wasmtime']:.1f} | "
        f"{vals['wasmer_cranelift']:.1f} | {vals['wasmer_llvm']:.1f} | {vals['wasmer_singlepass']:.1f} | "
        f"{ratio(vals['wasmtime'])} | {ratio(vals['wasmer_cranelift'])} | {ratio(vals['wasmer_llvm'])} | {ratio(vals['wasmer_singlepass'])} |"
    )


summary = out_dir / "SUMMARY.md"
summary.write_text("\n".join(md) + "\n")
print(f"Wrote {summary}")
PY

echo ""
echo "Results: $CSV"
echo "Summary: $OUT/SUMMARY.md"
