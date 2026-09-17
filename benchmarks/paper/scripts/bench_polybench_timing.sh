#!/usr/bin/env bash
# Benchmark PolyBench/C wasm cases and emit CSV for comparison with dtvm_polybench.xlsx.
#
# Timing semantics (local reproduction):
#   - Wall time of one process invocation (includes JIT compile on first run).
#   - Default: 1 warmup + N timed runs; reports min/mean/median ms.
#   - Does not match archived paper logs unless the original harness is recovered.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CASE_DIR="${CASE_DIR:-$ROOT/benchmarks/polybenchc}"
OUT_DIR="${OUT_DIR:-$ROOT/raw_data/benchs}"
REPEATS="${REPEATS:-3}"
WARMUP="${WARMUP:-1}"
RUNTIME="${1:-dtvm}"
PROFILE="${2:-multipass}"

mkdir -p "$OUT_DIR"
STAMP="$(date +%Y%m%d_%H%M%S)"
CSV="$OUT_DIR/polybench_timing_${RUNTIME}_${PROFILE}_${STAMP}.csv"

DTVM="${DTVM:-$ROOT/runtimes/dtvm/dtvm}"
WASMTIME="${WASMTIME:-$ROOT/runtimes/wasmtime-31.0.0/out/wasmtime}"
IWASM="${IWASM:-$ROOT/runtimes/wamr-1.2.3/out/iwasm}"
WASMER="${WASMER:-$ROOT/runtimes/wasmer-5.0.4/out/wasmer}"

source "$ROOT/scripts/common.sh"
if [[ "$RUNTIME" == "dtvm" ]]; then
  warn_if_debug_dtvm "$DTVM"
fi
XLSX="${XLSX:-$ROOT/raw_data/benchs/dtvm_polybench.xlsx}"

wasmer_compiler_flag() {
  case "$PROFILE" in
    cranelift) echo --cranelift ;;
    llvm) echo --llvm ;;
    singlepass) echo --singlepass ;;
    *)
      echo "Unknown wasmer profile: $PROFILE (cranelift|llvm|singlepass)" >&2
      return 2
      ;;
  esac
}

dtvm_profile_opts() {
  case "$PROFILE" in
    lazy)
      echo "-m multipass --enable-multipass-lazy --disable-multipass-greedyra --disable-multipass-multithread"
      ;;
    lazy_greedy_mt)
      # Lazy + greedy RA + multipass multithread (all enabled).
      echo "-m multipass --enable-multipass-lazy"
      ;;
    multipass_greedy_mt)
      # Greedy register allocation + multipass multithread enabled (defaults).
      echo "-m multipass"
      ;;
    multipass|*)
      echo "-m multipass --disable-multipass-greedyra --disable-multipass-multithread"
      ;;
  esac
}

run_case() {
  local wasm="$1"
  local -a cmd=()
  case "$RUNTIME" in
    dtvm)
      local -a zopts=()
      read -r -a zopts <<< "$(dtvm_profile_opts)"
      cmd=("$DTVM" "${zopts[@]}" "$wasm")
      ;;
    wasmtime)
      if [[ "$PROFILE" == "nocache" ]]; then
        export WASMTIME_CACHE=0
      fi
      cmd=("$WASMTIME" run "$wasm" --invoke main)
      ;;
    wasmtime_nocache)
      WASMTIME_CACHE=0 cmd=("$WASMTIME" run "$wasm" --invoke main)
      ;;
    iwasm)
      cmd=("$IWASM" --heap-size=0 --stack-size=8000000 "$wasm")
      ;;
    wasmer)
      local -a wopts=()
      read -r -a wopts <<< "$(wasmer_compiler_flag)"
      cmd=("$WASMER" run "$wasm" "${wopts[@]}" -q)
      ;;
    *)
      echo "Unknown runtime: $RUNTIME (dtvm|wasmtime|wasmtime_nocache|iwasm|wasmer)" >&2
      return 2
      ;;
  esac

  local i rc
  for ((i = 0; i < WARMUP; i++)); do
    "${cmd[@]}" >/dev/null 2>&1 || return 1
  done

  measure_ms() {
    local start end
    start="$(date +%s%N)"
    set +e
    "${cmd[@]}" >/dev/null 2>&1
    rc=$?
    set -e
    end="$(date +%s%N)"
    if [[ $rc -ne 0 ]]; then
      return 1
    fi
    awk -v s="$start" -v e="$end" 'BEGIN { printf "%.3f", (e - s) / 1e6 }'
  }

  local -a samples=()
  for ((i = 0; i < REPEATS; i++)); do
    wall="$(measure_ms)" || {
      echo "failed"
      return 1
    }
    samples+=("$wall")
  done

  local min mean med
  min="$(printf '%s\n' "${samples[@]}" | sort -n | head -1)"
  mean="$(printf '%s\n' "${samples[@]}" | awk '{s+=$1} END {printf "%.3f", s/NR}')"
  med="$(printf '%s\n' "${samples[@]}" | sort -n | awk '{
    a[NR]=$1
  } END {
    if (NR%2) printf "%.3f", a[(NR+1)/2]; else printf "%.3f", (a[NR/2]+a[NR/2+1])/2
  }')"
  echo "$min,$mean,$med"
}

echo "case,runtime,profile,repeat_min_ms,repeat_mean_ms,repeat_median_ms,exit" > "$CSV"

shopt -s nullglob
for wasm in "$CASE_DIR"/*.wasm; do
  case_name="$(basename "$wasm" .wasm)"
  printf '%s' "$case_name" >&2
  result="$(run_case "$wasm" 2>/dev/null || echo "failed,failed,failed,1")"
  IFS=',' read -r min_ms mean_ms med_ms exit_code <<< "$result"
  if [[ "$result" == *failed* ]]; then
    echo "$case_name,$RUNTIME,$PROFILE,,,,1" >> "$CSV"
    echo " FAIL" >&2
  else
    echo "$case_name,$RUNTIME,$PROFILE,$min_ms,$mean_ms,$med_ms,0" >> "$CSV"
    echo " ${med_ms}ms" >&2
  fi
done

echo "Wrote $CSV"

if command -v python3 >/dev/null && [[ -f "$XLSX" ]]; then
  python3 - "$CSV" "$XLSX" "$RUNTIME" "$PROFILE" <<'PY'
import sys, zipfile
from xml.etree import ElementTree as ET

csv_path, xlsx_path, runtime, profile = sys.argv[1:5]
col_map = {
    ("dtvm", "multipass"): "dtvm  multipass",
    ("dtvm", "multipass_greedy_mt"): "dtvm  multipass",
    ("dtvm", "lazy"): "dtvm multipass + lazy ",
    ("dtvm", "lazy_greedy_mt"): "dtvm multipass + lazy ",
    ("wasmtime", "default"): "wasmtime",
    ("wasmtime", "nocache"): "wasmtime nocache",
    ("wasmer", "cranelift"): "wasmer cranelift",
    ("wasmer", "llvm"): "wasmer llvm",
    ("wasmer", "singlepass"): "wasmer singlepass",
}
col = col_map.get((runtime, profile))
if not col:
    sys.exit(0)

ns = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
with zipfile.ZipFile(xlsx_path) as z:
    ss = ET.fromstring(z.read("xl/sharedStrings.xml"))
    strings = [
        "".join(
            (x.text or "")
            for x in si.iter("{http://schemas.openxmlformats.org/spreadsheetml/2006/main}t")
        )
        for si in ss.findall("m:si", ns)
    ]
    sh = ET.fromstring(z.read("xl/worksheets/sheet1.xml"))
    rows = sh.findall(".//m:row", ns)
    header = []
    for c in rows[0].findall("m:c", ns):
        v = c.find("m:v", ns)
        if v is None:
            continue
        header.append(strings[int(v.text)] if c.get("t") == "s" else v.text)
    try:
        col_idx = header.index(col)
    except ValueError:
        print(f"Column not found: {col!r}")
        sys.exit(0)
    ref = {}
    for row in rows[1:]:
        cells = row.findall("m:c", ns)
        if not cells:
            continue
        name = None
        val = None
        for c in cells:
            r = c.get("r", "")
            col_letter = "".join(ch for ch in r if ch.isalpha())
            v = c.find("m:v", ns)
            if v is None:
                continue
            if col_letter == "A":
                name = (
                    strings[int(v.text)]
                    if c.get("t") == "s"
                    else v.text
                )
                if name.endswith(".wasm"):
                    name = name.split("/")[-1].replace(".wasm", "")
            idx = ord(col_letter) - ord("A")
            if idx == col_idx:
                val = float(v.text)
        if name:
            ref[name] = val

import csv
ours = {}
with open(csv_path) as f:
    for row in csv.DictReader(f):
        if row.get("repeat_median_ms"):
            ours[row["case"]] = float(row["repeat_median_ms"])

print(f"\nComparison vs xlsx column: {col}")
print(f"{'case':<16} {'ours_med':>10} {'xlsx':>10} {'ratio':>8}")
for case in sorted(ref):
    if case not in ours:
        continue
    x = ref[case]
    o = ours[case]
    ratio = o / x if x else 0
    print(f"{case:<16} {o:10.2f} {x:10.2f} {ratio:8.2f}")
PY
fi
