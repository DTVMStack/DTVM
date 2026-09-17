#!/usr/bin/env bash
# WAPM compile-time round: dtvm (DTVM) + wasmtime 45.0.0 + wasmer 7.1.0
set -euo pipefail

REPEATS="${1:-3}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAMP="$(date +%Y%m%d_%H%M%S)"
BENCH_ROOT="$ROOT/raw_data/benchs/wapm_v45_v71_${STAMP}"

DTVM="${DTVM:-$(cd "$ROOT/../.." && pwd)/build/dtvm}"
WASMTIME="${WASMTIME:-$ROOT/runtimes/wasmtime-45.0.0/out/wasmtime}"
WASMER="${WASMER:-$ROOT/runtimes/wasmer-7.1.0/out/bin/wasmer}"

export DTVM WASMTIME WASMER
export WASMTIME_CACHE=0
export CLEAR_WASMTIME_CACHE=1

echo "=== WAPM v45/v71 round -> $BENCH_ROOT ==="
echo "  dtvm:      $DTVM"
echo "  wasmtime: $WASMTIME ($($WASMTIME --version 2>&1 | head -1))"
echo "  wasmer:   $WASMER ($($WASMER --version 2>&1 | head -1))"
echo "  repeats:  $REPEATS"
echo ""

mkdir -p "$BENCH_ROOT"

# dtvm + wasmtime
DTVM_WT_OUT="$BENCH_ROOT/dtvm_wt"
DTVM="$DTVM" WASMTIME="$WASMTIME" \
  "$(dirname "$0")/run_dtvm_wt_compile_round.sh" "$REPEATS" "$DTVM_WT_OUT"

# wasmer backends
for engine in cranelift singlepass llvm; do
  if [[ "$engine" == llvm ]]; then
    if ! "$WASMER" run --help 2>&1 | grep -q -- '--llvm'; then
      echo "SKIP wasmer llvm (binary not built with llvm feature)"
      continue
    fi
  fi
  WASMER="$WASMER" "$(dirname "$0")/run_wasmer_ttfi_compare.sh" \
    "$REPEATS" "$BENCH_ROOT/wasmer_${engine}" "$engine"
done

LLVM_CSV="$BENCH_ROOT/wasmer_llvm/results.csv"
export OUT_DIR="$BENCH_ROOT/table"
export DTVM_LOG_DIR="$DTVM_WT_OUT/logs/dtvm"
export WT_CSV="$DTVM_WT_OUT/wt/results.csv"
export WASMER_CR_CSV="$BENCH_ROOT/wasmer_cranelift/results.csv"
export WASMER_SP_CSV="$BENCH_ROOT/wasmer_singlepass/results.csv"
export ROOT="$ROOT"
if [[ -f "$LLVM_CSV" ]]; then
  export WASMER_LLVM_CSV="$LLVM_CSV"
else
  unset WASMER_LLVM_CSV 2>/dev/null || true
fi
python3 "$(dirname "$0")/build_wapm_local_table.py"

cp "$BENCH_ROOT/table/wapm_local_latency_table.md" \
  "$ROOT/raw_data/benchs/wapm_v45_v71_latency_table.md"
cp "$BENCH_ROOT/table/wapm_local_latency_table.csv" \
  "$ROOT/raw_data/benchs/wapm_v45_v71_latency_table.csv"

# Append version banner
{
  echo ""
  echo "---"
  echo ""
  echo "**Runtimes:** wasmtime 45.0.0, wasmer 7.1.0 (cranelift + singlepass + llvm), dtvm (DTVM \`build/dtvm\`)"
  echo ""
  echo "**LLVM:** \`${LLVM_SYS_211_PREFIX:-/opt/LLVM-21.1.8-Linux-X64}\`"
  echo ""
  echo "**Data dir:** \`$BENCH_ROOT\`"
} >> "$ROOT/raw_data/benchs/wapm_v45_v71_latency_table.md"

echo ""
echo "Done: $ROOT/raw_data/benchs/wapm_v45_v71_latency_table.md"
