#!/usr/bin/env bash
# PolyBench TTFI round: DTVM main + wasmtime 45 + wasmer 7.1 (3 backends).
# Same metric as WAPM (Total compilation time). Default 1 repeat per case (faster).
set -euo pipefail

REPEATS="${1:-1}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAMP="$(date +%Y%m%d_%H%M%S)"
BENCH_ROOT="$ROOT/raw_data/benchs/polybench_ttfi_${STAMP}"
SCRIPT_DIR="$(dirname "$0")"

DTVM="${DTVM:-$ROOT/runtimes/dtvm_main/dtvm}"
source "$ROOT/scripts/common.sh"
warn_if_debug_dtvm "$DTVM"
WASMTIME="${WASMTIME:-$ROOT/runtimes/wasmtime-45.0.0/out/wasmtime}"
WASMER="${WASMER:-$ROOT/runtimes/wasmer-7.1.0/out/wasmer}"

export DTVM WASMTIME WASMER
export WASMTIME_CACHE=0
export CLEAR_WASMTIME_CACHE=1

ttfi_hits="$(strings "$DTVM" 2>/dev/null | grep -c 'Total compilation time' || true)"
if [[ "${ttfi_hits:-0}" -lt 1 ]]; then
  echo "error: DTVM binary missing TTFI strings: $DTVM" >&2
  exit 1
fi

mkdir -p "$BENCH_ROOT"
chmod +x "$SCRIPT_DIR/run_polybench_ttfi_compare.sh"

echo "=== PolyBench TTFI round -> $BENCH_ROOT ==="
echo "  dtvm:      $DTVM"
echo "  wasmtime: $WASMTIME ($($WASMTIME --version 2>&1 | head -1))"
echo "  wasmer:   $WASMER ($($WASMER --version 2>&1 | head -1))"
echo "  repeats:  $REPEATS"
echo ""

DTVM="$DTVM" "$SCRIPT_DIR/run_polybench_ttfi_compare.sh" dtvm lazy "$REPEATS" \
  "$BENCH_ROOT/dtvm_lazy"
DTVM="$DTVM" "$SCRIPT_DIR/run_polybench_ttfi_compare.sh" dtvm multipass_greedy_mt "$REPEATS" \
  "$BENCH_ROOT/dtvm_multipass_greedy_mt"
WASMTIME="$WASMTIME" "$SCRIPT_DIR/run_polybench_ttfi_compare.sh" wasmtime default "$REPEATS" \
  "$BENCH_ROOT/wasmtime45"
for engine in singlepass cranelift llvm; do
  if [[ "$engine" == llvm ]] && ! "$WASMER" run --help 2>&1 | grep -q -- '--llvm'; then
    echo "SKIP wasmer llvm (binary not built with llvm feature)"
    continue
  fi
  WASMER="$WASMER" "$SCRIPT_DIR/run_polybench_ttfi_compare.sh" wasmer "$engine" "$REPEATS" \
    "$BENCH_ROOT/wasmer_${engine}"
done

export BENCH_ROOT
export OUT_DIR="$BENCH_ROOT/table"
export DTVM_CSV="$BENCH_ROOT/dtvm_lazy/results.csv"
export DTVM_GREEDY_CSV="$BENCH_ROOT/dtvm_multipass_greedy_mt/results.csv"
export WT_CSV="$BENCH_ROOT/wasmtime45/results.csv"
export WASMER_SP_CSV="$BENCH_ROOT/wasmer_singlepass/results.csv"
export WASMER_CF_CSV="$BENCH_ROOT/wasmer_cranelift/results.csv"
export WASMER_LLVM_CSV="$BENCH_ROOT/wasmer_llvm/results.csv"
export DTVM_VERSION="$ROOT/runtimes/dtvm_main/version.txt"
python3 "$SCRIPT_DIR/build_polybench_ttfi_table.py"

cp "$BENCH_ROOT/table/polybench_ttfi_compare.md" \
  "$ROOT/raw_data/benchs/polybench_ttfi_compare_latest.md"
cp "$BENCH_ROOT/table/polybench_ttfi_compare.csv" \
  "$ROOT/raw_data/benchs/polybench_ttfi_compare_latest.csv"

echo ""
echo "Done:"
echo "  $ROOT/raw_data/benchs/polybench_ttfi_compare_latest.md"
echo "  $ROOT/raw_data/benchs/polybench_ttfi_compare_latest.csv"
echo "  $BENCH_ROOT/"
