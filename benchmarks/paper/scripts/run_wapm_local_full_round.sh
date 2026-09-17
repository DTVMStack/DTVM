#!/usr/bin/env bash
# One-shot: build runtimes (if needed), run all WAPM TTFI benches, emit local paper-style table.
set -euo pipefail

REPEATS="${1:-3}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAMP="$(date +%Y%m%d_%H%M%S)"
BENCH_ROOT="$ROOT/raw_data/benchs/wapm_local_round_${STAMP}"

DTVM="${DTVM:-$(cd "$ROOT/../.." && pwd)/build/dtvm}"
export DTVM

echo "=== WAPM local full round -> $BENCH_ROOT ==="
mkdir -p "$BENCH_ROOT"

# 1) dtvm + wasmtime
DTVM_WT_OUT="$BENCH_ROOT/dtvm_wt"
DTVM="$DTVM" "$(dirname "$0")/run_dtvm_wt_compile_round.sh" "$REPEATS" "$DTVM_WT_OUT"

# 2) wasmer backends
WASMER_OUT_CR="$BENCH_ROOT/wasmer_cranelift"
WASMER_OUT_SP="$BENCH_ROOT/wasmer_singlepass"
"$(dirname "$0")/run_wasmer_ttfi_compare.sh" "$REPEATS" "$WASMER_OUT_CR" cranelift
"$(dirname "$0")/run_wasmer_ttfi_compare.sh" "$REPEATS" "$WASMER_OUT_SP" singlepass

# 3) merge table
OUT_DIR="$BENCH_ROOT/table" \
  DTVM_LOG_DIR="$DTVM_WT_OUT/logs/dtvm" \
  WT_CSV="$DTVM_WT_OUT/wt/results.csv" \
  WASMER_CR_CSV="$WASMER_OUT_CR/results.csv" \
  WASMER_SP_CSV="$WASMER_OUT_SP/results.csv" \
  ROOT="$ROOT" \
  python3 "$(dirname "$0")/build_wapm_local_table.py"

cp "$BENCH_ROOT/table/wapm_local_latency_table.md" "$ROOT/raw_data/benchs/wapm_local_latency_table.md"
cp "$BENCH_ROOT/table/wapm_local_latency_table.csv" "$ROOT/raw_data/benchs/wapm_local_latency_table.csv"

echo ""
echo "Done."
echo "  Round dir: $BENCH_ROOT"
echo "  Table:     $ROOT/raw_data/benchs/wapm_local_latency_table.md"
