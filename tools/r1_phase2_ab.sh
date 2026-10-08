#!/usr/bin/env bash
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# 2×2 ablation: absinterp (R1) on/off × SPP on/off, on the paper EVM hex
# corpus. Also times closest in-tree dtvm EVM execute (fib/counter) when
# the dtvm binary is present.
#
# Usage (from repo root):
#   tools/r1_phase2_ab.sh [demo_binary] [hex_dir] [out_dir] [dtvm_binary]
#
# Default demo/dtvm: build-r1/evmCacheComplexityDemo and build-r1/dtvm
# Default hex_dir: benchmarks/paper/benchmarks/contracts/bench_bytecode
# Default out_dir: artifacts/r1

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEMO="${1:-$ROOT/build-r1/evmCacheComplexityDemo}"
HEX_DIR="${2:-$ROOT/benchmarks/paper/benchmarks/contracts/bench_bytecode}"
OUT="${3:-$ROOT/artifacts/r1}"
DTVM="${4:-$ROOT/build-r1/dtvm}"
SLICE="${SLICE:-runtime}"
GLOB="${GLOB:-*_evm.hex}"

mkdir -p "$OUT"

if [ ! -x "$DEMO" ]; then
  echo "error: $DEMO not executable" >&2
  exit 2
fi
if [ ! -d "$HEX_DIR" ]; then
  echo "error: $HEX_DIR is not a directory" >&2
  exit 2
fi

HEADER="cell,r1,spp,label,slice,code_bytes,n_jumpdest,n_jump,n_jumpi,n_jump_total,n_resolved,n_unresolved,unresolved_frac,n_jd_blocked,jd_blocked_frac,implicit_dyn_pred,n_gas_chunks,n_meter_nonzero_before,n_meter_nonzero_after,spp_zeroed_chunks,n_chunks_shifted,build_us,r1_flag,spp_flag,n_multi"

AB_CSV="$OUT/r1_phase2_ab.csv"
{
  echo "$HEADER"
  shopt -s nullglob
  for r1 in off on; do
    for spp in off on; do
      cell="r1=${r1},spp=${spp}"
      for path in "$HEX_DIR"/$GLOB; do
        [ -f "$path" ] || continue
        base=$(basename "$path")
        label=${base%.*}
        row=$("$DEMO" --bytecode "$path" --label "$label" --dump-r1-stats \
          --slice "$SLICE" --r1 "$r1" --spp "$spp")
        echo "${cell},${r1},${spp},${row}"
      done
    done
  done
} > "$AB_CSV"

echo "wrote $AB_CSV"

# Closest in-tree EVM execute: fibonacci(20) and counter increment on
# extracted runtime hex when present. test_vmbench is out-of-tree.
EXEC_LOG="$OUT/r1_phase2_exec.log"
: > "$EXEC_LOG"
if [ -x "$DTVM" ]; then
  RUNTIME_DIR="$OUT/runtime_hex"
  mkdir -p "$RUNTIME_DIR"
  # Reuse extracted runtime if Phase 1 left it; otherwise extract via demo
  # by running a throwaway stats dump (demo already extracts internally).
  FIB_HEX="$RUNTIME_DIR/fib_evm.hex"
  CTR_HEX="$RUNTIME_DIR/counter_evm.hex"
  if [ ! -s "$FIB_HEX" ] && [ -f "$HEX_DIR/fib_evm.hex" ]; then
    cp "$HEX_DIR/fib_evm.hex" "$FIB_HEX"
  fi
  if [ ! -s "$CTR_HEX" ] && [ -f "$HEX_DIR/counter_evm.hex" ]; then
    cp "$HEX_DIR/counter_evm.hex" "$CTR_HEX"
  fi

  run_exec() {
    local name=$1 hex=$2 calldata=$3 extras=$4
    if [ ! -s "$hex" ]; then
      echo "skip $name: missing $hex" | tee -a "$EXEC_LOG"
      return 0
    fi
    for r1env in 0 1; do
      local envcmd=()
      if [ "$r1env" = 0 ]; then
        envcmd=(env ZEN_EVM_DISABLE_R1=1)
        label="r1=off"
      else
        envcmd=(env -u ZEN_EVM_DISABLE_R1)
        label="r1=on"
      fi
      echo "=== $name $label extras=$extras ===" >> "$EXEC_LOG"
      local t0 t1
      t0=$(date +%s%N)
      "${envcmd[@]}" "$DTVM" --format evm --mode multipass --enable-evm-gas \
        --gas-limit 21000000 --enable-statistics \
        --num-extra-executions "$extras" \
        --calldata "$calldata" "$hex" >> "$EXEC_LOG" 2>&1 || \
        echo "dtvm $name $label failed" >> "$EXEC_LOG"
      t1=$(date +%s%N)
      python3 - <<PY >> "$EXEC_LOG"
t0=$t0; t1=$t1
print(f"wall_ms_{'$label'}_{(t1-t0)/1e6:.3f}")
PY
    done
  }

  # fibonacci(20) selector 0x61047ff4
  FIB_DATA=61047ff40000000000000000000000000000000000000000000000000000000000000014
  # counter increment() 0xd09de08a (best-effort; may revert on creation hex)
  CTR_DATA=d09de08a
  run_exec fib "$FIB_HEX" "$FIB_DATA" 50
  run_exec counter "$CTR_HEX" "$CTR_DATA" 50
  echo "test_vmbench: blocked (out-of-tree contract-testbed)" >> "$EXEC_LOG"
else
  echo "skip dtvm execute: $DTVM not executable" | tee -a "$EXEC_LOG"
fi

echo "wrote $EXEC_LOG"
