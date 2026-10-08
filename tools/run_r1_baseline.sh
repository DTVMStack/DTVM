#!/usr/bin/env bash
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Reproduce the R1 Phase-1 baseline: configure a RelWithDebInfo EVM
# (+ multipass when LLVM 15 is available), run in-tree benches that
# this VM can host, and dump jump/SPP upper-bound counters on the
# paper contract hex corpus.
#
# Usage (from repo root):
#   tools/run_r1_baseline.sh
#   LLVM_DIR=/opt/llvm15/lib/cmake/llvm tools/run_r1_baseline.sh
#
# Outputs land under artifacts/r1/ (gitignored logs + committed report
# is written separately).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT/build-r1}"
ARTIFACTS="${ARTIFACTS:-$ROOT/artifacts/r1}"
JOBS="${JOBS:-2}"
HEX_DIR="$ROOT/benchmarks/paper/benchmarks/contracts/bench_bytecode"
POLY_DIR="$ROOT/benchmarks/paper/benchmarks/polybenchc"
CACHE_RUNS="${CACHE_RUNS:-5}"

mkdir -p "$ARTIFACTS"

log() { printf '[r1-baseline] %s\n' "$*"; }

detect_llvm_dir() {
  if [[ -n "${LLVM_DIR:-}" && -f "${LLVM_DIR}/LLVMConfig.cmake" ]]; then
    echo "$LLVM_DIR"
    return 0
  fi
  if [[ -n "${LLVM_SYS_150_PREFIX:-}" && -f "${LLVM_SYS_150_PREFIX}/lib/cmake/llvm/LLVMConfig.cmake" ]]; then
    echo "${LLVM_SYS_150_PREFIX}/lib/cmake/llvm"
    return 0
  fi
  local Candidate
  for Candidate in \
    /opt/llvm15/lib/cmake/llvm \
    /opt/clang+llvm-15.0.0-x86_64-linux-gnu-rhel-8.4/lib/cmake/llvm \
    /opt/clang+llvm-15.0.6-x86_64-linux-gnu-ubuntu-18.04/lib/cmake/llvm \
    /opt/llvm-15/lib/cmake/llvm; do
    if [[ -f "$Candidate/LLVMConfig.cmake" ]]; then
      echo "$Candidate"
      return 0
    fi
  done
  return 1
}

CMAKE_GENERATOR=()
if command -v ninja >/dev/null 2>&1; then
  CMAKE_GENERATOR=(-G Ninja)
fi

ENABLE_MULTIPASS=OFF
LLVM_CMAKE_DIR=""
if LLVM_CMAKE_DIR=$(detect_llvm_dir); then
  ENABLE_MULTIPASS=ON
  log "LLVM 15 found at $LLVM_CMAKE_DIR — enabling multipass"
else
  log "LLVM 15 not found — building EVM cache/interpreter only (no multipass)"
fi

CMAKE_ARGS=(
  -S "$ROOT"
  -B "$BUILD_DIR"
  "${CMAKE_GENERATOR[@]}"
  -DCMAKE_BUILD_TYPE=RelWithDebInfo
  -DZEN_ENABLE_EVM=ON
  -DZEN_ENABLE_SINGLEPASS_JIT=OFF
  -DZEN_ENABLE_SPEC_TEST=ON
  -DZEN_ENABLE_MULTIPASS_JIT="$ENABLE_MULTIPASS"
)
if [[ "$ENABLE_MULTIPASS" == ON ]]; then
  CMAKE_ARGS+=(-DLLVM_DIR="$LLVM_CMAKE_DIR")
fi

log "cmake ${CMAKE_ARGS[*]}"
cmake "${CMAKE_ARGS[@]}" | tee "$ARTIFACTS/cmake-configure.log"

TARGETS=(evmCacheComplexityDemo dtvm)
if [[ "$ENABLE_MULTIPASS" == ON ]]; then
  TARGETS+=(evmCacheTests)
fi

log "cmake --build $BUILD_DIR --target ${TARGETS[*]} -j$JOBS"
cmake --build "$BUILD_DIR" --target "${TARGETS[@]}" -j"$JOBS" \
  | tee "$ARTIFACTS/cmake-build.log"

DEMO="$BUILD_DIR/evmCacheComplexityDemo"
DTVM="$BUILD_DIR/dtvm"

log "R1 stats (runtime slice) on paper EVM hex"
"$ROOT/tools/r1_baseline_stats.sh" "$DEMO" "$HEX_DIR" \
  "$ARTIFACTS/r1_stats_runtime.csv" runtime

log "R1 stats (full hex, including constructor/metadata if extraction skipped)"
"$ROOT/tools/r1_baseline_stats.sh" "$DEMO" "$HEX_DIR" \
  "$ARTIFACTS/r1_stats_auto.csv" auto

log "evm-cache wall-clock ($CACHE_RUNS runs / file)"
"$ROOT/tools/bench_evm_cache.sh" "$DEMO" "$HEX_DIR" "$CACHE_RUNS" \
  "$ARTIFACTS/evm_cache_timing.csv"

# Synthetic sanity: one unresolved JUMP must stamp every JUMPDEST.
log "synthetic sanity (8 JUMPDESTs)"
"$DEMO" 8 --dump-r1-stats --label synthetic8 \
  | tee "$ARTIFACTS/synthetic_r1_stats.csv"

if [[ "$ENABLE_MULTIPASS" == ON ]]; then
  log "PolyBench timing (dtvm multipass, paper script)"
  DTVM="$DTVM" CASE_DIR="$POLY_DIR" OUT_DIR="$ARTIFACTS" REPEATS=3 WARMUP=1 \
    "$ROOT/benchmarks/paper/scripts/bench_polybench_timing.sh" dtvm multipass \
    | tee "$ARTIFACTS/polybench_timing.log" || \
    log "PolyBench timing failed (see log)"

  log "dtvm EVM CLI smoke (fib deploy + extra executions)"
  /usr/bin/time -f 'elapsed_sec=%e' \
    "$DTVM" --format evm --mode multipass --enable-evm-gas --deploy \
      --enable-statistics --num-extra-executions 20 --benchmark \
      "$HEX_DIR/fib_evm.hex" \
      > "$ARTIFACTS/dtvm_fib_deploy.log" 2>&1 || \
    log "fib deploy CLI failed (see log)"
else
  log "skip PolyBench multipass and EVM JIT CLI — LLVM 15 missing"
  log "interpreter CLI smoke (fib deploy)"
  /usr/bin/time -f 'elapsed_sec=%e' \
    "$DTVM" --format evm --mode interpreter --enable-evm-gas --deploy \
      --enable-statistics --num-extra-executions 5 --benchmark \
      "$HEX_DIR/fib_evm.hex" \
      > "$ARTIFACTS/dtvm_fib_deploy_interp.log" 2>&1 || \
    log "fib interpreter CLI failed (see log)"
fi

log "done. artifacts in $ARTIFACTS"
ls -la "$ARTIFACTS"
