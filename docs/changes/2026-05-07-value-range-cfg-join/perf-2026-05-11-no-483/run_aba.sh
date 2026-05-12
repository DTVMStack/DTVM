#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")"

EVMONE_BENCH=/home/abmcar/evmone/build/bin/evmone-bench
BENCHES=/home/abmcar/evmone/test/evm-benchmarks/benchmarks
FILTER='^external/total/(main|micro)/'
REPS=20
BRANCH_LIB=/home/abmcar/DTVM/.worktrees/perf-value-range-cfg-join/build/lib/libdtvmapi.so
BASELINE_LIB=/home/abmcar/dtvm-baseline/build-baseline/lib/libdtvmapi.so

echo "=== Pass 1: branch (d1: 3d273e0 = f203bd5 with #483 reverted) ===" | tee -a progress.log
date | tee -a progress.log
taskset -c 2 "$EVMONE_BENCH" \
  "${BRANCH_LIB},mode=multipass" "$BENCHES" \
  --benchmark_filter="$FILTER" --benchmark_repetitions=$REPS \
  --benchmark_format=json --benchmark_out=branch.json > branch.stdout 2> branch.stderr
echo "Pass 1 exit: $?" | tee -a progress.log
date | tee -a progress.log

echo "=== Pass 2: baseline (upstream/main c644fbe) ===" | tee -a progress.log
date | tee -a progress.log
taskset -c 2 "$EVMONE_BENCH" \
  "${BASELINE_LIB},mode=multipass" "$BENCHES" \
  --benchmark_filter="$FILTER" --benchmark_repetitions=$REPS \
  --benchmark_format=json --benchmark_out=baseline.json > baseline.stdout 2> baseline.stderr
echo "Pass 2 exit: $?" | tee -a progress.log
date | tee -a progress.log

echo "=== Pass 3: baseline_pingpong (drift control) ===" | tee -a progress.log
date | tee -a progress.log
taskset -c 2 "$EVMONE_BENCH" \
  "${BASELINE_LIB},mode=multipass" "$BENCHES" \
  --benchmark_filter="$FILTER" --benchmark_repetitions=$REPS \
  --benchmark_format=json --benchmark_out=baseline_pingpong.json > baseline_pingpong.stdout 2> baseline_pingpong.stderr
echo "Pass 3 exit: $?" | tee -a progress.log
date | tee -a progress.log
echo "=== ALL DONE ===" | tee -a progress.log
