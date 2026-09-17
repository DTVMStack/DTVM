#!/bin/bash
# Overflow benchmark runner — DTVM (multipass + checked arithmetic)
#
# Usage:
#   1. Build DTVM with multipass + checked arithmetic enabled (see REPRODUCE_fib_overflow_5way.md §1).
#      Override path via:  DTVM=/path/to/dtvm bash run_dtvm.sh
#   2. Make sure em++ (Emscripten, tested 5.0.7) is on PATH so wasm can be built.
#   3. Run: bash run_dtvm.sh
#
# This script automatically compiles perf_test_swap_pool.cpp into 4 wasm
# variants (-O2/-O1/-O0/-g) the first time it runs, or whenever the wasm
# file is missing. Set FORCE_REBUILD=1 to always rebuild.
#
# Per opt level: 5 repetitions, taskset CPU 0, bash builtin time.

set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
DTVM="${DTVM:-$(cd "$DIR/../../../.." && pwd)/build/dtvm}"
source "$DIR/../../scripts/common.sh"
warn_if_debug_dtvm "$DTVM"
OUT="${OUT:-/tmp/overflow_dtvm_raw.log}"
N="${N:-100000000}"
INPUT="${INPUT:-2000000}"
REPS="${REPS:-5}"
CPU="${CPU:-0}"
MODE="${MODE:-multipass}"
FORCE_REBUILD="${FORCE_REBUILD:-0}"

if [ ! -x "$DTVM" ]; then
  echo "dtvm not executable at $DTVM" >&2
  exit 1
fi

# Build wasm if missing (or always when FORCE_REBUILD=1).
# Compile command for one variant (Emscripten 5.0.7), note -DENABLE_DTVM_TEST
# which makes the cpp use env::checked_i64_* hostapis instead of __builtin_*_overflow:
#   em++ -std=c++17 -O2 -o perf_test_swap_pool_dtvm_O2.wasm \
#     perf_test_swap_pool.cpp -DENABLE_DTVM_TEST -I . \
#     -s 'EXPORTED_FUNCTIONS=["_test_dtvm"]' \
#     --no-entry -Wl,--allow-undefined \
#     -s ERROR_ON_UNDEFINED_SYMBOLS=0 -s WASM=1 \
#     -s STANDALONE_WASM=0 -s PURE_WASI=1
for OPT in O2 O1 O0 g; do
  WASM="$DIR/perf_test_swap_pool_dtvm_${OPT}.wasm"
  if [ "$FORCE_REBUILD" = "1" ] || [ ! -f "$WASM" ]; then
    if ! command -v em++ >/dev/null; then
      echo "em++ not on PATH; source emsdk_env.sh first" >&2
      exit 1
    fi
    echo "[build] em++ -$OPT -DENABLE_DTVM_TEST -> $(basename "$WASM")" >&2
    em++ -std=c++17 -o "$WASM" -$OPT \
      "$DIR/perf_test_swap_pool.cpp" -DENABLE_DTVM_TEST -I "$DIR" \
      -s 'EXPORTED_FUNCTIONS=["_test_dtvm"]' \
      --no-entry -Wl,--allow-undefined \
      -s ERROR_ON_UNDEFINED_SYMBOLS=0 -s WASM=1 \
      -s STANDALONE_WASM=0 -s PURE_WASI=1
  fi
done

: > "$OUT"
{
  echo "dtvm: $DTVM ($(stat -c %y "$DTVM" 2>/dev/null | cut -d. -f1))"
  echo "dtvm_commit: $(cd "$(dirname "$DTVM")/.." && git rev-parse HEAD 2>/dev/null)"
  echo "dtvm_mode: $MODE"
  echo "host: $(uname -a)"
  echo "cpu_model: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //')"
  echo "cpu_family_model_stepping: family=$(grep -m1 'cpu family' /proc/cpuinfo | awk '{print $4}') model=$(grep -m1 '^model' /proc/cpuinfo | awk '{print $3}') stepping=$(grep -m1 'stepping' /proc/cpuinfo | awk '{print $3}')"
  echo "cpu_mhz_observed: $(grep -m1 'cpu MHz' /proc/cpuinfo | awk '{print $4}')"
  echo "no_turbo: $(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || echo unknown)"
  echo "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)"
  echo "n=$N input_amount=$INPUT reps=$REPS taskset_cpu=$CPU"
  echo "----"
} | tee -a "$OUT"

for OPT in O2 O1 O0 g; do
  WASM="$DIR/perf_test_swap_pool_dtvm_${OPT}.wasm"
  echo "### opt=$OPT  file=$(basename "$WASM")" | tee -a "$OUT"
  for i in $(seq 1 $REPS); do
    LINE=$( { taskset -c "$CPU" bash -c "time $DTVM --format wasm -m $MODE -f test_dtvm $WASM --args $N $INPUT >/dev/null"; } 2>&1 | grep -E '^(real|user|sys)' | tr '\n' ' ' )
    echo "  rep$i $LINE" | tee -a "$OUT"
  done
done
echo "----" | tee -a "$OUT"
echo "raw log: $OUT"
