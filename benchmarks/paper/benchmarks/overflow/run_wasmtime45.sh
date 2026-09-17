#!/bin/bash
# Overflow benchmark — wasmtime 45.0.0 reproducer
#
# Usage:
#   1. Set WT to your wasmtime path (default: ~/.wasmtime/bin/wasmtime).
#   2. Make sure em++ (Emscripten, tested 5.0.7) is on PATH.
#      Easiest: `source /path/to/emsdk/emsdk_env.sh`
#   3. Run: bash run_wasmtime45.sh
#
# This script automatically compiles perf_test_swap_pool.cpp into 4 wasm
# variants (-O2/-O1/-O0/-g) the first time it runs, or whenever the wasm
# file is missing. Set FORCE_REBUILD=1 to always rebuild.
#
# Output: stdout + /tmp/overflow_wasmtime45_raw.log
# Records: wasmtime version, host, /proc/cpuinfo cpu MHz, intel_pstate no_turbo,
# governor, then 5 reps × 4 emcc opt levels (O2/O1/O0/g), each pinned to CPU 0.

set -u
WT="${WT:-$HOME/.wasmtime/bin/wasmtime}"
DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-/tmp/overflow_wasmtime45_raw.log}"
N="${N:-100000000}"
INPUT="${INPUT:-2000000}"
REPS="${REPS:-5}"
CPU="${CPU:-0}"
FORCE_REBUILD="${FORCE_REBUILD:-0}"

if [ ! -x "$WT" ]; then
  echo "wasmtime not executable at $WT" >&2
  exit 1
fi

# Build wasm if missing (or always when FORCE_REBUILD=1).
# Compile command for one variant (Emscripten 5.0.7):
#   em++ -std=c++17 -O2 -o perf_test_swap_pool_non_dtvm_O2.wasm \
#     perf_test_swap_pool.cpp -I . \
#     -s 'EXPORTED_FUNCTIONS=["_test_traditional"]' \
#     --no-entry -Wl,--allow-undefined \
#     -s ERROR_ON_UNDEFINED_SYMBOLS=0 -s WASM=1 \
#     -s STANDALONE_WASM=0 -s PURE_WASI=1
for OPT in O2 O1 O0 g; do
  WASM="$DIR/perf_test_swap_pool_non_dtvm_${OPT}.wasm"
  if [ "$FORCE_REBUILD" = "1" ] || [ ! -f "$WASM" ]; then
    if ! command -v em++ >/dev/null; then
      echo "em++ not on PATH; source emsdk_env.sh first" >&2
      exit 1
    fi
    echo "[build] em++ -$OPT -> $(basename "$WASM")" >&2
    em++ -std=c++17 -o "$WASM" -$OPT \
      "$DIR/perf_test_swap_pool.cpp" -I "$DIR" \
      -s 'EXPORTED_FUNCTIONS=["_test_traditional"]' \
      --no-entry -Wl,--allow-undefined \
      -s ERROR_ON_UNDEFINED_SYMBOLS=0 -s WASM=1 \
      -s STANDALONE_WASM=0 -s PURE_WASI=1
  fi
done

: > "$OUT"
{
  echo "wasmtime: $($WT --version)"
  echo "host: $(uname -a)"
  echo "os: $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '\"')"
  echo "cpu_model: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //')"
  echo "cpu_family_model_stepping: family=$(grep -m1 'cpu family' /proc/cpuinfo | awk '{print $4}') model=$(grep -m1 '^model' /proc/cpuinfo | awk '{print $3}') stepping=$(grep -m1 'stepping' /proc/cpuinfo | awk '{print $3}')"
  echo "cpu_mhz_observed: $(grep -m1 'cpu MHz' /proc/cpuinfo | awk '{print $4}')"
  echo "no_turbo: $(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || echo unknown)"
  echo "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)"
  echo "n=$N input_amount=$INPUT reps=$REPS taskset_cpu=$CPU"
  echo "----"
} | tee -a "$OUT"

for OPT in O2 O1 O0 g; do
  WASM="$DIR/perf_test_swap_pool_non_dtvm_${OPT}.wasm"
  echo "### opt=$OPT  file=$(basename "$WASM")" | tee -a "$OUT"
  for i in $(seq 1 $REPS); do
    LINE=$( { taskset -c "$CPU" bash -c "time $WT --invoke test_traditional $WASM $N $INPUT >/dev/null"; } 2>&1 | grep -E '^(real|user|sys)' | tr '\n' ' ' )
    echo "  rep$i $LINE" | tee -a "$OUT"
  done
done

echo "----" | tee -a "$OUT"
echo "raw log: $OUT"
