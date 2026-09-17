#!/usr/bin/env bash
# Build PolyBench/C 4.2.1 to WASM using WASI SDK clang.
#
# Source: https://github.com/MatthiasJReisinger/PolyBenchC-4.2.1
# See BUILD.md for full procedure and compiler flags.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"
SRC_DIR="${SRC_DIR:-$BUILD_DIR/PolyBenchC-4.2.1}"
OUT_DIR="${OUT_DIR:-$ROOT/out}"
POLYBENCH_GIT="${POLYBENCH_GIT:-https://github.com/MatthiasJReisinger/PolyBenchC-4.2.1.git}"
WASI_CLANG="${WASI_CLANG:-${CLANG:-/opt/wasi-sdk/bin/clang}}"

NO_SIMD="-mno-mmx -mno-sse2 -mno-sse3 -mno-ssse3 -mno-sse4 -mno-sse4a -mno-sse4.1 -mno-sse4.2 -mno-avx -mno-avx2 -mno-avx512f \
 -mno-avx512pf -mno-avx512er -mno-avx512cd -mno-avx512vl -mno-avx512bw -mno-avx512dq -mno-avx512ifma -mno-avx512vbmi"

GCC_PARGS="-O3 -I utilities -DPOLYBENCH_TIME -DSMALL_DATASET -DDATA_TYPE_IS_INT $NO_SIMD -lm"

# WASI clang flags (aligned with archived wasm: DUMP_ARRAYS + WASI)
CLANG_COMMON="-O3 -I utilities -DSMALL_DATASET -DDATA_TYPE_IS_INT -DPOLYBENCH_DUMP_ARRAYS -D_WASI_EMULATED_PROCESS_CLOCKS"
CLANG_LDFLAGS="-Wl,--export=__heap_base -Wl,--export=__data_end -Wl,--export=malloc -Wl,--export=free"

usage() {
    cat <<'EOF'
Usage: build.sh [prepare|native|wasm|all|emcc|one]

  prepare   Clone PolyBenchC-4.2.1
  native    Build native binaries with GCC (reference)
  wasm      Build all cases to WASM with WASI clang
  all       prepare + native + wasm
  emcc      Example single-case build with emcc (optional)
  one       Build one case with WASI clang: build.sh one <path/to/case.c>

Environment:
  POLYBENCH_GIT   Source repo URL
  WASI_CLANG      Path to wasi-sdk clang (default: /opt/wasi-sdk/bin/clang)
  CLANG           Alias for WASI_CLANG
  BUILD_DIR       Working directory for clone/build
  OUT_DIR         Output directory for artifacts
EOF
}

prepare_source() {
    mkdir -p "$BUILD_DIR" "$OUT_DIR"
    if [[ ! -d "$SRC_DIR/.git" ]]; then
        git clone --depth 1 "$POLYBENCH_GIT" "$SRC_DIR"
    fi
    echo "Prepared source at $SRC_DIR"
}

build_native() {
    cd "$SRC_DIR"
    while IFS= read -r benchmark; do
        [[ -f "$benchmark" ]] || continue
        base="${benchmark%.c}"
        base="${base//\//_}"
        echo "Native: $benchmark"
        gcc $GCC_PARGS -o "$OUT_DIR/${base}_native" "$benchmark" utilities/polybench.c
    done < utilities/benchmark_list
}

build_wasm() {
    command -v "$WASI_CLANG" >/dev/null 2>&1 || {
        echo "Error: clang not found: $WASI_CLANG (set WASI_CLANG=...)" >&2
        exit 1
    }
    cd "$SRC_DIR"
    while IFS= read -r benchmark; do
        [[ -f "$benchmark" ]] || continue
        base="$(basename "${benchmark%.c}")"
        case_dir="$(dirname "$benchmark")"
        echo "WASM: $benchmark -> $base.wasm"
        "$WASI_CLANG" $CLANG_COMMON -I "$case_dir" \
            utilities/polybench.c "$benchmark" \
            $CLANG_LDFLAGS \
            -o "$OUT_DIR/$base.wasm" \
            || echo "WARN: failed to build $benchmark" >&2
    done < utilities/benchmark_list
}

build_one() {
    local case_file="${1:?usage: build.sh one <path/to/case.c>}"
    command -v "$WASI_CLANG" >/dev/null 2>&1 || {
        echo "Error: clang not found: $WASI_CLANG" >&2
        exit 1
    }
    prepare_source
    cd "$SRC_DIR"
    [[ -f "$case_file" ]] || { echo "Not found: $case_file" >&2; exit 1; }
    local base="$(basename "${case_file%.c}")"
    local case_dir="$(dirname "$case_file")"
    "$WASI_CLANG" $CLANG_COMMON -I "$case_dir" \
        utilities/polybench.c "$case_file" \
        $CLANG_LDFLAGS \
        -o "$OUT_DIR/$base.wasm"
}

build_emcc_example() {
    local case="${1:-linear-algebra/solvers/mvt/mvt.c}"
    command -v emcc >/dev/null 2>&1 || { echo "emcc not found" >&2; exit 1; }
    prepare_source
    cd "$SRC_DIR"
    local case_dir="$(dirname "$case")"
    emcc -O3 -s WASM=1 -DSMALL_DATASET -DDATA_TYPE_IS_INT -DPOLYBENCH_DUMP_ARRAYS \
        -I utilities -I "$case_dir" \
        -o "$OUT_DIR/mvt_emcc.wasm" \
        "$case" utilities/polybench.c
}

cmd="${1:-all}"
case "$cmd" in
    prepare) prepare_source ;;
    native) prepare_source; build_native ;;
    wasm) prepare_source; build_wasm ;;
    all) prepare_source; build_native; build_wasm ;;
    one) build_one "${2:-}" ;;
    emcc) build_emcc_example "${2:-}" ;;
    -h|--help|help) usage ;;
    *) echo "Unknown command: $cmd" >&2; usage; exit 1 ;;
esac

echo "Done. Outputs in $OUT_DIR"
