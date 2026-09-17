#!/usr/bin/env bash
# Build upstream WAMR 1.2.3 (iwasm) for paper baseline.
# See BUILD.md for CMake options and Ant Group practice notes.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
WAMR_SRC="${WAMR_SRC:-$ROOT/build/wasm-micro-runtime}"
WAMR_TAG="${WAMR_TAG:-WAMR-1.2.3}"
WAMR_REPO="${WAMR_REPO:-https://github.com/bytecodealliance/wasm-micro-runtime.git}"
BUILD_DIR="${BUILD_DIR:-$WAMR_SRC/product-mini/platforms/linux/build}"
LLVM_DIR="${LLVM_DIR:-/usr/lib/llvm-11/lib/cmake/llvm}"

# Paper / Ant practice defaults
: "${WAMR_BUILD_INTERP:=1}"
: "${WAMR_BUILD_FAST_JIT:=1}"
: "${WAMR_BUILD_AOT:=1}"
: "${WAMR_BUILD_LIBC_WASI:=1}"
: "${WAMR_BUILD_LIBC_BUILTIN:=0}"
: "${WAMR_BUILD_MULTI_MODULE:=0}"

usage() {
    cat <<'EOF'
Usage: build.sh [clone|configure|build|install|all|version]

  clone      Clone wasm-micro-runtime and checkout WAMR-1.2.3
  configure  Run cmake in product-mini/platforms/linux/build
  build      make iwasm
  install    Copy iwasm to ./out/ and write version.txt
  all        clone + configure + build + install
  version    Print iwasm --version (after build)

Environment:
  WAMR_TAG              Git tag (default: WAMR-1.2.3)
  LLVM_DIR              LLVM 11 cmake dir for AOT (Ant: LLVM 11.1.0)
  WAMR_BUILD_INTERP       1 = interpreter (default)
  WAMR_BUILD_FAST_JIT     1 = fast JIT / singlepass (default)
  WAMR_BUILD_AOT          1 = AOT compiler (default, needs LLVM)
  WAMR_BUILD_LIBC_WASI    1 = WASI libc (default, required for polybench)
EOF
}

clone_source() {
    if [[ ! -d "$WAMR_SRC/.git" ]]; then
        git clone --depth 1 --branch "$WAMR_TAG" "$WAMR_REPO" "$WAMR_SRC"
    else
        git -C "$WAMR_SRC" fetch --tags origin
        git -C "$WAMR_SRC" checkout "$WAMR_TAG"
    fi
    echo "Checked out $WAMR_TAG at $WAMR_SRC"
}

configure() {
    clone_source
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    local -a cmake_args=(
        -DWAMR_BUILD_INTERP="$WAMR_BUILD_INTERP"
        -DWAMR_BUILD_FAST_JIT="$WAMR_BUILD_FAST_JIT"
        -DWAMR_BUILD_AOT="$WAMR_BUILD_AOT"
        -DWAMR_BUILD_LIBC_WASI="$WAMR_BUILD_LIBC_WASI"
        -DWAMR_BUILD_LIBC_BUILTIN="$WAMR_BUILD_LIBC_BUILTIN"
        -DWAMR_BUILD_MULTI_MODULE="$WAMR_BUILD_MULTI_MODULE"
    )

    if [[ "$WAMR_BUILD_AOT" == "1" ]]; then
        cmake_args+=(-DLLVM_DIR="$LLVM_DIR")
    fi

    cmake .. "${cmake_args[@]}"
}

build_iwasm() {
    cd "$BUILD_DIR"
    make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
}

install_artifacts() {
    local iwasm="$BUILD_DIR/iwasm"
    [[ -x "$iwasm" ]] || iwasm="$BUILD_DIR/build/iwasm"
    [[ -x "$iwasm" ]] || { echo "Error: iwasm not found under $BUILD_DIR" >&2; exit 1; }

    mkdir -p "$ROOT/out"
    cp "$iwasm" "$ROOT/out/iwasm"
    "$ROOT/out/iwasm" --version | tee "$ROOT/version.txt"
    echo "Installed: $ROOT/out/iwasm"
}

print_version() {
    "$ROOT/out/iwasm" --version 2>/dev/null || "$BUILD_DIR/iwasm" --version 2>/dev/null || "$BUILD_DIR/build/iwasm" --version
}

cmd="${1:-all}"
case "$cmd" in
    clone) clone_source ;;
    configure) configure ;;
    build) build_iwasm ;;
    install) install_artifacts ;;
    all) configure && build_iwasm && install_artifacts ;;
    version) print_version ;;
    -h|--help|help) usage ;;
    *) echo "Unknown command: $cmd" >&2; usage; exit 1 ;;
esac
