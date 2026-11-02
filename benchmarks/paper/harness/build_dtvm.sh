#!/usr/bin/env bash
# Copy-pasteable Release dtvm build for the paper-bench harness.
# Does not install into gitignored runtimes/dtvm_main/; the harness looks at
# build-paper-bench/dtvm (this script) then build/dtvm then $DTVM.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build-paper-bench}"
JOBS="${JOBS:-$(nproc)}"

find_llvm_dir() {
  if [[ -n "${LLVM_DIR:-}" && -f "${LLVM_DIR}/LLVMConfig.cmake" ]]; then
    printf '%s' "$LLVM_DIR"
    return
  fi
  local cand
  for cand in \
    /usr/lib/llvm-15/lib/cmake/llvm \
    /usr/lib/cmake/llvm \
    /opt/llvm15/lib/cmake/llvm \
    /usr/lib/llvm-16/lib/cmake/llvm
  do
    if [[ -f "$cand/LLVMConfig.cmake" ]]; then
      printf '%s' "$cand"
      return
    fi
  done
  echo "error: LLVMConfig.cmake not found; set LLVM_DIR" >&2
  exit 1
}

LLVM_DIR="$(find_llvm_dir)"
echo "LLVM_DIR=$LLVM_DIR"
echo "BUILD=$BUILD"

cmake -S "$ROOT" -B "$BUILD" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_DIR="$LLVM_DIR" \
  -DZEN_ENABLE_SINGLEPASS_JIT=ON \
  -DZEN_ENABLE_MULTIPASS_JIT=ON \
  -DZEN_ENABLE_CHECKED_ARITHMETIC=ON \
  -DZEN_ENABLE_BUILTIN_WASI=ON \
  -DZEN_ENABLE_BUILTIN_LIBC=ON

cmake --build "$BUILD" -j"$JOBS" --target dtvm
test -x "$BUILD/dtvm"
echo "dtvm: $BUILD/dtvm"
echo "export DTVM=$BUILD/dtvm"
