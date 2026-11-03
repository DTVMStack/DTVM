#!/usr/bin/env bash
# Dedicated Release CLI for one-shot Singlepass comparisons.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build-paper-singlepass}"
JOBS="${JOBS:-$(nproc)}"

cmake -S "$ROOT" -B "$BUILD" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DZEN_ENABLE_SINGLEPASS_JIT=ON \
  -DZEN_ENABLE_MULTIPASS_JIT=OFF \
  -DZEN_ENABLE_CHECKED_ARITHMETIC=ON \
  -DZEN_ENABLE_BUILTIN_WASI=ON \
  -DZEN_ENABLE_BUILTIN_LIBC=ON

cmake --build "$BUILD" -j"$JOBS" --target dtvm
test -x "$BUILD/dtvm"
echo "Singlepass-only dtvm: $BUILD/dtvm"
echo "Run the harness with --dtvm-modes singlepass."
