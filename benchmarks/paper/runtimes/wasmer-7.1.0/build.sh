#!/usr/bin/env bash
# Build Wasmer v7.1.0 with WAPM paper TTFI reporting.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
WASMER_SRC="${WASMER_SRC:-/path/to/wasmer-7.1.0}"
OUT="$ROOT/out"

if [[ -f "$HOME/.cargo/env" ]]; then
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
fi

FEATURES="cranelift,singlepass"
if [[ -n "${LLVM_SYS_211_PREFIX:-}" ]] || [[ -x "${LLVM21_PREFIX:-/opt/LLVM-21.1.8-Linux-X64}/bin/llvm-config" ]]; then
  export LLVM_SYS_211_PREFIX="${LLVM_SYS_211_PREFIX:-${LLVM21_PREFIX:-/opt/LLVM-21.1.8-Linux-X64}}"
  FEATURES="${FEATURES},llvm"
  echo "LLVM 21 found at $LLVM_SYS_211_PREFIX — building with llvm backend"
else
  echo "WARN: no LLVM 21 (set LLVM_SYS_211_PREFIX) — skipping wasmer llvm backend"
fi
echo "Building wasmer v7.1.0 from $WASMER_SRC (release, features=$FEATURES, -j6)..."
cd "$WASMER_SRC"
cargo build --release -p wasmer-cli -j6 --features "$FEATURES"

mkdir -p "$OUT/bin"
install -m 755 "$WASMER_SRC/target/release/wasmer" "$OUT/bin/wasmer"
echo "Installed: $OUT/bin/wasmer"
"$OUT/bin/wasmer" --version
