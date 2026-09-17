#!/usr/bin/env bash
# Build Wasmer 5.0.4 with WAPM paper TTFI reporting (patched wasmer-wasix + cli).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
WASMER_SRC="${WASMER_SRC:-/path/to/wasmer-5.0.4}"
OUT="$ROOT/out"

if [[ -f "$HOME/.cargo/env" ]]; then
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
fi

echo "Building wasmer from $WASMER_SRC (release, -j6)..."
cd "$WASMER_SRC"
FEATURES="cranelift,singlepass"
if [[ -n "${LLVM_SYS_180_PREFIX:-}" ]] || command -v llvm-config-18 >/dev/null 2>&1; then
  FEATURES="${FEATURES},llvm"
  echo "LLVM 18 found — building with llvm backend"
else
  echo "WARN: no LLVM 18 (set LLVM_SYS_180_PREFIX) — skipping wasmer llvm backend"
fi
cargo build --release -p wasmer-cli -j6 --features "$FEATURES"

mkdir -p "$OUT/bin"
install -m 755 "$WASMER_SRC/target/release/wasmer" "$OUT/bin/wasmer"
echo "Installed: $OUT/bin/wasmer"
"$OUT/bin/wasmer" --version
