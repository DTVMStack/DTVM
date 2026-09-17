#!/usr/bin/env bash
# Build Wasmtime v45.0.0 with WAPM TTFI reporting.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
WASMER_SRC="${WASMER_SRC:-/path/to/wasmtime-45.0.0}"
OUT="$ROOT/out"

if [[ -f "$HOME/.cargo/env" ]]; then
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
fi

echo "Building wasmtime v45.0.0 from $WASMER_SRC (release, -j6)..."
cd "$WASMER_SRC"
cargo build --release -j6

mkdir -p "$OUT"
install -m 755 "$WASMER_SRC/target/release/wasmtime" "$OUT/wasmtime"
echo "Installed: $OUT/wasmtime"
"$OUT/wasmtime" --version
