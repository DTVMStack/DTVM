#!/usr/bin/env bash
# Install the current paper Wasmtime pin (45.0.0) into runtimes/wasmtime-45.0.0/out/.
# Binary is gitignored; version.txt stays in-tree as the pin proof.
set -euo pipefail

PAPER="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$PAPER/runtimes/wasmtime-45.0.0/out"
VER="${WASMTIME_VERSION:-45.0.0}"
URL="https://github.com/bytecodealliance/wasmtime/releases/download/v${VER}/wasmtime-v${VER}-x86_64-linux.tar.xz"

mkdir -p "$DEST"
if [[ -x "$DEST/wasmtime" ]]; then
  echo "already present: $DEST/wasmtime ($("$DEST/wasmtime" --version | head -1))"
  exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
echo "fetch $URL"
curl -fsSL -o "$tmp/wasmtime.tar.xz" "$URL"
tar -C "$tmp" -xf "$tmp/wasmtime.tar.xz"
src="$(find "$tmp" -type f -name wasmtime | head -1)"
cp "$src" "$DEST/wasmtime"
chmod +x "$DEST/wasmtime"
"$DEST/wasmtime" --version
echo "export WASMTIME=$DEST/wasmtime"
