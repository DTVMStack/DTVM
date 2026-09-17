#!/usr/bin/env bash
# Create case symlinks for the webassembly-testsuites runner:
#   case/benchmark/polybenchc -> benchmarks/polybenchc
#   case/wapm               -> benchmarks/wapm
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUNNER="$ROOT/scripts/webassembly-testsuites"

mkdir -p "$RUNNER/case/benchmark"
ln -sfn "$(cd "$ROOT/benchmarks/polybenchc" && pwd)" "$RUNNER/case/benchmark/polybenchc"
ln -sfn "$(cd "$ROOT/benchmarks/wapm" && pwd)" "$RUNNER/case/wapm"

pb_count="$(find -L "$RUNNER/case/benchmark/polybenchc" -maxdepth 1 -name '*.wasm' | wc -l)"
wapm_count="$(find -L "$RUNNER/case/wapm" -maxdepth 1 -name '*.wasm' | wc -l)"
echo "Linked $RUNNER/case/benchmark/polybenchc -> benchmarks/polybenchc ($pb_count wasm files)"
echo "Linked $RUNNER/case/wapm               -> benchmarks/wapm ($wapm_count wasm files)"
