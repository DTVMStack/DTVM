#!/usr/bin/env bash
# Sweep buildBytecodeCache wall-clock across N JUMPDESTs. Background and
# numbers live in README.md alongside this script.
# Prereq: cmake --build build --target evmCacheComplexityDemo

set -euo pipefail

DEMO=${EVMCACHE_DEMO:-build/evmCacheComplexityDemo}
if [[ ! -x "$DEMO" ]]; then
  echo "demo binary not found at $DEMO" >&2
  echo "build it with: cmake --build build --target evmCacheComplexityDemo" >&2
  exit 1
fi

echo "n_jumpdests,build_ms"
for N in 100 500 1000 2000 5000 10000 20000; do
  "$DEMO" "$N"
done
