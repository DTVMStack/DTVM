#!/usr/bin/env bash
# Polybench runner skeleton.
# Requires webassembly-testsuites checkout and runtime binaries on PATH.
set -euo pipefail

RUNTIME="${1:-iwasm}"
SUITE="polybenchc"

# TODO: set WEBASSEMBLY_TESTSUITES to your checkout path
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WEBASSEMBLY_TESTSUITES="${WEBASSEMBLY_TESTSUITES:-$SCRIPT_DIR/webassembly-testsuites}"

if [[ ! -d "$WEBASSEMBLY_TESTSUITES" ]]; then
  echo "Error: WEBASSEMBLY_TESTSUITES not found: $WEBASSEMBLY_TESTSUITES" >&2
  echo "Clone the webassembly-testsuites repo, or symlink case/ here via setup_polybench_case.sh" >&2
  exit 1
fi

if [[ ! -e "$WEBASSEMBLY_TESTSUITES/case/benchmark/polybenchc" ]]; then
  "$SCRIPT_DIR/setup_polybench_case.sh"
fi

cd "$WEBASSEMBLY_TESTSUITES"

case "$RUNTIME" in
  dtvm)
    DTVM_BIN="${DTVM:-$(cd "$SCRIPT_DIR/.." && pwd)/runtimes/dtvm/dtvm}"
    if [[ ! -x "$DTVM_BIN" ]]; then
      echo "Error: dtvm not found: $DTVM_BIN (build per runtimes/dtvm/BUILD.md)" >&2
      exit 1
    fi
    ./runtest_webassembly.py -r "$DTVM_BIN" \
      --dtvm-options="${DTVM_OPTIONS:--m multipass --disable-multipass-greedyra --disable-multipass-multithread}" \
      -s "$SUITE"
    ;;
  wasmtime)
    WT="${WASMTIME:-$(cd "$SCRIPT_DIR/.." && pwd)/runtimes/wasmtime-31.0.0/out/wasmtime}"
    ./runtest_webassembly.py -r "$WT" -s "$SUITE"
    ;;
  iwasm)
    IW="${IWASM:-$(cd "$SCRIPT_DIR/.." && pwd)/runtimes/wamr-1.2.3/out/iwasm}"
    ./runtest_webassembly.py -r "$IW" -s "$SUITE"
    ;;
  *)
    ./runtest_webassembly.py -r "$RUNTIME" -s "$SUITE"
    ;;
esac
