#!/usr/bin/env bash
# Tiny measured matrix: atax, fib_iter 1e6, overflow builtin 1e6, figlet.
# Uses interp+singlepass+multipass-G-ST+lazy-F-ST vs wasmtime cranelift-nocache.
set -euo pipefail

HARNESS="$(cd "$(dirname "$0")" && pwd)"
PAPER="$(cd "$HARNESS/.." && pwd)"
REPO="$(cd "$PAPER/../.." && pwd)"

export DTVM="${DTVM:-$REPO/build-paper-bench/dtvm}"
export WASMTIME="${WASMTIME:-$PAPER/runtimes/wasmtime-45.0.0/out/wasmtime}"

if [[ ! -x "$DTVM" ]]; then
  echo "building dtvm via $HARNESS/build_dtvm.sh" >&2
  "$HARNESS/build_dtvm.sh"
  export DTVM="${BUILD_DIR:-$REPO/build-paper-bench}/dtvm"
fi
if [[ ! -x "$WASMTIME" ]]; then
  echo "fetching wasmtime via $HARNESS/fetch_wasmtime.sh" >&2
  "$HARNESS/fetch_wasmtime.sh"
  export WASMTIME="$PAPER/runtimes/wasmtime-45.0.0/out/wasmtime"
fi

exec python3 "$HARNESS/run.py" --preset smoke --repeats "${REPEATS:-1}" --warmup "${WARMUP:-1}" --cpu "${CPU:-0}" "$@"
