#!/bin/bash
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Run evmCacheComplexityDemo on each file in a corpus dir; spawn one fresh
# process per repetition to avoid intra-process cache reuse; emit long-form
# CSV (label,n_jumpdests,run_idx,phase,phase_us) to stdout.
#
# `phase=total` rows come from the demo's stdout. Per-phase rows come from
# the binary's stderr if it was built with -DZEN_EVM_CACHE_PROFILE=ON.
#
# Usage: bench_evm_cache.sh <demo_binary> <corpus_dir> <runs> [out_csv]

set -euo pipefail

if [ $# -lt 3 ]; then
  echo "usage: $0 <demo_binary> <corpus_dir> <runs> [out_csv]" >&2
  exit 2
fi

DEMO=$1
CORPUS=$2
RUNS=$3
OUT=${4:-/dev/stdout}

if [ ! -x "$DEMO" ]; then
  echo "error: $DEMO not executable" >&2
  exit 2
fi
if [ ! -d "$CORPUS" ]; then
  echo "error: $CORPUS is not a directory" >&2
  exit 2
fi

ERR=$(mktemp)
trap 'rm -f "$ERR"' EXIT

{
  echo "label,n_jumpdests,run_idx,phase,phase_us"
  for path in "$CORPUS"/*; do
    [ -f "$path" ] || continue
    base=$(basename "$path")
    label=${base%.*}
    for run in $(seq 1 "$RUNS"); do
      stdout=$("$DEMO" --bytecode "$path" --label "$label" 2>"$ERR")
      n_jd=$(printf '%s' "$stdout" | awk -F, '{print $2}')
      total_us=$(printf '%s' "$stdout" | awk -F, '{print $3}')
      printf '%s,%s,%s,total,%s\n' "$label" "$n_jd" "$run" "$total_us"
      awk -F, -v label="$label" -v n="$n_jd" -v r="$run" \
        '$1=="EVM_CACHE_PROFILE"{printf "%s,%s,%s,%s,%s\n", label, n, r, $2, $3}' \
        "$ERR"
    done
  done
} > "$OUT"
