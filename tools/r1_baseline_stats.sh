#!/usr/bin/env bash
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Dump today's R1 upper-bound counters for every file in a corpus dir.
# Requires evmCacheComplexityDemo built with ZEN_ENABLE_EVM.
#
# Usage:
#   tools/r1_baseline_stats.sh <demo_binary> <corpus_dir> [out_csv] [slice]
#
# slice: auto (default) | runtime | full
# stdout / out_csv columns are documented in the header row.

set -euo pipefail

if [ $# -lt 2 ]; then
  echo "usage: $0 <demo_binary> <corpus_dir> [out_csv] [slice]" >&2
  exit 2
fi

DEMO=$1
CORPUS=$2
OUT=${3:-/dev/stdout}
SLICE=${4:-auto}

if [ ! -x "$DEMO" ]; then
  echo "error: $DEMO not executable" >&2
  exit 2
fi
if [ ! -d "$CORPUS" ]; then
  echo "error: $CORPUS is not a directory" >&2
  exit 2
fi

HEADER="label,slice,code_bytes,n_jumpdest,n_jump,n_jumpi,n_jump_total,n_resolved,n_unresolved,unresolved_frac,n_jd_blocked,jd_blocked_frac,implicit_dyn_pred,n_gas_chunks,n_meter_nonzero_before,n_meter_nonzero_after,spp_zeroed_chunks,build_us"

{
  echo "$HEADER"
  shopt -s nullglob
  for path in "$CORPUS"/*; do
    [ -f "$path" ] || continue
    base=$(basename "$path")
    label=${base%.*}
    "$DEMO" --bytecode "$path" --label "$label" --dump-r1-stats --slice "$SLICE"
  done
} > "$OUT"
