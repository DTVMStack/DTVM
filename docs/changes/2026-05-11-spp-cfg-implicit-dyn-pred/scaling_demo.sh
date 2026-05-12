#!/usr/bin/env bash
# Demonstrate the cache-build wall clock as JUMPDEST count grows.
# Generates synthetic contracts of the form
#   CALLDATALOAD JUMP <N x JUMPDEST> STOP
# (one dynamic jump, N JUMPDESTs — exercises the Phase 7 implicit-dyn-pred
# stamping and the reachability stitch on every JUMPDEST.)
#
# Build the demo binary first:
#   cmake --build build --target evmCacheComplexityDemo
#
# What Phase 7 changed: the per-JUMPDEST over-approximation step that used
# to materialise D*J explicit edges is now O(N) (one count stamp per
# JUMPDEST). The dominator and loop analyses that run AFTER buildCFGEdges
# are unaffected by this PR and remain super-linear (~O(N*alpha(N)) for
# the iterative dom dataflow). The wall clock you see below is the
# WHOLE pipeline, so the residual super-linearity is the dom analysis,
# not Phase 7.
#
# Reference point: `evmone-unittests` wall-clock for
# `loop_full_of_jumpdests` (24556 JUMPDESTs, multipass mode) dropped from
# 7.3s (pre-Phase-7, with explicit D*J edges + critical-edge split) to
# 3.3s (post-Phase-7). The 4s saving is the Phase 7 contribution; the
# remaining 3.3s is dom analysis + JIT compile + test body, unaffected by
# this PR.

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
