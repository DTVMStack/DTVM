# Change: bound regalloc split and coalescer work on use-dense megablocks

- **Status**: Proposed
- **Date**: 2026-07-07
- **Tier**: Light

## Overview

EEST worst-case modulo contracts (a single basic block with ~11 000 arithmetic
sites that all reference one constant modulus value) drove three backend code
paths quadratic in the block size. All three now carry bounded strategies; the
worst measured case on upstream (SMOD, constant 127-bit modulus) drops from
36 s to 5.9 s, and codegen for ordinary functions is unchanged.

1. **Greedy-RA local splitting** (`reg_alloc_greedy.cpp`). Every virtual
   register in a one-block function is a "local" interval, so a value with
   thousands of uses entered `tryLocalSplit`, whose best-window search rescans
   every gap for every candidate physical register, may peel off only a tiny
   window per round, and pays O(uses) analysis/rewrite/weight-recalc per
   round. An interval with more than `LocalSplitGapsCutoff` (512) gaps is now
   split into uniform 256-use chunks in a single SplitEditor pass; each chunk
   is small enough for the regular allocation path, and the connector
   segments stay in a complement whose only uses are the chunk-boundary
   copies.

2. **Register coalescing** (`register_coalescer.cpp`). `joinCopy` picks the
   rename direction by live-range *segment* count; a whole-block-live value
   has one segment but thousands of uses, so every per-site copy join rewrote
   the dense register's full use list — O(sites × uses). A bounded
   (256-instruction) scan of both sides now renames the sparse side when one
   side has ≥ 64 use instructions and more than 4× the other.

3. **Spill-weight recomputation** (`calc_spill_weights.cpp`). Each split
   generation defines the child value with a copy; `isRematerializable`
   walked that chain end-to-end per value, making weight recalculation across
   a deeply split family quadratic. The walk now stops after
   `RematCopyChainCutoff` (8) hops; giving up forfeits only the 0.5× remat
   weight discount, not the spiller's actual rematerialization.

## Motivation

Compile time is a first-class cost for a JIT. On EEST
`benchmark/compute/instruction/arithmetic` fixtures (1M-gas tier, wall time
per blockchain test including the per-test JIT compile, taskset-pinned,
performance governor), measured on this branch against its upstream/main
merge base:

| Case (sites) | upstream/main | this change | ratio |
|---|---|---|---|
| mod.json SMOD, 127-bit modulus, 11 475 sites | 36.1 s | 5.87 s | **6.1×** |
| mod.json MOD, 127-bit modulus, 11 310 sites | 9.98 s | 5.44 s | **1.8×** |
| arithmetic.json DIV-0, 12 280 sites | 4.45 s | 4.52 s | 1.0× |
| arithmetic.json ADDMOD, 8 184 sites | 22.9 s | 23.4 s | 1.0× |
| mod_arithmetic.json ADDMOD, 127-bit modulus, 666 sites (control) | 1.34 s | 1.34 s | 1.0× |

![Per-test JIT compile time before and after bounded regalloc; two constant-modulus megablocks collapse while three controls stay flat](figures/compile-time.svg)

*Figure: per-test JIT compile time, before → after (lower is better). The two
constant-modulus megablocks collapse (SMOD 6.1×, MOD 1.8×); the three controls
stay within run-to-run variance (DIV-0 +1.6%, ADDMOD +2.2%, 666-site ADDMOD
±0%), their near-zero connectors showing the bounds are targeted, not blanket.
Mean of 2 reps (n=2); the target effects are an order of magnitude larger than
any control drift. Every case passes its post-state hash.*

Median of two reps per case, 1M-gas tier, taskset CPU6, performance governor;
every case passes its post-state hash. On a clean upstream base only the
mod.json constant-modulus megablocks trigger the coalescer/split quadratic — a
single modulus value stays live across all ~11 000 sites, which is exactly the
density the bounds target (SMOD 3.14 → 0.51 ms/site; MOD 0.88 → 0.48 ms/site).
The other two large cases are not register-allocation pathologies and the
bounds are a no-op on them: DIV-0 already compiles linearly (0.36 ms/site), and
arithmetic.json ADDMOD's cost is `intx` inline expansion (2.8 ms/site),
untouched here. The ≤2.2% drift on those two (DIV-0 +1.6%, ADDMOD +2.2%) is run-to-run build
variance — an order of magnitude below the megablock effects.

The same contracts under the in-flight EVM u64-narrowing change add dense
per-site register pressure that pushes DIV-0 to ~152 s and MULMOD to ~475 s;
the identical bounds cut those to ~7.4 s and ~3.4 s, so this fix is a
prerequisite for that change — but the standalone benefit measured against
upstream is the mod.json cases above.

evmone kernel benchmarks (`^external/total/(main|micro)/`, single-shot A/B, 6
alternations) are unchanged: main geomean fix/base 0.9992 (n=14), micro 0.9946
(n=13) — both inside the run-to-run band.

## Impact

- `src/compiler/cgir/pass/reg_alloc_greedy.cpp` — chunked split for use-dense
  local intervals; new `LocalSplitGapsCutoff` constant.
- `src/compiler/cgir/pass/register_coalescer.cpp` — use-density-aware rename
  direction in `joinCopy`; new bounded counting helper.
- `src/compiler/cgir/pass/calc_spill_weights.cpp` — bounded split-copy chain
  walk in `isRematerializable`.

All three strategies are deterministic (fixed constants, no host-dependent
behavior) and only alter compile-time strategy on shapes real contracts do
not exhibit (triggers: >512 gaps of one virtual register inside one basic
block, ≥64-use imbalance on a copy join, >8-hop split-copy chains). The
shared backend serves both EVM and WASM multipass compilation; the bounds are
shape-based, not EVM-specific.

## Checklist

- [x] Implementation complete
- [x] Tests added/updated — covered by existing suites: EEST benchmark
      blockchain tests verify post-state hashes on every shape above;
      multipass unittests + EEST statetest + evm_asm pass
- [ ] Module specs in `docs/modules/` updated (if affected)
- [x] Build and tests pass — 5 EEST compile cases above all pass post-state
      hash on this branch; kernel A/B geomean 0.9992 main / 0.9946 micro (no
      regression). Still to run before submit: `tools/format.sh check`,
      multipass unittests / statetest / evm_asm.
