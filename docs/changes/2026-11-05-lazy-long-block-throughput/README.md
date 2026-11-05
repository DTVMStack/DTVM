# Change: Bound long-block compiler searches

- **Status**: Implemented
- **Date**: 2026-11-05
- **Tier**: Light

Long MIR blocks repeatedly scan earlier statements to resolve local constants;
FastRA repeatedly scans spilled virtual entries at call regmasks. Both searches
can grow quadratically in a straight-line call chain. This change indexes the
nearest completed direct assignment for blocks with at least 32 statements and
bounds large FastRA clobber discovery by physical register units.

Updates occur after rewriting assignment operands, including self-updates;
dynamic writes and block/function transitions invalidate the constant index.
FastRA deduplicates aliases and preserves original dense-set spill order. Small
blocks/live sets use the existing paths. No MC reset, ABI, tiering, publication,
trap check or teardown policy changes are included.

The user authorized a focused, measured PR. Full source provenance, raw samples,
reproduction scripts, assembly, rejected directions, compatibility inventory and
regression logs are in the [immutable evidence snapshot](https://github.com/zoowii/DTVM/blob/345fab10b2ae851d86a96881d3a1ce91f3675d0e/docs/changes/2026-11-05-lazy-long-block-throughput/README.md). The production
and test source in that snapshot is identical to this PR; the large raw dataset
is maintained separately from the implementation diff.

## Measured results

Median total fresh-process milliseconds, pinned to CPU 0, cache disabled for
Wasmtime. Main is f4b8507. Previous research 28ad2de additionally contains
experimental MC reuse and is not the PR base. Same-row engines were interleaved
within randomized rounds; serial FastRA and default background-Greedy results
must not be pooled.

| Mode and case | Main | Previous research | This PR | WT45 | WT49 |
|---|---:|---:|---:|---:|---:|
| Serial lazy, 5000 helpers | 577.169 | 314.363 | 352.983 | 484.925 | 486.277 |
| Serial lazy, 10000 helpers | 1852.595 | 739.298 | 821.089 | 1806.611 | 1816.429 |
| Serial lazy, 10000 calls to one helper | 1222.430 | 245.034 | 247.839 | 1431.906 | 1425.543 |
| Default lazy MT, 10000 calls to one helper | 2721.288 | 801.650 | 820.709 | 1463.086 | 1484.858 |

Relative to main, the one-helper call chain improves 79.73% in serial mode and
69.84% in default lazy mode, with paired 95% intervals excluding zero. Serial
mode has 21 measured rounds; default mode has 15. This is compilation-plus-one-
execution latency for generated long blocks, not steady-state guest throughput
or a universal application claim. Wasmtime compiles the whole module while lazy
DTVM may defer work.

Twelve WAPM cases were checked. They do not establish general speedups. An initial
dice regression signal was not reproduced as stable in an independent 51-round
check (+1.07%, interval [-1.44%, +5.94%]); this does not prove zero overhead.
Main/candidate JIT buffers match on the representative call chain after masking
three checked absolute address operands. Guest instruction sequences are unchanged.

## Verification

Five new tests cover local-dataflow ordering/isolation and 512-call integer/FP
chains under eager and lazy FastRA. All seven CTest suites, 97 WAST groups in each
of three configurations, and 26 harness tests passed. All 2100 formal-phase
processes exited successfully with matching captured outputs; 1995 are measured
samples and 105 warmups. Source formatting and whitespace checks passed.
ASan and optional EVM/SGX/Linux-perf feature configurations were not tested.
