# Change: Bound long-block compiler searches

- **Status**: Implemented
- **Date**: 2026-11-05
- **Tier**: Light

Long MIR blocks repeatedly scan earlier statements to resolve local constants;
FastRA repeatedly scans spilled virtual entries at call regmasks. Index nearest
completed assignments in blocks with at least 32 statements, and discover large
clobber sets through the physical-unit map. Use full-width sparse indices so
live-entry lookup does not itself scan a truncated-index chain.

Updates occur after rewriting assignment operands; dynamic writes and block/function
transitions invalidate the index. FastRA deduplicates aliases and preserves dense-set
spill order. Small blocks/live sets retain their prior paths. No MC reset, ABI,
tiering, publication, trap check or teardown policy changes are included.

## Review fixes

[PR #640](https://github.com/DTVMStack/DTVM/pull/640) review found two issues:

- Default uint8_t LLVM SparseSet indices probe in strides of 256 in large sets,
  leaving a residual quadratic lookup cost. Use uint32_t dense indices. The sparse
  array costs three extra bytes per virtual-register universe entry; dense order
  and generated-code decisions are unchanged.
- CMake fixture formatting blocked CI before compilation or benchmarking. Run
  cmake-format and the complete tools/format.sh check with CI-matching versions.
  The no-summary regression comment on the original run was not measured data.

Extend the 512-step test with mixed integer/FP values across alternating calls;
use distinct checksum weights to detect permuted live values. Source, diagnostic
probe, raw data and test logs are in the [review evidence snapshot](https://github.com/zoowii/DTVM/blob/c59e4e39a9c7d07bbc9c15a1775e42d61942c99a/docs/changes/2026-11-05-lazy-long-block-throughput/review/README.md).
The [pre-review snapshot](https://github.com/zoowii/DTVM/blob/345fab10b2ae851d86a96881d3a1ce91f3675d0e/docs/changes/2026-11-05-lazy-long-block-throughput/README.md)
captures 6a6ede1 and earlier broad WAPM checks; its source/results are not relabeled
as the post-review version. Production/test source matches the review snapshot.

## Measured results after review

Fresh-process median milliseconds, CPU 0 affinity, Wasmtime cache disabled.
Main is f4b8507; before is the exact pre-review PR commit 6a6ede1. Same-row engines
were interleaved in randomized rounds. Do not pool serial and default-MT modes.

| Mode and case | Main | Before 6a6ede1 | After review | WT45 | WT49 |
|---|---:|---:|---:|---:|---:|
| Serial lazy, 10000 helpers | 1775.269 | 797.832 | 682.116 | 1692.673 | 1684.379 |
| Serial lazy, 10000 calls to one helper | 1229.603 | 254.124 | 160.796 | 1444.639 | 1449.402 |
| Default lazy MT, 10000 calls to one helper | 2678.437 | 795.807 | 707.066 | 1468.155 | 1445.391 |

Against the pre-review PR, the one-helper chain improves 36.73% serial and 11.15%
default lazy MT, with paired 95% intervals excluding zero. Serial has 15 measured
rounds; default MT has 21. These are generated long-block compilation-plus-one-
execution cases, not steady-state throughput or universal application gains.
Post-review dice/echo intervals cross zero. Wasmtime compiles the whole module;
lazy DTVM may defer work. Captured representative guest code matches before/after
following normalization of three checked absolute address operands.

## Verification

Seven CTest suites and 97 WAST groups in each of three configurations passed.
After strengthening the mixed checksum, all 98 tests in the affected MIR/codegen
target passed. The complete tools/format.sh check passes with clang-format 15.0.6
and cmake-format 0.6.13; generated fixture bytes are unchanged by formatting.
All 490 post-review formal-phase processes succeeded with matching outputs:
465 measured samples and 25 warmups. Earlier 2100 runs remain in their versioned
archive. Diff whitespace checks pass. ASan and optional EVM/SGX/Linux-perf feature
configurations were not tested locally; remote CI status is separate.
