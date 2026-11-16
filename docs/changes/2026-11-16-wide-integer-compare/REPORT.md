# Standalone two-limb comparison measurements

Main: `aa98c1b712aa27cc23e55216ca7ce2b5e38b8fcf` (#650). Candidate contains only
the comparator, bounded proof bookkeeping, tests and benchmark integration.
It has no AVX-folding change, runtime research switches or dump hooks.

## Reproduction

The new codegen reactor is registered in the existing paper harness; source,
checked-in Wasm and rebuild steps are in
`benchmarks/paper/benchmarks/codegen/README.md`. It is a synthetic compiler
diagnostic, not an original paper application or a contract.

```sh
# Build baseline and candidate separately with the same configuration.
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DZEN_ENABLE_MULTIPASS_JIT=ON -DZEN_ENABLE_SINGLEPASS_JIT=ON \
  -DZEN_ENABLE_BUILTIN_WASI=ON -DZEN_ENABLE_SPEC_TEST=OFF \
  -DZEN_ENABLE_ASAN=OFF -DLLVM_DIR=/path/to/llvm15/lib/cmake/llvm
cmake --build build --target dtvm -j2

python3 benchmarks/paper/harness/run.py \
  --cases wide_compare_dev,wide_compare_paper \
  --dtvm /path/to/candidate/dtvm --wasmtime /path/to/wasmtime-45 \
  --dtvm-modes singlepass,lazy-F-ST,lazy-G-MT,multipass-G-ST \
  --warmup 2 --repeats 7 --require-wasmtime --out /tmp/wide-harness

python3 docs/changes/2026-11-16-wide-integer-compare/benchmark.py \
  --main /path/to/main/dtvm --candidate /path/to/candidate/dtvm \
  --wasmtime /path/to/wasmtime-45 --out /tmp/wide-paired \
  --rounds 31 --seed 6511602 --cpu 0

python3 docs/changes/2026-11-16-wide-integer-compare/validate.py \
  --dtvm /path/to/candidate/dtvm --out /tmp/wide-validation.json --cpu 0
```

`benchmark.py` uses the existing harness's command/cwd construction and checks
checksums with an independent Python oracle. Expected results: N=0 -> 0,
N=5,000,000 -> 2,499,920; N=50,000,000 -> 24,999,969.

## Conditions and interpretation

AMD EPYC 9V74, GCC14.2 / LLVM15, Release O3, both compilers and WASI enabled,
SPEC/ASAN off. Two-CPU cgroup quota; engine and workers pinned to CPU0. Warm
file cache, fresh processes, two excluded warmups, randomized engine order
within each round. Wasmtime 45 CLI cache disabled. No builds, tests or profiles
overlap formal samples. Wall time includes startup, compilation, invocation and
teardown; it is not pure native execution or TTFT. No clock instrumentation is
added to the Wasm.

Ratios are medians of within-round process ratios, with pointwise 95% percentile
bootstrap intervals (10,000 resamples). They are not ratios of group medians.
Multiple comparisons are not corrected, and intervals covering one do not prove
equivalence. Separate cohorts are never pooled. Raw samples, executable/input
hashes, commands and summaries are under [evidence](evidence/).

The reactor has exactly one internal function. `lazy-G-MT` denotes the default
lazy CLI flags; DTVM's existing one-function policy chooses Greedy on demand
without creating background workers. `lazy-F-ST` explicitly selects FastRA;
`multipass-G-ST` is serial eager Greedy. Singlepass is a control and its compiler
is not changed by this PR. Wasmtime is the same reference row across modes.

## Final independent R31: comparison-dense diagnostic

Group wall medians, milliseconds. Reduction is from paired ratios.

| N | Mode | Main | Candidate | WT45 | Paired reduction [95% CI] |
|---|---|---:|---:|---:|---|
| 5M | lazy default / on-demand Greedy | 13.450 | 11.484 | 11.546 | 13.1% [11.5%,16.1%] |
| 5M | lazy FastRA, serial | 14.691 | 13.597 | 11.546 | 6.0% [3.7%,8.7%] |
| 5M | eager Greedy, serial | 13.143 | 11.583 | 11.546 | 10.7% [8.2%,14.6%] |
| 50M | lazy default / on-demand Greedy | 79.927 | 64.803 | 58.242 | 19.4% [18.4%,21.7%] |
| 50M | lazy FastRA, serial | 96.639 | 86.630 | 58.242 | 11.0% [8.2%,13.5%] |
| 50M | eager Greedy, serial | 81.135 | 64.287 | 58.242 | 18.5% [17.6%,20.7%] |

N=50M singlepass main/candidate 116.117/113.093 ms, paired ratio
0.9853 [0.9609,1.0039]; no singlepass benefit is attributed to this change.
For N=0, candidate/main intervals in all four modes cover one: this establishes
neither a compile-time win nor zero latency penalty.

The main A/A control reuses exactly the same executable/inode. At 50M its ratio
is 0.9949 [0.9714,1.0116]. Small short-process differences remain sensitive to
file/layout and scheduling; the longer workload, A/A, native mechanism and
independent cohorts provide stronger evidence than a lone small-case result.
WT45 remains faster at 50M. This PR does not claim to overtake it generally.

An earlier independent production R31, before final bounded-owner/cache-snapshot
review, found 50M reductions of 17.8% for lazy default and 9.8% for lazy FastRA.
That revision's full data is retained as `initial-r31`, not relabeled as final.
The earlier research-only same-binary switch experiments are not part of this
production build's measurements.

## Real application regression samples

Final R31, group process-wall medians in ms, default lazy CLI flags:

| Case | Main | Candidate | WT45 | Candidate/main paired ratio [95% CI] |
|---|---:|---:|---:|---|
| bicg | 60.521 | 61.056 | 73.225 | 0.9939 [0.9790,1.0140] |
| atax | 53.303 | 52.000 | 62.936 | 0.9800 [0.9650,0.9926] |
| md5 | 27.860 | 27.339 | 44.983 | 0.9847 [0.9594,1.0423] |
| cowsay | 110.847 | 111.725 | 401.385 | 1.0131 [0.9933,1.0352] |
| base64cli | 105.955 | 101.907 | 464.762 | 0.9777 [0.9548,1.0098] |

Original input/output streams match. Atax's small final-cohort gain was not
confirmed in the earlier independent cohort (1.0050 [0.9867,1.0414]); do not
attribute it to this optimization without a native hotspot change. One final
bicg A/A interval marginally excludes one (1.0101 [1.0004,1.0416]), and the
initial cohort had other small A/A shifts. Keep these controls; the data does
not establish universal no-regression or feature-attributable application wins.
This is a regression sample, not a complete WAPM/PolyBench rerun or suite score.

## Correctness, review and limitations

- 34 x86 lowering/peephole/policy tests pass, including all relational/equality
  directions, swapped equality operands, overwritten local snapshots,
  already-materialized comparisons, non-leaf rejection and both proof budgets.
- The public validator passes 9,450 independent Python-oracle executions across
  eager Greedy, eager FastRA and lazy, CPU0 pinned. It covers signed high limbs,
  unsigned low limbs, all directions, inverted selects and source overwrites.
- 65 cross-engine contract fixture checks pass; 56 extra calldata vectors agree
  under lazy, eager multipass, singlepass and WT45. Cross-engine agreement is
  not an independent contract-semantic oracle.
- 26 harness tests, `run.py --selftest`, the actual R7 harness bench invocation,
  C++ formatting and whitespace checks pass. Optional EVM and ASAN builds and
  another physical CPU have not been run locally; remote CI is separate.
- Two unpinned multi-export lazy validation processes timed out during discovery
  (20s and 60s). Exact-input replay (30 alternating launches), 8,000 subsequent
  main/candidate fixed-input launches and 6,000 parallel main-only launches did
  not reproduce them. Their cause is
  unresolved; these incomplete timeout failures are not clean passes. Their logs and
  the clean pinned validator result are retained under evidence/validation.

The final review adds bounded parent walks and rejects cached comparison
results, which may refer to values before a local rewrite. Only proven local
reads are combined, with no memory/trap/call reordering or ISA feature gating.
