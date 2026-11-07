# Private tiering cold work and scalar load folding

## Findings

This experiment separates startup cost, existing private promotion, and scalar
kernel throughput. All final measurements use source `58b0fd3` (the benchmark
files and documentation added later do not change the measured compiler).

* Default combined/main paired wall-time ratios in 31 rounds: md5 0.9064
  [0.8924, 0.9408], pi(1) 0.9520 [0.9402, 0.9867], qr2text 0.9614
  [0.9485, 0.9762]. These are combined-change results, not isolated folding gains.
* pi(1000): enabling the existing private policy on the candidate reduces time
  by about 11.8%; the NEW incremental candidate/main gain with that policy
  enabled on BOTH sides is only about 1.2% (ratio 0.9882 [0.9688, 0.9969]).
  Group medians: main+policy 523.33 ms, candidate+policy 512.49 ms, WT45 527.65 ms.
  pi(1) policy-on/off ratio 0.9924 [0.9791, 1.0193] establishes neither a penalty
  nor equivalence. Existing admission thresholds/budgets/defaults are unchanged.
* bicg native loop: 22 -> 20 static instructions, 6 -> 4 explicit scalar loads,
  two folded multiplication memory operands, no frame accesses. Body size
  1437 -> 1429 bytes. This reduces instructions, not memory traffic.
* bicg repeat-30 warm kernel: candidate/main 1.0021 [0.9804, 1.0394];
  candidate/cold-only 0.9992 [0.9636, 1.0327]. No established runtime improvement.
  Candidate/WT45 1.0560 [1.0329, 1.0720]: still about 5.6% slower.
* atax repeat-30 warm candidate/main 0.9888 [0.9555, 1.0105], also inconclusive.
* A full PolyBench one-round scout suggested heat-3d gains and syr2k losses.
  Independent seven-round holdout did NOT confirm the heat-3d win. A subsequent
  31-round syr2k comparison confirms a small regression: candidate/main 1.0171
  [1.0039, 1.0314]. Group medians main 2669.95, candidate 2705.73, WT45 3124.68 ms.
  An independent four-engine R21 ablation did not reproduce it: combined/main
  0.9793 [0.9609, 1.0553], cold-only/main 0.9945 [0.9707, 1.0134],
  combined/cold-only 0.9964 [0.9588, 1.0271]. Group medians main 2640.44,
  cold-only 2580.55, combined 2630.24, WT45 3149.15 ms. Keep both cohorts;
  do not pool them or claim equivalence/no regression from the second result.
  Untimed captures show the hottest syr2k loop is byte-identical between main
  and combined (23 instructions, two frame accesses, no folded multiplication;
  1342-byte main function on both). Thus the proposed longer address lifetime
  explanation is unsupported for this hotspot. The CLI output-formatting path
  is also substantial. This remains a draft performance concern, not a reason
  to add benchmark-name heuristics or to claim a universal throughput gain.

## Measurement contract

GCC 14.2 / LLVM 15, production Release O3, ASAN off, multipass and singlepass
on, WASI on, SPEC off, virtual stack off. A two-CPU quota is shared by the
machine. Engines and worker threads are pinned to CPU 0; the collector runs on
CPU 1. Builds, tests and native profiles are excluded from formal timing.
Each sample is a fresh process, measured from pre-spawn through exit. File
cache is warm; Wasmtime compilation cache is explicitly disabled. Engine
order is randomized within each process-paired round using the manifest seed.
One warmup per engine is excluded, except the full PolyBench scout (none).
This measures CLI startup plus execution, not compilation alone.

`main` is the frozen artifact SHA256
`662424b2d69a2080642912e7fe9c5e458d47f5a2fe905fae778a9c4b9d4ca4f9`,
originally built at `2d07843`. The runtime source diff to `7eb81b0` is empty
under src, CMakeLists.txt, cmake and third_party; this is source-equivalent
artifact reuse, not a claim of a freshly built main executable.
Wasmtime is the existing 45.0.0 prebuilt artifact, SHA256
`d7b7317b34a717f4b809df14657975e2ce83221a697167219abdad6e44c7a12c`.
All input, executable hashes, commands and arguments are in cohort manifests.
`private` disables the entire scalar-folding dispatch hook on the candidate
source; its exact ablation patch is supplied. `_tier` explicitly enables the
existing budgeted private promotion. It is off for unsuffixed engines.

Statistical unit: independent process, paired by round. Ratios are medians of
paired process ratios, not ratios of group medians. Reported intervals are
pointwise exploratory 95% percentile bootstrap intervals, 10,000 resamples,
xorshift32 seed 6461199 reset per comparison. No multiple-comparison correction
or cross-cohort pooling. R1 is discovery only. `analyze.mjs` reproduces the
non-phase summaries from compressed samples; no timing rerun is needed.

The 15-round phase cohort repeats derived, normalized atax/bicg inputs 1/8/30
times in one instance; warm medians exclude the first iteration. Binaryen
normalization changes source shape. These explain startup/steady-state
separately; they do not replace canonical paper CLI data. See the original
phase harness and phase manifest for clock boundaries, packet validation and
input hashes. Native profiles are untimed and their sparse PC counts are not
retired instruction counts or compile-time estimates.

## Correctness and review

108 MIR/CgIR tests pass, including ASAN O1 with leak detection disabled;
24 lazy/private policy tests pass; 99 adapted WAST units pass in each eager
and lazy multipass mode. Final scalar fixture also exits successfully under
interpreter, singlepass, eager multipass, lazy multipass and explicit FastRA.
Repository formatting check passes. Test logs are compressed under evidence.
Upstream unsupported WAST fixture adaptation is reversed in the working tree;
it is not a production source modification.

Folding is limited to matching f32/f64 RHS add/sub/mul/div, one definition/use,
no subregisters, at most four pure virtual-register COPYs, no source kill or
address-register redefinition, and no crossed memory/call/branch operations.
Operand order and memory address tuples are preserved; replacement preserves
arithmetic flags. Failed candidates must leave use-def lists untouched.
Tests cover the bound, all-forward and independent copies, width mismatch,
shared loads, flags, address clobber, NaN, infinities, signed zero and traps.
Private owner/index publication stays under the existing lock; descriptor
allocation/lifetime stays stable. EVM high-multiply presence is conservative
through instruction deletion and reset only when all instructions are cleared.

## Full-suite coverage

Tables below use each cohort's own main and WT45 samples. Never compare these
absolute times to a different cohort. Fortune/uuid output is nondeterministic;
all other successful original-case streams match exactly across engines.
`sam` exits 1 on all engines during warmup and has no performance result.

### WAPM R7 (ms)

| Case | main | combined | combined_tier | wt45 |
|---|---:|---:|---:|---:|
| amirali | 5.99 | 5.82 | 5.59 | 5.79 |
| base64cli | 111.59 | 111.14 | 109.00 | 465.76 |
| chkfont | 41.70 | 40.46 | 38.89 | 75.25 |
| code-stock | 22.80 | 22.76 | 21.21 | 83.55 |
| cowsay | 120.66 | 120.15 | 116.94 | 396.67 |
| dice | 20.11 | 18.95 | 18.94 | 34.26 |
| echo | 24.44 | 23.59 | 24.23 | 33.88 |
| erdtree | 55.86 | 52.00 | 52.94 | 154.28 |
| figlet | 49.27 | 46.62 | 48.06 | 103.26 |
| fortune | 62.90 | 61.27 | 60.98 | 117.41 |
| irb | 3864.72 | 3793.41 | 3765.63 | 9609.09 |
| md5 | 28.37 | 27.70 | 29.62 | 43.48 |
| pi | 27.30 | 25.17 | 25.14 | 39.09 |
| pkg1 | 25.10 | 23.36 | 23.40 | 93.36 |
| qr2text | 61.60 | 51.16 | 51.60 | 132.95 |
| sam | excluded | excluded | excluded | excluded |
| suggest | 103.97 | 97.28 | 98.18 | 444.28 |
| tpl | 263.00 | 254.47 | 255.13 | 759.26 |
| uuid | 79.60 | 75.57 | 76.34 | 452.69 |
| viu | 244.21 | 234.47 | 230.36 | 1294.78 |
| pi1000 | 585.91 | 586.86 | 519.73 | 521.56 |

### PolyBench R1 scout (ms; discovery only)

| Case | main | combined | wt45 |
|---|---:|---:|---:|
| 2mm | 2521.58 | 2299.80 | 2596.13 |
| 3mm | 3522.96 | 3349.23 | 4349.85 |
| adi | 10958.12 | 10570.37 | 11261.49 |
| atax | 62.28 | 54.95 | 76.75 |
| bicg | 68.38 | 59.09 | 74.27 |
| cholesky | 12799.04 | 13153.00 | 14151.07 |
| correlation | 3152.05 | 3118.70 | 3746.77 |
| covariance | 3304.61 | 3531.86 | 4633.01 |
| deriche | 6401.44 | 6556.70 | 9861.92 |
| doitgen | 2817.10 | 2892.39 | 4532.56 |
| durbin | 33.46 | 31.96 | 44.44 |
| fdtd-2d | 4433.89 | 4192.80 | 5923.47 |
| floyd-warshall | 21254.09 | 20750.71 | 24325.11 |
| gemm | 1763.04 | 1661.82 | 2193.26 |
| gemver | 74.76 | 61.91 | 74.63 |
| gesummv | 51.42 | 48.44 | 57.82 |
| gramschmidt | 3773.47 | 3817.52 | 4758.35 |
| heat-3d | 4771.39 | 4508.61 | 5419.69 |
| jacobi-2d | 3712.44 | 3798.18 | 5000.03 |
| jacobi_1d | 40.69 | 37.45 | 42.73 |
| lu | 15999.08 | 15633.85 | 18623.08 |
| ludcmp | 12631.84 | 13395.46 | 13018.27 |
| mvt | 57.76 | 56.46 | 69.28 |
| nussinov | 5223.08 | 5702.98 | 6721.39 |
| seidel-2d | 21314.69 | 21472.77 | 23261.09 |
| symm | 1995.91 | 1918.64 | 2516.95 |
| syr2k | 2519.41 | 2674.20 | 2954.67 |
| syrk | 1533.41 | 1540.03 | 2155.66 |
| trisolv | 46.33 | 39.77 | 49.50 |
| trmm | 1810.49 | 1713.55 | 2370.05 |
