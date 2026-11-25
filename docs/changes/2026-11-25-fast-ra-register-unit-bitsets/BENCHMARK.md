# FastRA register-unit membership benchmark

Base `00b8d10` includes #661. Candidate `d6c4066` uses a bit vector
for each of the two instruction-local register-unit membership sets.
The tests, marks, unmarks, and resets still operate on LLVM's physical
register-unit IDs, including aliases.

## FastRA attribution

An initial counting probe on `irb` observed 1,323,596 virtual live-in
scans, with 182,778 repeated in the same block. The experiment focused
on the physical register-unit membership sets. They are active across
register allocation and have no iteration consumers.

A separate timing probe put a `steady_clock` span around
`FastRA::Impl::runOnCgFunction`. Each entry is the median accumulated
FastRA time per process using fixed serial lazy FastRA.

| Case | Rounds | Main FastRA (ms) | Bit vectors (ms) | Paired change |
| --- | --- | --- | --- | --- |
| base64cli | 11 | 18.96 | 18.20 | -0.9% |
| md5 | 11 | 3.38 | 3.48 | -4.3% |
| tpl | 11 | 31.55 | 29.37 | -4.9% |
| viu | 11 | 46.16 | 42.00 | -5.6% |
| bicg | 11 | 4.10 | 3.57 | -9.7% |
| irb | 7 | 335.63 | 312.76 | -6.6% |

A second experiment added a byte-table implementation and shuffled
all three variants within each round.

| Case | Rounds | Main (ms) | Bit vectors (ms) | Byte tables (ms) | Bit-vector change | Byte-table change |
| --- | --- | --- | --- | --- | --- | --- |
| base64cli | 11 | 19.25 | 18.17 | 17.74 | -5.1% | -10.2% |
| md5 | 11 | 3.44 | 3.20 | 3.20 | -7.8% | -7.7% |
| tpl | 11 | 31.92 | 31.65 | 31.86 | -6.1% | -3.8% |
| viu | 11 | 43.85 | 41.56 | 41.01 | -5.1% | -6.2% |
| bicg | 11 | 3.68 | 3.50 | 3.65 | -4.4% | -3.3% |
| irb | 5 | 320.08 | 311.42 | 293.40 | -0.2% | -9.1% |

The byte table was faster in the large `irb` representation
comparison. Bit vectors use one bit per register unit, rounded to a
word, and reduced FastRA time for `tpl`, `viu`, and `bicg` in both
timing cohorts.

In the local GCC 14 Release executable, the host
`FastRA::Impl::useVirtReg` symbol shrank from 865 to 675 bytes and
`allocateCgInstruction` from 7,438 to 7,119 bytes. These are sizes of
the compiler routines obtained with `nm -S`.

The emitted disassembly matched for every sampled function of
`tpl` (249), `viu` (281), `bicg` (35), `gemm` (35), and `2mm` (35)
with fixed FastRA after normalizing embedded host addresses.
Default lazy can choose an initial allocator under a time budget.

## Process performance

D is default lazy Multipass. F is serial lazy FastRA. SP is Singlepass.
The benchmark used fresh processes pinned to CPU 0 on an AMD EPYC
9V74. Wasmtime 45.0.0 ran with its cache disabled. A/A uses a
byte-identical copy of main. The reported effects use paired median
ratios and bootstrap intervals.

| Case | Rounds | Main D (ms) | Candidate D (ms) | Wasmtime 45 (ms) | D change [95%] | D A/A [95%] | F change [95%] | SP change [95%] |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| base64cli | 21 | 106.94 | 107.26 | 509.06 | -1.1% [-3.6%, +3.7%] | +8.4% [+3.5%, +12.3%] | -6.2% [-10.0%, +0.2%] | -4.8% [-6.3%, +3.9%] |
| md5 | 21 | 23.29 | 22.98 | 38.23 | -1.9% [-3.9%, +1.3%] | -0.4% [-1.9%, +1.7%] | +1.1% [-3.7%, +5.2%] | -2.8% [-10.7%, +10.7%] |
| qr2text | 21 | 45.94 | 45.49 | 122.08 | +3.0% [-3.8%, +4.6%] | +4.3% [-0.5%, +8.6%] | -2.4% [-4.7%, +4.1%] | -0.9% [-4.9%, +3.7%] |
| tpl | 21 | 253.86 | 250.70 | 822.67 | -1.9% [-4.3%, +2.4%] | +6.6% [-0.5%, +11.0%] | -1.4% [-4.4%, +1.6%] | -2.4% [-3.5%, +3.1%] |
| viu | 21 | 221.53 | 219.89 | 1343.33 | -3.7% [-5.6%, +0.8%] | +3.2% [-1.1%, +5.1%] | -0.9% [-8.6%, +8.4%] | -1.0% [-3.1%, +3.1%] |
| atax | 21 | 51.46 | 51.51 | 63.95 | -1.2% [-5.4%, +0.1%] | -2.4% [-3.8%, +1.8%] | +0.1% [-1.8%, +3.4%] | -2.4% [-10.3%, +0.0%] |
| bicg | 21 | 66.82 | 61.83 | 73.98 | -3.7% [-9.8%, -0.3%] | -1.1% [-8.7%, +1.8%] | -4.5% [-6.7%, -0.4%] | +2.6% [-1.2%, +6.6%] |
| gemver | 21 | 65.73 | 63.70 | 75.39 | -2.8% [-6.5%, -1.1%] | +2.2% [-7.2%, +11.7%] | +0.6% [-4.0%, +4.6%] | -0.1% [-1.7%, +1.3%] |
| gesummv | 21 | 56.93 | 57.75 | 66.40 | -0.6% [-4.2%, +7.6%] | +3.7% [-1.4%, +11.8%] | -5.4% [-13.4%, +2.7%] | -0.6% [-8.8%, +2.2%] |
| mvt | 21 | 61.14 | 64.86 | 74.23 | +2.7% [+0.2%, +10.9%] | -1.2% [-2.8%, +3.7%] | -1.9% [-3.7%, -0.4%] | -1.9% [-4.2%, +0.1%] |
| gemm | 5 | 2270.88 | 2252.30 | 3206.75 | -1.0% [-8.5%, +7.5%] | +0.3% [-9.7%, +17.4%] | -0.8% [-8.5%, +8.1%] | — |
| 2mm | 5 | 2767.88 | 2815.78 | 3461.90 | +0.3% [-1.9%, +3.0%] | -0.6% [-4.5%, +5.7%] | +0.7% [-2.8%, +1.6%] | — |

The following local repeats used independent shuffled schedules.

| Case | Rounds | Main D (ms) | Candidate D (ms) | Wasmtime 45 (ms) | D change [95%] | D A/A [95%] | F change [95%] | SP change [95%] |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| mvt | 41 | 58.54 | 58.05 | 70.17 | -0.1% [-4.0%, +3.8%] | +3.0% [-2.1%, +4.9%] | -1.1% [-3.6%, +1.9%] | -0.9% [-2.5%, +0.4%] |
| qr2text | 41 | 45.06 | 45.21 | 120.26 | -0.4% [-1.6%, +2.2%] | +0.4% [-0.7%, +2.6%] | -1.8% [-4.8%, +1.6%] | -2.2% [-6.5%, +0.7%] |

| Case | Rounds | Main SP (ms) | Candidate SP (ms) | Wasmtime 45 (ms) | SP change [95%] | SP A/A [95%] |
| --- | --- | --- | --- | --- | --- | --- |
| viu | 31 | 62.93 | 62.31 | 1246.96 | -0.6% [-1.6%, +0.5%] | +0.2% [-1.0%, +2.0%] |

## Foreground compilation

These additional Release runs used `--enable-statistics` and sampled
DTVM's accumulated foreground lazy compilation time.

| Case | Rounds | Main foreground (ms) | Candidate foreground (ms) | D change [95%] | D A/A [95%] |
| --- | --- | --- | --- | --- | --- |
| base64cli | 15 | 85.33 | 85.77 | -1.5% [-3.5%, +4.6%] | -0.0% [-3.9%, +1.4%] |
| tpl | 15 | 168.21 | 159.70 | -3.0% [-13.1%, -0.2%] | -3.6% [-13.6%, +2.4%] |
| viu | 15 | 187.33 | 181.01 | -2.2% [-15.1%, +0.9%] | -2.9% [-14.3%, +3.0%] |
| bicg | 15 | 20.90 | 21.16 | +2.6% [-7.6%, +4.0%] | -0.9% [-3.7%, +6.3%] |
| irb | 6 | 1699.05 | 1764.52 | +1.0% [-4.8%, +4.2%] | +1.3% [-3.0%, +4.6%] |

In the 17 MiB Ruby `irb` cold run, the three DTVM variants used all six
orders with Wasmtime last in each round. Every runtime evaluated
`3+4` as 7. Process medians for main, candidate, and Wasmtime were
3908.86/3931.20/10570.94 ms. The candidate paired change was -2.5% [-5.7%, +2.8%] and A/A was
-1.2% [-3.3%, +6.3%].

The independent runner measured default lazy process changes of −2.9%
[−3.4%, −2.3%] for `viu` and −1.1% [−1.3%, −0.7%] for `tpl`.
Local `bicg` improved by 3.7% in default lazy. Its independent interval
crossed zero. The large-case default lazy estimates were −1.0% for
`gemm` and +0.3% for `2mm`, within the observed A/A ranges. Each
large case used five rounds.

The initial local default lazy `mvt` estimate was +2.7%. A 41-round
independent repeat measured −1.1% for `mvt` and −1.1% for
`qr2text`, with both intervals crossing zero.

The local 41-round repeat estimated −0.1% for `mvt` and −0.4%
for `qr2text` in default lazy. The balanced `irb` process and
foreground intervals spanned zero, with the candidate's foreground
estimate close to A/A.

The initial hosted `viu` Singlepass estimate was +1.7%. The 31-round
local Singlepass-focused repeat estimated −0.6% [−1.6%, +0.5%].

## Independent runner

The [Ubuntu 24.04 hosted experiment](https://github.com/zoowii/DTVM/actions/runs/45602280466)
records executable and fixture hashes, runtime commands, and raw samples.

| Case | Rounds | Main D (ms) | Candidate D (ms) | Wasmtime 45 (ms) | D change [95%] | D A/A [95%] | F change [95%] | SP change [95%] |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| md5 | 21 | 31.64 | 30.81 | 49.48 | -1.5% [-6.2%, +2.7%] | -0.1% [-3.6%, +6.9%] | +0.7% [-4.8%, +5.4%] | -0.1% [-2.5%, +21.1%] |
| qr2text | 21 | 57.69 | 59.88 | 137.25 | +0.2% [-7.0%, +6.2%] | -1.6% [-15.2%, +2.1%] | -1.6% [-4.9%, +3.4%] | +0.5% [-7.8%, +4.9%] |
| viu | 21 | 255.45 | 247.98 | 1398.32 | -2.9% [-3.4%, -2.3%] | +0.1% [-0.6%, +0.5%] | -0.8% [-1.0%, -0.1%] | +1.7% [+0.0%, +2.0%] |
| tpl | 21 | 308.53 | 304.93 | 899.22 | -1.1% [-1.3%, -0.7%] | -0.1% [-0.3%, +0.5%] | -1.1% [-2.1%, -0.7%] | -0.4% [-0.9%, +0.5%] |
| atax | 21 | 68.29 | 68.61 | 81.45 | +1.3% [-1.9%, +2.5%] | +0.2% [-4.3%, +2.8%] | -1.5% [-3.2%, +1.7%] | -0.0% [-0.5%, +0.7%] |
| bicg | 21 | 85.74 | 85.13 | 97.42 | +1.4% [-1.1%, +3.6%] | +0.1% [-1.8%, +1.8%] | +0.1% [-1.4%, +1.6%] | +0.1% [-1.1%, +0.3%] |

The [second independent run](https://github.com/zoowii/DTVM/actions/runs/45603508982)
focused on `mvt` and `qr2text`.

| Case | Rounds | Main D (ms) | Candidate D (ms) | Wasmtime 45 (ms) | D change [95%] | D A/A [95%] | F change [95%] | SP change [95%] |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| mvt | 41 | 65.77 | 65.03 | 75.61 | -1.1% [-2.2%, +0.0%] | -0.4% [-1.7%, +1.5%] | +0.6% [-0.4%, +1.4%] | +0.2% [-0.8%, +0.9%] |
| qr2text | 41 | 44.80 | 44.20 | 109.78 | -1.1% [-3.5%, +1.5%] | -0.2% [-1.8%, +0.7%] | -1.4% [-5.2%, +2.5%] | +1.4% [-2.2%, +6.1%] |

## Reproduce

Build both revisions with GCC 14, LLVM 15, and the following Release
options. Copy main's executable to a second path for A/A.

```bash
cmake -S . -B "$build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_DIR="$llvm15_cmake" -DZEN_ENABLE_MULTIPASS_JIT=ON \
  -DZEN_ENABLE_SINGLEPASS_JIT=ON -DZEN_ENABLE_BUILTIN_WASI=ON \
  -DZEN_ENABLE_CPU_EXCEPTION=ON -DZEN_ENABLE_EVM=OFF -DZEN_ENABLE_ASAN=OFF
cmake --build "$build" --target dtvm -j2

bench=(python3 docs/changes/2026-11-20-signed-pow2-remainder/benchmark.py
  --main "$main" --candidate "$candidate" --main-aa "$main_copy"
  --wasmtime "$wt45" --wasm benchmarks/paper/benchmarks/wapm/md5.wasm
  --default-lazy-aa --cpu 0)
"${bench[@]}" --group catalog --candidate-singlepass \
  --cases base64cli,md5,qr2text,tpl,viu,atax,bicg,gemver,gesummv,mvt \
  --rounds 21 --seed 661251 --out local-catalog
"${bench[@]}" --group catalog --omit-singlepass --cases gemm,2mm \
  --rounds 5 --long-rounds 5 --warmups 1 --seed 661252 --out local-large
"${bench[@]}" --group catalog --candidate-singlepass --cases mvt,qr2text \
  --rounds 41 --seed 661273 --out local-repeat
```

All Wasm CTest targets passed with default lazy, serial lazy FastRA,
eager Multipass, and Singlepass. For EVM, all 209 assembly fixtures
passed with explicit FastRA and the baseline comparison also matched
32 gas and state controls across all four tested configurations.
The repository formatting check passed.


## Follow-up on operand classification

The branch also records register definition indices and virtual use operands in the
first FastRA operand scan. It reuses those collections for definition allocation,
reverse-order release, and virtual use allocation. Physical uses are still read
after definitions have been assigned. The tied-operand and register-mask paths
keep their order and alias checks.

Main was `00b8d10`, bit vectors were `d6c4066`, and the full branch used
`18cb79c`. The AMD EPYC 9V74 process runs used Release binaries with LLVM 15,
fresh processes pinned to CPU 0 unless a different CPU is named, and Wasmtime 45.0.0 with its
cache disabled.
Both DTVM lazy modes and Singlepass used independently shuffled process order.
A/A uses a byte-identical main executable. Each row shows absolute medians and
paired median changes with 95% bootstrap intervals. Smaller is better.

### FastRA phase

Two shuffled rounds of experiments timed only `FastRA::runOnCgFunction` in
serial lazy FastRA on WAPM `irb`. This module compiled about 1,911 functions.
The 7-round experiment also timed a prototype that fused candidate conflict
and spill-cost checks. On `irb` its paired estimate was +6.0% relative to
operand classification. This prototype and a separate workspace reuse
prototype were discarded after the ablation runs.

| Series | Rounds | Main (ms) | Bit vectors (ms) | With operands (ms) | vs main [95%] | vs bit vectors [95%] |
| --- | --- | --- | --- | --- | --- | --- |
| Initial | 5 | 323.91 | 297.92 | 286.02 | -9.3% [-15.6%, -7.4%] | -4.2% [-7.9%, +0.4%] |
| Ablation | 7 | 317.66 | 334.13 | 300.27 | -5.8% [-7.9%, -4.4%] | -11.6% [-12.9%, -9.3%] |

### Local Default lazy Multipass

| Case | Rounds | Main (ms) | Bit vectors (ms) | With operands (ms) | Wasmtime 45 (ms) | vs main [95%] | vs bit vectors [95%] | Main A/A [95%] |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| base64cli | 21 | 103.18 | 95.97 | 97.50 | 472.50 | -0.6% [-7.5%, +6.4%] | -0.7% [-2.8%, +5.2%] | -1.0% [-2.8%, +9.8%] |
| md5 | 21 | 23.81 | 23.64 | 23.03 | 39.03 | -2.2% [-6.5%, +0.7%] | -2.2% [-8.2%, +1.8%] | +0.0% [-3.3%, +5.0%] |
| qr2text | 21 | 44.63 | 44.51 | 43.06 | 114.93 | -1.6% [-5.1%, +1.9%] | -0.9% [-4.4%, +1.3%] | -1.3% [-4.1%, +0.5%] |
| tpl | 21 | 254.74 | 251.78 | 261.45 | 805.62 | +1.8% [-4.0%, +7.3%] | +0.2% [-2.4%, +4.7%] | +2.6% [-5.0%, +9.7%] |
| viu | 21 | 209.88 | 207.69 | 205.88 | 1317.53 | -3.5% [-6.6%, -0.3%] | -2.8% [-5.1%, +3.7%] | +0.0% [-3.6%, +2.3%] |
| atax | 21 | 50.30 | 51.94 | 50.20 | 61.25 | +0.1% [-2.1%, +2.4%] | -1.3% [-5.8%, +1.7%] | +1.6% [-0.8%, +6.5%] |
| bicg | 21 | 58.55 | 57.10 | 58.12 | 69.44 | -1.1% [-3.4%, +2.6%] | +1.4% [+0.1%, +3.9%] | -1.7% [-2.7%, -0.1%] |
| gemver | 21 | 59.25 | 58.44 | 59.18 | 69.63 | -0.2% [-4.1%, +1.7%] | +1.4% [-0.2%, +4.7%] | +3.8% [-1.3%, +9.6%] |
| gesummv | 21 | 48.11 | 47.95 | 47.56 | 57.97 | -0.8% [-3.0%, +3.2%] | +0.6% [-1.5%, +3.7%] | -1.4% [-4.1%, +3.7%] |
| mvt | 21 | 58.43 | 56.72 | 56.12 | 68.62 | -1.7% [-4.7%, +2.9%] | -1.9% [-4.8%, +1.1%] | -2.5% [-4.4%, +4.2%] |
| gemm | 5 | 2371.40 | 2316.96 | 2393.14 | 3043.39 | +2.4% [-16.8%, +10.6%] | +2.1% [-5.9%, +14.6%] | -3.2% [-11.0%, +7.5%] |
| 2mm | 5 | 2750.03 | 2694.01 | 2820.03 | 3484.77 | +3.4% [+0.1%, +5.3%] | +5.1% [-5.5%, +12.5%] | -0.6% [-2.9%, +6.1%] |

### Local Serial lazy FastRA

| Case | Rounds | Main (ms) | Bit vectors (ms) | With operands (ms) | Wasmtime 45 (ms) | vs main [95%] | vs bit vectors [95%] | Main A/A [95%] |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| base64cli | 21 | 96.33 | 94.74 | 95.72 | 472.50 | -1.3% [-3.4%, +1.0%] | +0.4% [-4.8%, +1.5%] | +0.3% [-2.2%, +1.8%] |
| md5 | 21 | 21.81 | 21.77 | 23.04 | 39.03 | +5.7% [-2.6%, +10.6%] | +6.4% [-0.6%, +7.7%] | +2.3% [-2.4%, +3.6%] |
| qr2text | 21 | 40.66 | 40.21 | 40.74 | 114.93 | -0.6% [-1.4%, +2.8%] | +0.8% [-0.5%, +3.7%] | +1.8% [-0.8%, +3.8%] |
| tpl | 21 | 234.07 | 228.46 | 229.91 | 805.62 | -2.9% [-6.7%, +7.5%] | +0.3% [-4.8%, +7.5%] | -0.1% [-8.5%, +0.8%] |
| viu | 21 | 204.02 | 210.27 | 206.14 | 1317.53 | +1.3% [-1.1%, +2.8%] | -1.9% [-5.1%, +1.6%] | +3.2% [+0.2%, +7.3%] |
| atax | 21 | 64.25 | 63.04 | 63.62 | 61.25 | -0.9% [-3.9%, +0.7%] | -0.2% [-3.2%, +2.2%] | -1.3% [-3.0%, +0.3%] |
| bicg | 21 | 59.79 | 56.40 | 58.05 | 69.44 | -1.2% [-3.7%, +0.5%] | +0.7% [-2.8%, +5.0%] | -3.3% [-5.1%, -0.8%] |
| gemver | 21 | 84.46 | 83.89 | 84.16 | 69.63 | -0.7% [-2.4%, +0.4%] | -0.3% [-1.7%, +0.8%] | -0.8% [-2.1%, +0.8%] |
| gesummv | 21 | 47.36 | 45.22 | 45.26 | 57.97 | -2.8% [-11.2%, +1.0%] | -0.0% [-1.3%, +4.6%] | -3.0% [-7.1%, -0.3%] |
| mvt | 21 | 80.12 | 79.23 | 78.70 | 68.62 | -0.5% [-4.1%, +1.3%] | -1.6% [-5.0%, +0.6%] | -1.2% [-3.0%, +1.6%] |
| gemm | 5 | 3284.74 | 3252.15 | 3243.30 | 3043.39 | +0.3% [-14.6%, +3.8%] | +3.7% [-7.3%, +5.7%] | -3.2% [-10.1%, +15.0%] |
| 2mm | 5 | 8027.57 | 8039.42 | 8027.87 | 3484.77 | +1.7% [-3.4%, +5.2%] | -0.4% [-1.7%, +3.7%] | +0.6% [-5.0%, +12.7%] |

### Local Singlepass

| Case | Rounds | Main (ms) | Bit vectors (ms) | With operands (ms) | Wasmtime 45 (ms) | vs main [95%] | vs bit vectors [95%] | Main A/A [95%] |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| base64cli | 21 | 23.98 | 25.59 | 23.65 | 472.50 | -1.3% [-3.1%, +3.8%] | -3.5% [-13.7%, +3.8%] | +5.4% [-3.7%, +8.0%] |
| md5 | 21 | 6.69 | 6.40 | 6.81 | 39.03 | +4.1% [-3.7%, +6.8%] | +2.6% [+0.4%, +6.6%] | -1.2% [-11.7%, +1.7%] |
| qr2text | 21 | 8.90 | 9.00 | 8.84 | 114.93 | -2.0% [-3.2%, +1.0%] | +1.9% [-5.0%, +3.3%] | +3.4% [-0.8%, +23.6%] |
| tpl | 21 | 108.97 | 106.77 | 104.49 | 805.62 | +0.3% [-4.1%, +4.1%] | -1.4% [-6.7%, +4.0%] | -1.7% [-10.7%, +3.5%] |
| viu | 21 | 63.74 | 63.38 | 64.70 | 1317.53 | +0.7% [-2.3%, +4.8%] | +3.7% [-1.3%, +6.4%] | -0.8% [-2.5%, +4.6%] |
| atax | 21 | 83.05 | 82.91 | 82.79 | 61.25 | +0.4% [-2.4%, +1.3%] | +0.3% [-2.0%, +2.7%] | +1.0% [-0.9%, +3.9%] |
| bicg | 21 | 78.66 | 80.82 | 77.82 | 69.44 | -0.1% [-1.2%, +0.4%] | -1.8% [-6.4%, -0.6%] | -0.1% [-1.5%, +1.6%] |
| gemver | 21 | 161.07 | 161.96 | 160.13 | 69.63 | -0.9% [-2.8%, +1.4%] | +0.3% [-1.5%, +1.7%] | +1.0% [-0.9%, +3.2%] |
| gesummv | 21 | 59.74 | 59.84 | 59.46 | 57.97 | -1.0% [-3.6%, +1.7%] | -0.5% [-2.6%, +1.6%] | +1.1% [-3.0%, +7.0%] |
| mvt | 21 | 100.36 | 102.72 | 100.27 | 68.62 | +1.2% [-1.1%, +4.0%] | -1.4% [-6.2%, +2.0%] | -1.5% [-2.3%, +0.5%] |

### Local independent shuffles

These repeats used CPU 1 and 41 rounds. The table shows paired estimates against main,
with separate A/A and bit-vector comparisons in the raw experiment.

| Case | Main D (ms) | Bit vectors D (ms) | With operands D (ms) | Wasmtime 45 (ms) | D vs main [95%] | F vs main [95%] | SP vs main [95%] |
| --- | --- | --- | --- | --- | --- | --- | --- |
| md5 | 23.48 | 23.13 | 23.13 | 38.42 | -2.0% [-5.1%, -0.2%] | +0.7% [-2.1%, +1.9%] | -5.2% [-10.6%, +2.4%] |
| bicg | 60.24 | 60.56 | 60.14 | 71.06 | +0.2% [-2.3%, +2.1%] | -0.5% [-2.3%, +1.1%] | +0.2% [-1.8%, +1.0%] |
| mvt | 56.49 | 55.68 | 55.61 | 68.48 | -1.1% [-3.4%, +1.1%] | +0.4% [-1.2%, +3.7%] | -0.5% [-1.9%, +1.3%] |

### Default lazy `2mm` repeat

The first five-round comparison estimated +3.4% against main. A separately
shuffled nine-round run on CPU 1 retained the four wall-time controls.

| Case | Rounds | Main (ms) | Bit vectors (ms) | With operands (ms) | Wasmtime 45 (ms) | vs main [95%] | vs bit vectors [95%] | Main A/A [95%] |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2mm | 9 | 2887.49 | 2843.62 | 2842.38 | 3619.56 | -3.7% [-11.5%, +4.4%] | +0.0% [-7.9%, +3.8%] | +4.6% [-3.8%, +6.5%] |

### Foreground compilation on default lazy

These runs used `--enable-statistics` and sampled the sum of foreground
compilation time over each process.

| Case | Rounds | Main (ms) | Bit vectors (ms) | With operands (ms) | vs main [95%] | vs bit vectors [95%] | Main A/A [95%] |
| --- | --- | --- | --- | --- | --- | --- | --- |
| viu | 21 | 181.96 | 172.67 | 173.63 | -4.6% [-10.0%, -0.3%] | +1.3% [-1.1%, +2.3%] | -3.0% [-7.2%, +0.5%] |
| tpl | 21 | 162.55 | 169.62 | 160.91 | -2.5% [-4.7%, +0.9%] | -3.9% [-9.6%, -2.2%] | +0.0% [-2.0%, +2.7%] |
| bicg | 21 | 20.42 | 20.28 | 22.27 | +0.9% [-3.9%, +3.9%] | +1.9% [-1.9%, +5.2%] | +1.3% [-4.6%, +10.7%] |

### WAPM `irb` on default lazy

Each measurement used a fresh process. Foreground compilation is DTVM’s
accumulated `JIT Lazy Compilation(Fg)` counter. Wasmtime 45 is measured
with full process wall time. It ran after the balanced DTVM order in each block.

| Series | Rounds | Measurement | Main (ms) | Bit vectors (ms) | With operands (ms) | Wasmtime 45 (ms) | vs main [95%] | vs bit vectors [95%] | Main A/A [95%] |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| CPU 0 | 5 | Foreground compilation | 1806.93 | 1692.68 | 1705.95 | — | -4.9% [-13.6%, +4.4%] | -0.4% [-2.4%, +6.3%] | -1.4% [-2.5%, +9.7%] |
| CPU 0 | 5 | Process wall time | 3796.45 | 3822.87 | 3905.38 | 10477.30 | +1.6% [-6.6%, +7.9%] | -4.2% [-7.4%, +12.4%] | +3.1% [-1.1%, +9.7%] |
| CPU 1 | 5 | Foreground compilation | 1709.51 | 1605.66 | 1636.00 | — | -3.1% [-13.2%, +6.5%] | +2.1% [-10.5%, +7.8%] | -1.1% [-3.1%, +1.3%] |
| CPU 1 | 5 | Process wall time | 3823.56 | 3683.41 | 3625.22 | 10033.67 | -5.1% [-8.0%, +2.3%] | +0.1% [-7.1%, +5.8%] | -3.8% [-5.7%, +3.5%] |

### Independent GitHub runner

The Ubuntu 24.04 runner repeated the three-revision process comparison. Its logs
and artifact contain the exact runtime commands, fixtures, and executable hashes. [Run and raw measurements](https://github.com/zoowii/DTVM/actions/runs/45610788150)


#### Default lazy Multipass

| Case | Rounds | Main (ms) | Bit vectors (ms) | With operands (ms) | Wasmtime 45 (ms) | vs main [95%] | vs bit vectors [95%] | Main A/A [95%] |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| md5 | 21 | 33.24 | 32.24 | 31.77 | 50.36 | -1.1% [-7.8%, +2.4%] | -1.4% [-5.2%, +0.2%] | +0.3% [-1.5%, +6.2%] |
| qr2text | 21 | 60.08 | 61.15 | 58.88 | 138.68 | +0.1% [-6.9%, +1.5%] | +0.2% [-7.8%, +5.7%] | -0.6% [-8.3%, +1.7%] |
| viu | 21 | 255.58 | 253.51 | 253.08 | 1400.96 | -1.6% [-3.3%, +0.4%] | +0.3% [-1.8%, +1.6%] | -0.1% [-1.2%, +0.2%] |
| tpl | 21 | 310.31 | 310.92 | 306.96 | 910.60 | -1.1% [-1.9%, -0.9%] | -0.5% [-1.3%, +0.3%] | -0.2% [-0.9%, +0.2%] |
| atax | 21 | 68.37 | 67.48 | 67.43 | 82.64 | -0.5% [-1.8%, +1.0%] | +0.7% [-0.8%, +1.9%] | -0.8% [-2.5%, +2.3%] |
| bicg | 21 | 84.49 | 84.03 | 84.40 | 98.42 | +0.4% [-1.5%, +1.5%] | +0.8% [-1.5%, +1.3%] | +1.4% [-0.4%, +2.4%] |

#### Serial lazy FastRA

| Case | Rounds | Main (ms) | Bit vectors (ms) | With operands (ms) | Wasmtime 45 (ms) | vs main [95%] | vs bit vectors [95%] | Main A/A [95%] |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| md5 | 21 | 29.19 | 28.22 | 30.71 | 50.36 | -0.3% [-3.5%, +3.8%] | +0.5% [-3.0%, +10.9%] | -4.6% [-6.2%, -0.3%] |
| qr2text | 21 | 53.26 | 55.05 | 53.27 | 138.68 | -0.8% [-2.3%, +0.9%] | +0.7% [-7.5%, +3.6%] | +1.1% [-5.0%, +3.9%] |
| viu | 21 | 249.64 | 251.03 | 249.74 | 1400.96 | -1.3% [-2.3%, +0.7%] | +0.0% [-1.2%, +1.1%] | -0.3% [-0.8%, +1.7%] |
| tpl | 21 | 284.04 | 280.94 | 280.77 | 910.60 | -1.1% [-1.8%, -0.5%] | -0.0% [-1.4%, +0.6%] | -0.1% [-0.4%, +1.4%] |
| atax | 21 | 80.71 | 80.22 | 82.39 | 82.64 | +0.6% [-0.3%, +1.7%] | +1.3% [-0.0%, +3.3%] | -0.1% [-1.4%, +1.0%] |
| bicg | 21 | 81.84 | 82.48 | 84.06 | 98.42 | +1.6% [-0.5%, +4.3%] | +1.9% [-0.2%, +5.8%] | +0.8% [-2.0%, +2.8%] |

#### Singlepass

| Case | Rounds | Main (ms) | Bit vectors (ms) | With operands (ms) | Wasmtime 45 (ms) | vs main [95%] | vs bit vectors [95%] | Main A/A [95%] |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| md5 | 21 | 7.79 | 7.81 | 7.91 | 50.36 | +1.1% [-11.2%, +9.4%] | +3.6% [-7.5%, +7.9%] | +0.5% [-2.2%, +10.6%] |
| qr2text | 21 | 12.80 | 13.45 | 13.31 | 138.68 | +0.6% [-3.5%, +6.1%] | -1.1% [-7.5%, +7.4%] | +0.2% [-3.3%, +5.7%] |
| viu | 21 | 88.23 | 93.05 | 89.50 | 1400.96 | +0.0% [-2.8%, +4.0%] | -0.4% [-1.7%, +0.6%] | +5.3% [-1.4%, +6.9%] |
| tpl | 21 | 141.95 | 143.93 | 142.93 | 910.60 | +0.5% [-1.2%, +1.1%] | -0.3% [-4.7%, +1.1%] | -0.7% [-1.4%, +0.8%] |
| atax | 21 | 102.09 | 102.72 | 101.58 | 82.64 | -0.5% [-1.0%, +0.7%] | -0.6% [-2.5%, +0.4%] | +0.2% [-0.7%, +1.1%] |
| bicg | 21 | 101.47 | 102.53 | 101.08 | 98.42 | -1.2% [-1.8%, -0.3%] | -0.7% [-1.7%, -0.1%] | +0.1% [-0.6%, +0.5%] |

Hosted `tpl` default lazy was 1.1% faster than main, with a 95% interval of [0.9%, 1.9%] lower wall time. Relative to bit vectors its interval crossed zero. All six hosted default-lazy comparisons against bit vectors also crossed zero.

The 41-round repeats narrowed the initial latency estimates. `md5` serial FastRA was +0.7% against main [−2.1%, +1.9%]. `bicg` default lazy was +0.7% against bit vectors [−1.2%, +3.7%].

### Correctness

- CTest passed 7/7 in each of default lazy Multipass, serial lazy FastRA,
  eager Multipass, and Singlepass.
- EVM differential runs matched across all three binaries for 209 fixtures
  and 32 gas/state controls in each of interpreter, eager Multipass, lazy
  Multipass, and fixed FastRA.
- Guest disassembly matched for all 881 compiled functions across
  `base64cli`, `md5`, `tpl`, `viu`, `bicg`, `gemm`, and `2mm`
  in serial lazy FastRA, after normalizing embedded host addresses.
- The repository format check passed.

The follow-up benchmark driver and build commands are attached to the
benchmark branch. It can be run from the repository root with the three
binaries and a byte-identical main copy. [Driver](https://github.com/zoowii/DTVM/blob/29b7aa632cb94e45429b308f5544de4a5c5c2384/.ci/benchmark-followup.py) [Build and invocation](https://github.com/zoowii/DTVM/blob/29b7aa632cb94e45429b308f5544de4a5c5c2384/.github/workflows/fast-ra-followup.yml)
