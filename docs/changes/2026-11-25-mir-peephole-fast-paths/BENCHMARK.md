# MIR peephole fast paths benchmark

Base `b5c7428` includes #660. Candidate `88cb3bd` adds direct returns for
local reads and constants during expression rewriting and skips the
separate floating-point hoisting walk in functions with no FP literals.

## Pass attribution

Four diagnostic builds timed expression rewriting and the independent
hoisting stage with `steady_clock` across each compiled function. Each
cell reports the median of process totals from shuffled rounds with
serial lazy FastRA. The Release process measurements below use separate
binaries.

| Case | Rounds | Main (ms) | Leaves only (ms) | Guard only (ms) | Both (ms) | Both paired change |
| --- | --- | --- | --- | --- | --- | --- |
| md5 | 9 | 0.722 | 0.622 | 0.614 | 0.468 | -38.7% |
| base64cli | 9 | 3.835 | 2.644 | 2.939 | 1.778 | -51.8% |
| tpl | 9 | 6.942 | 4.821 | 5.790 | 3.782 | -46.1% |
| viu | 9 | 8.194 | 5.551 | 6.369 | 3.989 | -51.2% |
| bicg | 9 | 0.870 | 0.671 | 0.731 | 0.512 | -39.1% |
| irb | 5 | 77.872 | 48.825 | 52.479 | 32.885 | -57.8% |

Scans count functions reaching constant collection. Hoists count
functions with a nonempty hoist set. Each variant preserved the
observed number of functions that performed hoisting.

| Case | Functions | Main scans | Candidate scans | Main hoists | Candidate hoists | Main rewrite (ms) | Leaves rewrite (ms) | Main scan (ms) | Guard scan (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| md5 | 31 | 31 | 1 | 1 | 1 | 0.474 | 0.365 | 0.229 | 0.139 |
| base64cli | 215 | 215 | 0 | 0 | 0 | 2.979 | 1.821 | 0.822 | 0.011 |
| tpl | 249 | 249 | 10 | 8 | 8 | 5.192 | 2.979 | 1.829 | 0.855 |
| viu | 281 | 281 | 2 | 2 | 2 | 6.310 | 3.810 | 1.809 | 0.078 |
| bicg | 35 | 35 | 3 | 3 | 3 | 0.576 | 0.408 | 0.252 | 0.157 |
| irb | 1911 | 1911 | 26 | 17 | 17 | 56.476 | 30.276 | 19.020 | 2.665 |

Guard-only foreground timings include the cost of recording literals
during MIR construction, the hoisting time, and the remaining JIT
pipeline. They measure the net impact of the guard. Individual
constructor costs are below the resolution of this experiment.

| Case | Main foreground (ms) | Guard foreground (ms) | Guard paired change |
| --- | --- | --- | --- |
| md5 | 16.57 | 16.06 | -2.4% |
| base64cli | 88.83 | 86.26 | -1.2% |
| tpl | 153.53 | 148.18 | -3.7% |
| viu | 192.79 | 186.05 | -0.7% |
| bicg | 18.69 | 17.87 | +1.6% |
| irb | 3045.84 | 3112.41 | -5.1% |

Fixed FastRA disassembly matched for the captured function objects in
`tpl` (249), `viu` (281), `bicg` (35), `gemm` (35), and `2mm` (35) after
normalizing embedded host addresses in `movabs` operands. Default
lazy itself chooses its initial allocator under a time budget.

## Foreground and process time

D is default lazy Multipass, F is serial lazy FastRA, and SP is
Singlepass. On AMD EPYC 9V74, each process inherits affinity to CPU 0.
Wasmtime 45.0.0 runs with its compilation cache disabled. A/A uses a
byte-identical copy of main. Values are medians and changes are paired
median ratios with bootstrap intervals.

| Case | Rounds | Main D (ms) | Candidate D (ms) | Wasmtime 45 (ms) | D change [95%] | D A/A [95%] | F change [95%] | SP change [95%] |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| base64cli | 21 | 173.01 | 176.03 | 817.97 | -0.7% [-9.7%, +9.1%] | +3.0% [-5.0%, +14.5%] | +13.8% [-4.8%, +24.1%] | +2.8% [-4.0%, +75.1%] |
| md5 | 21 | 31.51 | 57.41 | 73.61 | -0.2% [-12.5%, +29.0%] | +8.0% [-35.3%, +56.5%] | -2.0% [-10.6%, +10.4%] | +3.6% [-7.9%, +13.0%] |
| qr2text | 21 | 81.02 | 79.66 | 203.77 | -0.2% [-11.8%, +36.9%] | +5.2% [-2.0%, +21.0%] | -0.8% [-6.3%, +5.9%] | -1.7% [-6.3%, +24.9%] |
| tpl | 21 | 266.78 | 265.26 | 819.28 | +0.5% [-8.1%, +9.9%] | +0.6% [-5.1%, +4.7%] | -0.5% [-4.3%, +6.4%] | -1.9% [-13.7%, +1.6%] |
| viu | 21 | 229.33 | 211.48 | 1367.97 | -4.4% [-16.9%, -2.1%] | -1.1% [-9.0%, +5.3%] | -6.8% [-11.7%, +0.2%] | +0.8% [-1.8%, +3.4%] |
| atax | 21 | 50.95 | 51.43 | 61.47 | -1.4% [-14.0%, +5.2%] | -1.2% [-5.0%, +3.8%] | -2.6% [-5.5%, +0.1%] | -0.1% [-1.8%, +2.3%] |
| bicg | 21 | 59.54 | 59.76 | 69.92 | +0.4% [-2.3%, +2.5%] | +0.4% [-2.2%, +3.8%] | +0.9% [-5.3%, +5.6%] | -0.6% [-2.5%, +3.1%] |
| gemver | 21 | 65.79 | 62.81 | 77.31 | -3.8% [-9.8%, -0.8%] | -1.0% [-5.1%, +0.4%] | -0.1% [-4.5%, +2.7%] | -0.0% [-4.2%, +2.1%] |
| gesummv | 21 | 49.34 | 49.56 | 58.40 | -1.8% [-2.7%, +4.4%] | +0.3% [-2.0%, +8.9%] | -1.3% [-3.1%, +2.3%] | +0.0% [-0.8%, +2.3%] |
| mvt | 21 | 56.81 | 55.12 | 67.12 | -3.9% [-7.7%, -0.9%] | -0.5% [-4.4%, +2.3%] | -0.8% [-5.0%, +4.4%] | +0.5% [-3.2%, +2.4%] |
| gemm | 5 | 2391.81 | 2357.09 | 3250.96 | -0.9% [-10.6%, +5.7%] | +5.3% [-11.5%, +19.3%] | +2.0% [-7.5%, +17.4%] | — |
| 2mm | 5 | 2664.44 | 2693.64 | 3358.90 | +0.2% [-6.4%, +5.3%] | +0.7% [-0.6%, +7.4%] | -0.8% [-10.8%, +7.0%] | — |

A second local schedule repeated the noisy short cases and the
Singlepass `atax` signal after the local build jobs finished:

| Case | Rounds | Main D (ms) | Candidate D (ms) | Wasmtime 45 (ms) | D change [95%] | D A/A [95%] | F change [95%] | SP change [95%] |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| base64cli | 25 | 105.58 | 99.85 | 469.38 | -4.6% [-7.0%, -2.8%] | +0.5% [-3.5%, +2.5%] | -1.6% [-4.7%, +1.5%] | -3.3% [-7.0%, +3.3%] |
| md5 | 25 | 23.73 | 23.59 | 37.93 | -2.9% [-4.9%, +0.1%] | -0.7% [-3.1%, +4.9%] | -3.5% [-6.0%, -1.5%] | +2.4% [-3.7%, +4.6%] |
| qr2text | 25 | 47.42 | 45.82 | 118.73 | -3.2% [-5.7%, -0.3%] | +0.2% [-2.8%, +3.9%] | -1.7% [-4.0%, +0.9%] | +3.3% [-1.9%, +8.7%] |
| atax | 41 | 52.77 | 51.97 | 63.78 | -0.7% [-3.8%, +1.1%] | -0.1% [-2.7%, +2.7%] | -0.6% [-4.7%, +2.0%] | +0.0% [-0.8%, +1.3%] |

The separate Release cohort sampled the DTVM foreground compilation
statistic with `--enable-statistics`:

| Case | Rounds | Main foreground (ms) | Candidate foreground (ms) | D change [95%] | D A/A [95%] |
| --- | --- | --- | --- | --- | --- |
| tpl | 15 | 173.86 | 165.56 | -3.1% [-11.1%, +2.0%] | -1.2% [-5.8%, +3.8%] |
| viu | 15 | 183.04 | 179.89 | -1.2% [-3.9%, +0.8%] | -0.3% [-2.8%, +4.4%] |
| bicg | 15 | 20.43 | 20.50 | -1.8% [-7.2%, +5.2%] | +2.1% [-5.2%, +8.6%] |
| irb | 6 | 1730.04 | 1677.71 | -1.4% [-7.2%, +5.0%] | -3.4% [-10.0%, +3.5%] |

For the 17 MiB `irb` case the three DTVM variants use all six orders,
with Wasmtime last in each round. Each runtime evaluated `3+4` as 7.
Process medians for main, candidate, and Wasmtime were 3854.13/3737.53/10294.37 ms.
The candidate pair measured -1.8% [-7.5%, +14.2%] and A/A measured -1.8% [-5.5%, +0.9%].

The independent runner found a −2.0% process change for `viu` in serial
FastRA and a default lazy interval spanning zero. The two large
PolyBench cases used five rounds per case. Their default lazy paired
changes were −0.9% for `gemm` and +0.2% for `2mm`, within the A/A ranges.

The first hosted `atax` Singlepass estimate was +2.8% [+0.7%, +3.4%].
The independent 41-round follow-up measured +0.6% [−0.1%, +1.8%].
The initial local short-case screen overlapped local compilation and
had wide A/A intervals. The repeat reports those cases after the
build jobs finished.

The short-case repeat measured a default lazy process improvement of
4.6% [−7.0%, −2.8%] for `base64cli` and 3.2% [−5.7%, −0.3%] for
`qr2text`. The `md5` serial FastRA result was −3.5% [−6.0%, −1.5%]
locally and −2.9% [−9.7%, −0.5%] on the independent machine.
The `irb` process change of −1.8% was close to its A/A estimate.
The phase-local improvement is the consistent result on the large
Ruby fixture.
The local 41-round `atax` Singlepass confirmation measured
+0.0% [−0.8%, +1.3%].

## Independent runner

The [Ubuntu 24.04 hosted experiment](https://github.com/zoowii/DTVM/actions/runs/45571822522)
saves its fixture hashes, commands, and raw samples. Its process
comparison used a pinned CPU and a separate shuffled schedule.

| Case | Rounds | Main D (ms) | Candidate D (ms) | Wasmtime 45 (ms) | D change [95%] | D A/A [95%] | F change [95%] | SP change [95%] |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| md5 | 21 | 23.53 | 23.37 | 34.22 | +0.6% [-8.1%, +3.6%] | -0.0% [-7.7%, +2.3%] | -2.9% [-9.7%, -0.5%] | -1.2% [-4.2%, +1.4%] |
| qr2text | 21 | 40.20 | 39.81 | 91.00 | -2.2% [-4.5%, +4.7%] | -2.8% [-7.9%, +1.9%] | +0.5% [-1.9%, +4.2%] | -0.2% [-2.0%, +4.8%] |
| viu | 21 | 174.33 | 173.56 | 920.73 | -0.8% [-1.5%, +1.8%] | -0.5% [-2.2%, +1.7%] | -2.0% [-3.8%, -0.0%] | +0.3% [-0.6%, +6.1%] |
| tpl | 21 | 198.93 | 197.43 | 556.22 | -0.2% [-2.8%, +2.2%] | +0.3% [-1.1%, +2.1%] | -1.1% [-2.3%, +1.1%] | +0.8% [-0.0%, +2.0%] |
| atax | 21 | 47.19 | 47.09 | 55.69 | +1.7% [-4.1%, +4.7%] | -1.3% [-6.7%, +1.3%] | +0.1% [-2.9%, +4.0%] | +2.8% [+0.7%, +3.4%] |
| bicg | 21 | 61.42 | 60.78 | 68.20 | -2.6% [-3.1%, +2.2%] | +0.7% [-0.9%, +1.5%] | -0.6% [-1.9%, +0.4%] | +1.4% [-0.2%, +2.0%] |

The [independent `atax` confirmation](https://github.com/zoowii/DTVM/actions/runs/45573004040)
uses a separate 41-round schedule.

| Case | Rounds | Main D (ms) | Candidate D (ms) | Wasmtime 45 (ms) | D change [95%] | D A/A [95%] | F change [95%] | SP change [95%] |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| atax | 41 | 50.87 | 50.94 | 60.74 | +0.5% [-0.7%, +1.8%] | -0.5% [-2.6%, +1.2%] | +1.4% [-0.5%, +3.9%] | +0.6% [-0.1%, +1.8%] |

## Reproduce

Configure both Release binaries with GCC 14, LLVM 15, and:

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
  --rounds 21 --seed 660251 --out local-catalog
"${bench[@]}" --group catalog --omit-singlepass --cases gemm,2mm \
  --rounds 5 --long-rounds 5 --warmups 1 --seed 660252 --out local-large
"${bench[@]}" --group catalog --candidate-singlepass \
  --cases base64cli,md5,qr2text --rounds 25 --seed 660273 --out repeat-short
"${bench[@]}" --group catalog --candidate-singlepass \
  --cases atax --rounds 41 --seed 660294 --out repeat-atax

python3 benchmarks/paper/harness/run.py --dtvm "$candidate" --wasmtime "$wt45" \
  --cases tpl,viu,bicg,irb --dtvm-modes lazy-G-MT \
  --metric both --stats --repeats 6 --cpu 0 --out candidate-phases
```

The Wasm CTest suite passed in default lazy, serial lazy FastRA,
eager Multipass, and Singlepass. The EVM CLI matched its 209 assembly
fixtures and the additional 32 gas and state controls for each tested
configuration. The repository formatting check passed.
