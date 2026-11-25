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
