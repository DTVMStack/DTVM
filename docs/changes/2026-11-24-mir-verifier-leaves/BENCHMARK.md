# MIR leaf verification benchmark

Base `4cf5bca` includes #658. Candidate `cc19d65` adds fast paths
for local reads (`dread`) and constants in both MIR verification passes.
The existing constant type check and cycle checks for non-leaves still run.

## Pass attribution

A separate diagnostic build recorded the first and second `MVerifier` spans
per compiled function with `steady_clock`. The table sums those spans within
each process and reports the median of seven paired rounds in fixed FastRA.

| Case | Compiled functions | Main verifier (ms) | Candidate verifier (ms) | Paired change |
| --- | --- | --- | --- | --- |
| viu | 281 | 15.98 | 9.98 | -37.7% |
| tpl | 249 | 14.14 | 7.69 | -45.8% |
| md5 | 31 | 1.13 | 0.78 | -31.8% |
| qr2text | 74 | 2.88 | 1.53 | -43.1% |
| figlet | 113 | 2.29 | 1.52 | -33.6% |
| bicg | 35 | 1.34 | 1.04 | -27.8% |
| gemver | 35 | 1.21 | 0.87 | -25.6% |
| irb | 1911 | 142.24 | 69.59 | -49.3% |

The baseline verifier pushes callee-saved registers and probes its visit-state
map before dispatching on the instruction kind. In the candidate, the
`dread` branch reaches a `ret` before pushing registers. The constant branch
checks the MIR value type against the literal type directly.

The emitted guest disassembly matched for all sampled lazy FastRA function
objects from `md5` (31), `viu` (281), `bicg` (35), `gemm` (35), and
`2mm` (35) after normalizing embedded host addresses in `movabs` operands.
This comparison uses fixed allocation. The default lazy allocator may make
different budget decisions when compilation becomes faster.

## Foreground compilation

D is default lazy Multipass (`-m multipass --enable-multipass-lazy`).
F is explicit serial FastRA (add `--disable-multipass-greedyra
--disable-multipass-multithread`). These are separate paired runs with
`--enable-statistics` on the Release binaries. Foreground compilation is
the sum of demanded compilations measured by DTVM. DTVM's guest execution
statistic excludes those foreground spans.

| Case | Mode | Rounds | Main (ms) | Candidate (ms) | Paired foreground change [95%] | A/A [95%] |
| --- | --- | --- | --- | --- | --- | --- |
| md5 | D | 21 | 18.17 | 17.70 | -1.9% [-5.5%, +0.2%] | +0.1% [-2.4%, +3.6%] |
| md5 | F | 21 | 16.50 | 16.34 | -0.1% [-2.8%, +4.1%] | -0.1% [-2.8%, +2.0%] |
| qr2text | D | 21 | 38.06 | 37.17 | -2.8% [-4.9%, +0.6%] | +0.1% [-2.3%, +1.3%] |
| qr2text | F | 21 | 35.82 | 34.78 | -1.4% [-4.4%, +0.0%] | +0.4% [-1.4%, +3.6%] |
| tpl | D | 21 | 190.78 | 182.75 | -6.9% [-9.9%, -2.9%] | +3.1% [-4.7%, +5.9%] |
| tpl | F | 21 | 165.53 | 161.71 | -1.0% [-3.8%, +0.3%] | +3.4% [+0.8%, +8.5%] |
| viu | D | 21 | 188.75 | 186.60 | -1.3% [-4.0%, +0.3%] | +1.4% [-2.3%, +5.1%] |
| viu | F | 21 | 190.38 | 187.71 | -0.8% [-3.5%, +1.8%] | +1.0% [-0.6%, +1.9%] |
| bicg | D | 21 | 21.07 | 20.96 | +0.9% [-4.5%, +4.2%] | +1.7% [-3.4%, +4.5%] |
| bicg | F | 21 | 18.89 | 18.53 | -2.1% [-5.0%, +2.5%] | +4.9% [+2.2%, +7.1%] |
| irb | D | 7 | 1956.19 | 1899.97 | -5.0% [-10.4%, +5.9%] | -5.7% [-10.9%, +11.3%] |
| irb | F | 7 | 1789.04 | 1838.89 | +4.8% [-12.6%, +9.5%] | +4.8% [-2.0%, +10.0%] |

For the 17 MiB Ruby `irb` fixture, every runtime evaluated `3+4` as 7.
Wasmtime 45 is measured at the process boundary. The two DTVM modes
share the same seven Wasmtime samples.

| Mode | Main wall (ms) | Candidate wall (ms) | Wasmtime 45 wall (ms) | Paired wall change [95%] | Main guest execution (ms) | Candidate guest execution (ms) |
| --- | --- | --- | --- | --- | --- | --- |
| D | 4033.70 | 4044.20 | 10828.20 | -2.1% [-7.6%, +6.4%] | 1938.64 | 2077.98 |
| F | 4024.31 | 3961.80 | 10828.20 | -1.3% [-10.6%, +7.6%] | 1971.14 | 1980.61 |

## WAPM and PolyBench process time

Each sample runs a fresh process pinned to CPU 0 on an AMD EPYC 9V74 with
a two-CPU quota. Release builds use GCC 14, LLVM 15, CPU exceptions, WASI,
Multipass and Singlepass. Wasmtime is 45.0.0 with its cache disabled.
Variants are shuffled within each case and round. Wall times are medians.
The changes are paired median ratios with bootstrap intervals. A/A compares
a byte-identical copy of main to main with the same flags.

| Case | Rounds | Main D (ms) | Candidate D (ms) | Wasmtime 45 (ms) | D change [95%] | D A/A [95%] | F change [95%] | SP change [95%] |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| md5 | 21 | 24.56 | 24.13 | 40.83 | -2.0% [-5.9%, -1.0%] | -0.4% [-4.4%, +3.4%] | -1.6% [-5.2%, +2.7%] | -4.9% [-14.2%, +15.1%] |
| qr2text | 21 | 49.75 | 48.28 | 126.68 | -0.3% [-1.8%, +6.3%] | +0.4% [-0.9%, +4.3%] | -4.5% [-7.5%, -2.9%] | -3.0% [-11.2%, +4.8%] |
| figlet | 21 | 53.07 | 49.92 | 116.29 | -2.6% [-9.2%, +5.3%] | -6.3% [-10.0%, +3.2%] | +1.8% [-3.5%, +12.1%] | +6.5% [-2.7%, +10.9%] |
| tpl | 21 | 321.22 | 288.68 | 904.00 | -9.0% [-16.2%, -1.3%] | -2.7% [-11.2%, +6.3%] | +4.8% [-1.0%, +12.7%] | -0.5% [-5.1%, +6.1%] |
| viu | 21 | 230.85 | 230.33 | 1351.16 | -2.3% [-5.2%, +4.8%] | +4.9% [+0.4%, +7.3%] | +0.9% [-4.0%, +5.9%] | +1.1% [-1.4%, +5.0%] |
| atax | 21 | 54.42 | 56.22 | 67.88 | +0.9% [-5.2%, +6.8%] | +2.0% [-5.8%, +5.9%] | -4.4% [-17.5%, +2.3%] | -1.3% [-3.1%, +5.8%] |
| bicg | 21 | 61.90 | 62.53 | 73.97 | +0.1% [-5.5%, +4.9%] | +1.5% [-2.7%, +4.7%] | -1.4% [-6.1%, +1.7%] | +0.3% [-1.9%, +2.0%] |
| gemver | 21 | 60.79 | 59.26 | 71.55 | -1.9% [-5.2%, +2.6%] | +0.1% [-2.1%, +3.2%] | -0.4% [-3.4%, +1.4%] | -0.4% [-1.9%, +0.4%] |
| gesummv | 21 | 50.88 | 49.44 | 59.32 | +1.2% [-4.5%, +2.1%] | +1.1% [-3.0%, +4.4%] | +0.3% [-2.1%, +8.2%] | -1.1% [-2.5%, +0.4%] |
| jacobi_1d | 21 | 30.49 | 29.45 | 42.08 | -0.6% [-1.9%, +3.9%] | +2.7% [-2.8%, +4.6%] | +0.4% [-1.3%, +6.7%] | -1.2% [-4.5%, +1.7%] |
| mvt | 21 | 58.69 | 57.92 | 74.09 | -0.8% [-3.6%, +3.0%] | +3.2% [-1.2%, +7.8%] | -1.7% [-2.9%, +4.2%] | +1.9% [+0.6%, +8.1%] |
| trisolv | 21 | 42.58 | 41.86 | 53.35 | +0.3% [-2.1%, +2.4%] | -0.4% [-3.1%, +2.1%] | +1.2% [-2.1%, +1.7%] | +0.4% [-2.1%, +1.0%] |
| gemm | 5 | 2329.26 | 2329.50 | 3027.74 | +1.2% [-18.1%, +14.5%] | -3.0% [-13.8%, +13.7%] | -3.3% [-6.7%, +11.5%] | — |
| 2mm | 5 | 2844.95 | 2859.28 | 3458.95 | +1.0% [-4.9%, +21.8%] | -2.5% [-4.2%, +10.3%] | +1.2% [+0.4%, +13.1%] | — |

Default lazy `tpl` was faster on both machines. Locally its default lazy
foreground compilation paired change was −6.9% [−9.9%, −2.9%]. `irb` had
the largest measured verifier reduction. Its foreground and process
intervals overlap the A/A observations.

The initial Singlepass `mvt` estimate was +1.9% [+0.6%, +8.1%]. A new
41-round schedule on CPU 1 measured −1.4% [−2.8%, +0.8%]. The initial
large-case screen used five rounds per case, so its process intervals
are wider than those of the shorter cases. The FastRA `2mm` estimate
was +1.2% [+0.4%, +13.1%] alongside an A/A point estimate of +2.2%.
A new seven-round schedule on CPU 1 measured −2.7% [−4.23%, −0.03%]
for fixed FastRA and −1.5% [−2.4%, +2.8%] for default lazy. The
default-lazy main, candidate and Wasmtime medians were 2817.46, 2779.80 and
3480.11 ms. The fixed-FastRA medians were 8198.05 and 8152.95 ms, with a
same-binary A/A change of −0.2% [−3.2%, +4.1%]. The initial `2mm` slowdown
was absent on repeat.

## Independent runner

Ubuntu 24.04 hosted runner with the project's Linux x64 build container.
Pinning, ordering, binary hashes, fixture hashes and raw samples are
recorded by the [runner](https://github.com/zoowii/DTVM/actions/runs/45419779707).
The large PolyBench cases were measured locally.

| Case | Rounds | Main D (ms) | Candidate D (ms) | Wasmtime 45 (ms) | D change [95%] | F change [95%] | SP change [95%] | D A/A [95%] |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| md5 | 21 | 32.18 | 32.20 | 49.81 | -2.0% [-5.2%, +1.3%] | -1.1% [-2.5%, +4.4%] | -1.5% [-5.6%, +2.6%] | +0.9% [-3.2%, +2.3%] |
| qr2text | 21 | 63.26 | 60.55 | 139.42 | -3.6% [-4.7%, +0.1%] | -3.8% [-5.3%, -2.3%] | -1.4% [-7.2%, +3.9%] | -0.0% [-1.6%, +6.9%] |
| viu | 21 | 269.05 | 267.63 | 1396.02 | -2.5% [-3.8%, +0.7%] | -3.5% [-3.9%, -2.5%] | -1.0% [-2.1%, +0.4%] | +0.1% [-1.9%, +3.2%] |
| tpl | 21 | 326.36 | 316.94 | 897.60 | -3.0% [-3.1%, -1.9%] | -2.7% [-3.3%, -2.0%] | +0.2% [-0.6%, +1.1%] | -0.5% [-0.9%, -0.0%] |
| atax | 21 | 70.70 | 69.41 | 83.46 | -1.0% [-2.8%, -0.6%] | -1.3% [-2.2%, +1.0%] | -0.2% [-0.8%, +0.8%] | +0.8% [-2.6%, +1.7%] |
| bicg | 21 | 88.24 | 86.48 | 96.93 | +0.2% [-0.8%, +0.9%] | -0.9% [-3.2%, +1.8%] | +0.1% [-1.4%, +1.0%] | +0.4% [-1.1%, +1.5%] |

## Reproduce

Build both revisions using the flags above. Use a byte-identical copy of
the main binary for A/A and one logical CPU from the process affinity mask.

```bash
cmake -S . -B "$build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_DIR="$llvm15_cmake" -DZEN_ENABLE_MULTIPASS_JIT=ON \
  -DZEN_ENABLE_SINGLEPASS_JIT=ON -DZEN_ENABLE_BUILTIN_WASI=ON \
  -DZEN_ENABLE_CPU_EXCEPTION=ON -DZEN_ENABLE_SPEC_TEST=ON \
  -DZEN_ENABLE_EVM=OFF -DZEN_ENABLE_ASAN=OFF -DZEN_ENABLE_VIRTUAL_STACK=OFF
cmake --build "$build" --target dtvm -j2

script=docs/changes/2026-11-20-signed-pow2-remainder/benchmark.py
bench=(python3 "$script" --main "$main" --candidate "$candidate"
       --main-aa "$main_copy" --wasmtime "$wt45" --wasm benchmarks/paper/benchmarks/wapm/md5.wasm
       --default-lazy-aa --cpu 0)
"${bench[@]}" --group catalog --candidate-singlepass \
  --cases md5,qr2text,figlet,tpl,viu,atax,bicg,gemver,gesummv,jacobi_1d,mvt,trisolv \
  --rounds 21 --seed 658121 --out local-catalog
"${bench[@]}" --group catalog --omit-singlepass --cases gemm,2mm \
  --long-rounds 5 --warmups 1 --rounds 7 --seed 658122 --out local-large
"${bench[@]}" --group catalog --omit-singlepass --cases 2mm --cpu 1 \
  --long-rounds 7 --warmups 1 --rounds 7 --seed 658167 --out repeat-2mm
"${bench[@]}" --group catalog --candidate-singlepass --cases mvt --cpu 1 \
  --rounds 41 --seed 658131 --out repeat-mvt

python3 benchmarks/paper/harness/run.py --dtvm "$candidate" --wasmtime "$wt45" \
  --cases irb,viu,tpl,md5,qr2text,bicg --dtvm-modes lazy-G-MT,lazy-F-ST \
  --metric both --stats --repeats 7 --cpu 0 --out candidate-phases
```

The two focused verifier tests passed. All seven CTest targets passed with
the spec suite in each of default lazy Multipass, lazy serial FastRA, and
eager Multipass. The repository formatting check passed.
