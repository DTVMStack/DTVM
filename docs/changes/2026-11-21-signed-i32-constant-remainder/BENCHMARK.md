# Signed i32 literal remainder experiments

DTVM main is `5d566d2`, the merge of #654. Both DTVM CLI binaries are Release
builds with GCC 14, LLVM 15, Singlepass, Multipass, and WASI. The main binary was
rebuilt from the same tree and matched the saved executable byte for byte.
Wasmtime 45.0.0 uses Cranelift with module caching disabled. Every timing sample
is a fresh process pinned to CPU 0 unless a cohort reports otherwise. Commands,
inputs, binary hashes, and pairing by round are recorded in the raw manifests.

Process medians are in milliseconds. Ratios use the median of within-round
trial/main ratios with a percentile bootstrap interval. Two or three rounds
on long PolyBench cases give a coarse check. They cannot establish a tight
regression bound. The initial mixed catalog screen completed `chkfont`,
`figlet`, `irb`, `qr2text`, and `tpl` before the long remaining cases were split
into separate cohorts. Each reported row uses all scheduled samples for that case.

## Kernel confirmation

Inputs use the same linear congruential recurrence and compare results against
an integer oracle. The first trial takes the correction sign from the
intermediate quotient. The second trial takes it from the dividend, permitting
independent execution of the correction. Clang canonicalized `-1009` in the C
kernel to a positive Wasm literal. Separate WAST tests use negative literals.
The `/0` row compiles the exported function with zero loop iterations.
`bucket1024` exercises the existing power-of-two lowering.

| Case | Rounds | Main FastRA | Trial 1 FastRA | Trial 2 FastRA | Main default lazy | Trial 2 default lazy | Main SP | Trial SP | Wasmtime 45 | FastRA ratio | Default lazy ratio | Trial 2 / Trial 1 FastRA |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `bucket3/8000000` | 31 | 23.10 | 19.48 | 19.54 | 24.41 | 21.67 | 19.09 | 19.49 | 21.46 | 0.865 [0.837, 0.875] | 0.885 [0.866, 0.914] | 1.029 [0.980, 1.041] |
| `bucket7/8000000` | 31 | 23.79 | 19.83 | 20.48 | 25.00 | 22.85 | 19.99 | 20.41 | 24.07 | 0.869 [0.839, 0.888] | 0.905 [0.877, 0.927] | 1.025 [0.986, 1.068] |
| `bucket1009/8000000` | 31 | 23.79 | 20.27 | 20.54 | 25.12 | 22.42 | 20.89 | 20.51 | 24.44 | 0.880 [0.852, 0.913] | 0.905 [0.886, 0.931] | 1.038 [0.999, 1.066] |
| `bucket1024/8000000` | 31 | 18.81 | 19.25 | 18.97 | 20.16 | 20.93 | 19.37 | 19.88 | 19.88 | 1.032 [1.015, 1.055] | 1.020 [1.010, 1.048] | 0.998 [0.985, 1.014] |
| `bucket7/0` | 31 | 5.51 | 5.94 | 5.97 | 5.59 | 6.34 | 4.59 | 4.91 | 7.21 | 1.059 [0.977, 1.150] | 1.120 [1.012, 1.226] | 1.012 [0.959, 1.060] |

## WAPM and PolyBench

| Case | Rounds | Main FastRA | Trial FastRA | Main default lazy | Trial default lazy | Main SP | Trial SP | Wasmtime 45 | FastRA ratio | Default lazy ratio | Singlepass ratio |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `chkfont` | 31 | 37.11 | 37.67 | 37.84 | 38.46 | 8.66 | 8.82 | 77.62 | 1.024 [0.990, 1.055] | 1.009 [0.994, 1.055] | 1.014 [0.998, 1.098] |
| `figlet` | 31 | 45.15 | 44.91 | 46.81 | 47.53 | 9.56 | 10.20 | 107.00 | 1.002 [0.981, 1.021] | 1.014 [0.989, 1.038] | 1.043 [1.003, 1.088] |
| `qr2text` | 31 | 46.78 | 47.21 | 49.21 | 49.39 | 10.25 | 10.64 | 125.20 | 1.016 [0.992, 1.035] | 1.020 [0.983, 1.038] | 1.025 [1.006, 1.048] |
| `md5` | 31 | 24.96 | 27.19 | 29.50 | 28.92 | 7.49 | 7.29 | 45.42 | 1.048 [1.030, 1.099] | 1.015 [0.973, 1.040] | 1.015 [0.970, 1.048] |
| `echo` | 31 | 22.02 | 23.80 | 25.19 | 25.06 | 6.67 | 6.82 | 36.81 | 1.044 [0.997, 1.108] | 1.029 [0.974, 1.061] | 1.015 [0.972, 1.056] |
| `gemver` | 31 | 93.95 | 92.44 | 68.21 | 67.70 | 174.94 | 175.24 | 77.04 | 0.984 [0.956, 1.004] | 0.986 [0.974, 1.023] | 0.981 [0.965, 1.017] |
| `bicg` | 31 | 65.63 | 63.88 | 64.53 | 66.12 | 84.60 | 85.79 | 74.73 | 0.972 [0.926, 1.007] | 1.031 [0.960, 1.080] | 0.999 [0.989, 1.025] |
| `atax` | 31 | 64.48 | 67.05 | 52.26 | 53.65 | 86.33 | 86.30 | 65.12 | 1.043 [0.992, 1.057] | 1.024 [1.002, 1.056] | 1.001 [0.977, 1.013] |
| `gesummv` | 31 | 46.79 | 47.01 | 47.88 | 50.57 | 62.03 | 61.80 | 59.14 | 1.010 [0.990, 1.035] | 1.064 [1.026, 1.072] | 0.998 [0.980, 1.017] |
| `mvt` | 31 | 83.53 | 84.29 | 59.21 | 58.93 | 101.01 | 102.59 | 71.56 | 1.010 [0.978, 1.038] | 1.006 [0.987, 1.024] | 1.015 [0.996, 1.029] |
| `trisolv` | 31 | 44.16 | 46.34 | 41.39 | 43.57 | 44.76 | 46.22 | 53.72 | 1.043 [1.009, 1.062] | 1.038 [0.985, 1.063] | 1.018 [1.003, 1.045] |
| `jacobi_1d` | 31 | 28.77 | 29.12 | 29.41 | 29.64 | 24.45 | 24.88 | 42.59 | 1.023 [1.004, 1.041] | 1.003 [0.982, 1.030] | 1.005 [0.994, 1.031] |
| `base64cli` | 13 | 101.69 | 103.82 | 103.47 | 106.65 | 23.83 | 23.16 | 483.00 | 1.019 [1.005, 1.044] | 1.018 [0.986, 1.118] | 1.008 [0.931, 1.073] |
| `cowsay` | 13 | 114.67 | 122.42 | 124.99 | 120.26 | 21.02 | 20.32 | 426.44 | 1.048 [0.998, 1.147] | 0.966 [0.893, 1.075] | 0.963 [0.892, 1.048] |
| `tpl` | 13 | 236.58 | 241.87 | 268.74 | 258.99 | 103.45 | 104.55 | 768.08 | 1.015 [0.996, 1.066] | 1.003 [0.953, 1.072] | 1.012 [0.994, 1.070] |
| `irb` | 7 | 3683.98 | 3733.03 | 3704.07 | 3619.34 | 2035.14 | 2154.11 | 10100.38 | 1.009 [0.967, 1.085] | 0.976 [0.943, 1.028] | 1.002 [0.891, 1.119] |

## Long PolyBench controls

| Case | Rounds | Main FastRA | Trial FastRA | Main default lazy | Trial default lazy | Wasmtime 45 | FastRA ratio | Default lazy ratio |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `gemm` | 3 | 2840.64 | 2870.85 | 1593.05 | 2018.97 | 2629.74 | 1.001 [0.885, 1.011] | 1.246 [1.070, 1.508] |
| `2mm` | 3 | 7830.14 | 7541.71 | 2224.80 | 2310.02 | 2878.79 | 0.974 [0.963, 0.992] | 1.038 [0.955, 1.109] |
| `nussinov` | 2 | 8794.23 | 9991.37 | 5759.46 | 5563.39 | 6575.89 | 1.135 [1.070, 1.200] | 0.967 [0.932, 1.002] |

## Assembly and phase timing

A separate diagnostic build toggles the transform within the same executable.
The generated FastRA text for `% 3`, `% 7`, and `% 1009` shrank from 170 bytes
to 144, 149, and 152 bytes respectively. Each shed one `IDIV`. The 137-byte
power-of-two control was unchanged. Wasmtime 45 uses fixed-register `IMUL` to
write the high half directly to EDX. The DTVM trial sign-extends the input,
uses a three-operand widened `IMUL`, and extracts the high half by shifting.
The latter avoids fixed-register constraints on the allocator.

On `% 7`, the same-binary toggle produced an execution ratio of 0.819 and a
foreground-compilation ratio of 1.010. The same-binary zero-iteration
process-wall ratio was 1.001. In separate uninstrumented binaries, the zero
control was slower in some cohorts. Foreground compilation and process wall
cover different boundaries.

`qr2text` compiled 74 functions in both modes and shed five `IDIV` sites. The
median foreground JIT time in the main diagnostic sample was 35.42 ms and the
execution time was 0.78 ms. `figlet` had identical native sizes for all 113
compiled functions. `irb` compiled 1,911 functions and shed eight `IDIV`
sites across five functions. The `nussinov` site is the `% 20` output newline
check immediately before `fputc`.

## Correctness

The new test file contributes 10 WAST assertions. Together with the 28 prior
power-of-two assertions, they passed in the interpreter, Singlepass, all three
Multipass modes, main FastRA, and Wasmtime 45. A fixed-seed differential module
checked 47 divisors and 65,536 inputs per divisor against dynamic signed
remainder. All 3,080,192 comparisons per mode passed in the three Multipass
modes and Wasmtime 45.

## Independent CPU 1 recheck

| Case | Main FastRA | Trial FastRA | Main default lazy | Trial default lazy | Wasmtime 45 | FastRA trial/main | Default lazy trial/main |
|---|---:|---:|---:|---:|---:|---:|---:|
| `md5` | 24.04 | 25.20 | 26.23 | 27.43 | 42.04 | 1.038 [0.996, 1.072] | 1.047 [1.018, 1.079] |
| `gesummv` | 49.69 | 49.77 | 50.26 | 52.16 | 59.67 | 1.025 [0.990, 1.063] | 1.029 [1.006, 1.080] |
| `trisolv` | 48.55 | 48.39 | 44.85 | 45.36 | 56.15 | 0.974 [0.956, 1.007] | 1.019 [0.989, 1.047] |
| `atax` | 64.32 | 63.35 | 51.97 | 52.33 | 62.75 | 0.994 [0.987, 1.030] | 1.007 [0.999, 1.029] |

`gemm` was rechecked on CPU 1 with default lazy mode, seven wall-time rounds,
and statistics enabled. DTVM's documented `Execution` scope is shown
separately from fresh-process wall time. The diagnostic on and off use the
same executable. The main A/A run repeats the same unmodified binary with
identical flags. Wasmtime does not emit these DTVM phase timings.

| Variant | Wall median (ms) | Execution median (ms) | Wall ratio within round |
|---|---:|---:|---:|
| `main` | 1678.59 | 1627.09 | — |
| `main-AA` | 1641.18 | 1593.19 | 1.002 |
| `candidate` | 1637.13 | 1585.27 | 0.981 |
| `off` | 1621.61 | 1569.84 | — |
| `on` | 1629.77 | 1571.69 | 1.008 |
| `WT45` | 2128.99 | — | — |

## Default lazy `gesummv` phase recheck

The same diagnostic executable was run on CPU 1 with the switch on and
off. This cohort uses 31 rounds and the same measurement boundaries as
the `gemm` recheck.

| Variant | Wall median (ms) | Execution median (ms) | Wall ratio within round |
|---|---:|---:|---:|
| `main` | 49.81 | 19.31 | — |
| `main-AA` | 50.63 | 20.23 | 1.000 |
| `candidate` | 50.66 | 19.89 | 1.009 |
| `off` | 51.54 | 20.67 | — |
| `on` | 51.80 | 19.73 | 0.983 |
| `WT45` | 58.48 | — | — |

The `gemm` slowdown in the three-round screen did not recur. The
uninstrumented `gesummv` trial was slower in both regular process
cohorts. `gesummv` has no `i32.rem_s`, and changing the diagnostic
switch did not reproduce a slowdown of that size. The measurements
do not establish the cause of the process-level difference.

## Reproduction

Build DTVM from `5d566d2` and from the PR with the same compiler and CMake
flags. The commands below assume both builds include Multipass and
Singlepass. Use an available pinned CPU for both runs.

```sh
change=docs/changes/2026-11-21-signed-i32-constant-remainder
bench=docs/changes/2026-11-20-signed-pow2-remainder/benchmark.py
work=$(mktemp -d)
clang --target=wasm32 -O2 -ffreestanding -fno-unroll-loops -c "$change/signed_buckets.c" -o "$work/buckets.o"
wasm-ld --no-entry --export=bucket3 --export=bucket7 --export=bucket1009 --export=bucket1024 "$work/buckets.o" -o "$work/buckets.wasm"
python3 "$bench" --main /path/main-dtvm --candidate /path/pr-dtvm \
  --wasmtime /path/wasmtime-45 --wasm "$work/buckets.wasm" \
  --group kernel --signed-i32-kernels --default-lazy-aa --candidate-singlepass \
  --rounds 31 --seed 6553031 --input-seed 463 --out "$work/kernel"
python3 "$bench" --main /path/main-dtvm --candidate /path/pr-dtvm \
  --wasmtime /path/wasmtime-45 --wasm "$work/buckets.wasm" \
  --group catalog --cases gesummv,atax,bicg,md5,qr2text,figlet \
  --default-lazy-aa --candidate-singlepass --rounds 41 --seed 6553410 \
  --out "$work/catalog"
```

## Follow-up for the reviewed change

The main A/A column repeats the same main executable and flags in each
randomized round. Both catalog cohorts use 41 rounds and bypass the Wasmtime
cache. DTVM's Singlepass runs are available in the raw summaries. Times are
fresh-process wall medians in milliseconds.

### Original host with a default-lazy A/A control

| Case | Main default lazy | Main A/A | Trial default lazy | Wasmtime 45 | Trial/Main | A/A/Main |
|---|---:|---:|---:|---:|---:|---:|
| `gesummv` | 51.69 | 50.77 | 52.56 | 62.77 | 0.997 [0.969, 1.031] | 0.978 [0.940, 1.006] |
| `md5` | 27.16 | 27.13 | 27.11 | 43.24 | 1.005 [0.967, 1.041] | 0.984 [0.949, 1.011] |
| `figlet` | 50.58 | 49.85 | 51.05 | 113.12 | 0.999 [0.958, 1.028] | 0.962 [0.926, 1.018] |
| `qr2text` | 48.27 | 47.45 | 48.90 | 121.35 | 1.010 [0.976, 1.039] | 0.992 [0.955, 1.013] |
| `atax` | 52.71 | 53.26 | 54.04 | 63.67 | 1.032 [1.000, 1.089] | 1.007 [0.988, 1.026] |
| `bicg` | 62.72 | 62.74 | 63.98 | 75.04 | 1.028 [0.999, 1.091] | 1.013 [0.989, 1.033] |

### Independent GitHub runner

The independent Ubuntu 24.04 GitHub runner used the DTVM development image
with GCC 11.4.0 and LLVM 15. It rebuilt both uninstrumented Release binaries
in the same CMake tree and used the verified Wasmtime 45.0.0 release archive.
The run log records the tables below. The uploaded artifact contains the
runner details, manifests and sample data. [Run and artifact](https://github.com/zoowii/DTVM/actions/runs/45184220749)

| Case | Main default lazy | Main A/A | Trial default lazy | Wasmtime 45 | Trial/Main | A/A/Main |
|---|---:|---:|---:|---:|---:|---:|
| `gesummv` | 37.02 | 36.94 | 37.43 | 47.22 | 1.008 [0.997, 1.017] | 0.998 [0.992, 1.013] |
| `atax` | 41.56 | 41.78 | 42.13 | 51.99 | 1.003 [0.990, 1.020] | 1.000 [0.984, 1.016] |
| `bicg` | 48.78 | 49.16 | 48.32 | 58.10 | 0.990 [0.980, 1.007] | 1.005 [0.994, 1.024] |
| `md5` | 20.98 | 20.94 | 20.40 | 33.46 | 0.998 [0.972, 1.013] | 0.984 [0.951, 1.018] |
| `qr2text` | 39.01 | 40.08 | 40.59 | 96.38 | 1.022 [1.002, 1.153] | 1.021 [0.982, 1.038] |
| `figlet` | 38.23 | 38.60 | 37.85 | 84.49 | 1.009 [0.964, 1.034] | 1.009 [0.995, 1.021] |

The same runner measured the kernel with 31 rounds per case.

| Case | Main FastRA | Trial FastRA | Main default lazy | Trial default lazy | Wasmtime 45 | FastRA Trial/Main | Default lazy Trial/Main |
|---|---:|---:|---:|---:|---:|---:|---:|
| `bucket3/8000000` | 16.72 | 14.48 | 18.81 | 15.82 | 19.27 | 0.853 [0.807, 0.869] | 0.842 [0.822, 0.860] |
| `bucket7/8000000` | 16.29 | 14.76 | 18.31 | 16.69 | 18.29 | 0.901 [0.879, 0.932] | 0.892 [0.861, 0.928] |
| `bucket1009/8000000` | 16.74 | 15.35 | 18.53 | 17.51 | 18.65 | 0.904 [0.840, 0.923] | 0.903 [0.884, 0.944] |
| `bucket1024/8000000` | 13.55 | 13.32 | 15.21 | 15.29 | 15.80 | 1.012 [0.982, 1.024] | 1.007 [0.970, 1.020] |
| `bucket7/0` | 3.20 | 3.36 | 3.49 | 3.57 | 5.12 | 1.016 [0.980, 1.039] | 1.005 [0.976, 1.080] |

The earlier default-lazy `gesummv` slowdown did not recur. The paired
trial/main ratio was 0.997 on the original host and 1.008 on the independent
runner. The corresponding main A/A ratios were 0.978 and 0.998. On that
runner, the paired default-lazy `qr2text` ratios were 1.022 for the trial
and 1.021 for main A/A. The three target kernels improved by 9.6%–14.7% with
FastRA and 9.7%–15.8% with default lazy.

### Singlepass and CLI process controls

A separate 81-round local check used the same two uninstrumented executables,
repeated main A/A, and added phase timing for Singlepass. The independent
runner measured a paired `qr2text` Singlepass ratio of 1.051. The local phase
check reproduced a wall-time difference, with a much smaller change in the
measured compilation and execution sections. The CLI `--help` control
showed a difference without loading any Wasm. These data leave a process
startup effect unresolved and do not identify a Singlepass codegen change.

| Case | Main wall (ms) | Main A/A (ms) | Trial wall (ms) | Wasmtime 45 wall (ms) | Trial/Main | A/A/Main |
|---|---:|---:|---:|---:|---:|---:|
| `qr2text` | 10.66 | 10.59 | 11.17 | 128.77 | 1.060 [1.042, 1.076] | 0.995 [0.960, 1.045] |
| `md5` | 7.70 | 7.75 | 8.02 | 46.21 | 1.030 [0.992, 1.082] | 0.976 [0.952, 1.057] |
| `--help` | 5.01 | 5.08 | 5.70 | 4.76 | 1.096 [1.064, 1.128] | 1.004 [0.966, 1.056] |

For `qr2text`, the main and trial Singlepass compilation medians were 3.053
and 3.116 ms. The execution medians were 0.641 and 0.645 ms. In a separate
fixed-argument, direct-spawn `--help` check with streams redirected to
`/dev/null`, wall medians were 3.465 ms for main, 3.385 ms for main A/A, and
3.567 ms for the trial. Dynamic loader startup medians were 461,320 and
463,460 cycles in the separate loader instrumentation for main and trial.
These timings use different process and instrumentation boundaries.

The [subsequent regression analysis](REGRESSION.md) repeats the short-process
measurements with an independent executable copy for main A/A, inherited CPU
affinity, and direct process launches on both hosts.
