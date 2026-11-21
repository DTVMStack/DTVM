# Signed power-of-two remainder measurements

Main is `14a7ad5` after #653. The candidate adds the literal signed-remainder
fold in the Wasm multipass frontend. Both binaries use Release O3 with GCC 14,
LLVM 15, singlepass, multipass and WASI. EVM and ASAN are disabled in the local
build. Wasmtime 45 runs Cranelift with the module cache disabled.

One AMD EPYC 9V74 host ran fresh processes pinned to CPU 0 under a 2-CPU
quota. Each cohort excludes two warmups and randomizes variant order within
each round. A/A repeats the main FastRA command using the same binary and
inode. Times are process wall-clock milliseconds, including loading, compile,
execution and exit. Ratios are medians of paired per-round ratios. The
pointwise 95% bootstrap intervals and the exploratory selection of cases limit
claims about small changes. No builds, capture or tests ran during timing.

## Target kernels

Clang/LLD 16 compiled C into Wasm with a signed remainder inside a varying
32-bit bucket accumulation and a dependent 64-bit recurrence. The source
of bucket64 uses a negative divisor, which Clang normalizes to positive in
the Wasm. The WAST tests independently exercise negative literal divisors.
The non-power-of-two divisor 1009 and zero-iteration caller are controls.
The Python oracle checks every output. These constructed kernels isolate
the mechanism and do not estimate application-wide speedup.

## Initial seed 123

| Case | Rounds | main singlepass | main lazy F | PR lazy F | main default lazy | PR default lazy | WT45 | F PR/main [95% CI] | Default PR/main [95% CI] |
|---|---:|---:|---:|---:|---:|---:|---:|---|---|
| bucket32/8000000 | 31 | 21.80 | 25.79 | 20.51 | 26.68 | 21.97 | 21.61 | 0.817 [0.764, 0.845] | 0.826 [0.796, 0.859] |
| bucket64/8000000 | 31 | 47.19 | 48.44 | 30.47 | 50.65 | 32.07 | 32.48 | 0.631 [0.624, 0.656] | 0.644 [0.615, 0.651] |
| bucket32_other/8000000 | 31 | 20.68 | 25.34 | 25.29 | 27.16 | 26.49 | 25.49 | 0.986 [0.935, 1.021] | 0.950 [0.932, 1.035] |
| bucket32/0 | 31 | 5.10 | 6.22 | 6.40 | 6.56 | 6.93 | 7.77 | 1.014 [0.975, 1.066] | 0.965 [0.903, 1.052] |

## Independent input seed 987654321

| Case | Rounds | main singlepass | main lazy F | PR lazy F | main default lazy | PR default lazy | WT45 | F PR/main [95% CI] | Default PR/main [95% CI] |
|---|---:|---:|---:|---:|---:|---:|---:|---|---|
| bucket32/8000000 | 31 | 20.72 | 23.95 | 19.02 | 25.82 | 20.75 | 20.85 | 0.803 [0.776, 0.814] | 0.806 [0.792, 0.829] |
| bucket64/8000000 | 31 | 43.69 | 45.38 | 28.05 | 46.47 | 29.00 | 30.19 | 0.622 [0.608, 0.632] | 0.626 [0.613, 0.638] |
| bucket32_other/8000000 | 31 | 20.51 | 23.80 | 23.53 | 25.17 | 24.86 | 23.96 | 0.976 [0.967, 1.004] | 0.985 [0.964, 1.006] |
| bucket32/0 | 31 | 5.19 | 6.23 | 6.32 | 5.63 | 5.63 | 7.89 | 1.088 [0.942, 1.135] | 1.021 [0.960, 1.102] |

## Catalog screen

| Case | Rounds | main singlepass | main lazy F | PR lazy F | main default lazy | PR default lazy | WT45 | F PR/main [95% CI] | Default PR/main [95% CI] |
|---|---:|---:|---:|---:|---:|---:|---:|---|---|
| base64cli | 7 | 24.09 | 104.03 | 107.09 | 103.79 | 105.16 | 489.32 | 1.032 [1.005, 1.138] | 1.018 [0.967, 1.034] |
| chkfont | 7 | 9.03 | 39.25 | 41.31 | 45.60 | 41.25 | 83.98 | 0.920 [0.893, 1.091] | 0.848 [0.724, 1.049] |
| code-stock | 7 | 9.40 | 21.64 | 20.13 | 25.25 | 24.06 | 88.19 | 0.963 [0.935, 1.021] | 1.049 [0.952, 1.108] |
| cowsay | 7 | 18.98 | 111.35 | 110.47 | 111.52 | 110.74 | 405.83 | 0.992 [0.970, 1.064] | 1.006 [0.909, 1.030] |
| echo | 7 | 8.37 | 24.24 | 25.09 | 26.33 | 26.83 | 38.78 | 1.084 [0.963, 1.280] | 1.029 [0.982, 1.208] |
| erdtree | 7 | 11.79 | 50.59 | 49.20 | 52.56 | 51.59 | 153.04 | 0.976 [0.955, 0.987] | 0.997 [0.937, 1.004] |
| figlet | 7 | 10.55 | 47.47 | 48.66 | 52.17 | 51.35 | 111.29 | 1.014 [0.996, 1.062] | 0.962 [0.932, 1.115] |
| fortune | 7 | 14.36 | 58.66 | 59.75 | 65.11 | 60.60 | 125.70 | 1.016 [0.971, 1.044] | 0.978 [0.931, 0.994] |
| md5 | 7 | 7.25 | 24.10 | 24.22 | 27.41 | 26.08 | 41.91 | 0.978 [0.905, 1.000] | 0.990 [0.932, 1.020] |
| pi | 7 | 7.42 | 24.32 | 23.02 | 26.78 | 24.77 | 38.88 | 0.968 [0.912, 1.028] | 0.917 [0.788, 1.002] |
| pkg1 | 7 | 9.68 | 23.55 | 22.90 | 24.33 | 25.18 | 93.54 | 0.968 [0.832, 1.069] | 0.992 [0.982, 1.087] |
| qr2text | 7 | 11.29 | 45.88 | 44.89 | 49.01 | 48.32 | 122.67 | 1.018 [0.977, 1.049] | 0.974 [0.919, 1.011] |
| suggest | 7 | 22.47 | 92.86 | 93.83 | 98.31 | 93.62 | 457.22 | 0.973 [0.945, 1.126] | 0.983 [0.920, 1.007] |
| tpl | 7 | 104.14 | 250.31 | 238.68 | 247.62 | 263.62 | 783.84 | 0.924 [0.906, 0.982] | 1.015 [0.928, 1.232] |
| atax | 7 | 85.82 | 64.53 | 67.01 | 51.86 | 52.98 | 65.94 | 1.039 [1.019, 1.127] | 1.028 [1.013, 1.123] |
| bicg | 7 | 87.08 | 67.95 | 62.05 | 63.81 | 61.66 | 76.43 | 0.906 [0.894, 0.985] | 0.982 [0.899, 1.064] |
| gemver | 7 | 191.03 | 106.06 | 99.79 | 73.80 | 71.00 | 83.58 | 0.976 [0.852, 0.998] | 1.002 [0.910, 1.043] |
| gesummv | 7 | 68.05 | 52.85 | 53.31 | 53.96 | 56.51 | 68.05 | 1.009 [0.939, 1.044] | 1.047 [0.976, 1.095] |
| jacobi_1d | 7 | 27.71 | 32.29 | 34.43 | 33.31 | 32.93 | 46.57 | 0.995 [0.982, 1.092] | 0.972 [0.945, 1.129] |
| mvt | 7 | 113.68 | 91.62 | 94.00 | 67.77 | 67.99 | 83.39 | 1.066 [0.984, 1.142] | 0.998 [0.850, 1.099] |
| trisolv | 7 | 53.55 | 54.64 | 52.27 | 47.46 | 50.27 | 58.54 | 0.882 [0.807, 0.947] | 1.113 [1.041, 1.197] |
| gemm | 3 | 13359.00 | 2519.98 | 2585.90 | 1661.72 | 1647.05 | 2182.66 | 1.006 [1.001, 1.026] | 1.037 [0.960, 1.079] |
| 2mm | 3 | 13566.10 | 7404.44 | 7701.63 | 2178.63 | 2271.69 | 2771.96 | 1.080 [1.028, 1.083] | 1.001 [0.990, 1.043] |

## Catalog confirmation

| Case | Rounds | main singlepass | main lazy F | PR lazy F | main default lazy | PR default lazy | WT45 | F PR/main [95% CI] | Default PR/main [95% CI] |
|---|---:|---:|---:|---:|---:|---:|---:|---|---|
| base64cli | 31 | 24.50 | 104.60 | 106.16 | 108.67 | 107.49 | 471.42 | 1.008 [0.983, 1.040] | 0.990 [0.949, 1.025] |
| code-stock | 31 | 9.15 | 21.70 | 20.77 | 23.51 | 23.00 | 90.76 | 0.960 [0.927, 0.982] | 0.964 [0.945, 1.026] |
| echo | 31 | 7.29 | 23.65 | 23.15 | 25.00 | 24.12 | 39.05 | 0.973 [0.929, 1.017] | 0.978 [0.944, 1.005] |
| qr2text | 31 | 10.49 | 45.71 | 45.38 | 49.39 | 48.79 | 123.79 | 0.980 [0.955, 1.002] | 0.982 [0.959, 1.002] |
| atax | 31 | 84.16 | 64.83 | 63.25 | 52.82 | 51.12 | 61.88 | 0.978 [0.958, 0.993] | 0.982 [0.974, 1.004] |
| gesummv | 31 | 64.62 | 48.58 | 49.13 | 52.10 | 51.88 | 60.47 | 1.006 [0.947, 1.030] | 0.995 [0.969, 1.039] |
| mvt | 31 | 101.14 | 81.28 | 81.80 | 59.42 | 58.18 | 69.34 | 1.000 [0.978, 1.026] | 0.990 [0.954, 1.016] |
| trisolv | 31 | 45.73 | 44.36 | 43.82 | 41.49 | 41.40 | 53.23 | 0.986 [0.973, 0.993] | 0.997 [0.968, 1.017] |

## 2mm confirmation

| Case | Rounds | main singlepass | main lazy F | PR lazy F | main default lazy | PR default lazy | WT45 | F PR/main [95% CI] | Default PR/main [95% CI] |
|---|---:|---:|---:|---:|---:|---:|---:|---|---|
| 2mm | 5 | — | 7628.54 | 7549.78 | 2281.07 | 2298.43 | 2852.39 | 1.000 [0.964, 1.010] | 1.008 [0.967, 1.090] |


The catalog tests use the repo's existing Wasm, commands, arguments and
working directories. All selected engines exited successfully. The harness
compares output hashes across variants for PolyBench and deterministic
base64cli, echo, md5 and qr2text. For other WAPM cases it retains hashes
and checks exits. The three-round long cases and renewed measurement windows
are documented in the manifests. The 2mm confirmation ran one excluded
warmup and five measured rounds without singlepass. A static adjacent-instruction search found
candidate signed remainders in qr2text, irb and zuk. An adjacent literal does
not establish that the corresponding path executes during a benchmark.

The independent eight-case confirmation did not repeat a slowdown in FastRA,
default lazy, or singlepass. The five-round 2mm repeat gave a FastRA ratio of
1.000 [0.964, 1.010] and a default lazy ratio of 1.008 [0.967, 1.090]. The initial
FastRA screen ratio of 1.080 did not repeat. Sample bounds remain wide on short
cold controls and the long-case repeats, so the measurements give no universal
non-regression margin.

## Native code and validation

Separate untimed builds captured the lazy FastRA native text. The baseline
emits IDIV in each target loop. The candidate uses arithmetic and masking.
Wasmtime 45 already avoids IDIV on those targets in its AOT disassembly.
The non-power-of-two control is recorded alongside them.
Both target functions shrink from 170 to 137 bytes and lose their IDIV. The
native summary records byte comparison of every 2mm function captured under
the same lazy FastRA configuration. Of 35 functions, 23 are byte-identical.
The other 12 differ only in large absolute-address MOV immediates. Their
instructions, registers and lengths match after normalizing those addresses.

23 WAST assertions passed under main FastRA, candidate lazy FastRA, candidate
default lazy, candidate eager Greedy, and Wasmtime 45. Another 1,296 candidate
executions in FastRA and Greedy passed a Python signed integer oracle. These
cover the most negative dividend and divisor, signed remainder direction,
a dynamic zero divisor and discarded results with trapping operands.

## Reproduction

Run from the repository root with Clang/LLD 16, Wasmtime 45 and both DTVM builds.

```sh
mkdir -p /tmp/signed-rem
clang --target=wasm32 -O2 -ffreestanding -fno-unroll-loops -c docs/changes/2026-11-20-signed-pow2-remainder/signed_buckets.c -o /tmp/signed-rem/buckets.o
wasm-ld --no-entry --export=bucket32 --export=bucket64 --export=bucket32_other /tmp/signed-rem/buckets.o -o /tmp/signed-rem/buckets.wasm
python3 docs/changes/2026-11-20-signed-pow2-remainder/benchmark.py \
  --main /path/main --candidate /path/candidate --wasmtime /path/wasmtime45 \
  --wasm /tmp/signed-rem/buckets.wasm --group kernel --rounds 31 --seed 6552010 \
  --out /tmp/signed-rem/result
```

The seed, exact engine commands, raw measurements and input hashes for every
cohort are in [evidence](evidence/).
