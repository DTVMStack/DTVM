# Singlepass process-time recheck

The earlier `qr2text` Singlepass wall-time difference was much larger than
the differences in measured JIT compilation and execution. The previous
CLI `--help` control also showed a difference before any Wasm was loaded.
This follow-up uses main `5d566d2` and the same Multipass code as `ed60014`.

## Diagnosis

- **Executable copies.** Separate files with the same `dtvm` basename and
  equal-length paths were checked byte for byte. With inherited CPU affinity,
  the candidate copies had `qr2text` ratios of 0.970–0.984 on CPU 0 and
  0.985–0.991 on CPU 1 against the first main copy. A byte-identical second
  main copy measured 3.9% slower for `--help` on CPU 0 and 4.0% slower on CPU 1.
  Repeating the same executable path as A/A missed this source of variation.
  In a separate two-cohort test, four identical-length paths were hard-linked
  to the two main files, then switched to the other file between cohorts.
  The faster launches tracked the file across the switch. Which file was
  faster differed from the earlier cohorts. The underlying OS or hardware
  cause remains undetermined.
- **Launcher.** With the same copies and randomized order, the `qr2text`
  slowdown did not recur under either a pinned or an unpinned parent using
  the old `taskset` wrapper. The wrapper added process work to every timed
  launch. The retest pins the benchmark process once and measures direct
  launches with inherited affinity. Old and new absolute wall times have
  different boundaries.
- **Link placement.** The original trial shifted `main` and `_start` by 64
  bytes. Three diagnostic relinks of the same main object files reproduce
  that shift and test offsets of 128 and 256 bytes. Their timings vary along
  with the unchanged executable copy. This provides no evidence that the
  64-byte shift causes the earlier slowdown.

| Executable | `--help` (ms) | `qr2text` Singlepass (ms) |
|---|---:|---:|
| `main-rebuilt-0` | 4.289 | 9.850 |
| `main-copy` | 4.034 | 9.603 |
| `main-shift64` | 3.993 | 9.435 |
| `main-shift128` | 4.032 | 9.677 |
| `main-shift256` | 3.967 | 9.456 |
| `candidate` | 4.056 | 9.181 |

The updated benchmark validates the SHA-256 of the main A/A copy and records
its path and hash. Catalog and kernel results below use the fixed runner.
Times are fresh-process wall medians in milliseconds. Ratios and bootstrap
intervals use within-round measurements. The compiler lowering uses the
same source as the prior experiment.

## Local retest

### Singlepass controls, 61 rounds

| Case | Main | Trial | Wasmtime 45 | Trial/Main | Main copy | Copy/Main |
|---|---:|---:|---:|---:|---:|---:|
| `qr2text` | 10.09 | 9.66 | 123.50 | 0.970 [0.946, 0.988] | 9.76 | 0.985 [0.949, 1.030] |
| `gesummv` | 60.53 | 60.82 | 58.59 | 1.001 [0.981, 1.009] | 60.61 | 1.005 [0.984, 1.012] |
| `atax` | 84.54 | 84.60 | 62.53 | 1.002 [0.993, 1.014] | 84.63 | 1.000 [0.976, 1.021] |
| `bicg` | 82.22 | 81.56 | 70.53 | 0.990 [0.979, 1.006] | 82.30 | 0.991 [0.977, 1.003] |
| `figlet` | 10.03 | 9.92 | 110.97 | 0.971 [0.934, 1.004] | 9.41 | 0.941 [0.895, 0.985] |
| `md5` | 6.77 | 6.53 | 42.15 | 0.959 [0.901, 1.044] | 6.34 | 0.930 [0.879, 1.056] |

### Default lazy controls, 61 rounds

| Case | Main | Trial | Wasmtime 45 | Trial/Main | Main copy | Copy/Main |
|---|---:|---:|---:|---:|---:|---:|
| `qr2text` | 49.63 | 48.87 | 123.50 | 0.991 [0.979, 1.001] | 49.25 | 0.993 [0.976, 1.009] |
| `gesummv` | 48.67 | 48.35 | 58.59 | 0.998 [0.973, 1.013] | 47.70 | 0.981 [0.959, 1.011] |
| `atax` | 52.93 | 51.43 | 62.53 | 0.977 [0.955, 1.003] | 51.75 | 0.967 [0.958, 0.985] |
| `bicg` | 61.60 | 59.95 | 70.53 | 0.969 [0.949, 0.999] | 60.32 | 0.988 [0.972, 1.003] |
| `figlet` | 50.05 | 49.05 | 110.97 | 0.983 [0.952, 0.995] | 48.03 | 0.969 [0.958, 0.982] |
| `md5` | 27.46 | 26.20 | 42.15 | 0.994 [0.967, 1.009] | 26.05 | 0.979 [0.939, 0.988] |

### Lazy FastRA literal remainder, 41 rounds

| Case | Main | Trial | Wasmtime 45 | Trial/Main | Main copy | Copy/Main |
|---|---:|---:|---:|---:|---:|---:|
| `bucket3/8000000` | 24.87 | 20.68 | 23.36 | 0.844 [0.814, 0.865] | 24.61 | 0.993 [0.977, 1.021] |
| `bucket7/8000000` | 23.59 | 20.14 | 23.75 | 0.854 [0.838, 0.868] | 23.59 | 0.993 [0.983, 1.017] |
| `bucket1009/8000000` | 23.90 | 20.65 | 24.20 | 0.857 [0.834, 0.876] | 23.88 | 0.972 [0.946, 1.003] |
| `bucket1024/8000000` | 19.88 | 19.54 | 20.81 | 0.996 [0.943, 1.016] | 20.05 | 0.989 [0.964, 1.015] |
| `bucket7/0` | 6.20 | 6.04 | 7.46 | 1.002 [0.903, 1.025] | 6.20 | 0.975 [0.906, 1.029] |

### Large PolyBench controls, five rounds

| Case | Main | Trial | Wasmtime 45 | Trial/Main | Main copy | Copy/Main |
|---|---:|---:|---:|---:|---:|---:|
| `gemm` | 2217.46 | 2302.98 | 3057.42 | 1.015 [0.952, 1.077] | 2340.63 | 0.994 [0.970, 1.118] |
| `2mm` | 2927.95 | 2859.97 | 3602.99 | 1.008 [0.870, 1.034] | 2841.02 | 0.983 [0.900, 1.084] |

For the same matrices in FastRA, the trial/main paired ratios were 1.005
for `gemm` and 1.014 for `2mm`. The copy/main ratios were 1.020 and 1.029.
The raw results contain both allocator modes and both A/A comparisons.

## Independent hosted runner

The replay uses equal-name, independently copied executables and the same
inherited-affinity launcher. It rebuilt both Release binaries with GCC 11.4
and LLVM 15 in the same CMake tree. The six input Wasm digests match their
repository versions. [Hosted run and raw artifact](https://github.com/zoowii/DTVM/actions/runs/45193635531)

### Singlepass controls, 61 rounds

| Case | Main | Trial | Wasmtime 45 | Trial/Main | Main copy | Copy/Main |
|---|---:|---:|---:|---:|---:|---:|
| `gesummv` | 53.56 | 53.44 | 52.35 | 0.997 [0.991, 1.004] | 53.29 | 0.996 [0.991, 0.999] |
| `atax` | 72.50 | 72.54 | 58.41 | 1.003 [0.998, 1.007] | 72.54 | 1.000 [0.996, 1.006] |
| `bicg` | 72.18 | 72.08 | 64.96 | 1.003 [0.996, 1.009] | 72.57 | 1.004 [0.992, 1.011] |
| `md5` | 5.33 | 5.15 | 35.68 | 0.972 [0.933, 1.001] | 5.47 | 1.008 [0.976, 1.060] |
| `qr2text` | 8.85 | 8.70 | 100.40 | 1.011 [0.965, 1.051] | 8.85 | 1.031 [0.978, 1.054] |
| `figlet` | 8.55 | 8.66 | 88.42 | 1.002 [0.984, 1.033] | 8.39 | 0.989 [0.942, 1.029] |

### Default lazy controls, 61 rounds

| Case | Main | Trial | Wasmtime 45 | Trial/Main | Main copy | Copy/Main |
|---|---:|---:|---:|---:|---:|---:|
| `gesummv` | 43.15 | 43.09 | 52.35 | 0.996 [0.990, 1.002] | 43.69 | 1.011 [0.995, 1.027] |
| `atax` | 49.02 | 49.54 | 58.41 | 1.002 [0.993, 1.013] | 50.18 | 1.003 [0.988, 1.026] |
| `bicg` | 57.35 | 57.18 | 64.96 | 1.000 [0.989, 1.007] | 56.56 | 0.991 [0.984, 1.004] |
| `md5` | 22.40 | 22.10 | 35.68 | 0.983 [0.973, 0.999] | 22.40 | 0.990 [0.961, 1.029] |
| `qr2text` | 42.05 | 41.98 | 100.40 | 1.010 [0.989, 1.020] | 41.46 | 0.991 [0.976, 1.011] |
| `figlet` | 40.24 | 40.26 | 88.42 | 0.992 [0.977, 1.008] | 40.41 | 1.009 [0.995, 1.024] |

### Lazy FastRA literal remainder, 41 rounds

| Case | Main | Trial | Wasmtime 45 | Trial/Main | Main copy | Copy/Main |
|---|---:|---:|---:|---:|---:|---:|
| `bucket3/8000000` | 18.03 | 15.88 | 21.09 | 0.865 [0.854, 0.881] | 18.02 | 1.011 [0.998, 1.022] |
| `bucket7/8000000` | 17.92 | 16.84 | 20.41 | 0.928 [0.914, 0.950] | 18.06 | 0.999 [0.988, 1.011] |
| `bucket1009/8000000` | 18.01 | 16.42 | 20.17 | 0.906 [0.895, 0.920] | 17.93 | 0.997 [0.975, 1.011] |
| `bucket1024/8000000` | 14.84 | 14.87 | 17.53 | 0.990 [0.983, 1.027] | 14.88 | 1.002 [0.990, 1.017] |
| `bucket7/0` | 4.46 | 4.39 | 7.14 | 1.008 [0.956, 1.031] | 4.52 | 1.019 [0.993, 1.057] |

The hosted `qr2text` Singlepass trial/main interval includes 1.000. Its paired
increase of 1.1% is smaller than the byte-identical main copy's 3.1%. The
default-lazy `gesummv` trial is within the variation of its main copy control.
The shortest `% 7` zero-iteration case still shows a 5.5% paired increase in
hosted default lazy. Main A/A is 3.9% and the intervals overlap. The local
zero-iteration comparison is compatible with no difference. The five-round
long PolyBench controls also have wide intervals.

## Reproduction

Use the Wasm kernel build commands in the [benchmark report](BENCHMARK.md).
Create independent executable files in same-length directories on the same
filesystem. Choose a CPU available to the current process.

```sh
work=$(mktemp -d)
mkdir "$work/a" "$work/b" "$work/c"
cp /path/main-dtvm "$work/a/dtvm"
cp /path/pr-dtvm "$work/b/dtvm"
cp /path/main-dtvm "$work/c/dtvm"
python3 docs/changes/2026-11-20-signed-pow2-remainder/benchmark.py \
  --main "$work/a/dtvm" --candidate "$work/b/dtvm" --main-aa "$work/c/dtvm" \
  --wasmtime /path/wasmtime-45 --wasm /path/buckets.wasm --cpu 0 \
  --default-lazy-aa --candidate-singlepass --group catalog \
  --cases qr2text,gesummv,atax,bicg,figlet,md5 --rounds 61 --seed 6553580 \
  --out "$work/results"
```
