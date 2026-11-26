# WASI entry scheduling benchmark

The Wasm runtime baseline is upstream `5c93255` (#663). The branch
was rebased over `6afa74f` (#651), which changes EVM source and docs.
EVM was disabled in the timing build. DTVM was built in Release with GCC
14.2 and LLVM 15.0.6 on AMD EPYC 9V74. The comparator binaries are the
official Linux x86-64 Wasmtime 45.0.0 and 51.0.0 builds. The timed
candidate predates the rebase and the declaration's access-control and
comment edits. Its executable compiler changes match the branch.

Each case uses the original paper Wasm and catalog inputs. CLI process wall
time includes startup, compilation, execution and shutdown. One warmup per
engine is discarded. Each round shuffles variant order. A one-core affinity
mask is used unless the cohort specifies two cores. The compilation cache is
disabled. Wasmtime 51 enables Preview 0 for modules that import `wasi_unstable`.
Every timed process checks guest stdout, stderr and exit status.

Times are per-variant medians in milliseconds. Changes are medians of
paired ratios with pointwise bootstrap 95% intervals. A/A compares two
labels of the same baseline executable in each round. Three-round
controls are regression screens with limited precision.

The paper inputs for `code-stock` and `ludcmp` each export three internal
functions, so their entries still follow the background compilation path.
The `dice` and `tpl` entries exceed the size cutoff.


## Lazy confirmation

41 measured rounds per case.

| Case | DTVM main | Candidate | 45 Cranelift | 45 Winch | 51 Cranelift | Candidate change | Main A/A |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| md5 | 21.01 | 19.70 | 37.36 | 10.99 | 39.63 | -7.30% [-8.47%, -6.35%] | +1.09% [-0.18%, +3.25%] |
| echo | 20.39 | 18.71 | 33.37 | 10.59 | 34.47 | -8.62% [-10.59%, -6.79%] | +1.51% [-1.18%, +2.94%] |
| figlet | 39.18 | 37.86 | 96.58 | 20.41 | 101.19 | -4.23% [-5.22%, -3.08%] | -0.51% [-1.35%, +1.28%] |
| qr2text | 41.40 | 40.54 | 114.06 | 31.15 | 120.44 | -0.51% [-1.62%, +0.59%] | -0.51% [-1.36%, +1.50%] |
| base64cli | 88.48 | 87.90 | 444.33 | 87.64 | 463.60 | -0.76% [-1.43%, +0.48%] | -0.49% [-1.15%, +0.07%] |
| bicg | 55.05 | 53.83 | 67.04 | 58.58 | 66.83 | -2.31% [-3.95%, -1.72%] | -1.19% [-2.05%, +2.75%] |
| atax | 46.63 | 46.06 | 57.89 | 60.71 | 58.46 | -1.69% [-3.44%, -0.71%] | +0.61% [-0.82%, +1.13%] |

## Lazy WAPM controls

9 measured rounds per case.

| Case | DTVM main | Candidate | 45 Cranelift | 45 Winch | 51 Cranelift | Candidate change | Main A/A |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| chkfont | 33.61 | 32.02 | 72.28 | 16.68 | 74.04 | -2.98% [-59.51%, +1.61%] | -1.12% [-44.10%, +7.32%] |
| code-stock | 18.64 | 19.37 | 81.13 | 26.30 | 85.28 | +1.41% [-3.46%, +7.29%] | -4.21% [-5.29%, +0.43%] |
| cowsay | 94.62 | 95.28 | 376.05 | 79.20 | 402.54 | -0.09% [-1.52%, +1.93%] | +1.55% [-0.38%, +3.01%] |
| dice | 16.44 | 16.37 | 32.14 | 11.87 | 33.64 | -1.15% [-3.02%, +1.66%] | -0.71% [-9.42%, +4.31%] |
| suggest | 78.30 | 73.48 | 388.21 | 75.43 | 412.12 | -0.91% [-11.72%, +1.44%] | -1.10% [-9.96%, -0.31%] |
| pi | 20.83 | 19.58 | 36.58 | 10.82 | 37.06 | -6.41% [-8.85%, +0.55%] | -0.18% [-1.25%, +3.13%] |
| tpl | 227.90 | 220.34 | 730.90 | 243.80 | 771.28 | -1.37% [-7.74%, +0.07%] | +1.57% [-6.50%, +19.95%] |
| viu | 182.82 | 182.25 | 1231.60 | 215.32 | 1216.84 | -0.32% [-24.14%, +1.05%] | +0.21% [-23.43%, +3.36%] |

## Lazy PolyBench controls

3 measured rounds per case.

| Case | DTVM main | Candidate | 45 Cranelift | 45 Winch | 51 Cranelift | Candidate change | Main A/A |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| syr2k | 3413.03 | 3206.04 | 4176.87 | 6563.66 | 4360.78 | -3.57% [-7.60%, -1.62%] | -1.22% [-6.16%, -0.70%] |
| 3mm | 3836.30 | 3648.64 | 4231.89 | 12522.16 | 4249.68 | -4.01% [-4.89%, -3.47%] | -2.03% [-3.84%, +0.89%] |

## Lazy ludcmp control

3 measured rounds per case.

| Case | DTVM main | Candidate | 45 Cranelift | 45 Winch | 51 Cranelift | Candidate change | Main A/A |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| ludcmp | 11589.88 | 12085.61 | 12036.93 | 29682.84 | 11633.29 | +1.67% [-0.26%, +5.40%] | +0.08% [-3.72%, +3.00%] |

## Singlepass controls

9 measured rounds per case.

| Case | DTVM main | Candidate | 45 Cranelift | 45 Winch | 51 Cranelift | Candidate change | Main A/A |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| md5 | 5.72 | 6.28 | 38.85 | 11.99 | 39.78 | +5.13% [-20.67%, +17.32%] | -6.66% [-17.81%, +22.10%] |
| echo | 6.08 | 6.07 | 34.82 | 10.82 | 35.91 | -1.70% [-5.21%, +319.54%] | -0.38% [-25.03%, +28.47%] |
| bicg | 79.18 | 76.40 | 68.90 | 61.68 | 69.97 | -3.59% [-8.24%, -0.28%] | -0.95% [-2.61%, +2.72%] |
| atax | 79.68 | 79.09 | 58.11 | 59.60 | 59.87 | -1.36% [-2.01%, +1.29%] | +0.38% [-2.82%, +9.25%] |

## Serial Lazy FastRA controls

9 measured rounds per case.

| Case | DTVM main | Candidate | 45 Cranelift | 45 Winch | 51 Cranelift | Candidate change | Main A/A |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| md5 | 20.27 | 19.03 | 37.76 | 11.09 | 39.42 | -6.52% [-8.54%, -0.51%] | +0.54% [-5.55%, +3.63%] |
| echo | 19.13 | 19.00 | 33.58 | 10.64 | 34.83 | -2.15% [-8.21%, +2.88%] | +5.48% [-5.22%, +7.92%] |
| bicg | 54.93 | 54.89 | 67.55 | 58.77 | 70.10 | +2.50% [-1.56%, +6.65%] | -0.91% [-4.30%, +6.35%] |
| atax | 60.74 | 57.10 | 59.62 | 61.90 | 60.19 | -4.80% [-27.10%, +1.44%] | -4.50% [-22.57%, +0.70%] |

## Eager Multipass controls

9 measured rounds per case.

| Case | DTVM main | Candidate | 45 Cranelift | 45 Winch | 51 Cranelift | Candidate change | Main A/A |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| md5 | 94.21 | 94.06 | 37.92 | 11.39 | 40.02 | -0.71% [-3.23%, +0.64%] | +1.55% [-1.96%, +12.93%] |
| echo | 85.17 | 85.14 | 34.42 | 10.83 | 34.95 | +1.39% [-5.43%, +7.40%] | -1.76% [-4.21%, +1.58%] |
| bicg | 118.88 | 122.22 | 67.18 | 58.16 | 68.48 | -0.37% [-2.04%, +5.92%] | -0.78% [-3.27%, +1.16%] |
| atax | 106.69 | 107.17 | 57.55 | 59.21 | 57.70 | -1.42% [-19.68%, +2.44%] | +0.05% [-12.60%, +5.87%] |

## Lazy WAPM repeat

41 measured rounds per case.

| Case | DTVM main | Candidate | 45 Cranelift | 45 Winch | 51 Cranelift | Candidate change | Main A/A |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| code-stock | 17.70 | 17.73 | 80.00 | 25.45 | 83.60 | +0.96% [-2.31%, +3.22%] | -0.53% [-1.47%, +2.55%] |

## Serial Lazy FastRA repeat

31 measured rounds per case.

| Case | DTVM main | Candidate | 45 Cranelift | 45 Winch | 51 Cranelift | Candidate change | Main A/A |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| md5 | 18.87 | 18.68 | 36.48 | 10.50 | 37.95 | -1.28% [-3.37%, +1.54%] | -0.81% [-3.25%, +1.83%] |
| bicg | 54.84 | 53.38 | 67.51 | 58.77 | 67.03 | -1.05% [-2.09%, +0.57%] | -0.90% [-1.75%, -0.14%] |

## Lazy ludcmp repeat

5 measured rounds per case.

| Case | DTVM main | Candidate | 45 Cranelift | 45 Winch | 51 Cranelift | Candidate change | Main A/A |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| ludcmp | 11026.54 | 11041.74 | 11259.35 | 28654.55 | 11121.65 | -0.08% [-1.46%, +2.60%] | +1.08% [-3.78%, +3.99%] |

## Lazy confirmation with two-core affinity

41 measured rounds per case.

| Case | DTVM main | Candidate | 45 Cranelift | 45 Winch | 51 Cranelift | Candidate change | Main A/A |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| md5 | 19.84 | 19.81 | 24.60 | 7.75 | 24.46 | +1.16% [-0.66%, +3.12%] | -0.46% [-3.71%, +1.07%] |
| echo | 19.04 | 18.66 | 22.54 | 7.32 | 23.41 | -1.92% [-6.65%, -0.31%] | +0.37% [-0.84%, +2.72%] |
| figlet | 38.82 | 38.61 | 52.82 | 13.64 | 55.93 | +0.10% [-2.34%, +1.15%] | -0.33% [-0.76%, +0.55%] |

The one-core measurements confirm a startup improvement for `md5`, `echo`
and `figlet`. With two cores, `echo` shows a smaller improvement and the
intervals for `md5` and `figlet` cross zero. Winch remains faster on all three.
The repeat intervals for `code-stock`, `ludcmp` and the serial Lazy FastRA
cases cross zero. The large PolyBench controls have too few rounds to
establish a kernel speedup.


## Separate compiler statistics

Eleven randomized pairs with `--enable-statistics`. Foreground and background
timers can overlap. These clocks are collected separately from process wall time.

| Case | Foreground compiles | Background compiles | Foreground compile ms | Background compile ms |
| --- | ---: | ---: | ---: | ---: |
| md5 | 31 → 31 | 1 → 0 | 15.756 → 14.711 | 1.433 → 0.000 |
| echo | 30 → 30 | 1 → 0 | 14.774 → 13.812 | 1.426 → 0.000 |
| figlet | 113 → 113 | 1 → 0 | 31.443 → 30.771 | 0.681 → 0.000 |
| bicg | 35 → 35 | 1 → 0 | 18.006 → 17.142 | 0.771 → 0.000 |
| atax | 35 → 35 | 1 → 0 | 17.930 → 17.206 | 0.765 → 0.000 |

With two cores, the background compile count also fell from one to zero
for these five inputs. Foreground compile time rose by 0.529 ms for `md5`
and 0.317 ms for `echo`. Background work can overlap with the foreground on
two cores, which limits the wall-time benefit of removing the duplicate work.

The prototype skipped the entry queue while retaining the default foreground
choice. It improved `md5` by 7.00% and `echo` by 8.17% in a 31-round pilot.
An independently tested ELF symbol-scan bypass did not show this gain.
The release implementation uses the configured allocator for the deferred
entry, preserving the existing Greedy code generation for its argument loops.

## Code generation experiments

Combining 32-bit address addition through `lea` with spill-reload sinking
reduced the native BiCG loop from 22 instructions to 19 and SYR2K from 23
to 20. Their Wasmtime 51 Cranelift equivalents contain 21 and 19
instructions. The paired SYR2K process change was -1.45% [-6.23%, +2.88%].
Adding VEX scalar load folding to the two changes improved the derived
ATAX warm kernel by 8.48% [7.12%, 10.87%]. The same experimental arm
increased matched CLI process time for `md5` by 2.05% and `echo` by 2.98%.
The branch contains the entry scheduling optimization.

## Correctness

All seven local Release CTest targets passed. The new entry fixture also
passed separately in interpreter, Singlepass, Eager Multipass and Lazy
Multipass. The lazy JIT unit tests check first-use compilation, subsequent
stub calls, and continued prewarming for a module-start function and for
`_start` with a different signature.

## Reproduction

From the repository root, use matching DTVM Release builds and the pinned
Wasmtime binaries.

```bash
python3 docs/changes/2026-11-26-lazy-wasi-entry-on-demand/benchmark.py \
  --variant main=/path/to/main-dtvm --variant final=/path/to/candidate-dtvm \
  --wasmtime45 /path/to/wasmtime45 --wasmtime51 /path/to/wasmtime51 \
  --cpu 0 --rounds 41 --seed 6632611 \
  --cases md5,echo,figlet,qr2text,base64cli,bicg,atax --out /tmp/wasi-entry-confirm
```

Run the three startup cases with `--cpu-set 0,1` in place of `--cpu 0`
and seed `6632643` to repeat the two-core sample.

The experiment archive `lazy-wasi-entry-evidence.tar.gz` contains
commands, hashes, paired samples, native excerpts and compiler counters.
