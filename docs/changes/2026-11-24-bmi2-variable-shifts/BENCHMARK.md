# FastRA BMI2 variable-shift benchmark

The baseline is upstream main `1ab3a84` after #656. The measured
implementation is `5a0c8b7`. Both local DTVM binaries use GCC 14.2,
LLVM 15.0.6, and the same Release build tree on an AMD EPYC 9V74.
The local Wasm build enables Multipass, Singlepass and built-in WASI.

Each sample measures a fresh process on CPU 0, including loading,
compilation, execution and exit. Engine order is shuffled within each
round. Wasmtime 45.0.0 runs with its compilation cache disabled.
A byte-identical copy of main at a separate path provides the A/A
control. Each table cell shows main and candidate wall-time medians
in milliseconds. Percentages use medians of within-round candidate/main
ratios with pointwise 95% bootstrap intervals.

## Final policy, local

The two shift kernels each execute three variable shifts per iteration.
The immediate-count kernel and the zero-iteration launch check provide
controls. The independent integer model gives the expected result for
each input in `kernels.json`. All tables use 31 measured rounds except
where noted.

| Case | Lazy FastRA | Default lazy | Eager GreedyRA | Singlepass | Wasmtime 45 | Lazy FastRA change (95% CI) | FastRA A/A (95% CI) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `shift32/6000000` | 19.27 → 16.86 | 20.70 → 18.60 | 15.99 → 15.57 | 16.32 → 16.06 | 18.37 | -12.6% [-16.4%, -10.2%] | -3.3% [-5.7%, +1.0%] |
| `shift64/6000000` | 22.22 → 18.68 | 24.17 → 20.34 | 15.08 → 14.80 | 19.87 → 19.46 | 14.52 | -17.6% [-18.8%, -15.9%] | -1.0% [-3.8%, -0.4%] |
| `immediate64/6000000` | 14.96 → 14.94 | 16.47 → 16.28 | 10.64 → 10.62 | 14.19 → 13.41 | 10.85 | -0.3% [-2.5%, +2.3%] | -3.5% [-6.9%, -1.0%] |
| `shift64/0` | 5.70 → 5.52 | 6.50 → 5.65 | 6.33 → 6.12 | 5.06 → 4.59 | 7.18 | -1.4% [-11.0%, +5.4%] | -2.1% [-6.8%, +5.3%] |

Local paired eager GreedyRA changes are -3.2% [-5.1%, +3.3%] for
`shift32` and -2.2% [-4.1%, +1.7%] for `shift64`. Eager GreedyRA uses
the legacy instructions. The default-lazy zero-iteration change is
-12.5%, alongside -10.0% for the byte-identical main A/A copy. The
zero-iteration results reflect launch variability.

### WAPM and PolyBench

| Case | Lazy FastRA | Default lazy | Singlepass | Wasmtime 45 | Lazy FastRA change (95% CI) | FastRA A/A (95% CI) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `viu` | 224.51 → 221.07 | 228.50 → 228.38 | 65.33 → 67.53 | 1295.64 | +0.5% [-2.4%, +8.1%] | -0.9% [-3.5%, +0.7%] |
| `qr2text` | 45.08 → 44.88 | 47.61 → 47.95 | 9.48 → 9.45 | 117.81 | +0.0% [-3.6%, +3.7%] | -1.5% [-6.1%, +1.8%] |
| `figlet` | 46.64 → 45.32 | 51.20 → 48.68 | 10.31 → 9.79 | 107.36 | -0.8% [-2.0%, +0.5%] | -3.3% [-4.6%, -2.1%] |
| `md5` | 22.57 → 22.36 | 25.05 → 23.65 | 6.44 → 6.06 | 39.75 | -0.5% [-3.1%, +2.1%] | +0.8% [-1.9%, +3.4%] |
| `base64cli` | 106.62 → 103.67 | 105.73 → 104.89 | 23.55 → 23.48 | 489.80 | -2.4% [-5.1%, +0.1%] | -1.4% [-5.0%, +0.5%] |
| `atax` | 64.17 → 62.82 | 51.16 → 50.60 | 83.68 → 81.52 | 62.77 | -2.3% [-2.8%, +1.5%] | -1.5% [-4.3%, +1.3%] |
| `bicg` | 61.87 → 61.89 | 62.96 → 62.89 | 83.80 → 82.98 | 74.08 | -1.0% [-3.3%, +3.0%] | -0.4% [-1.9%, +1.8%] |
| `gesummv` | 45.66 → 46.15 | 48.85 → 48.03 | 60.46 → 59.98 | 57.96 | +0.0% [-3.6%, +1.2%] | +0.0% [-2.2%, +1.6%] |
| `gemver` | 88.42 → 89.39 | 63.34 → 62.19 | 169.24 → 167.05 | 71.90 | -0.2% [-1.8%, +2.1%] | -0.6% [-2.0%, +1.8%] |

The output hashes match across engines and samples for the local catalog.
The large cases use three rounds and a warmup in both lazy configurations.

| Case | Lazy FastRA | Default lazy | Wasmtime 45 | Lazy FastRA change (95% CI) | FastRA A/A (95% CI) |
| --- | ---: | ---: | ---: | ---: | ---: |
| `gemm` | 3029.01 → 3117.36 | 2231.70 → 2239.81 | 2955.91 | +2.9% [-2.4%, +4.2%] | +0.6% [-3.1%, +2.1%] |
| `2mm` | 8280.26 → 8122.74 | 2849.94 → 2783.57 | 3672.18 | -1.9% [-2.8%, +2.1%] | +1.5% [-7.2%, +1.5%] |


The FastRA `gemm` median paired change was +2.9% over those three
rounds and the `2mm` change was -1.9%. Both three-round intervals span
zero. The native `.text` bytes for the `main` function containing the
compute loop matched byte-for-byte with the diagnostic switch off and on
in both cases.

## Independent GitHub runner

The runner rebuilt both revisions with Release and LLVM 15. It
checked the catalog fixtures against their LFS object hashes and
used 41 rounds for the kernels and 31 rounds for the catalog. These
measurements form a separate cohort. [Run and raw samples](https://github.com/zoowii/DTVM/actions/runs/45391954407)

| Case | Lazy FastRA | Default lazy | Eager GreedyRA | Singlepass | Wasmtime 45 | Lazy FastRA change (95% CI) | FastRA A/A (95% CI) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `shift32/6000000` | 15.45 → 13.24 | 17.03 → 14.89 | 12.93 → 13.14 | 13.35 → 13.51 | 14.61 | -13.9% [-17.1%, -12.4%] | -1.3% [-5.8%, +4.2%] |
| `shift64/6000000` | 16.50 → 14.41 | 17.86 → 15.63 | 13.12 → 13.07 | 16.59 → 16.51 | 14.58 | -12.7% [-13.9%, -11.0%] | +0.2% [-3.0%, +2.2%] |
| `immediate64/6000000` | 10.42 → 10.43 | 12.07 → 11.98 | 8.46 → 8.56 | 9.92 → 9.97 | 10.87 | +0.1% [-3.6%, +2.8%] | +6.3% [+0.6%, +10.5%] |
| `shift64/0` | 4.20 → 4.17 | 4.34 → 4.31 | 4.65 → 4.65 | 3.57 → 3.46 | 6.38 | -0.4% [-2.6%, +2.3%] | +0.3% [-2.3%, +1.7%] |

| Case | Lazy FastRA | Default lazy | Singlepass | Wasmtime 45 | Lazy FastRA change (95% CI) | FastRA A/A (95% CI) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `gesummv` | 37.58 → 36.47 | 38.71 → 38.59 | 49.88 → 49.52 | 48.15 | -3.4% [-4.5%, -2.2%] | -1.1% [-2.8%, +0.4%] |
| `atax` | 49.93 → 49.34 | 43.25 → 42.96 | 68.63 → 68.52 | 54.24 | -1.5% [-2.1%, -0.2%] | -0.7% [-1.8%, +1.5%] |
| `bicg` | 50.11 → 50.22 | 50.95 → 51.21 | 67.69 → 67.65 | 58.88 | -0.4% [-2.2%, +1.0%] | +1.4% [-1.8%, +2.7%] |
| `md5` | 19.25 → 19.62 | 21.64 → 21.23 | 4.89 → 5.03 | 34.81 | +1.3% [-0.8%, +3.0%] | +0.6% [-1.8%, +4.7%] |
| `qr2text` | 39.08 → 37.63 | 40.40 → 40.66 | 8.31 → 8.09 | 98.13 | -1.8% [-5.0%, +1.6%] | -1.0% [-5.3%, +0.2%] |
| `figlet` | 37.62 → 39.72 | 38.08 → 39.40 | 7.80 → 7.97 | 86.13 | +2.0% [-0.6%, +10.2%] | +0.9% [-2.8%, +2.4%] |
| `viu` | 186.25 → 185.91 | 189.29 → 188.24 | 53.32 → 53.38 | 1002.61 | -0.6% [-1.1%, +0.3%] | +0.1% [-1.1%, +1.0%] |

The independent runner confirms gains of 13.9% and 12.7% in lazy FastRA
for the two variable-shift kernels. The catalog effects are smaller.
For example, hosted `figlet` with default lazy showed +1.7% [0.9%, 4.9%],
with an A/A median of +1.7% [-1.5%, 5.6%]. The local paired result was
-5.2% with a local A/A median of -4.2%.

## Prototype bisection and native code

The unrestricted prototype used BMI2 in both allocators. Its 32-bit
loop initially regressed with eager GreedyRA. The 24-million-iteration
repeat on one diagnostic executable with BMI2 toggled measured the
following medians. Execution comes from DTVM's statistics collector.

| Case | Main wall | Prototype wall | Wasmtime 45 wall | Same binary execution off → on | Paired execution change (95% CI) |
| --- | ---: | ---: | ---: | ---: | ---: |
| shift32 | 41.60 | 44.20 | 48.75 | 33.97 → 37.41 | +10.3% [+9.8%, +10.9%] |
| shift64 | 39.99 | 35.58 | 36.33 | 31.79 → 28.05 | -11.6% [-13.5%, -9.8%] |

The 32-bit GreedyRA loop had no stack references in either form.
FastRA removes fixed-count register traffic and also reduces stack
references. The final policy enables BMI2 only for FastRA. The table
shows the hot backward-edge loop in each code shape. Wasmtime's JIT
target is captured through `wasmtime compile`.

| Kernel and code shape | x86 instructions | Stack references | BMI2 shifts | Legacy `CL` shifts |
| --- | ---: | ---: | ---: | ---: |
| shift32 DTVM FastRA legacy → BMI2 | 33 → 30 | 15 → 11 | 0 → 3 | 3 → 0 |
| shift64 DTVM FastRA legacy → BMI2 | 39 → 35 | 17 → 12 | 0 → 3 | 3 → 0 |
| shift32 DTVM GreedyRA legacy → unrestricted prototype | 18 → 15 | 0 → 0 | 0 → 3 | 3 → 0 |
| shift32 Wasmtime 45 | 14 | 0 | 3 | 0 |
| shift64 Wasmtime 45 | 14 | 0 | 3 | 0 |

The FastRA function bodies are 216 → 216 bytes for `shift32` and
290 → 277 bytes for `shift64`. The 64-bit lazy case still trails
Wasmtime in the local measurement. Its loop retains 12 stack references
after changing shift instructions. A capture with the final allocator
gate matched the prototype-on bytes for FastRA `shift32` and the
prototype-off bytes for eager GreedyRA.

The static scan found register-count shifts in WAPM's `dlmalloc` and
in `viu`'s decompression state machine. The original `viu` screen
showed +3.3% paired lazy FastRA time. A separate 23-round diagnostic
with the same executable and a feature switch gave +0.6%
[-3.3%, +7.0%] for wall time and +0.2% [-4.0%, +7.4%] for foreground
compilation. The byte-identical main pair in that repeat gave -4.5%
[-11.6%, -0.6%] for wall time. The final-policy catalog comparison above
uses the uninstrumented binaries.

## Correctness

Twelve WAST assertions cover all six shift forms, count masking,
negative counts, preservation of live operands, and rotation. They
passed in native lazy FastRA, default lazy, eager GreedyRA, Singlepass,
interpreter and Wasmtime 45. Both Multipass allocators also passed the
assertions with QEMU 7.2 using its Nehalem CPU model. A CPUID probe
reported BMI2 on the native host and no BMI2 in Nehalem. Lazy FastRA
also matched all four kernel answers in both CPU configurations.
The diagnostic capture under Nehalem emitted the three legacy `CL`
shifts in `shift32`. The seven repository CTest targets passed with
the Wasm spec suite in both lazy FastRA and eager GreedyRA.

## Reproduction

Run from the repository root with LLVM 15, a wasm32 Clang and matching
Release configurations for main and candidate. Copy the main binary
to two separate paths of equal length for the A/A control. The
benchmark accepts an allowed CPU ID via `--cpu`.

```bash
change=docs/changes/2026-11-24-bmi2-variable-shifts
driver=docs/changes/2026-11-20-signed-pow2-remainder/benchmark.py
clang --target=wasm32 -O2 -ffreestanding -fno-unroll-loops \
  -c "$change/shifts.c" -o shifts.o
wasm-ld --no-entry --export=shift32 --export=shift64 \
  --export=immediate64 shifts.o -o shifts.wasm

common=(--main /path/to/a/dtvm --candidate /path/to/d/dtvm \
  --main-aa /path/to/c/dtvm --wasmtime /path/to/wasmtime \
  --wasm shifts.wasm --default-lazy-aa --cpu 0)
python3 "$driver" "${common[@]}" --candidate-singlepass --group kernel \
  --kernel-manifest "$change/kernels.json" --rounds 31 --seed 6566400 --out kernels
python3 "$driver" "${common[@]}" --candidate-singlepass --group catalog \
  --cases viu,qr2text,figlet,md5,base64cli,atax,bicg,gesummv,gemver \
  --rounds 31 --seed 6566401 --out catalog
python3 "$driver" "${common[@]}" --omit-singlepass --group catalog \
  --cases gemm,2mm --rounds 3 --warmups 1 --seed 6566402 --out large
```
