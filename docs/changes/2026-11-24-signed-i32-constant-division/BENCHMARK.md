# Signed i32 literal division benchmark

The comparison uses main `31310d9`, the implementation at `dbd37e7`, and
Wasmtime 45.0.0 with its compilation cache off. The local machine reported
AMD EPYC 9V74. DTVM was built with GCC 14.2, LLVM 15, and CMake Release.
Both binaries use the same build tree and build flags.

Each sample measures one new process, including loading, compilation,
execution, and exit. The harness pins itself and its children to CPU 0
and shuffles all variants in each round. The catalog runs use the same
Wasm and arguments across engines. A second, byte-identical copy of main
at a separate path measures launch variability. Times are medians in
milliseconds. Paired changes and their 95% bootstrap intervals use the
within-round ratios. The local runs used 31 measured rounds and two
warmups per condition, except the large PolyBench runs.

## Quotient kernels

The kernels use a fixed integer stream and accumulate signed quotients.
`divtime` sums the quotients of the same dividend by 60, 3600 and 86400.
The harness checks every result against an independent integer oracle.
`div1024`, `bucket7`, and the zero-iteration `div7` are controls for
power-of-two division, signed remainder, and startup, respectively.

| Case | Lazy FastRA | Default lazy | Eager GreedyRA | Singlepass | Wasmtime 45 | Paired Lazy FastRA change (95% CI) | FastRA main/main (95% CI) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `div3/8000000` | 21.25 → 20.84 | 24.17 → 23.31 | 23.44 → 21.88 | 19.87 → 19.87 | 20.83 | -1.9% [-5.9%, +0.1%] | +0.7% [-0.9%, +3.9%] |
| `div7/8000000` | 21.37 → 21.02 | 23.97 → 23.44 | 23.20 → 21.18 | 20.43 → 19.44 | 22.49 | -1.9% [-5.5%, +0.1%] | +0.2% [-3.7%, +2.3%] |
| `div1009/8000000` | 21.48 → 19.21 | 24.50 → 21.84 | 23.42 → 22.16 | 20.48 → 20.26 | 20.52 | -11.6% [-13.1%, -8.7%] | -1.2% [-2.3%, +2.6%] |
| `div1024/8000000` | 18.49 → 18.56 | 21.30 → 21.30 | 19.03 → 18.92 | 20.23 → 20.20 | 19.33 | +0.5% [-1.8%, +2.2%] | -1.2% [-2.5%, +3.5%] |
| `bucket7/8000000` | 19.91 → 19.85 | 22.20 → 21.65 | 21.76 → 21.38 | 19.82 → 19.40 | 23.06 | -0.6% [-4.5%, +1.3%] | -2.4% [-4.6%, +0.9%] |
| `divtime/4000000` | 28.18 → 18.05 | 30.61 → 20.29 | 29.54 → 18.46 | 27.05 → 26.74 | 21.65 | -36.4% [-37.3%, -35.6%] | -0.6% [-1.9%, +0.8%] |
| `div7/0` | 6.13 → 5.63 | 6.31 → 6.30 | 7.24 → 6.38 | 4.86 → 4.67 | 8.08 | -1.6% [-16.8%, +9.4%] | +0.5% [-10.4%, +9.0%] |

The local paired reductions for `divtime` are 36.4% for lazy FastRA,
35.2% for default lazy and 37.1% for eager GreedyRA. For `/1009`, the
corresponding reductions are 11.6%, 10.3% and 4.8%. The zero-iteration
lazy intervals span zero.

## WAPM and PolyBench

Static scanning found 429 adjacent literal `i32.div_s` sites with eligible
divisors across 15 local WAPM fixture modules.
The `qr2text` site is in its `large_checkerboard` mask. The PolyBench
fixtures each have one eligible site, in the output formatter for the
inspected `2mm` and `gesummv` fixtures.

| Case | Lazy FastRA | Default lazy | Singlepass | Wasmtime 45 | Paired Lazy FastRA change (95% CI) | FastRA main/main (95% CI) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `qr2text` | 44.72 → 44.21 | 47.85 → 48.87 | 9.65 → 9.41 | 120.03 | -1.2% [-4.0%, +1.7%] | -1.2% [-2.7%, +0.8%] |
| `md5` | 24.80 → 23.82 | 25.70 → 25.59 | 6.78 → 6.60 | 41.42 | -0.9% [-4.6%, +0.5%] | -2.9% [-5.5%, +1.3%] |
| `figlet` | 45.04 → 45.66 | 46.56 → 45.80 | 9.58 → 9.64 | 103.46 | -0.3% [-2.4%, +1.6%] | -0.4% [-2.4%, +3.7%] |
| `cowsay` | 116.36 → 111.88 | 116.27 → 114.72 | 20.13 → 20.14 | 398.57 | -1.9% [-4.2%, +0.0%] | -1.6% [-4.6%, +0.1%] |
| `base64cli` | 104.67 → 102.24 | 106.29 → 105.11 | 23.04 → 23.31 | 479.26 | -1.3% [-2.5%, +0.9%] | -0.1% [-1.7%, +1.3%] |
| `atax` | 63.10 → 63.71 | 50.62 → 51.04 | 82.80 → 82.02 | 61.53 | -0.7% [-2.0%, +2.5%] | -0.4% [-2.2%, +0.8%] |
| `bicg` | 59.50 → 59.17 | 60.94 → 60.55 | 80.48 → 81.18 | 69.73 | -1.5% [-3.3%, +1.6%] | -0.2% [-2.3%, +2.6%] |
| `gesummv` | 45.46 → 45.13 | 48.92 → 47.89 | 60.12 → 59.55 | 57.23 | -0.7% [-2.4%, +0.4%] | -0.9% [-2.1%, +2.4%] |
| `gemver` | 89.30 → 90.19 | 63.45 → 61.11 | 167.75 → 167.04 | 72.23 | +0.9% [-1.3%, +2.7%] | +0.3% [-2.7%, +2.0%] |

The large PolyBench runs use three measured rounds and one warmup.

| Case | Lazy FastRA | Default lazy | Wasmtime 45 |
| --- | ---: | ---: | ---: |
| `gemm` | 3199.87 → 3105.56 | 2281.50 → 2282.64 | 3033.69 |
| `2mm` | 8382.93 → 8066.47 | 2744.66 → 2749.42 | 3448.72 |

The large cases serve as a check for substantial regressions. The
`gemm` FastRA paired change was -1.5% against +1.7% in A/A. The `2mm`
FastRA paired change was -3.8% against -3.5% in A/A. The five WAPM and four
smaller PolyBench cases showed no consistent wall-time change across
the lazy modes and Singlepass.

## Independent GitHub runner

The runner rebuilt both DTVM revisions and used 41 rounds for the
kernels and 61 rounds for the catalog. It verified the six catalog
Wasm files against their LFS SHA-256 pointers. The timings below are
from that runner. [Run and raw samples](https://github.com/zoowii/DTVM/actions/runs/45342813984)

| Case | Lazy FastRA | Default lazy | Singlepass | Wasmtime 45 | Paired Lazy FastRA change (95% CI) |
| --- | ---: | ---: | ---: | ---: | ---: |
| `div3/8000000` | 18.54 → 15.21 | 21.91 → 17.55 | 17.14 → 17.18 | 18.08 | -19.1% [-20.5%, -16.4%] |
| `div7/8000000` | 18.66 → 16.06 | 21.16 → 18.14 | 16.97 → 16.92 | 18.45 | -13.3% [-16.2%, -9.1%] |
| `div1009/8000000` | 18.98 → 15.37 | 21.94 → 18.16 | 17.55 → 17.59 | 19.33 | -18.3% [-19.6%, -17.1%] |
| `div1024/8000000` | 13.90 → 13.89 | 16.58 → 16.47 | 17.02 → 17.09 | 17.55 | 1.4% [-1.5%, 2.2%] |
| `bucket7/8000000` | 15.64 → 15.82 | 18.35 → 18.10 | 17.12 → 17.17 | 19.20 | 0.5% [-1.6%, 3.1%] |
| `divtime/4000000` | 23.95 → 14.07 | 27.10 → 16.11 | 22.87 → 22.73 | 17.50 | -41.8% [-42.7%, -40.0%] |
| `div7/0` | 5.36 → 5.38 | 5.78 → 5.77 | 4.51 → 4.48 | 8.94 | 0.7% [-3.1%, 2.4%] |

| Case | Lazy FastRA | Default lazy | Singlepass | Wasmtime 45 | Paired Lazy FastRA change (95% CI) |
| --- | ---: | ---: | ---: | ---: | ---: |
| `gesummv` | 43.18 → 43.06 | 45.13 → 45.17 | 52.62 → 52.34 | 54.13 | -0.3% [-2.5%, 1.0%] |
| `atax` | 59.02 → 59.14 | 51.09 → 50.88 | 72.46 → 72.98 | 60.13 | -0.4% [-1.1%, 1.0%] |
| `bicg` | 61.94 → 61.23 | 64.04 → 63.93 | 75.06 → 75.52 | 70.91 | -0.5% [-1.3%, 0.7%] |
| `md5` | 20.04 → 19.69 | 22.94 → 22.69 | 6.44 → 6.36 | 33.82 | -1.1% [-4.7%, 0.5%] |
| `qr2text` | 36.04 → 36.06 | 38.72 → 38.62 | 10.00 → 9.65 | 90.25 | 0.4% [-1.3%, 1.7%] |
| `figlet` | 35.43 → 35.05 | 37.13 → 36.58 | 9.33 → 9.34 | 80.58 | -0.7% [-2.6%, 1.1%] |

The runner reproduced the `divtime` and `/1009` gains. Its `/3` and
`/-7` loops also improved in both lazy modes. The catalog lazy
intervals include zero or meet zero at the reported precision.
The paired Singlepass change for `atax` was +0.9% [0.1%, 1.3%] on the
runner and -0.8% [-1.4%, 0.0%] locally. The change affects Multipass
lowering, and the Singlepass results show the scale of observed
launch variability.

## Generated x86-64 code

A diagnostic build dumped each compiled lazy FastRA function after code
generation. An environment switch toggled only the new division path
within that build. Wasmtime 45 assembly came from `wasmtime compile`.

| Function | DTVM emitted bytes | DTVM `idiv` count | Wasmtime 45 `idiv` count |
| --- | ---: | ---: | ---: |
| `div3` | 216 → 137 | 1 → 0 | 0 |
| `div7` | 216 → 146 | 1 → 0 | 0 |
| `div1009` | 216 → 142 | 1 → 0 | 0 |
| `div1024` | 132 → 132 | 0 → 0 | 0 |
| `divtime` | 323 → 211 | 3 → 0 | 0 |
| `qr2text::large_checkerboard` | 172 → 101 | 1 → 0 | 0 |
| `gesummv::printf_core` | 20472 → 20424 | 1 → 0 | 0 |

The previous DTVM `divtime` loop emitted `cdq`, `idiv`, and the signed
overflow branches at all three divides. With folding, the loop uses
sign extension, an immediate `imul`, and shifts for each quotient.
Wasmtime already uses three signed high-product multiplies with constants
loaded from its code section. DTVM obtains the rounding correction from
the input sign. Wasmtime obtains it from each shifted intermediate result.
The new DTVM loop still sign-extends the same input three times and
computes its sign bit three times. These instructions are opportunities
for reuse when multiple quotients share a dividend.

### Shared dividend probe

Three equivalent Wasm functions used the same 4-million-iteration input
stream. One used literal division. The other two wrote out the
multiply-and-shift formula with separate or shared sign extension and
sign correction. The 31-round local probe checked each result against an
integer oracle.

| Mode | Main literal division | Candidate literal division | Candidate separate | Candidate shared |
| --- | ---: | ---: | ---: | ---: |
| Lazy FastRA | 28.73 | 18.39 | 18.47 | 17.63 |
| Default lazy | 30.53 | 20.07 | 20.18 | 19.71 |
| Wasmtime 45 | | 21.37 | | 19.61 |

The paired changes from the candidate's literal form to the shared form
were -3.7% [-8.3%, +1.0%] with lazy FastRA and -2.0% [-5.8%, +0.4%] with
default lazy. Both intervals span zero. The branch uses the single-quotient
lowering measured in the preceding sections.

## Correctness

The new WAST covers signed boundaries, rounding on either side of an exact
multiple, and division by large negative literals. It also verifies one
evaluation of a call and preserves divide-by-zero, signed overflow, and
out-of-bounds load traps when the quotient is dropped. The three literal
arithmetic WAST modules passed 60 assertions per engine configuration.
A separate check compared the folded and dynamic divide for 47 eligible
divisors and 65,536 inputs per divisor. All 3,080,192 comparisons passed
in each of lazy FastRA, default lazy, eager GreedyRA, and Wasmtime 45.

The repository's seven CTest targets passed with the Wasm spec suite
configured for lazy FastRA and again with eager GreedyRA.

## Reproduction

Run from the project root with both Release binaries and Wasmtime 45.0.0.
Use copies of main in separate paths of equal length for the A/A control.

```bash
change=docs/changes/2026-11-24-signed-i32-constant-division
driver=docs/changes/2026-11-20-signed-pow2-remainder/benchmark.py
clang --target=wasm32 -O2 -ffreestanding -fno-unroll-loops \
  -c "$change/signed_division.c" -o kernels.o
wasm-ld --no-entry --export=div3 --export=div7 --export=div1009 \
  --export=div1024 --export=divtime --export=bucket7 kernels.o -o kernels.wasm

common=(--main /path/to/a/dtvm --candidate /path/to/b/dtvm \
  --main-aa /path/to/c/dtvm --wasmtime /path/to/wasmtime \
  --wasm kernels.wasm --default-lazy-aa --cpu 0)
python3 "$driver" "${common[@]}" --candidate-singlepass --group kernel \
  --signed-i32-div-kernels --input-seed 463 --rounds 31 --seed 6554110 --out kernels
python3 "$driver" "${common[@]}" --candidate-singlepass --group catalog \
  --cases qr2text,md5,figlet,cowsay,base64cli,atax,bicg,gesummv,gemver \
  --rounds 31 --seed 6554111 --out catalog
python3 "$driver" "${common[@]}" --omit-singlepass --group catalog \
  --cases gemm,2mm --rounds 3 --warmups 1 --seed 6554112 --out large
```
