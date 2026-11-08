# Greedy-only scalar AVX experiment

- **Status**: Implemented, experimental opt-in
- **Tier**: Light
- **Date**: 2026-11-08

In this original opt-in experiment, `--enable-greedy-scalar-avx` enabled
non-fused scalar AVX arithmetic for Wasm functions already selected for Greedy
allocation; it was off by default. See the subsequent automatic policy change
for the current default behavior.
The decision also requires LLVM's host AVX detection, which on x86 checks OS
support for saving AVX state. FastRA and unsupported hosts use the SSE path.
Only f32/f64 addition, subtraction, multiplication and division change; the
operand order is preserved. No global target feature or FMA is enabled.

## Evidence and limits

These experiments are on an AMD EPYC 9V74 with a two-CPU container quota;
engines and their workers were pinned to CPU 0. The warm-kernel collector was
pinned to CPU 1; the fresh-process collector had no explicit affinity.
Engines were run in random order within each round, in fresh processes, with
Wasmtime's compilation cache disabled. The baseline `7eb81b0` precedes #646;
the parent `58b0fd3` contains its implementation. Candidate binary SHA-256:
`9625a020ef1ff1bfecd46c3d314ba81e78127b355d422efb536f303494b7f01c`.
Times below are group medians in milliseconds, not ratios of paired medians.

The same-instance experiment uses an instrumented Binaryen-normalized input,
which preserves the original exports and validates outputs. Its warm-kernel
time is the per-process median of calls 2–30, so it is not the original CLI
benchmark or a first-call measurement. There were 31 measured processes per
engine and one excluded warmup. Parent refers to the #646 implementation.

| Case | Baseline | Parent | Candidate on | Wasmtime 45 | Candidate/parent paired median [95% bootstrap CI] |
| --- | ---: | ---: | ---: | ---: | ---: |
| atax, warm kernel | 6.711 | 6.548 | 6.595 | 7.947 | 1.0088 [1.0032, 1.0227] |
| bicg, warm kernel | 14.611 | 14.660 | 13.765 | 13.865 | 0.9545 [0.9390, 0.9696] |

The atax result indicates a small regression while bicg improves; the bicg
candidate/Wasmtime paired interval includes one. Confidence intervals are
pointwise percentile bootstrap intervals, without multiple-testing correction.
The evidence does not support enabling the option globally by default.

Fresh-process end-to-end, original CLI inputs, 31 measured rounds:

| Case | Baseline | Parent | Candidate on | Candidate off | Wasmtime 45 | On/parent paired median [95% CI] |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| atax | 55.895 | 54.488 | 54.367 | 54.154 | 67.039 | 1.0005 [0.9773, 1.0321] |
| bicg | 67.381 | 65.962 | 65.011 | 64.701 | 76.577 | 0.9864 [0.9734, 1.0072] |
| mvt | 59.490 | 60.738 | 58.645 | 60.101 | 71.884 | 0.9770 [0.9585, 1.0055] |
| echo | 25.770 | 24.371 | 23.800 | 24.484 | 35.048 | 0.9907 [0.9557, 1.0144] |
| md5 | 26.993 | 25.819 | 25.521 | 25.897 | 40.206 | 0.9989 [0.9714, 1.0285] |
| pkg1 | 22.659 | 22.327 | 22.376 | 21.995 | 82.833 | 1.0175 [0.9905, 1.0403] |
| qr2text | 54.826 | 51.922 | 51.732 | 50.544 | 130.622 | 0.9936 [0.9581, 1.0184] |

The intervals above all include one; they establish neither a short-case win
nor equality. On/off paired intervals also include one for these cases. The
original-input and warm-kernel measurements have different inputs and timing
boundaries and must not be combined. The research harness and raw local data
are under `work/greedy-scalar-avx-final-{phase,short}-r31/`.

Untimed disassembly of the research prototype shows the relevant mechanism:
the three-operand arithmetic removes some scalar register copies. In ADI two
sampled hot loops have 29 -> 26 and 31 -> 28 static instructions. BICG's
function grows from 1429 to 1437 bytes because the existing SSE-only load
folding does not apply to the AVX instructions. These counts are not dynamic
instruction counts and do not by themselves establish a speedup.

The ASAN MIR/CgIR suite passed 110 tests. The supported WAST subset passed 99
tests in each of eager, lazy, FastRA-with-option and default-off configurations.
On this host a 48-case dynamic f32/f64 bit comparison (including NaNs, signed
zeros, infinities and subnormals) produced identical parent and candidate JIT
bytes. The interpreter already differs in NaN bit patterns from the parent
JIT; WebAssembly permits arithmetic NaN variation. A non-AVX machine has not
been tested: the fallback policy is unit-tested, but that is not a substitute
for hardware validation. Do not reuse host-specific generated code on a host
without the required AVX support.

## Additional original-input screening

ADI used the original benchmark, fresh-process wall time, seven measured rounds
and one excluded warmup. All exits were zero and stdout/stderr hashes matched.
Group medians were baseline 10828.149 ms, parent 10693.079 ms, candidate
10140.776 ms, and Wasmtime 45 10813.216 ms. The paired candidate/parent median
was 0.9486 [0.9367, 0.9760] (95% percentile bootstrap). Seven rounds on a
single host are exploratory.

The complete WAPM screen below used the same fresh-process boundary, seven
measured rounds and one warmup. The `pi1000` case supplies argument 1000.
Group medians and paired ratios are different statistics.

| Case | Baseline ms | Parent ms | Candidate on ms | Wasmtime 45 ms | On/parent median [95% CI] |
| --- | ---: | ---: | ---: | ---: | ---: |
| amirali | 6.39 | 6.02 | 6.69 | 6.23 | 1.1118 [0.9848, 1.2031] |
| base64cli | 111.21 | 105.99 | 108.09 | 464.51 | 1.0130 [0.9972, 1.0392] |
| chkfont | 40.07 | 40.53 | 39.24 | 74.83 | 0.9857 [0.9604, 1.0045] |
| code-stock | 23.30 | 21.35 | 22.12 | 86.28 | 0.9900 [0.9325, 1.0788] |
| cowsay | 125.88 | 116.73 | 116.29 | 401.50 | 0.9962 [0.9406, 1.0263] |
| dice | 19.17 | 19.97 | 19.12 | 35.42 | 0.9421 [0.9235, 0.9917] |
| echo | 23.51 | 23.96 | 22.65 | 33.58 | 0.9585 [0.9258, 1.0149] |
| erdtree | 54.12 | 52.30 | 52.14 | 154.57 | 0.9960 [0.9833, 1.0035] |
| figlet | 48.51 | 45.33 | 47.33 | 105.47 | 1.0223 [1.0124, 1.0505] |
| fortune | 62.15 | 60.84 | 61.58 | 117.74 | 1.0123 [0.9771, 1.0176] |
| irb | 4015.00 | 3697.76 | 3772.15 | 9815.66 | 1.0103 [0.9888, 1.0584] |
| md5 | 28.53 | 27.69 | 28.42 | 42.35 | 1.0439 [0.9108, 1.2057] |
| pi | 27.55 | 26.79 | 26.88 | 38.41 | 0.9859 [0.9313, 1.1115] |
| pi1000 | 582.56 | 585.58 | 582.97 | 525.10 | 0.9960 [0.9907, 1.0186] |
| pkg1 | 23.35 | 22.76 | 24.73 | 88.02 | 1.0546 [1.0259, 1.1176] |
| qr2text | 46.95 | 47.73 | 45.46 | 113.39 | 1.0050 [0.9346, 1.0263] |
| suggest | 98.28 | 91.16 | 92.37 | 427.78 | 1.0044 [0.9639, 1.0313] |
| tpl | 267.10 | 267.19 | 267.47 | 773.88 | 0.9628 [0.9307, 1.0786] |
| uuid | 78.39 | 77.34 | 76.31 | 458.18 | 0.9868 [0.9433, 1.0725] |
| viu | 249.02 | 237.74 | 220.17 | 1279.17 | 0.9436 [0.8977, 0.9660] |

`sam` exited 1 in the warmup for every engine and was excluded. `fortune` and
`uuid` have nondeterministic stdout; all other included cases had matching
stdout/stderr hashes across variants and rounds. `figlet` and `pkg1` showed
possible regressions in this screen; the separate 31-round `pkg1` interval
above includes one. The small sample and multiple comparisons preclude
conclusions about each individual WAPM result.

For the instrumented 30-call input, the first result packet is observed before
the original main returns and includes startup, demand compilation and work up
to that packet; it is not pure compile or call latency. Candidate/parent paired
median [95% CI] was 0.9948 [0.9684, 1.0237] for atax and 0.9831
[0.9636, 0.9963] for bicg. These exploratory measurements do not establish an
independent compilation-time improvement.

## Reproduction

Build baseline, parent and candidate with identical Release options, using
LLVM 15, and obtain Wasmtime 45.0.0. The measured builds use GCC 14.2,
Release `-O3 -DNDEBUG`, multipass and singlepass enabled, with ASAN and
profiling disabled. Run from the repository root; the local
measurements used the commands recorded in each result manifest. For example:

```sh
python3 docs/changes/2026-11-08-greedy-scalar-avx/benchmark.py \
  --suite polybench --cases adi --rounds 7 --warmups 1 --seed 6461816 \
  --out /tmp/adi-results --main /path/to/baseline/dtvm \
  --private /path/to/parent/dtvm --candidate /path/to/candidate/dtvm \
  --wasmtime /path/to/wasmtime-45 --variants main,private,combined,wt45 --cpu 0
python3 docs/changes/2026-11-08-greedy-scalar-avx/summarize.py /tmp/adi-results
```

The benchmark's variant `combined` turns the option on; `off` uses the same
candidate binary with the option off. For the warm-kernel experiment, install
Binaryen `wasm-dis` and `wasm-as` (version 120 was used), generate inputs with
`make_phase_inputs.py --out /tmp/phase-inputs`, then run `phase_benchmark.py`
with those inputs and four binaries. The generator uses fixed scratch memory
and checks the expected original code shape; it is a diagnostic for these
inputs, not a general Wasm transformer. Keep count 1 in the generated inputs:
the runner uses it for canonical-output validation even when only count 30 is
timed. The local raw samples and manifests are
retained in `work/greedy-scalar-avx-final-{phase,short,adi,wapm}-*`.
