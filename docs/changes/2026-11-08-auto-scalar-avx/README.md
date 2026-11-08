# Automatic scalar AVX policy experiment

- **Status**: Implemented, experimental
- **Tier**: Light
- **Date**: 2026-11-08

Evaluate a workload-independent policy that enables the existing scalar AVX
lowering on AVX-capable hosts for functions selected for initial Greedy because
of their loop shape. Preserve explicit force and disable controls and fallback
on unsupported CPUs and operating systems. Compare default policy against
upstream, forced AVX and Wasmtime 45, including startup and steady-state costs.
Use results to decide whether automatic enablement is safe as a default; the
existing eligibility heuristic is a performance hypothesis, not proof of
profitability. Preserve WebAssembly semantics and FastRA behavior.

## Candidate policy and measurements

The experimental default uses AVX only for a function already selected for
initial Greedy by `LazyInitialRAPolicy`. This reuses its loop-shape checks and
compile budget; it is not measured runtime hotness or a per-function payoff
guarantee. The explicit force option still applies to other Greedy functions,
while `--disable-auto-greedy-scalar-avx` disables automatic selection. Both
respect host/OS AVX detection; FastRA remains SSE. The automatic path applies
to initial lazy selection, not eager or background Greedy.

One AMD EPYC 9V74 host, engine threads CPU 0, fresh processes and random order
within rounds. Wasmtime cache disabled. The warm kernel uses a derived
Binaryen-normalized input, with calls 2–30 summarized once per process; the
collector was pinned to CPU 1. Group medians (ms), 21 measured rounds:

| Case | Baseline #645 | Upstream #646 | Auto | Forced | Auto off | Wasmtime 45 | Auto / upstream [95% bootstrap CI] |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| atax | 6.494 | 6.447 | 6.453 | 6.460 | 6.534 | 7.811 | 1.0015 [0.9800, 1.0126] |
| bicg | 14.732 | 14.563 | 13.944 | 13.972 | 14.621 | 13.930 | 0.9623 [0.9484, 0.9815] |

Original CLI input, 21 rounds, fresh-process wall time, collector without
explicit affinity. All stdout/stderr hashes matched for each case. `pi1000`
has argument 1000. The intervals below are paired medians; they all include
one and do not prove equality or a short-case win. Pointwise percentile
bootstrap, 10,000 resamples, no multiple-testing correction.

| Case | Baseline #645 | Upstream #646 | Auto | Forced | Auto off | Wasmtime 45 | Auto / upstream [95% CI] |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| atax | 55.25 | 56.88 | 57.21 | 55.84 | 56.23 | 67.55 | 1.0203 [0.9637, 1.0391] |
| bicg | 68.88 | 66.88 | 67.63 | 65.03 | 67.52 | 75.61 | 1.0164 [0.9866, 1.0353] |
| mvt | 63.11 | 61.68 | 62.15 | 61.68 | 61.66 | 74.24 | 1.0211 [0.9983, 1.0379] |
| echo | 25.27 | 24.18 | 24.81 | 24.95 | 24.89 | 34.68 | 1.0076 [0.9848, 1.0592] |
| figlet | 49.76 | 47.53 | 49.00 | 49.03 | 47.89 | 103.77 | 1.0296 [0.9927, 1.0650] |
| md5 | 28.43 | 27.76 | 26.83 | 26.76 | 27.84 | 40.85 | 0.9866 [0.9228, 1.0264] |
| pi | 30.62 | 29.08 | 29.57 | 30.70 | 29.44 | 42.22 | 1.0328 [0.9538, 1.1070] |
| pkg1 | 23.31 | 22.17 | 22.86 | 22.91 | 22.94 | 85.86 | 1.0361 [0.9916, 1.0705] |
| qr2text | 52.50 | 50.72 | 52.45 | 51.34 | 52.96 | 122.29 | 1.0380 [0.9958, 1.0793] |
| pi1000 | 586.77 | 582.80 | 586.82 | 588.86 | 587.56 | 532.75 | 0.9992 [0.9788, 1.0213] |

A QEMU 10.0.13 user-mode run with `-cpu max,-avx,-avx2` confirmed guest CPUID
`avx=0`, and the parent, automatic, forced and disabled modes gave identical
bytes on a dynamic floating-point boundary test. Lazy bicg also succeeded with
matching auto/forced/off stdout and stderr hashes. This checks emulated fallback,
not physical non-AVX hardware or performance.

Raw manifests and samples are in `work/auto-avx-{phase-r21,short-r21,adi-r5}`.
The experiment drivers are `phase_benchmark.py` and `benchmark.py` in this
directory; the phase input generator is in the preceding scalar AVX change
directory. Both record exact commands and binary/input hashes in the output
manifest. `combined` is automatic, `load` is forced, and `off` disables
automatic selection in the original-input driver.

For example, from the repository root with matching Release builds:

```sh
python3 docs/changes/2026-11-08-auto-scalar-avx/benchmark.py \
  --suite polybench --cases adi --rounds 5 --warmups 1 --seed 6461905 \
  --out /tmp/auto-avx-adi --main /path/to/pre-646/dtvm \
  --private /path/to/646/dtvm --candidate /path/to/candidate/dtvm \
  --wasmtime /path/to/wasmtime-45 --variants main,private,combined,off,wt45 --cpu 0
```

The original-input ADI screen (five measured rounds, seed 6461905) produced
median wall times of 10440.65 / 10543.89 / 10110.34 / 10643.19 / 10655.66 ms
for #645 / #646 / auto / auto off / Wasmtime 45, respectively. Auto / #646 was
0.9589 [0.9522, 0.9812]; the sample is small and exploratory. All output
hashes matched.

In the instrumented 30-call input, the first parent-observed result packet is
not pure compilation time: auto / #646 paired medians [95% CI] were 1.0131
[0.9911, 1.0333] for atax and 1.0002 [0.9716, 1.0073] for bicg. These
intervals do not establish a first-result improvement or regression.

QEMU `-cpu max,-xsave` additionally reported `avx=1 osxsave=0`. The dynamic
float test produced the same bytes under auto, forced and #646 parent modes,
verifying the OS-state fallback in emulation.

An untimed instrumented build captured the original bicg main function. Auto
and forced each produced seven scalar AVX arithmetic instructions and a
1321-byte body; auto off produced seven corresponding SSE instructions and a
1313-byte body. Diagnostic instrumentation did not participate in timing.

Validation: ASAN MIR/CgIR 110/110; ASAN WAST 99/99 in each of auto, auto-off,
forced and forced-FastRA lazy configurations. The Wasm spec submodule's
existing supported-suite patch was applied during the build and reversed after
testing. The policy truth table covers missing host features and the controls.
Only one physical CPU model has been measured; the non-AVX checks use QEMU.
The earlier forced-AVX study observed an atax warm-kernel regression, while the
current auto study's atax interval includes one. Additional physical CPU and
workload coverage is needed before considering the default policy mature.
