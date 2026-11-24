# Lazy GreedyRA for integer loop-carried locals

Baseline `6de49e4` includes #657. The implementation under test is
`3cb8b1c`. Local measurements used AMD EPYC 9V74, GCC 14.2,
LLVM 15.0.6 and one Release CMake tree for both revisions. The CLI
build includes Multipass, Singlepass and WASI.

Each sample covers one fresh process on CPU 0, including loading,
compilation, execution, and exit. The order changes within each round.
Wasmtime 45.0.0 runs with its cache off. An independently launched copy
of the exact main binary provides A/A data. Table cells give main and
candidate wall-time medians in milliseconds. Paired changes use
within-round ratios and pointwise 95% bootstrap intervals.

The test module exports thin wrappers. The kernel functions are private
and first compile when a wrapper calls them. Every kernel invocation
checks its result against the existing manifest's independent integer
answers. The immediate-count loop tests the same allocator decision
with constant shift counts.

## Local kernels

31 measured rounds and two warmups.

| Case | Default lazy | Explicit lazy FastRA | Eager GreedyRA | Singlepass | Wasmtime 45 | Paired default-lazy change (95% CI) | Default lazy A/A (95% CI) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `shift32/6000000` | 19.28 → 17.12 | 17.72 → 17.42 | 16.23 → 16.36 | 16.28 → 16.31 | 18.93 | -11.7% [-14.5%, -9.2%] | -2.5% [-5.7%, +0.6%] |
| `shift64/6000000` | 22.37 → 17.19 | 20.73 → 20.08 | 16.58 → 17.02 | 20.58 → 21.00 | 15.93 | -22.0% [-25.0%, -19.5%] | +0.8% [-4.7%, +3.3%] |
| `immediate64/6000000` | 17.78 → 12.82 | 15.85 → 16.12 | 11.53 → 11.32 | 14.79 → 14.74 | 11.29 | -27.8% [-30.9%, -25.6%] | -2.3% [-5.7%, +0.6%] |
| `shift64/0` | 6.39 → 6.46 | 6.29 → 6.31 | 7.02 → 6.82 | 5.10 → 4.99 | 7.46 | +3.9% [+0.5%, +13.0%] | -3.1% [-9.7%, +3.5%] |

## WAPM and PolyBench

The final local catalog uses 21 rounds and two warmups on the original
repo fixtures.

| Case | Default lazy | Explicit lazy FastRA | Singlepass | Wasmtime 45 | Paired default-lazy change (95% CI) | Default lazy A/A (95% CI) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `figlet` | 48.64 → 49.09 | 48.73 → 46.53 | 10.47 → 9.99 | 115.71 | +0.3% [-7.3%, +4.4%] | +1.1% [-5.3%, +4.3%] |
| `tpl` | 270.85 → 266.35 | 244.52 → 248.74 | 106.60 → 106.75 | 815.74 | -1.1% [-3.9%, +5.4%] | -4.2% [-5.7%, +0.7%] |
| `viu` | 226.97 → 231.43 | 221.79 → 224.54 | 63.94 → 63.79 | 1276.24 | +0.6% [-2.6%, +7.5%] | -1.5% [-2.8%, +3.5%] |
| `md5` | 26.95 → 26.45 | 25.06 → 24.32 | 7.00 → 7.41 | 44.38 | -0.9% [-5.8%, +3.6%] | +3.4% [-4.7%, +9.2%] |
| `atax` | 53.64 → 53.24 | 67.58 → 65.43 | 87.11 → 84.33 | 63.24 | -1.4% [-4.8%, +5.0%] | -1.5% [-5.0%, +5.0%] |
| `bicg` | 64.25 → 64.18 | 66.32 → 64.41 | 86.11 → 82.66 | 75.73 | +1.4% [-3.2%, +3.9%] | -2.3% [-5.3%, -0.5%] |
| `gemver` | 64.50 → 64.15 | 91.74 → 90.75 | 169.96 → 170.43 | 74.95 | +2.0% [-2.4%, +5.4%] | +1.5% [-3.0%, +4.6%] |

The large canonical cases use three rounds and one warmup in both
lazy modes.

| Case | Default lazy | Explicit lazy FastRA | Wasmtime 45 | Paired default-lazy change (95% CI) | Default lazy A/A (95% CI) |
| --- | ---: | ---: | ---: | ---: | ---: |
| `gemm` | 2238.31 → 2301.75 | 3050.82 → 3204.76 | 2953.12 | +2.8% [-5.1%, +4.6%] | -0.5% [-0.6%, -0.1%] |
| `2mm` | 2736.78 → 2745.82 | 7940.97 → 8130.90 | 3356.89 | +3.1% [-0.9%, +3.7%] | +2.6% [+1.9%, +4.8%] |

Seven-round `gemm` confirmation with one warmup. The new rule is
toggled within one diagnostic binary. The two Release binaries and
Wasmtime run in the same rounds.

| Main | Candidate | Wasmtime 45 | Diagnostic off → on | Candidate/main (95% CI) | Same binary on/off (95% CI) | A/A (95% CI) |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2384.58 | 2365.32 | 3135.42 | 2413.34 → 2325.39 | -0.5% [-2.4%, +8.1%] | +0.2% [-7.5%, +1.4%] | -1.1% [-5.2%, +8.9%] |

A diagnostic trace recorded zero selections by the new rule in the
15 catalog cases run through it, including `gemm`, `2mm`, `viu` and `tpl`.
This trace observes foreground selection for those invocations. The
prototype also screened the wider WAPM and PolyBench set before
the final run. The uninstrumented tables measure full wall time.

## Independent GitHub runner

The runner built both revisions with LLVM 15, verified LFS fixture
hashes, then used 41 measured kernel rounds and 31 catalog rounds.
These are a separate set of measurements. [Run and raw samples](https://github.com/zoowii/DTVM/actions/runs/45414023078)

| Case | Default lazy | Explicit lazy FastRA | Eager GreedyRA | Singlepass | Wasmtime 45 | Paired default-lazy change (95% CI) | Default lazy A/A (95% CI) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `shift32/6000000` | 22.36 → 19.63 | 18.72 → 18.47 | 18.09 → 18.01 | 19.14 → 18.56 | 21.91 | -10.9% [-17.8%, -4.8%] | -1.3% [-5.5%, +1.5%] |
| `shift64/6000000` | 22.93 → 18.57 | 20.31 → 20.61 | 17.47 → 17.24 | 21.91 → 22.21 | 18.70 | -19.8% [-24.9%, -15.9%] | +1.7% [-0.8%, +5.0%] |
| `immediate64/6000000` | 20.76 → 14.08 | 17.53 → 17.37 | 12.64 → 12.07 | 17.91 → 16.66 | 16.45 | -29.4% [-34.3%, -25.3%] | -3.3% [-9.9%, -1.2%] |
| `shift64/0` | 8.43 → 8.93 | 6.83 → 6.82 | 7.53 → 7.42 | 5.55 → 5.44 | 9.95 | +4.5% [-2.3%, +12.4%] | +3.1% [-4.1%, +11.4%] |

| Case | Default lazy | Explicit lazy FastRA | Singlepass | Wasmtime 45 | Paired default-lazy change (95% CI) | Default lazy A/A (95% CI) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `gesummv` | 63.47 → 63.13 | 61.64 → 62.28 | 72.43 → 72.37 | 75.72 | -1.4% [-3.1%, +1.6%] | -0.4% [-3.6%, +1.5%] |
| `atax` | 70.74 → 71.09 | 82.26 → 82.83 | 102.65 → 102.55 | 82.42 | +0.6% [-0.6%, +2.3%] | +0.3% [-2.7%, +1.8%] |
| `bicg` | 85.65 → 87.56 | 84.50 → 84.68 | 102.50 → 103.01 | 97.81 | +1.0% [+0.0%, +3.4%] | +1.1% [+0.1%, +2.5%] |
| `md5` | 36.10 → 34.64 | 30.50 → 29.89 | 8.05 → 7.98 | 50.30 | -1.7% [-6.7%, +1.7%] | +0.0% [-4.1%, +3.3%] |
| `qr2text` | 65.20 → 62.96 | 58.02 → 64.64 | 14.41 → 14.67 | 138.28 | -3.2% [-6.1%, +5.8%] | -1.9% [-7.4%, +3.6%] |
| `figlet` | 61.84 → 63.73 | 58.63 → 57.76 | 13.23 → 13.38 | 120.77 | +1.4% [-3.4%, +4.9%] | -1.7% [-5.1%, +1.9%] |
| `viu` | 265.64 → 266.80 | 261.45 → 262.21 | 88.32 → 87.56 | 1402.88 | +0.2% [-0.2%, +0.7%] | -0.4% [-0.8%, +0.2%] |

## Foreground compilation and execution

The diagnostic build toggles only the new selection rule and captures
the first-demand body of the private `shift64` kernel. The phase
comparison uses 31 rounds. Times are medians in milliseconds.
The A/A launch and release binaries are sampled in the same rounds.

| Iterations | Main process | Candidate process | Wasmtime 45 process | Same binary foreground compile off → on | Same binary execution off → on |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 7.84 | 7.80 | 7.85 | 1.091 → 1.349 | 0.006 → 0.007 |
| 64 | 6.24 | 6.14 | 7.35 | 0.978 → 1.271 | 0.006 → 0.006 |
| 200000 | 8.15 | 7.43 | 8.37 | 1.137 → 1.398 | 0.406 → 0.258 |
| 6000000 | 21.17 | 16.69 | 15.22 | 1.095 → 1.390 | 13.450 → 8.812 |

The same binary increased foreground compile time by 0.26 ms at zero
iterations and 0.29 ms at 64 iterations. The 6-million-iteration
execution result improved by 34.5% [-35.6%, -33.2%] from the paired
ratios. At 200,000 iterations the compilation cost still exceeded
the execution savings. The rule chooses from loop structure before
the first call, so a short call can pay the compilation cost.

### Foreground machine code

The capture separates foreground and background objects and checks
that the policy selects Greedy only on the enabled arm for the
private loop. Both captures execute the identical wrapped Wasm.

| First-demand `shift64` body | x86 instructions per iteration | Stack loads and stores per iteration |
| --- | ---: | ---: |
| Legacy FastRA selection | 35 | 12 |
| GreedyRA selected by the carried-local rule | 20 | 0 |

## Verification

Both default lazy and explicit lazy FastRA passed all seven CTest
targets. The integration test keeps its loop functions private and
compiles a single exported dispatcher in the background. It checks a
four-carried-local loop, locals defined before their use, a memory
loop, and the automatic-selection disable flag. The policy tests
cover the new hint's priority and existing limits.

## Reproduction

From the repo root, build matching Release DTVM binaries and place a
byte-identical main copy in a second path for the A/A control.

```bash
change=docs/changes/2026-11-24-lazy-loop-carried-locals
fixture=docs/changes/2026-11-24-bmi2-variable-shifts
driver=docs/changes/2026-11-20-signed-pow2-remainder/benchmark.py
clang --target=wasm32 -O2 -ffreestanding -fno-unroll-loops \
  -c "$fixture/shifts.c" -o shifts.o
clang --target=wasm32 -O2 -ffreestanding -c "$change/demand_wrappers.c" -o wrappers.o
wasm-ld --no-entry shifts.o wrappers.o -o loops.wasm

common=(--main /path/to/a/dtvm --candidate /path/to/d/dtvm \
  --main-aa /path/to/c/dtvm --wasmtime /path/to/wasmtime \
  --wasm loops.wasm --default-lazy-aa --cpu 0)
python3 "$driver" "${common[@]}" --candidate-singlepass --group kernel \
  --kernel-manifest "$fixture/kernels.json" --rounds 31 --seed 6576200 --out kernels
python3 "$driver" "${common[@]}" --candidate-singlepass --group catalog \
  --cases figlet,tpl,viu,md5,atax,bicg,gemver --rounds 21 --seed 6576201 --out catalog
python3 "$driver" "${common[@]}" --omit-singlepass --group catalog \
  --cases gemm,2mm --rounds 3 --warmups 1 --seed 6576202 --out large
```
