# Initial allocator policy: first-call cost and admission budgets

Production compiler source: `19af308` (full revision in evidence/build.json).
Artifact SHA256: `e4881cae3554aba193f565962874cd291571b0f08fb07a818d426330abfb1ddf`.
Baseline represents merged main `af4b07b`; previous dense-loop candidate is the
frozen `be96a8c7` compiler artifact, also used in PR29's original measurements.
Exact executable hashes and commands are recorded for every cohort.

## Implementation and decision

`LazyInitialRAPolicy` owns FP/deep-word predicates, collection-depth gates,
saturating word-load counts, module/function size checks and the soft elapsed
compile budget. Frontend constructs facts; the compiler requests a decision and
reports elapsed work through a scoped timer. The policy returns decisions by
value, including rejection reasons, without mutable last-decision state.

Defaults preserve the prior selector: 2048 source body bytes, no module limit,
no time limit. New flags are experimental controls, not newly tuned defaults:

| Control | Default | Meaning |
|---|---:|---|
| `--disable-lazy-auto-greedy` | false | Disable automatic initial choice only |
| `--lazy-auto-greedy-max-module-bytes` | 0 | Whole input-binary cap; 0 unlimited |
| `--lazy-auto-greedy-max-function-bytes` | 2048 | Source body cap; 0 unlimited |
| `--lazy-auto-greedy-budget-ms` | 0 | Cumulative foreground elapsed budget; 0 unlimited |

Budget scope is stub precompilation plus complete foreground compilation,
including failed attempts, MIR, allocation, emission, relocations and protection.
Recheck before collecting features and again after MIR, including current elapsed
time. Exclude module loading, guest execution and background work. Already
admitted work, including concurrent admissions, may overrun. This is neither a
CPU-time cap nor a first-call deadline. Unlimited mode reads no budget clock.
Configured eager/serial/one-function/background Greedy and opt-in private
promotion retain their existing choices and separate admission rules.

## Controlled marker experiment

Same hot function in a 901-byte module and a 1,545,815-byte module with 3000
additional cold, table-referenced private functions. The reached function indices
are unchanged. A runtime argv parameter N controls three nested loops, with two
word loads, one word store and 20 live integer accumulators. N is not embedded in
the Wasm. Both calls reset state; outputs match an independently computed modular
checksum. No names or function IDs influence the selector.

Marker E precedes the call, K is inside the callee before loops, and D follows
return. E→K is observed admission delay (compile/dispatch/I/O), E→D is first-call
latency, and second-call k→d is observed warm execution. These are pipe-receipt
intervals, not pure compiler or hardware kernel timers. Tiny intervals approach
reader/pipe granularity. Wasmtime compiles before E, so its E→K does not describe
startup cost; always consider first output and full process too.

21 rounds per small-module parameter; 7 per large-module parameter. Randomized
within-round engine order, one excluded warmup per case/engine, fresh processes,
warm file-page cache, WT45 cache disabled. Engines and workers pin CPU0, reader
CPU1. GCC14.2/LLVM15 Release, both JITs and WASI on, SPEC/ASAN/profiling off;
AMD EPYC9V74 with a two-core cgroup quota. No builds/tests/profiles ran alongside
formal timing. Final marker cohort: 735 measured processes plus 49 warmups,
all exit 0 and pass checksum validation. Raw rows and full phase medians are in
[evidence](evidence/).

Group medians, milliseconds. Each process calls the kernel twice:

| Module / N | Main first call / total | Previous first call / total | Policy first call / total | WT45 first call / total |
|---|---:|---:|---:|---:|
| small / 0 | 0.490 / 7.099 | 3.419 / 9.774 | 3.033 / 10.044 | 0.006 / 7.512 |
| small / 8 | 0.489 / 7.558 | 2.542 / 10.223 | 3.156 / 10.880 | 0.008 / 7.961 |
| small / 64 | 4.156 / 13.955 | 5.550 / 14.811 | 5.296 / 14.679 | 1.792 / 11.491 |
| small / 128 | 22.923 / 51.530 | 19.714 / 43.708 | 19.289 / 43.951 | 13.660 / 35.603 |
| large / 0 | 0.523 / 15.468 | 2.292 / 18.750 | 3.158 / 18.306 | 0.014 / 2123.826 |
| large / 64 | 4.000 / 22.245 | 5.131 / 23.689 | 5.381 / 23.631 | 1.592 / 2146.838 |
| large / 128 | 22.262 / 58.535 | 19.333 / 50.487 | 18.807 / 50.732 | 13.343 / 2137.024 |

At small N=64, warm time improves 2.659→2.041 ms but first call worsens
4.156→5.296 ms. At N=128, enough work amortizes compilation: first call improves
22.923→19.289 ms. Small-module total remains slower than WT45. For large N=128,
WT45 warm time is 12.946 ms versus policy 15.847 ms; DTVM's full-process advantage
comes from lazy startup. First output is 14.860 versus 2107.201 ms. Do not present
this as a kernel throughput win.

Static loop shape does not establish runtime heat: the identical qualifying
function is unprofitable at N=0/8/64 and profitable at N=128 in this protocol.
Paired policy/main total ratios include small N=64: 1.051 [1.028,1.063] and N=128:
0.854 [0.826,0.870]. Source-size caps alone cannot resolve runtime trip counts.

## Optional guard tradeoffs

Group medians, first call / full process in milliseconds:

| Module / N | Default policy | Auto disabled | 64 KiB module cap | 1 ms compile budget |
|---|---:|---:|---:|---:|
| small / 0 | 3.033 / 10.044 | 0.463 / 7.147 | 3.104 / 9.290 | 0.467 / 7.224 |
| small / 128 | 19.289 / 43.951 | 22.767 / 52.347 | 19.344 / 43.751 | 23.029 / 52.988 |
| large / 0 | 3.158 / 18.306 | 0.497 / 15.983 | 0.509 / 16.295 | 0.511 / 15.652 |
| large / 128 | 18.807 / 50.732 | 23.109 / 61.835 | 22.140 / 58.891 | 24.572 / 64.066 |

A tight budget reduces cold-call compile delay but sacrifices long-kernel
throughput. A module cap rejects the same useful hot function solely because
unrelated cold code was appended. Retain these as configurable conservative
controls; these measurements do not justify a new universal module/time cap.
The 1 ms configuration often exhausts its allowance before reaching the kernel;
it is not a fitted threshold for individual Greedy compilation cost.

## Sequential candidates and soft-budget exhaustion

Eight distinct private candidates, same function body, called once each then
reused. 21 rounds each for N=0/128; seed 2026110753. All 252 measured processes
and 12 warmups exit 0 with matching checksums. No builds/tests/profiles overlap.
Per-function median admission delays for N=0, milliseconds:

| Policy | Function 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Main | .449 | .447 | .441 | .458 | .459 | .435 | .432 | .454 |
| Default | 3.408 | 2.923 | 2.124 | 2.097 | 2.079 | 2.148 | 2.165 | 2.107 |
| 5 ms budget | 3.516 | .543 | .453 | .418 | .447 | .414 | .423 | .404 |
| 10 ms budget | 3.671 | 2.188 | 2.004 | 1.956 | .465 | .433 | .439 | .407 |

These observed delays demonstrate sequential budget behavior; they are not logs
of exact allocator-choice counts or strict upper bounds. Admission can overrun.
The tradeoff persists at N=128: total main/previous/default/5ms/10ms/WT45 medians
are 348.093 / 272.312 / 279.538 / 334.785 / 315.468 / 222.420 ms.

The first N=0 burst showed a policy/previous paired ratio 1.040 [1.016,1.079].
An independent 41-round N=0 followup, seed 2026110755, did not reproduce it:
0.995 [0.921,1.013]. Group totals main/previous/policy/5ms/10ms/WT45 are
12.969 / 29.675 / 28.172 / 16.139 / 20.175 / 13.423 ms. Preserve both cohorts;
do not pool them or infer equivalence from intervals crossing 1.

## Real large module and validation

IRB is 17,177,819 bytes, catalog invocation stdin `3+4\n`. Seven randomized
fresh-process rounds plus one excluded warmup, seed 2026110752. Full-process
main/policy/WT45 medians: 3752.370 / 3841.479 / 9824.118 ms. All output matches,
including result 7. Paired policy/main ratio 1.017 [0.995,1.045]: the positive
point estimate is retained, with no claimed speedup or equivalence. This cohort
measures full process, not IRB's isolated first-call interval.

Intervals throughout are fixed-seed, 10,000-resample percentile bootstrap
intervals of within-round paired medians, pointwise without multiple-comparison
correction. Seven rounds have limited precision. Measurements are from one host.
Previous full WAPM/PolyBench and native-code evidence belongs to the earlier
[dense-word change](../2026-11-07-lazy-deep-word-loops/README.md); it is not a
fresh full-suite rerun of this policy refactor. No new machine peephole,
allocator algorithm, guest heat counter or OSR is introduced here.

22 lazy JIT/policy tests pass: prior structural and allocator/publication modes,
new module/function boundary integration, disabled selection, budget/current-MIR
boundaries, saturation and counter overflow. Production build, format and diff
checks pass. Logs, build flags, executable/input hashes and raw timing rows are
archived separately. The initial pre-collection-extraction exploratory marker
cohort is retained with its artifact hash, superseded and never pooled; its dirty
source was not committed. Final accepted measurements use committed source.

## Reproduction

Run from repository root with GCC14/LLVM15 Release artifacts and `wat2wasm` on
PATH. Separate output directories preserve independent cohorts:

```sh
python3 docs/changes/2026-11-07-lazy-initial-ra-policy/generate.py --out /tmp/ra-inputs
python3 docs/changes/2026-11-07-lazy-initial-ra-policy/measure.py \
  --out /tmp/ra-inputs --main /path/to/main/dtvm \
  --previous /path/to/previous/dtvm --candidate /path/to/policy/dtvm \
  --wasmtime /path/to/wasmtime-45
python3 docs/changes/2026-11-07-lazy-initial-ra-policy/measure_burst.py \
  --out /tmp/ra-inputs --main /path/to/main/dtvm \
  --previous /path/to/previous/dtvm --candidate /path/to/policy/dtvm \
  --wasmtime /path/to/wasmtime-45
```

For the independent burst check use a separate input/output directory and add
`--n 0 --rounds 41 --seed 2026110755`. The IRB command is recorded in its manifest
and uses the existing dense-word benchmark driver with `--suite wapm --cases irb
--rounds 7 --seed 2026110752`. Do not run builds/profiles/tests concurrently.
