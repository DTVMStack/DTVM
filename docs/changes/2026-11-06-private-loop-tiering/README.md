# Change: Budgeted private loop tiering

- **Status**: Implemented
- **Date**: 2026-11-06
- **Tier**: Full

## Motivation and scope

WAPM pi(1000) spends most sampled CPU time in a private scalar helper. Previous
native-code experiments found FastRA emitted 893 bytes with 95 frame accesses,
versus Greedy's 518 bytes with one frame access; Wasmtime 45 emitted 688 bytes.
These are code-shape observations, not instruction counts or guarantees of
runtime speed. The prior frozen analysis is available at
[research evidence](https://github.com/zoowii/DTVM/blob/11a8bbaa8f339453709167a1a327ff877451472c/docs/changes/2026-11-06-fast-ra-liveout/README.md).

The production change uses no function IDs, names or benchmark-specific checks.
It adds an experimental, default-off way to upgrade repeatedly called private
WASM loop helpers. It does not address one-shot long loops or replace live frames.
Compiler, runtime, CLI and tests are affected; the guest ABI is unchanged.

## Design

1. Compile normal FastRA. Eligible helpers are private (including exclusion of
   start and hinted entry), at most 768 source bytes and 32 locals by default,
   without guest calls or memory/global/table effects, with actual WASM loops
   and at least two spill slots. Source bytes exclude local declarations.
2. Install a native entry counter. Default warmup is 10,000 calls. One-shot loops
   therefore get no backedge instrumentation or extra compilation.
3. At the warmup threshold reserve a unique-function/source-byte admission.
   `calls` queues Greedy directly. `loops` and `budgeted` compile a second FastRA
   body with preserve-all native ticks at loop headers. A profiling entry gate
   also counts calls. The sample stops after min(loop threshold, 4096) header
   visits, including first entries. Then restore the original FastRA body.
4. Use sample visits/call to calculate another entry-counter quantum. `loops`
   requires at least the configured estimated loop work (default 1,000,000).
   `budgeted` also requires projected savings to repay estimated compilation,
   probe and counter overhead. It rejects a sample whose estimated per-call
   savings cannot cover the entry counter. On quantum completion queue Greedy.
5. Publish future calls to Greedy, retaining old bodies until module destruction.

The nominal savings model uses min(2 × spill slots, 16) saved operations per
loop visit, 3 operations/ns, an 8 ns entry tick and a 30 ns sample tick. Predicted
Greedy compilation is max(32 × measured initial FastRA elapsed time, 0.1 ms);
profile compilation is measured. Default benefit ratio is 2. These constants
are heuristics, not bounds: the runtime cannot know remaining work or guarantee
payback. Initial calibration found about 6.7 ms Greedy versus 0.35 ms FastRA,
so the earlier experimental factor of 4 was rejected before final validation.

Hard per-module limits default to 4 admitted functions and 16,384 source bytes.
Each function is admitted once, with no refund after failure. Both profiling and
Greedy compilation share a serialized, soft 20 ms elapsed budget. One active
compile may overrun; queued tasks check again immediately before compiling.
Failures are charged too. Exhaustion retires profiling gates. Initial entry gate
pages are capped at min(64, 4 × max admitted functions); two extra pages per
admitted sampled helper are possible. Per-function metadata remains O(module
functions). Code is retained, so profiling consumes additional code memory.

## Publication and native state

Profile transitions use expected-target CAS and cannot overwrite canonical
Greedy code. Foreground compilation is serialized when the policy is active.
Budget tasks use independent worker contexts. Workers join before gate cookies
and counters are freed. Callback exceptions cannot unwind through assembly.

The x86-64 tick preserves GPRs and FXSAVE64 state (x87 and XMM0–15); arithmetic
flags and unsaved AVX/AVX-512 extensions are modeled as clobbered. Gates occupy
separate code-pool pages. This follows the existing lazy stub patching mechanism.
There is no OSR: an already active profiling frame can retain inactive CALL/RET
ticks until it returns, even though subsequent calls use original FastRA.

## Compatibility and controls

Only lazy MT with more than one internal function, Greedy enabled and non-SGX
activates the policy. Eager, serial, explicit FastRA and zero admission/time
budgets leave it inactive. Default is off. Positive call/loop thresholds and
benefit ratio are required when enabled. Timing and counters affect scheduling,
not guest semantics. Host timing makes tier schedules nondeterministic, as with
the existing background compiler; guest results must remain deterministic.

Flags: `--enable-lazy-private-tiering`, `--lazy-tier-policy calls|loops|budgeted`,
`--lazy-tier-call-threshold`, `--lazy-tier-loop-threshold`,
`--lazy-tier-max-functions`, `--lazy-tier-max-bytes`,
`--lazy-tier-max-function-bytes`, `--lazy-tier-budget-ms`,
`--lazy-tier-benefit-ratio`. `--enable-statistics` reports admission, publishes,
measured sample heat and estimated heat separately; disable it for benchmarks.

## Implementation and verification

- [x] Native entry/loop gates and preserved-register lowering.
- [x] Eligibility, bounded sample, benefit estimate, hard admission and soft time budget.
- [x] Calls/loops/budgeted ablations and CLI controls.
- [x] Arguments across FastRA/profiling/Greedy, including integer/FP/stack arguments.
- [x] One-shot rejection, disable switches, byte/size rejection, benefit rejection.
- [x] Concurrent admission/gate crossing and failed-compilation time accounting.
- [x] 14 unit tests, 98 MIR tests, 97 WAST cases each in interpreter, singlepass,
      multipass eager and multipass lazy with private tiering enabled.
- [x] Final production-binary timing, 17-case screen and parameter sensitivity.

Spec fixtures are generated after applying `tests/wast/spec.patch`; the patch is
reversed in the submodule after tests. Production benchmarking has SPEC/ASAN/EVM/
profiler/logging disabled; tests use a separate SPEC-enabled build.

## Build reference

The original 17-case advantage table used main `193b8d2`, not this opt-in
policy. The saved CMake cache corresponds to the following Release build
(GCC 14.2, LLVM 15; substitute your LLVM installation path). Build main and
candidate checkouts separately with identical options:

```sh
cmake -S . -B build-release -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=gcc-14 -DCMAKE_CXX_COMPILER=g++-14 \
  -DLLVM_DIR=/path/to/llvm-15/lib/cmake/llvm \
  -DZEN_ENABLE_MULTIPASS_JIT=ON -DZEN_ENABLE_SINGLEPASS_JIT=ON \
  -DZEN_ENABLE_CHECKED_ARITHMETIC=ON -DZEN_ENABLE_BUILTIN_WASI=ON \
  -DZEN_ENABLE_SPEC_TEST=OFF -DZEN_ENABLE_ASAN=OFF -DZEN_ENABLE_EVM=OFF \
  -DZEN_ENABLE_PROFILER=OFF -DZEN_ENABLE_JIT_LOGGING=OFF \
  -DZEN_ENABLE_LINUX_PERF=OFF
cmake --build build-release --target dtvm -j 2
```

Release C++ flags are `-O3 -DNDEBUG`. For the original table, select lazy MT
at runtime without the new private-tiering flag:

```sh
taskset -c 0 ./build-release/dtvm -m multipass --enable-multipass-lazy \
  benchmarks/paper/benchmarks/wapm/base64cli.wasm --args encode helloworld
WASMTIME_CACHE=0 taskset -c 0 /path/to/wasmtime-45 run -C cache=n \
  benchmarks/paper/benchmarks/wapm/base64cli.wasm encode helloworld
```

Wasmtime was the existing `wasmtime 45.0.0 (377cd917a 2026-05-21)` artifact,
not rebuilt in this study. Its repository build script runs `cargo build
--release -j6` inside the Wasmtime source checkout. This describes the script,
not independently verified provenance of every build option in that artifact.

## Experimental protocol

Frozen upstream main is `193b8d2e8ddeb54af974bc8a2b9cc52b838de8b2`.
Linux x86-64, AMD EPYC 9V74, GCC 14.2, LLVM 15, Release `-O3 -DNDEBUG`.
All engines and their child threads are pinned to CPU 0. Independent processes,
warm file-page cache, Wasmtime 45 compilation cache disabled (`-C cache=n`).
Measure Python pre-spawn through process exit, including startup, compilation,
execution and teardown. One excluded warmup, randomized engine order within each
round. No concurrent builds, tests or profiles during formal timing. This is one
machine/CPU-affinity configuration, not a multi-host throughput claim.

The first 7-round pilot and 31-round factor-4 confirmation are exploratory and
retained under their original labels. Factor-32 final timing uses a new seed.
Always include upstream main, policy-off candidate and Wasmtime 45, plus policy
ablations. Compare paired within-round ratios and bootstrap 95% intervals, not
only ratios of group medians. Preserve commands, input/binary hashes, exits and
output hashes. Validate deterministic outputs; UUID/fortune-style programs need
not emit identical text across runs.

Reproduce from the repository root (paths point at frozen binaries):

```sh
python3 docs/changes/2026-11-06-private-loop-tiering/benchmark.py \
  --main /path/to/dtvm-main --candidate /path/to/dtvm-candidate \
  --wasmtime /path/to/wasmtime-45 --out /path/to/new-results \
  --cases pi,pi100,pi1000,fib_iter_dev,base64cli,echo,md5 \
  --repeats 31 --seed 2026110616
```

## Results and limitations

Final production SHA-256: `ed77ecc2816738e2a7a8c97de3a8ea991da32a252624b43bb1fdb815e1f2ecfd`.
A final review corrected the existing xchg input-only operand to read/write;
the rebuilt production binary was byte-identical to the frozen 31-round binary.
The register mask also correctly marks unsaved AVX/AVX-512 state as clobbered.

Final confirmation, 31 rounds, medians in milliseconds:

| Case | Main | Candidate off | Calls | Loops | Budgeted | WT45 |
|---|---:|---:|---:|---:|---:|---:|
| base64cli | 126.576 | 123.025 | 123.082 | 123.414 | 124.735 | 498.806 |
| echo | 27.016 | 28.074 | 27.034 | 27.995 | 28.259 | 39.534 |
| fib_iter_dev | 23.258 | 24.114 | 23.609 | 23.795 | 23.978 | 15.887 |
| md5 | 28.397 | 28.138 | 29.002 | 29.542 | 29.395 | 43.404 |
| pi | 26.436 | 26.877 | 26.273 | 27.351 | 26.778 | 38.894 |
| pi100 | 35.810 | 35.735 | 36.050 | 37.187 | 36.684 | 47.555 |
| pi1000 | 623.597 | 628.795 | 555.514 | 554.318 | 563.338 | 560.139 |

For pi(1000), paired budgeted/main ratio is **0.9008** (bootstrap 95%
**0.8842–0.9096**), budgeted/off **0.8964** (0.8856–0.9044), and
budgeted/WT45 **1.0007** (0.9839–1.0132). Thus about 9.9% less time than main;
no demonstrated win against WT45. Calls/main is 0.8776 and loops/main 0.8843:
the joint estimator has **not** surpassed the simpler calls policy.

pi(100) pays a measured profiling toll: paired budgeted/off 1.0245
(1.0084–1.0609). Echo's budgeted/main ratio is 1.0508 (1.0110–1.0970),
whereas budgeted/off is 1.0291 (0.9774–1.0607). The latter does not isolate
a clear policy effect. These are pointwise exploratory intervals without
multiple-comparison correction. Do not describe short-case results as zero
regression. Fib remains slower than WT45 and gains no stable benefit.

Parameter sensitivity, pi(1000), independent 11 rounds (all include main/off/WT45):

| Configuration | Median ms | Paired ratio vs main |
|---|---:|---:|
| budget0 | 594.134 | 1.0130 |
| budget1ms | 540.898 | 0.9229 |
| budgeted | 543.642 | 0.9029 |
| heat8m | 556.137 | 0.9125 |
| main | 592.228 | 1.0000 |
| off | 606.905 | 1.0016 |
| warm100k | 541.036 | 0.9009 |
| warm1k | 545.248 | 0.9281 |
| wt45 | 537.705 | 0.9039 |

`warm1k`/`warm100k` change call warmup to 1,000/100,000; `heat8m`
raises the heat threshold to 8,000,000. `budget1ms` and `budget0` change
elapsed compile budget. Budget zero removes the gain. Budget 1 ms can still
upgrade: it is a **soft** cap; a diagnostic run spent 1.996 ms because a Greedy
compile started below the limit and was allowed to complete. Do not call this
a hard deadline. Default gain also repeated in this independent set (paired
ratio 0.9029, 95% 0.8822–0.9200).

Independent diagnostic runs (not timed data) showed pi(1) admitted zero helpers,
pi(100) published a profile but no Greedy, and pi(1000) published both. The
measured sample was 4096 visits; millions of reported estimated visits are
extrapolations, not measured loop counters. At an 8-million heat setting,
publication waited for that estimate, versus about 5.7 million with the default
profit gate in one diagnostic run. Diagnostics perturb scheduling; they are not
per-round traces of the formal samples.

The 17 canonical short WAPM cases were also screened in 7 new rounds. All
remained faster than WT45 under this process-level boundary, but that advantage
predates this feature. The screen is too small/noisy to establish broad policy
non-regression; full medians and samples are retained with the evidence.

A one-shot long invocation cannot switch tier without OSR. Sampled density can
change with workload phases, and spill slots need not measure spills in a hot
loop. Code memory, inactive calls in live profiling frames, short-case overhead,
and cost-model transfer to other machines remain limitations. This PR keeps
the policy opt-in and exposes ablations for further study. No overall WAPM win
rate, guaranteed profitability or default-policy improvement is claimed.

Full commands, raw samples, output hashes, diagnostics, verification logs and
bootstrap analysis: [immutable evidence](https://github.com/zoowii/DTVM/tree/3fbb002b68d6776a5c005c5d131e2aa2081b2578/docs/changes/2026-11-06-private-loop-tiering/evidence).
