# Change: Restore lazy throughput for small numeric loop nests

- **Status**: Implemented
- **Date**: 2026-11-06
- **Tier**: Light

## Problem and causal diagnosis

PR #632 made lazy MT queue background Greedy only for start/exports, avoiding
speculative compilation of unused libc/table targets. Private functions compile
FastRA on demand and can remain there for their entire first invocation.
PolyBench gemm/2mm inline their large computations into an unexported main,
called once through exported WASI wrappers. A later stub upgrade cannot replace
an already running frame. This change is independent of private hot-function
promotion and contains none of that branch's runtime instrumentation.

On pristine upstream main 193b8d2, a 3-round mode pilot reproduced 2mm at
8200.9 ms lazy MT versus 2385.7 ms eager Greedy / 2526.0 ms serial lazy Greedy;
gemm was 3125.2 versus 2004.0 / 1909.8 ms. The discrepancy is primarily execution
quality, not just compilation. Instrumented gemm compilation totals were tens
of milliseconds, while wall time was seconds. These diagnostic sums are not
exclusive phases: overlapping worker elapsed times must not be subtracted
from wall time.

## Policy

Keep #632 background scheduling unchanged. On foreground demand in lazy MT,
construct MIR once, then choose initial Greedy when:

- Greedy is not explicitly disabled;
- source body is at most 2048 bytes, excluding local declarations;
- there is f32/f64 add/sub/mul/div inside at least two nested WASM loops;
- a qualifying loop subtree contains no emitted guest call/call_indirect.

The effects belong to structured blocks and merge upwards at block exit.
Check a loop only after its complete subtree has been seen, including calls
occurring after FP arithmetic. A call outside a qualifying inner loop does not
exclude the function. This permits allocation/printing outside matrix kernels
while rejecting call-heavy numeric wrappers. Existing control frames carry two
boolean facts; there is no extra IR traversal, guest counter, second foreground
compilation, OSR, deferred promotion or new background task. An existing export
background race can still produce its own body, as before.

Eager, serial lazy, single-internal-function behavior and explicit FastRA keep
their allocator choices. Foreground publication still CASes only from the
trampoline and cannot overwrite canonical background Greedy. The internal
compiler helper returns whether this selection happened; its observable count
is not a publication barrier. Public runtime/C APIs and the guest ABI are unchanged.

Review also corrected a control-frame lifetime issue in the modified handler:
Info aliases the top frame, so next-block/reachability values must be captured
before popping it and updating its parent.

## Assembly evidence

Native dumps from the final policy build confirm only internal function 2
(global 9, main) is selected in each matrix case. Diagnostic IDs identify the
observed code; production has no name, ID or benchmark path checks. Capture
Wasmtime 45 live main through perfmap and /proc of our own child process, rather
than presenting an AOT listing as live JIT evidence. Native code and extraction
scripts are retained with the evidence.

| Minimal compute loop | Main FastRA instructions / frame accesses | Initial Greedy | WT45 live |
|---|---:|---:|---:|
| gemm | 24 / 8 | 14 / 0 | 14 / 0 |
| 2mm first product | 25 / 10 | 12 / 0 | 14 / 0 |
| 2mm second product | 23 / 9 | 11 / 0 | 13 / 0 |

These are static counts inside the minimal backward-edge intervals containing
FP multiply and add, not measured retired instructions. Whole-body disassembly
can include literal pools. DTVM keeps loop-carried values and the hoisted alpha
constant in registers; WT45's first 2mm product reloads alpha and uses extra
move/branch instructions. Both are scalar computations; VEX mnemonics do not
imply vectorized kernels. Final-policy loop bytes matched the earlier Greedy
prototype byte-for-byte. No guest arithmetic reassociation or memory-address
folding is introduced here.

## Experimental refinement and negative results

All versions and negative results are retained, without pooling samples:

1. A 4 KiB, FP-nesting-only prototype improved the matrix kernels but regressed
   viu about 9% in an independent 21-round retest. Its only selected helper was
   a roughly 3.1 KiB thumbnail routine whose short workload did not repay
   foreground Greedy compilation. Tighten the input-size gate to 2 KiB.
2. The 2 KiB prototype repaired viu, but a further 21-round check confirmed
   pi(1) about 16% slower. Its 1280-byte main has nested FP arithmetic with calls
   to mathematical helpers. Require a call-free qualifying loop region.
3. Initial 3-round bicg and 7-round suggest negatives did not repeat in their
   independent 21-round followups. No benchmark-specific exclusions were added.
4. Repeat final-policy comparisons with new randomized seeds after both
   refinements. These are independent process runs, not blind workload holdouts:
   the earlier screens informed policy design.

The size/depth/effect rule estimates the usefulness and cost of initial global
allocation; it does not know runtime trip counts or guarantee profitability.
Integer-only loops, bodies over 2 KiB, call-heavy regions and short pure numeric
loops remain limitations. This does not claim to fix every PolyBench regression.

## Final measurements

Final production binary SHA-256:
`511d01c98bf11a66d4daadc2f2b036e3b0ba6eaea67a6009be1ff23c407065ca`.
Main is pristine 193b8d2e8ddeb54af974bc8a2b9cc52b838de8b2; current upstream tip
was checked before publication. The DFS control uses a separate diagnostic build
of the same final source, restores old scheduling and disables the selector.
Trace/statistics hooks are off during timing and absent from production.

Nine-round confirmation, medians in milliseconds:

| Case | Main | DFS control | Fix | WT45 |
|---|---:|---:|---:|---:|
| 2mm | 8329.018 | 2687.656 | 2733.384 | 3284.590 |
| gemm | 2918.905 | 2000.592 | 1942.351 | 2762.105 |

Paired median time ratios (fix/reference), 10,000-resample percentile bootstrap:

| Case | Fix / main, 95% interval | Fix / WT45, 95% interval |
|---|---:|---:|
| 2mm | 0.3199 [0.2851, 0.3515] | 0.7965 [0.7223, 0.8424] |
| gemm | 0.6535 [0.6038, 0.7199] | 0.7360 [0.6882, 0.7676] |

Ratios above are medians of within-round ratios, not ratios of the displayed
group medians. DFS controls can be bimodal: background Greedy may miss the first
invocation, leaving that live frame FastRA. This race is unchanged by publishing
better code later. Source/native evidence explains the mechanism; timing alone
is not a per-round tier trace.

Additional breadth screen, three rounds, medians in milliseconds:

| Case | Main | Fix | WT45 |
|---|---:|---:|---:|
| atax | 79.956 | 63.928 | 65.266 |
| bicg | 72.350 | 75.924 | 73.193 |
| fdtd-2d | 6434.572 | 5478.532 | 7501.405 |
| gemver | 124.044 | 88.110 | 77.989 |
| jacobi-2d | 6308.533 | 4944.176 | 5829.525 |
| syrk | 2879.072 | 2114.132 | 2942.122 |

Startup and previously problematic cases, 21 new rounds:

| Case | Main ms | Fix ms | WT45 ms | Paired fix/main, 95% interval |
|---|---:|---:|---:|---:|
| base64cli | 123.675 | 125.044 | 523.067 | 1.0127 [0.9653, 1.0259] |
| bicg | 86.576 | 85.486 | 84.250 | 0.9870 [0.9556, 1.0769] |
| cowsay | 148.464 | 149.776 | 470.338 | 0.9777 [0.9504, 1.0451] |
| md5 | 34.672 | 36.063 | 52.383 | 1.0207 [0.9883, 1.0729] |
| pi | 33.640 | 34.217 | 48.057 | 1.0798 [0.9542, 1.1358] |
| suggest | 120.611 | 126.147 | 534.514 | 1.0351 [0.9639, 1.0960] |
| viu | 254.991 | 264.888 | 1324.677 | 1.0023 [0.9878, 1.1046] |

The separate 17-case WAPM screen has seven rounds. Small screens and confidence
intervals crossing 1 do not establish equivalence or universal non-regression.
All intervals are pointwise, without multiple-comparison correction. Do not
combine different versions, input sizes or timing boundaries into a win rate.
The old scheduling control's startup penalty is preserved separately: in the
earlier 21-round ablation, base64/cowsay/md5 took about 998/1450/134 ms under
DFS, versus about 123/149/31 ms with entry-only scheduling and numeric selection.

## Protocol and reproduction

Linux x86-64, AMD EPYC 9V74, GCC 14.2, LLVM 15, Release `-O3 -DNDEBUG`.
Multipass and singlepass built ON; SPEC/ASAN/EVM/profiler/JIT logging/perf OFF
for production timing; WASI and checked arithmetic ON. Main/candidate/control
use identical options. Tests use a separate SPEC-enabled build.

All engines and workers pin CPU 0. Fresh processes, warm file-page cache,
Wasmtime 45 compilation cache disabled with `-C cache=n`. Time pre-spawn through
subprocess return, including startup, compile, execution, captured output and
teardown. PolyBench prints complete matrices on stderr; these are included in
all engines' process times. This is not isolated kernel timing or TTFI.
One excluded warmup per engine/case; randomized within-round engine order.
No builds/tests/profiles run during formal sessions. This is one host/affinity
configuration, not a universal multi-host throughput claim.

Every process exited 0. Full stdout AND stderr hashes match for each numeric
case across rounds and engines, including the full result matrices. Deterministic
WAPM controls are checked too; UUID-style outputs can vary. Full dumps remain
in the executor, compressed and deduplicated; the published archive retains
hashes, byte counts and previews rather than duplicating huge matrices.

Wasmtime 45 is the existing repository artifact (version 45.0.0, 377cd917a),
not rebuilt for this experiment; its hash is recorded. No claim is made about
independently verifying every historical Wasmtime build option.

Example from repository root, after building matching main/candidate binaries:

```sh
python3 docs/changes/2026-11-06-lazy-numeric-loop-firstcall/benchmark.py \
  --main /path/to/main-193b8d2/dtvm --candidate /path/to/fix/dtvm \
  --wasmtime /path/to/wasmtime-45 --variants main,candidate,wt45 \
  --cases gemm,2mm --rounds 9 --seed 2026110634 --out /path/to/new-results
```

DFS ablations additionally require the archived diagnostic patch/binary and
`--revert /path/to/diagnostic --variants main,candidate,revert,wt45`. The driver
sets its research-only scheduling environment switch. Production has no such
switch. All exact commands, hashes, seeds, samples and scripts are archived.

## Validation and review

- [x] 9 lazy JIT tests, including first-invocation FP32/FP64 selection, sibling
      loops versus nested blocks, FP outside loops, 2–4 KiB rejection, direct and
      indirect calls after FP arithmetic, calls outside qualifying regions,
      cold-function exclusion, alias reuse, eager/serial/explicit-Fast behavior.
- [x] 98 MIR tests.
- [x] 97 WAST cases in each of lazy MT, eager multipass, singlepass, interpreter.
- [x] Fixtures generated with tests/wast/spec.patch applied; submodule restored.
- [x] Repository clang-format 15 / cmake-format checks.
- [x] Publication/lifetime review; no extra background queue traversal.
- [x] Independent final-policy comparisons and native code verification.

Only Linux x86-64 was exercised locally; CI and other hosts remain separate
validation. The source-size limit guards compilation input, not elapsed time.

## Archived evidence

[Immutable raw samples, assembly, validation logs and implementation snapshot](https://github.com/zoowii/DTVM/tree/7eb9a80443233f0399efa4815e4fa78750f78cae/docs/changes/2026-11-06-lazy-numeric-loop-firstcall/evidence).

## Rebase integration

Rebased onto upstream main 59fe3cc (#641 private loop tiering). Preserve its loop
profiling argument and metadata alongside initial allocator selection. Functions
already selected for initial Greedy bypass private FastRA entry/profiling gates.
The measurements above remain against historical 193b8d2; they are not new
measurements against 59fe3cc. The immutable archive describes the pre-rebase
source snapshot.

Rebase validation: Release lazy JIT target rebuilt successfully; all 16 tests
from 4 suites passed, including numeric selection with private tiering both
enabled and disabled, and the upstream private-tiering/budget/gate tests.
Repository formatting and diff checks passed. Full WAST/MIR results above are
from the pre-rebase validation; they were not rerun for this integration.
