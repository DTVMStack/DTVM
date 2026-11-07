# Anonymous zero tail: final implementation and experiments

PR643 was reviewed at d6f31ef: all 17 checks passed, including both performance
gates, and it merged as 3cb4f2e. No reproducible CI failure or blocking defect
required a speculative fix. See [CI review](evidence/pr643-review.json).
This is a separate runtime optimization based on that merged upstream main.

Final production source: **7cbf6294adb37f5e0ee1aa81a2e076fca240d346**.
Main: **3cb4f2e30c4024c95390c1b72147c2c7ea155632**. Full hashes/flags/commands
are in [build metadata](evidence/build.json) and cohort manifests.

## Change and correctness

Bucket eligibility already requires constant active data segments inside the
module's initial memory. Keep that entire file-backed data prefix intact.
On the first positive in-bucket grow (old size equals the module initial size),
replace only the unused tail through the owned 32 MiB item boundary with private
anonymous PROT_NONE pages. Existing mprotect exposes exactly the requested size.
Memory is monotonic, so later growth reuses the anonymous reservation without
another mmap. No additional tracking field, workload threshold or names/IDs.

This retains initial data sharing, prior writes, base addresses, neighbouring
items and guard permissions. New bytes are zero; metadata/protection and bucket
retirement span both backing types. Growth beyond the bucket limit keeps the
existing allocate/copy fallback. Mapping failures follow the existing abort
convention. No JIT pass, allocator selection or background policy changes.

PR644 review found that SGX mmap does not implement fixed-address replacement
and its headers omit MAP_FIXED/MAP_FAILED. The new remap block is excluded from
SGX; its previous path is retained. All24 Release tests pass after the guard.
A syntax smoke check of the actual block against the real SGX mmap header
passes for SGX and non-SGX; this does not replace a full SGX SDK build.

Two exercised tests cover modified-prefix persistence, successive/zero/failed
growth, OOB, independent instances,12-instance bucket retirement and >32MiB
fallback. All24 unit tests pass in Release and ASan(O1/NDEBUG, virtual stack off,
exit0). All97 WAST cases pass separately in lazy MT/eager/singlepass/interpreter.
Production uses ASan-off Release artifacts. Logs are retained.

## Canonical production comparisons

GCC14.2/LLVM15, Linux x86-64 AMD EPYC9V74, two-core cgroup quota. Engine and all
workers CPU0; phase collector CPU1. Fresh processes, randomized within-round
order, excluded warmup, warm input cache, WT45 cache disabled. No concurrent
builds/tests/profiles during formal timing. WT45 is an existing release artifact.

The main reference is frozen e4881cae… built at19af308; its entire src tree is
identical to merged main3cb4f2e (git diff verified). It is source-equivalent main,
not a new main rebuild. Do not pool binaries, boundaries or cohorts as a win rate.

31 measured processes per case/engine. Group medians in milliseconds include
startup, compilation, execution, captured output and teardown. Positive reduction
means faster. Outputs match byte-for-byte on all four canonical workloads.

| Case | Main | Final | Wasmtime45 | Reduction vs main | Reduction vs WT45 |
|---|---:|---:|---:|---:|---:|
| atax | 62.574 | 51.526 | 62.768 | +17.7% | +17.9% |
| bicg | 70.403 | 60.839 | 70.067 | +13.6% | +13.2% |
| gesummv | 57.316 | 49.991 | 57.329 | +12.8% | +12.8% |
| trisolv | 51.196 | 45.147 | 52.826 | +11.8% | +14.5% |

Within-round paired candidate/main median ratios, pointwise95% intervals:

- atax: 0.8197 [0.7896, 0.8439].
- bicg: 0.8650 [0.8477, 0.8828].
- gesummv: 0.8708 [0.8415, 0.8869].
- trisolv: 0.8648 [0.8466, 0.8982].

Fixed-seed10,000-resample percentile bootstrap; no multiple-comparison correction.
Ratio estimates differ from reduction of separate group medians. One host and
selected targets do not establish a universal or multi-host advantage.

## First result, cold initialization and warm execution

Nine independent processes per count/engine on identical derived atax/bicg
Wasm, counts1 and8. Original exports stay memory/_start; main remains private.
Each original_main retains main's allocation/init/free/stack restoration.
Constructors/dtors run once. CRT argv allocation has one-shot lifetime and can
accumulate modestly across repeats; this is not full-process state reset.

Seven WASI monotonic stamps separate wrapper/main admission, allocation, vector
init, matrix init, kernel and output/free. A packet reports a result before main
returns. Parent receipt is not pure function-return latency; admission includes
argv-wrapper work and demand compilation, not pure JIT. WT compiles before that
stamp, so compare first result/process too, not its near-zero admission alone.

The Binaryen roundtrip normalizes code (atax main688→614 bytes, bicg823→710),
all below the2048 allocator cap. Clock calls are outside original loop subtrees
but can affect function liveness/layout. These are modified-input diagnostics,
not an exact decomposition of canonical native code. Scratch8..76 precedes data
at1024; direct-access scan and all-run canonical*N output checks are retained.
The scan alone is not a complete dynamic alias proof.

Count1 medians, milliseconds:

| Phase | Atax main | Atax final | Atax WT45 | Bicg main | Bicg final | Bicg WT45 |
|---|---:|---:|---:|---:|---:|---:|
| First result receipt | 56.484 | 47.989 | 59.899 | 66.096 | 59.647 | 68.482 |
| Main admission | 7.409 | 7.064 | .017 | 7.684 | 7.593 | .015 |
| Cold matrix init | 20.601 | 13.317 | 13.453 | 21.053 | 13.339 | 13.763 |
| First kernel | 6.500 | 6.692 | 7.935 | 14.504 | 14.837 | 14.302 |
| Full process | 61.117 | 51.078 | 62.075 | 71.203 | 62.641 | 70.931 |

Count8: per-process medians of calls2..8, then group medians. Repeated calls are
not treated as independent statistical samples.

| Phase | Atax main | Atax final | Atax WT45 | Bicg main | Bicg final | Bicg WT45 |
|---|---:|---:|---:|---:|---:|---:|
| Warm matrix init | 5.515 | 5.526 | 5.212 | 5.611 | 5.629 | 5.354 |
| Warm kernel | 6.566 | 6.674 | 8.051 | 15.000 | 15.001 | 14.209 |
| Post-last-result tail | 5.577 | 3.670 | 2.200 | 7.186 | 3.659 | 2.443 |
| Full process | 161.478 | 152.080 | 178.644 | 239.605 | 235.939 | 248.177 |

Benefits concentrate in cold initialization and cleanup; warm arithmetic has
not accelerated. Bicg still trails WT45 in warm computation. Tail includes guest
dtors, late compilation and runtime/OS cleanup, not only workers. Untimed compile
traces identify four late cold functions totaling about0.8–1ms; they do not alone
explain the tail. No exact per-component cleanup causality is claimed.

## Negative control and refinement

V1(source6cd5d65) remapped each newly grown range. A no-touch loop of511 successful
one-page grows exposed its extra syscall cost. We rejected that implementation
before publication and changed to one inaccessible reservation on first growth.
Same-input31-round control, milliseconds, one cohort containing all four engines:

| Engine | Grow-call interval | Full process |
|---|---:|---:|
| Main | .849 | 7.420 |
| Rejected per-grow v1 | 1.188 | 7.440 |
| Final once-only version | .802 | 7.342 |
| Wasmtime45 | .145 | 6.648 |

The internal call interval includes first-demand compilation/background overlap;
it is not a pure syscall timer. All end at512 pages without touching extensions.
A separate strace confirms one page-aligned fixed anonymous mmap for the final
instance, versus none for main; the v1 source calls mmap for every positive grow.
Raw rows and input are in [growth-no-touch](evidence/growth-no-touch/).
This control supports removing the repeated mapping cost, not universal parity
with WT45 growth performance.

Separate untimed proc-maps snapshots show the final's initial128KiB file-backed,
grown accessible pages anonymous, unused anonymous tail still PROT_NONE through
the32MiB item boundary, and file-backed guard beyond it. Both captures use30
calls and match full numerical output. See [final maps](evidence/growth-maps-final.json).
The same-binary early probe's total minor-fault counts stayed essentially equal
(atax10783/10785,bicg10785/10788 bucket/anonymous). Do not claim fewer faults;
the evidence is consistent with changing backing/handling and cleanup cost.
THP was madvise, shmem THP never; no huge-page advice was added.

## WAPM and larger-case controls

Final source, seven-round full catalog screen, medians in milliseconds:

| Case | Main | Final | WT45 |
|---|---:|---:|---:|
| amirali | 5.440 | 5.934 | 5.356 |
| base64cli | 106.839 | 106.963 | 445.892 |
| chkfont | 36.144 | 36.653 | 70.299 |
| code-stock | 21.638 | 21.525 | 81.524 |
| cowsay | 120.827 | 121.099 | 396.591 |
| dice | 22.168 | 20.830 | 37.001 |
| echo | 25.409 | 26.373 | 37.053 |
| erdtree | 55.337 | 54.876 | 152.865 |
| figlet | 52.208 | 51.758 | 113.408 |
| fortune | 63.187 | 64.585 | 117.619 |
| irb | 3806.597 | 3812.795 | 9526.390 |
| md5 | 29.455 | 27.801 | 41.125 |
| pi | 28.487 | 27.775 | 40.914 |
| pkg1 | 26.261 | 23.981 | 92.524 |
| qr2text | 55.245 | 56.874 | 125.297 |
| suggest | 92.673 | 95.788 | 417.517 |
| tpl | 281.226 | 281.995 | 786.450 |
| uuid | 83.777 | 80.812 | 471.405 |
| viu | 236.039 | 242.037 | 1233.263 |

19 cases succeed; sam exits1 on all engines and is excluded. Fortune/UUID vary;
other deterministic outputs match. Screen ratios for chkfont,qr2text,suggest,viu
were respectively1.0201,1.0834,1.0216,1.0331, with pointwise intervals above1.
Independent31-round confirmation retains all negatives and does not pool them:

| Case | Main | Final | WT45 | Paired final/main,95% interval |
|---|---:|---:|---:|---|
| amirali | 6.221 | 6.055 | 6.215 | 0.9910 [0.9249, 1.0567] |
| base64cli | 112.370 | 111.218 | 466.057 | 0.9761 [0.9589, 0.9844] |
| chkfont | 39.659 | 40.095 | 75.525 | 1.0012 [0.9861, 1.0120] |
| qr2text | 51.915 | 51.905 | 120.455 | 0.9906 [0.9776, 1.0219] |
| suggest | 95.080 | 94.712 | 413.569 | 0.9962 [0.9783, 1.0179] |
| viu | 235.490 | 232.623 | 1227.144 | 0.9770 [0.9653, 0.9871] |

Those negatives did not repeat. Crossing1 is not proof of equivalence.
Five-round large FP controls:

| Case | Main | Final | WT45 |
|---|---:|---:|---:|
| 2mm | 2208.041 | 2213.034 | 2738.661 |
| gemm | 1620.601 | 1648.024 | 2167.802 |

Both paired intervals cross1; no reliable FP speedup/equivalence claim. This is
not a fresh all30-PolyBench rerun. V1 data and followups remain separately
labelled in evidence/summary.csv and the superseded-v1 report; never pool them
with this final source.

## Other research, held back

A variable i32 MOV+ADD→three-address LEA prototype at405aa1a passed102 MIR tests
and98 WAST cases in lazy/eager plus explicit-Fast wrap/OOB checks. Fresh bicg
native compute-loop ranges: current0x237..28f has22 instructions/0 frame accesses,
LEA0x238..28b has19/0, WT45 live0x222..28c has21/3. Static improvement did not
translate into repeatable canonical/phase benefit. No such JIT change is shipped.
Native dumps come from a separate diagnostic artifact; WT code was read from our
own live perfmap-enabled child with matching output. Counts are not retired ops.

An8→1 worker counterfactual also produced small/mixed improvements that did not
repeat clearly in phase results. AuxContexts are lightweight copies; only used
contexts initialize LLVM, so8 idle workers are not8 initialized LLVM compilers.
No worker policy change is included. Both alternative studies and diagnostic
patches are retained, not relabelled as accepted optimizations or CI repairs.

Follow-up source investigations, not implemented or benchmarked here: single
mapping growth after bucket fallback still uses the allocator-wide bucket cap,
potentially causing repeated full copies; and zero-only initial BSS might be
separable from actual initialized-data image pages. Each needs its own controlled
experiments and correctness review. No benefit is claimed from these notes.

## Reproduction and scope

Production ASan-off build;24 Release/24 ASan tests;97 WAST cases in each of four
engines; format/diff checks. ASan/profiling/builds run outside performance timing.
Full flags, hashes, raw gzip rows and source revisions accompany each cohort.
No multi-host, equivalence or universal no-regression claim is made.

```sh
python3 docs/changes/2026-11-07-anonymous-grown-pages/benchmark.py \
  --suite polybench --cases atax,bicg,gesummv,trisolv --rounds 31 \
  --seed 2026110780 --out /tmp/new-results \
  --main /path/to/main/dtvm --main-commit 3cb4f2e \
  --candidate /path/to/new/dtvm --candidate-commit 7cbf629 \
  --wasmtime /path/to/wasmtime-45
```

Use --suite wapm --rounds 7 and fresh output for the screen.
Generate modified inputs with make_phase_inputs.py --out DIR; run phase_bench.py
with --inputs DIR --out RESULTS --main BIN --candidate BIN --wasmtime BIN
--counts 1,8 --rounds 9. Binaryen is only needed to
regenerate diagnostics. grow_control.py reproduces the no-touch control with
--main BIN --candidate BIN --wasmtime BIN --out RESULTS. All paths are relative
to the repository root. Do not overlap formal timing with other workloads.
