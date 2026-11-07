# Anonymous growth: review, experiments and evidence

PR643 was reviewed at d6f31ef. All 17 checks passed, including WASM/EVM and both
performance gates, and it merged as 3cb4f2e. No speculative CI fix was needed.
[evidence/pr643-review.json](evidence/pr643-review.json) records the jobs.
This change is independent of that merged compiler-policy PR.

## Production change and correctness argument

Source **6cd5d65fcca16c0268388b42894084d22001da60**, based on upstream main
**3cb4f2e30c4024c95390c1b72147c2c7ea155632**. Only runtime memory growth changes.
The initial data prefix retains its file-backed copy-on-write template.
Newly accessible pages inside an existing bucket item use MAP_FIXED private
anonymous mapping at the same virtual addresses. No allocator-selection rule,
JIT pass, guest counter, function-name rule or background scheduling changes.

The bucket verifier already requires active data segments to fit within initial
memory. Growth starts at the old page-aligned size and is bounded by the
bucket's 32 MiB item limit, so the replaced interval contains only newly
accessible zero bytes. Initial data, previous guest writes, neighbours and the
following protected range are excluded. Anonymous pages satisfy zero semantics.
Existing protection/size accounting still operates across the mixed VMAs;
retirement unmaps them together. Beyond the bucket limit, existing allocate/copy
fallback remains. Mapping failures follow the existing abort convention.

Two added tests exercise actual bucket mode, not skipped on this host: modified
initial-prefix persistence, repeated and zero growth, failed growth and OOB,
two instances with independent zero tails, 12 sequential instances crossing
bucket retirement, and >32 MiB fallback retaining data and new zero bytes.
The other paths retain their existing backends. No new CLI option is needed.

## Protocol and source identity

GCC14.2 / LLVM15 Release, Linux x86-64 AMD EPYC9V74, two-core cgroup quota.
Engines and workers pin CPU0; phase collector pins CPU1. Fresh processes,
randomized within-round order, warm input-file cache, one excluded warmup per
case/engine, WT45 cache disabled. No builds, tests or profiles overlap formal
sampling. Wasmtime45 is the existing release artifact, not rebuilt here.

Main uses the frozen e4881cae… artifact built from 19af308. Its entire src tree
is identical to d6f31ef and merged main 3cb4f2e (verified by git diff). This is a
source-equivalent main reference, not a newly rebuilt main binary. Full hashes,
commands, input hashes and build flags accompany every cohort. An extra old
main af4b07b control is retained in the primary cohorts, labelled previous.
Never pool binaries, cohorts or boundaries into a single win rate.

The same-binary preliminary probe compared bucket on/off with variable LEA
disabled in both modes. Disabling buckets globally also changes initial-data
copying, so that probe was hypothesis discovery only. The production experiment
below keeps initial templates and changes only grown zero pages.

## Canonical weak-case comparison

31 measured processes per engine/case. Group wall-time medians in milliseconds,
including startup, compilation, execution, captured output and teardown.
Positive reductions mean faster. All outputs match byte-for-byte.

| Case | Main 3cb4f2e | Anonymous growth | Wasmtime45 | Reduction vs main | Reduction vs WT45 |
|---|---:|---:|---:|---:|---:|
| atax | 62.968 | 53.338 | 62.854 | +15.3% | +15.1% |
| bicg | 74.608 | 68.144 | 74.949 | +8.7% | +9.1% |
| gesummv | 56.758 | 48.272 | 56.372 | +15.0% | +14.4% |
| trisolv | 50.367 | 43.747 | 53.374 | +13.1% | +18.0% |

Paired candidate/main median ratios with pointwise 95% intervals:

- atax: 0.8547 [0.8320, 0.8649].
- bicg: 0.8983 [0.8696, 0.9526].
- gesummv: 0.8394 [0.8311, 0.8554].
- trisolv: 0.8642 [0.8342, 0.8793].

Intervals use within-round ratios, fixed seed and 10,000-resample percentile
bootstrap. They are pointwise, without multiple-comparison correction, on one
host. Reduction columns use group medians and therefore differ from paired
ratio estimates. These targets were selected before the mapping prototype;
this is independent production confirmation after the diagnostic screen,
not blind new-workload validation or a universal engine advantage.

## First-result and same-instance phases

Nine independent processes per engine/count for atax and bicg, counts 1 and 8.
The same derived Wasm is supplied to all engines; exports stay memory/_start,
main stays private, and original initialization/free/stack restoration remains.
Seven WASI monotonic timestamps separate wrapper/main admission, allocation,
vector/matrix initialization, kernel and output/free. A 56-byte packet reports
results before main returns; parent receipt is not a pure function-return event.
Admission also contains argv-wrapper work and demand compilation, not just JIT.
Constructors/destructors execute once; original_main repeats in the instance.
Its CRT argv allocation has one-shot lifetime and can accumulate modestly across
repeats; do not call this full-process state reset.

Binaryen roundtrip normalizes code: main body sizes atax 688→614, bicg 823→710,
both below the 2048 selector cap. Clock calls are outside original loop subtrees
but can still affect full-function liveness/code layout. These are modified-input
diagnostics, not exact canonical phase attribution. Original data starts at 1024;
scratch 8..76 has no direct constant-access overlap. That static scan is not a
complete dynamic alias proof: every run additionally matches repeated canonical
stderr byte-for-byte and checks timestamp packets. Inputs/audit are archived.

Single-call cohort group medians, milliseconds:

| Phase | Atax main | Atax new | Atax WT45 | Bicg main | Bicg new | Bicg WT45 |
|---|---:|---:|---:|---:|---:|---:|
| First result receipt | 57.102 | 49.605 | 60.883 | 71.138 | 62.427 | 71.866 |
| Main admission | 7.362 | 7.511 | .017 | 8.270 | 8.606 | .016 |
| Cold matrix init | 21.230 | 13.292 | 13.061 | 22.892 | 14.217 | 14.903 |
| First kernel | 6.886 | 6.752 | 7.741 | 15.365 | 15.814 | 15.452 |
| Full process | 61.720 | 52.423 | 62.954 | 76.267 | 65.679 | 75.134 |

WT compilation happens before the internal admission timestamp; compare full
process/first result when assessing startup. Do not infer near-zero WT compile
cost from its admission interval.

Eight-call cohort: per-process warm medians exclude the first call, then group
medians summarize processes. Repeats are not independent statistical samples.

| Phase | Atax main | Atax new | Atax WT45 | Bicg main | Bicg new | Bicg WT45 |
|---|---:|---:|---:|---:|---:|---:|
| Warm matrix init | 5.477 | 5.178 | 5.404 | 5.560 | 5.545 | 5.352 |
| Warm kernel | 6.793 | 6.743 | 7.966 | 14.938 | 15.001 | 14.191 |
| Post-last-result tail | 7.390 | 3.782 | 2.433 | 7.321 | 3.471 | 2.492 |
| Full process | 163.149 | 152.476 | 182.464 | 238.970 | 232.121 | 248.453 |

The benefit is predominantly cold initialization and cleanup, not faster warm
arithmetic. Bicg warm execution remains behind WT45. Tail includes guest dtors,
late compilation and runtime/OS cleanup; it is not just worker waiting.
Diagnostic compile events identify four late cold functions totaling about
0.8–1ms, insufficient alone to explain the whole tail. Those diagnostic timings
are outside formal sampling and include tracing overhead.

## OS backing evidence

A separate, untimed proc-maps capture after first result shows main's accessible
region file-backed. The production candidate retains the first 128 KiB file-backed,
then maps the grown tail anonymously. Both end at the same offset 0x1ea0000 from
their respective bases; the following file-backed range remains PROT_NONE.
Both 30-call captures exit 0 with the same repeated numerical output hash.
See [growth-maps.json](evidence/growth-maps.json).

The same-binary probe's total minor-fault medians were essentially unchanged:
atax10783/10785, bicg10785/10788, gesummv9586/9586, trisolv8612/8610
(bucket/anonymous). Do not claim fewer faults. The result is consistent with
changing fault backing/handling and template cleanup costs, rather than reducing
fault count. THP was madvise, shmem THP never; no huge-page advice was added.
There is no isolated per-fault hardware-counter attribution claim.

## WAPM and larger-case controls

Seven-round full WAPM catalog screen, medians in milliseconds:

| Case | Main | New | WT45 |
|---|---:|---:|---:|
| amirali | 5.920 | 6.522 | 6.448 |
| base64cli | 109.821 | 112.739 | 461.583 |
| chkfont | 42.533 | 41.288 | 77.979 |
| code-stock | 22.171 | 21.806 | 85.141 |
| cowsay | 122.562 | 119.725 | 393.019 |
| dice | 22.338 | 21.471 | 38.214 |
| echo | 25.032 | 25.789 | 36.064 |
| erdtree | 61.107 | 61.881 | 167.210 |
| figlet | 50.632 | 49.210 | 108.578 |
| fortune | 66.525 | 66.887 | 122.100 |
| irb | 3877.481 | 3911.225 | 10067.940 |
| md5 | 28.135 | 28.893 | 42.079 |
| pi | 28.212 | 28.014 | 39.626 |
| pkg1 | 23.911 | 23.062 | 84.575 |
| qr2text | 51.972 | 51.442 | 120.676 |
| suggest | 101.190 | 97.864 | 444.953 |
| tpl | 298.880 | 288.110 | 840.548 |
| uuid | 81.306 | 81.552 | 445.499 |
| viu | 233.718 | 232.081 | 1222.954 |

Sam exits1 on every engine under the catalog invocation and is excluded.
Nineteen cases succeed. Fortune/UUID output varies; other deterministic outputs
match. All original runs, including negative signals, remain archived.

The first screen showed IRB paired1.0325 [1.0011,1.0479] and md51.0272
[1.0016,1.0754]. Independent followups did not reproduce those negatives:

| Independent followup | Rounds | Main | New | WT45 | Paired new/main, 95% interval |
|---|---:|---:|---:|---:|---|
| irb | 11 | 3845.939 | 3834.195 | 9817.023 | 0.9832 [0.9293, 1.0285] |
| amirali | 31 | 5.949 | 6.009 | 5.906 | 1.0190 [0.9367, 1.0482] |
| echo | 31 | 24.991 | 25.223 | 34.317 | 1.0062 [0.9798, 1.0409] |
| md5 | 31 | 27.667 | 27.043 | 40.194 | 0.9870 [0.9603, 1.0072] |

Do not pool screen and followup or treat crossing1 as proof of equivalence.
Large FP controls, five rounds each:

| Case | Main | New | WT45 |
|---|---:|---:|---:|
| 2mm | 2380.437 | 2226.420 | 2811.423 |
| gemm | 1854.884 | 1720.290 | 2239.456 |

Paired intervals cross1 for both; favorable point estimates are not established
speedups. This iteration does not rerun all30 PolyBench workloads.

## Alternative hypotheses retained, not shipped

Variable i32 addition with three-address LEA was prototyped at405aa1a on a
separate branch. It passed102 MIR tests and98 WAST cases in lazy/eager, plus
explicit-Fast wrap/OOB checks. Fresh diagnostic bicg native innermost loop:
current22 instructions/0 frame accesses, LEA19/0, WT45 live21/3. Ranges are
0x237..28f,0x238..28b,0x222..28c respectively. MOV+ADD→LEA removes three static
instructions, but canonical and repeated-phase runtime benefits were mixed.
Static counts are not retired operations or causal proof. The variable LEA
change is absent from this production branch. Fresh asm and diagnostic deltas
are retained; diagnostics were outside timing, WT code read from our own live
perfmap-enabled child with matching output.

Reducing workers8→1 was another counterfactual. Canonical weak-case and WAPM
results were small/mixed; independent phase results did not demonstrate a
reliable first-result/tail improvement. AuxContexts are lightweight copies;
LLVM machinery initializes only when used. Do not describe8 workers as8 full
LLVM compiler initializations. The unvalidated worker-cap patch is retained as
unapplied research, not an accepted implementation or CI fix.

## Validation and reproduction

- 24 lazy/policy/memory tests, including two exercised bucket-specific tests.
- 97 WAST cases in each of lazy MT/eager multipass/singlepass/interpreter.
- ASan Release O1/NDEBUG, virtual stack off:24 tests, exit 0, no sanitizer errors.
- Production Release build and repository formatting/diff checks.

All production timing uses the ASan-off artifact; sanitizers/profiles/builds ran
separately. Evidence includes full commands, hashes, flags and raw compressed
samples. Source-equivalent main reuse and modified phase-input limitations are
explicit above. No universal no-regression or multi-host claim is made.

From repository root, with same-config Release artifacts and catalog fixtures:

```sh
python3 docs/changes/2026-11-07-anonymous-grown-pages/benchmark.py \
  --suite polybench --cases atax,bicg,gesummv,trisolv --rounds 31 \
  --seed 2026110770 --out /tmp/new-results \
  --main /path/to/main/dtvm --main-commit 3cb4f2e \
  --candidate /path/to/new/dtvm --candidate-commit 6cd5d65 \
  --wasmtime /path/to/wasmtime-45
```

Add optional --previous /path/to/af4b07b/dtvm for the historical control.
Use --suite wapm --rounds 7 and a fresh output directory
for the catalog screen. Generate phases with make_phase_inputs.py --out DIR,
then phase_bench.py --inputs DIR --out RESULTS --main BIN --candidate BIN
--wasmtime BIN --counts 1,8 --rounds 9.
Binaryen tools are required only for derived diagnostic inputs. Do not overlap
formal timing with other workloads.
