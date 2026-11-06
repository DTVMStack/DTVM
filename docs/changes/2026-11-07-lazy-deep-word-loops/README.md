# Change: Initial Greedy for deep integer word-memory loops

- **Status**: Implemented
- **Date**: 2026-11-07
- **Tier**: Light

## Overview

Keep #642's FP policy and bounded entry-only scheduling. Select initial Greedy
for a demanded body up to 2048 source bytes containing a third-level loop
subtree with at least two syntactic 32/64-bit integer loads and one integer
store, with no other memory access types/widths or guest calls in that subtree.
Deeper loops contribute effects to the third-level subtree; an isolated pure
inner fragment does not override a mixed or callful enclosing region.

Byte/halfword and mixed accesses, shallow integer loops, register-only loops,
single-load updates and read-only pointer scans do not trigger the new rule.
Do not collect hints for ineligible bodies or allocator modes. Preserve #641
loop/call metadata independently. This is a static opportunity/cost heuristic,
not a proof of runtime trip counts or universal profitability.

## Rejected first prototype

An any-word-access depth>=3 prototype accelerated the integer targets but
independently regressed base64cli about 13%, qr2text about 6% and suggest about
8% in paired 21-round checks. Diagnostics identified read-only pointer scans,
Clap traversals and mixed byte/word HashBrown rehash loops. The refined rule
uses multi-input word updates and rejects mixed/callful third-level regions;
it has no benchmark-specific exclusions. Workload screens informed refinement;
new process runs are independent confirmation, not blind workload holdouts.
The original 2mm +23% three-round negative did not repeat in nine new rounds
(paired ratio 1.004, interval [0.964, 1.037]). All prototype data are retained.

## Motivation

The completed #642 study covers all 30 PolyBench and 20 WAPM catalog cases.
Three-round mode controls on merged main af4b07b show Floyd lazy MT 36698 ms
versus serial Greedy 22718 ms (WT45 26736); Nussinov 10806 versus 8102 (WT45 9320).
Mode changes also change threading, so a new MT candidate must verify the
hypothesis. No benchmark IDs or names belong in production selection.

## Impact and validation plan

Compiler frontend hint collection and initial allocator choice only. No guest
counters, OSR, new background tasks or arithmetic transformations. Explicit
Fast, eager/serial choices and monotonic publication remain unchanged.
The loop-depth/width rule is a static tradeoff, not guaranteed runtime heat.
Compare production merged main, candidate and WT45 on integer targets, existing
FP gains, short numeric cases and all WAPM; preserve negative results. Add
positive/negative hint tests and rerun existing suites before opening a PR.

- [x] Implementation complete
- [x] Tests added/updated
- [x] Compiler spec updated
- [x] Build and tests pass
- [x] Production benchmark benefit and startup checks

## Final production measurements

Baseline is merged upstream main af4b07b22adf9f08586f9dd08adb1d57a07cce51
(including #642). Measured implementation is be96a8c7c91541a647606292b0357aaafa80cbdd.
Production SHA256 is 580305bd1e92b0953e67637f7a6955e208e9a3b9c6a5e2caff846780c2d82ad2.
Later report/runner edits leave compiler and test sources unchanged.
This experiment is separate from the earlier full 30-PolyBench / 20-WAPM
validation of #642. Those original results and review are preserved in the
archive; they are not claimed as a full 30-case rerun of this new candidate.

Five independent final rounds, group medians in milliseconds:

| Case | Merged main lazy MT | New lazy MT | Wasmtime 45 | Lower time vs main | Lower time vs WT45 |
|---|---:|---:|---:|---:|---:|
| floyd-warshall | 37780.070 | 22869.817 | 26385.395 | 39.5% | 13.3% |
| nussinov | 9750.603 | 6425.554 | 7223.223 | 34.1% | 11.0% |

Paired median ratios use within-round comparisons, not ratios of group medians:

| Case | New/main, pointwise 95% interval | New/WT45, pointwise 95% interval |
|---|---:|---:|
| floyd-warshall | 0.6024 [0.5655, 0.6281] | 0.8748 [0.8458, 0.8837] |
| nussinov | 0.6447 [0.5904, 0.8168] | 0.9208 [0.7937, 0.9861] |

## Startup and existing-throughput checks

Final 20-case WAPM screen: 19 successful cases at seven rounds; sam returns 1
on all engines under its catalog invocation and is excluded. Fortune/UUID text
varies; deterministic outputs match. Final independent 21-round checks retain
all raw runs and use the same main/new/WT45 comparison.

| Cohort | Case | Main ms | New ms | WT45 ms | Paired new/main, pointwise 95% interval |
|---|---|---:|---:|---:|---:|
| word2-startup-r21 | base64cli | 139.793 | 140.056 | 570.630 | 1.0019 [0.9555, 1.0405] |
| word2-startup-r21 | chkfont | 44.837 | 44.256 | 84.725 | 0.9953 [0.9066, 1.0312] |
| word2-startup-r21 | cowsay | 141.876 | 138.473 | 436.428 | 1.0019 [0.9853, 1.0319] |
| word2-startup-r21 | pi | 27.753 | 28.020 | 40.454 | 0.9939 [0.9692, 1.0322] |
| word2-startup-r21 | qr2text | 55.037 | 52.962 | 125.736 | 0.9896 [0.9352, 1.0059] |
| word2-startup-r21 | suggest | 100.677 | 106.638 | 462.287 | 1.0225 [0.9575, 1.1055] |
| word2-startup-r21 | tpl | 299.013 | 305.852 | 820.696 | 0.9659 [0.9463, 1.0253] |
| word2-final-followup-r21 | durbin | 37.366 | 37.867 | 51.334 | 0.9933 [0.9767, 1.0183] |
| word2-final-followup-r21 | viu | 261.293 | 258.560 | 1320.610 | 0.9933 [0.9893, 1.0442] |
| word2-short-r21 | bicg | 83.839 | 83.049 | 82.001 | 0.9931 [0.9515, 1.0279] |
| word2-short-r21 | durbin | 43.315 | 47.224 | 61.806 | 1.0452 [1.0019, 1.1387] |
| word2-short-r21 | gesummv | 64.054 | 65.178 | 63.086 | 0.9777 [0.9311, 1.0441] |
| word2-short-r21 | trisolv | 55.367 | 54.511 | 57.854 | 0.9892 [0.9393, 1.0562] |
| word2-fp-r9 | 2mm | 2863.232 | 2726.014 | 3214.571 | 1.0163 [0.9594, 1.0692] |
| word2-fp-r9 | gemm | 1953.146 | 1860.995 | 2715.527 | 0.9790 [0.9228, 1.0176] |

The seven-round final screen still showed base64cli and viu negatives. The
independent 21-round checks did not repeat them. A marginal durbin negative in
the first final 21-round cohort also did not repeat in the separate followup.
Do not pool cohorts or treat an interval crossing 1 as proof of equivalence.
All intervals are fixed-seed, 10,000-resample percentile bootstrap intervals of
paired medians, pointwise without multiple-comparison correction. Five-round
intervals have limited precision. Screens informed design; these are independent
process confirmations, not blind workload holdouts or multi-host claims.

## Native-code evidence

Native code was captured outside formal timing using a separate diagnostic
build; research switches and dumps are absent from production. Selector on/off
captures isolate initial allocation in that diagnostic binary. Wasmtime45 main
was read live from our own perfmap-enabled child, not an AOT listing; its full
matrix output hash matches the formal runs. Final-policy integer compute-loop
bytes match the first prototype byte-for-byte. The two 2mm FP compute-loop byte
sequences also match between prototypes, supporting unchanged guest code there.

| Minimal compute loop | FastRA static instructions / frame accesses | Greedy | WT45 live |
|---|---:|---:|---:|
| Floyd-Warshall | 26 / 8 | 15 / 0 | 13 / 0 |
| Nussinov | 28 / 11 | 11 / 0 | 13 / 0 |

Counts are manually checked minimal backward-edge intervals, not retired
instructions or hardware counters. Whole-function code shrinks 1231 to 971
bytes and 1353 to 1033 bytes. Fewer instructions alone do not predict runtime:
WT45 Floyd folds a memory ADD but has conditional-exit plus unconditional-backedge
branches; DTVM has one backedge branch. No independent attribution of branch or
instruction effects is claimed. This change performs no reassociation,
vectorization, address folding or new machine peepholes.

## Protocol, reproduction and limits

GCC 14.2 / LLVM15 Release on Linux x86-64 AMD EPYC9V74, both JITs ON, WASI and
checked arithmetic ON; SPEC/ASAN/EVM/profiling/logging/perf OFF for production.
Main/candidate build options match. All engines and worker threads pin CPU0.
Fresh processes, warm file-page cache, one excluded warmup per case/engine,
randomized within-round engine order, WT45 cache disabled (-C cache=n).
Wall time includes startup, compile, execution, captured full matrix output and
teardown; hashing/compression are outside timing. No builds/tests/profiles ran
alongside formal timing. This is not isolated-kernel timing or a universal
engine win rate. WT45 is the existing artifact, not independently rebuilt here.

Environment restarts interrupted one original mode warmup and one WT native
capture before final-candidate timing. Both are marked incomplete and excluded;
restarted captures/cohorts have new directories/seeds. No samples are spliced
across these boundaries. All completed original and rejected-prototype cohorts
remain archived. Full compressed/deduplicated outputs and executables remain in
the executor; public evidence retains hashes, byte counts and previews instead
of duplicating enormous matrices.

Example from repository root, with identically configured builds:

```sh
python3 docs/changes/2026-11-07-lazy-deep-word-loops/benchmark.py \
  --main /path/to/main-af4b07b/dtvm --main-commit af4b07b \
  --candidate /path/to/new/dtvm --candidate-commit YOUR_SOURCE_REVISION \
  --wasmtime /path/to/wasmtime-45 --cases floyd-warshall,nussinov \
  --rounds 5 --seed 2026110722 --out /path/to/new-results
```

Use --suite wapm for the full WAPM catalog, or --suite polybench for all numeric
cases. The portable driver records supplied revisions (unknown when omitted),
executable/input hashes, complete commands, exits, timeouts and raw byte output
hashes. Nonzero cases are retained and excluded, including sam's non-UTF8 output.
The earlier #642 benchmark helper's hardcoded baseline revision is also fixed.

The access counts are syntactic; there is no dependence analysis, trip-count
inference, elapsed compile deadline or OSR. Source size bounds input, not elapsed
time. Read-only reductions, single-load kernels, mixed accesses and larger
functions remain outside this rule. Only this host/affinity setup was measured.
The first-frame problem remains for other unrecognized long functions.

## Validation and review

- 19 lazy JIT tests, including 32/64-bit positives; shallow, byte, register-only,
  readonly, single-load, mixed, late-call, deep pure-island and oversize negatives;
  cold exclusion, aliases and explicit Fast/eager/serial behavior.
- Pure FP pressure fixture with 20 live FP values, private loop policy thresholds
  set to one, ten calls: one initial Greedy compile and no private probe/upgrade.
  This closes the #642 interaction coverage gap without changing its guard.
- 98 MIR tests; 97 WAST cases in each of lazy MT, eager multipass, singlepass and
  interpreter. Canonical spec.patch applied before generation and then reversed.
- Repository formatting/diff checks; no production diagnostic switches, new
  background traversal, guest counters or ABI changes.

CI and other hosts remain separate validation. The older full #642 report
contains its historical 16-test validation, not a claim those counts are new
candidate reruns. Detailed final 19/98/97x4 logs are separate in the evidence.

## Immutable evidence

[All original and new cohorts, raw samples, assembly, validation and source snapshots](https://github.com/zoowii/DTVM/tree/d753589a5584a34d278dd5eb01540981768b2afe/docs/changes/2026-11-07-lazy-deep-word-loops/evidence).

[Original PR642 full 30-PolyBench / 20-WAPM report and review](https://github.com/zoowii/DTVM/blob/d753589a5584a34d278dd5eb01540981768b2afe/docs/changes/2026-11-07-lazy-deep-word-loops/evidence/REPORT.md).
