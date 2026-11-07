# Unsigned i32 constant remainder: implementation and measured limits

This change replaces nonzero, non-power-of-two unsigned i32 remainder with
`x - floor(x/d)*d`, using the existing exact magic quotient builder. It removes
targeted hardware DIV instructions and improves the dependent synthetic hot
loops tested here. **It does not establish a WAPM/PolyBench process-time win.**
It also adds first-demand compilation cost and emitted bytes. Keep both results.

## Source, scope and correctness

Main is merged PR644, **3bff8bf**, freshly rebuilt; candidate compiler source is
**2d07843**. Later changes add dropped-result tests and evidence only. The
separate single-mmap growth optimization was rebased onto main but is NOT in
this branch. No allocator/tiering policy, threshold or ISA feature switch changes.

`foldU32MagicDivRem` shares one LLVM magic-parameter calculation and quotient
builder between udiv and urem. Remainder may reuse a dividend only if its MIR
tree is pure and nontrapping. The Wasm frontend already materializes source
operands once into locals. Raw call/load/trapping trees remain intact. Zero,
one and power-of-two rules remain distinct. Signed remainder and i64 are not
extended. Reuse of the existing division builder also retains its correction
sequence for IsAdd divisors such as 7.

For any uint32 x and nonzero d, q=floor(x/d) implies 0<=q*d<=x, so x-q*d is the
exact uint32 remainder. The quotient expansion is already used/tested for udiv.
New tests exercise non-IsAdd and IsAdd values, random/boundary inputs, large
unsigned divisors, single side effects, OOB/NaN/div0 traps, and dropped results
that still must evaluate their operands. See [compiler contract](../../modules/compiler/spec.md).

[Build metadata](evidence/build.json) and cohort manifests pin complete source
identities, flags, binary/input hashes, arguments, seeds and boundaries. Main's
newly built SHA256 equals the previous 7cbf629 artifact: the intervening SGX guard
compiles away on this non-SGX host. Candidate production SHA256 is
662424b2d69a2080642912e7fe9c5e458d47f5a2fe905fae778a9c4b9d4ca4f9.
Production binaries are ASan/profiling OFF; diagnostic builds are separate.

## Protocol and statistical unit

One Linux AMD EPYC9V74 host, GCC14.2/LLVM15 Release, two-core cgroup quota.
All engine workers CPU0, collector CPU1. Fresh processes, randomized engine
order within case/round, one excluded warmup, warm input page cache, Wasmtime45
cache disabled. No builds, tests or profilers overlap formal sampling. Different
cohorts, allocator modes, binaries and timing boundaries are never pooled.

Each independent process is one sample. In microbenches, calls 2..8 are reduced
to ONE warm median per process; they are not seven independent observations.
Tables show separate group medians and within-round paired candidate/main
median ratios. Those estimates differ. Pointwise 95% intervals use fixed-seed
10,000-resample paired bootstrap. Canonical screening/holdout intervals are
exploratory and not multiplicity-adjusted; a crossing1 is not equivalence proof.
The nine predeclared eligible synthetic hot cases additionally pass exact paired
sign tests with Holm adjustment within that family (maximum adjusted p<0.000002).
That family is not a sample of nine independent real applications.

## Synthetic private hot loop, default lazy MT

Identical Wasm on all engines. A private kernel runs a uint32 LCG update, adds
its remainder and wraps to32 bits, then returns a checked checksum. Runtime
parameters supply the seed/iteration count; literal divisor is in the kernel.
A dynamic-divisor kernel and divisor 8 are negative controls. No guest I/O or
memory growth inside the kernel. The exported _start reports24-byte WASI
begin/end/checksum/index packets after each call. Export/private structure and
default lazy policy are retained; the private scalar loop initially uses FastRA.

31 independent processes per case/engine. Units: **ms per1000000 iterations**,
median of calls 2..8 within each process:

| Case | Main | Candidate | Wasmtime45 | Candidate/main paired ratio (95% CI) |
|---|---:|---:|---:|---:|
| rem-3 | 5.068 | 3.656 | 3.928 | 0.7278 [0.7250, 0.7321] |
| rem-7 | 5.115 | 4.867 | 4.884 | 0.9560 [0.9459, 0.9660] |
| rem-10 | 5.185 | 3.753 | 4.075 | 0.7251 [0.7179, 0.7492] |
| rem-20 | 5.148 | 3.871 | 4.140 | 0.7440 [0.7316, 0.7601] |
| rem-255 | 4.866 | 3.714 | 3.987 | 0.7666 [0.7555, 0.7699] |
| rem-1900 | 5.127 | 3.863 | 4.148 | 0.7600 [0.7448, 0.7755] |
| rem-2100 | 4.963 | 3.858 | 4.071 | 0.7740 [0.7626, 0.7852] |
| rem-65521 | 4.716 | 3.838 | 4.159 | 0.8149 [0.8058, 0.8260] |
| rem-4294967295 | 4.535 | 3.917 | 3.330 | 0.8677 [0.8487, 0.8843] |
| rem-8 | 1.720 | 1.739 | 1.708 | 0.9983 [0.9895, 1.0257] |
| rem-dynamic | 5.058 | 5.147 | 5.095 | 1.0169 [0.9963, 1.0383] |

Nine nonpow2 constants improve in this tested dependent loop. Divisor7's extra
correction sequence limits its gain; the remaining gap for UINT32_MAX is retained.
Power-of-two and dynamic controls do not establish a change. Do not turn these
results into a whole-program speedup or an all-input/all-host guarantee.

First kernel call, same cohort, **ms** (includes private demand compilation):

| Case | Main | Candidate | Wasmtime45 | Candidate/main paired ratio (95% CI) |
|---|---:|---:|---:|---:|
| rem-3 | 5.701 | 4.442 | 4.029 | 0.7686 [0.7626, 0.7962] |
| rem-7 | 5.726 | 5.629 | 4.909 | 0.9842 [0.9512, 1.0279] |
| rem-10 | 5.936 | 4.499 | 4.178 | 0.7719 [0.7504, 0.8031] |
| rem-20 | 6.005 | 4.765 | 4.066 | 0.8145 [0.7623, 0.8540] |
| rem-255 | 5.598 | 4.308 | 4.011 | 0.7786 [0.7600, 0.7956] |
| rem-1900 | 5.887 | 4.627 | 4.314 | 0.8120 [0.7808, 0.8404] |
| rem-2100 | 5.704 | 4.724 | 4.138 | 0.8250 [0.7505, 0.8421] |
| rem-65521 | 5.556 | 4.533 | 4.135 | 0.8339 [0.8144, 0.8618] |
| rem-4294967295 | 5.294 | 4.758 | 3.263 | 0.9204 [0.8785, 0.9334] |
| rem-8 | 2.371 | 2.325 | 1.711 | 0.9606 [0.8851, 1.1067] |
| rem-dynamic | 5.825 | 5.783 | 5.127 | 0.9961 [0.9431, 1.0151] |

## First call and compile cost: no-op counterfactual

Separate31-round cohorts set the runtime iteration parameter to 0 while retaining
the same kernel loop in the binary. This measures first private-call admission,
compilation, call/return and clock boundary overhead; it is not a pure compiler
phase. Wasmtime compiles before _start, so its near-zero internal interval
must not be compared as total startup latency. Parent first-packet time includes
that engine's startup and compilation.

Default MT no-op intervals were bimodal, with broad/unstable ratios including
negative controls. Background compilation contends with foreground on CPU0; depending on whether
_start was compiled in foreground, foreground context initialization may also
fall inside the first private kernel interval. These components were not
separately timestamped here.
Do not infer pure compiler cost from that cohort. Its full raw data are retained.

Serial FastRA disables background workers and Greedy explicitly. First private
zero-loop call, **microseconds**:

| Case | Main | Candidate | Wasmtime45 | Candidate/main paired ratio (95% CI) |
|---|---:|---:|---:|---:|
| rem-3 | 124.683 | 134.939 | 0.661 | 1.1167 [1.0496, 1.1808] |
| rem-7 | 124.774 | 140.497 | 0.631 | 1.1132 [1.0774, 1.1655] |
| rem-20 | 123.993 | 134.238 | 0.651 | 1.0929 [1.0658, 1.1303] |
| rem-255 | 123.452 | 136.611 | 0.651 | 1.1331 [1.1009, 1.2009] |
| rem-4294967295 | 122.371 | 136.841 | 0.741 | 1.1310 [1.0799, 1.1655] |
| rem-8 | 125.125 | 121.730 | 0.611 | 0.9730 [0.9218, 1.0297] |
| rem-dynamic | 125.805 | 125.856 | 0.641 | 0.9874 [0.9421, 1.0363] |

The selected constants add roughly 10–16 microseconds to group-median FastRA
first-call admission. This is a real cost, not a cold-start improvement. Extra
MIR/CgIR nodes and longer native sequences must be amortized by execution.
Power-of-two and dynamic controls do not establish an incremental change.

Parent first result for that SAME serial FastRA no-op cohort, **ms**:

| Case | Main | Candidate | Wasmtime45 | Candidate/main paired ratio (95% CI) |
|---|---:|---:|---:|---:|
| rem-3 | 4.990 | 5.103 | 5.435 | 1.0041 [0.9773, 1.0466] |
| rem-7 | 5.100 | 5.113 | 5.230 | 1.0148 [0.9890, 1.0554] |
| rem-20 | 4.967 | 5.034 | 5.152 | 1.0017 [0.9765, 1.0418] |
| rem-255 | 5.556 | 5.488 | 5.652 | 1.0402 [1.0024, 1.0725] |
| rem-4294967295 | 5.169 | 5.355 | 5.692 | 1.0020 [0.9810, 1.0558] |
| rem-8 | 5.076 | 5.193 | 5.401 | 1.0136 [0.9964, 1.0669] |
| rem-dynamic | 5.238 | 5.601 | 5.718 | 1.0206 [1.0053, 1.0425] |

Serial configured Greedy is a separate counterfactual. First zero-loop call,
**microseconds**:

| Case | Main | Candidate | Wasmtime45 | Candidate/main paired ratio (95% CI) |
|---|---:|---:|---:|---:|
| rem-3 | 186.835 | 195.268 | 0.641 | 1.0457 [1.0350, 1.0526] |
| rem-7 | 198.442 | 230.830 | 0.741 | 1.1312 [1.0501, 1.2612] |
| rem-20 | 187.787 | 202.359 | 0.711 | 1.0484 [1.0356, 1.0847] |
| rem-255 | 189.629 | 198.422 | 0.601 | 1.0626 [1.0481, 1.0863] |
| rem-4294967295 | 188.268 | 201.377 | 0.621 | 1.0509 [1.0338, 1.1112] |
| rem-8 | 184.262 | 184.502 | 0.611 | 1.0152 [0.9689, 1.2017] |
| rem-dynamic | 225.262 | 197.882 | 0.661 | 0.9781 [0.7994, 1.0123] |

Serial Greedy hot execution, **ms per1000000 iterations**:

| Case | Main | Candidate | Wasmtime45 | Candidate/main paired ratio (95% CI) |
|---|---:|---:|---:|---:|
| rem-3 | 5.130 | 3.713 | 3.951 | 0.7218 [0.7115, 0.7265] |
| rem-7 | 5.304 | 5.133 | 5.045 | 0.9514 [0.9400, 0.9586] |
| rem-20 | 5.029 | 3.713 | 3.997 | 0.7456 [0.7344, 0.7488] |
| rem-255 | 4.789 | 3.664 | 3.941 | 0.7664 [0.7605, 0.7747] |
| rem-4294967295 | 4.410 | 3.815 | 3.142 | 0.8530 [0.8436, 0.8668] |
| rem-8 | 1.693 | 1.694 | 1.710 | 0.9977 [0.9869, 1.0103] |
| rem-dynamic | 5.182 | 5.217 | 5.172 | 1.0116 [0.9980, 1.0180] |

Do not mix these modes or promise a universal iteration break-even threshold.
The default MT first-result/process tables, all first-call data and negative
controls are available in their summary.csv files.

## Native comparison and Wasmtime implementation

Wasmtime45 opts/arithmetic.isle:156-162 calls its unsigned constant quotient
expansion; prelude_opt.isle:343-347 finishes remainder as numerator-q*divisor.
[Tag/URL/SHA256 manifest](evidence/wasmtime45-source.json) pins the sources.
DTVM reuses its own LLVM-based exact quotient implementation.

Untimed diagnostic native captures (private kernel, before/after, WT45):

| Input | Main bytes / DIV | Candidate bytes / DIV | WT45 bytes / DIV |
|---|---:|---:|---:|
| %3 |101 /1|116 /0|80 /0|
| %7 |101 /1|124 /0|96 /0|
| %255 |101 /1|119 /0|88 /0|
| %8 |92 /0|92 /0|58 /0|
| dynamic |102 /1|102 /1|64 /1|

Counts are static disassembly of captured blobs, not retired instructions. WT
blobs can include constant-pool bytes. Targeted operator neighborhoods confirm
the DIV replacement. Candidate %7's frame shrinks 20 to 16 bytes even though the
body grows 23 bytes. It uses a64-bit product/shift and correction; WT uses32-bit
MULX with constant-pool operands. Smaller native text is not automatically faster
on this host. No AVX or ISA policy was changed in DTVM.

Bicg main's whole captured blob changes 1251 to 1321 bytes and 4 static DIV to 0.
Its FP kernel is not the target of this rule. QR constructor changes 25208 to
25228 bytes,3 static DIV to 2; WT45 is 22304 bytes with 2. QR wrappers and other
remaining operations are preserved. All captured canonical outputs match.

[Raw native/profile archive](evidence/profile-native.tar.gz), profile summaries,
per-function metadata and capture tools preserve the evidence. Micro packet
timestamps vary: DTVM diagnostic stdout hashes normalize checksum/index pairs;
WT capture hashes raw packets after independently validating those pairs.
Canonical workload stdout hashes are raw. DTVM diagnostic
builds dump lazy native bodies; WT perfmap bytes are read from our own live
child. The1 ms SIGPROF sampler records PCs on any process thread. Profiles include
startup/compiler/runtime work; dump I/O can perturb budgeting. Few/zero samples
in QR or sorting targets do NOT prove those functions are cold. Instrumented
samples are descriptive and cannot replace formal timing. Extended QR inputs
512/1024/2048 bytes were diagnostic only, not canonical timing claims.

## Canonical WAPM screen and independent controls

Full 20-case WAPM screen,7 rounds, **ms full process**:

| Case | Main | Candidate | Wasmtime45 | Candidate/main paired ratio (95% CI) |
|---|---:|---:|---:|---:|
| amirali | 6.545 | 7.327 | 6.667 | 1.1086 [0.7161, 1.4625] |
| base64cli | 110.063 | 111.252 | 459.455 | 1.0016 [0.9592, 1.0114] |
| chkfont | 39.676 | 39.770 | 75.797 | 1.0180 [1.0024, 1.0923] |
| code-stock | 21.056 | 21.930 | 83.132 | 1.0235 [0.9985, 1.0561] |
| cowsay | 118.081 | 118.161 | 389.909 | 0.9913 [0.8684, 1.0256] |
| dice | 22.942 | 22.131 | 38.321 | 0.9042 [0.8829, 1.2332] |
| echo | 26.578 | 25.765 | 36.624 | 0.9501 [0.8737, 1.0059] |
| erdtree | 71.810 | 57.120 | 159.477 | 0.9734 [0.9273, 1.0182] |
| figlet | 49.339 | 49.064 | 107.386 | 0.9510 [0.9427, 1.0441] |
| fortune | 60.423 | 60.850 | 112.458 | 0.9915 [0.9889, 1.0149] |
| irb | 3710.439 | 3755.013 | 9631.630 | 1.0063 [0.9919, 1.0149] |
| md5 | 25.415 | 26.886 | 38.354 | 0.9867 [0.9787, 1.0689] |
| pi | 25.167 | 25.079 | 35.372 | 1.0204 [0.9717, 1.0338] |
| pkg1 | 22.316 | 22.299 | 84.444 | 0.9846 [0.9603, 1.0349] |
| qr2text | 52.094 | 54.957 | 126.694 | 1.0359 [0.9994, 1.0904] |
| suggest | 99.091 | 92.834 | 410.086 | 0.9739 [0.9237, 0.9954] |
| tpl | 277.359 | 265.150 | 777.569 | 0.9968 [0.9628, 1.0356] |
| uuid | 84.650 | 82.382 | 475.173 | 0.9850 [0.9566, 1.0251] |
| viu | 235.863 | 241.719 | 1195.366 | 1.0568 [0.9978, 1.0772] |

Nineteen cases succeed; sam exits 1 on all engines and is excluded. fortune/uuid
are nondeterministic; all other successful outputs agree. This timing includes
module loading, compilation, execution, captured output and teardown.

Independent31-round follow-up for selected targets and startup controls:

| Case | Main | Candidate | Wasmtime45 | Candidate/main paired ratio (95% CI) |
|---|---:|---:|---:|---:|
| amirali | 5.661 | 5.738 | 5.616 | 0.9886 [0.9680, 1.0336] |
| base64cli | 112.003 | 110.703 | 466.746 | 0.9886 [0.9748, 1.0061] |
| code-stock | 22.810 | 23.076 | 87.069 | 1.0012 [0.9700, 1.0395] |
| md5 | 27.800 | 28.116 | 40.417 | 1.0103 [0.9834, 1.0285] |
| qr2text | 50.658 | 50.659 | 119.708 | 0.9784 [0.9699, 1.0145] |
| viu | 236.994 | 235.568 | 1231.427 | 1.0100 [0.9856, 1.0278] |

Screen-selected chkfont/suggest, independent31 rounds:

| Case | Main | Candidate | Wasmtime45 | Candidate/main paired ratio (95% CI) |
|---|---:|---:|---:|---:|
| chkfont | 38.433 | 38.871 | 72.515 | 0.9989 [0.9938, 1.0141] |
| suggest | 92.079 | 93.630 | 407.015 | 1.0149 [1.0053, 1.0305] |

Suggest initially appeared faster, then this follow-up showed an approximately
1.5% paired slowdown with a pointwise interval above 1. It was NOT discarded.
A third independent31-round cohort, with chkfont/code-stock controls:

| Case | Main | Candidate | Wasmtime45 | Candidate/main paired ratio (95% CI) |
|---|---:|---:|---:|---:|
| chkfont | 37.116 | 37.869 | 72.247 | 1.0088 [0.9966, 1.0201] |
| code-stock | 22.704 | 22.550 | 84.534 | 1.0061 [0.9860, 1.0224] |
| suggest | 93.916 | 93.090 | 415.729 | 0.9908 [0.9830, 0.9995] |

Suggest reverses direction again, so neither a stable process-time improvement
nor a stable slowdown is supported across these cohorts. Keep all three. No
whole-WAPM or generic startup-speed claim follows from the synthetic gains.

## Selected PolyBench screen and repeat

Ten selected cases,7 rounds, **ms full process**. This is not all 30 cases:

| Case | Main | Candidate | Wasmtime45 | Candidate/main paired ratio (95% CI) |
|---|---:|---:|---:|---:|
| 2mm | 2287.708 | 2234.089 | 2725.312 | 0.9898 [0.9285, 1.0495] |
| 3mm | 3317.487 | 3407.408 | 3822.609 | 1.0228 [0.9273, 1.0813] |
| atax | 51.155 | 52.368 | 62.762 | 1.0156 [0.9938, 1.0506] |
| bicg | 59.132 | 59.465 | 67.070 | 1.0184 [0.9705, 1.0506] |
| correlation | 3582.162 | 3267.118 | 3951.589 | 0.9121 [0.8823, 0.9880] |
| covariance | 3256.801 | 3293.749 | 4104.097 | 1.0093 [0.9715, 1.0933] |
| gemm | 1710.450 | 1669.082 | 2112.527 | 0.9720 [0.9104, 1.0777] |
| gesummv | 47.864 | 48.567 | 57.289 | 1.0038 [0.9639, 1.0398] |
| mvt | 56.540 | 56.855 | 71.591 | 1.0033 [0.9690, 1.0131] |
| trisolv | 46.304 | 44.392 | 56.091 | 0.9920 [0.9481, 1.0128] |

Correlation alone had a pointwise screening interval below1. The predeclared
selection rule repeated every such positive or negative screen case in a new
21-round cohort. Correlation's apparent improvement did not reproduce:

| Case | Main | Candidate | Wasmtime45 | Candidate/main paired ratio (95% CI) |
|---|---:|---:|---:|---:|
| correlation | 3270.413 | 3269.415 | 3855.887 | 0.9855 [0.9392, 1.0515] |

The other screen intervals cross 1. This establishes neither a warm FP-kernel
improvement nor whole-suite equivalence. More static remainder sites do not
imply that remainder is the process bottleneck.

## Correctness and validation

- 102 Release MIR tests pass, including four new effect/trap/structure tests.

- 98 WAST cases pass in each of lazy MT/eager multipass/singlepass/interpreter,
 including the enhanced new suite's dropped-result side-effect/trap assertions.

- The new remainder suite also passes explicit FastRA and serial Greedy modes.

- ASan with leak detection:102 MIR tests and98 lazy WAST cases pass; explicit
 Fast/serial Greedy/eager remainder cases also pass with no Failure diagnostics.
 Release-O1/NDEBUG, virtual stack OFF, detect_leaks=1:abort_on_error=1, exit0.

- Existing spec.patch is applied before generation and restored afterward. An
 initial unpatched generated-file list left an empty imports directory; it was
 removed and generation rerun consistently before the successful suites.

- Formatting, diff and canonical output checks pass. Diagnostic compiler edits
 are absent from production. Shared dependency builds were restored to Release.

Source review checks the quotient identity, nontrapping/pure dividend
condition, existing zero/pow2 rules and unchanged signed/i64 scope. The raw
validation logs are included; rebuildable test executables were compressed or
removed after their logs, and production benchmark binaries remain frozen.

## PR645 review

[Review and fixes](REVIEW.md) harden complete-pair validation and child deadlines.
The compiler/runtime and all historical measurements are unchanged. Archived gzip
logs can now be summarized directly; truncated/failed/duplicate data are rejected.

## Reproduction

From repository root with CPU0/1 available, Python3 and WABT:

```sh
python3 docs/changes/2026-11-07-u32-magic-remainder/micro_bench.py \
  --main /path/to/main --candidate /path/to/candidate \
  --wasmtime /path/to/wasmtime45 --out /tmp/rem-hot \
  --rounds 31 --iterations 1000000
```

Default is 8 calls and
all nine constant cases plus two controls. For zero-loop serial Fast, add
`--iterations 0 --dtvm-extra=--disable-multipass-multithread` and
`--dtvm-extra=--disable-multipass-greedyra`; serial configured Greedy omits the
last flag. Run summarize.py FOLDER --micro afterward. Canonical benchmark.py from
the preceding anonymous-zero-tail change accepts main/candidate/wasmtime paths;
its cohort manifests record exact commands and seeds. Raw samples are gzip JSONL.

## Decision and next boundary

This is a small deterministic compiler transform with verified hot-integer-loop
benefits and measurable admission/code-size costs. It is not evidence that the
current short WAPM invocations are remainder-bound. Remaining compile-cost work
could investigate dead constant temporaries after propagation (the FastRA %7
blob still contains an unused immediate move), but that is not implemented or
claimed here. Use profiles to choose targets, isolate phases, retain controls
and independently repeat screen-selected effects before adding policy thresholds.
