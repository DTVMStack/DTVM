# Change: Break scalar integer-to-float false dependencies

- **Status**: Implemented
- **Date**: 2026-11-04
- **Tier**: Light

## Overview

Precede scalar register GPR-to-XMM conversions with an SSE zero idiom at final
MC emission. This is an independent change based on upstream main `0258bd0`;
it does not include or require private-function promotion.

## Motivation and evidence

Legacy `CVTSI2SS`/`CVTSI2SD` preserve upper destination lanes. In conversion/division
loops that can create a false dependency on the previous iteration's division.
The candidate clears the destination with `XORPS` before conversion, allowing
independent iterations to overlap without requiring AVX or changing FP arithmetic.

The earlier experiment, on a branch with promotion disabled, found R15 wall-time
improvements of 16.7% (atax), 17.6% (bicg), 20.9% (gesummv), and 15.5% (mvt).
Gemver and short controls did not establish a general benefit. These are
single-host measurements, not universal performance claims. Full raw observations,
assembly excerpts and the separately evaluated promotion strategy remain in the
[research branch](https://github.com/zoowii/DTVM/tree/perf/scalar-conversion-dependencies/docs/changes/2026-11-04-scalar-conversion-dependencies).

## Contracts and review

- Only four scalar register conversion opcodes are modified. Their result
  register classes are FR32/FR64 with no upper-lane input; the `_Int` vector
  variants have a tied upper-lane input and are deliberately excluded.
- The allocated XMM destination cannot alias the GPR source. Clearing its dead
  upper lanes preserves the scalar result, rounding and integer input.
- XORPS does not modify EFLAGS or raise FP exceptions. Host ISA support already
  requires SSE4.1. This introduces no AVX requirement or fused arithmetic.
- Emission occurs after allocation; no instruction scheduler follows it.
  Added bytes go through normal MC layout and relocations.
- Both FastRA and GreedyRA use this path. Singlepass is unchanged.
- New WAST tests cover all signed/unsigned i32/i64 to f32/f64 combinations,
  boundaries and rounding, live neighboring FP values, and a conversion loop.

The affected external contract is documented in
[the compiler spec](../../modules/compiler/spec.md).

## Verification

The standalone mixed Release binary builds successfully. R9 independently
compares it to the frozen original-main binary (the latest main adds only the
Singlepass build script). All 180 processes exit successfully with matching
stdout/stderr hashes per input. CPU 0 affinity, warm page cache, randomized
rounds; wall time includes compilation, execution and cleanup.

| Original input, lazy-G-MT | Baseline ms | Standalone ms | Change (paired 95% interval) |
|---|---:|---:|---:|
| atax | 107.339 | 88.320 | -17.7% [-21.3%, -11.3%] |
| bicg | 93.815 | 92.808 | -1.1% [-15.9%, +8.5%] |
| gesummv | 73.738 | 61.203 | -17.0% [-26.1%, +4.2%] |
| mvt | 122.350 | 101.852 | -16.8% [-20.3%, -7.9%] |
| echo | 35.903 | 34.396 | -4.2% [-16.4%, +13.2%] |
| md5 | 33.963 | 30.866 | -9.1% [-12.8%, +2.8%] |

[Raw samples and commands](standalone-measurements.json) include binary/input
hashes. Intervals use 10,000 paired round resamples, seed 20261104; processes
are the sampling unit. Keep the uncertain results: this standalone run does
not independently establish bicg or gesummv improvement. Historical stacked
measurements above remain separately labeled; results are not pooled.

Standalone validation passes:

- Seven CTest suites, including all 97 available WAST groups in lazy mode.
- All 97 WAST groups separately under eager Greedy/ST and eager FastRA/ST.
- New conversion tests, existing MIR and stub-publication regressions.
- C++ formatting and whitespace checks.

Spec preparation uses the canonical CI `tests/wast/spec.patch`, reversed after
testing; no submodule changes are included. ASan and cross-machine checks were
not run. Review found no blocking scalar-value, register-liveness, EFLAGS or
relocation issue. The initial PR-scope issue (an unmerged promotion dependency)
was corrected by preparing this standalone branch on current upstream main.
