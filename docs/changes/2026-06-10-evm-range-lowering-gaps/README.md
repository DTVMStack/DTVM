# Change: Consume value-range tags in EVM bool/compare/bitwise lowering

- **Status**: Implemented
- **Date**: 2026-06-10
- **Tier**: Light

## Overview

The range analysis in the multipass JIT already proves a large number of
operands to be u64. Several lowering paths do not consume that proof and
still emit full-width 4-limb sequences. This change makes four lowering
categories consume the existing ValueRange tags. On the EEST Cancun suite,
the site-weighted fast-path hit rate rises from 78.72% to **80.02%** (+364
sites move to narrow paths, zero reverse regressions), with ISZERO rising
from 23.2% to 85.9%. All correctness suites pass. The adversarial
differential coverage for these lowering paths now ships separately with the
consolidated EVM differential suite change
(`docs/changes/2026-06-11-evm-differential-suite/`), which carries the 21
fixtures for these paths.

## Motivation

A separate real-load analysis (shipped by the in-flight mainnet-replay
analysis-suite work, not part of this diff) quantified two gap categories:
the analysis-side gap (static proof fails;
the majority) and the lowering-side gap (the proof exists but the builder
does not consume it). This change closes the part of the lowering-side gap
where the proof already exists and the builder can consume it directly:

- **ISZERO**: the deferred zero-test materialization unconditionally
  OR-folds all 4 limbs, and its 0/1 result loses the U64 tag — on the
  real-load corpus, 58.5% of ISZERO full-width executed operands are already
  statically proven u64.
- **JUMPI**: the condition lowering still OR-folds 4 limbs for conditions
  already tagged U64. When an ISZERO result is the condition, it is first
  materialized into 0/1 and then the whole chain is recomputed (the
  `LT;ISZERO;JUMPI` loop-exit pattern pays three layers of redundancy).
- **OR/XOR**: only a const-u64 fast path exists, with no range narrowing —
  on the real-load corpus, 51.8% of OR full-width executions have at least one
  side proven u64.
- **SLT/SGT**: not even a const fast path exists — 22.4% of real-load SLT
  full-width executions take the `slt(x, small constant)` shape.

A fifth gap identified by the same analysis — environment opcode producers
(PC/GAS/CALLDATASIZE/CODESIZE/MSIZE/RETURNDATASIZE) returning the default
U256 despite structurally zero high limbs — landed upstream separately as
#532 while this change was in review, and is no longer part of this diff.

## Changes

All changes are in `src/compiler/evm_frontend/evm_mir_compiler.{h,cpp}`:

1. **ISZERO deferred zero-test carries the base range**:
   `createDeferredZeroTest` gains a `BaseRange` parameter (new member
   `DeferredBaseRange`), and `handleCompareEQZ` folds 1/2/4 limbs according
   to the base range. All creation and materialization sites are updated in
   sync, including range propagation through nested ISZERO flips. (The
   companion result tag — the deferred operand's own U64 range, sound since
   its materialized value is always 0/1 — landed upstream via #524 during
   review; this change keeps the base-range plumbing and the narrow fold.)
2. **JUMPI condition fusion and narrowing**: a deferred zero-test condition
   is no longer materialized; it is folded according to the base range and
   compared against 0 directly, with the EQ/NE predicate chosen by the
   negation flag. A non-deferred condition folds only the limbs that may be
   non-zero, per the Range contract. The dest and branch/jump-table logic
   is unchanged.
3. **OR/XOR range-narrowing paths**: when both operands are proven U64
   (non-constant), a single i64 op plus zeroed high limbs is emitted and
   the result is tagged U64. When exactly one side is proven U64, the low
   limbs are combined and the wide side's high limbs pass through —
   isomorphic to the existing const-u64 path — and the result is tagged
   with the wide side's range.
4. **SLT/SGT fast path for u64 constants**: a u64 constant has zero high
   limbs and is a non-negative signed-256 value, so `slt(x, c)` lowers to
   "sign bit ∨ (high limbs all zero ∧ unsigned limb0 comparison)". New
   helpers `handleCompareSltRhsU64`/`handleCompareSgtRhsU64` use the same
   three-level range tier (U64/U128/default) as the existing
   unsigned-comparison helpers. Both constant sides are covered via the
   `c <s x ⟺ x >s c` swap.

## Soundness

- Range contract: the `U64` tag only asserts that the high limbs are
  semantically zero. All new paths narrow the read width only where the
  tag is already proven, and introduce no new tag sources.
- SLT/SGT: an operand with limb0 in `[2^63, 2^64-1]` is a positive 256-bit
  value. The new path compares limb0 with unsigned predicates
  (`ICMP_ULT/UGT`); the negative case is short-circuited by the sign bit
  of limb3. The truth table of the three-level tier was verified by
  boundary enumeration over
  2^63, 2^64, 2^128, 2^192, 2^255, -1, equal values, c=0, and c≥2^63.
- analyzer/builder symmetry: the builder result ranges for ISZERO,
  comparison results, OR/XOR, and environment opcodes match or are wider
  than the analyzer transfer (`evm_analyzer.h`); no
  builder-narrower-than-truth state exists.
- JUMPI now depends on the correctness of the Range contract — an
  over-narrow upstream tag would cause a wrong branch rather than only a
  slowdown. This dependency is recorded explicitly in code comments.

## Verification

- **Differential fixtures (ship separately)**: the 21 `.easm` + `.expected`
  pairs and the `EVMRangeNarrowingDifferentialTest` suite for these lowering
  paths now ship with the consolidated EVM differential suite change
  (`docs/changes/2026-06-11-evm-differential-suite/`). The fixtures cover both
  the narrow-path trigger side and the full-path preservation side of every
  new path, with adversarial values including 2^64, 2^128, 2^192, -1, limb0-MSB
  (`0x8000000000000000`, the hard gate for the unsigned predicate), and
  high-sparse values; the suite asserts that the interp and multipass outputs
  are byte-identical and that multipass actually JIT-compiles. This change
  carries no test fixtures.
- **multipass evmone-unittests**: 223/223.
- **multipass evmone-statetest `-k fork_Cancun`**: 2723/2723.
- **Full ctest**: 11/11 — solidityContractTests requires copying the
  gitignored `tests/evm_solidity/*/*.json` generated artifacts into the
  worktree, which is environment data, not a regression.
- `tools/format.sh check` passes; the build produces no new warnings.

## Measurements

### Fast-path hit rate (EEST Cancun, site-weighted, paired measurement)

Measurement method: on a measurement branch carrying a per-opcode
fast-path-hit-rate counter (measurement-only, does not ship with this PR),
one capture is
taken for base and one for base plus this change; 28,109 shared sites are
paired point by point. The measurement predates the upstream merge of #532
and #524; the treatment side included the environment-opcode tag that has
since landed as #532 (see the ADD row for its attribution).

| op | base | this change | Δ | migrated sites |
|---|---:|---:|---:|---|
| ISZERO | 23.2% | **85.9%** | +62.7pp | 316 sites: full-width → 64-bit narrow path |
| SGT | 80.6% | 95.0% | +14.4pp | 20 sites: full-width → u64-constant fast path |
| SLT | 61.5% | 66.7% | +5.2pp | 9 sites: full-width → u64-constant fast path |
| ADD | 75.1% | 75.6% | +0.5pp | 17 sites: full-width → 128-bit narrow path (unlocked by the environment-opcode tags, since landed upstream as #532) |
| OR | 98.7% | 98.9% | +0.2pp | 2 sites: full-width → 64-bit narrow path |
| **Overall** | 78.72% | **80.02%** | +1.29pp | +364 sites, zero reverse migrations |

ISZERO contributes the bulk of the migrated sites, and every migration
moves toward a narrower path. JUMPI fusion is outside the counter's coverage —
JUMPI is not an arithmetic op. Its benefit shows up in generated-code shape
(the materialize-then-refold round trip and 3 redundant ORs are removed)
and is not counted in the table above.

### Real-load corpus (mainnet replay, 247 transactions)

Under the production configuration with stack-lift disabled by default, the
gate that rejects contracts with unresolved non-lifted deep stack entries
on current upstream/main (`evm_module.cpp:112`,
`hasUnresolvedNonLiftedDeepEntryRisk`) sends 20 of the corpus's 27
contracts back to the interpreter. The real-load JIT coverage problem
therefore precedes the lowering quality problem; the in-progress SSA
stack-lifting work is addressing it. Paired measurement on the slice of 7 contracts that
still compile: the overall execution-weighted hit rate rises from 26.7% to
45.3%, with ISZERO from 0% to 100% (13 sites) and SLT from 0% to 100%.
This slice carries too little execution volume; it serves only as a
directional corroboration, not as the headline.

### Performance (evmone-bench, 27-bench, multipass, vs upstream/main baseline)

Across the full 27-bench set
(`--benchmark_filter='^external/total/(main|micro)/'`, median of 5 reps),
the median delta is **-0.23%**, within the ~2% multipass run-to-run variance on
this machine. The first-round outliers (`narrow_compare_u128/loop` +11.8%,
`swap_math/received` -12.7%) were re-measured with 15 reps: both are
sub-microsecond-scale noise, landing at -3.0% and -0.2% respectively after
re-measurement. The largest and lowest-variance benchmark, `snailtracer`
(48.4µs, cv 1.5%), shows -1.1% and -1.3% across two independent runs, in a
consistent direction.

Conclusion: **no performance regression**. The aggregate is neutral, and
the heaviest realistic-program benchmark shows a consistent small
improvement. The narrowing benefit primarily takes the form of leaner
generated code — 3-9 MIR nodes and several spills saved per site. Its
end-to-end effect on calldata-driven real-contract loads is limited by JIT
coverage (see the next section).

## Known limitations

1. **Pre-existing interaction with the SSA stack-lifting path** (not
   introduced by this change): with
   `ZEN_ENABLE_EVM_STACK_SSA_LIFT=ON` (default OFF, CI OFF),
   `getOperandIdentityKey()` in `evm_lifted_stack_lifter.h` does not
   recognize deferred operands, so a live-out deferred zero-test triggers
   an assertion or an incorrect merge. This exposure existed before this
   change — neither the deferred mechanism nor its cross-block lifetime
   changed. The fix belongs to the SSA stack-lifting follow-up work, which
   should add identity-key handling for deferred operands.
2. The execution-weighted view of the real-load hit rate is limited by JIT
   coverage (see above). After the stack-lift work lands, the full
   27-contract view can be re-measured by replaying the mainnet-replay
   corpus through the multipass JIT and capturing the per-opcode fast-path
   hit rate (the profiling tooling ships with the separate mainnet-replay
   analysis-suite work).

## Checklist

- [x] Implementation complete
- [x] Tests added/updated
- [ ] Module specs in `docs/modules/` updated (if affected)
- [x] Build and tests pass
