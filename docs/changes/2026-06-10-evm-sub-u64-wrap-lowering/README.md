# Change: Narrow wrap-form lowering for EVM SUB with u64-proven operand pairs

- **Status**: Implemented
- **Date**: 2026-06-10
- **Tier**: Light

## Overview

The result of EVM SUB wraps to the 2^256 scale on underflow, so the
**result** cannot be narrowed — but when range analysis has proven both
operands to be u64, the **computation** can: `(a - b) mod 2^256` is
identically `{wrapped difference a₀-b₀, borrow broadcast, borrow broadcast,
borrow broadcast}`, bit-exact for all inputs. This change lowers such SUB
sites from "8 `protectUnsafeValue` spills + a SUB/SBB chain" to "1 sub +
1 compare + 1 negate + borrow reuse". Paired EEST Cancun measurement:
site-weighted SUB fast-path hit rate **18.4% → 42.1% (+23.8pp)**, 925 sites
migrated, every other op's per-site classification unchanged; the correctness
suites pass (unittests 223/223, statetest 2723/2723 — see Verification), and
the end-to-end benchmarks are neutral.

The differential coverage for this lowering path now ships separately with
the consolidated EVM differential suite change
(`docs/changes/2026-06-11-evm-differential-suite/`). That change carries the
6 fixtures for this SUB path — including the underflow all-ones-fill and
wrap-boundary adversarial cases — so this optimization change stays
code-only.

## Motivation

On EEST Cancun, SUB has the largest generic-4-limb-path site count of any
operator (3,893 sites, more than 4x ADD). At 50.2% of those sites both operands are
already statically proven u64 — loop counters, gas arithmetic, and length
differences. Yet SUB previously had only a constant-RHS fast path
(`handleSubU64Const`); dynamic u64 pairs all fell to the generic 4-limb
path. To protect the SBB carry chain from flag clobbering during x86
lowering, the generic path first materializes all 8 operand limbs into
variables via `protectUnsafeValue`. This is a known source of spill
pressure.

The value-range roadmap previously evaluated "SUB result narrowing" and
correctly deferred it: it requires the relational fact a≥b, which the
current lattice does not carry. This change takes a different route that
does not depend on that premise: **keep the result's U256 tag and narrow
only the computation form**. The underflow wrap is expressed exactly by the
borrow broadcast, so no no-underflow proof is needed.

## Changes

`src/compiler/evm_frontend/evm_mir_compiler.h` (the `handleBinaryArithmetic`
BO_SUB branch, inserted after the ADD narrow-form branch and before the
constant-folding paths):

- Gate: `Operand::bothFitU64(LHSOp, RHSOp)` with both sides non-constant.
  Constant cases still take the existing folding / identity /
  `handleSubU64Const` paths, with ordering unchanged.
- Lowering: `Diff = sub(a₀, b₀)`; `Borrow = zext(a₀ <ᵤ b₀)`;
  `Fill = 0 - Borrow` (in i64, 0-1 = all-ones, expressing the wrap fill of
  the upper 192 bits exactly). Fill is materialized once into a temporary
  variable and re-read per limb (the conservative multi-parent mode). There
  is no SBB chain, so no flag-protection barriers are required.
- The result returns the **default U256 range** — no narrowing claim is
  attached. This is the core soundness constraint of this change; the
  analyzer's SUB transfer (`evm_analyzer.h:1645`, pushTop = U256) remains
  symmetric.
- Adds a `SubFastRangeU64Count` counter and wires it into the arithmetic
  fast-path summary predicate and log line.

## Soundness

- Wrap algebra: for a,b ∈ [0,2^64), a≥b → `{a₀-b₀,0,0,0}`; a<b →
  `{(a₀-b₀) mod 2^64, ~0, ~0, ~0}` (= 2^256-(b-a)). Enumeration over
  4 million boundary pairs and computation over 442 boundary pairs both
  match `(a-b) mod 2^256` at every pair.
- U64 tag provenance audit: on upstream/main, every tag producer (automatic
  derivation from constants, comparison results, AND-const, analyzer entry
  import) has structurally zero high limbs. On upstream/main, none of the
  audited tag producers can carry non-zero high limbs.
- The dual consumption of a₀/b₀ (by the sub and the compare) is isomorphic
  to the existing ADD narrow-form branch; CgIR lowering memoizes by pointer,
  so there is no duplicate emission.
- Diff carries no `protectUnsafeValue` barrier: single consumer, no SBB
  chain, consistent with the existing comment in `handleSubU64Const`.

## Verification

- The differential coverage for this path — 6 fixtures plus the interp-vs-
  multipass byte-for-byte equality test — now ships separately with the
  consolidated EVM differential suite change
  (`docs/changes/2026-06-11-evm-differential-suite/`). It covers no underflow,
  **underflow with all-ones fill** (5-7 → 2^256-2), equal operands, wrap
  boundary (0 - (2^64-1), limb0=1 + 48 F digits), dynamic zero RHS, and a
  single-side-wide control (does not trigger).
- multipass evmone-unittests 223/223; multipass evmone-statetest
  `-k fork_Cancun` 2723/2723; format check passes; no new warnings.

## Measurements

Paired EEST Cancun measurement (38,808 instrumented site rows, 28,109 shared
sites, site-weighted; the measurement branch carries the tap and is not
committed with this PR):

| Metric | base | this change | Δ |
|---|---:|---:|---:|
| SUB fast-path hit rate | 18.4% | 42.1% | +23.8pp (925 sites moved from the generic 4-limb path to the narrowed u64 path) |
| All other ops | — | — | identical per site |

The migration is confined to SUB: 925 sites move from the generic 4-limb
path to the narrowed u64 wrap-form path, while every other op's per-site
classification is unchanged.

Stacking with the open PRs: this measurement uses a base without the
range-tag-consuming PR (#534). That PR's ENV/comparison tags produce more
u64 pairs. Measured here: 925 sites. A separate estimate from the #534
measurement data suggests stacking #534's tags could raise the covered
sites to about 1,594; this is directional and not measured on this build.

evmone-bench 27-bench (median of 5, with outliers re-measured at 15 reps):
median +0.62%. All outliers, including bidirectional swings on benchmarks
unrelated to SUB, returned to their respective cv noise bands on
re-measurement; the largest and most stable benchmark, snailtracer, shows
+0.4% (cv 0.9-1.1%). Conclusion: end-to-end neutral, no regressions.
The benefit takes the form of removing 7 spills + an SBB chain of generated
code per site, and this suite's hot paths do not isolate that pattern.

## Known limitations

1. On real mainnet loads, cross-block widening leaves dynamic u64 pairs
   nearly nonexistent at generic-4-limb-path SUB sites (execution-weighted
   ≈0). The benefit of this path on real loads is unlocked only after the
   cross-block precision work that lifts the EVM stack into SSA values
   (gated by `ZEN_ENABLE_EVM_STACK_SSA_LIFT`) lands. EEST's in-block pairs
   (loop/gas patterns) are the portion this path covers today.
2. As with the existing narrowing paths, tag trust extends to the analyzer
   import path under `ZEN_ENABLE_EVM_STACK_SSA_LIFT=ON` (OFF by default and
   in CI). Before that path is enabled, the transfer soundness should be
   re-reviewed (as recorded in the const-shift change document).

## Checklist

- [x] Implementation complete
- [x] Tests added/updated
- [ ] Module specs in `docs/modules/` updated (if affected)
- [x] Build and tests pass
