# Change: Statically resolve constant-amount EVM shift guards and prune dead source terms

- **Status**: Implemented
- **Date**: 2026-06-10
- **Tier**: Light

## Overview

For SHL/SHR/SAR with a constant shift amount, the multipass JIT still emits a
runtime `>= 256` guard (one Select per limb) and source-limb computations
already proven zero by the range analysis. This change resolves that dead code
at compile time. A constant shift amount ≥256 folds SHL/SHR directly to a
constant zero. A constant amount <256 omits the entire `IsLargeShift` chain
and the per-limb Selects. When the value operand is proven U64/U128, the dead
source terms are pruned as well. This is pure generated-code reduction; no
new range claims are introduced. Correctness suites pass and the end-to-end
benchmark shows no regression.

## Motivation

On real mainnet load, 92.5% of full-width SHL executions and 99.6% of SHR
executions use a compile-time-constant shift amount (Solidity
storage-slot/address packing patterns). The existing const-amount fast path
avoids the per-limb select cascade of dynamic shifts, but still retains:

1. the `isU256GreaterOrEqual(Shift, 256)` comparison chain — statically
   decidable for a full constant;
2. one `Select(IsLargeShift, fill, R)` + spill per result limb — dead code
   when the guard is always false;
3. for shifted values proven U64/U128, the shl/ushr/or terms on the high
   source limbs — zero under the Range contract semantics.

`getConstShiftAmount` reads only limb0. Constants with a nonzero high limb
(such as 2^64) historically relied on the runtime guard as a backstop. Static
resolution must therefore decide on the full 256-bit constant; this is the
core correctness constraint of this change.

## Changes

All changes are in `src/compiler/evm_frontend/evm_mir_compiler.{h,cpp}`:

1. **Static large-shift resolution** (`handleShift`): when the shift amount is
   constant, obtain the full 256-bit value via `u256ValueToIntx`. For ≥256,
   SHL/SHR_U return a constant-zero Operand. The result is always 0 under EVM
   semantics, consistent with the existing both-operands-constant folding path;
   the constant constructor automatically derives a U64 tag, which is more
   precise than the previous dynamic zero. SAR keeps the original flow, because
   its fill value depends on the sign bit of the shifted value. For <256,
   `IsLargeShift` is no longer constructed and nullptr is passed to the
   helpers.
2. **Helpers accept a nullptr guard**: the const-amount path of the three
   helpers skips the per-limb Select when the guard is nullptr. SAR's
   out-of-range sign-fill comes from R's default initial value, is independent
   of the deleted Selects, and is left untouched. The dynamic-path entry gains
   a defensive `ZEN_ASSERT(IsLargeShift != nullptr)`.
3. **Range-aware source-limb pruning** (SHL/SHR_U const path only): a new
   `LiveLimbs` parameter (U64→1, U128→2, default 4). Shifted/carry terms whose
   source-limb index is ≥ LiveLimbs are not emitted; when both terms are dead,
   that limb becomes a shared zero constant. SAR is deliberately excluded —
   its fill is sign-dependent, so pruning would constitute a new range claim.

## Soundness

- The 2^64 trap (a constant with a small limb0 and a nonzero high limb): the
  static decision uses the full constant. A constant ≥256 folds or keeps the
  guard; nullptr is passed only when the full constant is <256.
- Term-liveness algebra (SHL reads `Value[SrcIdx]`/`Value[SrcIdx-1]`, SHR_U
  reads `Value[SrcIdx]`/`Value[SrcIdx+1]`): term-liveness was checked across
  the full parameter space (CompShift × ShiftMod × LiveLimbs ∈ {1,2,4} × shift
  amounts 0-255) against a reference implementation; the boundary cases such as
  shifted-dead/carry-live were hand-verified (e.g. a
  U64 value << 136, where the top result limb keeps only the carry term
  sourced from the live low limb).
- The early return occurs after both operands are popped. EVM stack operands
  are pure values with no side effects, so discarding unmaterialized value
  expressions is safe.
- Result range tag: SHR_U keeps the existing `ValueOp.getRange()`
  pass-through — pruning makes the zero limbs structurally zero, which
  strengthens rather than violates the tag. SHL stays U256. The only change is
  that the ≥256 fold product becomes a constant zero instead of a dynamic
  zero; the tag is more precise, which is the safe direction.

## Verification

- Differential coverage for these shift-lowering paths now ships separately
  with the consolidated EVM differential suite change
  (`docs/changes/2026-06-11-evm-differential-suite/`). That change carries 13
  fixtures plus the `EVMConstShiftDifferentialTest` suite covering cross-limb
  carry (<<96), source pruning (a u64 value <<200 / >>8), the carry-only
  emission branch (u64 value <<136), ≥256 folding, the 2^64 trap, SAR
  positive/negative sign-fill, and a dynamic-shift-amount regression control;
  interpreter and multipass outputs match byte-for-byte, and multipass is
  confirmed to actually JIT-compile the fixtures.
- multipass evmone-unittests 223/223; multipass evmone-statetest
  `-k fork_Cancun` 2723/2723; no regression in the golden suite;
  `tools/format.sh check` passes; no new warnings.

## Measurements

evmone-bench 27-bench (multipass, vs upstream/main baseline, median of 5):
median delta **-0.08%**. The shift-focused benchmarks and all >3% outliers
were re-measured at 15 reps; all fall back inside their respective cv noise
bands (blake2b_shifts +1.3% @cv 2.4-3.4%, sha1_shifts +0.2%, signextend
-0.1%, weierstrudel -1.8%).

Conclusion: **end-to-end neutral, no regression**. The benefit takes the form
of generated-code reduction at each constant-shift site — 4 Selects plus one
4-limb comparison chain, and for narrow values the dead source terms on top.
That reduction is not measurable in the hot-spot composition of this benchmark
suite. The effect on compiled-code size and register pressure has not been
quantified separately.

## Known limitations

1. Source-limb pruning trusts the Range contract. For narrow values produced
   inside a block by AND-masks or constants, the high limbs are physically
   zero. Narrow tags imported across blocks via `EntryStackRanges` depend on
   the analyzer's sound over-approximation; this was checked and currently
   holds (`meetRange=max` is monotone and the SHL transfer is U256). That path
   is gated by `ZEN_ENABLE_EVM_STACK_SSA_LIFT`, which is OFF by default and in
   CI. If it is ever enabled by default, the analyzer transfer soundness
   should be re-reviewed first, and differential fixtures for cross-block
   narrow tags under lift-ON should be added.
2. The narrow values in the existing differential fixtures all come from
   producers that physically zero the high limbs (AND-masks). The cross-block
   path proven only by analyzer tags is not covered (same as above; follow-up
   in the lift series).

## Checklist

- [x] Implementation complete
- [x] Tests added/updated
- [ ] Module specs in `docs/modules/` updated (if affected)
- [x] Build and tests pass
