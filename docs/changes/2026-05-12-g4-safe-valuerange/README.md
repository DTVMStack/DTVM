# Change: G4-safe ValueRange propagation for OR/XOR/SHR_U + range-driven compare

- **Status**: Proposed
- **Date**: 2026-05-12
- **Tier**: Light

## Overview

Extend `EVMMirBuilder::ValueRange` propagation to three monotone-safe sites:

1. `handleBitwiseOp<BO_OR>` / `handleBitwiseOp<BO_XOR>`: result range = `max(LHS.range, RHS.range)` (both Phase-1 u64-const fast path and Phase-5 general path).
2. `handleShift<BO_SHR_U>` (unsigned right shift): result range = `ValueOp.range` (right shift cannot widen).
3. `handleCompareEqU64` / `handleCompareLtRhsU64` / `handleCompareGtRhsU64`: when the wide operand carries `ValueRange::U64`, skip the upper-limbs OR-fold and emit a direct single-limb compare.

Explicitly **out of scope** for this PR per `2026-05-12-verified-opportunities.md` §1.G4 verdict: SUB (wraps to full U256), SHL (widens), SAR (sign-fills), ADDMOD/MULMOD (need richer range model), EXP, signed compare.

This work is **orthogonal** to the `perf/value-range-cfg-join` branch, which performs CFG-level join/meet range analysis and plumbs analyzer-derived ranges into block-entry operands. G4-safe adds per-opcode producer threading; cfg-join feeds those producers across control flow. The two compose without conflict (G4-safe touches `handleBitwiseOp`, `handleShift`, `handleCompare*RhsU64`; cfg-join touches `createStackEntryOperand` and adds an `EVMValueRange` external type).

## Motivation

`ValueRange` was introduced in PR #458 (`fca0b1a`) as a wholesale producer-side annotation: ADD/MUL/DIV/MOD/AND/BYTE/u64-compare populate it; the only non-arithmetic consumer is AND. Every other bitwise/shift/compare operator **drops the range to U256** even when the inputs are demonstrably narrower:

- `(narrow_mul a, b) | c` → range falls back to U256, blocking any downstream narrow-path lowering.
- `(narrow_mul a, b) >> k` → same loss.
- `(narrow_mul a, b) < C64` → constant fast path triggers, but the helper still emits a 3-upper-limb OR-fold check (`LHS[1] | LHS[2] | LHS[3]`) that we *know* is zero.

The 2026-05-12 verification doc isolated this as the smallest, lowest-risk subset of the G4 work: monotone propagation only, no wraparound or sign-fill semantics. The win is small per opcode but **load-bearing** for any future narrow consumer (compare-via-range, narrow lowering paths for additional opcodes).

## Impact

### Modules touched

- `src/compiler/evm_frontend/evm_mir_compiler.h` — three return sites in `handleBitwiseOp` (Phase 1 OR/XOR fast path, Phase 5 general path) and one in `handleShift`. Optionally a small `static maxRange` helper near the `ValueRange` enum.
- `src/compiler/evm_frontend/evm_mir_compiler.cpp` — three helper bodies: `handleCompareEqU64` (around line 2978), `handleCompareLtRhsU64` (around line 3011), `handleCompareGtRhsU64` (around line 3046).

### Contracts preserved

- EVM observable semantics: unchanged. All optimizations rely on `getRange()` annotations established at producer sites; values whose runtime bits do not match their annotation would be a pre-existing invariant violation.
- `protectUnsafeValue` calls remain on every generated I64 result that flows into stack-residence — the consumer side only changes WHICH limbs are computed, not their barrier annotation.
- Result encoding for narrow-path compares unchanged: `Result[0] = cmp`, `Result[1..3] = Zero`, `Range = U64`.

### Risks

- **Low**: monotone non-widening transformations only. OR/XOR of two operands with range `U128` yields a U128 value (limbs[2..3] of both operands are 0 → OR/XOR of zeros is zero). Logical right shift of a U64 value yields a U64 value (limbs[1..3] of input are 0 → shifting out is still zero in limbs[1..3]; shift cannot inject bits from above-limb).
- **Compare consumer change**: requires the producer-side `ValueRange::U64` invariant to hold at runtime. PR #458 establishes this invariant from ADD/MUL/DIV/MOD/AND; this PR extends it to OR/XOR/SHR_U.

### Invariant chain (correctness of the compare-side fast path)

The compare-side fast path trusts a **value-level** invariant: when an operand carries `ValueRange::U64`, its upper limbs evaluate to zero at runtime — even if the MIR for those limbs is not a literal `Zero` constant. This is the **Range contract**.

Two independent producer paths uphold the contract:

1. **Direct materialization** (pre-existing, since PR #458). Every producer that explicitly assigns `Range = U64` also writes literal MIR `Zero` to `limbs[1..3]`. Verified producer sites: `evm_mir_compiler.h:565` (general compare result), `evm_mir_compiler.h:629` (AND u64-const fast path), `evm_mir_compiler.cpp:2024` (DIV u64÷u64), `evm_mir_compiler.cpp:2194` (MOD u64÷u64), the three existing `handleCompare*U64` helpers, and BYTE.
2. **Analyzer-derived narrowing** (PR #493, `EVMRangeAnalyzer`). The dataflow analyzer retrofits `Range = U64` onto stack-popped operands whose backing variables hold any MIR that *evaluates to* a u64-fitting value. The analyzer guarantees value-level zero in `limbs[1..3]`, not literal-zero MIR.

The new compare-side fast path **does not weaken** the Range contract: it only reads `getRange()` and elides reading `LHS[1..3]`. It never creates a U64-tagged operand with non-zero upper-limb values.

**SHR_U caveat (value-level, not MIR-level)**: `handleLogicalRightShift` emits `Select(IsLargeShift, Zero, <ushr-of-zero>)` for upper limbs when the input has `ValueRange::U64`. The runtime value is zero, but the MIR is not necessarily a literal `Zero`. Consumers must gate on `Range` rather than MIR-pattern-match upper limbs — the compare-side fast path here does exactly that.

The same trust model already applies to the AND `NarrowRange` path at `evm_mir_compiler.h:633-655`.

## Implementation

### Step 1 — Helper: derive merged range for binary ops

Add an inline helper in `evm_mir_compiler.h` (near the `ValueRange` enum), or inline at use site:

```cpp
static ValueRange maxRange(const Operand &A, const Operand &B) {
  return A.getRange() > B.getRange() ? A.getRange() : B.getRange();
}
```

`ValueRange` is `uint8_t` with `U64=0 < U128=1 < U256=2`, so `>` gives the wider tier.

### Step 2 — OR/XOR: thread range through two return sites

In `handleBitwiseOp` (`evm_mir_compiler.h:570-693`):

- Phase 1 u64-const fast path return (currently line 678):
  ```cpp
  return Operand(Result, EVMType::UINT256, OtherOp.getRange());
  ```
  Rationale: the u64-const side has range U64, so `max(U64, OtherOp.range) = OtherOp.range`. Limb[0] is recomputed; limbs[1..3] pass through unchanged from `OtherOp`. Their value-range claim is preserved.

- Phase 5 general path return (currently line 692):
  ```cpp
  return Operand(Result, EVMType::UINT256, maxRange(LHSOp, RHSOp));
  ```

### Step 3 — Unsigned SHR: thread range from ValueOp

In `handleShift<BO_SHR_U>` (`evm_mir_compiler.h:704-756`):

Change the single shared `return Operand(Result, EVMType::UINT256);` (line 755) to be operator-aware:

```cpp
if constexpr (Operator == BinaryOperator::BO_SHR_U) {
  return Operand(Result, EVMType::UINT256, ValueOp.getRange());
}
return Operand(Result, EVMType::UINT256);
```

Rationale: for SHL the range *can* widen and we keep U256 default; for SAR sign-fill can populate upper limbs and we keep U256 default. For SHR_U, an N-bit value shifted right yields an at-most-N-bit value, so the range is preserved.

### Step 4 — Compare consumer: skip upper-limbs OR-fold when range is U64

Modify three helpers in `evm_mir_compiler.cpp`:

- `handleCompareEqU64`: when `FullOp.getRange() == ValueRange::U64`, the 3-upper-limb OR-fold (`Upper = LHS[1] | LHS[2] | LHS[3]`) is provably zero. Skip it; emit `FinalResult = ICMP_EQ(LHS[0], U64Val)` directly. Save 2 OR + 1 CMP + 1 AND per call.
- `handleCompareLtRhsU64`: when `LHSOp.getRange() == ValueRange::U64`, `HasUpper` is provably false. Skip the 3-upper-limb OR-fold and the `SelectInstruction`; emit `FinalResult = ICMP_ULT(LHS[0], RhsVal)` directly. Save 2 OR + 1 CMP + 1 SELECT.
- `handleCompareGtRhsU64`: when `LHSOp.getRange() == ValueRange::U64`, mirror of LT: emit `FinalResult = ICMP_UGT(LHS[0], RhsVal)` directly.

Preserve the `protectUnsafeValue` wrap and the `Result[1..3] = Zero` tail in all three. Return range remains `ValueRange::U64` (comparison results are 0 or 1).

### Step 5 — Build + verify

- Configure CMake with the worktree-bootstrap default flags (includes `-DZEN_ENABLE_JIT_PRECOMPILE_FALLBACK=ON` per memory `feedback_jit_fallback_required_flag.md`; otherwise peephole O(n²) `setInsertBlock` hangs).
- Run `tools/format.sh check`.
- Local tests per `.claude/rules/dtvm-local-test.md`:
  - `evmone-unittests` multipass with `EVMOneMultipassUnitTestsRunList.txt`
  - `evmone-statetest -k fork_Cancun` multipass with `enable_gas_metering=true`
- For perf measurement: `/bench-compare` on 27-bench vs upstream/main baseline (per `.claude/rules/dtvm-perf-worktree-lab.md`).

### Step 6 — Document the result back into the analysis doc

Update `docs/research/directions/u256-strength-reduction/analysis/2026-05-12-verified-opportunities.md`:

- §0 landed-status table: add a row for "G4-safe ValueRange OR/XOR/SHR_U/compare" with commit reference.
- §2 Tier 1 entry #1 and §3 Sprint 1: annotate as `Implemented` with link to this change doc and bench numbers.

## Checklist

- [ ] Step 1 helper or inline merge in place
- [ ] Step 2: OR/XOR Phase 1 + Phase 5 returns thread range
- [ ] Step 3: SHR_U return threads `ValueOp.getRange()`
- [ ] Step 4: three compare helpers gain U64-range early branch
- [ ] `tools/format.sh check` passes
- [ ] Build with CI-faithful flags green
- [ ] `evmone-unittests` (multipass) green
- [ ] `evmone-statetest -k fork_Cancun` (multipass) green
- [ ] `/bench-compare` shows no regression vs upstream/main on 27-bench
- [ ] `2026-05-12-verified-opportunities.md` updated with shipped status
- [ ] Module specs in `docs/modules/` updated (if affected — likely not for this change)
- [ ] No new producer site emits `ValueRange::U64` without setting `Result[1..3] = Zero` at the MIR level (self-audit of the diff before commit)
