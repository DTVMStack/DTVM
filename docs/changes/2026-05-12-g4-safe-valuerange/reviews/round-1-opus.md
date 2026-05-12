# Round 1 — Opus Review of G4-safe Spec

Reviewer: Opus 4.7
HEAD reviewed: `c644fbe` (worktree `/home/abmcar/DTVM/.worktrees/g4-safe-valuerange`)
Spec: `docs/changes/2026-05-12-g4-safe-valuerange/README.md`

## Verdict

**PASS** — with minor improvements. No correctness blockers found.

The three transforms (OR/XOR range threading, SHR_U range threading, U64-range
compare-side OR-fold skip) are sound against current HEAD. The
`ValueRange::U64` invariant is **structurally enforced** today: every U64
producer materializes literal MIR zero constants in limbs[1..3], so the
compare-side fast path's runtime safety does not rely on optimistic guesses.
The spec's line numbers (678, 692, 755 in the header; 2978, 3011, 3046 in the
.cpp) match HEAD exactly.

Three nits in *Improvements* — none gate the implementation; can be addressed
in the same PR or follow-up.

## Critical issues

None.

## Improvements

### I1. Document the "literal MIR zero in upper limbs" invariant explicitly

The spec says (lines 38–40 / 44–45):

> EVM observable semantics: unchanged. All optimizations rely on `getRange()`
> annotations established at producer sites; values whose runtime bits do not
> match their annotation would be a pre-existing invariant violation.

This is correct, but understates **why** today it is safe: every existing
`ValueRange::U64` producer materializes upper limbs as literal MIR zero
constants — the invariant is not just "runtime bits are zero", it is "the MIR
limb is a `createIntConstInstruction(I64Type, 0)`". I verified all eight
producer sites:

- `src/compiler/evm_frontend/evm_mir_compiler.h:565` (general compare result —
  built by `handleCompareImpl`, which calls `handleCompareEQZ` / `handleCompareEQ`
  / `handleCompareGT_LT` — each writes `Result[1..3] = Zero` literally; see
  `evm_mir_compiler.cpp:2771-2773`, `2802-2804`, and the GT_LT path)
- `evm_mir_compiler.h:629` (AND u64-const fast path) — `Result[I] = Zero` for `I >= 1`
- `evm_mir_compiler.cpp:2024` (DIV u64÷u64) — `U256Inst Result = {DivResult, Zero, Zero, Zero}`
- `evm_mir_compiler.cpp:2194` (MOD u64÷u64) — `U256Inst Result = {ModResult, Zero, Zero, Zero}`
- `evm_mir_compiler.cpp:3002-3006` (handleCompareEqU64) — `Result[I] = Zero`
- `evm_mir_compiler.cpp:3037-3041` (handleCompareLtRhsU64) — same
- `evm_mir_compiler.cpp:3073-3077` (handleCompareGtRhsU64) — same
- `evm_mir_compiler.cpp:3689-3693` (BYTE) — `ResultComponents[I] = Zero`

(The Phase-2 AND NarrowRange path at `evm_mir_compiler.h:636-655` also writes
`Result[I] = Zero` whenever `NarrowRange == U64` and `I >= 1` — confirming the
invariant is already industry-standard inside this file.)

Suggest adding a sentence to the *Risks* section that pins this down — and
that this PR preserves it: the new compare-side fast path **does not weaken**
the invariant because it only **reads** the Range tag and elides reading
`LHS[1..3]` entirely; it never *creates* a U64-tagged operand with
non-literal-zero upper limbs.

### I2. Phase 2 OR/XOR helper is fine; "Result[1..3] = Other[1..3]" pass-through holds

For Phase 1 OR/XOR fast path at `evm_mir_compiler.h:670-678`, the code
literally does:

```cpp
Result[0] = protectUnsafeValue(<OR/XOR of Other[0] and U64Val>, MirI64Type);
for (size_t I = 1; I < EVM_ELEMENTS_COUNT; ++I) {
  Result[I] = Other[I];
}
return Operand(Result, EVMType::UINT256);
```

The spec's proposed return-with-`OtherOp.getRange()` is sound because
`Result[1..3] == Other[1..3]` (identity pass-through; OR/XOR of `Other[I]`
with the U64 constant's upper limb, which is 0, is `Other[I]` and the code
correctly skips emitting that no-op). If `OtherOp` had `Range == U64`, its
upper limbs were already MIR zero (per I1), so `Result[1..3]` are also MIR
zero. Same logic for U128. **Spec claim verified.**

One small textual nit: the spec at line 69 says "Limb[0] is recomputed;
limbs[1..3] pass through unchanged from `OtherOp`. Their value-range claim is
preserved." Consider tightening to: "limbs[1..3] are the *same MInstruction
pointers* as `Other[I]`, so any zero-limb materialization in the producer is
preserved bit-identically — no semantic re-derivation needed."

### I3. SHR_U: confirm that result-limb MIR is **not** required to be literal-zero, only runtime-zero

In `handleLogicalRightShift` (cpp:3291) — for a U64 input where
`Value[1..3]` are literal MIR zero constants:

- Constant-shift path (3300-3355): result limbs are
  `Select(IsLargeShift, Zero, R)` where `R` is composed from `Value[SrcIdx]`
  and `Value[SrcIdx+1]` via `OP_ushr`/`OP_shl`/`OP_or`. If all `Value[J]` for
  `J ≥ 1` are MIR zero constants, then `R` is shift/OR of zeros, which the
  optimizer may or may not fold. **Runtime value is zero**, but MIR-level
  identity is `Select(IsLargeShift, Zero, <ushr-of-zero>)`, **not** a literal
  zero.
- Variable-shift path (3358-end): similar — variable-index selects from
  `Value[*]`, but all the sources are zero at runtime.

**Implication**: future consumers that re-read `extractU256Operand(SHR_U_result)`
and need MIR-level zero in limbs[1..3] (e.g., to constant-fold) **will not
get** literal zero — they will get a Select instruction. **Today's compare-side
fast path is unaffected** because it elides reading limbs[1..3] entirely when
`Range == U64`, but the spec should note that the SHR_U-produced Range
annotation is a *value-level* guarantee, not a *MIR-level* one. This matters
the moment a future opcode handler wants to constant-fold based on
`extractU256Operand[I] == Zero-instruction`.

**Recommendation**: add a 1-line note to the *Risks* or *Contracts preserved*
section: "SHR_U-produced U64-range operands have runtime-zero upper limbs but
the corresponding MIR may not be a literal zero constant — consumers must
gate on `Range` rather than MIR-pattern-match upper limbs."

### I4. Checklist is binary but missing one item

The Implementation Checklist (lines 119-129) is mostly measurable. One gap:
no checklist item covers the **assertion / DCHECK** practice. Suggest adding:

- [ ] No new producer site emits `ValueRange::U64` without setting
  `Result[1..3] = Zero` at the MIR level. (Verify by reading the diff;
  inheritance check, not codegen.)

This is mostly self-policing since the PR only touches *consumers* (OR/XOR
threading is pass-through, SHR_U is read-only on `ValueOp.getRange()`), but
flagging it prevents future producer-extension PRs from regressing the
invariant silently.

### I5. cfg-join interaction: textually orthogonal, semantically a soft coupling

The spec (line 17) claims orthogonality with `perf/value-range-cfg-join`.
**Textual orthogonality holds** — the cfg-join diff against
`upstream/main` is 64 lines in `evm_mir_compiler.{h,cpp}` and touches:

- `evm_mir_compiler.h:127` — `enum class ValueRange` → `using ValueRange = EVMValueRange`
  (just refactors the enum into a shared header; no semantic change)
- `evm_mir_compiler.h:~260` — adds `void setRange(ValueRange NewRange)`
- `evm_mir_compiler.h:311` — `createStackEntryOperand` gains
  `ValueRange Range = ValueRange::U256` parameter
- `evm_mir_compiler.cpp:1006-1017` — body of `createStackEntryOperand`
- `src/action/evm_bytecode_visitor.h:1132-1185` — calls `Opnd.setRange(EntryRanges[SlotIdx])`
  on every operand popped at a lifted-block boundary, retrofitting the analyzer-computed range

None of these overlap with G4-safe's touchpoints (`handleBitwiseOp:570-693`,
`handleShift:704-756`, three compare helpers at `evm_mir_compiler.cpp:2978/3011/3046`).
**The spec's "compose without conflict" claim is true at the file/diff level.**

However, there is a **semantic soft coupling worth surfacing**: cfg-join
attaches `Range = U64` to operands whose `U256Var` backing variables may
contain *anything* in upper-limb slots — the analyzer guarantees value-level
zero, not MIR-level zero. The G4-safe compare fast path skips reading those
upper limbs and trusts the Range tag. **If cfg-join's analyzer ever has a
soundness bug that over-narrows a Range to U64, the compare-side change here
amplifies the impact from "wrong upper limbs in arithmetic" to "wrong
boolean result of EQ/LT/GT".**

This is already the situation today for the AND NarrowRange path
(`evm_mir_compiler.h:633-655`), which also trusts `getRange()` and rewrites
upper limbs to Zero in the *output*. So G4-safe is **consistent with the
existing trust model**, not introducing a new one. But the spec should
acknowledge that cfg-join + G4-safe compose into a **trust-chain**:

> compare-side fast path correctness  ⇐  Range == U64 implies runtime upper
> limbs are zero  ⇐  (today) producer materializes literal zero MIR  ⇐
> (with cfg-join) analyzer soundness

Recommend adding to the *Risks* section: "When `perf/value-range-cfg-join`
lands, the compare-side fast path will additionally rely on the analyzer's
soundness — extend the analyzer's correctness test matrix to exercise EQ/LT/GT
with analyzer-narrowed range at the U64 boundary."

## Spec compliance audit

### Scope-creep check (passes)

The spec's "out of scope" list (line 15) — SUB, SHL, SAR, ADDMOD, MULMOD, EXP,
signed compare — is internally consistent. The Implementation section never
re-introduces any of them:

- Step 2 explicitly handles `BO_OR` / `BO_XOR` only (excludes `BO_AND` which
  is already done).
- Step 3 explicitly handles `BO_SHR_U`; the `if constexpr (Operator ==
  BinaryOperator::BO_SHR_U)` guard at the proposed line 755 site explicitly
  excludes SHL and SHR_S — verified against `evm_mir_compiler.h:747-753`.
- Step 4 explicitly names the three unsigned compare helpers; signed compare
  (`CO_LT_S`, `CO_GT_S`, `handleCompareSlt*` if any) is untouched.

No hidden scope-widening suggestion in the body.

### Step-reference accuracy

| Spec claim | Actual file:line | Match |
|---|---|---|
| `handleBitwiseOp` at `.h:570-693` | `.h:570-693` | ✓ |
| Phase 1 u64-const OR/XOR return at line 678 | `.h:678` (`return Operand(Result, EVMType::UINT256);`) | ✓ |
| Phase 5 general return at line 692 | `.h:692` (`return Operand(Result, EVMType::UINT256);`) | ✓ |
| `handleShift` at `.h:704-756` | `.h:704-756` (with return at 755) | ✓ |
| SHR return at line 755 | `.h:755` | ✓ |
| `handleCompareEqU64` around `.cpp:2978` | `.cpp:2978` | ✓ |
| `handleCompareLtRhsU64` around `.cpp:3011` | `.cpp:3011` | ✓ |
| `handleCompareGtRhsU64` around `.cpp:3046` | `.cpp:3046` | ✓ |
| `ValueRange` enum near `.h:127` | `.h:127-131` | ✓ |
| PR #458 → `fca0b1a` | `git log fca0b1a -1` confirms commit message starts `perf(evm): u256 arithmetic optimizations (shift/addmod/barrier/value-range/div-mod) (#458)` | ✓ |

### "Result encoding for narrow-path compares unchanged" claim (passes)

Spec (line 40) says `Result[0] = cmp`, `Result[1..3] = Zero`, `Range = U64`.
Verified for all three compare helpers — they always set `Result[I] = Zero` for
`I >= 1` regardless of whether the fast path was taken; the spec's "Preserve
the `protectUnsafeValue` wrap and the `Result[1..3] = Zero` tail in all three"
at line 99 is the correct guidance.

## Verified facts

| Claim | Source |
|---|---|
| `ValueRange` is `uint8_t` with `U64=0, U128=1, U256=2` | `evm_mir_compiler.h:127-131` |
| `Operand::getRange()` returns Range field | `evm_mir_compiler.h:259` |
| Range default is `U256` | `evm_mir_compiler.h:273` |
| `bothFitU64` checks both at `U64` | `evm_mir_compiler.h:262-264` |
| OR/XOR Phase-1 return drops range to default U256 today | `evm_mir_compiler.h:678` |
| OR/XOR Phase-5 general return drops range to default U256 today | `evm_mir_compiler.h:692` |
| SHR (all three) shares one return that drops range to default U256 today | `evm_mir_compiler.h:755` |
| `handleLogicalRightShift` body | `evm_mir_compiler.cpp:3291-3475` (approx) |
| `extractU256Operand` does not consult Range | `evm_mir_compiler.cpp:4900-4963` |
| All `ValueRange::U64` producers materialize literal-zero limbs[1..3] | See I1 list above |
| `handleCompareEqU64` upper-limbs OR-fold is at | `evm_mir_compiler.cpp:2991-3000` |
| `handleCompareLtRhsU64` upper-limbs OR-fold and SelectInstruction | `evm_mir_compiler.cpp:3020-3035` |
| `handleCompareGtRhsU64` upper-limbs OR-fold and SelectInstruction | `evm_mir_compiler.cpp:3056-3071` |
| cfg-join branch diff against upstream/main, evm_mir_compiler scope | 64 lines, no overlap with G4-safe touchpoints |
| `EVMValueRange` shared enum | `src/compiler/evm_frontend/evm_value_range.h` on `perf/value-range-cfg-join` |
| cfg-join retrofits Range onto popped operands | `src/action/evm_bytecode_visitor.h:1140-1185` on `perf/value-range-cfg-join` |

## Summary

Ship it. The spec is correct, scoped, and reproducible against HEAD. The
improvements above are documentation polish on the invariant chain (I1, I2,
I3, I5) and one optional checklist item (I4) — none block implementation.
The author can address them inline in the README or pick them up in PR
review comments.
