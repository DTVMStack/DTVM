<!--
Copyright (C) 2025 the DTVM authors. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
-->

# dMIR To CgIR/x86 Mapping

## Scope

This note records the lowering bridge for the dMIR arithmetic subset that the
offline rewrite pipeline currently touches, plus the safe subset already wired
into the production dMIR rewrite pass:

- integer `add/sub`
- `cmp`
- `select`
- `adc/sbb`
- EVM 64x64->128 multiplication helpers
- EVM 128/64 division helpers

Phase 1 keeps the production DSL at `CgIR/x86`, so every dMIR-side candidate
rule eventually has to be translated into the instruction families emitted by
`X86CgLowering`.

## Current Production Status

`JITCompilerBase::compileMIRToCgIR()` now runs a tree-local `DMirRewritePass`
after `dead_mbb_elim` and before x86 lowering. The pass currently applies only
a conservative in-code subset of accepted rules whose replacements are either
existing subtrees, typed integer constants, or small synthesized boolean
expressions, for example:

- `add/sub/or/xor/shift` identities with zero
- `and` identities with zero or all-ones
- `not(not x) => x`
- `select(cond, x, x) => x`
- complement folds such as `or((not x), x) => allones`
- boolean factoring such as `xor((and x y), (xor x y)) => (or x y)`

`adc` and `sbb` candidates remain validation-only: the explicit third operand
is visible in dMIR, but rewriting them safely still requires carry/borrow-chain
proof beyond the current structural pass.

## Mapping Table

| dMIR expression family | Lowering entrypoint | CgIR/x86 family | Bridge notes |
| --- | --- | --- | --- |
| `add`, `sub` | generic FastISel path in `CgLowering<X86CgLowering>` plus `X86GenFastISel.inc` (see `src/compiler/target/x86/x86lowering.h`) | `ADD*rr/ri`, `SUB*rr/ri` | This path is table-driven, not hand-written in `x86lowering.cpp`. The exact register/immediate form depends on operand materialization. |
| `cmp` | `X86CgLowering::lowerCmpExpr()` in `src/compiler/target/x86/x86lowering.cpp` | compare op (`CMP*` or `TEST*`) + `SETCCr` + optional `MOVZX32rr8` | Integer compare results become 8-bit condition materialization first, then widen to i32/i64. This is the source-side pattern behind the existing `SETCCr/TEST8rr/JCC_1` peephole fold. |
| `select` | `X86CgLowering::lowerSelectExpr()` in `src/compiler/target/x86/x86lowering.cpp` | integer: `CMOV*`; floating-point: conditional branch + `COPY` | Integer `select` survives as a recognizable dataflow choice. Floating-point `select` is lowered into control flow and loses the direct value-select shape. |
| `adc` | `X86CgLowering::lowerAdcExpr()` in `src/compiler/target/x86/x86lowering.cpp` | `ADC8rr`, `ADC16rr`, `ADC32rr`, `ADC64rr` | The carry operand is not reified in x86 CgIR. Lowering asserts that operand 2 is the constant zero and then consumes the hardware `CF` chain directly. Any dMIR-side analysis that depends on the explicit third operand being zero must therefore happen before lowering. That alone does not justify rewriting `adc(lhs, rhs, 0)` into `add(lhs, rhs)` inside an EVM carry chain. |
| `sbb` | `X86CgLowering::lowerSbbExpr()` in `src/compiler/target/x86/x86lowering.cpp` | `SBB8rr`, `SBB16rr`, `SBB32rr`, `SBB64rr` | Same information-loss caveat as `adc`: x86 CgIR only preserves the borrow-consuming instruction, not the explicit third operand from dMIR. The zero-borrow precondition can be checked only before lowering, but borrow-chain safety still has to be established separately. |
| `evm_umul128_lo`, `evm_umul128_hi` | `X86CgLowering::lowerEvmUmul128Expr()` and `lowerEvmUmul128HiExpr()` in `src/compiler/target/x86/x86lowering.cpp` | `COPY -> RAX`, `MUL64r`, `COPY RAX`, optional `COPY RDX` | The low half is always materialized from `RAX`. The high half exists only when an `evm_umul128_hi` user is present; lowering pre-scans the function and allocates the extra copy lazily. |
| `evm_udiv128_by64`, `evm_urem128_by64` | `X86CgLowering::lowerEvmUdiv128By64Expr()` and `lowerEvmUrem128By64Expr()` in `src/compiler/target/x86/x86lowering.cpp` | `COPY -> RDX`, `COPY -> RAX`, `DIV64r`, `COPY RAX`, `COPY RDX` | Quotient and remainder are split across `RAX` and `RDX`. As with `umul128`, the helper pair lowers to one x86 instruction plus explicit register copies. |

## Translation Rules For The Current Seed Set

The current seed dMIR candidate file lives at
`src/compiler/mir/dmir_rewrite_rules.json`. For Phase 1 option A, these rules
translate into x86-facing families as follows:

| dMIR candidate | x86-facing shape after lowering | Recommended landing layer |
| --- | --- | --- |
| `(add x 0:i64) => x` | `ADD*rr/ri` with a zero operand | x86 DSL can represent this, but only after matching the exact zero-immediate form. |
| `(not (not x)) => x` | `NOT*` pair | Either layer works; x86 DSL keeps it target-specific. |
| `(select cond x x) => x` | integer `CMOV*` or FP branch diamond | Prefer dMIR for the generic rule. Lowering splits the integer and FP cases. |
| `(adc x y 0:i64) => (add x y)` | `ADC*rr` consuming implicit `CF` | Only a dMIR-side candidate today. The explicit third operand disappears after lowering, so this precondition cannot be recovered at the x86 layer. A future promotion still needs carry-chain-specific safety proof. |
| `(sbb x y 0:i64) => (sub x y)` | `SBB*rr` consuming implicit `CF` | Same reasoning as `adc`: the precondition is only visible in dMIR, but promotion still needs borrow-chain-specific safety proof. |

## Why This Mapping Matters

Two pieces of information are lost across lowering:

- The explicit third operand of `adc/sbb`
- The high-level `select(cmp(...), lhs, rhs)` shape once it turns into x86
  condition codes plus `SETCCr`, `CMOV*`, or explicit branches

That split is the main reason the current implementation keeps three parallel
tracks:

- a conservative production `DMirRewritePass` for tree-local structural folds
- production peepholes at `CgIR/x86`
- offline dMIR candidate rules plus interpreter-backed validation

The bridge file above is the minimum subset needed to move rules between those
tracks without rediscovering the source locations each time.
