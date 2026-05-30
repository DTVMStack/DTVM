# Change: Constant-fold EXP and SIGNEXTEND in the EVM MIR builder

- **Status**: Implemented
- **Date**: 2026-05-29
- **Tier**: Light

## Overview

Add compile-time constant folding for the `EXP` and `SIGNEXTEND` opcodes in the
EVM-to-dMIR frontend. When both operands are compile-time constants, the result
is computed directly and emitted as a constant `Operand`, instead of generating
the full inline lowering (square-and-multiply loop for `EXP`, multi-`select`
byte/sign machinery for `SIGNEXTEND`).

## Motivation

The u256 arithmetic fast-path audit (2026-05-29) found `EXP` and `SIGNEXTEND`
were the only arithmetic opcodes with **no** constant-folding tier, while peers
such as `MUL`/`MULMOD`/`ADD`/`BYTE` already fold. Constant `EXP` idioms
(`10 ** 18`, `2 ** 96` masks) are pervasive in Solidity yet currently emit the
entire inline `EXP` loop (dozens of multiply steps). Folding is the single
highest-leverage, lowest-risk improvement identified by the audit: it is
unconditionally sound (no value-range hazard) and independent of other work.

## Impact

- Module: `src/compiler/evm_frontend` — `handleExp`, `handleSignextend`.
  - `handleExp`: fold via `intx::exp(base, exponent)` (matches EVM
    `base ** exponent mod 2^256`).
  - `handleSignextend`: `index >= 31` returns the value unchanged; otherwise
    sign-extend from bit `index*8 + 7`, mirroring the inline lowering.
- No change to the non-constant lowering paths; behavior for runtime operands is
  byte-identical.
- Affected contracts: any with constant `EXP`/`SIGNEXTEND` operands — smaller
  generated IR, faster compile, identical results.

## Checklist

- [x] Implementation complete
- [x] Tests added/updated (`EVMMirBuilderConstFoldTest.ExpFoldsConstantOperands`,
      `EVMMirBuilderConstFoldTest.SignextendFoldsConstantOperands`)
- [x] Module specs in `docs/modules/` updated (if affected) — none affected
- [x] Build and tests pass — multipass `evmone-unittests` 223/223, multipass
      `evmone-statetest -k fork_Cancun` 2723/2723, unit tests 5/5.

## Note: EXP dynamic gas

Initial folding skipped the EIP-160 dynamic gas (`GasPerByte * exponent-byte-
size`) charged inside `handleExp`, regressing `evm.exp*` unit tests and 123
state tests. Fixed by charging the equivalent constant gas on the fold path
(exponent byte-size is known at compile time). Re-validated: all green.
