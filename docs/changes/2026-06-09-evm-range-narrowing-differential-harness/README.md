# Value-range lowering differential harness

## What

A C++ gtest suite (`EVMRangeDifferential` in `src/tests/evm_interp_tests.cpp`)
that runs EVM opcodes through both the interpreter and the multipass JIT on an
adversarial operand matrix and asserts the multipass result is bit-identical to
the interpreter (the full-width reference).

Four tests, split by which lowering path the operands actually drive:

- `BinaryOpsMatchInterpreterOnAdversarialOperands` — 20 binary opcodes (ADD,
  MUL, SUB, DIV, SDIV, MOD, SMOD, SIGNEXTEND, LT, GT, SLT, SGT, EQ, AND, OR,
  XOR, BYTE, SHL, SHR, SAR) over all pairs of an 11-value operand set. Both
  operands are dynamic `CALLDATALOAD` values (U256-range), so they do **not**
  enter the bothFitU64 / AND-narrow fast paths: this test gates the
  **full-width 4-limb lowering** — the #487-class high-limb-corruption surface.
  `EXP` is excluded because its gas cost scales with the exponent byte length,
  so the high-limb operands in this matrix (2^192, 2^255, 2^256-1) would charge
  enormous dynamic gas and trip out-of-gas before a value-range divergence
  could show.
- `ShiftAmountsMatchInterpreterOnLimbBoundaries` — SHL, SHR, SAR swept with
  shift amounts {2, 7, 8, 31, 63, 64, 65, 127, 128, 129, 136, 191, 192, 200,
  255} crossed with the 11-value matrix as the shifted value, both fed through
  `CALLDATALOAD` so the full-width dynamic shift path fires. The 11-value
  matrix, when used as a shift **amount**, only realizes {0, 1, >=2^64}, so the
  amounts 2..255 — where the dynamic-shift lowering moves bits across 64-bit
  limb boundaries (64/128/192) and within a limb (the rest) — are unreachable
  from the binary-op sweep. This test exercises that cross-limb carry/offset
  logic directly.
- `AndU64MaskMatchesInterpreter` — `AND` with a u64 constant (the CONST_U64
  fast path, which tags the result U64 and zeros limbs[1..3]) returned
  **directly**, over the adversarial set. Returning the masked value unconsumed
  is what makes a dropped/kept high limb observable.
- `AndU64MaskThenNarrowAddMatchesInterpreter` — the same u64-masked value fed
  through a self-`ADD` (the bothFitU64 narrow path), exercising a
  narrow-result **consumer**.

The two `AndU64Mask*` tests gate the actual narrowing fast paths; the binary-op
and shift-amount sweeps gate the full-width path.

## Why

A multipass value-range fast path emits a single- or double-limb result that
must equal the full 4-limb path for every input the range tag claims to cover.
A **too-narrow** tag silently miscompiles only on operands with non-zero high
limbs — exactly what ordinary corpora (evmone-statetest, real-load replay)
almost never carry. So a too-narrow narrowing can pass the entire existing
suite and still be wrong.

The interpreter is the full-width reference. Feeding high-sparse operands
(`{0,x,0,0}`, `{0,0,0,x}`, `2^192+5`, `2^255`) through both engines turns a
dropped or kept high limb into an observable interp-vs-multipass divergence.

To keep the differential from being vacuous, `rangeDiffRun` forces synchronous
multipass compilation (`DisableMultipassMultithread`) — the default async
config can fall back to the interpreter for a single call — and `rangeDiffAgree`
asserts `JITCompiled` so the multipass side really executes JIT code. That
assertion is compiled under `#ifdef ZEN_ENABLE_JIT`; the whole suite is already
gated on `ZEN_ENABLE_MULTIPASS_JIT`, so in the builds where these tests run the
multipass side is JIT-backed. In a hypothetical no-JIT build the assertion is
absent and the comparison would reduce to interpreter-vs-interpreter (still
correct, but not exercising the JIT).

## Adversarial operand set

`0`, `1`, `2^64-1`, `2^64`, `2^128-1`, `2^128`, `2^192`, `2^192+5`,
`{0,x,0,0}`, `2^255`, `2^256-1` — every value-range boundary plus the
high-sparse class that a too-narrow tag would corrupt.

## Negative control

To prove the harness catches a too-narrow narrowing rather than passing
vacuously, the AND-u64 fast path was temporarily mutated to keep the high limbs
(`Result[I] = Other[I]` instead of `Zero`). Rebuilt,
`AndU64MaskMatchesInterpreter` — the test that returns the masked value directly
— **failed** on the high-sparse inputs with an output divergence; reverting
restored green. (The consumer test `AndU64MaskThenNarrowAddMatchesInterpreter`
does **not** catch this mutation: its trailing bothFitU64 ADD reads only
limb[0] and re-zeros the high limbs, masking the bug — which is exactly why the
direct-return test exists.) The committed tree contains only the harness, not
the mutation.

## Testing

CI-faithful flags (`ZEN_ENABLE_JIT_PRECOMPILE_FALLBACK=ON`), `SPEC_TEST=ON` for
the test executables:

- `evmInterpTests --gtest_filter=EVMRangeDifferential.*`: **4 / 4 pass** on the
  current tree (multipass agrees with the interpreter on every adversarial
  pair, including all swept shift amounts).
- Negative control: the deliberate too-narrow AND mutation is caught by the
  direct-return test, then reverted.
- `tools/format.sh check`: pass.

Test-only change — no runtime / codegen impact on `libdtvmapi`.

## Scope and limits

This harness covers the **in-block** lowering: operands constructed and consumed
within one basic block (full-width via CALLDATALOAD; narrow via AND-mask /
bothFitU64). It does not yet drive a context-size producer
(CALLDATASIZE/GAS/...) into a narrow consumer, nor the **cross-block**
`EntryStackRanges` re-import path; both would extend the suite with dedicated
fixtures.
