# Change: Strength-reduce DIV/MOD/SMOD with a small constant dividend

- **Status**: Proposed
- **Date**: 2026-07-03
- **Tier**: Light

## Overview

For a compile-time-constant unsigned dividend `A` with a runtime divisor `x`
(the "constant numerator" shape, e.g. `DIV(3, x)` from `PUSH1 3; DIV`), the
multipass JIT lowered each op to a single guarded hardware 64-bit divide. This
change replaces that divide with a branchless compare/select ladder computed
from `A` at compile time:

- **DIV(A, x)**: `A / x` is a non-increasing step function of `x` with
  O(sqrt(A)) distinct values; emit one `(x <= xhi) ? q : prev` select per
  quotient segment (at most 8 segments, else fall back to the hardware divide).
- **MOD(A, x)**, `A <= 8`: enumerate the remainder directly with equality
  selects — `res = A` for `x > A`, then `res = (x == v) ? A % v : res` for
  `v = A..1` — no divide and no multiply. For larger `A` that still fits the
  segment budget, compute the quotient ladder and use `A - (A/x)*x`; otherwise
  fall back to the hardware divide.
- **SMOD(A, x)**, `0 < A <= 8`: the result takes the dividend's sign, so for a
  positive constant `A` it equals `A mod |x|`; compute `|x|` with the existing
  two's-complement-negate idiom and dispatch to the unsigned MOD lowering.
  This shape previously fell through to the `GetSMod` runtime call.

The existing divide-by-zero select and upper-limb guard are preserved
unchanged, and every tier falls back to the previous lowering when the
constant is too large for a profitable ladder. SDIV is intentionally
untouched: a prototype constant-dividend path measured slower than its
current lowering.

## Motivation

On x86 a 64-bit integer divide is unpipelined (tens of cycles), and in a
data-dependent chain consecutive divides cannot overlap, so the single
hardware divide dominates steady-state cost. The replacement compare/select
chain lowers to `CMP`+`CMOVcc` sequences that are each ~1 cycle and
independent.

Measured on an 8-op dependent-chain loop corpus per opcode (median of 30 runs
after 5 warmups, x86-64 Linux, 2026-07-03, verifier-memoization change
applied on both sides):

| opcode | before (Mgas/s) | after (Mgas/s) | speedup | evmone, same corpus |
|---|---|---|---|---|
| DIV  | 3077 | 5379 | 1.75x | 4888 |
| MOD  | 2404 | 5123 | 2.13x | 4832 |
| SMOD | 1729 | 4373 | 2.53x | 4894 |
| SDIV | 1672 | 1675 | unchanged | 4897 |

Gas is byte-identical to the baseline and to evmone on every opcode.

## Impact

- Module: `src/compiler/evm_frontend` (`evm_mir_compiler.cpp` only):
  `handleDivU64Dividend`, `handleModU64Dividend`, and a new constant-dividend
  entry in `handleSMod`.
- **Depends on the MIR-verifier memoization change** (this branch includes
  it). The ladder emits more shared MIR nodes per op than the single divide,
  which amplifies the verifier's per-path DAG walk. Compile time of a 12-op
  dependent DIV chain across the three configurations: unpatched main
  (hardware-divide lowering, unmemoized verifier) 17.7 ms; ladder lowering
  without the memoization fix 3.5 s; ladder lowering with the fix 3.0 ms.
  With both changes, compile time is linear in chain depth and lower than the
  memoized hardware-divide lowering (depth 32: 6.6 ms vs 10.0 ms), because the
  ladder nodes verify and lower more cheaply than the guarded-divide
  expression tree.
- Correctness: a differential harness compared this build against evmone on
  DIV/SDIV/MOD/SMOD with the dividend as a bytecode constant and the divisor
  from calldata. 19 dividends: the enumeration tier (1, 2, 3, 5, 7, 8), the
  ladder tier (9, 12, 16, 20, 21), the fallback tier (100, 255, 65535, 2^32,
  2^63, 2^64-1), and non-u64 controls (2^64, -2^255). 41 divisors: 0;
  nineteen values between 1 and 22; 99, 100, 101, 255, 256; the u64/limb
  boundaries 2^31, 2^32, 2^62, 2^63, 2^63+1, 2^64-2, 2^64-1, 2^64, 2^64+1;
  2^128; 2^192; 2^255; and the negative values -1, -2, -3, -20. Result:
  3116 cases (4 x 19 x 41), 0 output mismatches, 0 gas mismatches.

## Tests

- `evmone-unittests` (multipass run list): pass.
- `evmone-statetest` over the EEST `state_tests` corpus (`-k fork_Cancun`): pass.
- `tests/evm_asm` full suite: 211 total, 198 passed, 13 skipped, 0 failed —
  identical counts to the unpatched baseline build.
- Differential harness vs evmone as described above: 3116/3116.
- `tools/format.sh check` clean; 0 new compiler warnings.

## Checklist

- [x] Implementation complete
- [ ] Tests added/updated — covered by the differential harness during
  development and the existing suites above; no new unit test retained
- [ ] Module specs in `docs/modules/` updated (if affected) — not affected
- [x] Build and tests pass
