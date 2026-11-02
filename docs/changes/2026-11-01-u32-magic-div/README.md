# Change: u32 non-pow2 constant udiv via magic multiply

- **Status**: Implemented
- **Date**: 2026-11-01
- **Tier**: Light

## Overview

Strength-reduce `i32.div_u` by a non-zero, non-power-of-two constant into a
widening multiply and shift, using LLVM's
`UnsignedDivisionByConstantInfo` (Hacker's Delight unsigned magic numbers).

Power-of-two unsigned division and remainder use the existing shift/mask
lowering (DTVMStack #626). Divisor `0` is not folded, so the wasm integer-divide-by-zero trap is
unchanged.

The wasm frontend keeps reusable operand temps. The peephole recovers a
same-block constant assignment through `dread` to identify the divisor.

## Motivation

Hardware `DIV` on a u32 `/20` microbench is the hot instruction. The identity

```
q = trunc_i32((uext_i64(x) * 0xcccccccd) >> 36)
```

is the no-add case of the general magic expansion, not a `/20`-only special
case. Real static sites exist (jacobi `print_array` `/20`, libc formatting
`/10`); this change does not claim jacobi e2e stencil wins.

## Impact

- [compiler](../../modules/compiler/spec.md): `MIRPeephole` may rewrite
  `i32` `OP_udiv` when the divisor is a proven non-zero, non-pow2 constant
  (including a same-block local that holds that constant). Zero-divisor traps
  are preserved. No public API change.
- tests: helper brute-force, MIR litmus, WAST, microbench.

## Checklist

- [x] Implementation complete
- [x] Tests added/updated
- [x] Module specs in `docs/modules/` updated (if affected)
- [x] Build and tests pass

## Historical measurement (Release, multipass Greedy, `--disable-multipass-multithread`)

Kernel: 20e6-iteration `i32.div_u` loop. Five `/20` runs (Exe ms from
`--enable-statistics`):

| kernel | before Exe (median) | after Exe (median) |
| --- | ---: | ---: |
| u32 `/20` | 30.290 ms | 10.114 ms |
| u32 `/7` (add-indicator) | 30.281 ms | 14.973 ms |
| u32 `/10` | (same DIV loop, ~30.3 ms) | 10.080 ms |

After `/20` objdump of the Greedy body: `movabs $0xcccccccd; imul; shr $0x24`.
Hardware `div`/`idiv` count **1 → 0**.

## Rebase review (2026-11-02)

Rebased onto main including #633. This optimization still covers a distinct
case: unsigned i32 division by non-power-of-two constants. It does not
optimize i64 division or EVM 256-bit division. Historical timings above have
not been remeasured against this base and are not application-wide gains.

Keep effectful nested dividends intact in the add-indicator expansion;
frontend-materialized dividends still optimize. Constant/constant division
continues to use the existing algebra fold. Added varied divisor and quotient
boundary coverage, large unsigned divisors, dropped trapping dividends, and
single evaluation of a dividend call.

Local validation passed 3,436,326 formula cases using the LLVM 15 reference
magic-number algorithm (both add/no-add paths), 42 Wasmtime reference WAST
assertions, merged WAT validation, clang-format 15, and whitespace checks.
These are reference checks, not DTVM JIT execution. DTVM builds, MIR tests,
and spec tests on this rebased revision must pass in CI before merging.
