# Change: Strength-reduce signed division by a positive power of two

- **Status**: Implemented
- **Date**: 2026-11-01
- **Tier**: Light

## Overview

When wasm `i32.div_s` / `i64.div_s` has a compile-time **positive power-of-two**
divisor of known bitwidth, emit toward-zero signed division as a bias-plus
arithmetic shift instead of `sdiv`/`idiv`, and skip the `INT_MIN / -1`
overflow diamond. That overflow is impossible for a strictly positive divisor.

Unsigned `udiv`/`urem` power-of-two lowering is out of scope (DTVMStack #626).

## Motivation

Signed wasm division toward zero is not a raw arithmetic shift. The frontend
always emits an overflow compare against `INT_MIN` and `-1` plus an `sdiv`.
For a positive power-of-two divisor both are wasted: overflow cannot fire, and
the quotient is

```
q = (x + ((x >>s (bitwidth-1)) & (d-1))) >>s k    where d = 2^k > 0
```

Example, i32 `/ 8` (`k = 3`): `q = (x + ((x >>s 31) & 7)) >>s 3`.

Previously reported Greedy microbenchmark: i32 `/8`
Exe ~30.539→13.153 ms; `idiv` gone; static insn 41→22.

Originally reported Release multipass Greedy run, `--disable-multipass-multithread`,
`n=20e6` loop iters, 7 runs of the same `div8` kernel:

| | Before | After |
| --- | ---: | ---: |
| Exe min | 71.436 ms | 25.332 ms |
| static insns (`div8` loop) | 42 | 18 |
| `idiv` | 1 | 0 |

Hot loop after: `sar $31; and $7; add; sar $3`. Overflow trap path is gone.

## Impact

- [compiler](../../modules/compiler/spec.md): `FunctionMirBuilder::handleIDiv`
  for `BO_DIV_S` only; `MIRPeephole` may rewrite remaining pure `OP_sdiv` with
  a constant positive power-of-two rhs.
- Trap / gas / wrap: zero-divisor and `INT_MIN / -1` traps stay for every
  case this fold does **not** match. The folded case cannot trap. `OP_add`
  still wraps.

## Checklist

- [x] Implementation complete
- [x] Tests added/updated
- [x] Module specs in `docs/modules/` updated (if affected)
- [x] Build and tests pass (`mirPeepholeTests`; `signed_pow2_div` interp/SP/MP; `i32`/`i64`/`peephole` MP)

## Rebase review (2026-11-02)

Rebased onto main after #630/#631/#632. The signed-division optimization is
still absent from main and complements the existing unsigned folds.
The timings above are historical measurements, not a comparison against this
new base or an application-wide speedup. The benchmark initializes x to 1,
so x stays 1 throughout; it measures a narrow division kernel.

Added coverage for i64 / 2^62, INT_MIN divisors, and trapping dividends whose
/1 or /8 results are dropped. Local checks passed 94,940 deterministic
bias/shift property cases, 47 WAST assertions on Wasmtime, WAT validation,
clang-format 15, and whitespace checks. These reference checks do not execute
DTVM's generated code; DTVM JIT/spec tests must pass in CI before merging.
