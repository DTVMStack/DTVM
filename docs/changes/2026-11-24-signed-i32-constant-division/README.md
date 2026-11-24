# Reduce signed i32 division by literal divisors

- **Status**: Proposed
- **Date**: 2026-11-24
- **Tier**: Light

Reuse the Wasm Multipass signed remainder quotient for `i32.div_s` by a
literal whose magnitude is greater than one and is not a power of two.
Apply the sign of the divisor to the quotient after rounding toward zero.
Evaluate the dividend once and preserve the existing trap paths.

- [ ] Compare assembly, code size, and wall time with main and Wasmtime 45.
- [ ] Validate extreme dividends, negative divisors, traps, and side effects.
- [ ] Check first-process overhead and WAPM and PolyBench controls.
