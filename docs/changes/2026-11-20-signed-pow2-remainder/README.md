# Fold signed remainder by powers of two

- **Status**: Implemented
- **Date**: 2026-11-20
- **Tier**: Light

The Wasm multipass frontend lowers signed remainder through an overflow
split and x86 IDIV. For literal divisors whose unsigned magnitude is a
power of two greater than one, a sign bias and mask can compute the
toward-zero remainder using fixed-width integer arithmetic. Preserve
dividend evaluation and leave divide-by-zero and unit-divisor handling to
the existing path.

Check positive and negative divisors, the minimum signed value, trapped
dividends, and dynamic divisors. Inspect native code and measure two input
patterns against latest main, main singlepass, and uncached Wasmtime 45.
Check WAPM and PolyBench for repeatable regressions.

The two kernel cohorts and the 23-case catalog screen with independent
confirmation are recorded in [BENCHMARK.md](BENCHMARK.md).
