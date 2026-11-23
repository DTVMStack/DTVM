# Reduce signed i32 remainder by literal divisors

- **Status**: Proposed
- **Date**: 2026-11-21
- **Tier**: Light

Extend Wasm multipass lowering to compute signed i32 remainder by an eligible
non-power-of-two literal using a widened multiply and shifts. Reuse LLVM's
signed division constants. Evaluate the dividend once and keep the existing
zero, unit, and dynamic divisor paths.

- [x] Compare generated code with main and Wasmtime 45.
- [x] Verify both dividend signs, minimum and maximum values, and trapping operands.
- [x] Measure cold calls, dependent loops, and WAPM and PolyBench controls.

The Multipass prototype speeds up the arithmetic kernels. Default lazy
`gesummv`, which has no `i32.rem_s`, was slower in two independent cohorts.
This leaves the uninstrumented executable's regression bound unresolved.
The experiment includes a main A/A comparison on an independent runner.
[Measurements and reproduction](BENCHMARK.md)
