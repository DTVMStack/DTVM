# Reduce signed i32 remainder by literal divisors

- **Status**: Implemented
- **Date**: 2026-11-21
- **Tier**: Light

Extend Wasm multipass lowering to compute signed i32 remainder by an eligible
non-power-of-two literal using a widened multiply and shifts. Reuse LLVM's
signed division constants. Evaluate the dividend once and keep the existing
zero, unit, and dynamic divisor paths.

- [x] Compare generated code with main and Wasmtime 45.
- [x] Verify both dividend signs, minimum and maximum values, and trapping operands.
- [x] Measure cold calls, dependent loops, and WAPM and PolyBench controls.

Two hosts confirmed the arithmetic kernel gains. The default-lazy
`gesummv` slowdown from the initial cohorts did not recur with main A/A
controls. The Singlepass `qr2text` process-wall difference also did not
recur on either host with independently copied executables and inherited
CPU affinity. [Measurements and reproduction](BENCHMARK.md) · [Regression analysis](REGRESSION.md)
