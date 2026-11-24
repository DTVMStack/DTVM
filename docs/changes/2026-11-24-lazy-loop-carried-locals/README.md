# Select initial GreedyRA for integer loop-carried locals

- **Status**: Implemented
- **Date**: 2026-11-24
- **Tier**: Light

Extend the automatic foreground allocator policy to recognize a
call-free function whose single integer loop reads and rewrites several
Wasm locals across a self-edge. Use bounded MIR inspection and the
existing automatic Greedy size, time and disable controls.

- [x] Verify policy selection and exclusions.
- [x] Compare machine code, foreground compilation and execution on a single call.
- [x] Check WAPM, PolyBench, and the explicit allocator controls.

[Benchmark results and reproduction commands](BENCHMARK.md)
