# Verify common MIR leaf instructions without a hash lookup

- **Status**: Implemented
- **Date**: 2026-11-24
- **Tier**: Light

Local reads and constants have no operand edges. Dispatch their existing
checks directly during MIR verification. Keep visit tracking for the rest of
the operand graph to detect cycles and avoid rechecking shared subgraphs.
The compiler still verifies MIR before and after its optimization passes.

[Benchmark results and reproduction commands](BENCHMARK.md)
