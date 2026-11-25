# Skip redundant MIR peephole work

- **Status**: Implemented
- **Date**: 2026-11-25
- **Tier**: Light

Return literals and local reads directly during expression rewriting.
The parent expression continues to apply its existing folding rules.

Track floating-point literals when instructions are created. Skip the
separate hoisting walk when there are no such literals in the function.
Keep the bit conservative after individual instruction erasure and
reset it when the function's instructions are discarded.

[Benchmark results and reproduction commands](BENCHMARK.md)
