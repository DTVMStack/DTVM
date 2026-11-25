# Reduce CgIR function teardown work

- **Status**: Implemented
- **Date**: 2026-11-25
- **Tier**: Light

During whole-function destruction, destroy the instructions in each
block and discard the register use/def index with the function. The
index has no remaining readers at that point. The existing removal
hooks still update the index when an instruction is erased during a
pass.

The teardown path runs all instruction and block destructors. This
preserves the compiler memory pool's debug allocation tracking.

[Benchmark results and reproduction commands](BENCHMARK.md)
