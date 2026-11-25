# Walk MIR peephole statements in place

- **Status**: Implemented
- **Date**: 2026-11-25
- **Tier**: Light

Walk the existing statement list by index. Keep the same index when a
constant conditional branch is erased, and advance when a statement is
kept or replaced. This removes the snapshot and membership set from each
basic block while preserving rewrite order and edge and phi updates.

Use the statement index to search short blocks backward for a local
assignment. Stop at the latest assignment, including a dynamic one.
Long blocks continue to use their existing per-variable index.

[Benchmark results and reproduction commands](BENCHMARK.md)
