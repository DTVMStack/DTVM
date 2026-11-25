# Use bit vectors for FastRA register-unit membership

- **Status**: Implemented
- **Date**: 2026-11-25
- **Tier**: Light

Represent the two per-instruction sets of physical register units as
bit vectors indexed by the target's dense unit IDs. These sets only
use membership, insertion, removal, and reset operations. Keep the
existing reset points and alias checks.

[Benchmark results and reproduction commands](BENCHMARK.md)
