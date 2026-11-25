# Reduce FastRA register-unit and operand scan overhead

- **Status**: Implemented
- **Date**: 2026-11-25
- **Tier**: Light

Represent the two per-instruction sets of physical register units as
bit vectors indexed by the target's dense unit IDs. These sets only
use membership, insertion, removal, and reset operations. Keep the
existing reset points and alias checks.

Record register definition positions and virtual use operands during the
allocator's initial operand scan. Reuse that information for definition
allocation, reverse-order release, and virtual use allocation. Tied
definitions, physical uses, and register masks keep their allocation order.

[Benchmark results and reproduction commands](BENCHMARK.md)
