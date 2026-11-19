# Defer integer literals in wide x86 calls

- **Status**: Implemented
- **Date**: 2026-11-20
- **Tier**: Light

The x86 multipass compiler currently computes all arguments before placing them
in registers or stack slots. In wide calls, simultaneously live integer
literals can force extra saves and reloads. Materialize direct i32/i64 literals
at their existing ABI copy or stack store when a call has at least 16 operands.
This uses the existing literal emitter and preserves nonliteral evaluation
order, indirect target lowering and argument placement.

Measure the standalone change against main and Wasmtime 45 on pressure fixtures,
Clang-generated calls, and representative canonical cases. Exercise direct and
indirect calls, mixed argument classes and argument evaluation traps. The
compiler module specification documents the lowering invariant.

See [Benchmark and validation](BENCHMARK.md) for the measured results.
