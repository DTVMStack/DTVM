# Add EVM Stack SSA Lift in Multipass JIT

## Summary
Implement a conservative stack-to-virtual-register lifting path in the EVM multipass JIT frontend so stack values can flow across selected basic-block boundaries without immediate runtime stack materialization.

## Motivation
The current EVM JIT frontend spills most block-boundary stack state to `EVMInstance`, then reloads it in later blocks. This hides value flow from later code generation and adds avoidable load/store traffic. A conservative lifting pass in the EVM frontend improves generated IR quality while preserving determinism and fallback safety.

## What Changes
- Extend EVM bytecode analysis with block-local stack requirements, jumpdest canonicalization, CFG edges, and conservative entry-depth propagation.
- Add a lifted block mode in the EVM bytecode visitor.
- Represent lifted block entries with per-block virtual entry variables.
- Copy stack values across safe edges instead of eagerly spilling to runtime stack.
- Preserve runtime spill/materialization on unsupported or unsafe edges.

## Scope
This change targets a conservative Phase-1 implementation:
- safe fallthrough and constant-jump lifting
- conservative fallback for unsafe dynamic control flow
- no full MIR phi node support yet

## Impact
- Improves IR quality for safe EVM control-flow regions
- Reduces runtime stack traffic on lifted regions
- Preserves correctness by materializing state on unsupported edges

## Current Status
- The conservative Phase-1 frontend path is wired through `EVMAnalyzer`, `EVMByteCodeVisitor`, and `EVMMirBuilder`.
- Focused frontend regression coverage for lifted edges and fallback behavior has been added and used as the validation scope for this change.

