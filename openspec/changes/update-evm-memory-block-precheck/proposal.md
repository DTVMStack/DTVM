# Change: tighten and document EVM block-local memory precheck

## Summary

This change formalizes a conservative EVM multipass-JIT frontend optimization that hoists one block-local memory precheck for a narrow class of eligible direct-memory basic blocks, while also retaining compile-time diagnostics for development builds.

The implemented scope is intentionally smaller than a general memory-check hoisting pass. It only covers block-local constant-address `MLOAD`, `MSTORE`, and `MSTORE8` sequences that can be proven safe by a local bytecode scan. All other blocks stay on the existing per-op expansion path.

## Why

Week 1 and Week 2 analysis showed that the main P1.2 cost is not the absence of direct memory access, but repeated frontend-generated memory expansion control flow:

- `handleMLoad()`, `handleMStore()`, and `handleMStore8()` each emit their own `expandMemoryIR(...)` path
- `expandMemoryIR(...)` materializes overflow checks, max-size checks, `NeedExpand` checks, and expansion-only CFG
- some straight-line blocks contain multiple direct-memory ops whose required sizes are compile-time constant and monotonic

Block-level diagnostics made the first safe optimization target explicit:

- blocks with at least two direct-memory ops
- no helper-sensitive opcode barrier
- no unsupported stack effect in the local scan
- no dynamic or malformed address pattern

Without documenting this boundary precisely, the current OpenSpec text understates the real optimization behavior and does not clearly separate optimization logic from diagnostics-only instrumentation.

## Problem Statement

The existing docs are too brief for the current implementation. They do not fully describe:

- how eligibility is decided
- how basic-block scanning stops
- how malformed or truncated `PUSHn` immediates invalidate the optimization
- how `MaxRequiredSize` is derived
- which per-op expansion checks are skipped after precheck coverage
- which operations are deliberately excluded
- how diagnostics are gated behind `ZEN_ENABLE_MULTIPASS_JIT_LOGGING`
- how the implementation preserves the frontend's existing condition-value typing model

This leaves review risk, maintenance risk, and a mismatch between the code and the documented scope.

## Goals

- Document the current optimization as implemented, not as an aspirational future pass
- Clarify the exact eligibility envelope for block-local memory precheck planning
- Specify the scanner's block-boundary, terminator, and malformed-bytecode behavior
- Explain which per-op expansion checks are eliminated on covered paths and which paths still fall back
- Separate semantics-affecting optimization logic from diagnostics-only bookkeeping
- Provide a verification plan that matches the current code and recent CI fixes

## Non-Goals

- Expanding coverage to dynamic-address recurrence patterns
- Hoisting memory checks across basic blocks or loops
- Covering helper-sensitive blocks (`LOG*`, `KECCAK256`, `*COPY`, `CALL*`, `CREATE*`)
- Covering `MCOPY` in the block-local precheck path
- Redesigning runtime memory helpers or gas accounting
- Changing backend or x86 lowering behavior
- Introducing new runtime flags or new logging modes

## Scope

### In Scope

- builder-side state for block-local precheck planning and consumption
- visitor-side bytecode scan for a conservative constant-address direct-memory subset
- one shared precheck for eligible blocks before covered direct-memory ops
- compile-time diagnostics and block summary logging for development builds
- documentation of the current condition-value and overflow typing expectations

### Out of Scope

- any block shape that cannot be proven eligible by the current local stack simulation
- malformed patterns that cannot be resolved conservatively
- helper-sensitive paths that may require memory-size reload or other ordering constraints

## What Changes

### Optimization behavior

The EVM bytecode visitor performs a block-local scan at block entry and, if the block is eligible, installs a `MemoryBlockConstPrecheckPlan` into `EVMMirBuilder`.

The builder then:

- emits one shared `expandMemoryIR(RequiredSize, NoOverflow)` when the first covered direct-memory op is compiled
- marks the plan as emitted
- decrements remaining coverage on subsequent covered ops
- skips the redundant per-op pre-expansion path for those covered ops

### Diagnostics behavior

The same implementation keeps compile-time instrumentation for:

- aggregate memory compile counters
- per-block memory summaries
- precheck hit accounting

These counters are diagnostics-only and are gated by `ZEN_ENABLE_MULTIPASS_JIT_LOGGING`, so non-logging builds keep the optimization behavior but avoid the extra bookkeeping work.

### Correctness hardening included in the documented behavior

The documented implementation also includes these analysis constraints:

- `JUMPI` is treated as a block terminator during scan
- truncated or malformed `PUSHn` immediates invalidate the plan
- `NoOverflow` in the precheck path uses the existing EVM frontend condition type representation rather than a new boolean type

## Expected Benefits

- reduce repeated `expandMemoryIR()` emission inside covered direct-memory blocks
- reduce repeated `NeedExpand` CFG generation on those covered paths
- keep the optimization reviewable because unsupported shapes still take the original path
- preserve development visibility via logging when enabled

## Constraints and Trade-offs

- the optimization is intentionally narrow to preserve correctness and make review simpler
- the current prototype does not improve dynamic-address `memory_grow_*` benchmark paths yet
- diagnostics remain available in logging builds, but are intentionally compiled out of non-logging builds

## Affected Artifacts

### Specs

- `openspec/changes/update-evm-memory-block-precheck/specs/evm-jit/spec.md`

### Design and Tasks

- `openspec/changes/update-evm-memory-block-precheck/design.md`
- `openspec/changes/update-evm-memory-block-precheck/tasks.md`

### Code already implementing this change

- `src/action/evm_bytecode_visitor.h`
- `src/compiler/evm_frontend/evm_mir_compiler.h`
- `src/compiler/evm_frontend/evm_mir_compiler.cpp`

## Risks

- over-documenting capabilities that are not actually implemented
- under-documenting failure and fallback cases, which would mislead future extension work
- conflating diagnostics counters with optimization semantics

This proposal addresses those risks by rewriting the change docs around current code behavior, explicit boundaries, and verifiable scenarios.
