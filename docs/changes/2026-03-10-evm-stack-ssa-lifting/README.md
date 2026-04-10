# Change: implement true-SSA stack lifting for EVM multipass JIT

- **Status**: Implemented
- **Date**: 2026-03-10
- **Tier**: Full
- **PR**: #395

## Overview

Implement a conservative true-SSA stack lifting pass for the EVM multipass JIT frontend. The pass statically analyzes EVM bytecode basic blocks, identifies blocks where stack depth is fully resolved at compile time, and lifts runtime stack push/pop operations into SSA virtual registers with phi-node merges at control-flow join points. This eliminates redundant runtime stack memory traffic for lifted blocks while preserving correctness by falling back to the existing runtime stack for non-lifted blocks.

## Motivation

The EVM stack machine model requires every opcode to push/pop operands through a runtime stack array. In the multipass JIT path, this generates substantial memory traffic even when the stack depth at each program point is statically known. For straight-line code and blocks with resolved entry depths, the stack operations can be replaced by SSA register assignments, with phi nodes inserted at merge points where multiple predecessors provide different values for the same stack slot.

Prior profiling showed that stack push/pop lowering and the associated runtime memory accesses are a measurable fraction of JIT-compiled EVM execution cost, especially for arithmetic-heavy contracts.

## Impact

### Affected Modules

- `src/compiler/evm_frontend/` — analyzer, MIR compiler, new stack lifter
- `src/action/` — EVM bytecode visitor (block entry/exit state management)
- `src/compiler/cgir/` — CG basic block and function (phi operand support)
- `src/compiler/mir/` — new MIR opcodes for phi and stack merge
- `src/runtime/` — EVM module (multipass execution path awareness)
- `src/evm/` — opcode handlers (fallback path optimization)

### Affected Contracts

No external API changes. The optimization is internal to the JIT compilation pipeline.

### Compatibility

Fully backwards compatible. Non-lifted blocks continue to use the existing runtime stack path. The pass is gated by the multipass JIT feature flag (`ZEN_ENABLE_MULTIPASS_JIT`).

## Implementation Plan

### Phase 1: analyzer stack depth resolution

- [x] Extend `EVMAnalyzer` with per-block stack depth tracking (`ResolvedEntryStackDepth`, `ResolvedExitStackDepth`, `FullEntryStateDepth`)
- [x] Add forward dataflow pass to propagate stack depths across the CFG
- [x] Identify lifted blocks: blocks where entry depth is statically resolved and consistent across all predecessors
- [x] Track dynamic jump target compatibility regions for stack state transfer

### Phase 2: SSA stack lifter

- [x] Implement `EVMLiftedStackLifter` template class for managing lifted block entry states
- [x] Support `assignEntryState` for transferring logical stack vectors between predecessor and successor blocks
- [x] Support `getMergeMaterializationRequests` for generating phi-like merge requests at join points
- [x] Implement `getLogicalEntryState` to reconstruct the logical stack from assigned entry states

### Phase 3: bytecode visitor integration

- [x] Add lifted block entry state restoration at block entry (`restoreLiftedBlockLogicalEntryState`)
- [x] Add merge operand materialization at block entry (`materializeLiftedBlockMergeRequests`)
- [x] Route block exit through `finalizeBlockExit` with selective materialization
- [x] Handle JUMP, JUMPI, JUMPDEST, and implicit-stop control flow for lifted/non-lifted transitions
- [x] Propagate entry states from runtime stack for non-lifted to lifted transitions

### Phase 4: MIR and CGIR backend support

- [x] Add `evm_stack_merge` MIR opcode for phi-like stack slot merges
- [x] Add phi elimination pass in CGIR (`phi_elimination.cpp`)
- [x] Add `spillTrackedStackPreservingPrefix` for partial stack materialization preserving hidden live-in prefix
- [x] Add `registerCurrentBlockPC` for block-level tracking in MIR compiler

### Phase 5: testing and validation

- [x] Add `evm_jit_frontend_tests.cpp` with mock IRBuilder for frontend unit testing
- [x] Add SFINAE compatibility shims for test mock builders
- [x] Validate against existing EVM spec test suite
- [x] Validate stack underflow/overflow bounds checking for lifted blocks

## Compatibility Notes

No backwards-incompatible changes. The optimization is additive and transparent to the runtime interface. Non-multipass execution paths are unaffected.

## Risks

- **Correctness risk at merge points**: phi-node insertion must correctly handle all predecessor paths; mitigated by the conservative lifted-block eligibility criteria and runtime stack fallback for unresolved blocks
- **Analyzer depth resolution soundness**: incorrect depth propagation could cause miscompilation; mitigated by assertions on entry depth consistency and bounds validation at block entry
- **Dynamic jump targets**: blocks reachable via dynamic jumps require compatible stack depth across all possible sources; mitigated by the compatible-dynamic-jump-region analysis that only lifts blocks with consistent depth from all compatible predecessors
