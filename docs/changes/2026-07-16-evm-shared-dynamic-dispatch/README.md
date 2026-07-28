# Change: EVM shared dynamic jump dispatch

Status: Implemented
Date: 2026-07-16
Tier: Full

## Overview

Reduce EVM JIT frontend latency for contracts with many dynamic `JUMP` /
`JUMPI` instructions by avoiding per-source expansion of the full indirect
jump dispatch CFG.

The previous lowering built a complete dispatch graph for each dynamic jump
source. On large contracts with hundreds of `JUMPDEST`s and hundreds of dynamic
jump sites, this made frontend IR construction scale close to
`O(dynamic_jump_sites * jumpdest_count)`.

This change introduces:

- a conservative analyzer API for runtime dispatch candidate sets;
- a module-level shared dynamic dispatch CFG for full-table dispatch;
- per-source filtered dispatch only when a smaller candidate set is proven safe;
- compatibility wrappers in the bytecode visitor so test/mock builders can keep
  the old jump-handler interface.

## Design

The shared dispatch path preserves the existing runtime semantics:

1. each dynamic jump source materializes the computed target into
   `JumpTargetVar`;
2. sources branch to one shared dispatch block;
3. the shared dispatch block performs the existing hash/switch validation
   against valid `JUMPDEST`s;
4. valid cases branch to the existing jump-dest entry blocks and invalid cases
   branch to `EVMBadJumpDestination`.

Dynamic phi incoming registration remains per-source only when the frontend is
using per-source dispatch. The shared dispatch path is disabled under
`ZEN_ENABLE_EVM_STACK_SSA_LIFT` because that mode still depends on source-aware
predecessor accounting.

## Affected Files

- `src/compiler/evm_frontend/evm_analyzer.h`
- `src/action/evm_bytecode_visitor.h`
- `src/compiler/evm_frontend/evm_mir_compiler.h`
- `src/compiler/evm_frontend/evm_mir_compiler.cpp`
- `src/tests/evm_jit_frontend_tests.cpp`

## Validation

- Run code formatting checks.
- Build and run `evmJitFrontendTests`.
- Re-run representative large-contract frontend profiling and 200-transaction
  cold-run comparison.
