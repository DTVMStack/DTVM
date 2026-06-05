# Change: Cache EVM host CALL modules by code identity

- **Status**: Implemented
- **Date**: 2026-06-05
- **Tier**: Light

## Overview

Add a transaction-local module cache to `ZenMockedEVMHost` for recursive EVM
CALL execution. Repeated internal calls to the same contract code should reuse
the already-loaded `EVMModule` and only create a fresh `EVMInstance` per call.

## Motivation

Replay benchmarks show ERC20 transfer and Uniswap v3 swap execution time is
dominated by repeated host CALL re-entry. The current host generates a unique
module name and calls `Runtime::loadEVMModule()` for every recursive CALL, so
the same bytecode may repeatedly pay module creation, analyzer, and JIT costs
within one transaction.

The cache preserves execution isolation by reusing only immutable module state;
each call still gets a new isolation and instance.

## Impact

- `src/tests/evm_test_host.hpp`: recursive CALL module lookup/load behavior.
- EVM replay/state-test tooling that uses `ZenMockedEVMHost`.
- Runtime and EVM public contracts are unchanged.

The first implementation intentionally excludes CREATE/initcode from the cache
because CREATE has distinct lifecycle and address-collision semantics.

## Checklist

- [x] Implementation complete
- [x] Tests added/updated
- [x] Module specs in `docs/modules/` updated (not required; no public module
      contract changed)
- [x] Build and tests pass
