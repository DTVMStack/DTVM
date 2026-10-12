# Change: Report unexpected faults in EVM JIT code as internal errors

- **Status**: Proposed
- **Date**: 2026-10-11
- **Tier**: Light

## Overview

`Runtime::callEVMInJITMode` mapped every SIGSEGV and SIGBUS raised in JIT code,
other than native stack exhaustion, to `OutOfBoundsMemory` /
`EVMC_INVALID_MEMORY_ACCESS`. It now reports them as `EVMC_INTERNAL_ERROR`,
the status it already uses for other unexpected signals. Stack exhaustion still
maps to `EVMC_STACK_OVERFLOW`.

## Motivation

The mapping comes from WebAssembly, where linear memory is bounds-checked by
guard pages and a fault is a legitimate out-of-bounds access. EVM memory is a
heap buffer expanded explicitly before every access, and EVM exceptions are
raised through the illegal-instruction trap, so in EVM JIT code a memory fault
can only be an engine defect.

`EVMC_INVALID_MEMORY_ACCESS` is an EVM halt that an embedder accepts as a valid
result, so such a defect produced a plausible but wrong execution instead of a
failure. This happened with the stale cached memory base fixed in #600: the
replay of mainnet block 25818502 finished with wrong gas instead of stopping.

## Impact

- `runtime`: the SIGSEGV/SIGBUS branch of `callEVMInJITMode`. WebAssembly
  execution is unchanged.
- Breaking for embedders: a fault in EVM JIT code now returns
  `EVMC_INTERNAL_ERROR`, which must not be accepted as a block result. No
  status changes for any condition the EVM defines.
- `docs/modules/evm/spec.md` lists `EVMC_INTERNAL_ERROR`.

## Checklist

- [x] Implementation complete
- [x] Existing test suites pass
- [x] Module specs in `docs/modules/` updated
- [x] Build and tests pass
