# Change: Reduce register allocation time on large EVM functions

- **Status**: Proposed
- **Date**: 2026-10-11
- **Tier**: Light

## Overview

Two changes to the multipass register allocation pipeline:

- `CgRegisterCoalescer::joinVirtRegs` asks `isHighCostLiveInterval` before it
  builds its two `JoinVals`, not after. The coalescer makes the same decisions
  and the generated code is unchanged.
- The EVM compiler marks the live interval of the function's only parameter,
  the instance pointer, unspillable before greedy allocation, so it stays in
  one register for the whole function. `compileMIRToCgIR` takes this as an
  opt-in flag; WebAssembly compilation is unchanged.

## Motivation

On large mainnet contracts, register allocation dominates compile time. Runtime
helper calls and state accesses read the instance pointer throughout an EVM
function, yet greedy treats it like any other long interval: it splits it,
spills the pieces and keeps coming back to them. The coalescer, for its part,
repeatedly sets up join state for the stack-size and stack-top intervals only
to give up on them.

Multipass JIT, 338 mainnet contracts, synchronous compilation, Release build:

| | Before | After |
|---|---:|---:|
| Total compile time | 529 s | 199 s |
| JIT code size, page-rounded | 228.3 MB | 217.1 MB |

Execution time of the generated code on `evmone-bench` is unchanged within
noise (geometric mean 0.998 on the `main` set).

## Impact

- `compiler`: `compileMIRToCgIR` gains `KeepFirstParamInRegister`, default
  `false`, which only `EVMJITCompiler` sets. `CgLowering::getVarReg()` exposes
  the variable-to-register map.
- Generated EVM code changes: the instance pointer lives in one callee-saved
  register. Most contracts get smaller code; individual benchmarks move by up
  to about 2% either way.

## Checklist

- [x] Implementation complete
- [x] Existing test suites pass
- [x] Module specs reviewed; no contract update required
- [x] Build and tests pass
