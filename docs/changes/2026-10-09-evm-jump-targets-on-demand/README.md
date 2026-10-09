# Change: Resolve EVM jump targets only when a compile needs them

- **Status**: Proposed
- **Date**: 2026-10-09
- **Tier**: Light

## Overview

`buildBytecodeCache` resolves the constant JUMP/JUMPI targets of every module
with an abstract-stack pass and stores them in
`EVMBytecodeCache::ResolvedJumpTargets`. This change lets a build without SPP
leave the table empty and adds `resolveJumpTargets()` to fill it later.
`EVMModule` builds its interpreter-side cache without the table and completes
it in the new `getBytecodeCacheForJIT()`, which the JIT compiler calls.

The cache contents the interpreter reads, the table the JIT reads, and the
generated code are unchanged.

## Motivation

The table has two readers: `buildCFGEdges` in the SPP pipeline and the JIT
front end. A build without SPP returns from `buildGasChunksSPP` before
`buildCFGEdges`, and the interpreter never reads the table. A module that is
only interpreted therefore pays for a pass whose result nothing reads. That
is every module in interpreter mode, and in profile-guided JIT mode every
module until it is hot enough to be compiled.

Measured on `main` at `e839f6b` with the duplicate resolution call already
removed, Release build, on 338 mainnet contracts (5.1 MB of runtime bytecode):

| Interpreter-side `buildBytecodeCache`, total over 338 contracts | Before | After |
|---|---:|---:|
| Median of 30 repetitions | 105.3 ms | 71.7 ms |

The ranges are [104.0, 107.3] ms and [70.9, 79.9] ms.

## Impact

- `evm`: `buildBytecodeCache` gains `ResolveJumpTargets` (default `true`, so
  existing direct callers behave as before; an SPP build resolves regardless).
  New `resolveJumpTargets()`. `docs/modules/evm/cache-build.md` describes
  both.
- `runtime`: `EVMModule::getBytecodeCache()` may now return a cache whose
  `ResolvedJumpTargets` is empty when the cache was built without SPP.
  `EVMModule::getBytecodeCacheForJIT()` returns the same cache object with the
  table filled in.
- `compiler`: `EVMJITCompiler::compile()` reads the cache through
  `getBytecodeCacheForJIT()`.
- `vm`: the profile-guided JIT trigger calls `getBytecodeCacheForJIT()` before
  it queues a background compile. The table is therefore filled on the thread
  that interprets the module, and the compile thread only reads the cache, as
  before.

Verified on the 338 contracts: the other five cache fields are identical with
and without the table; the table resolved later equals the one resolved up
front (220,603 targets); and the JIT code of a module loaded for
profile-guided JIT and then compiled is byte-identical before and after.

## Checklist

- [x] Implementation complete
- [x] Tests added/updated
- [x] Module specs in `docs/modules/` updated (if affected)
- [x] Build and tests pass
