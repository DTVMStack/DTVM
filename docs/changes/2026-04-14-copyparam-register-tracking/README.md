# Change: Move register tracking side-effect out of ZEN_ASSERT in copyParam

- **Status**: Implemented
- **Date**: 2026-04-14
- **Tier**: Light

## Overview

Move the `GpRegUsed` and `FpRegUsed` register tracking bit-or assignments out of `ZEN_ASSERT()` macros in `OnePassCodeGen::copyParam()`, so they execute in both debug and release builds.

## Motivation

The original code placed side-effect expressions inside `ZEN_ASSERT`:

```cpp
ZEN_ASSERT(GpRegUsed |= (1 << Reg));
ZEN_ASSERT(FpRegUsed |= (1 << Reg));
```

In release builds (`NDEBUG`), `ZEN_ASSERT` is compiled out entirely, which means the register tracking updates are silently skipped. This causes the singlepass JIT to lose track of which registers are in use during parameter copying, potentially leading to register allocation conflicts and incorrect code generation.

## Impact

- **Module**: `src/singlepass/common/codegen.h` — `OnePassCodeGen::copyParam()`
- **Contracts affected**: None (internal implementation detail; no API change)
- **Behavior change**: Register tracking now works correctly in release builds. No change in debug builds.

## Checklist

- [x] Implementation complete
- [x] Tests added/updated
- [x] Module specs in `docs/modules/` updated (if affected)
- [x] Build and tests pass
