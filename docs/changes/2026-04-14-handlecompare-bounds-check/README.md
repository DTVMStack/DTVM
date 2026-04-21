# Change: Add bounds check before macro-fusion read in handleCompare

- **Status**: Implemented
- **Date**: 2026-04-14
- **Tier**: Light

## Overview

Add an early bounds check in `WASMByteCodeVisitor::handleCompare()` to prevent an out-of-bounds read when peeking the next opcode for macro-fusion optimization.

## Motivation

In `handleCompare()`, the code attempts to read the next opcode (`*Ip`) to detect macro-fusion opportunities (e.g., fusing a compare with a subsequent branch). However, when the compare instruction is the last opcode in the bytecode stream (`Ip >= End`), this dereference reads past the end of the buffer — causing **undefined behavior** (out-of-bounds memory access).

Without the fix, a crafted or truncated WASM module where a compare is the final instruction would trigger an OOB read in both debug and release builds.

## Impact

- **Module**: `src/action/bytecode_visitor.h` — `WASMByteCodeVisitor::handleCompare()`
- **Contracts affected**: None (internal implementation detail; no API change)
- **Behavior change**: When `Ip >= End`, the code now falls back to the non-fused `handleCompareOp` path and returns safely, instead of performing an OOB read.

## Checklist

- [x] Implementation complete
- [ ] Tests added/updated (defensive check; unreachable via normal WASM validation)
- [x] Module specs in `docs/modules/` updated (if affected)
- [x] Build and tests pass
