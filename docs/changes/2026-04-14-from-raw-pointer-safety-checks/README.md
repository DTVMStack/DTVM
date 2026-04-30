# Change: Add safety checks to `from_raw_pointer` in Rust bindings

- **Status**: Accepted
- **Date**: 2026-04-14
- **Tier**: Light

## Overview

Add explicit null-pointer and alignment checks to `ZenInstance::from_raw_pointer()` in the Rust crate, replacing silent undefined behavior with clear panic messages.

## Motivation

`from_raw_pointer` converts a raw C `ZenInstanceExtern*` pointer back into a Rust `&ZenInstance<T>` reference. Previously, passing a null pointer or receiving a misaligned custom-data pointer would cause undefined behavior (null dereference or misaligned access). The fix adds three `assert!` checks:

1. `c_ptr` is not null
2. The custom-data pointer returned by `ZenGetInstanceCustomData` is not null
3. The custom-data pointer is properly aligned for `ZenInstance<T>`

## Impact

- **Module**: `rust_crate/src/core/instance.rs`
- Only affects the Rust binding layer; no changes to the C++ core.
- Callers passing invalid pointers will now get a clear panic message instead of silent UB. Note: since the project uses `panic=abort` by default, panics at the FFI boundary will abort the process rather than unwinding across the FFI boundary (which would itself be UB). This ensures safe, deterministic failure.

## Checklist

- [x] Implementation complete
- [x] Tests added/updated
- [ ] Module specs in `docs/modules/` updated (if affected)
- [x] Build and tests pass
