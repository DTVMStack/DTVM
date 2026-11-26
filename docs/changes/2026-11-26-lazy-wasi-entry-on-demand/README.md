# Compile small WASI entries on demand in Lazy Multipass

- **Status**: Proposed
- **Date**: 2026-11-26
- **Tier**: Light

Background compilation can start building a WASI entry just before its first
foreground call. This can compile the same small function twice during CLI
startup. In a module with one internal function export and no WebAssembly
start section, defer `_start` with the WASI signature and a body
of at most 512 bytes to the foreground.

Use the configured allocator for the entry and publish through the same path
as serial lazy. Private promotion remains available to eligible callees.
Other entry scheduling follows the
[compiler specification](../../modules/compiler/spec.md).
