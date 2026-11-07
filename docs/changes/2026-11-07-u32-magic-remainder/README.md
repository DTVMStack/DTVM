# Change: Extend unsigned i32 constant remainder strength reduction

- **Status**: Proposed
- **Date**: 2026-11-07
- **Tier**: Light

Use the existing exact magic quotient expansion for nonzero/nonpow2 constant
unsigned i32 remainder, followed by dividend - quotient * divisor.
Preserve single evaluation and traps; direct effectful MIR trees stay unchanged.
No signed/i64/FP feature or host-policy change.

Wasmtime45 implements this exact rule. Static inventories show candidate sites
in15/20 WAPM modules and30/30 PolyBench modules, with shared libc duplication.
Static prevalence does not establish runtime frequency or performance benefit.

- [x] Build and format
- [x] 102 MIR tests and98 WAST cases; explicit Fast/serial-Greedy/lazy/eager
- [ ] Native code confirms removal of targeted hardware DIV
- [ ] Identical-input latest-main/candidate/Wasmtime45 controlled measurements
- [ ] Independently confirm selected real-case effects; retain negatives
- [ ] Record compile, first-result, warm execution, code-size changes

Consult [compiler contracts](../../modules/compiler/spec.md). This implementation
shares one quotient builder with division; benchmark and verification are pending.
Base: merged PR644, upstream main3bff8bf. The separate single-mmap growth branch
is rebased on that main and is not included here.
