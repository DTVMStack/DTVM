# Change: Extend unsigned i32 constant remainder strength reduction

- **Status**: Implemented
- **Date**: 2026-11-07
- **Tier**: Light

Use the existing exact magic quotient expansion for nonzero/nonpow2 constant
unsigned i32 remainder, followed by dividend - quotient * divisor.
Preserve single evaluation and traps; direct effectful MIR trees stay unchanged.
No signed/i64/FP feature or host-policy change.

Wasmtime45 implements this exact rule. Static inventories show candidate sites
in 15/20 WAPM modules and 30/30 PolyBench modules, with shared libc duplication.
Static prevalence does not establish runtime frequency or performance benefit.

- [x] Build and format
- [x] 102 MIR tests and 98 WAST cases; explicit Fast/serial-Greedy/lazy/eager
- [x] Native code confirms removal of targeted hardware DIV
- [x] Identical-input latest-main/candidate/Wasmtime45 controlled measurements
- [x] Independently repeat selected real-case effects; retain sign reversals
- [x] Record compile, first-result, warm execution, code-size changes

Consult [compiler contracts](../../modules/compiler/spec.md). This implementation
shares one quotient builder with division; verification and measurements are complete.
Base: merged PR644, upstream main 3bff8bf. The separate single-mmap growth branch
is rebased on that main and is not included here.

[Full report, all controls, compile costs and raw measurements](REPORT.md).
The confirmed gain is in dependent synthetic integer loops. Canonical WAPM and
selected PolyBench process-time effects did not consistently reproduce; do not
claim whole-suite acceleration. Serial FastRA zero-loop admission adds roughly
10–16 microseconds for the tested constants. ASan: 102 MIR/98 lazy WAST tests pass.
