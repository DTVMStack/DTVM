# WAPM Benchmarks

21 WAPM wasm files (the paper's 20 cases + `fortune`, which the reproduction scripts use as a substitute for `zuk`), used for the lazy time-to-first-invocation (TTFI) experiment.

## Migrated Contents

- 21 `.wasm` files (paper's 20 cases + `fortune` substitute) + test configs + `runtest_wapm.sh`
- `fonts/`, `parallel-small.png` runtime dependencies
- `MANIFEST.md`, `SHA256SUMS`

## Related Raw Data

The paper's lazy TTFI table (not shipped) compares dtvm lazy vs wasmtime/wasmer for the 20 cases.

## Missing

- `test_lazy.sh` (referenced by the experiment notebook; absent from the archive)
