# Wasmtime 45.0.0 (TTFI / overflow / fib mainline)

Shared version for PolyBench TTFI, WAPM TTFI, overflow, and fib(30). Requires a source tree **already containing the `ttfi-report` instrumentation**.

## Instrumentation Locations

- `src/ttfi_report.rs`
- `Cargo.toml` (`ttfi-report` feature)
- `src/common.rs`, `src/commands/run.rs`

Example instrumented source: `/path/to/wasmtime-45.0.0`

> The equivalent patch for the paper-era 31.0.0 is `../wasmtime-31.0.0/patches/ttfi-report.patch` (same semantics; usable as a cherry-pick reference).

## Build

```bash
# The default source-path variable is WASMER_SRC (historical name; points at the wasmtime source)
WASMER_SRC=/path/to/wasmtime-45.0.0 ./build.sh
# artifact: out/wasmtime
```

## Usage (TTFI)

```bash
export WASMTIME_CACHE=0
rm -rf ~/.cache/wasmtime          # clear the cache before each cold start
./out/wasmtime run case.wasm --invoke main
# expected stdout: Total compilation time: <ms> ms (<µs> µs)
```

Benchmark entry points: [`../../docs/POLYBENCH_TTFI_REPRODUCE.md`](../../docs/POLYBENCH_TTFI_REPRODUCE.md), [`../../docs/WAPM_TTFI_REPRODUCTION.md`](../../docs/WAPM_TTFI_REPRODUCTION.md).
