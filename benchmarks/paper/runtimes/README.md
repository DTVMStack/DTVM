# Runtimes

Build scripts and version proofs for each runtime. **Binaries are not committed** (covered by `.gitignore`); each subdirectory keeps only `BUILD.md` / `build.sh` / `version.txt`.

## Paper Baselines (PolyBench wall-clock)

| Directory | Version | Purpose |
|-----------|---------|---------|
| [`wamr-1.2.3/`](wamr-1.2.3/) | WAMR 1.2.3 (`iwasm`) | interpreter baseline |
| [`wasmtime-31.0.0/`](wasmtime-31.0.0/) | Wasmtime 31.0.0 (optional TTFI instrumentation) | wall-clock baseline |
| [`wasmer-5.0.4/`](wasmer-5.0.4/) | Wasmer 5.0.4 (cr + sp + optional llvm/LLVM18) | the `wasmer llvm` column |
| [`dtvm/`](dtvm/) | DTVM source fork @ `882c83155` | paper PolyBench / WAPM main column |

## Current Mainline (TTFI + overflow + fib)

| Directory | Version | Purpose |
|-----------|---------|---------|
| [`wasmtime-45.0.0/`](wasmtime-45.0.0/) | Wasmtime **45.0.0** (with TTFI instrumentation) | PolyBench TTFI / WAPM TTFI / overflow / fib |
| [`wasmer-7.1.0/`](wasmer-7.1.0/) | Wasmer **7.1.0** (cr + sp + **llvm**/LLVM21) | same |
| [`dtvm_main/`](dtvm_main/) | DTVM main HEAD (with `Total compilation time`) | TTFI mainline (commit recorded in `version.txt`) |

## Build-output Paths

`build.sh` installs into the corresponding subdirectory's `out/`:

| Runtime | Binary path |
|---------|-------------|
| WAMR 1.2.3 | `wamr-1.2.3/out/iwasm` |
| Wasmtime 31 | `wasmtime-31.0.0/out/wasmtime` |
| Wasmtime 45 | `wasmtime-45.0.0/out/wasmtime` |
| Wasmer 5.0.4 | `wasmer-5.0.4/out/bin/wasmer` |
| Wasmer 7.1.0 | `wasmer-7.1.0/out/bin/wasmer` |
| DTVM paper | `dtvm/dtvm` (manually copied from `build_paper/dtvm`) |
| DTVM mainline | `dtvm_main/dtvm` (manually copied from a main build) |

See each subdirectory's `BUILD.md` and [`../VERSIONS.md`](../VERSIONS.md).
