# Runtimes

Build scripts and version proofs for each runtime. **Binaries are not committed** (covered by `.gitignore`); each subdirectory keeps only `BUILD.md` / `build.sh` / `version.txt`.

## Current Paper Experiments (PolyBench + TTFI + overflow + fib)

| Directory | Version | Purpose |
|-----------|---------|---------|
| [`wasmtime-45.0.0/`](wasmtime-45.0.0/) | Wasmtime **45.0.0** (with TTFI instrumentation) | current PolyBench wall-clock / PolyBench TTFI / WAPM TTFI / overflow / fib |
| [`wasmer-7.1.0/`](wasmer-7.1.0/) | Wasmer **7.1.0** (cr + sp + **llvm**/LLVM21) | same |
| [`dtvm_main/`](dtvm_main/) | DTVM **`c3c3fd856`** (with `Total compilation time`) | current PolyBench / TTFI (commit recorded in `version.txt`) |
| [`wamr-1.2.3/`](wamr-1.2.3/) | WAMR 1.2.3 (`iwasm`) | interpreter baseline |

## Historical Captures (earlier PolyBench wall-clock)

These are **not** the current paper experimental versions.

| Directory | Version | Purpose |
|-----------|---------|---------|
| [`wasmtime-31.0.0/`](wasmtime-31.0.0/) | Wasmtime 31.0.0 (optional TTFI instrumentation) | historical wall-clock |
| [`wasmer-5.0.4/`](wasmer-5.0.4/) | Wasmer 5.0.4 (cr + sp + optional llvm/LLVM18) | historical `wasmer llvm` column |
| [`dtvm/`](dtvm/) | DTVM source fork @ `882c83155` | historical PolyBench / WAPM main column |

## Build-output Paths

`build.sh` installs into the corresponding subdirectory's `out/`:

| Runtime | Binary path |
|---------|-------------|
| WAMR 1.2.3 | `wamr-1.2.3/out/iwasm` |
| Wasmtime 31 | `wasmtime-31.0.0/out/wasmtime` |
| Wasmtime 45 | `wasmtime-45.0.0/out/wasmtime` |
| Wasmer 5.0.4 | `wasmer-5.0.4/out/bin/wasmer` |
| Wasmer 7.1.0 | `wasmer-7.1.0/out/bin/wasmer` |
| DTVM current paper | `dtvm_main/dtvm` (manually copied from a `c3c3fd856` build) |
| DTVM historical | `dtvm/dtvm` (manually copied from `build_paper/dtvm`) |

See each subdirectory's `BUILD.md` and [`../VERSIONS.md`](../VERSIONS.md).
