# Runtime Version Pins

This package covers two sets of version pins:

- **Paper baseline**: the PolyBench wall-clock main table and the early WAPM table (`dtvm_polybench.xlsx` / `latencytofirstinvocation.md`)
- **Current mainline** (PolyBench TTFI / WAPM TTFI / overflow / fib(30)): DTVM main with `Total compilation time` instrumentation + Wasmtime 45.0.0 + the three Wasmer 7.1.0 backends

No binaries are committed; each `runtimes/<rt>/` directory keeps only `BUILD.md` + `build.sh` + `version.txt`. Build artifacts (`out/`, `build/`, `dtvm`, `CMakeCache.txt`) are gitignored.

## Paper Baseline (PolyBench wall-clock)

| Runtime | Version | Role | Build doc |
|---------|---------|------|-----------|
| WAMR (`iwasm`) | **1.2.3** | interpreter baseline | `runtimes/wamr-1.2.3/BUILD.md` |
| Wasmtime | **31.0.0** | wall-clock baseline (Cranelift) | `runtimes/wasmtime-31.0.0/BUILD.md` |
| Wasmer | **5.0.4** | `wasmer llvm` column | `runtimes/wasmer-5.0.4/BUILD.md` |
| DTVM (`dtvm`) | DTVM source fork @ **`882c83155`** | paper PolyBench / WAPM body | `runtimes/dtvm/BUILD.md` |

## Current Mainline (TTFI + overflow + fib)

| Runtime | Version | Role | Build script |
|---------|---------|------|--------------|
| Wasmtime | **45.0.0** (with `ttfi-report` instrumentation) | PolyBench TTFI / WAPM TTFI / overflow / fib | `runtimes/wasmtime-45.0.0/build.sh` |
| Wasmer | **7.1.0** (cranelift + singlepass + **llvm**) | same | `runtimes/wasmer-7.1.0/build.sh` |
| DTVM (`dtvm`) main | TTFI mainline e.g. **`c3c3fd856`**; overflow / fib use the newest fastest commit e.g. **`e532db3e2`** | TTFI + overflow + fib | `runtimes/dtvm_main/version.txt` |

> The overflow / fib(30) experiments run only the newest fastest DTVM build (not required to share the TTFI commit); the other four columns are fixed at Wasmtime 45 + the three Wasmer 7.1 backends.

## Known DTVM Commits

| Label | Commit | Date | Notes |
|-------|--------|------|-------|
| **Paper baseline** | **`882c83155`** | 2024 | PolyBench / WAPM body; branch `dev/init_code` |
| **TTFI mainline** | **`c3c3fd856`** | 2026-05-29 | includes `Total compilation time` instrumentation; `perf: commute two-address operands and fix branch peephole for 30% fib speedup` |
| **overflow / fib latest** | **`e532db3e2`** | 2026-05-30 | `perf: add post-RA peephole optimizations for x86 code generation` |
| singlepass-dev HEAD | `bc137635` | 2023-10-26 | old HEAD of the fork |
| wtf pin | `396d1f61` | 2022-08-11 | `wtf/cmake/project_wamr.cmake` |

The commits above are from the DTVM source history; for local reproduction use this repository.

**Note**: the fork is based on 2021–2022 upstream WAMR plus in-house patches (singlepass / multipass JIT etc.) and is **not** a substitute for WAMR 1.2.3.

## Wasmtime 31.0.0 (paper baseline)

Doc: `runtimes/wasmtime-31.0.0/BUILD.md`
Build script: `runtimes/wasmtime-31.0.0/build.sh` (includes `patches/ttfi-report.patch`, optional `Total compilation time` instrumentation)

| Item | Value |
|------|-------|
| Version | **31.0.0** |
| Git tag | `release-31.0.0` |
| Rust (source build) | ≥ **1.85.0** |
| Prebuilt tarball (x86_64 Linux) | [wasmtime-v31.0.0-x86_64-linux.tar.xz](https://github.com/bytecodealliance/wasmtime/releases/download/v31.0.0/wasmtime-v31.0.0-x86_64-linux.tar.xz) |
| Release page | https://github.com/bytecodealliance/wasmtime/releases/tag/v31.0.0 |

```bash
# A. Official prebuilt tarball
curl -LO https://github.com/bytecodealliance/wasmtime/releases/download/v31.0.0/wasmtime-v31.0.0-x86_64-linux.tar.xz
tar xf wasmtime-v31.0.0-x86_64-linux.tar.xz

# B. Source build (applies the TTFI patch automatically)
cd runtimes/wasmtime-31.0.0 && ./build.sh all
# Output: runtimes/wasmtime-31.0.0/out/wasmtime
```

## Wasmtime 45.0.0 (TTFI / overflow / fib mainline)

Doc: `runtimes/wasmtime-45.0.0/build.sh` (requires a v45.0.0 source tree that already contains the `ttfi-report` instrumentation)

| Item | Value |
|------|-------|
| Version | **45.0.0** |
| Git tag | `v45.0.0` |
| Instrumentation | `src/ttfi_report.rs` + `Cargo.toml` `ttfi-report` feature + `commands/run.rs` |
| Instrumented source example | `/path/to/wasmtime-45.0.0` |

```bash
WASMER_SRC=/path/to/wasmtime-45.0.0 runtimes/wasmtime-45.0.0/build.sh
# Output: runtimes/wasmtime-45.0.0/out/wasmtime
export WASMTIME_CACHE=0     # required for TTFI
```

## Wasmer 5.0.4 (paper baseline)

Doc: `runtimes/wasmer-5.0.4/BUILD.md`
Build script: `runtimes/wasmer-5.0.4/build.sh` (cranelift + singlepass; llvm needs LLVM 18, optional)

| Item | Value |
|------|-------|
| Version | **5.0.4** |
| LLVM backend | **LLVM 18** (`LLVM_SYS_180_PREFIX`) |
| Singlepass used in the paper | `v5.0.5-rc1` |

## Wasmer 7.1.0 (TTFI / overflow / fib mainline)

Build script: `runtimes/wasmer-7.1.0/build.sh`

| Item | Value |
|------|-------|
| Version | **7.1.0** |
| Git tag | `v7.1.0` |
| Instrumentation | `lib/wasix/src/ttfi_report.rs` etc. |
| LLVM backend | **LLVM 21** (not 18; needs `LLVM_SYS_211_PREFIX`) |
| LLVM 21 example | `/opt/LLVM-21.1.8-Linux-X64` |

```bash
LLVM_SYS_211_PREFIX=/opt/LLVM-21.1.8-Linux-X64 \
  WASMER_SRC=/path/to/wasmer-7.1.0 \
  runtimes/wasmer-7.1.0/build.sh
# Output: runtimes/wasmer-7.1.0/out/bin/wasmer
```

## WAMR 1.2.3

Upstream tag: `WAMR-1.2.3` (`bytecodealliance/wasm-micro-runtime`)

Docs: `runtimes/wamr-1.2.3/BUILD.md` / `runtimes/wamr-1.2.3/build.sh`

| Item | Version |
|------|---------|
| WAMR | **1.2.3** |
| LLVM (AOT) | **11.1.0** |

Default CMake options:

```
-DWAMR_BUILD_INTERP=1
-DWAMR_BUILD_FAST_JIT=1
-DWAMR_BUILD_AOT=1
-DWAMR_BUILD_LIBC_WASI=1
-DLLVM_DIR=/usr/lib/llvm-11/lib/cmake/llvm   # for AOT
```

## Toolchain

See [`ENVIRONMENT.md`](ENVIRONMENT.md). Summary:

| Tool | Version / note | Basis |
|------|----------------|-------|
| **rustc** | ≥ **1.85.0** stable | Wasmtime 31 / 45, Wasmer 5 / 7.1 |
| **Wasmtime (paper)** | **31.0.0** | `runtimes/wasmtime-31.0.0/` |
| **Wasmtime (mainline)** | **45.0.0** (TTFI-instrumented) | `runtimes/wasmtime-45.0.0/` |
| **Wasmer (paper)** | **5.0.4** | `runtimes/wasmer-5.0.4/` |
| **Wasmer (mainline)** | **7.1.0** | `runtimes/wasmer-7.1.0/` |
| **Wasmer 5 LLVM backend** | **LLVM 18.1.7** | `runtimes/wasmer-5.0.4/BUILD.md` |
| **Wasmer 7.1 LLVM backend** | **LLVM 21.1.8** | `runtimes/wasmer-7.1.0/build.sh` |
| **WAMR AOT LLVM** | **11.1.0** | `runtimes/wamr-1.2.3/BUILD.md` |
| **DTVM build LLVM** | **15.0.0** (`clang+llvm-15.0.0-...-rhel-8.4`) | experiment notes, Coremark build steps |
| **WASI-SDK / clang** | **11.0.0** (27 cases), **14.0.3** (3 cases) | archived PolyBench wasm metadata |
| **PolyBench/C** | **4.2.1** | standard 30-case suite |
| **Emscripten (`em++`)** | not pinned, `-O2` | `benchmarks/overflow/build.sh` |
| **evmone / solc / wabt** (contract bench) | not pinned in the archive | contract hex are prebuilt artifacts |

### Not Recorded in the Archive

- Contract vm_benchmark host: **OS distribution, kernel, Docker, CPU governor, core pinning, drop_caches**
- **`solc`** / **`wat2wasm`** versions and commands used to produce `bench_bytecode/*.hex`
