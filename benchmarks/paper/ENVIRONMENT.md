# Experiment Environment and Toolchain

This file collects the environment and version information that can be **confirmed from the archive**. Anything not present in the reproduction notes, the contract-testbed repository, this repository's docs, or the original lab notes is marked **not recorded** rather than guessed.

Different benchmark suites may have used different machines or toolchains; the tables below separate the **contract microbenchmark (vm_benchmark)** from the **other paper baselines**.

---

## Checklist (contract vm_benchmark)

**Test machine (from experiment notes, confirmed):**

> **Compute-optimized c7, 8C16G, Intel(R) Xeon(R) Platinum 8369B CPU @ 2.70GHz**
> Runtime `/proc/cpuinfo`: **cpu MHz = 2699.998**; **Turbo Boost not enabled**

| # | Item | Status | Archived evidence |
|---|------|--------|-------------------|
| — | **Machine hardware** | **confirmed** | see above; source: reproduction notes |
| 1 | Original OS version | **not recorded** | the notes give the hardware spec but no Linux distribution or version |
| 2 | Kernel version | **not recorded** | — |
| 3 | Docker / container | **not recorded** | no container usage recorded |
| 4 | Dockerfile / image / env scripts | **partial** | no Dockerfile; the contract bench ran `sh build.sh release.vmbench 6 false 2` inside the contract-testbed repo (see `benchmarks/contracts/REPRODUCE.md`) |
| 5 | Dedicated machine | **not recorded** | — |
| 6 | CPU core pinning | **not recorded** | the notes say the microbenchmark is "serial, 1C is enough"; no `taskset`/pinning command was recorded |
| 7 | Fixed CPU frequency | **partial** | `/proc/cpuinfo` read **cpu MHz ≈ 2699.998** at runtime (archived runner source, not included); no manual `cpufreq` step was recorded |
| 8 | Turbo Boost disabled | **confirmed** | notes: "turbo boost not enabled"; the archived runner source comments also require disabling Turbo Boost on Intel CPUs |
| 9 | CPU governor | **not recorded** | — |
| 10 | OS / runtime cache clearing | **not recorded** | no `drop_caches` step recorded for the contract bench; **State and Module LRU caches are reused** across measurements (see `benchmarks/contracts/REPRODUCE.md` §5) |
| 11 | Background load | **not recorded** | — |
| 12 | Toolchain versions | **partial** | see "contract toolchain" below; **no** solc / hex-compile command versions |

---

## Contract Microbenchmark (vm_benchmark)

Sources: reproduction notes (2025-04-22 archive) + `benchmarks/contracts/`.

### Hardware and CPU

| Item | Value | Source |
|------|-------|--------|
| Cloud instance | compute-optimized **c7, 8C16G** | experiment notes |
| CPU model | Intel Xeon Platinum **8369B** @ **2.70GHz** (nominal) | experiment notes |
| Observed frequency | **2699.998 MHz** (`cpu MHz` in `/proc/cpuinfo`) | experiment notes + archived runner source |
| Turbo Boost | **off** | experiment notes |
| Workload shape | **serial** microbenchmark; the notes state "**1C is enough**", test environment was **8C16G** | experiment notes |
| OS | **Linux** (reads `/proc/cpuinfo`); distribution **not recorded** | code + gap |

### Repository and DTVM Macros

| Item | Value |
|------|-------|
| Repository | contract-testbed repository |
| Branch | development branch |
| DTVM build macros | `ZEN_ENABLE_JIT`, `ZEN_ENABLE_SINGLEPASS_JIT`, `ZEN_ENABLE_DWASM`, `ZEN_ENABLE_CHECKED_ARITHMETIC` |

### Contract Toolchain

| Tool | Archive status |
|------|----------------|
| **evmone** | pulled in via the testbed's Bazel deps; **no** standalone version pin |
| **DTVM (`dtvm`)** | see the macros above; the `dtvm` binary is built from the DTVM source fork (`VERSIONS.md`) |
| **solc** (hex generation) | **not recorded** |
| **wabt / wat2wasm** | **not used** in the archived contract-bench flow |
| **clang / LLVM** (contract bench itself) | **not recorded** as a standalone version; hex are prebuilt artifacts |

---

## Other Paper Baselines (non-contract)

The following come from experiment notes / `VERSIONS.md` / the experiment notebook, and **may not** share the contract-bench machine.

### Comparison Runtimes

| Runtime | Notes / archived version | Notes |
|---------|--------------------------|-------|
| **Wasmtime** | **31.0.0** ([official x86_64-linux tar.xz](https://github.com/bytecodealliance/wasmtime/releases/download/v31.0.0/wasmtime-v31.0.0-x86_64-linux.tar.xz)) | `runtimes/wasmtime-31.0.0/BUILD.md` |
| **Wasmer** | **`v5.0.4`**; the Singlepass comparison also used **`v5.0.5-rc1`** (wasi limitation) | Wasmer is **not pinned** in this repo |
| **WAMR `iwasm`** | **1.2.3** | `runtimes/wamr-1.2.3/` |
| **DTVM `dtvm`** | DTVM source fork (commits in `VERSIONS.md`) | not vanilla WAMR |

### Build Toolchain (experiment notes / lab notebook)

| Tool | Version / path | Used for |
|------|----------------|----------|
| **rustc** | **≥ 1.85.0** (Wasmtime build) | Wasmtime baseline |
| **LLVM / clang (DTVM build)** | **15.0.0**, e.g. `/opt/clang+llvm-15.0.0-x86_64-linux-gnu-rhel-8.4/...` | Coremark / dtvm builds |
| **LLVM (Wasmer build)** | **18.1.7**, e.g. `...-ubuntu-18.04-...` | Wasmer build |
| **WASI SDK clang** | archived wasm metadata: **11.0.0** (27 cases), **14.0.3** (3 cases) | PolyBench (`benchmarks/polybenchc/BUILD.md`) |
| **WAMR AOT LLVM** | **11.1.0** | `runtimes/wamr-1.2.3/BUILD.md` |
| **Emscripten `em++`** | **not pinned** | `benchmarks/overflow/build.sh`, `-O2` |
| **clang (generic wasm example)** | `--target=wasm32` (no version pin) | md5 example in the experiment notebook |

Coremark self-reports **CLANG 14.0.6** (`-O2`) inside the wasm output — that is the **benchmark program's** compiler, not the host clang used to build DTVM.

### Cache Handling When Comparing Baselines (non-contract)

The archive notes that for Wasmtime / Wasmer comparisons one may `rm -rf ~/.cache/wasmtime`, set `WASMTIME_CACHE=0`, or use `wasmer run --cache-dir=/dev/null`. **No corresponding step was recorded for the contract vm_benchmark.**

---

## Related Documents

| Document | Contents |
|----------|----------|
| [`VERSIONS.md`](VERSIONS.md) | Runtime pins and toolchain summary |
| [`benchmarks/contracts/REPRODUCE.md`](benchmarks/contracts/REPRODUCE.md) | Contract build, run, and measurement methodology |
| [`REPRODUCE.md`](REPRODUCE.md) | Whole-package reproduction skeleton |
