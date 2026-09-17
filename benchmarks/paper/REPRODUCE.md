# Reproduction Guide

> This package lives at `benchmarks/paper/` in the DTVM repository. All relative paths below (`./scripts/...`, `benchmarks/...`) are rooted at this directory — `cd benchmarks/paper` first.

This document gives the install and run entry points for the three main experiment groups; details live in `docs/<TOPIC>_REPRODUCE.md` and `runtimes/<rt>/BUILD.md`.

## Requirements

- OS: **Linux x86_64**
- Common tools: `cmake` ≥ 3.20, `ninja`, `curl`, `python3`, `taskset`
- DTVM build: GCC C++17, **LLVM 15** (multipass JIT)
- Wasmtime 45 source build: **Rust ≥ stable** (via `rustup`, `source ~/.cargo/env`)
- Wasmer 7.1 LLVM backend: **LLVM 21** (`LLVM_SYS_211_PREFIX` → `LLVM-21.1.x-Linux-X64/`)
- overflow / fib: **Emscripten** (wasm compilation)

Contract-bench machine (from experiment notes): compute-optimized **c7 8C16G**, Xeon **8369B**, **Turbo Boost off**, observed **cpu MHz ≈ 2699.998**. The full 12-item environment/toolchain checklist is in [`ENVIRONMENT.md`](ENVIRONMENT.md).

## Step 1 — Install Runtimes

Each runtime directory keeps only `BUILD.md` + `build.sh` + `version.txt`; binaries are installed to `runtimes/<rt>/out/` (gitignored).

### DTVM (dtvm)

```bash
# Paper PolyBench / WAPM wall-clock: commit 882c83155
# TTFI mainline: main HEAD (includes "Total compilation time" instrumentation)
# overflow / fib: newest fastest commit (e.g. e532db3e2)
```

See [`runtimes/dtvm/BUILD.md`](runtimes/dtvm/BUILD.md).

### Wasmtime

| Purpose | Version | Path |
|---------|---------|------|
| Paper PolyBench wall-clock | **31.0.0** | `runtimes/wasmtime-31.0.0/` (includes `patches/ttfi-report.patch`) |
| TTFI / overflow / fib mainline | **45.0.0** | `runtimes/wasmtime-45.0.0/` (source tree must include the TTFI instrumentation) |

```bash
# 31.0.0: official prebuilt tarball, or build from source
cd runtimes/wasmtime-31.0.0 && ./build.sh all
# 45.0.0: build from an instrumented source tree
WASMER_SRC=/path/to/wasmtime-45.0.0 runtimes/wasmtime-45.0.0/build.sh
```

### Wasmer

| Purpose | Version | Path |
|---------|---------|------|
| Paper PolyBench `wasmer llvm` column | **5.0.4** | `runtimes/wasmer-5.0.4/` |
| TTFI / overflow / fib mainline | **7.1.0** | `runtimes/wasmer-7.1.0/` (cranelift + singlepass + llvm) |

```bash
# 5.0.4: cranelift + singlepass + llvm (llvm backend needs LLVM 18)
cd runtimes/wasmer-5.0.4 && ./build.sh
# 7.1.0: cranelift + singlepass (default); llvm needs LLVM 21
LLVM_SYS_211_PREFIX=/path/to/LLVM-21.1.8-Linux-X64 \
  WASMER_SRC=/path/to/wasmer-7.1.0 \
  runtimes/wasmer-7.1.0/build.sh
```

### WAMR 1.2.3 (optional, paper interpreter baseline)

```bash
cd runtimes/wamr-1.2.3 && ./build.sh all
```

## Step 2 — Main Experiment Groups

### 2.1 PolyBench wall-clock (30 cases)

```bash
./scripts/setup_polybench_case.sh

# Correctness (once per runtime)
./scripts/run_polybench.sh dtvm
./scripts/run_polybench.sh wasmtime

# Timing CSV (1 warmup + 3 timed runs)
./scripts/bench_polybench_timing.sh dtvm multipass        # mainline
./scripts/bench_polybench_timing.sh dtvm lazy
./scripts/bench_polybench_timing.sh wasmtime default
./scripts/bench_polybench_timing.sh wasmer llvm
```

Full procedure, command-line differences, and pitfalls when comparing against `dtvm_polybench.xlsx`: [`docs/POLYBENCH_REPRODUCE.md`](docs/POLYBENCH_REPRODUCE.md).

### 2.2 PolyBench TTFI (30 cases)

DTVM `multipass + lazy` vs **Wasmtime 45.0.0** vs **Wasmer 7.1.0 (cranelift / singlepass / llvm)**; the metric is the `Total compilation time` printed on stdout.

```bash
export DTVM=$PWD/runtimes/dtvm_main/dtvm
export WASMTIME=$PWD/runtimes/wasmtime-45.0.0/out/wasmtime
export WASMER=$PWD/runtimes/wasmer-7.1.0/out/bin/wasmer
export WASMTIME_CACHE=0
./scripts/run_polybench_ttfi_round.sh 1
# → raw_data/benchs/polybench_ttfi_<timestamp>/ + polybench_ttfi_compare_latest.{md,csv}
```

Details: [`docs/POLYBENCH_TTFI_REPRODUCE.md`](docs/POLYBENCH_TTFI_REPRODUCE.md).

### 2.3 WAPM TTFI + wall-clock (20 cases)

```bash
export DTVM=/path/to/DTVM/build/dtvm
export WASMTIME=$PWD/runtimes/wasmtime-45.0.0/out/wasmtime
export WASMER=$PWD/runtimes/wasmer-7.1.0/out/bin/wasmer
export WASMTIME_CACHE=0
./scripts/run_wapm_v45_v71_round.sh 3
# → raw_data/benchs/wapm_v45_v71_<timestamp>/ + wapm_v45_v71_latency_table.{md,csv}
```

Details: [`docs/WAPM_TTFI_REPRODUCTION.md`](docs/WAPM_TTFI_REPRODUCTION.md) and [`benchmarks/wapm/WAPM_REPRODUCE.md`](benchmarks/wapm/WAPM_REPRODUCE.md).

### 2.4 Integer overflow + fib(30) (5-way)

Only the **newest fastest** DTVM commit is used; the other four columns are Wasmtime 45 / Wasmer cranelift / singlepass / llvm.

```bash
cd benchmarks/overflow
# Compile the wasm (emscripten) — archived artifacts already exist, so this is skippable
bash build.sh
# 5-way benchmark
bash run_dtvm.sh           # DTVM
bash run_wasmtime45.sh     # Wasmtime 45 + all three Wasmer backends
```

Full command lines, the 5-rep median methodology, and per-runtime wasm variants: [`benchmarks/overflow/REPRODUCE_fib_overflow_5way.md`](benchmarks/overflow/REPRODUCE_fib_overflow_5way.md).

## Step 3 — Collect Raw Data

Benchmark output is written under `raw_data/benchs/` (generated at run time; gitignored — no result data is shipped).

## Contract Microbenchmark (ERC20 / Uniswap / Merkle Proof / Generative NFT / …)

Sources and hex artifacts are archived under `benchmarks/contracts/`. The runner builds only inside the contract-testbed repository:

```bash
sh build.sh release.vmbench 4
cd test_run
LD_LIBRARY_PATH=. ./test_vmbench --gtest_filter=VMBenchTest.Erc20Evm
```

Newer cases:

```bash
LD_LIBRARY_PATH=. ./test_vmbench --gtest_filter=VMBenchTest.MerkleProofEvm:VMBenchTest.SolMerkleProofWasm
LD_LIBRARY_PATH=. ./test_vmbench --gtest_filter=VMBenchTest.GenerativeNFTEvm:VMBenchTest.SolGenerativeNFTWasm
```

See `benchmarks/contracts/REPRODUCE.md`.
