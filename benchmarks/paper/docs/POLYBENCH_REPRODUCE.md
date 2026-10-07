# PolyBench Reproduction Guide (DTVM / Wasmtime / Wasmer)

This document explains how to reproduce the **correctness** and **performance** tests for **PolyBench/C (30 cases)** on **Linux x86_64**, using the three **current paper** runtime versions.

| Runtime | Version | Common paper xlsx columns |
|---------|---------|---------------------------|
| **DTVM (`dtvm`)** | git **`c3c3fd856`** | `dtvm multipass`, `dtvm multipass + lazy` |
| **Wasmtime** | **45.0.0** (Cranelift) | `wasmtime` |
| **Wasmer** | **7.1.0** (LLVM backend) | `wasmer llvm` |

Earlier wall-clock captures used Wasmtime **31.0.0**, Wasmer **5.0.4**, and DTVM **`882c83155`**. Those trees remain under `runtimes/wasmtime-31.0.0/`, `runtimes/wasmer-5.0.4/`, and `runtimes/dtvm/`; they are **historical**, not the current paper experiments. See [§10](#10-historical-runtimes-optional).

The benchmark artifacts are already archived: `benchmarks/polybenchc/*.wasm` (benchmarks can run without recompiling wasm locally). This guide does **not** regenerate or replace archived timing tables.

Related documents:

- **TTFI** (`Total compilation time`, DTVM lazy vs wasmtime 45 / wasmer 7.1): [`POLYBENCH_TTFI_REPRODUCE.md`](POLYBENCH_TTFI_REPRODUCE.md)
- Version-pin master table: [`VERSIONS.md`](../VERSIONS.md)
- paper-table column meanings and pitfalls: [`XLSX_FORMAT.md`](XLSX_FORMAT.md)
- DTVM current-paper build: [`runtimes/dtvm_main/README.md`](../runtimes/dtvm_main/README.md)
- Wasmtime current-paper build: [`runtimes/wasmtime-45.0.0/README.md`](../runtimes/wasmtime-45.0.0/README.md)

---

## 1. Requirements

| Item | Requirement |
|------|-------------|
| OS | Linux **x86_64** |
| Shell | bash |
| Common tools | `cmake`, `ninja`, `curl`, `python3` |
| DTVM build | GCC C++17, **LLVM 15** (e.g. `/opt/llvm15/lib/cmake/llvm`) |
| Wasmtime source build (optional) | **Rust ≥ 1.85.0** |
| Wasmer LLVM backend | **LLVM 21** (`LLVM_SYS_211_PREFIX`) |
| Disk | cloning the DTVM source + build takes a few GB |

Paper experiment machine (from experiment notes, for reference only): c7 8C16G, Xeon 8369B, **Turbo off**, fixed ~2.7 GHz. Identical hardware is not required for local reproduction, but CPU frequency scaling / pinning affects absolute ms.

---

## 2. Getting the Data Repo

This directory is `benchmarks/paper/` (inside the DTVM repository).

```bash
cd <DTVM repo>/benchmarks/paper
```

Below, this directory is `$ROOT`:

```bash
export ROOT="$(pwd)"
```

---

## 3. Installing the Three Runtimes

After installation, place the binaries at the conventional repo paths and **export** `DTVM` / `WASMTIME` / `WASMER`. Several helper scripts still default to the historical trees (`runtimes/dtvm/`, `wasmtime-31.0.0/`, `wasmer-5.0.4/`) when those variables are unset.

### 3.1 DTVM (`dtvm`) @ `c3c3fd856`

**Repository**: this DTVM repository. The current paper pin is recorded in [`runtimes/dtvm_main/version.txt`](../runtimes/dtvm_main/version.txt).

**Recommended**: check out **`c3c3fd856`** (or a worktree) so the recorded paper commit is the one you build:

```bash
cd /path/to/DTVM
git fetch origin
git worktree add ../DTVM_paper_c3c3fd856 c3c3fd856
cd ../DTVM_paper_c3c3fd856
```

**Build** (Release, matching `runtimes/dtvm_main/README.md`):

```bash
cmake -B build_main -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_DIR=/opt/llvm15/lib/cmake/llvm \
  -DZEN_ENABLE_SINGLEPASS_JIT=ON \
  -DZEN_ENABLE_MULTIPASS_JIT=ON

cmake --build build_main -j"$(nproc)"
```

Every script that launches dtvm warns on stderr if the resolved binary looks like a non-Release build — a Debug dtvm is far slower than the paper's Release configuration.

**Install into the data repo**:

```bash
DATA="$ROOT/runtimes/dtvm_main"
mkdir -p "$DATA"
cp build_main/dtvm "$DATA/dtvm"
chmod +x "$DATA/dtvm"
git log -1 --format='%H %ci %s' > "$DATA/version.txt"
```

**Verify**:

```bash
"$DATA/dtvm" -m multipass --disable-multipass-greedyra --disable-multipass-multithread \
  "$ROOT/benchmarks/polybenchc/atax.wasm"
# should exit 0 and print ==BEGIN DUMP_ARRAYS== etc.
```

`dtvm` has **no** `--version`; rely on `version.txt` (`c3c3fd856…`) and `CMakeCache.txt`.

---

### 3.2 Wasmtime **45.0.0**

**Option A — official prebuilt package (wall-clock)**

```bash
cd "$ROOT/runtimes/wasmtime-45.0.0"
mkdir -p out
curl -LO https://github.com/bytecodealliance/wasmtime/releases/download/v45.0.0/wasmtime-v45.0.0-x86_64-linux.tar.xz
tar xf wasmtime-v45.0.0-x86_64-linux.tar.xz
cp wasmtime-v45.0.0-x86_64-linux/wasmtime out/wasmtime
chmod +x out/wasmtime
out/wasmtime --version | tee version.txt
```

Expected: the version string contains **`45.0.0`**.

**Option B — build from source** (required for TTFI instrumentation; see [`../runtimes/wasmtime-45.0.0/README.md`](../runtimes/wasmtime-45.0.0/README.md))

```bash
cd "$ROOT/runtimes/wasmtime-45.0.0"
WASMER_SRC=/path/to/wasmtime-45.0.0 ./build.sh
```

**Verify** (any wasm in this repo):

```bash
"$ROOT/runtimes/wasmtime-45.0.0/out/wasmtime" run \
  "$ROOT/benchmarks/polybenchc/atax.wasm" --invoke main
```

---

### 3.3 Wasmer **7.1.0**

**Option A — official release tarball (wall-clock)**

```bash
cd "$ROOT/runtimes/wasmer-7.1.0"
mkdir -p out/bin
curl -LO https://github.com/wasmerio/wasmer/releases/download/v7.1.0/wasmer-linux-amd64.tar.gz
tar xf wasmer-linux-amd64.tar.gz -C out
ln -sf bin/wasmer out/wasmer
out/wasmer --version | tee version.txt
```

**Option B — source build** (cranelift + singlepass + llvm; llvm needs **LLVM 21**)

```bash
LLVM_SYS_211_PREFIX=/path/to/LLVM-21.1.8-Linux-X64 \
  WASMER_SRC=/path/to/wasmer-7.1.0 \
  "$ROOT/runtimes/wasmer-7.1.0/build.sh"
```

Expected: the version string contains **`7.1.0`**.

**Verify** (the paper's PolyBench column uses the LLVM backend):

```bash
"$ROOT/runtimes/wasmer-7.1.0/out/wasmer" run \
  --llvm -q "$ROOT/benchmarks/polybenchc/atax.wasm"
```

---

## 4. One-shot Check of the Three Versions

```bash
export ROOT=<repo>/benchmarks/paper

test -x "$ROOT/runtimes/dtvm_main/dtvm" && echo "dtvm: OK ($(head -n1 "$ROOT/runtimes/dtvm_main/version.txt"))"
"$ROOT/runtimes/wasmtime-45.0.0/out/wasmtime" --version
"$ROOT/runtimes/wasmer-7.1.0/out/wasmer" --version
ls "$ROOT/benchmarks/polybenchc"/*.wasm | wc -l   # should be 30
```

---

## 5. Correctness Testing (runtest)

Use the archived `scripts/webassembly-testsuites` (which contains `runtest_webassembly.py`). **11 cases** have `.expected` output comparisons; the rest only need to exit cleanly.

**First time**, set up the case-directory links:

```bash
cd "$ROOT"
./scripts/setup_polybench_case.sh
```

**Run the three runtimes**:

```bash
# DTVM @ c3c3fd856 (paper multipass: greedy RA off + multipass multithread off)
export DTVM="$ROOT/runtimes/dtvm_main/dtvm"
export DTVM_OPTIONS="-m multipass --disable-multipass-greedyra --disable-multipass-multithread"
./scripts/run_polybench.sh dtvm

export WASMTIME="$ROOT/runtimes/wasmtime-45.0.0/out/wasmtime"
./scripts/run_polybench.sh wasmtime

export WASMER="$ROOT/runtimes/wasmer-7.1.0/out/wasmer"
# run_polybench.sh expects a path for wasmer; or run manually:
cd "$ROOT/scripts/webassembly-testsuites"
./runtest_webassembly.py -r "$ROOT/runtimes/wasmer-7.1.0/out/wasmer run --llvm" -s polybenchc
```

Expected: cases with expected files show **PASS**; cases without expected files just must not crash.

---

## 6. Performance Testing (local timing CSV)

Script: [`scripts/bench_polybench_timing.sh`](../scripts/bench_polybench_timing.sh)

### 6.1 Timing Semantics (read first)

| Item | This script's behavior |
|------|------------------------|
| Measure | **wall time (ms)** of each **separately launched process** |
| Contents | typically = process startup + **JIT compile** + execution |
| Default | **1× warmup** + **3×** timed → CSV includes `repeat_median_ms` |
| vs paper table | **not equal to** the paper table's separate Compile / Total subcolumns; see [`XLSX_FORMAT.md`](XLSX_FORMAT.md) |
| Cache asymmetry | wasmtime/wasmer keep their on-disk module cache by default (warmup fills it, so timed repeats skip compilation), while DTVM recompiles on every launch; use the `wasmtime nocache` profile or wasmer `--cache-dir=/dev/null` for cold-cache runs |

Adjust via environment variables:

```bash
export WARMUP=1 REPEATS=3
```

### 6.2 Recommended Benchmark Commands (aligned with the paper's three columns)

Run under `$ROOT`. **Do not** run multiple dtvm configs in parallel (avoid CPU contention).

```bash
cd "$ROOT"
chmod +x scripts/bench_polybench_timing.sh

export DTVM="$ROOT/runtimes/dtvm_main/dtvm"
export WASMTIME="$ROOT/runtimes/wasmtime-45.0.0/out/wasmtime"
export WASMER="$ROOT/runtimes/wasmer-7.1.0/out/wasmer"

# 1) DTVM multipass (xlsx "dtvm multipass" — inferred CLI: greedy off + MT off)
./scripts/bench_polybench_timing.sh dtvm multipass

# 2) DTVM lazy (xlsx "dtvm multipass + lazy" — inferred CLI)
./scripts/bench_polybench_timing.sh dtvm lazy

# 3) Wasmtime 45.0.0
./scripts/bench_polybench_timing.sh wasmtime default

# 4) Wasmer 7.1.0 LLVM (xlsx "wasmer llvm" Total column)
./scripts/bench_polybench_timing.sh wasmer llvm
```

**Optional** (local comparison only; not separate columns in the paper xlsx):

```bash
# greedy RA + multipass multithread fully on
./scripts/bench_polybench_timing.sh dtvm multipass_greedy_mt
./scripts/bench_polybench_timing.sh dtvm lazy_greedy_mt

# Wasmtime with module cache disabled
./scripts/bench_polybench_timing.sh wasmtime nocache
```

### 6.3 Actual Command Lines per Runtime

Inside the script, the invocations are equivalent to:

| Invocation | Command |
|------------|---------|
| `dtvm multipass` | `dtvm -m multipass --disable-multipass-greedyra --disable-multipass-multithread case.wasm` |
| `dtvm lazy` | `dtvm -m multipass --enable-multipass-lazy --disable-multipass-greedyra --disable-multipass-multithread case.wasm` |
| `dtvm multipass_greedy_mt` | `dtvm -m multipass case.wasm` |
| `dtvm lazy_greedy_mt` | `dtvm -m multipass --enable-multipass-lazy case.wasm` |
| `wasmtime default` | `wasmtime run case.wasm --invoke main` |
| `wasmer llvm` | `wasmer run case.wasm --llvm -q` |

### 6.4 Output Location

CSVs are written to:

```text
raw_data/benchs/polybench_timing_<runtime>_<profile>_<timestamp>.csv
```

Columns: `case,runtime,profile,repeat_min_ms,repeat_mean_ms,repeat_median_ms,exit`

After a run, the script attempts a **rough comparison** against the paper table if `raw_data/benchs/dtvm_polybench.xlsx` is present (not shipped). **Read** [`XLSX_FORMAT.md`](XLSX_FORMAT.md) **before comparing**: do not mistake a compile column (e.g. `0.935` seconds) for total. That archived xlsx is a historical table; this guide does not invent replacement numbers.

### 6.5 Recommended Way to Compare Against the Paper Table

1. Compare only **Total-time** semantic columns (see the wasmer llvm, lazy total, etc. row-group notes in [`XLSX_FORMAT.md`](XLSX_FORMAT.md)).
2. Prefer the **`DTVM/Wasm/Wasmer`** ratio format (e.g. `1/1.02/7.0`), not `1:x:y` with colons.

---

## 7. Full Reproduction Checklist

```bash
# A. Environment and repo
export ROOT=<repo>/benchmarks/paper
cd "$ROOT"

# B. Install runtimes (§3)
#    - dtvm_main/dtvm @ c3c3fd856
#    - wasmtime-45.0.0/out/wasmtime
#    - wasmer-7.1.0/out/wasmer

# C. Version check (§4)

# D. Correctness (§5)
./scripts/setup_polybench_case.sh
export DTVM="$ROOT/runtimes/dtvm_main/dtvm"
export WASMTIME="$ROOT/runtimes/wasmtime-45.0.0/out/wasmtime"
./scripts/run_polybench.sh dtvm
./scripts/run_polybench.sh wasmtime

# E. Performance (§6, sequential; ~30 cases × 4 reps × 4 configs, hours)
export WASMER="$ROOT/runtimes/wasmer-7.1.0/out/wasmer"
./scripts/bench_polybench_timing.sh dtvm multipass
./scripts/bench_polybench_timing.sh dtvm lazy
./scripts/bench_polybench_timing.sh wasmtime default
./scripts/bench_polybench_timing.sh wasmer llvm
```

---

## 8. FAQ

### `dtvm: not found` / cannot execute

- Confirm `runtimes/dtvm_main/dtvm` exists and is `chmod +x`.
- Check whether the `DTVM` environment variable points at the right path.

### Wasmtime / Wasmer version mismatch

```bash
$ROOT/runtimes/wasmtime-45.0.0/out/wasmtime --version   # must contain 45.0.0
$ROOT/runtimes/wasmer-7.1.0/out/wasmer --version         # must be 7.1.0
```

### DTVM build cannot find LLVM

```bash
cmake -DLLVM_DIR=/opt/llvm15/lib/cmake/llvm ...
```

The path varies by machine; locate it with `find /opt -name LLVMConfig.cmake 2>/dev/null`.

### Numbers differ a lot from the xlsx

- First confirm you are comparing the **same column, same row group** (compile vs total).
- This script measures **whole-process wall time**, not the possibly compile-only split used in the paper.
- The archived xlsx may reflect the **historical** pins (Wasmtime 31.0.0 / Wasmer 5.0.4 / DTVM `882c83155`); current paper experiments use 45.0.0 / 7.1.0 / `c3c3fd856`.
- Historical `882c83155` has **no** public CLI matching the xlsx column `dtvm multipass + exit optimization`.

### Disabling caches (optional, matching experiment notes)

```bash
export WASMTIME_CACHE=0
# Wasmer: wasmer run --cache-dir=/dev/null ...
```

`bench_polybench_timing.sh` does **not** force cache disabling for wasmtime/wasmer by default; whether the paper's runs cleared caches is not recorded — rerun both variants if you need an exact match.

---

## 9. Reference: Version and Path Cheat Sheet

| Runtime | Version | Default binary path |
|---------|---------|---------------------|
| DTVM `dtvm` | **`c3c3fd856`** | `$ROOT/runtimes/dtvm_main/dtvm` |
| Wasmtime | **45.0.0** | `$ROOT/runtimes/wasmtime-45.0.0/out/wasmtime` |
| Wasmer | **7.1.0** | `$ROOT/runtimes/wasmer-7.1.0/out/wasmer` |

| Script | Purpose |
|--------|---------|
| `scripts/setup_polybench_case.sh` | link polybench cases |
| `scripts/run_polybench.sh` | correctness runtest |
| `scripts/bench_polybench_timing.sh` | performance CSV |

The paper's original ms table is in the paper (the xlsx is not shipped). This package does not add replacement timing numbers.

---

## 10. Historical Runtimes (optional)

Use these only to replay **earlier** wall-clock captures. They are **not** the current paper experimental versions.

| Runtime | Historical version | Path |
|---------|--------------------|------|
| DTVM `dtvm` | `882c83155` | `$ROOT/runtimes/dtvm/dtvm` — [`../runtimes/dtvm/BUILD.md`](../runtimes/dtvm/BUILD.md) |
| Wasmtime | **31.0.0** | `$ROOT/runtimes/wasmtime-31.0.0/out/wasmtime` — [`../runtimes/wasmtime-31.0.0/BUILD.md`](../runtimes/wasmtime-31.0.0/BUILD.md) |
| Wasmer | **5.0.4** | `$ROOT/runtimes/wasmer-5.0.4/out/wasmer` — [`../runtimes/wasmer-5.0.4/BUILD.md`](../runtimes/wasmer-5.0.4/BUILD.md) |

```bash
export DTVM="$ROOT/runtimes/dtvm/dtvm"
export WASMTIME="$ROOT/runtimes/wasmtime-31.0.0/out/wasmtime"
export WASMER="$ROOT/runtimes/wasmer-5.0.4/out/wasmer"
```
