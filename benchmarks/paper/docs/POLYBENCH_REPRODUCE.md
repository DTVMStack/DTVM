# PolyBench Reproduction Guide (DTVM / Wasmtime / Wasmer)

This document explains how to reproduce the **correctness** and **performance** tests for **PolyBench/C (30 cases)** on **Linux x86_64**, using the three paper-aligned runtime versions.

| Runtime | Version | Common paper xlsx columns |
|---------|---------|---------------------------|
| **DTVM (`dtvm`)** | git **`882c83155`** | `dtvm multipass`, `dtvm multipass + lazy` |
| **Wasmtime** | **31.0.0** (Cranelift) | `wasmtime` |
| **Wasmer** | **5.0.4** (LLVM backend) | `wasmer llvm` |

The benchmark artifacts are already archived: `benchmarks/polybenchc/*.wasm` (benchmarks can run without recompiling wasm locally).

Related documents:

- **TTFI** (`Total compilation time`, DTVM lazy vs wasmtime 45 / wasmer 7.1): [`POLYBENCH_TTFI_REPRODUCE.md`](POLYBENCH_TTFI_REPRODUCE.md)
- Version-pin master table: [`VERSIONS.md`](../VERSIONS.md)
- paper-table column meanings and pitfalls: [`XLSX_FORMAT.md`](XLSX_FORMAT.md)
- DTVM build details: [`runtimes/dtvm/BUILD.md`](../runtimes/dtvm/BUILD.md)
- Wasmtime build details: [`runtimes/wasmtime-31.0.0/BUILD.md`](../runtimes/wasmtime-31.0.0/BUILD.md)

---

## 1. Requirements

| Item | Requirement |
|------|-------------|
| OS | Linux **x86_64** |
| Shell | bash |
| Common tools | `cmake`, `ninja`, `curl`, `python3` |
| DTVM build | GCC C++17, **LLVM 15** (e.g. `/opt/llvm15/lib/cmake/llvm`) |
| Wasmtime source build (optional) | **Rust ≥ 1.85.0** |
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

After installation, place the binaries at the conventional repo paths (`bench_polybench_timing.sh`'s default `DTVM` / `WASMTIME` / `WASMER` read these paths).

### 3.1 DTVM (`dtvm`) @ `882c83155`

**Repository**: the DTVM source repository (the paper-era commit also lives in this repo's history).

**Recommended**: use a git worktree so the main branch is untouched:

```bash
cd /path/to/DTVM
git fetch origin
git worktree add ../DTVM_paper_882c83155 882c83155
cd ../DTVM_paper_882c83155
```

**Build** (Release, matching the paper archive):

```bash
cmake -S . -B build_paper -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_DIR=/opt/llvm15/lib/cmake/llvm \
  -DZEN_ENABLE_SINGLEPASS_JIT=ON \
  -DZEN_ENABLE_MULTIPASS_JIT=ON \
  -DZEN_ENABLE_CHECKED_ARITHMETIC=ON

cmake --build build_paper -j"$(nproc)"
```

If `FetchContent` fails to fetch dependencies, reuse `_deps` from another DTVM build on the same machine, or see [`runtimes/dtvm/BUILD.md`](../runtimes/dtvm/BUILD.md).

Every script that launches dtvm warns on stderr if the resolved binary looks like a non-Release build — a Debug dtvm is far slower than the paper's Release configuration.

**Install into the data repo**:

```bash
DATA="$ROOT/runtimes/dtvm"
cp build_paper/dtvm "$DATA/dtvm"
chmod +x "$DATA/dtvm"
cp build_paper/CMakeCache.txt "$DATA/CMakeCache.txt"
"$DATA/dtvm" --help > "$DATA/version.txt" 2>&1 || true
echo "commit=882c83155" >> "$DATA/version.txt"
```

**Verify**:

```bash
"$DATA/dtvm" -m multipass --disable-multipass-greedyra --disable-multipass-multithread \
  "$ROOT/benchmarks/polybenchc/atax.wasm"
# should exit 0 and print ==BEGIN DUMP_ARRAYS== etc.
```

`dtvm` has **no** `--version`; rely on `commit=882c83155` and `CMakeCache.txt`.

---

### 3.2 Wasmtime **31.0.0**

**Option A — official prebuilt package (recommended)**

```bash
cd "$ROOT/runtimes/wasmtime-31.0.0"
mkdir -p out
curl -LO https://github.com/bytecodealliance/wasmtime/releases/download/v31.0.0/wasmtime-v31.0.0-x86_64-linux.tar.xz
tar xf wasmtime-v31.0.0-x86_64-linux.tar.xz
cp wasmtime-v31.0.0-x86_64-linux/wasmtime out/wasmtime
chmod +x out/wasmtime
out/wasmtime --version | tee version.txt
```

Expected output:

```text
wasmtime 31.0.0 (7a9be587f 2025-03-20)
```

**Option B — build from source**

```bash
cd "$ROOT/runtimes/wasmtime-31.0.0"
./build.sh all
# copy the artifact to out/wasmtime; see BUILD.md
```

**Verify** (any wasm in this repo):

```bash
"$ROOT/runtimes/wasmtime-31.0.0/out/wasmtime" run \
  "$ROOT/benchmarks/polybenchc/atax.wasm" --invoke main
```

---

### 3.3 Wasmer **5.0.4**

**Option A — official install script (recommended)**

```bash
cd "$ROOT/runtimes/wasmer-5.0.4"
export WASMER_DIR="$PWD/out"
curl https://get.wasmer.io -sSfL | sh -s "v5.0.4"
# the installer writes to ~/.wasmer; link the binary into this repo's out/
mkdir -p out/bin
cp -a "$HOME/.wasmer/bin/wasmer" out/bin/ 2>/dev/null || cp -a "$WASMER_DIR/bin/wasmer" out/bin/
ln -sf bin/wasmer out/wasmer
out/wasmer --version | tee version.txt
```

**Option B — download the release tarball directly**

```bash
cd "$ROOT/runtimes/wasmer-5.0.4"
mkdir -p out/bin
curl -LO https://github.com/wasmerio/wasmer/releases/download/v5.0.4/wasmer-linux-amd64.tar.gz
tar xf wasmer-linux-amd64.tar.gz -C out/bin
ln -sf bin/wasmer out/wasmer
out/wasmer --version | tee version.txt
```

Expected output:

```text
wasmer 5.0.4
```

**Verify** (the paper's PolyBench column uses the LLVM backend):

```bash
"$ROOT/runtimes/wasmer-5.0.4/out/wasmer" run \
  --llvm -q "$ROOT/benchmarks/polybenchc/atax.wasm"
```

---

## 4. One-shot Check of the Three Versions

```bash
export ROOT=<repo>/benchmarks/paper

test -x "$ROOT/runtimes/dtvm/dtvm" && echo "dtvm: OK ($(grep commit= "$ROOT/runtimes/dtvm/version.txt"))"
"$ROOT/runtimes/wasmtime-31.0.0/out/wasmtime" --version
"$ROOT/runtimes/wasmer-5.0.4/out/wasmer" --version
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
# DTVM @ 882c83155 (paper multipass: greedy RA off + multipass multithread off)
export DTVM="$ROOT/runtimes/dtvm/dtvm"
export DTVM_OPTIONS="-m multipass --disable-multipass-greedyra --disable-multipass-multithread"
./scripts/run_polybench.sh dtvm

export WASMTIME="$ROOT/runtimes/wasmtime-31.0.0/out/wasmtime"
./scripts/run_polybench.sh wasmtime

export WASMER="$ROOT/runtimes/wasmer-5.0.4/out/wasmer"
# run_polybench.sh expects a path for wasmer; or run manually:
cd "$ROOT/scripts/webassembly-testsuites"
./runtest_webassembly.py -r "$ROOT/runtimes/wasmer-5.0.4/out/wasmer run --llvm" -s polybenchc
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

export DTVM="$ROOT/runtimes/dtvm/dtvm"
export WASMTIME="$ROOT/runtimes/wasmtime-31.0.0/out/wasmtime"
export WASMER="$ROOT/runtimes/wasmer-5.0.4/out/wasmer"

# 1) DTVM multipass (xlsx "dtvm multipass" — inferred CLI: greedy off + MT off)
./scripts/bench_polybench_timing.sh dtvm multipass

# 2) DTVM lazy (xlsx "dtvm multipass + lazy" — inferred CLI)
./scripts/bench_polybench_timing.sh dtvm lazy

# 3) Wasmtime 31.0.0
./scripts/bench_polybench_timing.sh wasmtime default

# 4) Wasmer 5.0.4 LLVM (xlsx "wasmer llvm" Total column)
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

After a run, the script attempts a **rough comparison** against the paper table if `raw_data/benchs/dtvm_polybench.xlsx` is present (not shipped). **Read** [`XLSX_FORMAT.md`](XLSX_FORMAT.md) **before comparing**: do not mistake a compile column (e.g. `0.935` seconds) for total.

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
#    - dtvm/dtvm @ 882c83155
#    - wasmtime-31.0.0/out/wasmtime
#    - wasmer-5.0.4/out/wasmer

# C. Version check (§4)

# D. Correctness (§5)
./scripts/setup_polybench_case.sh
./scripts/run_polybench.sh dtvm
./scripts/run_polybench.sh wasmtime

# E. Performance (§6, sequential; ~30 cases × 4 reps × 4 configs, hours)
./scripts/bench_polybench_timing.sh dtvm multipass
./scripts/bench_polybench_timing.sh dtvm lazy
./scripts/bench_polybench_timing.sh wasmtime default
./scripts/bench_polybench_timing.sh wasmer llvm
```

---

## 8. FAQ

### `dtvm: not found` / cannot execute

- Confirm `runtimes/dtvm/dtvm` exists and is `chmod +x`.
- Check whether the `DTVM` environment variable points at the right path.

### Wasmtime / Wasmer version mismatch

```bash
$ROOT/runtimes/wasmtime-31.0.0/out/wasmtime --version   # must contain 31.0.0
$ROOT/runtimes/wasmer-5.0.4/out/wasmer --version         # must be 5.0.4
```

### DTVM build cannot find LLVM

```bash
cmake -DLLVM_DIR=/opt/llvm15/lib/cmake/llvm ...
```

The path varies by machine; locate it with `find /opt -name LLVMConfig.cmake 2>/dev/null`.

### Numbers differ a lot from the xlsx

- First confirm you are comparing the **same column, same row group** (compile vs total).
- This script measures **whole-process wall time**, not the possibly compile-only split used in the paper.
- `882c83155` has **no** public CLI matching the xlsx column `dtvm multipass + exit optimization`.

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
| DTVM `dtvm` | `882c83155` | `$ROOT/runtimes/dtvm/dtvm` |
| Wasmtime | **31.0.0** | `$ROOT/runtimes/wasmtime-31.0.0/out/wasmtime` |
| Wasmer | **5.0.4** | `$ROOT/runtimes/wasmer-5.0.4/out/wasmer` |

| Script | Purpose |
|--------|---------|
| `scripts/setup_polybench_case.sh` | link polybench cases |
| `scripts/run_polybench.sh` | correctness runtest |
| `scripts/bench_polybench_timing.sh` | performance CSV |

The paper's original ms table is in the paper (the xlsx is not shipped).
