# WAPM `Total compilation time` Reproduction Guide

This document explains how to reproduce the paper's **Post-Loading & Compilation** experiment locally: comparing `Total compilation time` across **dtvm (DTVM lazy)**, **wasmtime 45.0.0**, and **wasmer 7.1.0** (cranelift / singlepass / llvm) on the WAPM **20 cases**.

**Paper table**: the paper's WAPM lazy-TTFI table (not shipped)
**Local summary**: generated under `raw_data/benchs/` when running §4
**Case and conf details**: `benchmarks/wapm/WAPM_REPRODUCE.md`

---

## 1. What Is Measured

### 1.1 Unified Metric

A single line on each runtime's stdout:

```text
Total compilation time: <ms> ms (<µs> μs)
```

- Parse the **microseconds** inside the parentheses; average over runs, then divide by 1000 to get ms (same as `scripts/avg_compile_time.py`).
- The paper table's lazy / wasmtime / wasmer columns were produced from per-runtime compile logs (the logs themselves are not shipped).

### 1.2 Per-runtime Semantics

| Runtime | What `Total compilation` means |
|---------|--------------------------------|
| **dtvm (DTVM multipass lazy)** | **Load** + JIT lazy precompilation + instantiation + **first** on-demand Fg JIT |
| **wasmtime** | `compile_module()` eager whole-module compile |
| **wasmer** | `Module::new` (module cache must be disabled) |

### 1.3 Metrics That Must Not Be Mixed

| Metric | Note |
|--------|------|
| The `Total:` line in statistics | includes the whole Load/Fg/Bg/Release; **not** the compile column |
| Shell wall-clock / `test_lazy.sh`'s `Average time` | much larger than the compile line; cannot be compared directly with the paper's compile column |

The dtvm formula is implemented in `DTVM/src/utils/statistics.cpp` (change: `DTVM/docs/changes/2026-05-28-wapm-ttfi-compile-time-report/`).

---

## 2. Environment and Layout

### 2.1 Dependencies

| Component | Requirement |
|-----------|-------------|
| OS | Linux x86_64 |
| DTVM | CMake 3.x, C++ compiler |
| wasmtime / wasmer | Rust stable + `source ~/.cargo/env` |
| wasmer **llvm** | **LLVM 21** (wasmer 7.1 uses `llvm-sys-211`) |
| Python | 3.x stdlib (table-merge script) |

### 2.2 Recommended Directory Layout

```text
~/
├── DTVM/                          # dtvm source and build/dtvm
├── wasmtime-45.0.0/               # wasmtime source with TTFI instrumentation
├── wasmer-7.1.0/                  # wasmer source with TTFI instrumentation
├── LLVM-21.1.8-Linux-X64/         # wasmer llvm backend (see §3.4)
└── benchmarks/paper/
    ├── benchmarks/wapm/           # *.wasm + *.wasm.conf
    ├── runtimes/
    │   ├── wasmtime-45.0.0/build.sh
    │   └── wasmer-7.1.0/build.sh
    ├── scripts/                   # benchmark + table-merge scripts
    └── docs/WAPM_TTFI_REPRODUCTION.md   # this document
```

### 2.3 Case List (20)

```text
amirali base64cli chkfont code-stock cowsay dice echo erdtree figlet
irb md5 pi pkg1 qr2text sam suggest tpl uuid viu fortune
```

`fortune` stands in for the paper table's `zuk` (the rerun used `fortune`, a case verified runnable in this harness, in place of `zuk`).

---

## 3. Building the Runtimes

### 3.1 dtvm (DTVM)

```bash
cd /path/to/DTVM
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j6 --target dtvm

export DTVM=/path/to/DTVM/build/dtvm
```

All scripts that launch dtvm warn on stderr if the resolved binary looks like a non-Release build (Debug `CMAKE_BUILD_TYPE` in the neighboring `CMakeCache.txt`, or embedded debug info otherwise) — a Debug dtvm is far slower than the paper's Release build.

**Confirm the instrumentation is in the binary**:

```bash
strings "$DTVM" | grep -F 'Total compilation time'
```

**Run flags (the paper's lazy multipass)**:

```bash
cd benchmarks/paper/benchmarks/wapm

$DTVM echo.wasm -m multipass \
  --enable-multipass-lazy \
  --disable-multipass-greedyra \
  --disable-multipass-multithread \
  --enable-statistics \
  --args 1234567890
```

**Note**: `INPUT_FILE` (`<case>.wasm`) must come **before all flags**, or the CLI reports `INPUT_FILE is required`.

### 3.2 wasmtime 45.0.0

The source must already contain the TTFI instrumentation (`src/ttfi_report.rs`, the `ttfi-report` feature in `Cargo.toml`, etc.). If not yet cloned:

```bash
git clone --depth 1 --branch v45.0.0 \
  https://github.com/bytecodealliance/wasmtime.git \
  /path/to/wasmtime-45.0.0
# then apply the same ttfi-report modifications used in the paper
```

Build and install:

```bash
cd benchmarks/paper/runtimes/wasmtime-45.0.0
WASMER_SRC=/path/to/wasmtime-45.0.0 ./build.sh   # variable kept for historical reasons; points to the wasmtime source

export WASMTIME=$PWD/out/wasmtime
export WASMTIME_CACHE=0
```

**Smoke test**:

```bash
rm -rf ~/.cache/wasmtime
cd benchmarks/paper/benchmarks/wapm
$WASMTIME run echo.wasm 1234567890
# You should see Creating mmap / Total compilation time / Execution 1
```

### 3.3 wasmer 7.1.0 (cranelift + singlepass + llvm)

```bash
git clone --depth 1 --branch v7.1.0 \
  https://github.com/wasmerio/wasmer.git \
  /path/to/wasmer-7.1.0
# then apply the TTFI instrumentation (lib/wasix/src/ttfi_report.rs etc.)
```

### 3.4 LLVM 21 (wasmer llvm backend)

wasmer **7.1.0** requires **LLVM 21** (not LLVM 18). Local example:

```bash
# If you only have the tarball:
cd ~
tar -xf LLVM-21.1.8-Linux-X64.tar.xz

export LLVM_SYS_211_PREFIX=$HOME/LLVM-21.1.8-Linux-X64
$LLVM_SYS_211_PREFIX/bin/llvm-config --version   # should print 21.1.8
```

Build wasmer (auto-detects LLVM 21 and enables the `llvm` feature):

```bash
cd benchmarks/paper/runtimes/wasmer-7.1.0
LLVM_SYS_211_PREFIX=$LLVM_SYS_211_PREFIX ./build.sh

export WASMER=$PWD/out/bin/wasmer
```

**Smoke test (three backends)**:

```bash
cd benchmarks/paper/benchmarks/wapm
$WASMER run --cranelift  --cache-dir=/dev/null echo.wasm -- 1234567890
$WASMER run --singlepass --cache-dir=/dev/null echo.wasm -- 1234567890
$WASMER run --llvm       --cache-dir=/dev/null echo.wasm -- 1234567890
```

Guest arguments starting with `-` require a `--` separator, e.g. `sam.wasm -- -debug sam.wav`.

---

## 4. Benchmarking

### 4.1 One-shot Full Flow (recommended)

```bash
cd <DTVM repo>/benchmarks/paper

export DTVM=/path/to/DTVM/build/dtvm
export WASMTIME=$PWD/runtimes/wasmtime-45.0.0/out/wasmtime
export WASMER=$PWD/runtimes/wasmer-7.1.0/out/bin/wasmer
export WASMTIME_CACHE=0

./scripts/run_wapm_v45_v71_round.sh 3
```

- Argument `3`: repeat each case 3 times and average.
- Output dir: `raw_data/benchs/wapm_v45_v71_<timestamp>/`
- Summary table: `raw_data/benchs/wapm_v45_v71_latency_table.md` / `.csv`
- If wasmer was built with llvm, the script runs `--llvm` automatically and fills the llvm column.

### 4.2 Step-by-step

```bash
BENCH=raw_data/benchs/wapm_v45_v71_manual
mkdir -p "$BENCH"

# dtvm + wasmtime
DTVM=$DTVM WASMTIME=$WASMTIME \
  ./scripts/run_dtvm_wt_compile_round.sh 3 "$BENCH/dtvm_wt"

# wasmer backends
WASMER=$WASMER ./scripts/run_wasmer_ttfi_compare.sh 3 "$BENCH/wasmer_cranelift" cranelift
WASMER=$WASMER ./scripts/run_wasmer_ttfi_compare.sh 3 "$BENCH/wasmer_singlepass" singlepass
WASMER=$WASMER ./scripts/run_wasmer_ttfi_compare.sh 3 "$BENCH/wasmer_llvm" llvm

# merge into the paper-format table
OUT_DIR="$BENCH/table" \
  DTVM_LOG_DIR="$BENCH/dtvm_wt/logs/dtvm" \
  WT_CSV="$BENCH/dtvm_wt/wt/results.csv" \
  WASMER_CR_CSV="$BENCH/wasmer_cranelift/results.csv" \
  WASMER_SP_CSV="$BENCH/wasmer_singlepass/results.csv" \
  WASMER_LLVM_CSV="$BENCH/wasmer_llvm/results.csv" \
  ROOT=$PWD \
  python3 scripts/build_wapm_local_table.py
```

### 4.3 Cache and Cold Start (required)

| Runtime | Setting |
|---------|---------|
| **wasmtime** | `export WASMTIME_CACHE=0`; **`rm -rf ~/.cache/wasmtime` before each run** (script's `CLEAR_WASMTIME_CACHE=1` is on by default) |
| **wasmer** | `--cache-dir=/dev/null` every run |
| **dtvm** | no cross-run module cache; fresh process each time |

Without clearing the wasmtime cache, cases like echo drop from ~20–30 ms to ~1 ms, making the results incomparable with the paper.

### 4.4 Per-case Arguments

Some cases depend on `benchmarks/wapm/<case>.wasm.conf` (`--dir`, `--args`, piped input, etc.). The benchmark scripts read the conf; for manual runs see `benchmarks/wapm/WAPM_REPRODUCE.md`.

---

## 5. Validation and Comparison with the Paper

### 5.1 Parsing the Paper's Original Logs

```bash
cd scripts
# edit log_file_path at the bottom of avg_compile_time.py to point at the dtvm/wasmtime/wasmer logs
python3 avg_compile_time.py
```

### 5.2 Quick Checklist

- [ ] `strings build/dtvm | grep 'Total compilation time'` produces output
- [ ] A single dtvm echo run prints a `Total compilation time: … ms (… µs)` line
- [ ] `rm -rf ~/.cache/wasmtime` ran before the wasmtime echo run
- [ ] wasmer uses `--cache-dir=/dev/null`
- [ ] wasmer llvm has `LLVM_SYS_211_PREFIX` set and `wasmer run --llvm` works
- [ ] The summary table has dtvm / wt / wasmer-cr / wasmer-sp columns for all 20 cases; the llvm column is non-empty after an llvm build

---

## 6. Script Index

| Script | Purpose |
|--------|---------|
| `scripts/run_wapm_v45_v71_round.sh` | one-shot: dtvm + wt45 + wasmer7 (cr/sp/llvm) + merged table |
| `scripts/run_dtvm_wt_compile_round.sh` | dtvm + wasmtime, 20 cases |
| `scripts/run_wasmtime_ttfi_compare.sh` | wasmtime only |
| `scripts/run_wasmer_ttfi_compare.sh` | wasmer only (args: `repeats out_dir engine`) |
| `scripts/build_wapm_local_table.py` | generate the paper-format md/csv from logs/CSVs |

Environment variables (table merge):

| Variable | Meaning |
|----------|---------|
| `DTVM_LOG_DIR` | dtvm log directory |
| `WT_CSV` | wasmtime `results.csv` |
| `WASMER_CR_CSV` / `WASMER_SP_CSV` / `WASMER_LLVM_CSV` | wasmer per-backend CSVs |
| `OUT_DIR` | output `wapm_local_latency_table.md` |

---

## 7. Instrumentation Locations

| Component | Location |
|-----------|----------|
| dtvm TTFI | `DTVM/src/utils/statistics.cpp` etc. |
| wasmtime 45 TTFI | `wasmtime-45.0.0/src/ttfi_report.rs`, `src/common.rs`, `src/commands/run.rs` |
| wasmtime 31 TTFI (legacy) | `runtimes/wasmtime-31.0.0/patches/ttfi-report.patch` |
| wasmer 7.1 TTFI | `wasmer-7.1.0/lib/wasix/src/ttfi_report.rs` etc. |
| wasmer 5.0.4 TTFI (legacy) | same modifications on `wasmer-5.0.4`; llvm needs **LLVM 18** |

---

## 8. FAQ

| Symptom | Fix |
|---------|-----|
| dtvm prints no `Total compilation time` | rebuild `dtvm` (`statistics.cpp` mtime must precede the binary) |
| wasmtime echo ~1 ms | `~/.cache/wasmtime` was not cleared |
| wasmer llvm fails to build | confirm `LLVM_SYS_211_PREFIX` points at **21.x**, not 18 |
| `llvm-config` from LLVM 18 reports `libtinfo.so.5` | the Ubuntu 18 prebuilt package is incompatible with newer ncurses; use the LLVM 21 package for wasmer 7 |
| `INPUT_FILE is required` | put `<case>.wasm` **before** the flags |
| irb extremely slow | expected (large module); the llvm backend is especially slow |
| fortune has no paper row | skip the fortune comparison when using the paper's `zuk` column |

---

## 9. Older Runtime Versions (optional)

To compare against the paper's **same-version** wasmtime 31 / wasmer 5.0.4:

```bash
./runtimes/wasmtime-31.0.0/build.sh
./runtimes/wasmer-5.0.4/build.sh    # llvm needs LLVM 18 + LLVM_SYS_180_PREFIX
./scripts/run_wapm_local_full_round.sh 3
```

Output: `raw_data/benchs/wapm_local_latency_table.md`.

---

## 10. Related Documents

| Document | Contents |
|----------|----------|
| [`benchmarks/wapm/WAPM_REPRODUCE.md`](../benchmarks/wapm/WAPM_REPRODUCE.md) | case confs, correctness testing |
