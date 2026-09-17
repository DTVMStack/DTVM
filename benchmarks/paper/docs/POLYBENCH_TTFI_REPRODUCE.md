# PolyBench TTFI Reproduction Guide (DTVM lazy / Wasmtime 45 / Wasmer 7.1)

This document explains how to reproduce the **TTFI (Time To First Invocation)** comparison for **PolyBench/C (30 cases)** on **Linux x86_64**:

- **DTVM** `multipass lazy` (same CLI as the WAPM experiment)
- **Wasmtime 45.0.0**
- **Wasmer 7.1.0** (singlepass / cranelift / llvm)

**Metric**: the `Total compilation time` line on stdout (same as the WAPM experiment; **not** whole-process wall time).

**Local results**: generated under `raw_data/benchs/` when running §5 (not shipped).

Related documents:

- PolyBench **wall-clock** reproduction: [`POLYBENCH_REPRODUCE.md`](POLYBENCH_REPRODUCE.md)
- WAPM TTFI reproduction (same metric, 20 cases): [`WAPM_TTFI_REPRODUCTION.md`](WAPM_TTFI_REPRODUCTION.md)

---

## 1. What Is Measured

### 1.1 Unified Metric

A single line on each runtime's stdout:

```text
Total compilation time: <ms> ms (<µs> μs)
```

The script parses the **microseconds** inside the parentheses and divides by 1000 to get **compile_ms** (same as WAPM's `avg_compile_time.py`).

### 1.2 Difference from the Wall-Clock Benchmark

| Item | TTFI (this doc) | `bench_polybench_timing.sh` |
|------|-----------------|-----------------------------|
| Measure | `Total compilation time` line | whole-process **wall time** |
| DTVM profile | **`lazy`** (WAPM protocol) | usually `multipass` / `lazy` / `multipass_greedy_mt` |
| Meaning | load + compile before first execution | startup + compile + **full execution** |
| Typical DTVM ms | **~0.45** (lazy) | seconds (includes large matrix math) |

**Do not mix**: `-m multipass` (greedy RA + MT fully on) gives a TTFI of ~90 ms because it is **eager whole-module JIT** and cannot be compared directly with the lazy column.

### 1.3 Per-runtime Semantics

| Runtime | What `Total compilation time` means |
|---------|-------------------------------------|
| **dtvm (DTVM lazy)** | Load + lazy precompile + instantiation + **first** on-demand function JIT |
| **wasmtime** | `compile_module()` eager whole-module compile |
| **wasmer** | `Module::new` (requires `--cache-dir=/dev/null`) |

---

## 2. Versions and Paths

Below, `$ROOT` is the data-repo root:

```bash
export ROOT=<repo>/benchmarks/paper
cd "$ROOT"
```

| Runtime | Version | Default binary |
|---------|---------|----------------|
| DTVM `dtvm` | **`c3c3fd856`** (example main HEAD) | `$ROOT/runtimes/dtvm_main/dtvm` |
| Wasmtime | **45.0.0** (with TTFI instrumentation) | `$ROOT/runtimes/wasmtime-45.0.0/out/wasmtime` |
| Wasmer | **7.1.0** (with TTFI instrumentation) | `$ROOT/runtimes/wasmer-7.1.0/out/wasmer` or `out/bin/wasmer` |

Benchmark: `$ROOT/benchmarks/polybenchc/*.wasm` (**30** cases, already archived; no need to recompile wasm).

---

## 3. Building the Runtimes

### 3.1 DTVM (`dtvm`, must include TTFI instrumentation)

Build **Release** from `DTVM` (or the DTVM source fork) and install into the data repo:

```bash
cd /path/to/DTVM
cmake -B build_main -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_DIR=/opt/llvm15/lib/cmake/llvm \
  -DZEN_ENABLE_SINGLEPASS_JIT=ON \
  -DZEN_ENABLE_MULTIPASS_JIT=ON

cmake --build build_main -j"$(nproc)"

mkdir -p "$ROOT/runtimes/dtvm_main"
cp build_main/dtvm "$ROOT/runtimes/dtvm_main/dtvm"
chmod +x "$ROOT/runtimes/dtvm_main/dtvm"
git rev-parse HEAD | xargs -I{} sh -c 'git log -1 --format="%H %ci %s" {}' \
  > "$ROOT/runtimes/dtvm_main/version.txt"
```

**Confirm the TTFI string is compiled into the binary** (required):

```bash
strings "$ROOT/runtimes/dtvm_main/dtvm" | grep -F 'Total compilation time'
```

**Smoke test (lazy profile)**:

```bash
export DTVM="$ROOT/runtimes/dtvm_main/dtvm"
cd "$ROOT/benchmarks/polybenchc"

$DTVM atax.wasm -m multipass \
  --enable-multipass-lazy \
  --disable-multipass-greedyra \
  --disable-multipass-multithread \
  --enable-statistics
```

Expected: exit 0, stdout contains `Total compilation time:` and `Execution 1:`.

> **Note**: `<case>.wasm` must come **before all flags**.

The TTFI implementation lives in `DTVM`'s `statistics.cpp`; the WAPM change notes are in `docs/changes/2026-05-28-wapm-ttfi-compile-time-report/`.

### 3.2 Wasmtime 45.0.0

Use a source tree **already instrumented for TTFI** (`ttfi-report` feature etc.). Example local source: `/path/to/wasmtime-45.0.0`.

```bash
cd "$ROOT/runtimes/wasmtime-45.0.0"
# If the source is not at the default path:
# export WASMER_SRC=/path/to/wasmtime-45.0.0
./build.sh

export WASMTIME="$ROOT/runtimes/wasmtime-45.0.0/out/wasmtime"
export WASMTIME_CACHE=0
```

**Smoke test**:

```bash
rm -rf ~/.cache/wasmtime
$WASMTIME run "$ROOT/benchmarks/polybenchc/atax.wasm" --invoke main
# You should see Total compilation time / Execution 1
```

Instrumentation details are the same as [`WAPM_TTFI_REPRODUCTION.md`](WAPM_TTFI_REPRODUCTION.md) §3.2.

### 3.3 Wasmer 7.1.0

```bash
cd "$ROOT/runtimes/wasmer-7.1.0"
# If the source is not at the default path:
# export WASMER_SRC=/path/to/wasmer-7.1.0
# the llvm backend needs LLVM 21:
export LLVM_SYS_211_PREFIX=/path/to/LLVM-21.1.8-Linux-X64
./build.sh

export WASMER="$ROOT/runtimes/wasmer-7.1.0/out/bin/wasmer"
# If the build output is at out/wasmer:
# export WASMER="$ROOT/runtimes/wasmer-7.1.0/out/wasmer"
```

**Smoke test (three backends)**:

```bash
cd "$ROOT/benchmarks/polybenchc"
$WASMER run --singlepass --cache-dir=/dev/null atax.wasm -q
$WASMER run --cranelift  --cache-dir=/dev/null atax.wasm -q
$WASMER run --llvm       --cache-dir=/dev/null atax.wasm -q
```

---

## 4. One-shot Check

```bash
export ROOT=<repo>/benchmarks/paper
export DTVM="$ROOT/runtimes/dtvm_main/dtvm"
export WASMTIME="$ROOT/runtimes/wasmtime-45.0.0/out/wasmtime"
export WASMER="$ROOT/runtimes/wasmer-7.1.0/out/wasmer"

test -x "$DTVM" && strings "$DTVM" | grep -q 'Total compilation time' && echo "dtvm TTFI: OK"
"$WASMTIME" --version    # expect wasmtime 45.0.0
"$WASMER" --version      # expect wasmer 7.1.0
ls "$ROOT/benchmarks/polybenchc"/*.wasm | wc -l   # 30
```

---

## 5. Benchmarking

### 5.1 Scripts

| Script | Purpose |
|--------|---------|
| [`scripts/run_polybench_ttfi_compare.sh`](../scripts/run_polybench_ttfi_compare.sh) | single runtime: run 30 cases → `results.csv` + `COMPARE.md` |
| [`scripts/run_polybench_ttfi_round.sh`](../scripts/run_polybench_ttfi_round.sh) | full flow: DTVM lazy + wasmtime + wasmer's three backends → merged table |
| [`scripts/build_polybench_ttfi_table.py`](../scripts/build_polybench_ttfi_table.py) | merge multiple `results.csv` into a comparison md/csv |

**Actual per-runtime command lines** (inside the scripts):

| Invocation | Command |
|------------|---------|
| `dtvm lazy` | `dtvm case.wasm -m multipass --enable-multipass-lazy --disable-multipass-greedyra --disable-multipass-multithread --enable-statistics` |
| `dtvm multipass_greedy_mt` | `dtvm case.wasm -m multipass --enable-statistics` (**reference column**, not the WAPM lazy protocol) |
| `wasmtime default` | `wasmtime run case.wasm --invoke main` |
| `wasmer singlepass` | `wasmer run --singlepass --cache-dir=/dev/null case.wasm -q` |
| `wasmer cranelift` | `wasmer run --cranelift --cache-dir=/dev/null case.wasm -q` |
| `wasmer llvm` | `wasmer run --llvm --cache-dir=/dev/null case.wasm -q` |

### 5.2 Cache and Cold Start (required)

| Runtime | Setting |
|---------|---------|
| **wasmtime** | `export WASMTIME_CACHE=0`; `rm -rf ~/.cache/wasmtime` before each run (script's `CLEAR_WASMTIME_CACHE=1` is on by default) |
| **wasmer** | `--cache-dir=/dev/null` every run |
| **dtvm** | no cross-run module cache; fresh process each time |

### 5.3 One-shot Full Flow (recommended)

Default is **1 repeat per case** (TTFI variance is small; pass `3` for more stability):

```bash
cd "$ROOT"

export DTVM="$ROOT/runtimes/dtvm_main/dtvm"
export WASMTIME="$ROOT/runtimes/wasmtime-45.0.0/out/wasmtime"
export WASMER="$ROOT/runtimes/wasmer-7.1.0/out/wasmer"
export WASMTIME_CACHE=0

./scripts/run_polybench_ttfi_round.sh 1
```

Output:

```text
raw_data/benchs/polybench_ttfi_<timestamp>/
  dtvm_lazy/results.csv
  dtvm_multipass_greedy_mt/results.csv   # reference column (optional)
  wasmtime45/results.csv
  wasmer_singlepass/results.csv
  wasmer_cranelift/results.csv
  wasmer_llvm/results.csv
  table/polybench_ttfi_compare.{md,csv}

raw_data/benchs/polybench_ttfi_compare_latest.{md,csv}   # copy
```

**Duration**: about **30–90 minutes** (large cases like `cholesky`/`ludcmp` execute slowly; only the compile line is measured, but the wasm still has to run to first execution).

**Background run** (survives SSH disconnect):

```bash
nohup ./scripts/run_polybench_ttfi_round.sh 1 \
  > /tmp/polybench_ttfi_round.log 2>&1 &
echo "PID=$!  log=/tmp/polybench_ttfi_round.log"
```

### 5.4 Partial Rerun (DTVM lazy column only)

If wasmtime/wasmer results already exist and only the DTVM lazy column needs a rerun:

```bash
cd "$ROOT"
export DTVM="$ROOT/runtimes/dtvm_main/dtvm"

BENCH="$ROOT/raw_data/benchs/polybench_ttfi_20260531_091216"   # existing data dir (from your own earlier round)
OUT="$BENCH/dtvm_lazy"

./scripts/run_polybench_ttfi_compare.sh dtvm lazy 1 "$OUT"

# merge the table (lazy as the main column, greedy_mt as reference)
export BENCH_ROOT="$BENCH" OUT_DIR="$BENCH/table"
export DTVM_CSV="$OUT/results.csv"
export DTVM_GREEDY_CSV="$BENCH/dtvm_multipass_greedy_mt/results.csv"
export WT_CSV="$BENCH/wasmtime45/results.csv"
export WASMER_SP_CSV="$BENCH/wasmer_singlepass/results.csv"
export WASMER_CF_CSV="$BENCH/wasmer_cranelift/results.csv"
export WASMER_LLVM_CSV="$BENCH/wasmer_llvm/results.csv"
export DTVM_VERSION="$ROOT/runtimes/dtvm_main/version.txt"

python3 scripts/build_polybench_ttfi_table.py

cp "$BENCH/table/polybench_ttfi_compare.md" \
   "$ROOT/raw_data/benchs/polybench_ttfi_compare_latest.md"
cp "$BENCH/table/polybench_ttfi_compare.csv" \
   "$ROOT/raw_data/benchs/polybench_ttfi_compare_latest.csv"
```

### 5.5 Single-runtime Examples

```bash
REPEATS=1
BENCH="$ROOT/raw_data/benchs/polybench_ttfi_manual"

DTVM=$DTVM   ./scripts/run_polybench_ttfi_compare.sh dtvm lazy "$REPEATS" "$BENCH/dtvm_lazy"
WASMTIME=$WASMTIME ./scripts/run_polybench_ttfi_compare.sh wasmtime default "$REPEATS" "$BENCH/wasmtime45"
WASMER=$WASMER ./scripts/run_polybench_ttfi_compare.sh wasmer singlepass "$REPEATS" "$BENCH/wasmer_sp"
WASMER=$WASMER ./scripts/run_polybench_ttfi_compare.sh wasmer cranelift "$REPEATS" "$BENCH/wasmer_cf"
WASMER=$WASMER ./scripts/run_polybench_ttfi_compare.sh wasmer llvm "$REPEATS" "$BENCH/wasmer_llvm"
```

Each subdirectory contains:

- `logs/<case>_1.log` — raw stdout
- `results.csv` — `case,compile_ms,execution_ms`
- `COMPARE.md` — single-runtime summary

---

## 6. Full Reproduction Checklist

```bash
# A. Repo
export ROOT=<repo>/benchmarks/paper
cd "$ROOT"

# B. Build runtimes (§3)
#    - dtvm_main/dtvm (with the Total compilation time string)
#    - wasmtime-45.0.0/out/wasmtime (TTFI instrumentation)
#    - wasmer-7.1.0/out/wasmer (TTFI instrumentation + optional llvm)

# C. Version check (§4)

# D. TTFI benchmark (§5.3, sequential — do not run multiple dtvm in parallel)
export WASMTIME_CACHE=0
./scripts/run_polybench_ttfi_round.sh 1

# E. View results
less raw_data/benchs/polybench_ttfi_compare_latest.md
```

---

## 7. FAQ

### `dtvm: binary missing TTFI strings`

- The `dtvm` in use is too old or was built without the WAPM TTFI change; rebuild from **main HEAD** (or a tree containing the `2026-05-28-wapm-ttfi` change).

### DTVM lazy is ~0.4 ms while greedy_mt is ~90 ms — which is right?

- **The TTFI comparison lazy column uses the `lazy` profile** (§1.2).
- `multipass_greedy_mt` compiles the whole module eagerly, so its compile time approaches the compile segment of wall-time — it **cannot** represent the WAPM lazy TTFI.

### wasmtime compile suddenly drops to ~1 ms

- `~/.cache/wasmtime` was not cleared or `WASMTIME_CACHE=0` was not set; confirm the script's `CLEAR_WASMTIME_CACHE=1`.

### Numbers differ by orders of magnitude from `bench_polybench_timing.sh`

- Expected: wall-clock includes the **full PolyBench computation** (seconds); TTFI only measures **pre-first-execution compilation** (milliseconds).

### PolyBench cases have no conf files

- Unlike WAPM, PolyBench wasm uniformly uses `--invoke main` (wasmtime) or direct execution (dtvm/wasmer); no `.wasm.conf` is needed.

---

## 8. Path Reference

| Item | Path |
|------|------|
| This document | `$ROOT/docs/POLYBENCH_TTFI_REPRODUCE.md` |
| Latest comparison table | `$ROOT/raw_data/benchs/polybench_ttfi_compare_latest.md` (generated) |
| Case wasm | `$ROOT/benchmarks/polybenchc/*.wasm` |
