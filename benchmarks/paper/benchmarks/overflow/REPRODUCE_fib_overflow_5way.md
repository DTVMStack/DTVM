# Reproduction Guide: fib(30) + Overflow 5-way Benchmark

## Prerequisites

- Linux x86_64 system
- Rust toolchain (for building Wasmer)
- LLVM 21 (for the Wasmer LLVM backend)
- Emscripten (for compiling wasm from C++)
- CMake 3.20+, GCC/Clang with C++17

## 1. Build DTVM

```bash
cd /path/to/DTVM
cmake -B build -DCMAKE_BUILD_TYPE=Release \
  -DZEN_ENABLE_MULTIPASS_JIT=ON \
  -DZEN_ENABLE_CHECKED_ARITHMETIC=ON \
  -DZEN_ENABLE_BUILTIN_LIBC=ON
cmake --build build -j$(nproc) --target dtvm
```

## 2. Install Wasmtime 45.0.0

```bash
curl https://wasmtime.dev/install.sh -sSf | bash -s -- --version v45.0.0
# Binary: ~/.wasmtime/bin/wasmtime
~/.wasmtime/bin/wasmtime --version
# Expected: wasmtime 45.0.0
```

## 3. Build Wasmer 7.1.0

```bash
# Extract LLVM 21 (for the LLVM backend)
cd /opt
tar xf LLVM-21.1.8-Linux-X64.tar.xz
export LLVM_SYS_211_PREFIX=/opt/LLVM-21.1.8-Linux-X64

# Build Wasmer with all 3 backends
git clone --branch v7.1.0 --depth 1 https://github.com/wasmerio/wasmer.git wasmer-7.1.0
cd wasmer-7.1.0
cargo build --release --features cranelift,singlepass,llvm
# Binary: target/release/wasmer
```

## 4. Compile Wasm Files

### fib(30) iterative (shared by all runtimes)

```bash
cd benchmarks/overflow

# Compile with emscripten (reactor mode, no main)
emcc -O2 -s STANDALONE_WASM=1 -s EXPORTED_FUNCTIONS='["_test_fib_iter"]' \
  --no-entry -o perf_test_fib_iter_invoke.wasm perf_test_fib_iter.cpp
```

### Integer overflow — DTVM variant

```bash
emcc -O2 -s STANDALONE_WASM=1 -DENABLE_DTVM_TEST \
  -s EXPORTED_FUNCTIONS='["_test_dtvm"]' \
  --no-entry -o perf_test_swap_pool_dtvm_O2.wasm perf_test_swap_pool.cpp
```

### Integer overflow — Wasmtime variant (reactor, --invoke)

```bash
emcc -O2 -s STANDALONE_WASM=1 \
  -s EXPORTED_FUNCTIONS='["_test_traditional"]' \
  --no-entry -o perf_test_swap_pool_non_dtvm_O2.wasm perf_test_swap_pool.cpp
```

### Integer overflow — Wasmer variant (with main entry)

```bash
emcc -O2 -s STANDALONE_WASM=1 \
  -o perf_test_swap_pool_wasmer_O2.wasm perf_test_swap_pool.cpp
```

## 5. Run Benchmarks

### Variables

```bash
DTVM=./build/dtvm
WASMTIME=~/.wasmtime/bin/wasmtime
WASMER=/path/to/wasmer-7.1.0/target/release/wasmer
BENCH=benchmarks/overflow
FIB_WASM=$BENCH/perf_test_fib_iter_invoke.wasm
```

### Benchmark 1: fib(30) iterative (500M iterations)

```bash
# DTVM
taskset -c 0 bash -c "time $DTVM $FIB_WASM -m multipass \
  -f test_fib_iter --args 500000000 30"

# Wasmtime 45
taskset -c 0 bash -c "time $WASMTIME run -C cache=n \
  --invoke test_fib_iter $FIB_WASM 500000000 30"

# Wasmer Cranelift
taskset -c 0 bash -c "time $WASMER run --cranelift \
  --invoke test_fib_iter $FIB_WASM -- 500000000 30"

# Wasmer Singlepass
taskset -c 0 bash -c "time $WASMER run --singlepass \
  --invoke test_fib_iter $FIB_WASM -- 500000000 30"

# Wasmer LLVM
taskset -c 0 bash -c "time $WASMER run --llvm \
  --invoke test_fib_iter $FIB_WASM -- 500000000 30"
```

**Expected output:** `832040` (= fib(30))

### Benchmark 2: Integer overflow (100M iterations)

```bash
# DTVM (uses checked_i64 hostapi)
taskset -c 0 bash -c "time $DTVM --format wasm -m multipass \
  -f test_dtvm $BENCH/perf_test_swap_pool_dtvm_O2.wasm --args 100000000 2000000"

# Wasmtime 45 (uses __builtin_*_overflow)
taskset -c 0 bash -c "time $WASMTIME run -C cache=n \
  --invoke test_traditional $BENCH/perf_test_swap_pool_non_dtvm_O2.wasm \
  100000000 2000000"

# Wasmer Cranelift
taskset -c 0 bash -c "time $WASMER run --cranelift \
  $BENCH/perf_test_swap_pool_wasmer_O2.wasm -- 100000000 2000000"

# Wasmer Singlepass
taskset -c 0 bash -c "time $WASMER run --singlepass \
  $BENCH/perf_test_swap_pool_wasmer_O2.wasm -- 100000000 2000000"

# Wasmer LLVM
taskset -c 0 bash -c "time $WASMER run --llvm \
  $BENCH/perf_test_swap_pool_wasmer_O2.wasm -- 100000000 2000000"
```

**Expected output:** `423724150000000` (consistent across all runtimes)

## 6. Methodology

- **CPU pinning:** `taskset -c 0` pins to a single core to reduce variance
- **Repetitions:** 5 reps per configuration, report **median**
- **Timing:** bash `time` command (wall-clock `real` time)
- **Warm-up:** None needed — compilation time is negligible for these small modules
- **Cache:** Wasmtime cache disabled (`-C cache=n`) for fair comparison

## 7. Notes

- The overflow benchmark uses **different wasm files** per runtime: DTVM uses
  native `checked_i64_*` host functions, while other runtimes use
  `__builtin_*_overflow` compiled to wasm branches. This reflects a real
  architectural advantage of DTVM, not a testing artifact.

- Wasmer 7.1.0 has a bug with `--invoke` on reactor-style wasm modules
  (exit code 45 for parameter passing), so the overflow benchmark for
  Wasmer uses wasm files with a `main()` entry point instead.

- Each benchmark run takes 2-13 seconds depending on runtime, so a full
  5-rep 5-runtime 2-benchmark suite completes in ~10 minutes.
