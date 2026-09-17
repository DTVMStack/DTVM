# Overflow + fib(30) Benchmarks

A Uniswap-swap-style **integer-overflow check** test plus a **fib(30) iteration** test. Both share the same 5-way benchmark (DTVM vs Wasmtime 45 / Wasmer 7.1 cranelift / singlepass / llvm).

## Entry Points

| File | Contents |
|------|----------|
| [`REPRODUCE_fib_overflow_5way.md`](REPRODUCE_fib_overflow_5way.md) | 5-way reproduction guide (runtime install → wasm build → benchmark → methodology) |
| `run_dtvm.sh` | reruns the DTVM column (builds the wasm on first run) |
| `run_wasmtime45.sh` | reruns the wasmtime column |

## Key Parameters

| Experiment | Parameters |
|------------|-----------|
| **fib(30) iterative** | 500,000,000 outer iterations × fib(30) with 8x unrolling; pure integer math, no imports / memory |
| **Integer overflow** | `n=100000000`, `input_amount=2000000`; DTVM uses `checked_i64_*` host functions, other runtimes use `__builtin_*_overflow` compiled into the wasm |

## Benchmark Dependencies

- DTVM main HEAD (see `../../runtimes/dtvm_main/README.md` or `REPRODUCE_fib_overflow_5way.md` §1)
- Wasmtime 45.0.0 (`../../runtimes/wasmtime-45.0.0/`)
- Wasmer 7.1.0, three backends, incl. LLVM 21 (`../../runtimes/wasmer-7.1.0/`)
- Emscripten (wasm build; measured locally with 5.0.7, `-O2`)
- `taskset -c 0` single-core pinning + 5 reps → median

## Files

| File | Description |
|------|-------------|
| `perf_test_swap_pool.cpp` | overflow C++ source (DTVM / non-DTVM / wasmer variants selected by macros) |
| `perf_test_fib_iter.cpp`, `perf_test_fib_iter_unrolled.cpp` | fib(30) iterative C++ sources |
| `perf_test_fib.cpp` / `fib_recursive.cpp` | fib(30) recursive variants (reference) |
| `perf_test_swap_pool_{dtvm,non_dtvm,wasmer}_O{0,1,2,g}.wasm` | overflow build artifacts (12) |
| `perf_test_fib*.wasm`, `fib_recursive*.wasm` | fib build artifacts |
| `build.sh` | legacy build script (paper-era wasmtime 31; historical reference — use `run_*.sh` now) |
