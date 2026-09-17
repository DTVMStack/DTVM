/**
 * Fibonacci Benchmark
 * -------------------
 * Recursive fibonacci — compute-intensive benchmark to measure
 * JIT compilation quality across different Wasm runtimes.
 *
 * Unlike perf_test_swap_pool.cpp, this benchmark does NOT use any
 * DTVM-specific host APIs. The same source and wasm binary can be
 * used across DTVM, Wasmtime, and Wasmer for a fair comparison.
 *
 * Usage:
 *   test_fib(iterations, fib_n)
 *     - iterations: number of times to call fib(fib_n) in a loop
 *     - fib_n:      fibonacci input (e.g. 30)
 *   Returns the last fib result (for correctness check).
 *
 * Build (invoke-style, no main, for DTVM/wasmtime --invoke):
 *   em++ perf_test_fib.cpp -O2 -o perf_test_fib_invoke.wasm \
 *       --no-entry \
 *       -s EXPORTED_FUNCTIONS='["_test_fib"]' \
 *       -s EXPORTED_RUNTIME_METHODS='[]'
 *
 * Build (main-style, for wasmer run / wasmtime run):
 *   em++ perf_test_fib.cpp -O2 -o perf_test_fib_main.wasm \
 *       -s EXPORTED_FUNCTIONS='["_test_fib"]' \
 *       -s EXPORTED_RUNTIME_METHODS='[]'
 *
 * Run:
 *   dtvm perf_test_fib_invoke.wasm -m multipass -f test_fib --args 10000 30
 *   wasmtime run -C cache=n --invoke test_fib perf_test_fib_invoke.wasm 10000 30
 *   wasmer run --invoke test_fib perf_test_fib_invoke.wasm -- 10000 30
 *   wasmer run --singlepass --invoke test_fib perf_test_fib_invoke.wasm -- 10000 30
 */
#include <cstdint>
#include <cstdlib>

// Naive recursive fibonacci — O(2^n) by design to stress the JIT
__attribute__((noinline))
static int64_t fib(int64_t n) {
    if (n <= 1) return n;
    return fib(n - 1) + fib(n - 2);
}

// Prevent the compiler from hoisting fib() out of the loop.
// Each iteration feeds (result & 1) back into fib_n, creating a true
// data dependency. Since (result & 1) is 0 or 1, the actual input is
// fib_n or fib_n+1, negligible difference for benchmarking purposes.
extern "C" int64_t test_fib(int32_t iterations, int32_t fib_n) {
    int64_t result = 0;
    for (int32_t i = 0; i < iterations; i++) {
        result = fib(static_cast<int64_t>(fib_n) + (result & 1));
    }
    return result;
}

// Entry for wasmer run / wasmtime run (via _start -> main)
int main(int argc, char* argv[]) {
    int iterations = 10000;
    int fib_n = 30;
    if (argc >= 2) iterations = atoi(argv[1]);
    if (argc >= 3) fib_n = atoi(argv[2]);
    volatile int64_t result = test_fib(iterations, fib_n);
    (void)result;
    return 0;
}
