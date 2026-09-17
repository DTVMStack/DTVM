/**
 * Fibonacci Benchmark (Iterative version)
 * ----------------------------------------
 * Iterative fibonacci — matches fib.sol's actual implementation.
 * Same wasm binary for all runtimes (no host API imports).
 *
 * Build:
 *   em++ perf_test_fib_iter.cpp -O2 -o perf_test_fib_iter_invoke.wasm \
 *       --no-entry \
 *       -s EXPORTED_FUNCTIONS='["_test_fib_iter"]' \
 *       -s EXPORTED_RUNTIME_METHODS='[]'
 *
 * Run:
 *   dtvm perf_test_fib_iter_invoke.wasm -m multipass -f test_fib_iter --args 100000000 30
 *   wasmtime run -C cache=n --invoke test_fib_iter perf_test_fib_iter_invoke.wasm 100000000 30
 *   wasmer run --invoke test_fib_iter perf_test_fib_iter_invoke.wasm -- 100000000 30
 *   wasmer run --singlepass --invoke test_fib_iter perf_test_fib_iter_invoke.wasm -- 100000000 30
 */
#include <cstdint>
#include <cstdlib>

// Iterative fibonacci — O(n), same as fib.sol
__attribute__((noinline))
static int64_t fib_iter(int64_t n) {
    if (n == 0) return 0;
    if (n == 1) return 1;
    int64_t a = 0, b = 1;
    for (int64_t i = 2; i <= n; i++) {
        int64_t tmp = a + b;
        a = b;
        b = tmp;
    }
    return b;
}

// Entry point: run fib_iter(fib_n) for `iterations` times.
// Data dependency (result & 1) prevents loop-invariant hoisting.
extern "C" int64_t test_fib_iter(int32_t iterations, int32_t fib_n) {
    int64_t result = 0;
    for (int32_t i = 0; i < iterations; i++) {
        result = fib_iter(static_cast<int64_t>(fib_n) + (result & 1));
    }
    return result;
}

int main(int argc, char* argv[]) {
    int iterations = 100000000;
    int fib_n = 30;
    if (argc >= 2) iterations = atoi(argv[1]);
    if (argc >= 3) fib_n = atoi(argv[2]);
    volatile int64_t result = test_fib_iter(iterations, fib_n);
    (void)result;
    return 0;
}
