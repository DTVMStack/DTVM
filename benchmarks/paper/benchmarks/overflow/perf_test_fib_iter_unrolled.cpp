/**
 * Fibonacci Benchmark (Iterative, MANUALLY 8x UNROLLED)
 * -----------------------------------------------------
 * Same as perf_test_fib_iter.cpp but with the inner loop manually
 * unrolled 8x to simulate what Cranelift v45 does automatically.
 * Purpose: verify that loop unrolling is the key optimization
 * that would close the gap between DTVM and Cranelift.
 *
 * Build:
 *   em++ perf_test_fib_iter_unrolled.cpp -O2 -o perf_test_fib_iter_unrolled.wasm \
 *       --no-entry \
 *       -s EXPORTED_FUNCTIONS='["_test_fib_iter_unrolled"]' \
 *       -s EXPORTED_RUNTIME_METHODS='[]'
 */
#include <cstdint>

__attribute__((noinline))
static int64_t fib_iter_unrolled(int64_t n) {
    if (n == 0) return 0;
    if (n == 1) return 1;
    int64_t a = 0, b = 1;
    int64_t i = 2;

    // Unrolled 8x: each iteration advances 8 fibonacci steps
    int64_t limit = n - 7; // avoid overflow: loop while i <= n-7
    for (; i <= limit; i += 8) {
        int64_t t0 = a + b;  // step 1
        int64_t t1 = b + t0; // step 2
        int64_t t2 = t0 + t1; // step 3
        int64_t t3 = t1 + t2; // step 4
        int64_t t4 = t2 + t3; // step 5
        int64_t t5 = t3 + t4; // step 6
        int64_t t6 = t4 + t5; // step 7
        int64_t t7 = t5 + t6; // step 8
        a = t6;
        b = t7;
    }

    // Remainder loop
    for (; i <= n; i++) {
        int64_t tmp = a + b;
        a = b;
        b = tmp;
    }
    return b;
}

extern "C" int64_t test_fib_iter_unrolled(int32_t iterations, int32_t fib_n) {
    int64_t result = 0;
    for (int32_t i = 0; i < iterations; i++) {
        result = fib_iter_unrolled(static_cast<int64_t>(fib_n) + (result & 1));
    }
    return result;
}

int main(int argc, char* argv[]) {
    int iterations = 500000000;
    int fib_n = 30;
    if (argc >= 2) {
        iterations = 0;
        for (const char* p = argv[1]; *p >= '0' && *p <= '9'; ++p)
            iterations = iterations * 10 + (*p - '0');
    }
    if (argc >= 3) {
        fib_n = 0;
        for (const char* p = argv[2]; *p >= '0' && *p <= '9'; ++p)
            fib_n = fib_n * 10 + (*p - '0');
    }
    volatile int64_t result = test_fib_iter_unrolled(iterations, fib_n);
    (void)result;
    return 0;
}
