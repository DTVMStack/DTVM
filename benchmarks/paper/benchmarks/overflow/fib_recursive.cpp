// Recursive Fibonacci benchmark — standalone wasm version
// Usage: fibonacci_recursive(n) returns fib(n)
// Intentionally uses naive recursive algorithm to create meaningful workload

#include <stdint.h>

__attribute__((noinline))
int64_t fib(int64_t n) {
    if (n <= 1) return n;
    return fib(n - 1) + fib(n - 2);
}

// Entry point for DTVM/wasmtime --invoke
extern "C" int64_t fibonacci_recursive(int n) {
    return fib((int64_t)n);
}

// Entry point for wasmer run (via main)
int main(int argc, char* argv[]) {
    if (argc < 2) return 1;
    int n = 0;
    for (const char* p = argv[1]; *p >= '0' && *p <= '9'; ++p)
        n = n * 10 + (*p - '0');
    volatile int64_t result = fib((int64_t)n);
    (void)result;
    return 0;
}
