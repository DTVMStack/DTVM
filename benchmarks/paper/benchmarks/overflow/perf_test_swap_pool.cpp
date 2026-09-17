/**
 * DeFi AMM Overflow Protection Benchmark
 * -------------------------------------
 * This benchmark compares the performance of two integer overflow protection approaches
 * in a realistic DeFi Automated Market Maker (AMM) scenario:
 *
 * 1. Traditional C/C++ approach using __builtin_*_overflow intrinsics
 * 2. Wasm JIT VM approach using native checked_i*_* operations
 *
 * The test simulates token swap calculations based on the constant product formula (x*y=k),
 * which is the core of many DEX platforms like Uniswap. Each calculation involves multiple
 * arithmetic operations that require overflow protection to ensure financial safety.
 *
 * Integer overflow vulnerabilities have been the source of numerous DeFi exploits,
 * making this a particularly relevant benchmark for blockchain applications.
 */
#include <iostream>
#include <stdint.h>

#ifdef ENABLE_DTVM_TEST
// DTVM checked-arithmetic hostapi
extern "C" int64_t checked_i64_add(int64_t a, int64_t b);
extern "C" int64_t checked_i64_sub(int64_t a, int64_t b);
extern "C" int64_t checked_i64_mul(int64_t a, int64_t b);
#else
#include <cstdio>
#include <cstdlib>

static void panic(const char* message) {
    fprintf(stderr, "PANIC: %s", message);
    exit(1);
}

#endif // ENABLE_DTVM_TEST

#ifndef ENABLE_DTVM_TEST
// Traditional overflow checking
int64_t safe_add_traditional(int64_t a, int64_t b) {
    int64_t result;
    if (__builtin_add_overflow(a, b, &result)) {
        panic("Integer overflow in addition");
    }
    return result;
}

int64_t safe_sub_traditional(int64_t a, int64_t b) {
    int64_t result;
    if (__builtin_sub_overflow(a, b, &result)) {
        panic("Integer underflow in subtraction");
    }
    return result;
}

int64_t safe_mul_traditional(int64_t a, int64_t b) {
    int64_t result;
    if (__builtin_mul_overflow(a, b, &result)) {
        panic("Integer overflow in multiplication");
    }
    return result;
}

int64_t safe_div_traditional(int64_t a, int64_t b) {
    if (b == 0) {
        panic("Division by zero");
    }
    if (a == INT64_MIN && b == -1) {
        panic("Integer overflow in division");
    }
    return a / b;
}

// AMM output with traditional overflow checks
int64_t get_output_amount_traditional(int64_t input_amount, int64_t input_reserve,
                                       int64_t output_reserve, int64_t fee_numerator,
                                       int64_t fee_denominator) {
    // Input amount after the fee
    int64_t input_with_fee = safe_mul_traditional(input_amount,
                                               safe_sub_traditional(fee_denominator, fee_numerator));
    input_with_fee = safe_div_traditional(input_with_fee, fee_denominator);

    // Constant-product formula: output = (input_with_fee * output_reserve) / (input_reserve + input_with_fee)
    int64_t numerator = safe_mul_traditional(input_with_fee, output_reserve);
    int64_t denominator = safe_add_traditional(input_reserve, input_with_fee);
    int64_t output_amount = safe_div_traditional(numerator, denominator);

    return output_amount;
}

#endif // !ENABLE_DTVM_TEST

// AMM output with WasmVM overflow checks
#ifdef ENABLE_DTVM_TEST
int64_t get_output_amount_wasmvm(int64_t input_amount, int64_t input_reserve,
                                  int64_t output_reserve, int64_t fee_numerator,
                                  int64_t fee_denominator) {
    // Input amount after the fee
    int64_t input_with_fee = checked_i64_mul(input_amount,
                                          checked_i64_sub(fee_denominator, fee_numerator));
    input_with_fee = input_with_fee/fee_denominator;

    // Constant-product formula: output = (input_with_fee * output_reserve) / (input_reserve + input_with_fee)
    int64_t numerator = checked_i64_mul(input_with_fee, output_reserve);
    int64_t denominator = checked_i64_add(input_reserve, input_with_fee);
    int64_t output_amount = numerator/denominator;

    return output_amount;
}
#endif // ENABLE_DTVM_TEST

// Test function - traditional overflow checks
#ifndef ENABLE_DTVM_TEST
extern "C" int64_t test_traditional(int n, int64_t input_amount) {
    // volatile prevents optimization
    volatile int64_t reserve_x = 1000000000000;
    volatile int64_t reserve_y = 4000000000000;
    volatile int64_t fee_numerator = 3;
    volatile int64_t fee_denominator = 1000;

    // pseudo-random seed prevents loop unrolling
    volatile int seed = n;
    int64_t total_output = 0;

    for (volatile int i = 0; i < n; i++) {
        // pseudo-random direction
        int direction = (i + seed) % 2;

        if (direction == 0) {
            int64_t output = get_output_amount_traditional(
                input_amount, reserve_x, reserve_y, fee_numerator, fee_denominator);
            total_output = safe_add_traditional(total_output, output);
        } else {
            int64_t output = get_output_amount_traditional(
                input_amount, reserve_y, reserve_x, fee_numerator, fee_denominator);
            total_output = safe_add_traditional(total_output, output);
        }
    }

    return total_output;
}
#endif // !ENABLE_DTVM_TEST

// Test function - DTVM overflow checks
#ifdef ENABLE_DTVM_TEST
extern "C" int64_t test_dtvm(int n, int64_t input_amount) {
    // volatile prevents optimization
    volatile int64_t reserve_x = 1000000000000;
    volatile int64_t reserve_y = 4000000000000;
    volatile int64_t fee_numerator = 3;
    volatile int64_t fee_denominator = 1000;

    // pseudo-random seed prevents loop unrolling
    volatile int seed = n;
    int64_t total_output = 0;

    for (volatile int i = 0; i < n; i++) {
        // pseudo-random direction
        int direction = (i + seed) % 2;

        if (direction == 0) {
            int64_t output = get_output_amount_wasmvm(
                input_amount, reserve_x, reserve_y, fee_numerator, fee_denominator);
            total_output = checked_i64_add(total_output, output);
        } else {
            int64_t output = get_output_amount_wasmvm(
                input_amount, reserve_y, reserve_x, fee_numerator, fee_denominator);
            total_output = checked_i64_add(total_output, output);
        }
    }

    return total_output;
}
#endif // ENABLE_DTVM_TEST

int main(int argc, char *argv[]) {
    int n = std::stoi(argv[1]);
    int64_t input_amount = std::stoll(argv[2]);

#ifndef ENABLE_DTVM_TEST
    int64_t result = test_traditional(n, input_amount);
#else
    int64_t result = test_dtvm(n, input_amount);
#endif

    // printf("Result: %lld\n", result);

    return 0;
}
