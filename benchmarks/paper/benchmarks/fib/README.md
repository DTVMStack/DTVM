# Standalone Fibonacci / MD5 Cases

Standalone cases used by the paper's compute-intensive and general-purpose Wasm comparisons (no contract hostapi dependency).

Source: experiment archive (original timings are in the paper's fib/overflow table).

## Files

| File | Description |
|------|-------------|
| `fib.sol` | iterative / tail-call-optimized Fibonacci Solidity contract source |
| `fib.wasm` | fib.sol compiled via the Solidity→Wasm toolchain (recursive-call path, args=30/40) |
| `fib.c.wasm` | C Fibonacci build artifact |
| `fib_no_contract.c.wasm` | contract-free C Fibonacci (the `args=30/40` rows in `fib&overflow.md`) |
| `md5.c` | MD5 C source (for compiling to wasm; artifact not archived) |

## Corresponding Paper Data

The `fib_no_contract.c.wasm (args=30/40)` and `fib.wasm (recursive, args=30/40)` rows in the paper's fib/overflow table.
