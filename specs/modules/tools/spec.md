# tools Module Specification

> Directory: `tools/`

## Boundaries and Responsibilities

The tools module provides **development helper scripts**, responsible for:

- **Code formatting**: Format check and auto-fix for C/C++, CMake, EVM ASM
- **EVM test tools**: EVM assembly to bytecode, EVM test runner, state root/MPT comparison
- **Solidity compilation**: Batch compile Solidity contracts to JSON
- **Static analysis**: Parallel clang-tidy, performance regression checks
- **Debugging aids**: GDB trace, CPU trace collection

This module does not include: Build system (CMake), test framework (gtest/ctest), core runtime logic.

## Core Concepts

### 1. Formatting (format.sh)

- **check**: Check CMake, C/C++, EVM ASM format; exit on failure
- **format**: Auto-format CMake (cmake-format), C/C++ (clang-format), EVM ASM (trim trailing space, trailing newline)
- **tidy-check**: clang-tidy naming checks (requires build directory)
- **Dependencies**: clang-format, clang-tidy, cmake-format

### 2. EVM Bytecode and Tests

| Script | Responsibility |
|--------|----------------|
| easm2bytecode.py | EVM assembly (.easm) → bytecode (.hex); opcode mapping table |
| easm2bytecode.sh | Batch invoke easm2bytecode.py |
| run_evm_tests.py | Drive dtvm CLI for evm_asm tests; stats succ/fail/ignore; supports --format evm, --mode |

### 3. Solidity Compilation

- **solc_batch_compile.sh**: Iterate `tests/evm_solidity/*/`; call solc on directory-name-matching `.sol`; output `contract.json` (bin, bin-runtime, ABI)
- **Dependencies**: solc, solc-select, jq

### 4. MPT / State Root Comparison

| Script | Responsibility |
|--------|----------------|
| mpt_compare_py.py | Python MPT state root; compare with C++ `mpt_compare_cpp` |
| compare_mpt.sh | Invoke MPT comparison tool |

### 5. Static Analysis and Performance

| Script | Responsibility |
|--------|----------------|
| run-clang-tidy.py | LLVM-style parallel clang-tidy; uses compile_commands.json |
| check_performance_regression.py | Run evmone benchmark; compare to baseline; configurable threshold (default 10%) |

### 6. Debugging and Tracing

| Script | Responsibility |
|--------|----------------|
| gdb_trace.py | GDB-driven dtvm; capture backtrace, CPU trace logs |
| collect_cpu_trace.py | Collect CPU trace data |
| bug_finder.py | Binary search for `GREEDY_FUNC_IDX_*` range that triggers exception (experimental) |

### 7. Miscellaneous

| Script | Responsibility |
|--------|----------------|
| function_selector.py | Compute Solidity function selector (keccak256 first 4 bytes) |
| requirements.txt | Python dependencies (PyYAML, rlp, eth-hash, trie, etc.) |

## External Contracts

| External Dependency | Use |
|---------------------|-----|
| clang-format | C/C++ formatting |
| clang-tidy | Static checks |
| cmake-format | CMake formatting |
| solc / solc-select | Solidity compilation |
| dtvm | EVM/WASM execution (run_evm_tests, bug_finder) |
| gdb | Debug tracing |
| Python 3 | pycryptodome, eth-hash, trie, rlp |

## Invariants and Permissions

- **Read-only preference**: Format scripts default to check; format writes
- **Paths**: Project root as working dir; relative paths to `tests/`, `build/`
- **Idempotent**: easm2bytecode, solc_batch_compile may be run repeatedly

## Compatibility Strategy

- **Toolchain version**: Depends on system/pipeline clang, solc, Python; `requirements.txt` specifies minimum pip dep versions
- **Platform**: format.sh, easm2bytecode.sh are bash; Python scripts cross-platform

## Cross-References

- [specs/testing/README.md](../../testing/README.md) — Test run instructions
- [docs/start.md](../../../docs/start.md) — Build and dependencies
- [specs/modules/tests/spec.md](../tests/spec.md) — Test module
