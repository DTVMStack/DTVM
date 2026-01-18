# DTVM Testing Guide

This document describes the testing methodology for DTVM, including test frameworks, test categories, and how to run and add tests.

## Test Framework

DTVM uses **CTest** as the primary test framework, integrated with CMake for test discovery and execution.

## Build Configuration for Testing

Enable testing during CMake configuration:

```bash
# Basic Wasm test support
cmake -B build -DZEN_ENABLE_SPEC_TEST=ON

# With specific execution modes
cmake -B build \
  -DZEN_ENABLE_SPEC_TEST=ON \
  -DZEN_ENABLE_SINGLEPASS_JIT=ON

# With multipass JIT (requires LLVM 15)
cmake -B build \
  -DZEN_ENABLE_SPEC_TEST=ON \
  -DZEN_ENABLE_MULTIPASS_JIT=ON \
  -DLLVM_DIR=<llvm-path>/lib/cmake/llvm

# With address sanitizer for memory checking
cmake -B build \
  -DZEN_ENABLE_SPEC_TEST=ON \
  -DZEN_ENABLE_ASAN=ON

# EVM test support
cmake -B build \
  -DZEN_ENABLE_SPEC_TEST=ON \
  -DZEN_ENABLE_EVM=ON \
  -DZEN_ENABLE_MULTIPASS_JIT=ON \
  -DLLVM_DIR=<llvm-path>/lib/cmake/llvm

# EVM with evmone unit tests (requires EVMC library)
cmake -B build \
  -DZEN_ENABLE_EVM=ON \
  -DZEN_ENABLE_LIBEVM=ON \
  -DZEN_ENABLE_MULTIPASS_JIT=ON \
  -DLLVM_DIR=<llvm-path>/lib/cmake/llvm
```

### Key CMake Options

| Option | Description |
|--------|-------------|
| `ZEN_ENABLE_SPEC_TEST` | Enable WebAssembly specification tests |
| `ZEN_ENABLE_EVM` | Enable EVM bytecode support and tests |
| `ZEN_ENABLE_LIBEVM` | Build EVMC-compatible library for evmone tests |
| `ZEN_ENABLE_SINGLEPASS_JIT` | Enable singlepass JIT compiler |
| `ZEN_ENABLE_MULTIPASS_JIT` | Enable multipass JIT compiler (requires LLVM) |
| `ZEN_ENABLE_ASAN` | Enable address sanitizer |
| `ZEN_ENABLE_COVERAGE` | Enable coverage instrumentation |
| `ZEN_ENABLE_CPU_EXCEPTION` | Use CPU exceptions for bounds checking |
| `ZEN_ENABLE_CHECKED_ARITHMETIC` | Enable checked arithmetic operations |
| `ZEN_ENABLE_VIRTUAL_STACK` | Enable virtual stack implementation |

## Test Categories

### 1. WebAssembly Specification Tests

Located in `tests/wast/spec/`. Tests WebAssembly compliance.

```bash
# Run all spec tests with CTest
cd build && ctest --verbose

# Run with specific execution mode
./build/specUnitTests 0  # interpreter mode
./build/specUnitTests 1  # singlepass mode
./build/specUnitTests 2  # multipass mode

# Run single test case
./build/specUnitTests i32 0      # i32 tests in interpreter mode
./build/specUnitTests memory 1   # memory tests in singlepass mode
```

### 2. EVM Assembly Tests

Located in `tests/evm_asm/`. Tests individual EVM opcodes using EVM assembly.

**Test Format:**
- `.easm` files: EVM assembly input
- `.expected` files: Expected output in YAML format

```yaml
# Example .expected file
status: SUCCESS
stack:
  - "0x0000000000000000000000000000000000000000000000000000000000000005"
return_value: ""
```

**Preparation:** Convert EVM assembly to bytecode before running tests:
```bash
./tools/easm2bytecode.sh ./tests/evm_asm ./tests/evm_asm
```

Run with:
```bash
./build/evmInterpTests
```

### 3. EVM State Tests

Located in `tests/evm_spec_test/state_tests/`. Ethereum state transition tests from the official Ethereum test suite.

```bash
# Run all EVM state tests
./build/evmStateTests

# With specific revision
DTVM_TEST_REVISION=Cancun ./build/evmStateTests
```

**Note:** EVM state tests are excluded in multipass mode by default in CI due to gas metering differences.

### 4. Solidity Contract Tests

Located in `tests/evm_solidity/`. End-to-end contract tests with real Solidity contracts.

Test directories include:
- `basic/` - Basic contract operations
- `erc20/` - ERC-20 token tests
- `fibonacci/` - Computation tests
- `caller/`, `callee/` - Cross-contract calls
- `Factory/` - Contract factory patterns

**Preparation:** Compile Solidity contracts before running tests:
```bash
./tools/solc_batch_compile.sh
```

Run with:
```bash
./build/solidityContractTests
```

### 5. Evmone Unit Tests

Integration tests using the evmone test framework. Requires `ZEN_ENABLE_LIBEVM=ON`.

```bash
# Clone evmone test framework
git clone --depth 1 --recurse-submodules -b for_test https://github.com/DTVMStack/evmone.git

# Copy built libraries
mv build/lib/* evmone/
mv EVMOneUnitTestsRunList.txt evmone/

# Run tests
cd evmone && ./run_unittests.sh
```

### 6. EVM CLI Tests (evmrealsuite)

Run EVM tests through the CLI using the Python test runner:

```bash
python3 tools/run_evm_tests.py -r build/dtvm -m multipass --format evm
```

### 7. MIR Tests

Located in `tests/mir/`. Tests for Middle Intermediate Representation.

```bash
cd tests/mir && ./test_mir.sh
```

## Test Execution Modes

| Mode | Flag | Description |
|------|------|-------------|
| Interpreter | 0 | Direct bytecode interpretation |
| Singlepass | 1 | Single-pass JIT compilation |
| Multipass | 2 | LLVM-based multi-pass JIT |

## CI Test Suites

The CI system uses `.ci/run_test_suite.sh` with these test suite configurations:

| TestSuite | Description | Input Format |
|-----------|-------------|--------------|
| `microsuite` | Wasm specification tests | wasm |
| `evmtestsuite` | EVM ctest-based tests | evm |
| `evmrealsuite` | EVM CLI-based tests | evm |
| `evmonetestsuite` | Evmone unit tests | evm |

### Running with CI Script

```bash
# Set environment variables
export LLVM_SYS_150_PREFIX=/opt/llvm15
export LLVM_DIR=$LLVM_SYS_150_PREFIX/lib/cmake/llvm
export PATH=$LLVM_SYS_150_PREFIX/bin:$PATH

# Configure test parameters
export CMAKE_BUILD_TARGET=Debug    # or Release
export ENABLE_ASAN=true
export RUN_MODE=multipass          # interpreter, singlepass, multipass
export INPUT_FORMAT=evm            # wasm, evm
export ENABLE_LAZY=true
export ENABLE_MULTITHREAD=true
export ENABLE_GAS_METER=true       # EVM gas metering
export CPU_EXCEPTION_TYPE='check'  # 'cpu' or 'check'
export TestSuite=evmtestsuite

# Run
bash .ci/run_test_suite.sh
```

## Running Tests

### All Tests

```bash
cd build
ctest --verbose

# With EVM-specific arguments
SPEC_TESTS_ARGS="-m multipass --format evm" ctest --verbose
```

### Specific Test Binaries

```bash
# Wasm specification tests
./build/specUnitTests [test_name] <mode>

# EVM interpreter tests
./build/evmInterpTests

# EVM state tests
./build/evmStateTests

# Solidity contract tests
./build/solidityContractTests

# C API tests
./build/cApiTests

# Memory pool tests
./build/memPoolTests
```

### Filtering Tests

```bash
# Run tests matching pattern
ctest -R "evm*" --verbose

# Exclude tests matching pattern (e.g., skip state tests in multipass)
ctest -E "evmStateTests" --verbose
```

## Adding New Tests

### Adding WebAssembly Tests

1. Create a `.wast` file in `tests/wast/spec/` or a subdirectory
2. Follow the WebAssembly test format with assertions

```wast
;; tests/wast/spec/mytest/example.wast
(module
  (func (export "add") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.add))

(assert_return (invoke "add" (i32.const 1) (i32.const 2)) (i32.const 3))
```

3. Run: `./build/specUnitTests mytest/example <mode>`

### Adding EVM Assembly Tests

1. Create `.easm` file with EVM assembly
2. Create matching `.expected` file with expected results

```
# tests/evm_asm/my_opcode.easm
PUSH1 0x02
PUSH1 0x03
ADD
STOP
```

```yaml
# tests/evm_asm/my_opcode.expected
status: SUCCESS
stack:
  - "0x0000000000000000000000000000000000000000000000000000000000000005"
```

### Adding Unit Tests

1. Add test file in `src/tests/`
2. Update `src/tests/CMakeLists.txt`
3. Use the test fixtures from `evm_test_fixtures.h` or `test_utils.h`

```cpp
// src/tests/my_feature_tests.cpp
#include "test_utils.h"

TEST(MyFeature, BasicTest) {
  // Test implementation
  EXPECT_EQ(expected, actual);
}
```

## Coverage Testing

Generate coverage reports:

```bash
# Build with coverage
cmake -B build \
  -DZEN_ENABLE_SPEC_TEST=ON \
  -DZEN_ENABLE_COVERAGE=ON
cmake --build build

# Run tests
cd build && ./specUnitTests 1

# Generate report
lcov -c -d . -o coverage.info
lcov --remove coverage.info '/usr/include/' '*/build/_deps/*' -o coverage.info
genhtml coverage.info -o COVERAGE

# View report
python3 -m http.server 12345 --directory COVERAGE
```

## Test Environment Variables

| Variable | Description |
|----------|-------------|
| `DTVM_TEST_REVISION` | EVM revision for state tests (e.g., `Cancun`, `Shanghai`) |
| `ZEN_LOG_LEVEL` | Log level for test output |
| `SPEC_TESTS_ARGS` | Additional arguments passed to spec tests |
| `CMAKE_BUILD_TARGET` | Build type (`Debug` or `Release`) |
| `RUN_MODE` | Execution mode (`interpreter`, `singlepass`, `multipass`) |
| `INPUT_FORMAT` | Input format (`wasm` or `evm`) |
| `ENABLE_LAZY` | Enable lazy JIT compilation |
| `ENABLE_MULTITHREAD` | Enable multithreaded compilation |
| `ENABLE_GAS_METER` | Enable EVM gas metering |
| `CPU_EXCEPTION_TYPE` | Exception handling type (`cpu` or `check`) |

## Best Practices

1. **Test all execution modes**: Ensure tests pass in interpreter, singlepass, and multipass modes
2. **Test both input formats**: For changes affecting both Wasm and EVM, test both formats
3. **Add expected files**: For EVM tests, always include `.expected` output files
4. **Test edge cases**: Include overflow, underflow, and boundary conditions
5. **Document test purpose**: Add comments explaining what each test validates
6. **Keep tests focused**: One test should verify one specific behavior
7. **Use fixtures**: Reuse test helpers from `src/tests/` for consistency
8. **Run CI locally**: Use `.ci/run_test_suite.sh` to replicate CI behavior locally
