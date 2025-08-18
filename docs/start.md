# Compilation

Recommended compilation environment is as follows:

- GCC >= 9.4.0
- CMake >= 3.16.3
- Ninja >= 1.10.0
- Python >= 3.8.10
- WABT >= 1.0.10
- llvm 15 (only for multipass JIT)

## Docker image

The fastest way to set up the compilation environment is to use a Docker image or build it based on docker/Dockerfile.

```
docker pull dtvmdev1/dtvm-dev-x64:main
```

## Interpreter

Interpreter mode is the current default execution mode. No specific CMake parameters are needed during compilation. Reference compilation commands are as follows:

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

Supported additional CMake parameters:

> `ZEN_ENABLE_ASAN`: Enable memory leak detection, disabled by default
> `ZEN_ENABLE_SPEC_TEST`: Enable support for spec test suite, disabled by default

## Singlepass JIT

To compile singlepass JIT, enable the CMake parameter `ZEN_ENABLE_SINGLEPASS_JIT`. Reference compilation commands:

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DZEN_ENABLE_SINGLEPASS_JIT=ON
cmake --build build
```

Supported additional CMake parameters:

> `ZEN_ENABLE_ASAN`: Enable memory leak detection, disabled by default
> `ZEN_ENABLE_JIT_BOUND_CHECK`: When enabled, singlepass JIT adds boundary check code for linear memory access during compilation, enabled by default
> `ZEN_ENABLE_JIT_LOGGING`: When enabled, singlepass JIT outputs asmjit logs, enabled by default in Debug mode, disabled in other modes
> `ZEN_ENABLE_SPEC_TEST`: Enable support for spec test suite, disabled by default

## Multipass JIT

Multipass JIT mode depends on LLVM 15. Prepare LLVM-15 before compiling multipass JIT:

```sh
wget <path-of-clang+llvm-15.0.0-x86_64-linux-gnu-rhel-8.4.tar.xz-in-github>
tar -xvf clang+llvm-15.0.0-x86_64-linux-gnu-rhel-8.4.tar.xz
export LLVM_DIR=/opt/clang+llvm-15.0.0-x86_64-linux-gnu-rhel-8.4/lib/cmake/llvm
export LLVM_SYS_150_PREFIX=/opt/clang+llvm-15.0.0-x86_64-linux-gnu-rhel-8.4
```

After compiling LLVM, use the following command to compile multipass JIT. The `ZEN_ENABLE_MULTIPASS_JIT` parameter enables multipass JIT compilation, and `LLVM_DIR` specifies the CMake module directory of the compiled LLVM:

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DZEN_ENABLE_MULTIPASS_JIT=ON -DLLVM_DIR=<llvm-project-upstream path>/build/lib/cmake/llvm
cmake --build build
```

> If the compiled LLVM is installed in the `/usr/lib` directory, you can omit the `LLVM_DIR` parameter, and CMake will automatically find the LLVM CMake module directory

<br/>

Supported additional CMake parameters:

> `ZEN_ENABLE_ASAN`: Enable memory leak detection, disabled by default
> `ZEN_ENABLE_JIT_LOGGING`: When enabled, multipass JIT outputs IR and assembly during compilation, enabled by default in Debug mode, disabled in other modes
> `ZEN_ENABLE_SPEC_TEST`: Enable support for spec test suite, disabled by default

## Testing Spec Cases

**You must enable the CMake parameter `ZEN_ENABLE_SPEC_TEST` during compilation to run tests**

```sh
cd build

ctest --verbose

# or

./build/specUnitTests 0

./build/specUnitTests 1

./build/specUnitTests 2
```

0, 1, 2 represent interpreter, singlepass, and multipass modes respectively

## Testing a Single Test

When testing a single test, specify the test case name as a parameter (excluding the `.wast` suffix)

```sh
./build/specUnitTests i32 0

./build/specUnitTests i32 1

./build/specUnitTests i32 2
```

> A more standard command is `./build/specUnitTests mvp/i32 0`

## Testing Custom Wast Cases

When testing custom wast cases, it is recommended to create a custom directory under `tests/spec`, then place custom cases in that directory. Assuming the relative path of the custom case is `tests/spec/my/demo.wast`, then execute:

```sh
./build/specUnitTests my/demo <0/1/2>
```

## Testing MIR Cases

### lit Command Installation

```sh
pip install lit
```

### Testing

Execute the test script:

```sh
cd tests/compiler/ && ./test_mir.sh
```

Manual testing:

```sh
lit mir/add.ir --no-indirectly-run-check

# or

lit mir/add.ir mir/sub.ir --no-indirectly-run-check
```

## Running Wasm Files

```sh
dtvm -f add i32.wasm --args "2" "3"

dtvm i32.wasm --repl
webassembly>add 1 1
0x2:i32

dtvm --dir . -f add i32.wasm --args "3" "1"
0x4:i32

dtvm --mode interpreter i32.wasm

dtvm --mode singlepass i32.wasm

dtvm --mode multipass i32.wasm
```

-f      Specify the function name to test
--args  Specify parameters, preferably quoted with ""
--repl  Enter REPL mode
--dir   Specify directory
--mode  Specify mode to run, currently supported modes include: interpreter / singlepass / multipass
