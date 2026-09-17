#!/bin/bash
set -e

# Same workload two ways: with the DTVM checked-arithmetic hostapi (dtvm build) vs plain wasm (wasmtime).


# build for dtvm
echo 'swap overflow perf test of dtvm'
em++ -std=c++17 -o perf_test_swap_pool_dtvm.wasm -O2 perf_test_swap_pool.cpp -DENABLE_DTVM_TEST -I . -s 'EXPORTED_FUNCTIONS=["_test_dtvm"]' --no-entry -Wl,--allow-undefined -s ERROR_ON_UNDEFINED_SYMBOLS=0 -s WASM=1 -s STANDALONE_WASM=0 -s PURE_WASI=1
# em++ -std=c++17 -o perf_test_swap_pool_dtvm.wasm -O1 perf_test_swap_pool.cpp -DENABLE_DTVM_TEST -I . -s 'EXPORTED_FUNCTIONS=["_test_dtvm"]' --no-entry -Wl,--allow-undefined -s ERROR_ON_UNDEFINED_SYMBOLS=0 -s WASM=1 -s STANDALONE_WASM=0 -s PURE_WASI=1
# em++ -std=c++17 -o perf_test_swap_pool_dtvm.wasm -O0 perf_test_swap_pool.cpp -DENABLE_DTVM_TEST -I . -s 'EXPORTED_FUNCTIONS=["_test_dtvm"]' --no-entry -Wl,--allow-undefined -s ERROR_ON_UNDEFINED_SYMBOLS=0 -s WASM=1 -s STANDALONE_WASM=0 -s PURE_WASI=1
# em++ -std=c++17 -o perf_test_swap_pool_dtvm.wasm -g perf_test_swap_pool.cpp -DENABLE_DTVM_TEST -I . -s 'EXPORTED_FUNCTIONS=["_test_dtvm"]' --no-entry -Wl,--allow-undefined -s ERROR_ON_UNDEFINED_SYMBOLS=0 -s WASM=1 -s STANDALONE_WASM=0 -s PURE_WASI=1
cmake --build build -j7
wasm2wat -o perf_test_swap_pool_dtvm.wat perf_test_swap_pool_dtvm.wasm
time ./build/dtvm -m multipass -f test_dtvm perf_test_swap_pool_dtvm.wasm --args 100000000 2000000

# build for non dtvm
echo 'swap overflow perf test of wasmtime'
em++ -std=c++17 -o perf_test_swap_pool_non_dtvm.wasm -O2 perf_test_swap_pool.cpp -I . -s 'EXPORTED_FUNCTIONS=["_test_traditional"]' --no-entry -Wl,--allow-undefined -s ERROR_ON_UNDEFINED_SYMBOLS=0 -s WASM=1 -s STANDALONE_WASM=0 -s PURE_WASI=1
# em++ -std=c++17 -o perf_test_swap_pool_non_dtvm.wasm -O1 perf_test_swap_pool.cpp -I . -s 'EXPORTED_FUNCTIONS=["_test_traditional"]' --no-entry -Wl,--allow-undefined -s ERROR_ON_UNDEFINED_SYMBOLS=0 -s WASM=1 -s STANDALONE_WASM=0 -s PURE_WASI=1
# em++ -std=c++17 -o perf_test_swap_pool_non_dtvm.wasm -O0 perf_test_swap_pool.cpp -I . -s 'EXPORTED_FUNCTIONS=["_test_traditional"]' --no-entry -Wl,--allow-undefined -s ERROR_ON_UNDEFINED_SYMBOLS=0 -s WASM=1 -s STANDALONE_WASM=0 -s PURE_WASI=1
# em++ -std=c++17 -o perf_test_swap_pool_non_dtvm.wasm -g perf_test_swap_pool.cpp -I . -s 'EXPORTED_FUNCTIONS=["_test_traditional"]' --no-entry -Wl,--allow-undefined -s ERROR_ON_UNDEFINED_SYMBOLS=0 -s WASM=1 -s STANDALONE_WASM=0 -s PURE_WASI=1
wasm2wat -o perf_test_swap_pool_non_dtvm.wat perf_test_swap_pool_non_dtvm.wasm
time /opt/wasmtime-v31.0.0-x86_64-linux/wasmtime --invoke test_traditional perf_test_swap_pool_non_dtvm.wasm 100000000 2000000

# build for wasmer
echo 'swap overflow perf test of wasmer'
em++ -std=c++17 -o perf_test_swap_pool_non_dtvm.wasm -O2 perf_test_swap_pool.cpp -I . -Wl,--allow-undefined -s ERROR_ON_UNDEFINED_SYMBOLS=0 -s WASM=1 -s STANDALONE_WASM=0 -s PURE_WASI=1
# em++ -std=c++17 -o perf_test_swap_pool_non_dtvm.wasm -O1 perf_test_swap_pool.cpp -I . -Wl,--allow-undefined -s ERROR_ON_UNDEFINED_SYMBOLS=0 -s WASM=1 -s STANDALONE_WASM=0 -s PURE_WASI=1
# em++ -std=c++17 -o perf_test_swap_pool_non_dtvm.wasm -O0 perf_test_swap_pool.cpp -I . -Wl,--allow-undefined -s ERROR_ON_UNDEFINED_SYMBOLS=0 -s WASM=1 -s STANDALONE_WASM=0 -s PURE_WASI=1
# em++ -std=c++17 -o perf_test_swap_pool_non_dtvm.wasm -g perf_test_swap_pool.cpp -I . -Wl,--allow-undefined -s ERROR_ON_UNDEFINED_SYMBOLS=0 -s WASM=1 -s STANDALONE_WASM=0 -s PURE_WASI=1
wasm2wat -o perf_test_swap_pool_non_dtvm.wat perf_test_swap_pool_non_dtvm.wasm
# wasmer --llvm , wasmer --cranelift, wasmer-singlepass
time wasmer run --llvm perf_test_swap_pool_non_dtvm.wasm -- 100000000 2000000
time wasmer run --cranelift perf_test_swap_pool_non_dtvm.wasm -- 100000000 2000000
time wasmer run --singlepass perf_test_swap_pool_non_dtvm.wasm -- 100000000 2000000
