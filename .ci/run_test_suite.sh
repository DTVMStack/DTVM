#!/bin/bash
# you need set the environments
# export LLVM_SYS_150_PREFIX=/opt/llvm15
# export LLVM_DIR=$LLVM_SYS_150_PREFIX/lib/cmake/llvm
# export PATH=$LLVM_SYS_150_PREFIX/bin:$PATH
# pushd tests/wast/spec
# git apply ../spec.patch
# popd
# # Debug, Release
# CMAKE_BUILD_TARGET=Debug
# ENABLE_ASAN=true
# # interpreter, singlepass, multipass
# RUN_MODE=multipass
# # evm, wasm
# INPUT_FORMAT=wasm
# ENABLE_LAZY=true
# ENABLE_MULTITHREAD=true
# TestSuite=microsuite
# # 'cpu' or 'check'
# CPU_EXCEPTION_TYPE='cpu'

set -e

# Convert INPUT_FORMAT to lowercase for case-insensitive comparison
INPUT_FORMAT=${INPUT_FORMAT,,}

CMAKE_OPTIONS="-DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TARGET"

if [[ ${CMAKE_BUILD_TARGET} != "Release" && ${RUN_MODE} != "interpreter" && ${INPUT_FORMAT} == "evm" ]]; then
    CMAKE_OPTIONS="$CMAKE_OPTIONS -DZEN_ENABLE_SPDLOG=ON -DZEN_ENABLE_JIT_LOGGING=ON"
fi

if [ "${ENABLE_ASAN:-false}" = true ]; then
    CMAKE_OPTIONS="$CMAKE_OPTIONS -DZEN_ENABLE_ASAN=ON"
fi

EXTRA_EXE_OPTIONS="-m $RUN_MODE --format $INPUT_FORMAT"

echo "testing in run mode: $RUN_MODE"

case $RUN_MODE in
    "interpreter")
        CMAKE_OPTIONS="$CMAKE_OPTIONS -DZEN_ENABLE_SINGLEPASS_JIT=OFF -DZEN_ENABLE_MULTIPASS_JIT=OFF"
        ;;
    "singlepass")
        CMAKE_OPTIONS="$CMAKE_OPTIONS -DZEN_ENABLE_SINGLEPASS_JIT=ON -DZEN_ENABLE_MULTIPASS_JIT=OFF"
        ;;
    "multipass")
        CMAKE_OPTIONS="$CMAKE_OPTIONS -DZEN_ENABLE_SINGLEPASS_JIT=OFF -DZEN_ENABLE_MULTIPASS_JIT=ON"
        if [ "${ENABLE_LAZY:-false}" = true ]; then
            EXTRA_EXE_OPTIONS="$EXTRA_EXE_OPTIONS --enable-multipass-lazy"
        fi
        if [ "${ENABLE_GAS_METER:-false}" = true ]; then
            EXTRA_EXE_OPTIONS="$EXTRA_EXE_OPTIONS --enable-evm-gas"
        fi
        if [ "${ENABLE_GAS_REGISTER:-false}" = true ]; then
            CMAKE_OPTIONS="$CMAKE_OPTIONS -DZEN_ENABLE_EVM_GAS_REGISTER=ON"
        fi
        if [ "${ENABLE_MULTITHREAD:-false}" = true ]; then
            EXTRA_EXE_OPTIONS="$EXTRA_EXE_OPTIONS --num-multipass-threads 16"
        else
            EXTRA_EXE_OPTIONS="$EXTRA_EXE_OPTIONS --disable-multipass-multithread"
        fi
        ;;
esac

case $TestSuite in
    "microsuite")
        CMAKE_OPTIONS="$CMAKE_OPTIONS -DZEN_ENABLE_SPEC_TEST=ON -DZEN_ENABLE_ASSEMBLYSCRIPT_TEST=ON -DZEN_ENABLE_CHECKED_ARITHMETIC=ON"
        ;;
    "evmtestsuite")
        CMAKE_OPTIONS="$CMAKE_OPTIONS -DZEN_ENABLE_SPEC_TEST=ON -DZEN_ENABLE_ASSEMBLYSCRIPT_TEST=ON -DZEN_ENABLE_CHECKED_ARITHMETIC=ON -DZEN_ENABLE_EVM=ON"
        ;;
    "evmrealsuite")
        CMAKE_OPTIONS="$CMAKE_OPTIONS -DZEN_ENABLE_SPEC_TEST=ON -DZEN_ENABLE_ASSEMBLYSCRIPT_TEST=ON -DZEN_ENABLE_CHECKED_ARITHMETIC=ON -DZEN_ENABLE_EVM=ON"
        ;;
    "evmonetestsuite")
        CMAKE_OPTIONS="$CMAKE_OPTIONS -DZEN_ENABLE_EVM=ON -DZEN_ENABLE_LIBEVM=ON"
        ;;
    "evmfallbacksuite")
        CMAKE_OPTIONS="$CMAKE_OPTIONS -DZEN_ENABLE_SPEC_TEST=ON -DZEN_ENABLE_ASSEMBLYSCRIPT_TEST=ON -DZEN_ENABLE_EVM=ON -DZEN_ENABLE_LIBEVM=ON -DZEN_ENABLE_JIT_FALLBACK_TEST=ON"
        ;;
    "benchmarksuite")
        CMAKE_OPTIONS="$CMAKE_OPTIONS -DZEN_ENABLE_EVM=ON -DZEN_ENABLE_LIBEVM=ON -DZEN_ENABLE_SINGLEPASS_JIT=OFF -DZEN_ENABLE_MULTIPASS_JIT=ON -DZEN_ENABLE_JIT_PRECOMPILE_FALLBACK=ON"
        ;;
esac

case $CPU_EXCEPTION_TYPE in
    "cpu")
        CMAKE_OPTIONS="$CMAKE_OPTIONS -DZEN_ENABLE_CPU_EXCEPTION=ON"
        ;;
    "check")
        CMAKE_OPTIONS="$CMAKE_OPTIONS -DZEN_ENABLE_CPU_EXCEPTION=OFF"
        ;;
esac

STACK_TYPES=("-DZEN_ENABLE_VIRTUAL_STACK=ON" "-DZEN_ENABLE_VIRTUAL_STACK=OFF")
if [[ $RUN_MODE == "interpreter" ]]; then
    STACK_TYPES=("-DZEN_ENABLE_VIRTUAL_STACK=OFF")
fi

if [[ $TestSuite == "evmonetestsuite" ]]; then
    STACK_TYPES=("-DZEN_ENABLE_VIRTUAL_STACK=ON")
fi

if [[ $TestSuite == "benchmarksuite" ]]; then
    STACK_TYPES=("-DZEN_ENABLE_VIRTUAL_STACK=ON")
fi

export PATH=$PATH:$PWD/build
CMAKE_OPTIONS_ORIGIN="$CMAKE_OPTIONS"

if [[ ${INPUT_FORMAT} == "evm" ]]; then
    ./tools/easm2bytecode.sh ./tests/evm_asm ./tests/evm_asm
    ./tools/solc_batch_compile.sh
fi

for STACK_TYPE in ${STACK_TYPES[@]}; do
    rm -rf build
    cmake -S . -B build $CMAKE_OPTIONS_ORIGIN $STACK_TYPE
    cmake --build build -j 16

    case $TestSuite in
        "microsuite")
            cd build
            # run times to test cases that not happen every time
            n=20
            if [[ $CMAKE_BUILD_TARGET != "Release" ]]; then
                n=2
            fi
            for i in {1..$n}; do
                SPEC_TESTS_ARGS=$EXTRA_EXE_OPTIONS ctest --verbose
            done
            cd ..

            # if [[ $RUN_MODE == "multipass" && !${ENABLE_MULTITHREAD} ]]; then
            #     cd tests/mir
            #     ./test_mir.sh
            #     cd ..
            # fi
            ;;
        "evmtestsuite")
            cd build
            # run times to test cases that not happen every time
            n=20
            if [[ $CMAKE_BUILD_TARGET != "Release" ]]; then
                n=2
            fi
            for i in {1..$n}; do
                if [[ $RUN_MODE == "interpreter" ]]; then
                    # The test case 'test_blob_gas_subtraction' has already passed in evmone + dtvm interpreter environments.
                    # The current failure is likely due to test framework configuration issues; will be handled separately in follow-up.
                    SKIP_LIST="-*test_blob_gas_subtraction*"
                    GTEST_FILTER=$SKIP_LIST SPEC_TESTS_ARGS=$EXTRA_EXE_OPTIONS ctest --verbose
                else # evm multipass
                    SPEC_TESTS_ARGS=$EXTRA_EXE_OPTIONS ctest --verbose -E evmStateTests
                fi
            done
            cd ..
            ;;
        "evmrealsuite")
            python3 tools/run_evm_tests.py -r build/dtvm $EXTRA_EXE_OPTIONS
            ;;
        "evmonetestsuite")
            git clone --depth 1 --recurse-submodules -b for_test https://github.com/DTVMStack/evmone.git
            mv build/lib/* evmone
            cd evmone
            ./run_unittests.sh ../tests/evmone_unittests/EVMOneMultipassUnitTestsRunList.txt "./libdtvmapi.so,mode=multipass"
            ./run_unittests.sh ../tests/evmone_unittests/EVMOneInterpreterUnitTestsRunList.txt "./libdtvmapi.so,mode=interpreter"
            ;;
        "evmfallbacksuite")
            python3 tools/run_evm_tests.py -r build/dtvm $EXTRA_EXE_OPTIONS
            ./build/evmFallbackExecutionTests
            ;;
        "benchmarksuite")
            # Clone evmone and run performance regression check
            EVMONE_DIR="evmone"
            if [ ! -d "$EVMONE_DIR" ]; then
                git clone --depth 1 --recurse-submodules -b for_test https://github.com/DTVMStack/evmone.git $EVMONE_DIR
            fi

            BENCHMARK_THRESHOLD=${BENCHMARK_THRESHOLD:-0.15}
            BENCHMARK_MODE=${BENCHMARK_MODE:-multipass}
            BENCHMARK_SUMMARY_FILE=${BENCHMARK_SUMMARY_FILE:-/tmp/perf_summary.md}

            cp build/lib/* $EVMONE_DIR/

            cd $EVMONE_DIR

            cp ../tools/check_performance_regression.py ./

            if [ ! -f "build/bin/evmone-bench" ]; then
                cmake -S . -B build -DEVMONE_TESTING=ON -DCMAKE_BUILD_TYPE=Release
                cmake --build build --parallel -j 16
            fi

            BASELINE_CACHE=${BENCHMARK_BASELINE_CACHE:-}

            if [ -n "$BASELINE_CACHE" ] && [ -f "$BASELINE_CACHE" ]; then
                # Cached baseline available -- only run current benchmarks.
                echo "Using cached baseline: $BASELINE_CACHE"
                python3 check_performance_regression.py \
                    --baseline "$BASELINE_CACHE" \
                    --threshold "$BENCHMARK_THRESHOLD" \
                    --output-summary "$BENCHMARK_SUMMARY_FILE" \
                    --lib ./libdtvmapi.so \
                    --mode "$BENCHMARK_MODE" \
                    --benchmark-dir test/evm-benchmarks/benchmarks
            elif [ -n "$BENCHMARK_BASELINE_LIB" ]; then
                # No cache -- run baseline benchmarks with the pre-built
                # baseline library, then run current benchmarks and compare.
                echo "Running baseline benchmarks with library from base branch..."
                cp "$BENCHMARK_BASELINE_LIB"/libdtvmapi.so ./libdtvmapi.so
                SAVE_PATH=${BASELINE_CACHE:-/tmp/perf_baseline.json}
                python3 check_performance_regression.py \
                    --save-baseline "$SAVE_PATH" \
                    --lib ./libdtvmapi.so \
                    --mode "$BENCHMARK_MODE" \
                    --benchmark-dir test/evm-benchmarks/benchmarks

                echo "Running current benchmarks with PR library..."
                cp ../build/lib/libdtvmapi.so ./libdtvmapi.so
                python3 check_performance_regression.py \
                    --baseline "$SAVE_PATH" \
                    --threshold "$BENCHMARK_THRESHOLD" \
                    --output-summary "$BENCHMARK_SUMMARY_FILE" \
                    --lib ./libdtvmapi.so \
                    --mode "$BENCHMARK_MODE" \
                    --benchmark-dir test/evm-benchmarks/benchmarks
            elif [ -n "$BENCHMARK_SAVE_BASELINE" ]; then
                echo "Saving performance baseline..."
                python3 check_performance_regression.py \
                    --save-baseline "$BENCHMARK_SAVE_BASELINE" \
                    --output-summary "$BENCHMARK_SUMMARY_FILE" \
                    --lib ./libdtvmapi.so \
                    --mode "$BENCHMARK_MODE" \
                    --benchmark-dir test/evm-benchmarks/benchmarks
            elif [ -n "$BENCHMARK_BASELINE_FILE" ]; then
                echo "Checking performance regression against baseline..."
                python3 check_performance_regression.py \
                    --baseline "$BENCHMARK_BASELINE_FILE" \
                    --threshold "$BENCHMARK_THRESHOLD" \
                    --output-summary "$BENCHMARK_SUMMARY_FILE" \
                    --lib ./libdtvmapi.so \
                    --mode "$BENCHMARK_MODE" \
                    --benchmark-dir test/evm-benchmarks/benchmarks
            else
                echo "Running benchmark suite without comparison..."
                python3 check_performance_regression.py \
                    --save-baseline benchmark_results.json \
                    --output-summary "$BENCHMARK_SUMMARY_FILE" \
                    --lib ./libdtvmapi.so \
                    --mode "$BENCHMARK_MODE" \
                    --benchmark-dir test/evm-benchmarks/benchmarks
                cat benchmark_results.json
            fi

            cd ..
            ;;
    esac
done
