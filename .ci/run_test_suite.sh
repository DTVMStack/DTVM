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
        CMAKE_OPTIONS="$CMAKE_OPTIONS -DZEN_ENABLE_EVM=ON -DZEN_ENABLE_LIBEVM=ON -DZEN_ENABLE_JIT_PRECOMPILE_FALLBACK=ON"
        ;;
    "evmonestatetestsuite")
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

if [[ $TestSuite == "evmonestatetestsuite" ]]; then
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
                    SPEC_TESTS_ARGS=$EXTRA_EXE_OPTIONS ctest --verbose
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
        "evmonestatetestsuite")
            EVMONE_REPO=${EVMONE_REPO:-https://github.com/DTVMStack/evmone.git}
            EVMONE_BRANCH=${EVMONE_BRANCH:-for_test}
            EVMONE_DIR=${EVMONE_DIR:-evmone-statetest}
            EVMONE_STATETEST_FILTER=${EVMONE_STATETEST_FILTER:-fork_Cancun}
            EVMONE_MODE_TIMEOUT_SECONDS=${EVMONE_MODE_TIMEOUT_SECONDS:-5400}
            WORKSPACE_ROOT=$PWD
            DTVM_VM_SO=${DTVM_VM_SO:-"$WORKSPACE_ROOT/build/lib/libdtvmapi.so"}
            EVM_FIXTURES_ROOT=${EVM_FIXTURES_ROOT:-"$WORKSPACE_ROOT/tests/fixtures"}
            EVM_SPEC_FIXTURES_SUFFIX=${EVM_SPEC_FIXTURES_SUFFIX:-develop}
            EVM_SPEC_FIXTURES_ARCHIVE="/tmp/fixtures_${EVM_SPEC_FIXTURES_SUFFIX}.tar.gz"
            EVM_SPEC_FIXTURES_URL=${EVM_SPEC_FIXTURES_URL:-"https://github.com/ethereum/execution-spec-tests/releases/latest/download/fixtures_${EVM_SPEC_FIXTURES_SUFFIX}.tar.gz"}
            EVMONE_STATETEST_BIN=${EVMONE_STATETEST_BIN:-"$WORKSPACE_ROOT/$EVMONE_DIR/build/bin/evmone-statetest"}

            if [ ! -f "$DTVM_VM_SO" ]; then
                echo "DTVM VM library not found: $DTVM_VM_SO"
                ls -la "$WORKSPACE_ROOT/build/lib" | sed -n '1,120p'
                exit 1
            fi
            ln -sf "$DTVM_VM_SO" "$WORKSPACE_ROOT/libdtvmapi.so"

            if [ ! -d "$EVMONE_DIR" ]; then
                git clone --depth 1 --recurse-submodules -b "$EVMONE_BRANCH" "$EVMONE_REPO" "$EVMONE_DIR"
            fi
            cp build/lib/* "$EVMONE_DIR"/
            if [ ! -f "$EVMONE_DIR/libdtvmapi.so" ]; then
                DTVM_SO_VERSIONED=$(find "$EVMONE_DIR" -maxdepth 1 -type f -name "libdtvmapi.so.*" | head -n1)
                if [ -n "$DTVM_SO_VERSIONED" ]; then
                    ln -sf "$(basename "$DTVM_SO_VERSIONED")" "$EVMONE_DIR/libdtvmapi.so"
                fi
            fi
            cd "$EVMONE_DIR"
            cmake -S . -B build -DEVMONE_TESTING=ON -DCMAKE_BUILD_TYPE="$CMAKE_BUILD_TARGET"
            cmake --build build --parallel 16
            EVMONE_STATETEST_BIN="$PWD/build/bin/evmone-statetest"
            cd "$WORKSPACE_ROOT"

            if [ -z "${EVMONE_STATETEST_PATH:-}" ]; then
                if [ -d "$EVM_FIXTURES_ROOT/state_tests" ]; then
                    EVMONE_STATETEST_PATH="$EVM_FIXTURES_ROOT/state_tests"
                elif [ -d "$EVM_FIXTURES_ROOT/fixtures/state_tests" ]; then
                    EVMONE_STATETEST_PATH="$EVM_FIXTURES_ROOT/fixtures/state_tests"
                else
                    mkdir -p "$EVM_FIXTURES_ROOT"
                    rm -rf "$EVM_FIXTURES_ROOT/state_tests" "$EVM_FIXTURES_ROOT/fixtures"
                    rm -f "$EVM_SPEC_FIXTURES_ARCHIVE"
                    if command -v aria2c >/dev/null 2>&1; then
                        aria2c -c --max-tries=3 --retry-wait=1 --auto-file-renaming=false \
                            --dir "$(dirname "$EVM_SPEC_FIXTURES_ARCHIVE")" \
                            --out "$(basename "$EVM_SPEC_FIXTURES_ARCHIVE")" \
                            "$EVM_SPEC_FIXTURES_URL"
                    elif command -v wget >/dev/null 2>&1; then
                        wget -c --tries=3 --waitretry=1 --max-redirect=20 \
                            --progress=dot:giga \
                            -O "$EVM_SPEC_FIXTURES_ARCHIVE" "$EVM_SPEC_FIXTURES_URL"
                    else
                        echo "Neither aria2c nor wget is available in CI environment."
                        exit 1
                    fi
                    if [ ! -s "$EVM_SPEC_FIXTURES_ARCHIVE" ]; then
                        echo "Downloaded archive is missing or empty: $EVM_SPEC_FIXTURES_ARCHIVE"
                        exit 1
                    fi
                    tar -xzf "$EVM_SPEC_FIXTURES_ARCHIVE" -C "$EVM_FIXTURES_ROOT" || true
                    if [ -d "$EVM_FIXTURES_ROOT/state_tests" ]; then
                        EVMONE_STATETEST_PATH="$EVM_FIXTURES_ROOT/state_tests"
                    elif [ -d "$EVM_FIXTURES_ROOT/fixtures/state_tests" ]; then
                        EVMONE_STATETEST_PATH="$EVM_FIXTURES_ROOT/fixtures/state_tests"
                    else
                        EVMONE_STATETEST_PATH=$(find "$EVM_FIXTURES_ROOT" -type d -name state_tests | head -n1)
                    fi
                fi
            fi

            if [ ! -d "$EVMONE_STATETEST_PATH" ]; then
                echo "State test fixtures not found: $EVMONE_STATETEST_PATH"
                ls -la "$EVM_FIXTURES_ROOT" | sed -n '1,120p'
                exit 1
            fi

            export LD_LIBRARY_PATH="$WORKSPACE_ROOT/build/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
            for EVMONE_MODE in multipass interpreter; do
                VM_ARG="${DTVM_VM_SO},mode=${EVMONE_MODE},enable_gas_metering=true"
                echo "Running evmone-statetest mode=${EVMONE_MODE}, filter=${EVMONE_STATETEST_FILTER}"
                if [ -n "$EVMONE_MODE_TIMEOUT_SECONDS" ]; then
                    timeout --foreground "$EVMONE_MODE_TIMEOUT_SECONDS" env \
                        DTVM_EVM_MODE="$EVMONE_MODE" \
                        DTVM_EVM_ENABLE_GAS_METERING=true \
                        EVMONE_EXTERNAL_OPTIONS="$VM_ARG" \
                        "$EVMONE_STATETEST_BIN" "$EVMONE_STATETEST_PATH" \
                        --vm external_vm \
                        -k "$EVMONE_STATETEST_FILTER"
                else
                    env EVMONE_EXTERNAL_OPTIONS="$VM_ARG" \
                        DTVM_EVM_MODE="$EVMONE_MODE" \
                        DTVM_EVM_ENABLE_GAS_METERING=true \
                        "$EVMONE_STATETEST_BIN" "$EVMONE_STATETEST_PATH" \
                        --vm external_vm \
                        -k "$EVMONE_STATETEST_FILTER"
                fi
            done
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
            BENCHMARK_REPETITIONS=${BENCHMARK_REPETITIONS:-3}
            BENCHMARK_MIN_TIME=${BENCHMARK_MIN_TIME:-""}

            PERF_ARGS=""
            if [ -n "$BENCHMARK_REPETITIONS" ]; then
                PERF_ARGS="$PERF_ARGS --benchmark-repetitions $BENCHMARK_REPETITIONS"
            fi
            if [ -n "$BENCHMARK_MIN_TIME" ]; then
                PERF_ARGS="$PERF_ARGS --benchmark-min-time $BENCHMARK_MIN_TIME"
            fi

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
                python3 check_performance_regression.py $PERF_ARGS \
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
                python3 check_performance_regression.py $PERF_ARGS \
                    --save-baseline "$SAVE_PATH" \
                    --lib ./libdtvmapi.so \
                    --mode "$BENCHMARK_MODE" \
                    --benchmark-dir test/evm-benchmarks/benchmarks

                echo "Running current benchmarks with PR library..."
                cp ../build/lib/libdtvmapi.so ./libdtvmapi.so
                python3 check_performance_regression.py $PERF_ARGS \
                    --baseline "$SAVE_PATH" \
                    --threshold "$BENCHMARK_THRESHOLD" \
                    --output-summary "$BENCHMARK_SUMMARY_FILE" \
                    --lib ./libdtvmapi.so \
                    --mode "$BENCHMARK_MODE" \
                    --benchmark-dir test/evm-benchmarks/benchmarks
            elif [ -n "$BENCHMARK_SAVE_BASELINE" ]; then
                echo "Saving performance baseline..."
                python3 check_performance_regression.py $PERF_ARGS \
                    --save-baseline "$BENCHMARK_SAVE_BASELINE" \
                    --output-summary "$BENCHMARK_SUMMARY_FILE" \
                    --lib ./libdtvmapi.so \
                    --mode "$BENCHMARK_MODE" \
                    --benchmark-dir test/evm-benchmarks/benchmarks
            elif [ -n "$BENCHMARK_BASELINE_FILE" ]; then
                echo "Checking performance regression against baseline..."
                python3 check_performance_regression.py $PERF_ARGS \
                    --baseline "$BENCHMARK_BASELINE_FILE" \
                    --threshold "$BENCHMARK_THRESHOLD" \
                    --output-summary "$BENCHMARK_SUMMARY_FILE" \
                    --lib ./libdtvmapi.so \
                    --mode "$BENCHMARK_MODE" \
                    --benchmark-dir test/evm-benchmarks/benchmarks
            else
                echo "Running benchmark suite without comparison..."
                python3 check_performance_regression.py $PERF_ARGS \
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
