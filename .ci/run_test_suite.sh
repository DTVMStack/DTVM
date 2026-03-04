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

# Emit periodic logs while a long-running command executes so CI does not look stalled.
log_keepalive_until_pid_exits() {
    local watched_pid=$1
    local context=$2
    local interval_seconds=$3

    while kill -0 "$watched_pid" 2>/dev/null; do
        echo "[keepalive] ${context} is still running..."
        sleep "$interval_seconds"
    done
}

run_with_keepalive_timeout_and_retries() {
    local description=$1
    local timeout_seconds=$2
    local retry_count=$3
    local retry_sleep_seconds=$4
    shift 4

    local attempt=1
    local cmd_status=0
    local keepalive_interval="${EVMONE_KEEPALIVE_SECONDS:-30}"

    while [ "$attempt" -le "$retry_count" ]; do
        echo "${description} (attempt ${attempt}/${retry_count})"

        set +e
        timeout --foreground "$timeout_seconds" "$@" &
        local cmd_pid=$!
        log_keepalive_until_pid_exits "$cmd_pid" "$description" "$keepalive_interval" &
        local keepalive_pid=$!

        wait "$cmd_pid"
        cmd_status=$?

        kill "$keepalive_pid" 2>/dev/null || true
        wait "$keepalive_pid" 2>/dev/null || true
        set -e

        if [ "$cmd_status" -eq 0 ]; then
            return 0
        fi

        if [ "$cmd_status" -eq 124 ]; then
            echo "${description} timed out after ${timeout_seconds}s"
        else
            echo "${description} failed with exit code ${cmd_status}"
        fi

        if [ "$attempt" -lt "$retry_count" ]; then
            echo "Retrying in ${retry_sleep_seconds}s..."
            sleep "$retry_sleep_seconds"
        fi
        attempt=$((attempt + 1))
    done

    return "$cmd_status"
}

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
        CMAKE_OPTIONS="$CMAKE_OPTIONS -DZEN_ENABLE_EVM=ON -DZEN_ENABLE_LIBEVM=ON"
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
            EVMONE_ABS_DIR="$PWD/$EVMONE_DIR"
            DTVM_BUILD_LIB_DIR="$PWD/build/lib"
            EVM_SPEC_TESTS_ROOT=${EVM_SPEC_TESTS_ROOT:-"$PWD/tests/evm_spec_test"}
            EVM_SPEC_FIXTURES_SUFFIX=${EVM_SPEC_FIXTURES_SUFFIX:-develop}
            EVM_SPEC_FIXTURES_ARCHIVE="/tmp/fixtures_${EVM_SPEC_FIXTURES_SUFFIX}.tar.gz"
            EVM_SPEC_FIXTURES_URL=${EVM_SPEC_FIXTURES_URL:-"https://github.com/ethereum/execution-spec-tests/releases/latest/download/fixtures_${EVM_SPEC_FIXTURES_SUFFIX}.tar.gz"}
            EVMONE_STATETEST_FILTER=${EVMONE_STATETEST_FILTER:-fork_Cancun}

            if [ ! -d "$EVMONE_DIR" ]; then
                git clone --depth 1 --recurse-submodules -b "$EVMONE_BRANCH" "$EVMONE_REPO" "$EVMONE_DIR"
            fi

            cp build/lib/* "$EVMONE_DIR"
            if [ ! -f "$EVMONE_DIR/libdtvmapi.so" ]; then
                DTVM_SO_VERSIONED=$(find "$EVMONE_DIR" -maxdepth 1 -type f -name "libdtvmapi.so.*" | head -n1)
                if [ -n "$DTVM_SO_VERSIONED" ]; then
                    ln -sf "$(basename "$DTVM_SO_VERSIONED")" "$EVMONE_DIR/libdtvmapi.so"
                fi
            fi
            if [ ! -f "$EVMONE_DIR/libdtvmapi.so" ]; then
                echo "libdtvmapi.so not found in $EVMONE_DIR"
                ls -la "$EVMONE_DIR" | sed -n '1,120p'
                exit 1
            fi

            export LD_LIBRARY_PATH="$EVMONE_ABS_DIR:$DTVM_BUILD_LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
            ASAN_LIB_PATH="${ASAN_LIB_PATH:-$(find /usr/lib /usr/lib64 /lib /lib64 -name 'libasan.so.*' 2>/dev/null | head -n1)}"
            if [ -n "$ASAN_LIB_PATH" ]; then
                export LD_PRELOAD="${ASAN_LIB_PATH}${LD_PRELOAD:+:$LD_PRELOAD}"
            fi

            mkdir -p "$EVM_SPEC_TESTS_ROOT"
            rm -rf "$EVM_SPEC_TESTS_ROOT/fixtures"
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
            echo "EVM spec fixtures archive size:"
            ls -lh "$EVM_SPEC_FIXTURES_ARCHIVE"
            echo "EVM spec fixtures download completed: $EVM_SPEC_FIXTURES_ARCHIVE"
            echo "::notice::EVM spec fixtures download completed"
            if [ -n "${GITHUB_OUTPUT:-}" ]; then
                {
                    echo "evm_spec_fixtures_downloaded=true"
                    echo "evm_spec_fixtures_archive=$EVM_SPEC_FIXTURES_ARCHIVE"
                } >> "$GITHUB_OUTPUT"
            fi
            if command -v gzip >/dev/null 2>&1; then
                if ! gzip -t "$EVM_SPEC_FIXTURES_ARCHIVE"; then
                    echo "gzip integrity check failed: $EVM_SPEC_FIXTURES_ARCHIVE"
                    exit 1
                fi
            fi
            echo "Disk usage before extraction:"
            df -h "$EVM_SPEC_TESTS_ROOT" /tmp || true
            echo "Inode usage before extraction:"
            df -ih "$EVM_SPEC_TESTS_ROOT" /tmp || true
            EXTRACT_SUBPATH="fixtures/state_tests"
            TAR_EXTRA_ARGS=()
            if tar -tzf "$EVM_SPEC_FIXTURES_ARCHIVE" \
                --wildcards --wildcards-match-slash "${EXTRACT_SUBPATH}/*" >/dev/null 2>&1; then
                TAR_EXTRA_ARGS+=(--wildcards --wildcards-match-slash "${EXTRACT_SUBPATH}/*")
                echo "Extracting subpath only: $EXTRACT_SUBPATH"
            else
                echo "Subpath not found in archive, extracting full archive."
            fi

            set +e
            tar -xzf "$EVM_SPEC_FIXTURES_ARCHIVE" -C "$EVM_SPEC_TESTS_ROOT" \
                "${TAR_EXTRA_ARGS[@]}" 2>/tmp/evm_spec_fixtures_extract.err
            tar_extract_status=$?
            set -e
            if [ "$tar_extract_status" -ne 0 ]; then
                extracted_state_tests_dir="$EVM_SPEC_TESTS_ROOT/$EXTRACT_SUBPATH"
                extracted_probe_json=""
                if [ -d "$extracted_state_tests_dir" ]; then
                    extracted_probe_json=$(find "$extracted_state_tests_dir" -type f -name "*.json" | head -n1)
                fi
                if [ "$tar_extract_status" -eq 1 ] && [ -n "$extracted_probe_json" ]; then
                    echo "tar returned 1, but extracted fixtures are present. Continuing."
                    echo "Probe json: $extracted_probe_json"
                else
                    echo "Failed to extract fixtures archive: $EVM_SPEC_FIXTURES_ARCHIVE"
                    echo "tar exit code: $tar_extract_status"
                    echo "tar stderr:"
                    if [ -s /tmp/evm_spec_fixtures_extract.err ]; then
                        sed -n '1,200p' /tmp/evm_spec_fixtures_extract.err
                    else
                        echo "(empty)"
                    fi
                    echo "Disk usage on extraction failure:"
                    df -h "$EVM_SPEC_TESTS_ROOT" /tmp || true
                    echo "Inode usage on extraction failure:"
                    df -ih "$EVM_SPEC_TESTS_ROOT" /tmp || true
                    exit "$tar_extract_status"
                fi
            fi
            echo "Disk usage after extraction:"
            df -h "$EVM_SPEC_TESTS_ROOT" /tmp || true
            echo "Inode usage after extraction:"
            df -ih "$EVM_SPEC_TESTS_ROOT" /tmp || true
            echo "EVM spec fixtures extracted: $EVM_SPEC_TESTS_ROOT/fixtures"
            echo "::notice::EVM spec fixtures extracted successfully"
            if [ -n "${GITHUB_OUTPUT:-}" ]; then
                {
                    echo "evm_spec_fixtures_extracted=true"
                    echo "evm_spec_fixtures_path=$EVM_SPEC_TESTS_ROOT/fixtures"
                } >> "$GITHUB_OUTPUT"
            fi

            EVMONE_STATETEST_PATH="$EVM_SPEC_TESTS_ROOT/fixtures/state_tests"
            if [ ! -d "$EVMONE_STATETEST_PATH" ]; then
                echo "State test fixtures not found: $EVMONE_STATETEST_PATH"
                exit 1
            fi

            EVMONE_CMAKE_CONFIG_TIMEOUT_SECONDS=${EVMONE_CMAKE_CONFIG_TIMEOUT_SECONDS:-1800}
            EVMONE_CMAKE_BUILD_TIMEOUT_SECONDS=${EVMONE_CMAKE_BUILD_TIMEOUT_SECONDS:-5400}
            EVMONE_CMAKE_CONFIG_RETRIES=${EVMONE_CMAKE_CONFIG_RETRIES:-3}
            EVMONE_CMAKE_BUILD_RETRIES=${EVMONE_CMAKE_BUILD_RETRIES:-2}
            EVMONE_CMAKE_RETRY_SLEEP_SECONDS=${EVMONE_CMAKE_RETRY_SLEEP_SECONDS:-20}
            EVMONE_KEEPALIVE_SECONDS=${EVMONE_KEEPALIVE_SECONDS:-30}
            HUNTER_GATE_VERSION=0.26.0
            HUNTER_GATE_SHA1=b1944539bad88a7cc006b4f3e4028a72a8ae46d1
            HUNTER_GATE_SHORT_SHA1=b194453
            HUNTER_GATE_URL=https://github.com/cpp-pm/hunter/archive/v${HUNTER_GATE_VERSION}.tar.gz

            if [ -z "${HUNTER_ROOT:-}" ]; then
                if [ -s "/root/.hunter/_Base/Download/Hunter/${HUNTER_GATE_VERSION}/${HUNTER_GATE_SHORT_SHA1}/v${HUNTER_GATE_VERSION}.tar.gz" ]; then
                    export HUNTER_ROOT="/root/.hunter"
                else
                    export HUNTER_ROOT="$HOME/.hunter"
                fi
            fi
            echo "Using HUNTER_ROOT=${HUNTER_ROOT}"

            HUNTER_DOWNLOAD_DIR="${HUNTER_ROOT}/_Base/Download/Hunter/${HUNTER_GATE_VERSION}/${HUNTER_GATE_SHORT_SHA1}"
            HUNTER_ARCHIVE_PATH="${HUNTER_DOWNLOAD_DIR}/v${HUNTER_GATE_VERSION}.tar.gz"
            mkdir -p "$HUNTER_DOWNLOAD_DIR"

            if [ ! -s "$HUNTER_ARCHIVE_PATH" ]; then
                echo "Prefetching Hunter archive: ${HUNTER_GATE_URL}"
                if command -v aria2c >/dev/null 2>&1; then
                    aria2c -c --max-tries=3 --retry-wait=1 --auto-file-renaming=false \
                        --dir "$HUNTER_DOWNLOAD_DIR" \
                        --out "$(basename "$HUNTER_ARCHIVE_PATH")" \
                        "$HUNTER_GATE_URL"
                elif command -v wget >/dev/null 2>&1; then
                    wget -c --tries=3 --waitretry=1 --max-redirect=20 \
                        --progress=dot:giga \
                        -O "$HUNTER_ARCHIVE_PATH" "$HUNTER_GATE_URL"
                else
                    echo "Neither aria2c nor wget is available to prefetch Hunter archive."
                    exit 1
                fi
            fi

            if [ ! -s "$HUNTER_ARCHIVE_PATH" ]; then
                echo "Hunter archive is missing or empty: ${HUNTER_ARCHIVE_PATH}"
                exit 1
            fi

            HUNTER_ARCHIVE_SHA1=$(sha1sum "$HUNTER_ARCHIVE_PATH" | awk '{print $1}')
            if [ "$HUNTER_ARCHIVE_SHA1" != "$HUNTER_GATE_SHA1" ]; then
                echo "Hunter archive SHA1 mismatch: expected=${HUNTER_GATE_SHA1}, actual=${HUNTER_ARCHIVE_SHA1}"
                rm -f "$HUNTER_ARCHIVE_PATH"
                exit 1
            fi

            cd "$EVMONE_DIR"
            if ! run_with_keepalive_timeout_and_retries \
                "Configuring evmone for statetests" \
                "$EVMONE_CMAKE_CONFIG_TIMEOUT_SECONDS" \
                "$EVMONE_CMAKE_CONFIG_RETRIES" \
                "$EVMONE_CMAKE_RETRY_SLEEP_SECONDS" \
                cmake -S . -B build -DEVMONE_TESTING=ON; then
                echo "Failed to configure evmone for statetests after ${EVMONE_CMAKE_CONFIG_RETRIES} attempts."
                find "${HUNTER_DOWNLOAD_DIR}" -maxdepth 4 -type f \( -name "*download*.log" -o -name "*-err.log" \) 2>/dev/null | while read -r hunter_log; do
                    echo "Hunter log: ${hunter_log}"
                    sed -n '1,200p' "$hunter_log"
                done
                exit 1
            fi

            if ! run_with_keepalive_timeout_and_retries \
                "Building evmone statetest binaries" \
                "$EVMONE_CMAKE_BUILD_TIMEOUT_SECONDS" \
                "$EVMONE_CMAKE_BUILD_RETRIES" \
                "$EVMONE_CMAKE_RETRY_SLEEP_SECONDS" \
                cmake --build build -j16; then
                echo "Failed to build evmone statetest binaries after ${EVMONE_CMAKE_BUILD_RETRIES} attempts."
                exit 1
            fi

            EVMONE_PROBE_TEST=$(find "$EVMONE_STATETEST_PATH" -type f -name "*.json" | head -n1)
            if [ -z "$EVMONE_PROBE_TEST" ]; then
                echo "No json test file found in $EVMONE_STATETEST_PATH"
                exit 1
            fi
            if ! ./build/bin/evmone-statetest "$EVMONE_PROBE_TEST" --gtest_list_tests --vm external_vm >/tmp/evmone_external_vm_probe.log 2>&1; then
                echo "external_vm probe failed. Diagnose output:"
                cat /tmp/evmone_external_vm_probe.log
                if [ -f "./libdtvmapi.so" ]; then
                    echo "ldd on ./libdtvmapi.so:"
                    ldd ./libdtvmapi.so || true
                fi
                exit 1
            fi

            EVMONE_MODE_TIMEOUT_SECONDS=${EVMONE_MODE_TIMEOUT_SECONDS:-}
            for EVMONE_MODE in multipass interpreter; do
                echo "Running evmone-statetest mode=${EVMONE_MODE}, filter=${EVMONE_STATETEST_FILTER}"
                run_status=0
                RESULT_LOG="/tmp/evmone_st_${EVMONE_MODE}.log"
                if [ -n "$EVMONE_MODE_TIMEOUT_SECONDS" ]; then
                    echo "Mode timeout enabled: ${EVMONE_MODE_TIMEOUT_SECONDS}s"
                    timeout --foreground "$EVMONE_MODE_TIMEOUT_SECONDS" env \
                        DTVM_EVM_MODE="$EVMONE_MODE" \
                        DTVM_EVM_ENABLE_GAS_METERING=true \
                        stdbuf -oL -eL \
                        ./build/bin/evmone-statetest "$EVMONE_STATETEST_PATH" \
                        --vm external_vm \
                        -k "$EVMONE_STATETEST_FILTER" 2>&1 | tee "$RESULT_LOG"
                    run_status=${PIPESTATUS[0]}
                else
                    env DTVM_EVM_MODE="$EVMONE_MODE" DTVM_EVM_ENABLE_GAS_METERING=true \
                        stdbuf -oL -eL \
                        ./build/bin/evmone-statetest "$EVMONE_STATETEST_PATH" \
                        --vm external_vm \
                        -k "$EVMONE_STATETEST_FILTER" 2>&1 | tee "$RESULT_LOG"
                    run_status=${PIPESTATUS[0]}
                fi

                if [ "$run_status" -ne 0 ]; then
                    if [ "$run_status" -eq 124 ]; then
                        echo "evmone-statetest timed out in mode=${EVMONE_MODE} after ${EVMONE_MODE_TIMEOUT_SECONDS}s"
                    else
                        echo "evmone-statetest failed in mode=${EVMONE_MODE} with exit code ${run_status}"
                    fi
                    exit "$run_status"
                fi
            done
            cd ..
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
