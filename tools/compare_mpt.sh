#!/bin/bash
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# requires:
# python requirements: eth-hash, trie, rlp
#   - you can install the requirements by running `pip3 install -r requirements.txt`
# Build the C++ MPT comparison binary before running this script:
#   - you can build the binary by running `cmake --build build -j --target mptCompareCpp`

# MPT Comparison Script - Compare C++ and Python MPT implementations
# Usage: ./compare_mpt.sh <json_file>

set -o pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <json_file>"
    echo "Example: $0 test_accounts.json"
    exit 1
fi

JSON_FILE="$1"

if [ ! -f "$JSON_FILE" ]; then
    echo "Error: File '$JSON_FILE' not found!"
    exit 1
fi

PY_BIN="$(command -v python3 || command -v python)"
if [ -z "$PY_BIN" ]; then
    echo "Error: python3/python not found in PATH"
    exit 1
fi

if [ ! -f "./tools/mpt_compare_py.py" ]; then
    echo "Error: Python script './tools/mpt_compare_py.py' not found!"
    exit 1
fi

normalize_hex() {
  local s="$1"
  s="${s#0x}"
  s="${s#0X}"
  echo "${s,,}"
}

echo "=== MPT Implementation Comparison ==="
echo "Input file: $JSON_FILE"
echo ""

# Run C++
echo "--- C++ Implementation ---"
CPP_OUTPUT=$(./build/mptCompareCpp "$JSON_FILE")
CPP_EXIT_CODE=$?
if [ $CPP_EXIT_CODE -ne 0 ]; then
    echo "ERROR: C++ implementation failed"
    echo "$CPP_OUTPUT"
    exit 1
fi
echo "$CPP_OUTPUT" > /tmp/cpp_result.json

# Run Python
echo "--- Python Implementation ---"
PY_OUTPUT=$("$PY_BIN" ./tools/mpt_compare_py.py "$JSON_FILE")
PY_EXIT_CODE=$?
if [ $PY_EXIT_CODE -ne 0 ]; then
    echo "ERROR: Python implementation failed"
    echo "$PY_OUTPUT"
    exit 1
fi
echo "$PY_OUTPUT" > /tmp/py_result.json

# State root (prefer jq; fallback grep/sed)
if command -v jq &> /dev/null; then
    CPP_STATE_ROOT_RAW=$(jq -r '.stateRoot' /tmp/cpp_result.json)
    PY_STATE_ROOT_RAW=$(jq -r '.stateRoot' /tmp/py_result.json)
else
    CPP_STATE_ROOT_RAW=$(echo "$CPP_OUTPUT" | grep -o '"stateRoot"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)"/\1/')
    PY_STATE_ROOT_RAW=$(echo "$PY_OUTPUT" | grep -o '"stateRoot"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)"/\1/')
fi

CPP_STATE_ROOT=$(normalize_hex "$CPP_STATE_ROOT_RAW")
PY_STATE_ROOT=$(normalize_hex "$PY_STATE_ROOT_RAW")

echo ""
echo "=== Results Comparison ==="
echo "C++ State Root:    0x$CPP_STATE_ROOT"
echo "Python State Root: 0x$PY_STATE_ROOT"

if [ "$CPP_STATE_ROOT" = "$PY_STATE_ROOT" ]; then
    echo "✅ SUCCESS: State roots match!"
    echo ""

    echo "=== Detailed Account Comparison ==="
    if command -v jq &> /dev/null; then
        echo "Comparing account details (normalized hex)..."
        ACCOUNTS_MATCH=true

        for account in $(jq -r '.accounts[].address' /tmp/cpp_result.json); do
            CPP_ACCOUNT=$(jq ".accounts[] | select(.address == \"$account\")" /tmp/cpp_result.json)
            PY_ACCOUNT=$(jq ".accounts[] | select(.address == \"$account\")" /tmp/py_result.json)

            for field in addressHash accountRLP storageRoot codeHash; do
                CPP_VAL_RAW=$(echo "$CPP_ACCOUNT" | jq -r ".${field}")
                PY_VAL_RAW=$(echo "$PY_ACCOUNT" | jq -r ".${field}")

                CPP_VAL=$(normalize_hex "$CPP_VAL_RAW")
                PY_VAL=$(normalize_hex "$PY_VAL_RAW")

                if [ "$CPP_VAL" != "$PY_VAL" ]; then
                    echo "❌ $field mismatch for $account"
                    echo "   C++:    $CPP_VAL_RAW"
                    echo "   Python: $PY_VAL_RAW"
                    ACCOUNTS_MATCH=false
                fi
            done

        done

        if [ "$ACCOUNTS_MATCH" = true ]; then
            echo "✅ All account details match perfectly!"
        fi
    else
        echo "Note: Install 'jq' for detailed (normalized) account comparison"
    fi
else
    echo "❌ FAILURE: State roots do not match!"

    echo ""
    echo "=== Debug Information ==="
    echo "C++ Output:"
    echo "$CPP_OUTPUT"
    echo ""
    echo "Python Output:"
    echo "$PY_OUTPUT"
fi

echo ""
echo "=== Summary ==="
if [ "$CPP_STATE_ROOT" = "$PY_STATE_ROOT" ]; then
    echo "✅ Both implementations produce identical results"
    exit 0
else
    echo "❌ Implementations produce different results"
    exit 1
fi
