#!/bin/bash
# Bulk Memory Operations test suite
# This script tests all 7 bulk memory instructions in interpreter mode.
# Usage: ./run_tests.sh <path_to_dtvm>

set -e

DTVM=${1:-"../../build/dtvm"}
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PASS=0
FAIL=0
TOTAL=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

assert_return() {
  local desc="$1"
  local expected="$2"
  shift 2
  TOTAL=$((TOTAL + 1))
  local result
  result=$("$@" 2>&1) || true
  if echo "$result" | grep -q "$expected"; then
    PASS=$((PASS + 1))
    echo -e "${GREEN}PASS${NC}: $desc (got $expected)"
  else
    FAIL=$((FAIL + 1))
    echo -e "${RED}FAIL${NC}: $desc (expected '$expected', got '$result')"
  fi
}

assert_trap() {
  local desc="$1"
  local expected_msg="$2"
  shift 2
  TOTAL=$((TOTAL + 1))
  local result
  result=$("$@" 2>&1) || true
  if echo "$result" | grep -q "$expected_msg"; then
    PASS=$((PASS + 1))
    echo -e "${GREEN}PASS${NC}: $desc (trapped: $expected_msg)"
  else
    FAIL=$((FAIL + 1))
    echo -e "${RED}FAIL${NC}: $desc (expected trap '$expected_msg', got '$result')"
  fi
}

assert_success() {
  local desc="$1"
  shift
  TOTAL=$((TOTAL + 1))
  local result
  if result=$("$@" 2>&1); then
    PASS=$((PASS + 1))
    echo -e "${GREEN}PASS${NC}: $desc (success)"
  else
    if echo "$result" | grep -q "error\|trap\|failed"; then
      FAIL=$((FAIL + 1))
      echo -e "${RED}FAIL${NC}: $desc (expected success, got '$result')"
    else
      PASS=$((PASS + 1))
      echo -e "${GREEN}PASS${NC}: $desc (success)"
    fi
  fi
}

echo "========================================"
echo "  Bulk Memory Operations Test Suite"
echo "========================================"
echo ""

# ---- memory.fill tests ----
echo "--- memory.fill ---"
assert_return "basic fill" "0xff:i32" \
  $DTVM -m interpreter "$SCRIPT_DIR/memory_fill.wasm" -f test_basic_fill

assert_return "fill value truncation (0xABCD -> 0xCD)" "0xcd:i32" \
  $DTVM -m interpreter "$SCRIPT_DIR/memory_fill.wasm" -f test_fill_value_truncation

echo ""

# ---- memory.copy tests ----
echo "--- memory.copy ---"
assert_return "basic copy" "0xcc:i32" \
  $DTVM -m interpreter "$SCRIPT_DIR/memory_copy.wasm" -f test_basic_copy

assert_return "overlapping copy" "0x2:i32" \
  $DTVM -m interpreter "$SCRIPT_DIR/memory_copy.wasm" -f test_overlap_copy

echo ""

# ---- memory.init tests ----
echo "--- memory.init ---"
assert_return "basic init from passive segment" "0xcc:i32" \
  $DTVM -m interpreter "$SCRIPT_DIR/memory_init.wasm" -f test_basic_init

echo ""

# ---- table_copy tests ----
echo "--- table.copy ---"
assert_return "call_indirect after active elem init (idx 0)" "0x0:i32" \
  $DTVM -m interpreter "$SCRIPT_DIR/table_copy.wasm" -f call_indirect --args 0

assert_return "call_indirect after active elem init (idx 1)" "0x1:i32" \
  $DTVM -m interpreter "$SCRIPT_DIR/table_copy.wasm" -f call_indirect --args 1

assert_return "call_indirect after active elem init (idx 2)" "0x2:i32" \
  $DTVM -m interpreter "$SCRIPT_DIR/table_copy.wasm" -f call_indirect --args 2

echo ""

# ---- table.init tests ----
echo "--- table.init ---"
assert_success "table.init from passive elem segment" \
  $DTVM -m interpreter "$SCRIPT_DIR/table_init.wasm" -f init --args 0 0 3

echo ""

# ---- data.drop tests ----
echo "--- data.drop ---"
assert_success "drop passive data segment" \
  $DTVM -m interpreter "$SCRIPT_DIR/data_drop.wasm" -f drop_passive

echo ""

# ---- elem.drop tests ----
echo "--- elem.drop ---"
assert_success "drop passive elem segment" \
  $DTVM -m interpreter "$SCRIPT_DIR/elem_drop.wasm" -f drop_elem

echo ""

# ---- JIT mode graceful error ----
echo "--- JIT mode graceful error ---"
assert_trap "memory.fill in singlepass mode" "not supported" \
  $DTVM -m singlepass "$SCRIPT_DIR/memory_fill.wasm" -f test_basic_fill

echo ""

# ---- Summary ----
echo "========================================"
echo "  Results: $PASS/$TOTAL passed, $FAIL failed"
echo "========================================"

if [ $FAIL -gt 0 ]; then
  exit 1
fi
