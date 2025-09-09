#!/bin/bash
# SPDX-License-Identifier: Apache-2.0

set -e

# Check if clang-format is installed
if ! command -v clang-format &>/dev/null; then
  echo "Error: clang-format command not found, please install it and try again." >&2
  exit 1
fi

# Check if clang-tidy is installed
if ! command -v clang-tidy &>/dev/null; then
  echo "Error: clang-tidy command not found, please install it and try again." >&2
  exit 1
fi

# Check if cmake-format is installed
if ! command -v cmake-format &>/dev/null; then
  echo "Error: cmake-format command not found, please install it and try again." >&2
  exit 1
fi

# Check EVM ASM file format: trailing whitespace and newline
check_evm_asm_format() {
  local file="$1"
  grep -q '[[:space:]]$' "$file" && { echo "Error: $file: Trailing whitespace found"; return 1; }
  [[ -s "$file" ]] && ! tail -c1 "$file" | od -An -tx1 | grep -q '0a' && { echo "Error: $file: Missing newline at end of file"; return 1; }
  return 0
}

# Format EVM ASM files:
# 1. Remove trailing whitespace
# 2. Remove all trailing empty lines and add exactly one newline
format_evm_asm_files() {
  local target_dir="tests/evm_asm"
  find "$target_dir" -type f -print0 | xargs -0 -I {} sh -c '
    file="$1"
    sed -i "s/[[:space:]]\+$//" "$file" 2>/dev/null || true
    sed -i -e :a -e "/^\n*$/{\$d;N;};/\n$/ba" "$file" 2>/dev/null || true
    tail -c1 "$file" | read -r _ || echo >> "$file"
  ' _ {}
}

if [ "$1" == "check" ]; then
  # Check the format of all CMake files
  cmake-format --check CMakeLists.txt
  find src -type f -name "CMakeLists.txt" | xargs cmake-format --check
  find third_party -type f -name "*.cmake" | xargs cmake-format --check
  # Check the format of all C/C++ files
  find src -path "src/compiler/llvm-prebuild" -prune -type f -or -name "*.h" -or -name "*.c" -or -name "*.cpp" | xargs clang-format --dry-run -style=file -Werror
  # Check EVM ASM file format
  export -f check_evm_asm_format
  find tests/evm_asm -type f -print0 | xargs -0 -I {} bash -c 'check_evm_asm_format "$1" || exit 1' _ {}
elif [ "$1" == "tidy-check" ]; then
  # Check variable naming conventions with clang-tidy
  if [ -d "build" ]; then
    find src -path "src/compiler/llvm-prebuild" -prune -type f -or -name "*.h" -or -name "*.c" -or -name "*.cpp" | head -5 | xargs clang-tidy -p build --quiet --checks='readability-identifier-naming'
  else
    echo "Warning: build directory not found, skipping clang-tidy checks"
  fi
elif [ "$1" == "format" ]; then
  # Format all CMake files
  cmake-format -i CMakeLists.txt
  find src -type f -name "CMakeLists.txt" | xargs cmake-format -i
  find third_party -type f -name "*.cmake" | xargs cmake-format -i
  # Format all C/C++ files
  find src -path "src/compiler/llvm-prebuild" -prune -type f -or -name "*.h" -or -name "*.c" -or -name "*.cpp" | xargs clang-format -i -style=file -Werror
  # Format EVM ASM files
  format_evm_asm_files
else
  echo "Error: invalid argument"
  echo "Usage: $0 [check|format|tidy-check]"
  exit 1
fi
