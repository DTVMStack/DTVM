#!/bin/bash
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Script to compile all Solidity files in subdirectories to JSON using solc
# Usage: ./solc_batch_compile.sh [directory]
# If no directory is provided, defaults to tests/evm_solidity
#
# For each subdirectory, this script looks for a .sol file with the same name
# as the directory and compiles it to JSON format with ABI and bytecode

# Default base directory containing Solidity contracts
DEFAULT_BASE_DIR="tests/evm_solidity"

# Use provided directory or default
BASE_DIR="${1:-$DEFAULT_BASE_DIR}"

# Convert to absolute path if it's a relative path
if [[ ! "$BASE_DIR" = /* ]]; then
    BASE_DIR="$(pwd)/$BASE_DIR"
fi

# Check if base directory exists
if [ ! -d "$BASE_DIR" ]; then
    echo "Error: Directory $BASE_DIR does not exist"
    exit 1
fi

# Check if solc is available
if ! command -v solc &> /dev/null; then
    echo "Error: solc compiler not found. Please install Solidity compiler."
    exit 1
fi

echo "Compiling Solidity contracts in $BASE_DIR..."

# Find all subdirectories in the base directory
for dir in "$BASE_DIR"/*/; do
    if [ -d "$dir" ]; then
        # Get the directory name (without path)
        dirname=$(basename "$dir")
        
        # Check if the corresponding .sol file exists
        sol_file="$dir$dirname.sol"
        json_file="$dir$dirname.json"
        
        if [ -f "$sol_file" ]; then
            echo "Compiling $sol_file..."
            
            # Compile the Solidity file
            if solc --combined-json abi,bin,bin-runtime "$dir$dirname.sol" > "$dir$dirname.json"; then
                echo "✓ Successfully compiled $dirname.sol to $dirname.json"
            else
                echo "✗ Failed to compile $dirname.sol"
            fi
        else
            echo "Warning: $sol_file not found, skipping directory $dirname"
        fi
    fi
done

echo "Compilation completed."
