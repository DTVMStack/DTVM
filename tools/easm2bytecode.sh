#!/bin/bash
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# check if the input and output paths are provided
if [ $# -ne 2 ]; then
    echo "Usage: $0 <input_path> <output_path>"
    exit 1
fi

# get the input and output paths from the command line arguments
INPUT_PATH="$1"
OUTPUT_PATH="$2"
EVMCONVERTER="tools/easm2bytecode.py"

# check if the input path exists and is a directory
if [ ! -d "$INPUT_PATH" ]; then
    echo "error: input directory '$INPUT_PATH' not found"
    exit 1
fi

# check if the output path exists, if not, create it
if [ ! -d "$OUTPUT_PATH" ]; then
    mkdir -p "$OUTPUT_PATH"
fi

# Initialize counters
success_count=0
failure_count=0
failed_files=()

for input_file in $INPUT_PATH/*.easm; do
    filename=$(basename "$input_file")
    output_file="$OUTPUT_PATH/${filename%.*}.evm.hex"

    # Always process the file, even if output exists - remove old output first
    [ -f "$output_file" ] && rm "$output_file"

    output=$(python3 $EVMCONVERTER "$input_file" "$output_file" 2>&1)
    ret=$?

    if [ $ret -eq 0 ] && [ -f "$output_file" ] && [ -s "$output_file" ]; then
        echo " ✅: $input_file -> $output_file"
        ((success_count++))
    else
        echo " ❌: $input_file"
        echo " ❌: $output"
        ((failure_count++))
        failed_files+=("$input_file")
        # remove the output file if it exists and is empty
        [ -f "$output_file" ] && rm "$output_file"
    fi
done

echo "========================================"
echo "Processing complete!"
echo "Success: $success_count files"
echo "Failure: $failure_count files"
echo "Total: $((success_count + failure_count)) files"

# Print failed files if any
if [ ${#failed_files[@]} -gt 0 ]; then
    echo ""
    echo "Failed files:"
    for failed_file in "${failed_files[@]}"; do
        echo "  - $failed_file"
    done
fi
