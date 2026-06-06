#!/usr/bin/env python3
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Regression guard for exact scalar dMIR synthesis coverage.

The production rule set can contain separate U256 composite rules. This test
keeps the scalar S3 coverage denominator focused on non-256-bit dMIR rules and
requires the preserved scalar result: 70/70 production names and 69/69
canonical patterns.

Usage: test_synth_pattern_coverage.py <source_dir>
"""
import pathlib
import subprocess
import sys
import tempfile


EXPECTED_PROD_NAMES = "Prod rules (names): 70"
EXPECTED_PROD_PATTERNS = "Prod unique canonical patterns: 69"
EXPECTED_MATCHED_PATTERNS = "Matched prod unique patterns: 69/69 = 100.0%"
EXPECTED_MATCHED_NAMES = "Matched prod names: 70/70"


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <source_dir>", file=sys.stderr)
        return 1
    source_dir = pathlib.Path(sys.argv[1])
    with tempfile.TemporaryDirectory() as tmpdir:
        out = pathlib.Path(tmpdir) / "synth.json"
        proc = subprocess.run(
            [sys.executable, str(source_dir / "tools/synthesize_dmir_rules.py"),
             "--max-depth", "2", "--out", str(out)],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            print("FAIL: synth exited non-zero", file=sys.stderr)
            print(proc.stderr, file=sys.stderr)
            return 1
        r = subprocess.run(
            [sys.executable, str(source_dir / "tools/measure_prod_overlap.py"),
             str(out),
             "--prod-json", str(source_dir / "src/compiler/mir/dmir_rewrite_rules.json"),
             "--threshold", "69",
             "--exclude-ir-width", "256"],
            capture_output=True, text=True,
        )
        sys.stdout.write(r.stdout)
        sys.stderr.write(r.stderr)
        if r.returncode != 0:
            print("FAIL: scalar canonical coverage below 69/69", file=sys.stderr)
            return r.returncode
        required_lines = [
            EXPECTED_PROD_NAMES,
            EXPECTED_PROD_PATTERNS,
            EXPECTED_MATCHED_PATTERNS,
            EXPECTED_MATCHED_NAMES,
        ]
        missing = [line for line in required_lines if line not in r.stdout]
        if missing:
            print(
                "FAIL: scalar synthesis coverage output missing expected lines: "
                + ", ".join(missing),
                file=sys.stderr,
            )
            return 1
        return 0


if __name__ == "__main__":
    sys.exit(main())
