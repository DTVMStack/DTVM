#!/usr/bin/env python3
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test that after S3 extension, synth output contains specific struct-eq
prod rule LHS patterns.

Usage: test_synth_pattern_struct_eq.py <source_dir>
"""
import json
import pathlib
import subprocess
import sys
import tempfile


REQUIRED_RULES = {
    # Task 4
    "mul-pow2-to-shl",
    "mul-one-rhs",
    "mul-zero-rhs",
    # Task 5
    "double-not",
    "shl-zero",
    "ushr-zero",
    "sshr-zero",
    # Task 6 (sample of structural families)
    "or-not-self",         # Family A: not+MASK64
    "and-not-or",          # Family B: not-absorption depth-2
    "select-false-cond",   # Family C: select
    "add-self-to-shl1",    # Family D: add/sub depth-2
    "sub-or-and-to-xor",   # Family D: cross-family
}


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <source_dir>", file=sys.stderr)
        return 1
    source_dir = pathlib.Path(sys.argv[1])
    with tempfile.TemporaryDirectory() as tmpdir:
        out = pathlib.Path(tmpdir) / "synth.json"
        proc = subprocess.run(
            [sys.executable, str(source_dir / "tools/synthesize_dmir_rules.py"),
             "--no-z3", "--max-depth", "2", "--out", str(out)],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            print("FAIL: synth exited non-zero", file=sys.stderr)
            print(proc.stderr, file=sys.stderr)
            return 1
        # Re-use measure_prod_overlap.py's parser to canonicalize both sides
        sys.path.insert(0, str(source_dir / "tools"))
        from mine_dmir_seed_rules import parse_expr, canonicalize_expr
        prod = json.load(
            open(source_dir / "src/compiler/mir/dmir_rewrite_rules.json")
        )["rules"]
        synth = json.load(open(out))
        synth_rules = (
            synth["rules"] if isinstance(synth, dict) and "rules" in synth
            else synth
        )
        prod_keys = {
            canonicalize_expr(parse_expr(r["lhs"])).render(): r["name"]
            for r in prod
        }
        synth_keys = {
            canonicalize_expr(
                parse_expr(r["lhs"] if isinstance(r, dict) else r[0])
            ).render()
            for r in synth_rules
        }
        matched_names = {prod_keys[k] for k in prod_keys if k in synth_keys}
        missing_required = REQUIRED_RULES - matched_names
        if missing_required:
            print(
                f"FAIL: required rules not discovered: "
                f"{sorted(missing_required)}",
                file=sys.stderr,
            )
            return 1
        print(
            f"PASS: all {len(REQUIRED_RULES)} required rules discovered "
            f"among {len(matched_names)} total matches"
        )
        return 0


if __name__ == "__main__":
    sys.exit(main())
