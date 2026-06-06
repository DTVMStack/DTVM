#!/usr/bin/env python3
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Regression guard: U256 synthesis must rediscover prod U256 rewrites."""

import json
import pathlib
import subprocess
import sys
import tempfile


REQUIRED_RULE = ("(u256_xor x x)", "(const_u256 0)")


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <source_dir>", file=sys.stderr)
        return 1
    source_dir = pathlib.Path(sys.argv[1])
    with tempfile.TemporaryDirectory() as tmpdir:
        out = pathlib.Path(tmpdir) / "u256_synth.json"
        proc = subprocess.run(
            [
                sys.executable,
                str(source_dir / "tools/synthesize_dmir_rules.py"),
                "--mode",
                "u256",
                "--max-depth",
                "2",
                "--out",
                str(out),
            ],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            print("FAIL: u256 synth exited non-zero", file=sys.stderr)
            sys.stdout.write(proc.stdout)
            sys.stderr.write(proc.stderr)
            return 1
        rules = json.loads(out.read_text(encoding="utf-8"))["rules"]
        pairs = {(rule["lhs"], rule["rhs"]) for rule in rules}
        if REQUIRED_RULE not in pairs:
            print(
                "FAIL: u256-xor-self-zero was not rediscovered by synthesis",
                file=sys.stderr,
            )
            return 1
        print("PASS: U256 synthesis rediscovered u256-xor-self-zero")
        return 0


if __name__ == "__main__":
    sys.exit(main())
