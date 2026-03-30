#!/usr/bin/env python3
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import pathlib
import subprocess
import sys
import tempfile


def run_checker(source_dir, rules_path, gtest_binary=None):
    script = pathlib.Path(source_dir) / "tools" / "check_x86_cg_peephole_validation.py"
    cmd = [sys.executable, str(script), "--rules", str(rules_path)]
    if gtest_binary:
        cmd += ["--gtest-binary", str(gtest_binary)]
    return subprocess.run(cmd, capture_output=True, text=True)


def main():
    if len(sys.argv) not in (2, 3):
        print(f"Usage: {sys.argv[0]} <source_dir> [<x86CgPeepholeTests_binary>]",
              file=sys.stderr)
        return 1

    source_dir = pathlib.Path(sys.argv[1])
    gtest_binary = pathlib.Path(sys.argv[2]) if len(sys.argv) == 3 else None
    rules_path = source_dir / "src/compiler/target/x86/x86_cg_peephole_rules.json"

    if not rules_path.exists():
        print(f"Rules file not found: {rules_path}", file=sys.stderr)
        return 1

    proc = run_checker(source_dir, rules_path, gtest_binary)
    if proc.returncode != 0:
        print("FAIL: checker failed on real rules file", file=sys.stderr)
        print(proc.stderr, file=sys.stderr)
        return 1
    if "x86 cg peephole validation metadata is complete" not in proc.stdout:
        print("FAIL: expected success message not in stdout", file=sys.stderr)
        print(proc.stdout, file=sys.stderr)
        return 1

    if gtest_binary:
        proc2 = run_checker(source_dir, rules_path, None)
        if proc2.returncode != 0:
            print("FAIL: checker failed without gtest binary", file=sys.stderr)
            print(proc2.stderr, file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = pathlib.Path(tmpdir)

        bad_rules = {
            "rules": [
                {
                    "name": "no-validation-rule",
                    "stage": "instruction",
                    "priority": 100,
                    "pattern": [{"bind": "I", "opcode": "MOV64rr"}],
                    "action": {"erase": ["I"]},
                }
            ]
        }
        bad_path = tmpdir / "bad_rules.json"
        bad_path.write_text(json.dumps(bad_rules), encoding="utf-8")
        proc3 = run_checker(source_dir, bad_path, None)
        if proc3.returncode == 0:
            print("FAIL: checker should fail on rule missing validation", file=sys.stderr)
            return 1
        if "missing validation metadata" not in proc3.stderr:
            print("FAIL: expected error about missing validation metadata", file=sys.stderr)
            print(proc3.stderr, file=sys.stderr)
            return 1

        structural_only = {
            "rules": [
                {
                    "name": "structural-only-rule",
                    "stage": "instruction",
                    "priority": 100,
                    "pattern": [{"bind": "I", "opcode": "MOV64rr"}],
                    "action": {"erase": ["I"]},
                    "validation": {
                        "modes": ["structural"],
                        "coverage": ["SomeSuite.SomeTest"],
                    },
                }
            ]
        }
        structural_path = tmpdir / "structural_only.json"
        structural_path.write_text(json.dumps(structural_only), encoding="utf-8")
        proc4 = run_checker(source_dir, structural_path, None)
        if proc4.returncode == 0:
            print("FAIL: checker should fail on instruction rule with only structural mode",
                  file=sys.stderr)
            return 1
        if "execution or semantics_model" not in proc4.stderr:
            print("FAIL: expected error about execution or semantics_model", file=sys.stderr)
            print(proc4.stderr, file=sys.stderr)
            return 1

    print("PASS: test_x86_cg_peephole_validation")
    return 0


if __name__ == "__main__":
    sys.exit(main())
