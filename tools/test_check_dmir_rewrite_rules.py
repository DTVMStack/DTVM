#!/usr/bin/env python3
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import copy
import json
import pathlib
import subprocess
import sys
import tempfile

VALID_RULE_TEMPLATE = {
    "name": "test-add-zero",
    "status": "accepted",
    "inputs": ["x"],
    "lhs": "(add x 0:i64)",
    "rhs": "x",
    "cost": {
        "lhs": {"dmir_inst": 1, "select_depth": 0, "adc_chain": 0, "runtime_calls": 0},
        "rhs": {"dmir_inst": 0, "select_depth": 0, "adc_chain": 0, "runtime_calls": 0},
        "delta": {"dmir_inst": -1, "select_depth": 0, "adc_chain": 0, "runtime_calls": 0},
    },
    "validation": {
        "modes": ["interpreter_fuzz"],
        "coverage": ["DMirValidation.FuzzesAddZeroRewrite"],
    },
}


def run_checker(source_dir, rules_path, gtest_binary=None):
    script = pathlib.Path(source_dir) / "tools" / "check_dmir_rewrite_rules.py"
    cmd = [sys.executable, str(script), "--rules", str(rules_path)]
    if gtest_binary:
        cmd += ["--gtest-binary", str(gtest_binary)]
    return subprocess.run(cmd, capture_output=True, text=True)


def write_rules(path, rules):
    path.write_text(json.dumps({"rules": rules}), encoding="utf-8")


def main():
    if len(sys.argv) not in (2, 3):
        print(f"Usage: {sys.argv[0]} <source_dir> [<dmirValidationTests_binary>]",
              file=sys.stderr)
        return 1

    source_dir = pathlib.Path(sys.argv[1])
    gtest_binary = pathlib.Path(sys.argv[2]) if len(sys.argv) == 3 else None
    rules_path = source_dir / "src/compiler/mir/dmir_rewrite_rules.json"

    if not rules_path.exists():
        print(f"Rules file not found: {rules_path}", file=sys.stderr)
        return 1

    proc = run_checker(source_dir, rules_path, gtest_binary)
    if proc.returncode != 0:
        print("FAIL: checker failed on real dmir rules", file=sys.stderr)
        print(proc.stderr, file=sys.stderr)
        return 1
    if "dmir rewrite rule metadata is complete" not in proc.stdout:
        print("FAIL: expected success message not found", file=sys.stderr)
        return 1

    if gtest_binary:
        proc2 = run_checker(source_dir, rules_path, None)
        if proc2.returncode != 0:
            print("FAIL: checker failed on real dmir rules without binary", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = pathlib.Path(tmpdir)

        dup_path = tmpdir / "dup.json"
        rule_a = copy.deepcopy(VALID_RULE_TEMPLATE)
        rule_b = copy.deepcopy(VALID_RULE_TEMPLATE)
        rule_b["lhs"] = "(add x 1:i64)"  # different expression so only name duplicates
        write_rules(dup_path, [rule_a, rule_b])
        proc3 = run_checker(source_dir, dup_path, None)
        if proc3.returncode == 0:
            print("FAIL: checker should fail on duplicate rule name", file=sys.stderr)
            return 1
        if "duplicate" not in proc3.stderr:
            print("FAIL: expected 'duplicate' in error output", file=sys.stderr)
            return 1

        bad_status = copy.deepcopy(VALID_RULE_TEMPLATE)
        bad_status["name"] = "bad-status-rule"
        bad_status["status"] = "unknown_status"
        bad_path = tmpdir / "bad_status.json"
        write_rules(bad_path, [bad_status])
        proc4 = run_checker(source_dir, bad_path, None)
        if proc4.returncode == 0:
            print("FAIL: checker should fail on invalid status", file=sys.stderr)
            return 1
        if "invalid status" not in proc4.stderr:
            print("FAIL: expected 'invalid status' in error output", file=sys.stderr)
            return 1

        rule_c = copy.deepcopy(VALID_RULE_TEMPLATE)
        rule_c["name"] = "test-add-zero-commuted"
        # (add 0:i64 x) normalizes to same canonical key as (add x 0:i64) due to commutativity
        rule_c["lhs"] = "(add 0:i64 x)"
        dup_canonical_path = tmpdir / "dup_canonical.json"
        write_rules(dup_canonical_path, [VALID_RULE_TEMPLATE, rule_c])
        proc5 = run_checker(source_dir, dup_canonical_path, None)
        if proc5.returncode == 0:
            print("FAIL: checker should fail on duplicate canonical lhs/rhs", file=sys.stderr)
            return 1
        if "duplicates canonical rewrite" not in proc5.stderr:
            print("FAIL: expected 'duplicates canonical rewrite' in error output", file=sys.stderr)
            return 1

        no_semantic = copy.deepcopy(VALID_RULE_TEMPLATE)
        no_semantic["name"] = "no-semantic-mode"
        no_semantic["validation"]["modes"] = ["interpreter_sample"]
        no_semantic_path = tmpdir / "no_semantic.json"
        write_rules(no_semantic_path, [no_semantic])
        proc6 = run_checker(source_dir, no_semantic_path, None)
        if proc6.returncode == 0:
            print("FAIL: checker should fail on rule with no semantic mode", file=sys.stderr)
            return 1
        if "interpreter_fuzz or smt" not in proc6.stderr:
            print("FAIL: expected 'interpreter_fuzz or smt' in error output", file=sys.stderr)
            return 1

        if gtest_binary:
            missing_cov = copy.deepcopy(VALID_RULE_TEMPLATE)
            missing_cov["name"] = "missing-coverage-rule"
            missing_cov["lhs"] = "(sub x 0:i64)"
            missing_cov["cost"]["lhs"]["dmir_inst"] = 1
            missing_cov["validation"]["coverage"] = ["NonExistentSuite.NonExistentTest"]
            missing_path = tmpdir / "missing_cov.json"
            write_rules(missing_path, [missing_cov])
            proc7 = run_checker(source_dir, missing_path, gtest_binary)
            if proc7.returncode == 0:
                print("FAIL: checker should fail on missing gtest coverage entry", file=sys.stderr)
                return 1
            if "missing gtest coverage" not in proc7.stderr:
                print("FAIL: expected 'missing gtest coverage' in error output", file=sys.stderr)
                return 1

    print("PASS: test_check_dmir_rewrite_rules")
    return 0


if __name__ == "__main__":
    sys.exit(main())
