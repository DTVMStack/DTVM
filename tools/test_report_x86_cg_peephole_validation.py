#!/usr/bin/env python3
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import pathlib
import subprocess
import sys
import tempfile


def run_reporter(source_dir, rules_path, gtest_binary=None, out_path=None):
    script = pathlib.Path(source_dir) / "tools" / "report_x86_cg_peephole_validation.py"
    cmd = [sys.executable, str(script), "--rules", str(rules_path)]
    if gtest_binary:
        cmd += ["--gtest-binary", str(gtest_binary)]
    if out_path:
        cmd += ["--out", str(out_path)]
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

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = pathlib.Path(tmpdir)

        out_path = tmpdir / "report.json"
        proc = run_reporter(source_dir, rules_path, gtest_binary, out_path)
        if proc.returncode != 0:
            print("FAIL: reporter exited non-zero", file=sys.stderr)
            print(proc.stderr, file=sys.stderr)
            return 1
        if not out_path.exists():
            print("FAIL: output file not created", file=sys.stderr)
            return 1
        try:
            report = json.loads(out_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"FAIL: output is not valid JSON: {exc}", file=sys.stderr)
            return 1

        for key in ("summary", "rules"):
            if key not in report:
                print(f"FAIL: report missing top-level key '{key}'", file=sys.stderr)
                return 1

        summary = report["summary"]
        for key in ("rule_count", "stage_counts", "mode_counts", "rules_with_missing_coverage"):
            if key not in summary:
                print(f"FAIL: summary missing key '{key}'", file=sys.stderr)
                return 1

        if summary["rule_count"] <= 0:
            print("FAIL: summary.rule_count must be > 0", file=sys.stderr)
            return 1

        for entry in report["rules"]:
            for field in ("name", "stage", "priority", "modes", "coverage", "coverage_complete"):
                if field not in entry:
                    print(f"FAIL: rule entry missing field '{field}'", file=sys.stderr)
                    return 1

        out_path2 = tmpdir / "report_no_binary.json"
        proc2 = run_reporter(source_dir, rules_path, None, out_path2)
        if proc2.returncode != 0:
            print("FAIL: reporter failed without gtest binary", file=sys.stderr)
            return 1
        report2 = json.loads(out_path2.read_text(encoding="utf-8"))
        for entry in report2["rules"]:
            for cov in entry.get("coverage", []):
                if not cov.get("present", True):
                    print(f"FAIL: coverage entry marked absent without binary: {cov}",
                          file=sys.stderr)
                    return 1

        if gtest_binary:
            if report["summary"]["rules_with_missing_coverage"] != 0:
                print("FAIL: real rules have missing coverage according to gtest binary",
                      file=sys.stderr)
                return 1

        proc3 = run_reporter(source_dir, rules_path, None, None)
        if proc3.returncode != 0:
            print("FAIL: reporter failed when writing to stdout", file=sys.stderr)
            return 1
        try:
            json.loads(proc3.stdout)
        except json.JSONDecodeError as exc:
            print(f"FAIL: stdout is not valid JSON: {exc}", file=sys.stderr)
            return 1

    print("PASS: test_report_x86_cg_peephole_validation")
    return 0


if __name__ == "__main__":
    sys.exit(main())
