#!/usr/bin/env python3
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import pathlib
import subprocess
import sys
import tempfile


def run_generator(rules_path, out_inc, out_report, source_dir):
    script = pathlib.Path(source_dir) / "tools" / "generate_x86_cg_peephole.py"
    proc = subprocess.run(
        [sys.executable, str(script),
         "--rules", str(rules_path),
         "--out-inc", str(out_inc),
         "--out-report", str(out_report)],
        capture_output=True,
        text=True,
    )
    return proc


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <source_dir>", file=sys.stderr)
        return 1

    source_dir = pathlib.Path(sys.argv[1])
    rules_path = source_dir / "src/compiler/target/x86/x86_cg_peephole_rules.json"

    if not rules_path.exists():
        print(f"Rules file not found: {rules_path}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = pathlib.Path(tmpdir)

        # Test 1: valid rules file produces output with exit code 0
        out_inc = tmpdir / "generated.inc"
        out_report = tmpdir / "report.txt"
        proc = run_generator(rules_path, out_inc, out_report, source_dir)
        if proc.returncode != 0:
            print(f"FAIL: generator exited {proc.returncode} on valid rules", file=sys.stderr)
            print(proc.stderr, file=sys.stderr)
            return 1
        if not out_inc.exists() or out_inc.stat().st_size == 0:
            print("FAIL: generated .inc file is missing or empty", file=sys.stderr)
            return 1
        inc_text = out_inc.read_text(encoding="utf-8")
        for marker in [
            "// Copyright (C) 2025 the DTVM authors",
            "GeneratedInstructionRuleResult",
            "tryGeneratedInstructionRules",
            "tryGeneratedBlockEndRules",
            "namespace {",
        ]:
            if marker not in inc_text:
                print(f"FAIL: generated .inc missing expected marker: {marker!r}", file=sys.stderr)
                return 1
        if not out_report.exists():
            print("FAIL: report file was not created", file=sys.stderr)
            return 1
        report_text = out_report.read_text(encoding="utf-8")
        if "No conflicts detected." not in report_text:
            print("FAIL: report does not say 'No conflicts detected.'", file=sys.stderr)
            print(report_text, file=sys.stderr)
            return 1

        # Test 2: conflicting rules produce exit code 1 and a conflict report
        conflict_rules = {
            "version": 1,
            "rules": [
                {
                    "name": "rule-a",
                    "stage": "instruction",
                    "priority": 100,
                    "pattern": [{"bind": "I", "opcode": "MOV64rr"}],
                    "action": {"erase": ["I"]},
                },
                {
                    "name": "rule-b",
                    "stage": "instruction",
                    "priority": 100,
                    "pattern": [{"bind": "I", "opcode": "MOV64rr"}],
                    "action": {"erase": ["I"]},
                },
            ],
        }
        conflict_rules_path = tmpdir / "conflict_rules.json"
        conflict_rules_path.write_text(json.dumps(conflict_rules), encoding="utf-8")
        out_inc2 = tmpdir / "generated2.inc"
        out_report2 = tmpdir / "report2.txt"
        proc2 = run_generator(conflict_rules_path, out_inc2, out_report2, source_dir)
        if proc2.returncode == 0:
            print("FAIL: generator should exit 1 for conflicting rules", file=sys.stderr)
            return 1
        if out_report2.exists():
            report2_text = out_report2.read_text(encoding="utf-8")
            if "Conflicts:" not in report2_text:
                print("FAIL: conflict report does not mention 'Conflicts:'", file=sys.stderr)
                return 1

    print("PASS: test_x86_cg_peephole_generator")
    return 0


if __name__ == "__main__":
    sys.exit(main())
