# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/env python3
"""Test wrapper for check_compiler_pass_timing_budget.py.

Called by CMakeLists.txt as:
    test_check_compiler_pass_timing_budget.py <source_dir>

Verifies the budget-checker tool works correctly by building a synthetic timing
report that satisfies both committed budget files and running the checker against
each one.  No dtvm binary is needed.
"""

import json
import pathlib
import subprocess
import sys
import tempfile


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BUDGET_FILES = [
    "tests/evm_asm/compiler_pass_timing_budget_x86_cg_peephole.json",
    "tests/evm_asm/compiler_pass_timing_budget_dmir_rewrite.json",
]

# Case names that appear in both budget baselines
CASE_NAMES = [
    "add",
    "mul",
    "div",
    "shl",
    "shr",
    "sar",
    "byte",
    "eq_true",
    "lt_true",
    "jump",
    "u256_shl_add_mul",
    "u256_mul_add_chain",
    "u256_shr_add_shl",
    "bool_and_or_xor_not",
    "bool_xor_not_chain",
]


def make_phase_stats(time_ms, share_pct):
    """Return a phase stats dict well within any reasonable budget."""
    return {
        "mean": time_ms,
        "median": time_ms,
        "p95": time_ms,
        "min": time_ms,
        "max": time_ms,
        "share_of_total_pct": {
            "mean": share_pct,
            "median": share_pct,
            "p95": share_pct,
            "min": share_pct,
            "max": share_pct,
        },
    }


def make_case_summary(total_time_ms, pass_name, pass_time_ms, pass_share_pct):
    return {
        "total_time_ms": {"mean": total_time_ms, "median": total_time_ms},
        "phases": {
            pass_name: make_phase_stats(pass_time_ms, pass_share_pct),
        },
        "runs": 1,
        "record_count": 1,
    }


def build_synthetic_report(pass_name, total_time_ms, pass_time_ms, pass_share_pct):
    """Build a manifest-style timing report that stays inside the budget."""
    cases = []
    for name in CASE_NAMES:
        cases.append(
            {
                "name": name,
                "input": f"/synthetic/{name}.evm.hex",
                "summary": make_case_summary(
                    total_time_ms, pass_name, pass_time_ms, pass_share_pct
                ),
            }
        )

    overall_summary = make_case_summary(
        total_time_ms, pass_name, pass_time_ms, pass_share_pct
    )
    overall_summary["runs"] = 1
    overall_summary["record_count"] = len(CASE_NAMES)

    return {
        "manifest": "/synthetic/manifest.json",
        "case_count": len(CASE_NAMES),
        "cases": cases,
        "overall": overall_summary,
    }


def run_checker(checker, budget_path, report_path):
    cmd = [
        sys.executable,
        str(checker),
        "--budget",
        str(budget_path),
        "--report",
        str(report_path),
        "--allow-missing-cases",
    ]
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    if len(sys.argv) != 2:
        print(
            "usage: test_check_compiler_pass_timing_budget.py <source_dir>",
            file=sys.stderr,
        )
        return 1

    source_dir = pathlib.Path(sys.argv[1]).resolve()
    checker = source_dir / "tools" / "check_compiler_pass_timing_budget.py"

    if not checker.exists():
        print(f"checker not found: {checker}", file=sys.stderr)
        return 1

    failures = []

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = pathlib.Path(tmp_dir)

        for rel_budget in BUDGET_FILES:
            budget_path = source_dir / rel_budget
            if not budget_path.exists():
                print(f"budget file not found: {budget_path}", file=sys.stderr)
                return 1

            budget = json.loads(budget_path.read_text(encoding="utf-8"))
            target_pass = budget["target_pass"]
            thresholds = budget["thresholds"]
            baseline_overall = budget["baseline"]["overall_total_time_ms_median"]

            # Choose values well inside all thresholds:
            #   - pass share p95 = 0.1 %  (budget typically 1.2–2.0 %)
            #   - pass time p95  = 0.001 ms (budget 0.01–0.06 ms)
            #   - total time = baseline (0 % regression)
            report = build_synthetic_report(
                pass_name=target_pass,
                total_time_ms=baseline_overall,
                pass_time_ms=0.001,
                pass_share_pct=0.1,
            )

            report_path = tmp / f"report_{pathlib.Path(rel_budget).stem}.json"
            report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

            result = run_checker(checker, budget_path, report_path)
            tag = pathlib.Path(rel_budget).stem

            if result.returncode != 0:
                failures.append(
                    f"checker failed for {tag} (exit {result.returncode}):\n"
                    f"{result.stderr.strip()}"
                )
                continue

            # Also verify that a clearly over-budget report is rejected
            bad_report = build_synthetic_report(
                pass_name=target_pass,
                total_time_ms=baseline_overall,
                pass_time_ms=999.0,         # massively over time budget
                pass_share_pct=99.0,        # massively over share budget
            )
            bad_report_path = tmp / f"bad_report_{pathlib.Path(rel_budget).stem}.json"
            bad_report_path.write_text(
                json.dumps(bad_report, indent=2), encoding="utf-8"
            )

            bad_result = run_checker(checker, budget_path, bad_report_path)
            if bad_result.returncode == 0:
                failures.append(
                    f"checker INCORRECTLY passed an over-budget report for {tag}"
                )

    if failures:
        for msg in failures:
            print(msg, file=sys.stderr)
        print(
            "FAIL: test_check_compiler_pass_timing_budget",
            file=sys.stderr,
        )
        return 1

    print("PASS: test_check_compiler_pass_timing_budget")
    return 0


if __name__ == "__main__":
    sys.exit(main())
