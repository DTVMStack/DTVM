# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/env python3
"""Test wrapper for update_compiler_pass_timing_budget.py.

Called by CMakeLists.txt as:
    test_update_compiler_pass_timing_budget.py <source_dir>

Runs the updater with a synthetic timing report and verifies that the output
budget JSON has the required structure.  No dtvm binary is needed.
"""

import json
import pathlib
import subprocess
import sys
import tempfile


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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

PASS_NAME = "x86_cg_peephole"
TOTAL_TIME_MS = 1.0
PASS_TIME_MS = 0.002
PASS_SHARE_PCT = 0.2


def make_phase_stats(time_ms, share_pct):
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


def build_synthetic_report(manifest_path):
    cases = []
    for name in CASE_NAMES:
        cases.append(
            {
                "name": name,
                "input": f"/synthetic/{name}.evm.hex",
                "summary": make_case_summary(
                    TOTAL_TIME_MS, PASS_NAME, PASS_TIME_MS, PASS_SHARE_PCT
                ),
            }
        )

    overall_summary = make_case_summary(
        TOTAL_TIME_MS, PASS_NAME, PASS_TIME_MS, PASS_SHARE_PCT
    )
    overall_summary["runs"] = 1
    overall_summary["record_count"] = len(CASE_NAMES)

    return {
        "manifest": str(manifest_path),
        "case_count": len(CASE_NAMES),
        "cases": cases,
        "overall": overall_summary,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    if len(sys.argv) != 2:
        print(
            "usage: test_update_compiler_pass_timing_budget.py <source_dir>",
            file=sys.stderr,
        )
        return 1

    source_dir = pathlib.Path(sys.argv[1]).resolve()
    updater = source_dir / "tools" / "update_compiler_pass_timing_budget.py"

    if not updater.exists():
        print(f"updater not found: {updater}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = pathlib.Path(tmp_dir)

        manifest_path = (
            source_dir / "tests" / "evm_asm" / "compiler_pass_timing_manifest.json"
        )
        report = build_synthetic_report(manifest_path)

        report_path = tmp / "timing_report.json"
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

        output_path = tmp / "budget_out.json"

        cmd = [
            sys.executable,
            str(updater),
            "--report",
            str(report_path),
            "--out",
            str(output_path),
            "--target-pass",
            PASS_NAME,
            "--runs",
            "1",
            "--compile-mode",
            "compile-only",
            "--threshold-status",
            "provisional",
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            print(result.stderr, file=sys.stderr)
            print(
                f"FAIL: test_update_compiler_pass_timing_budget — updater exited with "
                f"code {result.returncode}",
                file=sys.stderr,
            )
            return 1

        if not output_path.exists():
            print(
                "FAIL: test_update_compiler_pass_timing_budget — output JSON was not written",
                file=sys.stderr,
            )
            return 1

        try:
            budget = json.loads(output_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(
                f"FAIL: test_update_compiler_pass_timing_budget — invalid JSON: {exc}",
                file=sys.stderr,
            )
            return 1

        # Verify required top-level keys
        for field in ("version", "target_pass", "thresholds", "baseline", "metadata"):
            if field not in budget:
                print(
                    f"FAIL: test_update_compiler_pass_timing_budget — missing field "
                    f"'{field}'",
                    file=sys.stderr,
                )
                return 1

        # Verify target_pass recorded correctly
        if budget["target_pass"] != PASS_NAME:
            print(
                f"FAIL: test_update_compiler_pass_timing_budget — target_pass mismatch: "
                f"expected '{PASS_NAME}', got '{budget['target_pass']}'",
                file=sys.stderr,
            )
            return 1

        # Verify baseline structure
        baseline = budget["baseline"]
        for field in ("overall_total_time_ms_median", "case_total_time_ms_median"):
            if field not in baseline:
                print(
                    f"FAIL: test_update_compiler_pass_timing_budget — baseline missing "
                    f"field '{field}'",
                    file=sys.stderr,
                )
                return 1

        # Verify all cases are present in the baseline
        case_baselines = baseline["case_total_time_ms_median"]
        for name in CASE_NAMES:
            if name not in case_baselines:
                print(
                    f"FAIL: test_update_compiler_pass_timing_budget — baseline missing "
                    f"case '{name}'",
                    file=sys.stderr,
                )
                return 1

        # Verify overall baseline value matches the synthetic report
        expected_overall = TOTAL_TIME_MS  # synthetic median
        if abs(baseline["overall_total_time_ms_median"] - expected_overall) > 1e-9:
            print(
                f"FAIL: test_update_compiler_pass_timing_budget — overall baseline "
                f"{baseline['overall_total_time_ms_median']} != expected {expected_overall}",
                file=sys.stderr,
            )
            return 1

        # Verify thresholds keys are present
        thresholds = budget["thresholds"]
        for key in (
            "max_pass_share_p95_pct",
            "max_pass_time_p95_ms",
            "max_overall_total_time_regression_pct",
            "max_case_total_time_regression_pct",
        ):
            if key not in thresholds:
                print(
                    f"FAIL: test_update_compiler_pass_timing_budget — thresholds "
                    f"missing key '{key}'",
                    file=sys.stderr,
                )
                return 1

        # Verify metadata
        metadata = budget["metadata"]
        for key in ("compile_mode", "thresholds_status", "runs"):
            if key not in metadata:
                print(
                    f"FAIL: test_update_compiler_pass_timing_budget — metadata "
                    f"missing key '{key}'",
                    file=sys.stderr,
                )
                return 1

    print("PASS: test_update_compiler_pass_timing_budget")
    return 0


if __name__ == "__main__":
    sys.exit(main())
