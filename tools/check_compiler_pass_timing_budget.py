#!/usr/bin/env python3

import argparse
import json
import pathlib
import sys


def parse_args():
    parser = argparse.ArgumentParser(
        description="Validate compiler pass timing output against a budget file."
    )
    parser.add_argument("--budget", required=True, help="Budget JSON path")
    parser.add_argument("--report", required=True, help="Timing report JSON path")
    parser.add_argument(
        "--allow-missing-cases",
        action="store_true",
        help="Skip case-level checks when a baseline case is absent in the report",
    )
    return parser.parse_args()


def load_json(path):
    with pathlib.Path(path).open("r", encoding="utf-8") as f:
        return json.load(f)


def percent_regression(current, baseline):
    if baseline <= 0:
        return 0.0 if current <= 0 else float("inf")
    return (current - baseline) * 100.0 / baseline


def get_report_scope(report):
    if "overall" in report:
        return report["overall"], {
            case["name"]: case["summary"] for case in report.get("cases", [])
        }
    return report, {}


def get_threshold(thresholds, new_key, old_key):
    if new_key in thresholds:
        return thresholds[new_key]
    return thresholds[old_key]


def main():
    args = parse_args()
    budget = load_json(args.budget)
    report = load_json(args.report)

    summary, case_summaries = get_report_scope(report)
    target_pass = budget["target_pass"]
    thresholds = budget["thresholds"]
    baseline = budget.get("baseline", {})
    errors = []

    pass_summary = summary.get("phases", {}).get(target_pass)
    if pass_summary is None:
        errors.append(f"report is missing target pass '{target_pass}'")
    else:
        observed_share = pass_summary["share_of_total_pct"].get(
            "p95", pass_summary["share_of_total_pct"]["max"]
        )
        max_share = get_threshold(
            thresholds, "max_pass_share_p95_pct", "max_pass_share_of_total_pct"
        )
        if observed_share > max_share:
            errors.append(
                f"{target_pass} share p95 {observed_share:.6f}% exceeds budget "
                f"{max_share:.6f}%"
            )

        observed_time = pass_summary.get("p95", pass_summary["max"])
        max_time = get_threshold(
            thresholds, "max_pass_time_p95_ms", "max_pass_time_ms"
        )
        if observed_time > max_time:
            errors.append(
                f"{target_pass} p95 time {observed_time:.6f} ms exceeds budget "
                f"{max_time:.6f} ms"
            )

    baseline_overall = baseline.get("overall_total_time_ms_median")
    if baseline_overall is not None:
        observed_overall = summary["total_time_ms"]["median"]
        regression = percent_regression(observed_overall, baseline_overall)
        max_regression = thresholds["max_overall_total_time_regression_pct"]
        if regression > max_regression:
            errors.append(
                "overall median compile time regression "
                f"{regression:.6f}% exceeds budget {max_regression:.6f}%"
            )

    max_case_regression = thresholds.get("max_case_total_time_regression_pct")
    for case_name, baseline_value in baseline.get("case_total_time_ms_median", {}).items():
        current_case = case_summaries.get(case_name)
        if current_case is None:
            if not args.allow_missing_cases:
                errors.append(f"report is missing baseline case '{case_name}'")
            continue
        regression = percent_regression(
            current_case["total_time_ms"]["median"], baseline_value
        )
        if regression > max_case_regression:
            errors.append(
                f"case '{case_name}' median compile time regression {regression:.6f}% "
                f"exceeds budget {max_case_regression:.6f}%"
            )

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print("compiler pass timing budget check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
