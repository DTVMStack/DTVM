#!/usr/bin/env python3

import argparse
import json
import pathlib


DEFAULT_THRESHOLDS = {
    "max_pass_share_p95_pct": 2.0,
    "max_pass_time_p95_ms": 0.05,
    "max_overall_total_time_regression_pct": 15.0,
    "max_case_total_time_regression_pct": 20.0,
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Refresh compiler pass timing budget baselines from a timing report."
    )
    parser.add_argument("--report", required=True, help="Timing report JSON path")
    parser.add_argument("--out", required=True, help="Budget JSON output path")
    parser.add_argument(
        "--budget-in",
        help="Existing budget JSON to preserve thresholds and metadata fields",
    )
    parser.add_argument(
        "--rules",
        help="Optional rule JSON path used to refresh the recorded rule count",
    )
    parser.add_argument(
        "--target-pass",
        default="x86_cg_peephole",
        help="Pass name recorded in the budget file",
    )
    parser.add_argument("--manifest", help="Manifest path to record in metadata")
    parser.add_argument("--runs", type=int, help="Run count to record in metadata")
    parser.add_argument(
        "--num-extra-compilations",
        type=int,
        help="Extra compilation count used during collection",
    )
    parser.add_argument(
        "--compile-mode",
        default="compile-only",
        help="Compile mode label recorded in metadata",
    )
    parser.add_argument(
        "--threshold-status",
        default="provisional",
        help="Threshold status label recorded in metadata",
    )
    return parser.parse_args()


def load_json(path):
    with pathlib.Path(path).open("r", encoding="utf-8") as f:
        return json.load(f)


def count_rules(path):
    return len(load_json(path).get("rules", []))


def normalize_thresholds(thresholds):
    if not thresholds:
        return dict(DEFAULT_THRESHOLDS)

    normalized = dict(thresholds)
    if "max_pass_share_p95_pct" not in normalized:
        normalized["max_pass_share_p95_pct"] = normalized.pop(
            "max_pass_share_of_total_pct", DEFAULT_THRESHOLDS["max_pass_share_p95_pct"]
        )
    if "max_pass_time_p95_ms" not in normalized:
        normalized["max_pass_time_p95_ms"] = normalized.pop(
            "max_pass_time_ms", DEFAULT_THRESHOLDS["max_pass_time_p95_ms"]
        )
    return normalized


def main():
    args = parse_args()
    report = load_json(args.report)
    prior_budget = load_json(args.budget_in) if args.budget_in else {}

    thresholds = normalize_thresholds(prior_budget.get("thresholds"))
    case_baselines = {}
    for case in report.get("cases", []):
        case_baselines[case["name"]] = case["summary"]["total_time_ms"]["median"]

    metadata = dict(prior_budget.get("metadata", {}))
    if args.manifest:
        metadata["manifest"] = args.manifest
    elif "manifest" in report:
        metadata["manifest"] = report["manifest"]
    if args.runs is not None:
        metadata["runs"] = args.runs
    elif "runs" in metadata:
        metadata["runs"] = metadata["runs"]
    if args.num_extra_compilations is not None:
        metadata["num_extra_compilations"] = args.num_extra_compilations
    if args.rules:
        metadata["rule_count"] = count_rules(args.rules)
    metadata["compile_mode"] = args.compile_mode
    metadata["thresholds_status"] = args.threshold_status

    budget = {
        "version": 1,
        "target_pass": args.target_pass,
        "thresholds": thresholds,
        "baseline": {
            "overall_total_time_ms_median": report["overall"]["total_time_ms"][
                "median"
            ],
            "case_total_time_ms_median": case_baselines,
        },
        "metadata": metadata,
    }

    pathlib.Path(args.out).write_text(
        json.dumps(budget, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(budget, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
