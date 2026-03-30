#!/usr/bin/env python3

import argparse
import json
import pathlib
from collections import Counter

from check_x86_cg_peephole_validation import load_gtest_names, load_rules


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate a validation coverage report for x86 peephole rules."
    )
    parser.add_argument("--rules", required=True, help="Path to the rule JSON file")
    parser.add_argument(
        "--gtest-binary",
        help="Optional gtest binary used to mark coverage entries as present",
    )
    parser.add_argument(
        "--out",
        help="Optional output path. Defaults to stdout when omitted.",
    )
    return parser.parse_args()


def build_rule_entry(rule, gtest_names):
    validation = rule.get("validation", {})
    coverage_entries = []
    all_present = True
    for name in validation.get("coverage", []):
        present = gtest_names is None or name in gtest_names
        coverage_entries.append({"name": name, "present": present})
        all_present = all_present and present

    return {
        "name": rule.get("name"),
        "stage": rule.get("stage"),
        "priority": rule.get("priority"),
        "modes": list(validation.get("modes", [])),
        "coverage": coverage_entries,
        "coverage_complete": all_present,
    }


def main():
    args = parse_args()
    data = load_rules(args.rules)
    gtest_names = load_gtest_names(args.gtest_binary) if args.gtest_binary else None

    stage_counts = Counter()
    mode_counts = Counter()
    rule_entries = []
    missing_coverage_count = 0

    for rule in data.get("rules", []):
        stage_counts[rule.get("stage", "<unknown>")] += 1
        for mode in rule.get("validation", {}).get("modes", []):
            mode_counts[mode] += 1

        entry = build_rule_entry(rule, gtest_names)
        if not entry["coverage_complete"]:
            missing_coverage_count += 1
        rule_entries.append(entry)

    report = {
        "summary": {
            "rule_count": len(rule_entries),
            "stage_counts": dict(sorted(stage_counts.items())),
            "mode_counts": dict(sorted(mode_counts.items())),
            "rules_with_missing_coverage": missing_coverage_count,
        },
        "rules": rule_entries,
    }

    output = json.dumps(report, indent=2) + "\n"
    if args.out:
        pathlib.Path(args.out).write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
