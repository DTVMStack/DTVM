#!/usr/bin/env python3

import argparse
import json
import pathlib
import subprocess
import sys

from mine_dmir_seed_rules import build_candidate_key, parse_expr


ALLOWED_RULE_STATUSES = {
    "seed",
    "candidate",
    "accepted",
}

ALLOWED_VALIDATION_MODES = {
    "interpreter_sample",
    "interpreter_fuzz",
    "smt",
}

COST_FIELDS = (
    "dmir_inst",
    "select_depth",
    "adc_chain",
    "runtime_calls",
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Validate dMIR rewrite candidate metadata."
    )
    parser.add_argument("--rules", required=True, help="Path to the rule JSON file")
    parser.add_argument(
        "--gtest-binary",
        help="Optional gtest binary used to verify coverage entries exist",
    )
    return parser.parse_args()


def load_rules(path):
    with pathlib.Path(path).open("r", encoding="utf-8") as f:
        return json.load(f)


def load_gtest_names(path):
    proc = subprocess.run(
        [str(pathlib.Path(path).resolve()), "--gtest_list_tests"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"failed to list gtests from {path}")

    names = set()
    suite_name = None
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        if not line.startswith("  "):
            suite_name = line.strip().rstrip(".")
            continue
        if suite_name is None:
            continue
        test_name = line.strip().split()[0]
        test_name = test_name.split("#", 1)[0]
        names.add(f"{suite_name}.{test_name}")
    return names


def validate_cost(name, cost, errors):
    if not isinstance(cost, dict):
        errors.append(f"rule '{name}' has invalid cost metadata")
        return

    for section in ("lhs", "rhs", "delta"):
        section_cost = cost.get(section)
        if not isinstance(section_cost, dict):
            errors.append(f"rule '{name}' is missing cost section '{section}'")
            continue
        for field in COST_FIELDS:
            value = section_cost.get(field)
            if not isinstance(value, int):
                errors.append(
                    f"rule '{name}' has non-integer cost field '{section}.{field}'"
                )


def main():
    args = parse_args()
    data = load_rules(args.rules)
    errors = []
    seen_names = set()
    seen_rule_keys = {}
    mode_counts = {mode: 0 for mode in ALLOWED_VALIDATION_MODES}
    gtest_names = load_gtest_names(args.gtest_binary) if args.gtest_binary else None

    for rule in data.get("rules", []):
        name = rule.get("name", "<unnamed>")
        if name in seen_names:
            errors.append(f"duplicate dMIR rule name '{name}'")
            continue
        seen_names.add(name)

        status = rule.get("status")
        if status not in ALLOWED_RULE_STATUSES:
            errors.append(f"rule '{name}' has invalid status '{status}'")

        inputs = rule.get("inputs")
        if not isinstance(inputs, list) or not inputs or any(
            not isinstance(item, str) or not item.strip() for item in inputs
        ):
            errors.append(f"rule '{name}' has invalid inputs metadata")
        elif len(set(inputs)) != len(inputs):
            errors.append(f"rule '{name}' repeats input bindings")

        for field in ("lhs", "rhs"):
            value = rule.get(field)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"rule '{name}' is missing '{field}'")

        lhs = rule.get("lhs")
        rhs = rule.get("rhs")
        if isinstance(lhs, str) and lhs.strip() and isinstance(rhs, str) and rhs.strip():
            try:
                canonical_key = build_candidate_key(parse_expr(lhs), parse_expr(rhs))
            except ValueError as exc:
                errors.append(f"rule '{name}' has invalid expression syntax: {exc}")
            else:
                existing_name = seen_rule_keys.get(canonical_key)
                if existing_name is not None:
                    errors.append(
                        "rule "
                        f"'{name}' duplicates canonical rewrite '{existing_name}'"
                    )
                else:
                    seen_rule_keys[canonical_key] = name

        validate_cost(name, rule.get("cost"), errors)

        validation = rule.get("validation")
        if not isinstance(validation, dict):
            errors.append(f"rule '{name}' is missing validation metadata")
            continue

        modes = validation.get("modes")
        if not isinstance(modes, list) or not modes:
            errors.append(f"rule '{name}' has no validation modes")
        else:
            has_semantic_mode = False
            for mode in modes:
                if mode not in ALLOWED_VALIDATION_MODES:
                    errors.append(
                        f"rule '{name}' uses unknown validation mode '{mode}'"
                    )
                    continue
                mode_counts[mode] += 1
                if mode in {"interpreter_fuzz", "smt"}:
                    has_semantic_mode = True
            if not has_semantic_mode:
                errors.append(
                    f"rule '{name}' needs interpreter_fuzz or smt validation"
                )

        coverage = validation.get("coverage")
        if not isinstance(coverage, list) or not coverage:
            errors.append(f"rule '{name}' has no validation coverage entries")
        else:
            for entry in coverage:
                if not isinstance(entry, str) or not entry.strip():
                    errors.append(f"rule '{name}' has an invalid coverage entry")
                elif gtest_names is not None and entry not in gtest_names:
                    errors.append(
                        f"rule '{name}' references missing gtest coverage '{entry}'"
                    )

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print("dmir rewrite rule metadata is complete")
    for mode in sorted(mode_counts):
        print(f"{mode}: {mode_counts[mode]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
