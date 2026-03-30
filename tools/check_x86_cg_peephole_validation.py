#!/usr/bin/env python3

import argparse
import json
import pathlib
import subprocess
import sys


ALLOWED_VALIDATION_MODES = {
    "structural",
    "semantics_model",
    "execution",
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Validate x86 peephole rule validation metadata."
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


def main():
    args = parse_args()
    data = load_rules(args.rules)
    errors = []
    mode_counts = {mode: 0 for mode in ALLOWED_VALIDATION_MODES}
    gtest_names = None
    if args.gtest_binary:
        gtest_names = load_gtest_names(args.gtest_binary)

    for rule in data.get("rules", []):
        name = rule.get("name", "<unnamed>")
        validation = rule.get("validation")
        if validation is None:
            errors.append(f"rule '{name}' is missing validation metadata")
            continue

        modes = validation.get("modes")
        if not isinstance(modes, list) or not modes:
            errors.append(f"rule '{name}' has no validation modes")
        else:
            has_non_structural_mode = False
            for mode in modes:
                if mode not in ALLOWED_VALIDATION_MODES:
                    errors.append(
                        f"rule '{name}' uses unknown validation mode '{mode}'"
                    )
                else:
                    mode_counts[mode] += 1
                    if mode != "structural":
                        has_non_structural_mode = True
            if rule.get("stage") == "instruction" and not has_non_structural_mode:
                errors.append(
                    f"rule '{name}' needs execution or semantics_model validation"
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

    print("x86 cg peephole validation metadata is complete")
    for mode in sorted(mode_counts):
        print(f"{mode}: {mode_counts[mode]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
