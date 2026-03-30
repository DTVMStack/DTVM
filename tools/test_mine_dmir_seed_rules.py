#!/usr/bin/env python3
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import pathlib
import subprocess
import sys
import tempfile


def run_miner(source_dir, extra_args=()):
    script = pathlib.Path(source_dir) / "tools" / "mine_dmir_seed_rules.py"
    cmd = [sys.executable, str(script)] + list(extra_args)
    return subprocess.run(cmd, capture_output=True, text=True)


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <source_dir>", file=sys.stderr)
        return 1

    source_dir = pathlib.Path(sys.argv[1])

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = pathlib.Path(tmpdir)
        out_path = tmpdir / "seed_candidates.json"

        # Test 1: basic seed mode run
        proc = run_miner(source_dir, ["--out", str(out_path)])
        if proc.returncode != 0:
            print("FAIL: miner exited non-zero", file=sys.stderr)
            print(proc.stderr, file=sys.stderr)
            return 1
        if not out_path.exists():
            print("FAIL: output file not created", file=sys.stderr)
            return 1
        try:
            result = json.loads(out_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"FAIL: output is not valid JSON: {exc}", file=sys.stderr)
            return 1

        # Test 2: required top-level keys
        for key in ("summary", "candidates", "curated_candidates",
                    "covered_candidates", "novel_candidates"):
            if key not in result:
                print(f"FAIL: output missing top-level key '{key}'", file=sys.stderr)
                return 1

        summary = result["summary"]
        for key in ("term_count", "sample_count", "candidate_count",
                    "curated_candidate_count", "covered_candidate_count",
                    "novel_candidate_count", "config_supplied"):
            if key not in summary:
                print(f"FAIL: summary missing key '{key}'", file=sys.stderr)
                return 1

        if summary["term_count"] <= 0:
            print("FAIL: term_count should be > 0", file=sys.stderr)
            return 1
        if summary["sample_count"] <= 0:
            print("FAIL: sample_count should be > 0", file=sys.stderr)
            return 1

        # Test 3: no rules supplied -> nothing covered
        if summary["covered_candidate_count"] != 0:
            print("FAIL: covered_candidate_count should be 0 without --rules", file=sys.stderr)
            return 1
        if summary["config_supplied"] is not False:
            print("FAIL: config_supplied should be false without --config", file=sys.stderr)
            return 1

        # Test 4: candidate entries have lhs, rhs, cost
        for entry in result["curated_candidates"]:
            for field in ("lhs", "rhs", "cost"):
                if field not in entry:
                    print(f"FAIL: candidate entry missing field '{field}'", file=sys.stderr)
                    return 1

        # Test 5: a known identity appears - (add x 0:i64) -> x
        lhs_set = {entry["lhs"] for entry in result["curated_candidates"]}
        if "(add x 0:i64)" not in lhs_set:
            print("FAIL: expected '(add x 0:i64)' in curated candidates", file=sys.stderr)
            return 1

        # Test 6: novel_candidate_count == curated_candidate_count (no rules supplied)
        if summary["novel_candidate_count"] != summary["curated_candidate_count"]:
            print("FAIL: without --rules, novel count should equal curated count",
                  file=sys.stderr)
            return 1

        # Test 7: stdout mode
        proc2 = run_miner(source_dir)
        if proc2.returncode != 0:
            print("FAIL: miner failed writing to stdout", file=sys.stderr)
            return 1
        try:
            json.loads(proc2.stdout)
        except json.JSONDecodeError as exc:
            print(f"FAIL: stdout is not valid JSON: {exc}", file=sys.stderr)
            return 1

    print("PASS: test_mine_dmir_seed_rules")
    return 0


if __name__ == "__main__":
    sys.exit(main())
