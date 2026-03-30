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
    bootstrap_config = source_dir / "src/compiler/mir/dmir_rewrite_mining_bootstrap.json"

    if not bootstrap_config.exists():
        print(f"Bootstrap config not found: {bootstrap_config}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = pathlib.Path(tmpdir)
        out_path = tmpdir / "bootstrap_candidates.json"

        # Test 1: run with bootstrap config
        proc = run_miner(source_dir, [
            "--config", str(bootstrap_config),
            "--out", str(out_path),
        ])
        if proc.returncode != 0:
            print("FAIL: miner exited non-zero with bootstrap config", file=sys.stderr)
            print(proc.stderr, file=sys.stderr)
            return 1
        try:
            result = json.loads(out_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"FAIL: output is not valid JSON: {exc}", file=sys.stderr)
            return 1

        # Test 2: config_supplied is true
        if result["summary"].get("config_supplied") is not True:
            print("FAIL: config_supplied should be true when --config is used", file=sys.stderr)
            return 1

        # Test 3: structural validity
        for key in ("summary", "candidates", "curated_candidates",
                    "covered_candidates", "novel_candidates"):
            if key not in result:
                print(f"FAIL: output missing key '{key}'", file=sys.stderr)
                return 1
        for key in ("term_count", "sample_count", "candidate_count",
                    "curated_candidate_count", "covered_candidate_count",
                    "novel_candidate_count", "config_supplied"):
            if key not in result["summary"]:
                print(f"FAIL: summary missing key '{key}'", file=sys.stderr)
                return 1

        # Test 4: bootstrap config adds mul terms, so more terms than default
        default_out = tmpdir / "default_candidates.json"
        proc2 = run_miner(source_dir, ["--out", str(default_out)])
        if proc2.returncode != 0:
            print("FAIL: default miner failed", file=sys.stderr)
            return 1
        default_result = json.loads(default_out.read_text(encoding="utf-8"))
        if result["summary"]["term_count"] <= default_result["summary"]["term_count"]:
            print("FAIL: bootstrap config should produce more terms than default",
                  file=sys.stderr)
            return 1

        # Test 5: bootstrap-specific candidates exist (mul identities)
        lhs_set = {entry["lhs"] for entry in result["curated_candidates"]}
        bootstrap_expected = {"(mul x 0:i64)", "(mul x 1:i64)"}
        for expected_lhs in bootstrap_expected:
            if expected_lhs not in lhs_set:
                print(f"FAIL: expected bootstrap candidate '{expected_lhs}' not found",
                      file=sys.stderr)
                return 1

    print("PASS: test_mine_dmir_bootstrap_config")
    return 0


if __name__ == "__main__":
    sys.exit(main())
