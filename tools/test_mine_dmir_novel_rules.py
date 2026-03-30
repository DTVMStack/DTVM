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
    rules_path = source_dir / "src/compiler/mir/dmir_rewrite_rules.json"
    bootstrap_config = source_dir / "src/compiler/mir/dmir_rewrite_mining_bootstrap.json"

    if not rules_path.exists():
        print(f"Rules file not found: {rules_path}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = pathlib.Path(tmpdir)
        out_path = tmpdir / "novel_candidates.json"

        proc = run_miner(source_dir, ["--rules", str(rules_path), "--out", str(out_path)])
        if proc.returncode != 0:
            print("FAIL: miner exited non-zero", file=sys.stderr)
            print(proc.stderr, file=sys.stderr)
            return 1
        try:
            result = json.loads(out_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"FAIL: output is not valid JSON: {exc}", file=sys.stderr)
            return 1

        summary = result["summary"]

        if summary["covered_candidate_count"] == 0:
            print("FAIL: expected some candidates covered by the real rules file",
                  file=sys.stderr)
            return 1

        if (summary["covered_candidate_count"] + summary["novel_candidate_count"]
                != summary["curated_candidate_count"]):
            print("FAIL: covered + novel != curated", file=sys.stderr)
            return 1

        if summary["novel_candidate_count"] >= summary["curated_candidate_count"]:
            print("FAIL: novel_candidate_count should be < curated_candidate_count",
                  file=sys.stderr)
            return 1

        covered_lhs_set = {entry["lhs"] for entry in result["covered_candidates"]}
        if "(add x 0:i64)" not in covered_lhs_set:
            print("FAIL: '(add x 0:i64)' should appear in covered_candidates", file=sys.stderr)
            return 1

        for entry in result["novel_candidates"]:
            if entry.get("covered_by_rule_repo") is not False:
                print(f"FAIL: novel candidate '{entry.get('lhs')}' has wrong "
                      "covered_by_rule_repo", file=sys.stderr)
                return 1

        for entry in result["covered_candidates"]:
            if entry.get("covered_by_rule_repo") is not True:
                print(f"FAIL: covered candidate '{entry.get('lhs')}' has wrong "
                      "covered_by_rule_repo", file=sys.stderr)
                return 1

        if bootstrap_config.exists():
            out_path2 = tmpdir / "novel_bootstrap.json"
            proc2 = run_miner(source_dir, [
                "--rules", str(rules_path),
                "--config", str(bootstrap_config),
                "--out", str(out_path2),
            ])
            if proc2.returncode != 0:
                print("FAIL: miner failed with --rules + --config", file=sys.stderr)
                print(proc2.stderr, file=sys.stderr)
                return 1
            result2 = json.loads(out_path2.read_text(encoding="utf-8"))
            if result2["summary"]["config_supplied"] is not True:
                print("FAIL: config_supplied should be true with --config", file=sys.stderr)
                return 1
            if result2["summary"]["covered_candidate_count"] == 0:
                print("FAIL: expected some covered candidates with bootstrap + rules",
                      file=sys.stderr)
                return 1

    print("PASS: test_mine_dmir_novel_rules")
    return 0


if __name__ == "__main__":
    sys.exit(main())
