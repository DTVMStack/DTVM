# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/env python3
"""Test wrapper for collect_compiler_pass_timings.py.

Called by CMakeLists.txt as:
    test_collect_compiler_pass_timings.py <source_dir> <dtvm_binary>
"""

import json
import pathlib
import subprocess
import sys
import tempfile


def main():
    if len(sys.argv) != 3:
        print(
            "usage: test_collect_compiler_pass_timings.py <source_dir> <dtvm_binary>",
            file=sys.stderr,
        )
        return 1

    source_dir = pathlib.Path(sys.argv[1]).resolve()
    dtvm_binary = pathlib.Path(sys.argv[2]).resolve()

    collector = source_dir / "tools" / "collect_compiler_pass_timings.py"
    manifest = source_dir / "tests" / "evm_asm" / "compiler_pass_timing_manifest.json"

    if not collector.exists():
        print(f"collector not found: {collector}", file=sys.stderr)
        return 1
    if not manifest.exists():
        print(f"manifest not found: {manifest}", file=sys.stderr)
        return 1
    if not dtvm_binary.exists():
        print(f"dtvm binary not found: {dtvm_binary}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as tmp_dir:
        output_path = pathlib.Path(tmp_dir) / "timing_report.json"

        # Use --case to select only a single small case (add) for speed.
        cmd = [
            sys.executable,
            str(collector),
            "--dtvm",
            str(dtvm_binary),
            "--manifest",
            str(manifest),
            "--runs",
            "1",
            "--case",
            "add",
            "--output",
            str(output_path),
            "--",
            "--format",
            "evm",
            "--mode",
            "multipass",
            "--compile-only",
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
                f"FAIL: test_collect_compiler_pass_timings — collector exited with "
                f"code {result.returncode}",
                file=sys.stderr,
            )
            return 1

        if not output_path.exists():
            print(
                "FAIL: test_collect_compiler_pass_timings — output JSON was not written",
                file=sys.stderr,
            )
            return 1

        try:
            report = json.loads(output_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(
                f"FAIL: test_collect_compiler_pass_timings — invalid JSON: {exc}",
                file=sys.stderr,
            )
            return 1

        # Required top-level fields for a manifest run
        for field in ("manifest", "case_count", "cases", "overall"):
            if field not in report:
                print(
                    f"FAIL: test_collect_compiler_pass_timings — missing field '{field}'",
                    file=sys.stderr,
                )
                return 1

        overall = report["overall"]
        for field in ("runs", "record_count", "total_time_ms", "phases"):
            if field not in overall:
                print(
                    f"FAIL: test_collect_compiler_pass_timings — overall missing "
                    f"field '{field}'",
                    file=sys.stderr,
                )
                return 1

        total_time = overall["total_time_ms"]
        for stat in ("mean", "median"):
            if stat not in total_time:
                print(
                    f"FAIL: test_collect_compiler_pass_timings — "
                    f"total_time_ms missing stat '{stat}'",
                    file=sys.stderr,
                )
                return 1

    print("PASS: test_collect_compiler_pass_timings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
