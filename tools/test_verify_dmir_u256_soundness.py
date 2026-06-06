#!/usr/bin/env python3
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import pathlib
import subprocess
import sys


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <source_dir>", file=sys.stderr)
        return 1
    source_dir = pathlib.Path(sys.argv[1])
    proc = subprocess.run(
        [
            sys.executable,
            str(source_dir / "tools/verify_dmir_u256_soundness.py"),
            "--rules",
            str(source_dir / "src/compiler/mir/dmir_rewrite_rules.json"),
        ],
        capture_output=True,
        text=True,
    )
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
