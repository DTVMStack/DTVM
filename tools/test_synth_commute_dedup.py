#!/usr/bin/env python3
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Guard: synth output must not contain commutative-variant duplicates."""
import json
import pathlib
import re
import subprocess
import sys
import tempfile
from collections import Counter

_COMM_OPS = {"add", "and", "or", "xor", "mul"}
_TOKEN_RE = re.compile(r"\(|\)|[^\s()]+")


def _commute_key(s: str) -> str:
    toks = _TOKEN_RE.findall(s)
    pos = [0]

    def walk():
        tok = toks[pos[0]]
        pos[0] += 1
        if tok == "(":
            op = toks[pos[0]]
            pos[0] += 1
            args = []
            while toks[pos[0]] != ")":
                args.append(walk())
            pos[0] += 1
            if op in _COMM_OPS:
                args = sorted(args)
            return "(" + op + " " + " ".join(args) + ")"
        return tok

    return walk()


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <source_dir>", file=sys.stderr)
        return 1
    source_dir = pathlib.Path(sys.argv[1])
    with tempfile.TemporaryDirectory() as tmpdir:
        out = pathlib.Path(tmpdir) / "synth.json"
        subprocess.run(
            [sys.executable, str(source_dir / "tools/synthesize_dmir_rules.py"),
             "--max-depth", "2", "--out", str(out)],
            check=True, capture_output=True, text=True,
        )
        data = json.load(open(out))
        rules = data["rules"] if isinstance(data, dict) else data
        keys = Counter()
        for r in rules:
            keys[(_commute_key(r["lhs"]), _commute_key(r["rhs"]))] += 1
        dups = {k: v for k, v in keys.items() if v > 1}
        if dups:
            print(f"FAIL: {len(dups)} commutative-variant duplicates:",
                  file=sys.stderr)
            for k, v in list(dups.items())[:5]:
                print(f"  {k} x{v}", file=sys.stderr)
            return 1
        print(f"PASS: no commute-variant duplicates in {len(rules)} rules")
        return 0


if __name__ == "__main__":
    sys.exit(main())
