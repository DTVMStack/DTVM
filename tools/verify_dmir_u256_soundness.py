#!/usr/bin/env python3
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import argparse
import json
import pathlib
import sys

import z3


def parse_args():
    parser = argparse.ArgumentParser(
        description="Replay Z3 proofs for production U256 dMIR rewrite rules."
    )
    parser.add_argument(
        "--rules",
        default="src/compiler/mir/dmir_rewrite_rules.json",
        help="Path to dMIR rewrite rule JSON",
    )
    return parser.parse_args()


def prove_xor_self_zero(rule):
    x = z3.BitVec("x", 256)
    lhs = x ^ x
    rhs = z3.BitVecVal(0, 256)
    solver = z3.Solver()
    solver.add(lhs != rhs)
    result = solver.check()
    if result != z3.unsat:
        raise RuntimeError(f"{rule['name']} expected unsat, got {result}")


def main():
    args = parse_args()
    data = json.loads(pathlib.Path(args.rules).read_text(encoding="utf-8"))
    proved = []
    for rule in data.get("rules", []):
        if rule.get("name") != "u256-xor-self-zero":
            continue
        if rule.get("status") != "synthesized-u256":
            raise RuntimeError("u256-xor-self-zero has unexpected status")
        if rule.get("ir_width") != 256:
            raise RuntimeError("u256-xor-self-zero has unexpected ir_width")
        if rule.get("lhs") != "(u256_xor x x)":
            raise RuntimeError("u256-xor-self-zero has unexpected lhs")
        if rule.get("rhs") != "(const_u256 0)":
            raise RuntimeError("u256-xor-self-zero has unexpected rhs")
        if "smt_256" not in rule.get("validation", {}).get("modes", []):
            raise RuntimeError("u256-xor-self-zero is missing smt_256 validation")
        prove_xor_self_zero(rule)
        proved.append(rule["name"])

    if proved != ["u256-xor-self-zero"]:
        raise RuntimeError("u256-xor-self-zero rule not found")
    print("PASS: proved U256 dMIR rules: " + ", ".join(proved))
    return 0


if __name__ == "__main__":
    sys.exit(main())
