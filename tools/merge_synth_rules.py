#!/usr/bin/env python3
"""Merge synthesized dMIR rewrite candidates into dmir_rewrite_rules_v2.json.

Pipeline:
1. Load synth_report_depth2.json (458 candidates).
2. Apply Algorithm A: drop 0-var rules, structural subsumption dedup.
3. Optionally cap to top-K.
4. Emit entries in DSL v2 format (they already use compatible s-expression
   LHS/RHS and cost metadata, so conversion is almost identity).
5. Merge into existing rules JSON (append after hand-migrated rules).
"""
import argparse
import json
import pathlib
import re
import sys
from typing import Optional


# --- Tiny s-expression parser (kept standalone to avoid importing mine) ---
def tokenize(s):
    return re.findall(r"\(|\)|[^\s()]+", s)


def parse(tokens, i=0):
    if tokens[i] == "(":
        op, i = tokens[i + 1], i + 2
        args = []
        while tokens[i] != ")":
            a, i = parse(tokens, i)
            args.append(a)
        return (op, tuple(args)), i + 1
    return tokens[i], i + 1


def parse_sexpr(s):
    tree, _ = parse(tokenize(s.strip()), 0)
    return tree


def is_atom(t):
    return isinstance(t, str)


def is_var_atom(t):
    return isinstance(t, str) and t in ("x", "y", "z", "a", "b", "cond", "cf")


def vars_of(t, acc=None):
    if acc is None:
        acc = set()
    if is_var_atom(t):
        acc.add(t)
    elif not is_atom(t):
        for a in t[1]:
            vars_of(a, acc)
    return acc


def serialize(t):
    if is_atom(t):
        return t
    return "(" + t[0] + " " + " ".join(serialize(a) for a in t[1]) + ")"


def match(pattern, target, bindings):
    if is_var_atom(pattern):
        if pattern in bindings:
            return bindings[pattern] == target
        bindings[pattern] = target
        return True
    if is_atom(pattern):
        return is_atom(target) and pattern == target
    if is_atom(target) or pattern[0] != target[0] or len(pattern[1]) != len(target[1]):
        return False
    for a, b in zip(pattern[1], target[1]):
        if not match(a, b, bindings):
            return False
    return True


def subsumes(r1_lhs, r1_rhs, r2_lhs, r2_rhs):
    bindings = {}
    if not match(r1_lhs, r2_lhs, bindings):
        return False

    def subst(t):
        if is_var_atom(t):
            return bindings.get(t, t)
        if is_atom(t):
            return t
        return (t[0], tuple(subst(a) for a in t[1]))

    return subst(r1_rhs) == r2_rhs


def apply_algorithm_a(rules):
    parsed = []
    for r in rules:
        parsed.append(
            {
                "orig": r,
                "lhs": parse_sexpr(r["lhs"]),
                "rhs": parse_sexpr(r["rhs"]) if "(" in r["rhs"] else r["rhs"],
            }
        )

    # Filter 1: drop 0-var (constant fold)
    filt1 = [p for p in parsed if len(vars_of(p["lhs"])) >= 1]

    # Filter 2: structural subsumption
    keep = [True] * len(filt1)
    for i, a in enumerate(filt1):
        if not keep[i]:
            continue
        for j, b in enumerate(filt1):
            if i == j or not keep[j]:
                continue
            if subsumes(a["lhs"], a["rhs"], b["lhs"], b["rhs"]):
                if len(vars_of(a["lhs"])) >= len(vars_of(b["lhs"])):
                    keep[j] = False
    return [filt1[i]["orig"] for i in range(len(filt1)) if keep[i]]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--synth", required=True, help="synth_report_depth2.json")
    ap.add_argument("--out", required=True, help="output v2 JSON fragment (synth rules only)")
    ap.add_argument("--cap", type=int, default=0, help="cap top-K (0 = no cap)")
    ap.add_argument("--prefix", default="synth_", help="rule name prefix in output")
    args = ap.parse_args()

    synth = json.loads(pathlib.Path(args.synth).read_text())
    rules = synth["rules"]
    print(f"loaded {len(rules)} candidates from {args.synth}", file=sys.stderr)

    filtered = apply_algorithm_a(rules)
    print(f"after Algorithm A (drop-0-var + subsumption): {len(filtered)}", file=sys.stderr)

    if args.cap > 0:
        filtered = filtered[: args.cap]
        print(f"capped to top-{args.cap}", file=sys.stderr)

    out_rules = []
    for r in filtered:
        out_rules.append(
            {
                "name": args.prefix + r["name"].replace("-", "_"),
                "status": "synthesized",
                "origin": "synthesized_depth2",
                "lhs": r["lhs"],
                "rhs": r["rhs"],
                "cost": r["cost"],
                "validation": {"modes": ["smt"], "coverage": []},
            }
        )

    pathlib.Path(args.out).write_text(json.dumps({"version": 2, "rules": out_rules}, indent=2))
    print(f"wrote {len(out_rules)} rules to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
