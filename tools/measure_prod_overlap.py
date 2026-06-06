#!/usr/bin/env python3
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Measure alpha-renamed LHS overlap between synth output and prod dMIR rules.

Usage:
  python3 tools/measure_prod_overlap.py <synth.json> [--threshold 60]

Use --exclude-ir-width 256 to preserve the scalar-limb denominator when the
production rule set also contains separate U256 composite rules.

Delegates s-expression parsing to ``tools/mine_dmir_seed_rules.py`` and
applies a commute-equivalent canonicalisation that sorts operands of
commutative ops BEFORE alpha-renaming. Two prod rule names may therefore
map to the same canonical pattern key (e.g. ``add-y-neg-x-to-sub-y-x``
and ``add-neg-x-y-to-sub-y-x``); in that case both are considered matched
when synth emits a single representative of the class.

Threshold semantics: ``--threshold`` gates on the matched *canonical
pattern* count, not the nominal name count, because the two prod names in
a commute-equivalent pair are not independently targetable by synth.
"""
import argparse
import json
import pathlib as _pl
import sys as _sys
from collections import defaultdict

# Ensure sibling tools/ modules are importable when this script is run directly.
_sys.path.insert(0, str(_pl.Path(__file__).parent))
from mine_dmir_seed_rules import (  # noqa: E402
    COMMUTATIVE_OPS,
    Expr,
    canonical_var_name,
    parse_expr,
    var,
)


def _sort_commute_first(expr: Expr) -> Expr:
    """Recursively sort commutative-op operands by raw render. Runs before
    alpha-rename so the rename order becomes canonical across commutative
    variants."""
    if expr.op in ("var", "const", "const_u256"):
        return expr
    args = tuple(_sort_commute_first(a) for a in expr.args)
    if expr.op in COMMUTATIVE_OPS:
        args = tuple(sorted(args, key=lambda a: a.render()))
    return Expr(expr.op, args=args)


def _alpha_rename(expr: Expr, env: dict[str, str]) -> Expr:
    if expr.op == "var":
        name = str(expr.value)
        if name not in env:
            env[name] = canonical_var_name(len(env))
        return var(env[name])
    if expr.op in {"const", "const_u256"}:
        return expr
    return Expr(expr.op, args=tuple(_alpha_rename(a, env) for a in expr.args))


def _canonical_lhs_key(lhs_str: str) -> str:
    """Commute-sort then alpha-rename, so commutative-variant prod entries
    collapse into a single canonical key."""
    e = parse_expr(lhs_str)
    e = _sort_commute_first(e)
    env: dict[str, str] = {}
    return _alpha_rename(e, env).render()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("synth_json")
    ap.add_argument("--prod-json",
                    default="src/compiler/mir/dmir_rewrite_rules.json")
    ap.add_argument("--threshold", type=int, default=0,
                    help=("Minimum matched prod *canonical patterns* "
                          "required for exit 0"))
    ap.add_argument("--include-ir-width", type=int, default=None)
    ap.add_argument("--exclude-ir-width", type=int, default=None)
    args = ap.parse_args()

    with open(args.prod_json) as f:
        prod = json.load(f)["rules"]
    if args.include_ir_width is not None:
        prod = [rule for rule in prod
                if rule.get("ir_width") == args.include_ir_width]
    if args.exclude_ir_width is not None:
        prod = [rule for rule in prod
                if rule.get("ir_width") != args.exclude_ir_width]
    prod_key_to_names: dict[str, list[str]] = defaultdict(list)
    for r in prod:
        prod_key_to_names[_canonical_lhs_key(r["lhs"])].append(r["name"])

    with open(args.synth_json) as f:
        synth = json.load(f)
    synth_rules = (synth["rules"]
                   if isinstance(synth, dict) and "rules" in synth
                   else synth)
    synth_keys: set[str] = set()
    for r in synth_rules:
        lhs = r["lhs"] if isinstance(r, dict) else r[0]
        synth_keys.add(_canonical_lhs_key(lhs))

    matched_keys = {k for k in prod_key_to_names if k in synth_keys}
    matched_names = [n for k in matched_keys for n in prod_key_to_names[k]]
    unmatched_names = [n for k, names in prod_key_to_names.items()
                       if k not in synth_keys for n in names]

    total_names = sum(len(v) for v in prod_key_to_names.values())
    total_patterns = len(prod_key_to_names)

    print(f"Prod rules (names): {total_names}")
    print(f"Prod unique canonical patterns: {total_patterns}")
    print(f"Synth unique canonical LHS keys: {len(synth_keys)}")
    print(f"Matched prod unique patterns: "
          f"{len(matched_keys)}/{total_patterns} = "
          f"{100 * len(matched_keys) / total_patterns:.1f}%")
    print(f"Matched prod names: {len(matched_names)}/{total_names}")
    if unmatched_names:
        print(f"Unmatched ({len(unmatched_names)}): "
              f"{unmatched_names[:20]}"
              + ("..." if len(unmatched_names) > 20 else ""),
              file=_sys.stderr)
    _sys.exit(0 if len(matched_keys) >= args.threshold else 1)


if __name__ == "__main__":
    main()
