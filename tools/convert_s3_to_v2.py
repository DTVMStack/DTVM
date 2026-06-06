#!/usr/bin/env python3
"""Convert S3 extension pattern_config rules into DSL v2 JSON format.

Pipeline:
1. Load S3 synth output (tools/synthesize_dmir_rules.py --out ...).
2. Filter to source=="pattern_config" (the 110 prod-aware rules).
3. Drop any rule whose LHS/RHS shape cannot be expressed in DSL v2.
4. Dedup by canonical LHS s-expression against the current v2 rules JSON
   (alpha-rename + commutative-root sort) — keep our rule only if not
   already covered by an existing hand/synth rule.
5. Dedup internally by same canonical key — collapse duplicate LHS with
   different RHS (Z3 admits both, but generator only needs one).
6. Emit DSL v2 fragment with status="pattern_synth", origin="s3_auto_synth".
   Names prefixed with "s3pat_" to avoid collisions.

Usage:
  python3 tools/convert_s3_to_v2.py \\
      --s3-output /tmp/s3_output.json \\
      --existing-v2 src/compiler/mir/dmir_rewrite_rules_v2.json \\
      --out /tmp/s3_v2_ready.json \\
      --dropped-log /tmp/s3_dropped.log
"""
import argparse
import json
import pathlib
import re
import sys
from collections import Counter


# --- Tiny s-expression parser ---
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


def is_atom(n):
    return isinstance(n, str)


def is_const_atom(n):
    return isinstance(n, str) and ":" in n


# --- DSL v2 capability set (from tools/generate_dmir_rewrite.py) ---
BINARY_OPS = {"add", "sub", "mul", "and", "or", "xor", "shl", "sshr", "ushr"}
UNARY_OPS = {"not"}
LHS_ROOT_OPS = BINARY_OPS | UNARY_OPS | {"select", "adc", "sbb"}
COMMUTATIVE_OPS = {"add", "mul", "and", "or", "xor"}
# RHS ops allowed: binary + unary not. No select/adc/sbb as RHS constructors.
RHS_OPS = BINARY_OPS | UNARY_OPS


def rhs_supported(expr):
    if is_atom(expr):
        return True, None
    op, args = expr
    if op not in RHS_OPS:
        return False, f"RHS op '{op}' not supported by DSL v2"
    for a in args:
        ok, reason = rhs_supported(a)
        if not ok:
            return False, reason
    return True, None


def lhs_supported(expr):
    if is_atom(expr):
        return False, "LHS must be s-expr"
    op, args = expr
    if op not in LHS_ROOT_OPS:
        return False, f"LHS root '{op}' not supported"
    return True, None


# --- Canonical LHS key (for dedup) ---
def _alpha_rename(expr, mapping=None):
    if mapping is None:
        mapping = {}
    if is_atom(expr):
        if is_const_atom(expr):
            return expr
        # variable → canonical name x1/x2/...
        if expr not in mapping:
            mapping[expr] = f"x{len(mapping)}"
        return mapping[expr]
    op, args = expr
    new_args = tuple(_alpha_rename(a, mapping) for a in args)
    # Canonicalize commutative root by sorting operands (recursive-safe since
    # children already renamed)
    if op in COMMUTATIVE_OPS and len(new_args) == 2:
        rendered = sorted(new_args, key=lambda x: _render(x))
        new_args = tuple(rendered)
    return (op, new_args)


def _render(expr):
    if is_atom(expr):
        return expr
    op, args = expr
    return "(" + op + " " + " ".join(_render(a) for a in args) + ")"


def canon_lhs_key(lhs_str: str) -> str:
    tree = parse_sexpr(lhs_str)
    renamed = _alpha_rename(tree)
    return _render(renamed)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--s3-output", required=True,
                    help="S3 synth output JSON (contains 110 pattern_config rules)")
    ap.add_argument("--existing-v2", required=True,
                    help="current dmir_rewrite_rules_v2.json")
    ap.add_argument("--out", required=True,
                    help="output v2 fragment (pattern_config rules only)")
    ap.add_argument("--dropped-log", required=True,
                    help="per-rule drop reason log (markdown)")
    args = ap.parse_args()

    s3 = json.loads(pathlib.Path(args.s3_output).read_text())
    all_rules = s3["rules"]
    pc = [r for r in all_rules if r.get("source") == "pattern_config"]
    print(f"loaded {len(pc)} pattern_config rules", file=sys.stderr)

    existing = json.loads(pathlib.Path(args.existing_v2).read_text())
    existing_keys = set()
    for r in existing["rules"]:
        if "lhs" not in r:  # hook-only rules have no LHS
            continue
        existing_keys.add(canon_lhs_key(r["lhs"]))
    print(f"existing v2 rules: {len(existing['rules'])} ({len(existing_keys)} canonical LHS keys)",
          file=sys.stderr)

    dropped_log_lines = ["# Dropped pattern_config rules during S3→v2 conversion", ""]

    # First pass: DSL expressibility + identity filter
    # Identity rules (LHS ≡ RHS after alpha-rename) are never useful: the
    # generator would emit code that allocates a clone on every match,
    # inflating the hit counter and burning compile time.
    expressible = []
    dropped_unsupported = []
    dropped_identity = []
    for r in pc:
        lhs_tree = parse_sexpr(r["lhs"])
        rhs_tree = parse_sexpr(r["rhs"]) if "(" in r["rhs"] else r["rhs"]
        lok, lreason = lhs_supported(lhs_tree)
        rok, rreason = rhs_supported(rhs_tree)
        if not (lok and rok):
            dropped_unsupported.append((r, lreason or rreason))
            continue
        # Identity check: compare canonical (alpha-renamed) LHS vs RHS render
        lhs_canon = _render(_alpha_rename(lhs_tree))
        rhs_canon = (_render(_alpha_rename(rhs_tree))
                     if not is_atom(rhs_tree) else rhs_tree)
        if lhs_canon == rhs_canon:
            dropped_identity.append(r)
            continue
        expressible.append(r)
    print(f"DSL-expressible (non-identity): {len(expressible)}/{len(pc)}", file=sys.stderr)
    print(f"  dropped-unsupported: {len(dropped_unsupported)}", file=sys.stderr)
    print(f"  dropped-identity: {len(dropped_identity)}", file=sys.stderr)
    if dropped_unsupported:
        dropped_log_lines.append("## Unsupported shape (DSL v2 cannot express)")
        dropped_log_lines.append("")
        for r, reason in dropped_unsupported:
            dropped_log_lines.append(f"- `{r['name']}`: `{r['lhs']}` -> `{r['rhs']}`  ({reason})")
        dropped_log_lines.append("")
    if dropped_identity:
        dropped_log_lines.append("## Identity rule (LHS ≡ RHS after alpha-rename)")
        dropped_log_lines.append("")
        for r in dropped_identity:
            dropped_log_lines.append(f"- `{r['name']}`: `{r['lhs']}` -> `{r['rhs']}` (no-op)")
        dropped_log_lines.append("")

    # Second pass: dedup against existing + within
    kept = []
    dropped_dup_existing = []
    dropped_dup_within = []
    seen_keys = dict(existing_keys and {k: "existing" for k in existing_keys})
    # Maintain a dict of canon_key -> source
    for r in expressible:
        key = canon_lhs_key(r["lhs"])
        if key in existing_keys:
            dropped_dup_existing.append((r, key))
            continue
        if key in seen_keys and seen_keys[key] != "existing":
            dropped_dup_within.append((r, key, seen_keys[key]))
            continue
        seen_keys[key] = r["name"]
        kept.append(r)

    print(f"dedup: {len(kept)} kept, {len(dropped_dup_existing)} dup-existing, "
          f"{len(dropped_dup_within)} dup-within", file=sys.stderr)

    if dropped_dup_existing:
        dropped_log_lines.append("## Duplicate of existing v2 rule (same canonical LHS)")
        dropped_log_lines.append("")
        for r, key in dropped_dup_existing:
            dropped_log_lines.append(f"- `{r['name']}`: `{r['lhs']}` -> `{r['rhs']}`  "
                                     f"(canon key: `{key}`)")
        dropped_log_lines.append("")

    if dropped_dup_within:
        dropped_log_lines.append("## Duplicate within pattern_config (first occurrence kept)")
        dropped_log_lines.append("")
        for r, key, first in dropped_dup_within:
            dropped_log_lines.append(f"- `{r['name']}`: `{r['lhs']}` -> `{r['rhs']}`  "
                                     f"(canon key: `{key}`, first-seen: `{first}`)")
        dropped_log_lines.append("")

    # Emit v2 fragment
    out_rules = []
    for r in kept:
        # Normalize name: replace '-' with '_' and prefix
        norm_name = "s3pat_" + r["name"].replace("-", "_")
        out_rules.append({
            "name": norm_name,
            "status": "pattern_synth",      # distinct bucket for hit counting
            "origin": "s3_auto_synth",
            "lhs": r["lhs"],
            "rhs": r["rhs"],
            "cost": r["cost"],
            "validation": {"modes": ["smt", "prod_canonical_lhs"], "coverage": []},
        })

    pathlib.Path(args.out).write_text(
        json.dumps({"version": 2, "rules": out_rules}, indent=2))
    pathlib.Path(args.dropped_log).write_text("\n".join(dropped_log_lines) + "\n")

    print(f"wrote {len(out_rules)} rules to {args.out}", file=sys.stderr)
    print(f"wrote drop log to {args.dropped_log}", file=sys.stderr)

    # Summary to stdout (so the caller can capture it)
    summary = {
        "input_pattern_config": len(pc),
        "dsl_expressible": len(expressible),
        "dropped_unsupported": len(dropped_unsupported),
        "dropped_identity": len(dropped_identity),
        "dropped_dup_existing": len(dropped_dup_existing),
        "dropped_dup_within": len(dropped_dup_within),
        "kept_for_merge": len(kept),
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
