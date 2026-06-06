#!/usr/bin/env python3
"""Convert s3_synth_output.json (1966 Z3-admitted candidates) into records
that satisfy src/compiler/mir/dmir_rewrite_rules.json's schema.

The script does NOT promote rules to production; it only normalizes
metadata so check_dmir_rewrite_rules.py can validate the candidate set
during Phase 0b.3. Phase 5 admission still requires hand-coding each
chosen rule into a rewrite helper and assigning a real gtest coverage
entry.

Schema gaps closed:
  - status:        "synthesized" -> "candidate"
  - ir_width:      missing       -> 64
  - validation.coverage: empty   -> [coverage_default]

Filtered out (unless --allow-carry-select):
  - LHS containing adc / sbb / select (current generator cannot emit
    these without hand authoring; also not a target for Phase 0b)

Usage:
  python3 tools/convert_synth_to_schema.py \\
    --input  artifacts/s3_synth_output.json \\
    --output /tmp/converted_1966.json \\
    --coverage-default synthetic_e9_audit \\
    --report data/conversion_stats.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

UNSUPPORTED_TOKEN_RE = re.compile(r"\b(adc|sbb|select)\b")


def _has_unsupported_shape(lhs: str) -> bool:
    return bool(UNSUPPORTED_TOKEN_RE.search(lhs))


def build_dup_map(converted: list[dict], prod_rules_path: str) -> dict[str, str]:
    """Map each candidate name to the production rule sharing exact (lhs, rhs).

    Production rules are matched by string equality on both lhs and rhs.
    Hook-only production rules (no lhs field) are skipped.
    """
    raw = json.loads(Path(prod_rules_path).read_text())
    prod_rules = raw["rules"] if isinstance(raw, dict) and "rules" in raw else raw
    by_lhs_rhs: dict[tuple, str] = {}
    for r in prod_rules:
        lhs = r.get("lhs")
        rhs = r.get("rhs")
        if lhs is None or rhs is None:
            continue
        # First-wins: production order is the canonical preference.
        by_lhs_rhs.setdefault((lhs, rhs), r["name"])
    out: dict[str, str] = {}
    for c in converted:
        key = (c.get("lhs"), c.get("rhs"))
        if key in by_lhs_rhs:
            out[c["name"]] = by_lhs_rhs[key]
    return out


def convert_record(synth: dict, coverage_default: str, allow_carry_select: bool):
    lhs = synth.get("lhs", "")
    if _has_unsupported_shape(lhs) and not allow_carry_select:
        return None, "unsupported_shape"
    inputs = list(synth.get("inputs") or [])
    if not inputs:
        # Pure constant-folding rules (no symbolic inputs) are out of scope
        # for the peephole pass (handled at IR build time) and the production
        # validator rejects empty inputs lists.
        return None, "constant_fold_no_inputs"

    validation = synth.get("validation") or {}
    modes = list(validation.get("modes") or ["smt"])
    coverage = list(validation.get("coverage") or [])
    if not coverage:
        coverage = [coverage_default]

    cost = synth.get("cost") or {}
    record: dict[str, Any] = {
        "name": synth["name"],
        "status": "candidate",
        "inputs": inputs,
        "ir_width": 64,
        "lhs": lhs,
        "rhs": synth.get("rhs", ""),
        "cost": cost,
        "validation": {"modes": modes, "coverage": coverage},
        "metadata": {
            "from_artifact": "s3_synth_output.json",
            "synth_status": synth.get("status", "synthesized"),
            "source": synth.get("source"),
        },
    }
    return record, None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", required=True, help="path to s3_synth_output.json")
    ap.add_argument("--output", required=True, help="path to write converted JSON")
    ap.add_argument(
        "--coverage-default",
        default="synthetic_e9_audit",
        help="placeholder coverage entry injected when validation.coverage is empty",
    )
    ap.add_argument(
        "--allow-carry-select",
        action="store_true",
        help="keep candidates whose LHS uses adc/sbb/select (default: drop)",
    )
    ap.add_argument(
        "--report",
        default=None,
        help="optional path to write conversion stats JSON",
    )
    ap.add_argument(
        "--prod-rules",
        default=None,
        help="path to dmir_rewrite_rules_v2.json; when given, emit dup_to_prod_map",
    )
    ap.add_argument(
        "--dup-map-output",
        default=None,
        help="path to write candidate->prod-rule-name JSON map",
    )
    args = ap.parse_args(argv)

    raw = json.loads(Path(args.input).read_text())
    rules = raw["rules"] if isinstance(raw, dict) and "rules" in raw else raw

    converted: list[dict] = []
    skipped: list[dict] = []
    skip_breakdown: dict[str, int] = {}
    for r in rules:
        rec, reason = convert_record(
            r, args.coverage_default, args.allow_carry_select
        )
        if rec is None:
            skipped.append({"name": r.get("name"), "reason": reason})
            skip_breakdown[reason] = skip_breakdown.get(reason, 0) + 1
        else:
            converted.append(rec)

    output = {
        "version": SCHEMA_VERSION,
        "rules": converted,
        "skipped": skipped,
    }
    Path(args.output).write_text(json.dumps(output, indent=2))

    print(
        f"Converted: {len(converted)}/{len(rules)}; "
        f"skipped: {len(skipped)} ({skip_breakdown}).",
        file=sys.stderr,
    )

    if args.report:
        skipped_examples = skipped[:10]
        Path(args.report).write_text(
            json.dumps(
                {
                    "input_count": len(rules),
                    "converted_count": len(converted),
                    "skipped_count": len(skipped),
                    "skip_breakdown": skip_breakdown,
                    "skipped_examples": skipped_examples,
                },
                indent=2,
            )
        )

    if args.dup_map_output:
        if not args.prod_rules:
            print(
                "error: --dup-map-output requires --prod-rules",
                file=sys.stderr,
            )
            return 1
        dup_map = build_dup_map(converted, args.prod_rules)
        Path(args.dup_map_output).write_text(json.dumps(dup_map, indent=2))
        print(
            f"Dup map: {len(dup_map)} candidates mapped to prod rules.",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
