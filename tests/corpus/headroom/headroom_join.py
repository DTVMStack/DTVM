# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Offline joiner for the dual-tap analysis-precision instrumentation.

Stream A (interpreter, ZEN_EVM_LIMB_PROFILE) emits dynamic 64-bit limb widths
per executed arithmetic operand:

    codehash,pc,opcode,operand_index,limb_width

Stream B (JIT, ZEN_EVM_RANGE_PROFILE) emits the static value-range and the
operand source-kind per compiled arithmetic site:

    codehash,pc,opcode,lhs_range,rhs_range,lhs_source,rhs_source

This script joins the two streams on (codehash, pc, opcode) and reports, per
source-kind and per opcode, how much narrow-width headroom the static analyzer
left on the table:

    dynamic_u64_rate        fraction of Stream A operand rows with limb_width<=1
    analyzer_proved_u64_rate fraction of Stream B operand slots proved U64
    missed_headroom         dynamic_u64_rate - analyzer_proved_u64_rate

A positive missed_headroom means values that are *dynamically* small were not
*statically* proven small, i.e. recoverable optimization opportunity.
"""

import argparse
import csv
import json
import os
import sys
from collections import defaultdict


OPCODE_NAMES = {
    0x01: "ADD",
    0x02: "MUL",
    0x03: "SUB",
    0x04: "DIV",
    0x05: "SDIV",
    0x06: "MOD",
    0x07: "SMOD",
    0x08: "ADDMOD",
    0x09: "MULMOD",
    0x0A: "EXP",
    0x0B: "SIGNEXTEND",
    0x10: "LT",
    0x11: "GT",
    0x12: "SLT",
    0x13: "SGT",
    0x14: "EQ",
    0x15: "ISZERO",
    0x16: "AND",
    0x17: "OR",
    0x18: "XOR",
    0x19: "NOT",
    0x1A: "BYTE",
    0x1B: "SHL",
    0x1C: "SHR",
    0x1D: "SAR",
}


def opcode_name(op):
    try:
        op_int = int(op)
    except (TypeError, ValueError):
        return str(op)
    return OPCODE_NAMES.get(op_int, "0x%02x" % op_int)


def read_stream_a(path):
    """Return list of dicts for Stream A rows."""
    rows = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            rows.append(
                {
                    "codehash": r["codehash"],
                    "pc": int(r["pc"]),
                    "opcode": int(r["opcode"]),
                    "operand_index": int(r["operand_index"]),
                    "limb_width": int(r["limb_width"]),
                }
            )
    return rows


def read_stream_b(path):
    """Return list of dicts for Stream B rows (one per compiled arith site)."""
    rows = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            rows.append(
                {
                    "codehash": r["codehash"],
                    "pc": int(r["pc"]),
                    "opcode": int(r["opcode"]),
                    "lhs_range": r["lhs_range"],
                    "rhs_range": r["rhs_range"],
                    "lhs_source": r["lhs_source"],
                    "rhs_source": r["rhs_source"],
                }
            )
    return rows


def dedup_stream_b(rows):
    """One static row per (codehash, pc, opcode). Static facts do not vary
    across compiles, so the last seen row wins."""
    by_key = {}
    for r in rows:
        by_key[(r["codehash"], r["pc"], r["opcode"])] = r
    return by_key


def histogram_stream_a(rows):
    """Per (codehash, pc, opcode), per operand_index: a (u64_count, total)
    limb-width histogram. limb_width<=1 counts as "fits u64" (0 == the value
    zero, also fits)."""
    hist = defaultdict(lambda: defaultdict(lambda: [0, 0]))  # key -> idx -> [u64,total]
    for r in rows:
        key = (r["codehash"], r["pc"], r["opcode"])
        cell = hist[key][r["operand_index"]]
        cell[1] += 1
        if r["limb_width"] <= 1:
            cell[0] += 1
    return hist


def load_manifest(path):
    """Optional manifest.json: map code_address -> app_class. The manifest
    schema is owned by the replay tooling; we read defensively."""
    if not path or not os.path.exists(path):
        return {}
    with open(path) as f:
        data = json.load(f)
    mapping = {}
    entries = data.get("entries", data) if isinstance(data, dict) else data
    if isinstance(entries, dict):
        entries = entries.values()
    for e in entries:
        if not isinstance(e, dict):
            continue
        addr = e.get("code_address") or e.get("address")
        cls = e.get("app_class") or e.get("class")
        if addr and cls:
            mapping[str(addr).lower()] = cls
    return mapping


def load_app_class_map(path):
    """Optional FNV-1a-codehash -> app_class bridge. The stream codehash is the
    FNV-1a hash emitted by the taps (a 16-hex-char string), which does NOT
    equal the manifest's keccak codehash; this map is built offline by hashing
    each fixture's target-contract code with the same FNV-1a. Returns {} when
    no path is given."""
    if not path or not os.path.exists(path):
        return {}
    with open(path) as f:
        data = json.load(f)
    if not isinstance(data, dict):
        return {}
    return {str(k).lower(): v for k, v in data.items()}


def build_cross_table(stream_a, stream_b, app_class_map=None):
    """Join Stream A histogram with deduped Stream B per (codehash,pc,opcode).

    Produces one row per matched operand slot:
        codehash, pc, opcode, operand_index, source_kind,
        dynamic_u64_rate, analyzer_proved_u64 (0/1)
    Only keys present in BOTH streams are emitted (the join is the point).
    """
    b_by_key = dedup_stream_b(stream_b)
    a_hist = histogram_stream_a(stream_a)

    table = []
    for key, per_idx in a_hist.items():
        if key not in b_by_key:
            continue
        b = b_by_key[key]
        codehash, pc, opcode = key
        # Map operand_index -> (range, source) for slots 0/1 of Stream B.
        slots = {
            0: (b["lhs_range"], b["lhs_source"]),
            1: (b["rhs_range"], b["rhs_source"]),
        }
        for idx, (u64_count, total) in sorted(per_idx.items()):
            if total == 0:
                continue
            dyn_rate = u64_count / total
            rng, src = slots.get(idx, (None, None))
            if rng is None:
                # Stream A has a third operand (ternary), no Stream B slot.
                continue
            row = {
                "codehash": codehash,
                "pc": pc,
                "opcode": opcode,
                "operand_index": idx,
                "source_kind": src,
                "dynamic_u64_rate": dyn_rate,
                "analyzer_proved_u64": 1 if rng == "U64" else 0,
            }
            if app_class_map is not None:
                row["app_class"] = app_class_map.get(codehash.lower(), "unknown")
            table.append(row)
    return table


def aggregate(table, group_field):
    """Aggregate the cross-table by a single field, producing the headroom
    columns. Each operand slot contributes equally."""
    buckets = defaultdict(lambda: {"n": 0, "dyn": 0.0, "proved": 0})
    for row in table:
        b = buckets[row[group_field]]
        b["n"] += 1
        b["dyn"] += row["dynamic_u64_rate"]
        b["proved"] += row["analyzer_proved_u64"]
    out = []
    for k, b in buckets.items():
        if b["n"] == 0:
            continue
        dyn_rate = b["dyn"] / b["n"]
        proved_rate = b["proved"] / b["n"]
        out.append(
            {
                group_field: k,
                "slots": b["n"],
                "dynamic_u64_rate": dyn_rate,
                "analyzer_proved_u64_rate": proved_rate,
                "missed_headroom": dyn_rate - proved_rate,
            }
        )
    out.sort(key=lambda r: r["missed_headroom"], reverse=True)
    return out


def headline_ratio(table):
    """Overall runtime_narrow_but_static_unknown_ratio.

    Each operand slot carries a dynamic-u64 mass (dynamic_u64_rate, in [0,1]).
    The numerator sums the dynamic-u64 mass sitting on slots the analyzer did
    NOT prove U64; the denominator is the total dynamic-u64 mass. The ratio is
    therefore "of all arith operand-slot mass that is dynamically u64, the
    fraction the static analyzer left unproven" -- recoverable headroom.

    Returns (ratio, dyn_u64_mass, unproven_dyn_u64_mass, n_slots). The ratio is
    0.0 when there is no dynamic-u64 mass."""
    dyn_mass = 0.0
    unproven_mass = 0.0
    for r in table:
        dyn_mass += r["dynamic_u64_rate"]
        if not r["analyzer_proved_u64"]:
            unproven_mass += r["dynamic_u64_rate"]
    ratio = (unproven_mass / dyn_mass) if dyn_mass > 0 else 0.0
    return ratio, dyn_mass, unproven_mass, len(table)


def render_markdown(
    by_source,
    by_opcode,
    n_keys_a,
    n_keys_b,
    n_shared,
    headline=None,
    by_app_class=None,
):
    lines = []
    lines.append("# Analysis-Precision Headroom Report")
    lines.append("")
    lines.append(
        "Joins interpreter dynamic limb-width (Stream A) with JIT static "
        "value-range (Stream B) on (codehash, pc, opcode)."
    )
    lines.append("")

    if headline is not None:
        ratio, dyn_mass, unproven_mass, n_slots = headline
        lines.append("## Headline")
        lines.append("")
        lines.append(
            "**runtime_narrow_but_static_unknown_ratio = %.3f** "
            "(%.1f of %.1f dynamic-u64 slot-mass left unproven over %d joined "
            "operand slots)." % (ratio, unproven_mass, dyn_mass, n_slots)
        )
        lines.append("")

    lines.append("## Join coverage")
    lines.append("")
    lines.append("| metric | value |")
    lines.append("|---|---|")
    lines.append("| Stream A distinct (codehash,pc,opcode) | %d |" % n_keys_a)
    lines.append("| Stream B distinct (codehash,pc,opcode) | %d |" % n_keys_b)
    lines.append("| shared keys (joined) | %d |" % n_shared)
    lines.append("")

    def fmt_table(rows, label):
        out = ["## Headroom by %s" % label, ""]
        out.append(
            "| %s | slots | dynamic_u64_rate | analyzer_proved_u64_rate "
            "| missed_headroom |" % label
        )
        out.append("|---|---:|---:|---:|---:|")
        for r in rows:
            if label == "opcode":
                key = opcode_name(r["opcode"])
            else:
                key = r.get(label, r.get("source_kind", r.get("opcode")))
            out.append(
                "| %s | %d | %.3f | %.3f | %.3f |"
                % (
                    key,
                    r["slots"],
                    r["dynamic_u64_rate"],
                    r["analyzer_proved_u64_rate"],
                    r["missed_headroom"],
                )
            )
        out.append("")
        return out

    lines += fmt_table(by_source, "source_kind")
    lines += fmt_table(by_opcode, "opcode")
    if by_app_class is not None:
        lines += fmt_table(by_app_class, "app_class")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stream-a", required=True, help="Stream A limb CSV")
    ap.add_argument("--stream-b", required=True, help="Stream B range CSV")
    ap.add_argument("--manifest", default=None, help="optional manifest.json")
    ap.add_argument("--app-class-map", default=None,
                    help="optional FNV-1a-codehash -> app_class JSON bridge")
    ap.add_argument("--out-md", default="headroom_report.md")
    ap.add_argument("--out-csv", default="headroom_table.csv")
    args = ap.parse_args(argv)

    a = read_stream_a(args.stream_a)
    b = read_stream_b(args.stream_b)

    app_class_map = load_app_class_map(args.app_class_map)
    table = build_cross_table(a, b, app_class_map or None)

    a_keys = {(r["codehash"], r["pc"], r["opcode"]) for r in a}
    b_keys = {(r["codehash"], r["pc"], r["opcode"]) for r in b}
    shared = a_keys & b_keys

    by_source = aggregate(table, "source_kind")
    by_opcode = aggregate(table, "opcode")
    by_app_class = aggregate(table, "app_class") if app_class_map else None
    headline = headline_ratio(table)

    md = render_markdown(by_source, by_opcode, len(a_keys), len(b_keys),
                         len(shared), headline=headline,
                         by_app_class=by_app_class)
    with open(args.out_md, "w") as f:
        f.write(md + "\n")

    cols = [
        "codehash",
        "pc",
        "opcode",
        "operand_index",
        "source_kind",
        "dynamic_u64_rate",
        "analyzer_proved_u64",
    ]
    if app_class_map:
        cols.append("app_class")
    with open(args.out_csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for r in table:
            row = [
                r["codehash"],
                r["pc"],
                r["opcode"],
                r["operand_index"],
                r["source_kind"],
                "%.6f" % r["dynamic_u64_rate"],
                r["analyzer_proved_u64"],
            ]
            if app_class_map:
                row.append(r.get("app_class", "unknown"))
            w.writerow(row)

    sys.stdout.write(md + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
