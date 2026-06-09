# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Limb-occupancy distribution report for Stream A (interpreter limb profile).

Stream A (ZEN_EVM_LIMB_PROFILE) emits one row per executed arithmetic operand:

    codehash,pc,opcode,operand_index,limb_width,limb_mask

`limb_mask` is the full 4-bit per-limb occupancy pattern of the uint256 operand
(little-endian limbs [V0,V1,V2,V3], V0 = low 64 bits): bit i is set iff limb Vi
is non-zero, so the value is in 0..15. Unlike the magnitude-collapsed
`limb_width`, the mask distinguishes a high-sparse value such as {0,x,0,0}
(mask 0b0010 = 2) from a dense u128 {x,x,0,0} (mask 0b0011 = 3).

This script produces the occupancy-distribution report:

  * the full 16-row distribution (one row per mask 0..15),
  * a grouped summary (ZERO / U64 / U128-DENSE / U192-U256-DENSE / HIGH-SPARSE /
    MID-GAP),
  * the high-sparse-vs-dense split among non-u64 operands (limb_width>=2),
  * each of the above under two weightings reported side by side:
      - execution-weighted: every Stream A row is one executed operand,
      - distinct-site-weighted: dedup by (codehash,pc,operand_index), taking the
        representative (majority) mask per site,
  * a per-opcode breakdown of the grouped summary.

The report is measurement-only and consumes the regenerated Stream A CSV.
"""

import argparse
import csv
import sys
from collections import Counter, defaultdict


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

# Human-readable label for each of the 16 limb masks. Bit0=V0 (low 64) ...
# bit3=V3 (high 64). A '1' digit is shown high-bit-first (V3 V2 V1 V0) to read
# like a binary literal.
MASK_LABELS = {
    0b0000: "0000 ZERO",
    0b0001: "0001 U64 (V0 low only)",
    0b0010: "0010 HIGH-SPARSE single (V1)",
    0b0100: "0100 HIGH-SPARSE single (V2)",
    0b1000: "1000 HIGH-SPARSE single (V3)",
    0b0011: "0011 U128-dense (V0,V1)",
    0b0111: "0111 U192-dense (V0,V1,V2)",
    0b1111: "1111 U256-dense (V0..V3)",
    0b0101: "0101 MID-GAP (V0,V2)",
    0b1001: "1001 MID-GAP (V0,V3)",
    0b1101: "1101 MID-GAP (V0,V2,V3; gap at V1)",
    0b1011: "1011 MID-GAP (V0,V1,V3; gap at V2)",
    0b0110: "0110 HIGH-SPARSE (V1,V2; low zero)",
    0b1010: "1010 HIGH-SPARSE (V1,V3; low zero)",
    0b1100: "1100 HIGH-SPARSE (V2,V3; low zero)",
    0b1110: "1110 HIGH-SPARSE (V1,V2,V3; low zero)",
}


def mask_label(mask):
    if mask in MASK_LABELS:
        return MASK_LABELS[mask]
    return "%s UNCLASSIFIED" % format(mask, "04b")


def classify_group(mask):
    """Map a 4-bit limb mask to one mutually-exclusive group.

    Groups:
      ZERO            mask == 0
      U64             only V0 set (mask == 0b0001)
      U128-DENSE      V0 and V1 set, V2 and V3 clear (mask == 0b0011)
      U192-U256-DENSE contiguous from V0 covering V2 or V3
                      (mask == 0b0111 or 0b1111)
      HIGH-SPARSE     V0 clear (low limb zero) and some higher limb set
      MID-GAP         V0 set, but a zero gap below a set higher limb
                      (e.g. 0b0101, 0b1001, 0b1101, 0b1011)
    """
    if mask == 0:
        return "ZERO"
    v0 = mask & 0b0001
    if mask == 0b0001:
        return "U64"
    if not v0:
        # low limb zero, some higher limb set -> high-sparse
        return "HIGH-SPARSE"
    # v0 is set from here on
    if mask == 0b0011:
        return "U128-DENSE"
    if mask in (0b0111, 0b1111):
        return "U192-U256-DENSE"
    # v0 set but not a contiguous dense prefix -> a zero gap sits below a set
    # higher limb (0b0101, 0b1001, 0b1011, 0b1101)
    return "MID-GAP"


GROUP_ORDER = [
    "ZERO",
    "U64",
    "U128-DENSE",
    "U192-U256-DENSE",
    "HIGH-SPARSE",
    "MID-GAP",
]


def read_stream_a(path):
    """Yield (codehash, pc, opcode, operand_index, limb_width, limb_mask)."""
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        if "limb_mask" not in (reader.fieldnames or []):
            raise SystemExit(
                "Stream A CSV %r has no limb_mask column; regenerate with the "
                "instrumented build (ZEN_EVM_LIMB_PROFILE)." % path
            )
        for r in reader:
            rows.append(
                (
                    r["codehash"],
                    int(r["pc"]),
                    int(r["opcode"]),
                    int(r["operand_index"]),
                    int(r["limb_width"]),
                    int(r["limb_mask"]),
                )
            )
    return rows


def site_representative_masks(rows):
    """Collapse execution rows to one representative mask per distinct site.

    A site is (codehash, pc, operand_index). The representative is the majority
    (most-frequently-observed) mask for that site; ties break toward the
    numerically smaller mask for determinism. Returns a list of (mask,
    limb_width, opcode) tuples, one per site, where limb_width is recomputed
    from the representative mask and opcode is the site's opcode (constant per
    pc)."""
    per_site = defaultdict(Counter)
    site_opcode = {}
    for codehash, pc, opcode, idx, _width, mask in rows:
        key = (codehash, pc, idx)
        per_site[key][mask] += 1
        site_opcode[key] = opcode
    out = []
    for key, counter in per_site.items():
        # majority mask; tie -> smaller mask
        best_mask = min(
            counter.items(), key=lambda kv: (-kv[1], kv[0])
        )[0]
        out.append((best_mask, width_from_mask(best_mask), site_opcode[key]))
    return out


def width_from_mask(mask):
    """Highest set limb position (0..4), matching limbWidth() semantics."""
    if mask & 0b1000:
        return 4
    if mask & 0b0100:
        return 3
    if mask & 0b0010:
        return 2
    if mask & 0b0001:
        return 1
    return 0


def mask_distribution(masks):
    """Return a Counter of mask -> count over an iterable of masks."""
    return Counter(masks)


def group_distribution(masks):
    """Return a Counter of group -> count."""
    c = Counter()
    for m in masks:
        c[classify_group(m)] += 1
    return c


def non_u64_split(items):
    """Among operands with limb_width>=2, count HIGH-SPARSE vs DENSE.

    `items` is an iterable of (mask, limb_width). DENSE means contiguous from
    V0 (group U128-DENSE or U192-U256-DENSE); HIGH-SPARSE means V0 is zero and
    some higher limb set; MID-GAP (V0 set but with a zero gap) is reported as a
    third bucket so the split sums to the non-u64 total."""
    high_sparse = 0
    dense = 0
    mid_gap = 0
    total = 0
    for mask, width in items:
        if width < 2:
            continue
        total += 1
        g = classify_group(mask)
        if g == "HIGH-SPARSE":
            high_sparse += 1
        elif g in ("U128-DENSE", "U192-U256-DENSE"):
            dense += 1
        else:
            # MID-GAP (V0 set with a gap) is neither cleanly dense nor
            # low-zero high-sparse.
            mid_gap += 1
    return high_sparse, dense, mid_gap, total


def pct(n, total):
    return (100.0 * n / total) if total else 0.0


def render_markdown(exec_rows, site_rows):
    """exec_rows: list of (codehash,pc,opcode,idx,width,mask).
    site_rows: list of (mask,width,opcode)."""
    exec_masks = [r[5] for r in exec_rows]
    site_masks = [r[0] for r in site_rows]

    exec_total = len(exec_masks)
    site_total = len(site_masks)

    exec_mask_dist = mask_distribution(exec_masks)
    site_mask_dist = mask_distribution(site_masks)
    exec_group_dist = group_distribution(exec_masks)
    site_group_dist = group_distribution(site_masks)

    exec_items = [(r[5], r[4]) for r in exec_rows]
    site_items = [(r[0], r[1]) for r in site_rows]
    e_hs, e_dense, e_mid, e_nonu64 = non_u64_split(exec_items)
    s_hs, s_dense, s_mid, s_nonu64 = non_u64_split(site_items)

    L = []
    L.append("# Limb-Occupancy Distribution Report")
    L.append("")
    L.append(
        "Full per-operand limb-occupancy pattern from the interpreter "
        "Stream A tap (ZEN_EVM_LIMB_PROFILE) over the 225-fixture mainnet "
        "replay corpus. Unlike the magnitude-collapsed `limb_width`, the "
        "4-bit `limb_mask` records which of the four 64-bit limbs "
        "(V0 low .. V3 high) are non-zero, so high-sparse values "
        "({0,x,0,0}) are distinguished from dense ones ({x,x,0,0})."
    )
    L.append("")
    L.append("Two weightings are reported side by side:")
    L.append("")
    L.append(
        "- **execution-weighted**: every Stream A row is one executed "
        "operand (hot loops dominate);"
    )
    L.append(
        "- **distinct-site-weighted**: dedup by (codehash, pc, "
        "operand_index), one representative (majority) mask per static site."
    )
    L.append("")
    L.append("| metric | execution-weighted | distinct-site-weighted |")
    L.append("|---|---:|---:|")
    L.append("| operand observations | %d | %d |" % (exec_total, site_total))
    L.append("")

    # ---- Grouped summary (the headline table) ----
    L.append("## Grouped occupancy summary")
    L.append("")
    L.append(
        "| group | exec count | exec % | site count | site % |"
    )
    L.append("|---|---:|---:|---:|---:|")
    for g in GROUP_ORDER:
        ec = exec_group_dist.get(g, 0)
        sc = site_group_dist.get(g, 0)
        L.append(
            "| %s | %d | %.2f%% | %d | %.2f%% |"
            % (g, ec, pct(ec, exec_total), sc, pct(sc, site_total))
        )
    L.append("")

    # ---- High-sparse vs dense among non-u64 ----
    L.append("## High-sparse vs dense among non-u64 operands (limb_width>=2)")
    L.append("")
    L.append(
        "Of the operands that do NOT fit in a single 64-bit limb, how many "
        "are HIGH-SPARSE (low limb zero, a higher limb set) versus DENSE "
        "(contiguous from V0)? MID-GAP (V0 set with a zero gap below a set "
        "high limb) is listed separately so the rows sum to the non-u64 "
        "total."
    )
    L.append("")
    L.append("| split | exec count | exec % of non-u64 | site count | site % of non-u64 |")
    L.append("|---|---:|---:|---:|---:|")
    L.append(
        "| HIGH-SPARSE | %d | %.2f%% | %d | %.2f%% |"
        % (e_hs, pct(e_hs, e_nonu64), s_hs, pct(s_hs, s_nonu64))
    )
    L.append(
        "| DENSE | %d | %.2f%% | %d | %.2f%% |"
        % (e_dense, pct(e_dense, e_nonu64), s_dense, pct(s_dense, s_nonu64))
    )
    L.append(
        "| MID-GAP | %d | %.2f%% | %d | %.2f%% |"
        % (e_mid, pct(e_mid, e_nonu64), s_mid, pct(s_mid, s_nonu64))
    )
    L.append(
        "| non-u64 total | %d | 100.00%% | %d | 100.00%% |"
        % (e_nonu64, s_nonu64)
    )
    L.append("")

    # ---- Full 16-row distribution ----
    L.append("## Full 16-mask distribution")
    L.append("")
    L.append("| mask | label | exec count | exec % | site count | site % |")
    L.append("|---:|---|---:|---:|---:|---:|")
    for m in range(16):
        ec = exec_mask_dist.get(m, 0)
        sc = site_mask_dist.get(m, 0)
        L.append(
            "| %d | %s | %d | %.2f%% | %d | %.2f%% |"
            % (m, mask_label(m), ec, pct(ec, exec_total), sc,
               pct(sc, site_total))
        )
    L.append("")

    # ---- Per-opcode grouped breakdown ----
    L.append("## Per-opcode grouped breakdown (execution-weighted)")
    L.append("")
    L.append(
        "Group counts per opcode, execution-weighted. SHL and MUL are the "
        "usual producers of high-sparse values; this breakdown shows where "
        "each occupancy class concentrates."
    )
    L.append("")
    by_op = defaultdict(lambda: Counter())
    op_total = Counter()
    for codehash, pc, opcode, idx, width, mask in exec_rows:
        by_op[opcode][classify_group(mask)] += 1
        op_total[opcode] += 1
    header = "| opcode | total | " + " | ".join(GROUP_ORDER) + " |"
    L.append(header)
    L.append("|---|---:|" + "---:|" * len(GROUP_ORDER))
    for opcode in sorted(by_op, key=lambda o: -op_total[o]):
        name = OPCODE_NAMES.get(opcode, "0x%02x" % opcode)
        cells = []
        for g in GROUP_ORDER:
            c = by_op[opcode].get(g, 0)
            cells.append("%d (%.0f%%)" % (c, pct(c, op_total[opcode])))
        L.append(
            "| %s | %d | %s |" % (name, op_total[opcode], " | ".join(cells))
        )
    L.append("")
    return "\n".join(L)


def write_raw_csv(path, exec_rows, site_rows):
    """Write the per-mask distribution under both weightings as a raw CSV."""
    exec_dist = mask_distribution([r[5] for r in exec_rows])
    site_dist = mask_distribution([r[0] for r in site_rows])
    exec_total = len(exec_rows)
    site_total = len(site_rows)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "limb_mask",
                "label",
                "group",
                "exec_count",
                "exec_pct",
                "site_count",
                "site_pct",
            ]
        )
        for m in range(16):
            ec = exec_dist.get(m, 0)
            sc = site_dist.get(m, 0)
            w.writerow(
                [
                    m,
                    mask_label(m),
                    classify_group(m),
                    ec,
                    "%.6f" % (ec / exec_total if exec_total else 0.0),
                    sc,
                    "%.6f" % (sc / site_total if site_total else 0.0),
                ]
            )


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stream-a", required=True, help="Stream A limb CSV")
    ap.add_argument("--out-md", default="limb_occupancy_report.md")
    ap.add_argument("--out-csv", default="limb_occupancy.csv")
    args = ap.parse_args(argv)

    exec_rows = read_stream_a(args.stream_a)
    site_rows = site_representative_masks(exec_rows)

    md = render_markdown(exec_rows, site_rows)
    with open(args.out_md, "w") as f:
        f.write(md + "\n")
    write_raw_csv(args.out_csv, exec_rows, site_rows)

    sys.stdout.write(md + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
