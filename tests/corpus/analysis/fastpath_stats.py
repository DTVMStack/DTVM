# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Per-opcode fast-path hit-rate report for the JIT lowering-path tap.

The Stream B tap (ZEN_EVM_RANGE_PROFILE), extended with a `path` column, emits
one row per *compiled* arithmetic/compare/bitwise site:

    codehash,pc,opcode,lhs_range,rhs_range,lhs_source,rhs_source,path

`path` is the lowering path the JIT handler actually committed to for that site,
one of:

    CONST_U64    const-specialized u64 fast path
    NARROW_U64   both-operands-fit-u64 narrow fast path
    NARROW_U128  u128 fast path (e.g. MUL bothFitU64 -> u128)
    FULL         full 4-limb / 256-bit path (no fast path)

This script computes, per opcode, the FAST-PATH HIT RATE: the fraction of sites
(or executions) whose path is not FULL, plus the per-path breakdown.

Two weightings are produced:

  * SITE-weighted: over distinct (codehash, pc) static sites.
  * EXECUTION-weighted: each site joined to its exec_count from the runtime
    site histogram, then weighted by executions.

The histogram (site_histogram.csv) carries one row per
(codehash, pc, operand_index); this script sums exec_count over operand_index
to get a single execution weight per (codehash, pc) site.

Measurement-only: consumes the regenerated Stream B CSV and the histogram CSV;
emits a markdown report and a raw per-opcode CSV.
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

# Path enum names, in report column order. Must match the C++ LoweringPath enum
# names emitted by the visitor's pathName().
PATHS = ["FOLDED", "CONST_U64", "NARROW_U64", "NARROW_U128", "FULL"]
FAST_PATHS = ["CONST_U64", "NARROW_U64", "NARROW_U128"]

# Columns this script reads, looked up by name from the CSV header so a column
# reorder or insertion does not silently shift the reads.
STREAM_B_REQUIRED = ["codehash", "pc", "opcode", "path"]


def opcode_name(opcode):
    return OPCODE_NAMES.get(opcode, "0x%02x" % opcode)


def read_stream_b(path):
    """Read Stream B rows; return one (path) per distinct (codehash,pc) site.

    A static site is (codehash, pc); the tap fires once per compiled site, so a
    site normally appears once. If a (codehash, pc) appears more than once
    (e.g. a contract compiled twice with identical code), the representative is
    the majority path; ties break toward the path that ranks first in PATHS for
    determinism.

    Guards against a torn final CSV line on process exit: any data row that
    does not reach the highest required column index is dropped and counted.
    Extra trailing columns are tolerated for CSV compatibility.

    Returns (sites, dropped) where sites maps (codehash, pc) -> (opcode, path).
    """
    per_site_paths = defaultdict(Counter)
    per_site_opcode = {}
    dropped = 0
    rank = {p: i for i, p in enumerate(PATHS)}
    with open(path, newline="") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if header is None:
            raise SystemExit("Stream B CSV %r is empty." % path)
        missing = [c for c in STREAM_B_REQUIRED if c not in header]
        if missing:
            raise SystemExit(
                "Stream B CSV %r missing column(s) %s; regenerate with the "
                "instrumented build (ZEN_EVM_RANGE_PROFILE)."
                % (path, ", ".join(missing))
            )
        col = {name: header.index(name) for name in STREAM_B_REQUIRED}
        min_fields = max(col.values()) + 1
        for fields in reader:
            # Drop torn final lines that do not reach every required column;
            # extra trailing columns (e.g. lhs_const/rhs_const) are tolerated.
            if len(fields) < min_fields:
                dropped += 1
                continue
            codehash = fields[col["codehash"]]
            try:
                pc = int(fields[col["pc"]])
                opcode = int(fields[col["opcode"]])
            except ValueError:
                dropped += 1
                continue
            p = fields[col["path"]]
            if p not in rank:
                dropped += 1
                continue
            key = (codehash, pc)
            per_site_paths[key][p] += 1
            per_site_opcode[key] = opcode
    sites = {}
    for key, counter in per_site_paths.items():
        best = min(counter.items(), key=lambda kv: (-kv[1], rank[kv[0]]))[0]
        sites[key] = (per_site_opcode[key], best)
    return sites, dropped


def read_histogram(path):
    """Return (codehash, pc) -> summed exec_count over operand_index."""
    weights = Counter()
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            key = (r["codehash"], int(r["pc"]))
            weights[key] += int(r["exec_count"])
    return weights


def aggregate(sites, weights):
    """Aggregate per opcode under both weightings.

    Returns:
      site_stats: opcode -> Counter(path -> distinct-site count)
      exec_stats: opcode -> Counter(path -> summed exec_count)
      unmatched_sites: number of sites with no histogram exec_count match
      unmatched_by_opcode: opcode -> count of unmatched sites
    """
    site_stats = defaultdict(Counter)
    exec_stats = defaultdict(Counter)
    unmatched_sites = 0
    unmatched_by_opcode = Counter()
    for (codehash, pc), (opcode, p) in sites.items():
        site_stats[opcode][p] += 1
        w = weights.get((codehash, pc))
        if w is None:
            unmatched_sites += 1
            unmatched_by_opcode[opcode] += 1
            continue
        exec_stats[opcode][p] += w
    return site_stats, exec_stats, unmatched_sites, unmatched_by_opcode


def pct(n, total):
    return (100.0 * n / total) if total else 0.0


def fast_count(counter):
    return sum(counter.get(p, 0) for p in FAST_PATHS)


def total_count(counter):
    return sum(counter.get(p, 0) for p in PATHS)


def render_markdown(site_stats, exec_stats, unmatched_sites,
                    unmatched_by_opcode, dropped, fixture_count):
    L = []
    L.append("# Per-Opcode Fast-Path Hit-Rate Report")
    L.append("")
    L.append(
        "Which lowering path the multipass JIT actually emitted for each "
        "compiled arithmetic / compare / bitwise site, aggregated per opcode, "
        "over the %d-fixture mainnet replay corpus. The path is read back from "
        "the builder after each handler commits to a path; opcodes with no "
        "narrow/const fast path record FULL for every site, so their hit rate "
        "is honestly 0." % fixture_count
    )
    L.append("")
    L.append(
        "Fast-path hit rate = fraction of sites (or executions) whose path is "
        "CONST_U64/NARROW (a runtime fast path). FOLDED is reported "
        "separately: both operands constant, computed at compile time, no "
        "runtime op. FULL is genuine 256-bit runtime arithmetic. Paths: "
        "FOLDED, CONST_U64 (const-specialized), NARROW_U64 (both-fit-u64), "
        "NARROW_U128 (u128 fast path), FULL (256-bit)."
    )
    L.append("")
    L.append("Two weightings:")
    L.append("")
    L.append(
        "- **SITE-weighted**: over distinct (codehash, pc) static sites — one "
        "vote per compiled site."
    )
    L.append(
        "- **EXECUTION-weighted**: each site joined to its exec_count from the "
        "runtime site histogram (summed over operand_index), then weighted by "
        "executions. Sites with no histogram match are dropped from the "
        "execution column (see note below)."
    )
    L.append("")
    if dropped:
        L.append(
            "Note: %d Stream B data row(s) had an unexpected field count "
            "(torn final line guard) and were dropped." % dropped
        )
        L.append("")
    L.append(
        "Note: %d distinct site(s) had no matching exec_count in the histogram "
        "and are excluded from the EXECUTION-weighted columns only." %
        unmatched_sites
    )
    L.append("")

    all_opcodes = sorted(
        set(site_stats) | set(exec_stats),
        key=lambda o: -total_count(site_stats.get(o, Counter())),
    )

    # ---- Headline hit-rate table ----
    L.append("## Fast-path hit rate per opcode")
    L.append("")
    L.append(
        "| opcode | sites | site fast-hit % | site folded % | execs | "
        "exec fast-hit % | exec folded % |"
    )
    L.append("|---|---:|---:|---:|---:|---:|---:|")
    for op in all_opcodes:
        sc = site_stats.get(op, Counter())
        ec = exec_stats.get(op, Counter())
        s_tot = total_count(sc)
        e_tot = total_count(ec)
        L.append(
            "| %s | %d | %.2f%% | %.2f%% | %d | %.2f%% | %.2f%% |"
            % (
                opcode_name(op),
                s_tot,
                pct(fast_count(sc), s_tot),
                pct(sc.get("FOLDED", 0), s_tot),
                e_tot,
                pct(fast_count(ec), e_tot),
                pct(ec.get("FOLDED", 0), e_tot),
            )
        )
    L.append("")

    # ---- Per-path breakdown, SITE-weighted ----
    L.append("## Per-path breakdown (SITE-weighted, % of sites)")
    L.append("")
    header = "| opcode | sites | " + " | ".join(PATHS) + " |"
    L.append(header)
    L.append("|---|---:|" + "---:|" * len(PATHS))
    for op in all_opcodes:
        sc = site_stats.get(op, Counter())
        s_tot = total_count(sc)
        cells = []
        for p in PATHS:
            c = sc.get(p, 0)
            cells.append("%d (%.1f%%)" % (c, pct(c, s_tot)))
        L.append("| %s | %d | %s |" % (opcode_name(op), s_tot, " | ".join(cells)))
    L.append("")

    # ---- Per-path breakdown, EXECUTION-weighted ----
    L.append("## Per-path breakdown (EXECUTION-weighted, % of executions)")
    L.append("")
    L.append(header)
    L.append("|---|---:|" + "---:|" * len(PATHS))
    for op in all_opcodes:
        ec = exec_stats.get(op, Counter())
        e_tot = total_count(ec)
        cells = []
        for p in PATHS:
            c = ec.get(p, 0)
            cells.append("%d (%.1f%%)" % (c, pct(c, e_tot)))
        L.append("| %s | %d | %s |" % (opcode_name(op), e_tot, " | ".join(cells)))
    L.append("")

    return "\n".join(L)


def write_raw_csv(path, site_stats, exec_stats):
    """Per-opcode raw counts under both weightings."""
    all_opcodes = sorted(set(site_stats) | set(exec_stats))
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        cols = ["opcode", "opcode_name", "weighting", "total"]
        cols += PATHS + ["fast_total", "fast_hit_pct"]
        w.writerow(cols)
        for op in all_opcodes:
            for weighting, stats in (("site", site_stats), ("exec", exec_stats)):
                c = stats.get(op, Counter())
                tot = total_count(c)
                ft = fast_count(c)
                row = [op, opcode_name(op), weighting, tot]
                row += [c.get(p, 0) for p in PATHS]
                row += [ft, "%.6f" % (ft / tot if tot else 0.0)]
                w.writerow(row)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stream-b", required=True, help="Stream B path CSV")
    ap.add_argument(
        "--histogram", required=True, help="runtime site_histogram.csv"
    )
    ap.add_argument("--out-md", default="fastpath_hitrate.md")
    ap.add_argument("--out-csv", default="fastpath_hitrate.csv")
    ap.add_argument(
        "--fixture-count", type=int, default=225,
        help="number of corpus fixtures (for the report header)",
    )
    args = ap.parse_args(argv)

    sites, dropped = read_stream_b(args.stream_b)
    weights = read_histogram(args.histogram)
    site_stats, exec_stats, unmatched, unmatched_by_op = aggregate(
        sites, weights
    )

    md = render_markdown(
        site_stats, exec_stats, unmatched, unmatched_by_op, dropped,
        args.fixture_count,
    )
    with open(args.out_md, "w") as f:
        f.write(md + "\n")
    write_raw_csv(args.out_csv, site_stats, exec_stats)

    sys.stdout.write(md + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
