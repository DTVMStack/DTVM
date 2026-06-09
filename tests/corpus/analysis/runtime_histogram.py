#!/usr/bin/env python3
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Aggregate the raw per-execution Stream A limb profile into an analysis-ready
per-site histogram, so later analysis does not need to re-run the VM.

Input  (Stream A, ZEN_EVM_LIMB_PROFILE):
    codehash,pc,opcode,operand_index,limb_width,limb_mask   (one row per
    executed arithmetic/compare/bitwise operand)

Output (per-site histogram CSV):
    codehash,pc,opcode,operand_index,exec_count,
    m0,m1,...,m15,          # execution count per 4-bit limb-occupancy mask
    w0,w1,w2,w3,w4          # execution count per magnitude limb_width

One row per distinct (codehash,pc,opcode,operand_index). From this table every
downstream metric (u64 rate, occupancy distribution, execution- vs site-
weighting) is recoverable without touching the raw stream or the VM.

Usage:
    runtime_histogram.py --stream-a stream_a_limb.csv --out-csv site_histogram.csv
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict


def build(stream_a_path):
    # key -> {"exec": int, "mask": [16], "width": [5]}
    sites = defaultdict(lambda: {"exec": 0,
                                 "mask": [0] * 16,
                                 "width": [0] * 5})
    with open(stream_a_path, newline="") as f:
        for r in csv.DictReader(f):
            key = (r["codehash"], int(r["pc"]), int(r["opcode"]),
                   int(r["operand_index"]))
            s = sites[key]
            s["exec"] += 1
            mask = int(r["limb_mask"])
            if 0 <= mask <= 15:
                s["mask"][mask] += 1
            width = int(r["limb_width"])
            if 0 <= width <= 4:
                s["width"][width] += 1
    return sites


def write_csv(sites, out_path):
    cols = (["codehash", "pc", "opcode", "operand_index", "exec_count"]
            + ["m%d" % i for i in range(16)]
            + ["w%d" % i for i in range(5)])
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for (codehash, pc, opcode, idx) in sorted(sites):
            s = sites[(codehash, pc, opcode, idx)]
            w.writerow([codehash, pc, opcode, idx, s["exec"]]
                       + s["mask"] + s["width"])


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stream-a", required=True)
    ap.add_argument("--out-csv", default="site_histogram.csv")
    args = ap.parse_args(argv)
    sites = build(args.stream_a)
    write_csv(sites, args.out_csv)
    total_exec = sum(s["exec"] for s in sites.values())
    print("sites: %d  total operand executions: %d  -> %s"
          % (len(sites), total_exec, args.out_csv))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
