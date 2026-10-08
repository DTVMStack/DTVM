#!/usr/bin/env python3
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Classify unresolved JUMP/JUMPI on paper EVM runtime hex.

Uses evmCacheComplexityDemo --dump-r1-stats plus a local opcode walk so we
can label each unresolved PC as internal-return / dispatcher / computed / other
without implementing R1.

Usage:
  tools/r1_classify_unresolved.py --demo build-r1/evmCacheComplexityDemo \\
      --hex-dir benchmarks/paper/benchmarks/contracts/bench_bytecode \\
      --out artifacts/r1/unresolved_classify.csv
"""

from __future__ import annotations

import argparse
import csv
import subprocess
import sys
from pathlib import Path

OP = {
    0x00: "STOP",
    0x01: "ADD",
    0x02: "MUL",
    0x03: "SUB",
    0x10: "LT",
    0x11: "GT",
    0x14: "EQ",
    0x15: "ISZERO",
    0x16: "AND",
    0x17: "OR",
    0x18: "XOR",
    0x19: "NOT",
    0x1A: "BYTE",
    0x1B: "SHL",
    0x1C: "SHR",
    0x20: "SHA3",
    0x35: "CALLDATALOAD",
    0x36: "CALLDATASIZE",
    0x50: "POP",
    0x51: "MLOAD",
    0x52: "MSTORE",
    0x54: "SLOAD",
    0x55: "SSTORE",
    0x56: "JUMP",
    0x57: "JUMPI",
    0x5B: "JUMPDEST",
    0x5F: "PUSH0",
}

for i in range(1, 33):
    OP[0x5F + i] = f"PUSH{i}"
for i in range(1, 17):
    OP[0x7F + i] = f"DUP{i}"
    OP[0x8F + i] = f"SWAP{i}"


def opcode_len(op: int) -> int:
    if 0x60 <= op <= 0x7F:
        return op - 0x5F + 1
    return 1


def opname(op: int) -> str:
    return OP.get(op, f"OP_{op:02x}")


def strip_hex(text: str) -> bytes:
    s = "".join(text.split())
    if s.startswith(("0x", "0X")):
        s = s[2:]
    return bytes.fromhex(s)


def find_meta(code: bytes) -> int:
    marker = bytes.fromhex("a264697066735822")
    i = code.find(marker)
    return i if i >= 0 else len(code)


def extract_runtime(creation: bytes) -> bytes:
    meta = find_meta(creation)
    search = creation[: min(128, len(creation))]
    last = prev = None
    i = 0
    while i < len(search):
        op = search[i]
        if 0x60 <= op <= 0x7F:
            n = op - 0x5F
            if i + 1 + n <= len(search):
                prev, last = last, int.from_bytes(search[i + 1 : i + 1 + n], "big")
            i += 1 + n
            continue
        if op == 0x39 and last is not None and prev is not None:
            q = i + 1
            while q < len(search) and (
                search[q] == 0x5F or 0x80 <= search[q] <= 0x9F
            ):
                q += 1
            if q < len(search) and search[q] == 0xF3:
                for off, size in ((last, prev), (prev, last)):
                    if off and size and off < meta:
                        use_end = min(off + size, meta)
                        rt = creation[off:use_end]
                        if len(rt) >= 4:
                            return rt
        i += 1
    return creation[:meta] if meta >= 4 else creation


def walk(code: bytes):
    pcs = []
    pc = 0
    while pc < len(code):
        op = code[pc]
        pcs.append(pc)
        pc += opcode_len(op)
    return pcs


def window(code: bytes, jump_pc: int, before: int = 6) -> list[tuple[int, str]]:
    pcs = walk(code)
    idx = pcs.index(jump_pc) if jump_pc in pcs else -1
    if idx < 0:
        return []
    start = max(0, idx - before)
    out = []
    for p in pcs[start : idx + 1]:
        out.append((p, opname(code[p])))
    return out


def classify(code: bytes, jump_pc: int) -> str:
    ops = [name for _, name in window(code, jump_pc, 8)]
    if not ops:
        return "unknown"
    prev = ops[-2] if len(ops) >= 2 else ""
    if prev.startswith("PUSH"):
        return "adjacent_push"  # should already be resolved
    if prev.startswith("SWAP") and ops[-1] == "JUMP":
        return "internal_return"
    if prev.startswith("DUP") and ops[-1] in ("JUMP", "JUMPI"):
        return "dup_target"
    if "CALLDATALOAD" in ops[-5:]:
        return "top_calldata"
    if any(x in ops[-5:] for x in ("MLOAD", "SLOAD", "SHA3", "ADD", "SUB", "AND", "OR", "XOR", "SHL", "SHR")):
        return "top_computed"
    if prev == "JUMPDEST" or (len(ops) >= 3 and ops[-2] == "JUMPDEST"):
        return "bare_jumpdest_jump"
    return "unknown_dynamic"


def local_resolved(code: bytes, jump_pc: int) -> bool:
    """True if adjacent PUSH1..PUSH32 immediate is a JUMPDEST."""
    if jump_pc == 0:
        return False
    # find previous opcode
    prev = None
    pc = 0
    while pc < jump_pc:
        prev = pc
        pc += opcode_len(code[pc])
    if prev is None:
        return False
    op = code[prev]
    if not (0x60 <= op <= 0x7F):
        return False
    if prev + opcode_len(op) != jump_pc:
        return False
    n = op - 0x5F
    dest = int.from_bytes(code[prev + 1 : prev + 1 + n], "big")
    return dest < len(code) and code[dest] == 0x5B


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hex-dir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--demo", help="optional evmCacheComplexityDemo for census")
    args = ap.parse_args()

    hex_dir = Path(args.hex_dir)
    rows = []
    summary = {}
    for path in sorted(hex_dir.glob("*_evm.hex")):
        creation = strip_hex(path.read_text())
        code = extract_runtime(creation)
        label = path.stem
        counts = {k: 0 for k in (
            "internal_return", "dup_target", "top_calldata", "top_computed",
            "bare_jumpdest_jump", "adjacent_push", "unknown_dynamic",
        )}
        n_jump = n_unres = 0
        pcs = walk(code)
        for pc in pcs:
            op = code[pc]
            if op not in (0x56, 0x57):
                continue
            n_jump += 1
            if local_resolved(code, pc):
                continue
            # DUP/SWAP local const still unresolved here — matches "not adjacent PUSH"
            kind = classify(code, pc)
            # Refine: if the only unknown is from block-local DUP of a PUSH, mark maybe_const
            win = window(code, pc, 8)
            names = [n for _, n in win]
            if kind == "dup_target" and any(n.startswith("PUSH") for n in names[:-1]):
                kind = "local_dup_push"
                counts.setdefault("local_dup_push", 0)
            counts.setdefault(kind, 0)
            counts[kind] += 1
            n_unres += 1
            rows.append({
                "label": label,
                "pc": pc,
                "opcode": "JUMP" if op == 0x56 else "JUMPI",
                "class": kind,
                "window": " ".join(f"{p}:{n}" for p, n in win),
            })
        summary[label] = {"n_jump": n_jump, "n_unres_no_adj_push": n_unres, **counts}

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["label", "pc", "opcode", "class", "window"])
        w.writeheader()
        w.writerows(rows)

    sum_path = out.with_name(out.stem + "_summary.csv")
    keys = sorted({k for s in summary.values() for k in s})
    with sum_path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["label"] + keys)
        w.writeheader()
        for label, s in summary.items():
            w.writerow({"label": label, **s})

    print(f"wrote {out} ({len(rows)} unresolved-without-adjacent-PUSH)")
    print(f"wrote {sum_path}")
    for label, s in summary.items():
        print(f"  {label}: jumps={s['n_jump']} unres~={s['n_unres_no_adj_push']} "
              f"ret={s.get('internal_return', 0)} calldata={s.get('top_calldata', 0)} "
              f"computed={s.get('top_computed', 0)} dup={s.get('dup_target', 0)}+"
              f"{s.get('local_dup_push', 0)} other={s.get('unknown_dynamic', 0)}")


if __name__ == "__main__":
    main()
