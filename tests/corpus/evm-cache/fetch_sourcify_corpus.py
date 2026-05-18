#!/usr/bin/env python3
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fetch verified mainnet contracts from Sourcify, dedupe by runtime
codehash, extract metadata, and write hex + manifest for downstream
stratified sampling.

Output layout (out_dir):
  raw/<address>.hex          # runtime bytecode (0x-stripped)
  raw/<address>.meta.json    # selected metadata fields
  manifest.json              # one row per unique codehash

Usage:
  fetch_sourcify_corpus.py --out tests/corpus/evm-cache/raw \
    --manifest tests/corpus/evm-cache/manifest.json \
    --pages 8 --sleep 0.2

Schema of manifest rows:
  address, codehash, code_size, n_jumpdests, n_jumps, n_jumpis,
  dyn_jump_ratio, solc_version, optimizer_runs, viaIR, verified_at
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Tuple

SOURCIFY_API = "https://sourcify.dev/server/v2"
CHAIN_ID = "1"  # mainnet


def http_get_json(url: str, retries: int = 3, timeout: int = 15) -> Optional[dict]:
    last_err: Optional[Exception] = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode())
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError) as e:
            last_err = e
            time.sleep(0.5 * (attempt + 1))
    print(f"  warn: GET {url} failed after {retries} retries: {last_err}", file=sys.stderr)
    return None


def list_addresses(pages: int, sleep: float) -> List[Tuple[str, str]]:
    """Return [(address, matchId), ...] in newest-first order."""
    out: List[Tuple[str, str]] = []
    after = None
    for p in range(pages):
        url = f"{SOURCIFY_API}/contracts/{CHAIN_ID}?limit=200"
        if after is not None:
            url += f"&afterMatchId={after}"
        print(f"page {p + 1}/{pages}: {url}", file=sys.stderr)
        j = http_get_json(url)
        if not j or not j.get("results"):
            print("  empty page, stopping", file=sys.stderr)
            break
        results = j["results"]
        for r in results:
            out.append((r["address"], r["matchId"]))
        after = results[-1]["matchId"]
        time.sleep(sleep)
    return out


def fetch_contract_detail(address: str) -> Optional[dict]:
    url = f"{SOURCIFY_API}/contract/{CHAIN_ID}/{address}?fields=runtimeBytecode,metadata"
    return http_get_json(url)


def static_jump_stats(code: bytes) -> Tuple[int, int, int, float]:
    """Return (n_jumpdests, n_jumps, n_jumpis, dyn_jump_ratio).

    A jump is counted as static iff the immediately-preceding instruction is
    a PUSH AND the pushed value is a valid JUMPDEST PC (i.e. lands on a
    JUMPDEST opcode outside any PUSH-data region). This matches the cache
    builder's resolveConstantJumpTarget semantics in src/evm/evm_cache.cpp,
    so a PUSH whose constant points to a non-JUMPDEST byte is correctly
    counted as dynamic here.
    """
    OP_JUMP = 0x56
    OP_JUMPI = 0x57
    OP_JUMPDEST = 0x5B
    PUSH1 = 0x60
    PUSH32 = 0x7F

    n = len(code)

    # Pass 1: collect valid JUMPDEST PCs (skipping PUSH-data regions).
    jumpdests: set = set()
    pc = 0
    while pc < n:
        op = code[pc]
        if PUSH1 <= op <= PUSH32:
            pc += 1 + (op - PUSH1 + 1)
            continue
        if op == OP_JUMPDEST:
            jumpdests.add(pc)
        pc += 1

    # Pass 2: count jumps; classify as static iff the immediately preceding
    # PUSH produced a value in `jumpdests`. prev_push_value is reset to None
    # after every non-PUSH opcode so only the immediately-adjacent PUSH is
    # considered (matching the cache builder's PrevPc/LastPc adjacency
    # requirement).
    n_jd = len(jumpdests)
    n_jump = 0
    n_jumpi = 0
    n_dyn = 0
    prev_push_value = None
    pc = 0
    while pc < n:
        op = code[pc]
        if op == OP_JUMP:
            n_jump += 1
            if prev_push_value is None or prev_push_value not in jumpdests:
                n_dyn += 1
            prev_push_value = None
            pc += 1
            continue
        if op == OP_JUMPI:
            n_jumpi += 1
            if prev_push_value is None or prev_push_value not in jumpdests:
                n_dyn += 1
            prev_push_value = None
            pc += 1
            continue
        if PUSH1 <= op <= PUSH32:
            sz = op - PUSH1 + 1
            raw = code[pc + 1 : pc + 1 + sz]
            # PUSH at end-of-code is zero-padded on the right per EVM
            # semantics; mirror that here so the integer value matches the
            # interpreter's stack value.
            if len(raw) < sz:
                raw = raw + b"\x00" * (sz - len(raw))
            prev_push_value = int.from_bytes(raw, "big")
            pc += 1 + sz
            continue
        prev_push_value = None
        pc += 1
    total = n_jump + n_jumpi
    ratio = (n_dyn / total) if total else 0.0
    return n_jd, n_jump, n_jumpi, ratio


def extract_meta(detail: dict) -> dict:
    md = detail.get("metadata") or {}
    settings = md.get("settings") or {}
    optimizer = settings.get("optimizer") or {}
    return {
        "solc_version": (md.get("compiler") or {}).get("version", "unknown"),
        "optimizer_runs": optimizer.get("runs"),
        "viaIR": bool(settings.get("viaIR", False)),
    }


def strip_hex(s: str) -> bytes:
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]
    return bytes.fromhex(s)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True, help="dir for <addr>.hex + <addr>.meta.json")
    ap.add_argument("--manifest", required=True, help="json manifest path")
    ap.add_argument("--pages", type=int, default=5, help="pages of 200 contracts to list")
    ap.add_argument("--sleep", type=float, default=0.2, help="sleep between requests (s)")
    ap.add_argument("--min-size", type=int, default=200,
                    help="skip contracts whose runtime bytecode is < this many bytes (stubs/proxies)")
    ap.add_argument("--max-fetch", type=int, default=None,
                    help="stop after this many detail fetches (debug knob)")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    addrs = list_addresses(args.pages, args.sleep)
    print(f"listed {len(addrs)} addresses", file=sys.stderr)

    manifest: List[dict] = []
    seen_codehash: Dict[str, str] = {}
    fetched = 0
    for addr, match_id in addrs:
        if args.max_fetch is not None and fetched >= args.max_fetch:
            break
        fetched += 1
        detail = fetch_contract_detail(addr)
        time.sleep(args.sleep)
        if not detail:
            continue
        rb = (detail.get("runtimeBytecode") or {}).get("onchainBytecode")
        if not rb or rb in ("0x", "0x00"):
            continue
        try:
            code = strip_hex(rb)
        except ValueError:
            continue
        if len(code) < args.min_size:
            continue
        codehash = hashlib.sha256(code).hexdigest()[:16]
        if codehash in seen_codehash:
            continue
        seen_codehash[codehash] = addr

        n_jd, n_jump, n_jumpi, dyn_ratio = static_jump_stats(code)
        meta = extract_meta(detail)
        row = {
            "address": addr,
            "match_id": match_id,
            "codehash": codehash,
            "code_size": len(code),
            "n_jumpdests": n_jd,
            "n_jumps": n_jump,
            "n_jumpis": n_jumpi,
            "dyn_jump_ratio": dyn_ratio,
            "solc_version": meta["solc_version"],
            "optimizer_runs": meta["optimizer_runs"],
            "viaIR": meta["viaIR"],
            "verified_at": detail.get("verifiedAt"),
        }
        manifest.append(row)
        with open(os.path.join(args.out, f"{addr}.hex"), "w") as f:
            f.write(rb)
        with open(os.path.join(args.out, f"{addr}.meta.json"), "w") as f:
            json.dump(row, f, indent=2)
        if len(manifest) % 25 == 0:
            print(f"  unique so far: {len(manifest)} / fetched {fetched}", file=sys.stderr)

    with open(args.manifest, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"wrote {len(manifest)} unique contracts to {args.out} ({fetched} addresses scanned)", file=sys.stderr)


if __name__ == "__main__":
    main()
