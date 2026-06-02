#!/usr/bin/env python3
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Scan a corpus of EEST ``state_test`` fixtures and emit ``manifest.json``.

The manifest summarises the corpus along three axes:

  * block range (min/max ``env.currentNumber``)
  * per-stratum counts (stratum = tx kind: contract-call / plain-transfer /
    contract-creation)
  * per-app_class counts, where app_class is resolved from a seeded
    address -> class map (the 16 curated mainnet contracts' known roles,
    plus other well-known mainnet addresses) with a selector/code heuristic
    fallback

Codehash dual-weighting:

  * ``logical`` view  -- one row per fixture, preserving real call frequency
  * ``unique`` view   -- deduplicated by the keccak256 codehash of the
    ``to``-contract's runtime bytecode (so 100 USDT transfers collapse to 1)

A keccak256 of an absent/empty ``to`` code maps to the canonical empty-code
hash and is labelled ``eoa-or-empty``.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


# ---------------------------------------------------------------------------
# keccak-256 (Ethereum), pure-Python, stdlib-only
# ---------------------------------------------------------------------------

_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_KECCAK_ROTC = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
                27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44]
_KECCAK_PILN = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
                15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1]
_MASK64 = (1 << 64) - 1


def keccak256(data: bytes) -> bytes:
    def rol(x, n):
        return ((x << n) | (x >> (64 - n))) & _MASK64

    rate = 136
    buf = bytearray(data)
    buf.append(0x01)
    while len(buf) % rate != 0:
        buf.append(0x00)
    buf[-1] ^= 0x80

    st = [0] * 25
    for off in range(0, len(buf), rate):
        block = buf[off:off + rate]
        for i in range(rate // 8):
            st[i] ^= int.from_bytes(block[i * 8:i * 8 + 8], "little")
        for rnd in range(24):
            c = [st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20]
                 for x in range(5)]
            d = [c[(x + 4) % 5] ^ rol(c[(x + 1) % 5], 1) for x in range(5)]
            for x in range(5):
                for y in range(0, 25, 5):
                    st[x + y] ^= d[x]
            t = st[1]
            for i in range(24):
                j = _KECCAK_PILN[i]
                bb = st[j]
                st[j] = rol(t, _KECCAK_ROTC[i])
                t = bb
            for y in range(0, 25, 5):
                row = [st[y + x] for x in range(5)]
                for x in range(5):
                    st[y + x] = (row[x]
                                 ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5])
                                 & _MASK64)
            st[0] ^= _KECCAK_RC[rnd]

    out = bytearray()
    for i in range(25):
        out += st[i].to_bytes(8, "little")
    return bytes(out[:32])


EMPTY_CODE_HASH = (
    "0x" + keccak256(b"").hex()
)  # c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470


def code_to_bytes(code: str) -> bytes:
    if not code:
        return b""
    s = code.lower().removeprefix("0x")
    if not s:
        return b""
    try:
        return bytes.fromhex(s)
    except ValueError:
        return b""


def codehash(code: str) -> str:
    b = code_to_bytes(code)
    if not b:
        return EMPTY_CODE_HASH
    return "0x" + keccak256(b).hex()


# ---------------------------------------------------------------------------
# app_class label map
# ---------------------------------------------------------------------------

# Seeded from the 16 curated mainnet contracts (their known roles) plus other
# well-known mainnet addresses observed in the corpus. Roles:
#   stablecoin, erc20, dex-router, dex-pool, lending, nft, infra
ADDRESS_CLASS = {
    # stablecoins / curated ERC20 stores of value
    "0xdac17f958d2ee523a2206206994597c13d831ec7": "stablecoin",  # USDT
    "0x6b175474e89094c44da98b954eedeac495271d0f": "stablecoin",  # DAI
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "stablecoin",  # USDC
    # ERC20 tokens
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "erc20",       # WETH
    "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984": "erc20",       # UNI
    "0x514910771af9ca656af840dff83e8264ecf986ca": "erc20",       # LINK
    "0x6982508145454ce325ddbe47a25d4ec3d2311933": "erc20",       # PEPE
    # DEX routers
    "0xe592427a0aece92de3edee1f18e0157c05861564": "dex-router",  # UniV3Router
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "dex-router",  # UniV3Router2
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "dex-router",  # UniV2Router02
    "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f": "dex-router",  # SushiRouter
    "0x111111125421ca6dc452d289314280a0f8842a65": "dex-router",  # 1inchV6
    "0x1111111254eeb25477b68fb85ed929f73a960582": "dex-router",  # 1inchV5
    "0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae": "dex-router",  # LiFiDiamond
    # DEX pools / positions
    "0xc36442b4a4522e871399cd717abdd847ab11fe88": "dex-pool",    # UniV3 NFPM
    "0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640": "dex-pool",    # USDC/WETH 0.05
    # lending
    "0x4ddc2d193948926d02f9b1fe9e1daa0718270ed5": "lending",     # cETH
    "0xc3d688b66703497daa19211eedff47f25384cdc3": "lending",     # cUSDCv3
    # NFT / marketplace infra
    "0x00000000006c3852cbef3e08e8df289169ede581": "nft",         # Seaport1.1
    "0x0000000000000068f116a894984e2db1123eb395": "nft",         # Seaport1.6
    "0x00005ea00ac477b1030ce78506496e8c2de24bf5": "nft",         # SeaportConduit
    "0x06012c8cf97bead5deae237070f9587f8e7a266d": "nft",         # CryptoKitties
    # infra / account-abstraction / multicall / ENS
    "0x0000000071727de22e5e9d8baf0edac6f37da032": "infra",       # EntryPoint0.7
    "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789": "infra",       # EntryPoint0.6
    "0xca11bde05977b3631167028862be2a173976ca11": "infra",       # Multicall3
    "0x00000000000c2e074ec69a0dfb2997ba6c7d2e1e": "infra",       # ENS registrar
    # additional contracts observed as `to` in the Cancun replay suite
    "0x00000000000000adc04c56bf30ac9d3c0aaf14dc": "nft",         # Seaport 1.5
    "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2": "lending",     # Aave V3 Pool
    "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad": "dex-router",  # Uniswap Universal Router
    "0x83f20f44975d03b1b09e64809b757c47f942beea": "stablecoin",  # sDAI (Savings DAI)
    "0x893411580e590d62ddbca8a703d61cc4a8c7b2b9": "lending",     # Aave WrappedTokenGateway V3
    "0xdef1c0ded9bec7f1a1670819833240f027b25eff": "dex-router",  # 0x Exchange Proxy
}

# ERC20 / ERC721 standard function selectors used by the heuristic fallback.
ERC20_SELECTORS = {
    "0xa9059cbb",  # transfer(address,uint256)
    "0x23b872dd",  # transferFrom(address,address,uint256)
    "0x095ea7b3",  # approve(address,uint256)
}
SWAP_SELECTORS = {
    "0x38ed1739",  # swapExactTokensForTokens
    "0x7ff36ab5",  # swapExactETHForTokens
    "0x18cbafe5",  # swapExactTokensForETH
    "0x414bf389",  # exactInputSingle (UniV3)
    "0xc04b8d59",  # exactInput (UniV3)
    "0x5ae401dc",  # multicall (UniV3 router)
}


# Sampler hint -> canonical app_class. The sampler discovers each tx via a
# verified curated-contract log/tx-scan, so its hint is the authoritative
# application class even when the tx ``to`` is a router/aggregator not in
# ADDRESS_CLASS.
HINT_CLASS = {
    "stablecoin": "stablecoin",
    "dex": "dex-router",
    "lending": "lending",
    "nft": "nft",
    "infra": "infra",
}


def classify(to_addr: str, selector: str, has_code: bool,
             hint: str | None = None) -> str:
    a = (to_addr or "").lower()
    # 1. exact curated-address map wins (most specific, e.g. dex-pool vs
    #    dex-router distinction the hint cannot make)
    if a in ADDRESS_CLASS:
        return ADDRESS_CLASS[a]
    # 2. authoritative sampler hint
    if hint and hint in HINT_CLASS:
        return HINT_CLASS[hint]
    # 3. selector / code heuristic fallback
    if not has_code:
        return "eoa-transfer"
    if selector in SWAP_SELECTORS:
        return "dex-router"
    if selector in ERC20_SELECTORS:
        return "erc20"
    return "other-contract"


def stratum(to_addr: str, has_code: bool, data_hex: str) -> str:
    if not to_addr:
        return "contract-creation"
    if has_code:
        return "contract-call"
    if data_hex and data_hex not in ("0x", ""):
        return "data-to-eoa"
    return "plain-transfer"


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

def hex_int(v):
    if v is None:
        return 0
    if isinstance(v, int):
        return v
    s = str(v)
    return int(s, 16) if s.lower().startswith("0x") else int(s)


def first_case(fixture: dict) -> dict:
    return fixture[next(iter(fixture))]


def first_data(tx: dict) -> str:
    d = tx.get("data", [])
    if isinstance(d, list):
        return d[0] if d else "0x"
    return d or "0x"


def scan(corpus_dir: Path) -> dict:
    files = sorted(corpus_dir.glob("*.json"))
    blocks = []
    stratum_counts = Counter()
    logical_class = Counter()
    unique_by_codehash = {}        # codehash -> (class, addr, sample_file)
    codehash_logical = Counter()   # codehash -> #txns
    rows = []

    for f in files:
        if f.name == "manifest.json":
            continue
        if f.name in ("manifest.json", "tx-list.json"):
            continue
        try:
            fixture = json.loads(f.read_text(encoding="utf-8"))
            case = first_case(fixture)
        except (json.JSONDecodeError, KeyError, StopIteration):
            print(f"[skip] {f.name}: unreadable", file=sys.stderr)
            continue
        # Defensively skip any JSON that is not a single-case state_test
        # fixture (e.g. a stray tx-list or report file dropped in the dir).
        if not isinstance(case, dict) or "env" not in case \
                or "transaction" not in case:
            print(f"[skip] {f.name}: not a state_test fixture",
                  file=sys.stderr)
            continue

        env = case.get("env", {})
        tx = case.get("transaction", {})
        pre = case.get("pre", {})
        to = (tx.get("to") or "").lower()
        data = first_data(tx)
        selector = (data or "0x")[:10]

        # pre keys may carry mixed casing; resolve the to-contract code
        # case-insensitively.
        to_code = ""
        if to:
            for k, v in pre.items():
                if k.lower() == to:
                    to_code = v.get("code", "0x")
                    break
        has_code = bool(code_to_bytes(to_code))

        ch = codehash(to_code)
        hint = case.get("_info", {}).get("app_class_hint")
        cls = classify(to, selector, has_code, hint)
        strat = stratum(to, has_code, data)

        blocks.append(hex_int(env.get("currentNumber", "0x0")))
        stratum_counts[strat] += 1
        logical_class[cls] += 1
        codehash_logical[ch] += 1
        if ch not in unique_by_codehash:
            unique_by_codehash[ch] = {"app_class": cls, "to": to,
                                      "sample": f.name}

        rows.append({
            "file": f.name,
            "to": to,
            "selector": selector,
            "app_class": cls,
            "stratum": strat,
            "codehash": ch,
            "block": hex_int(env.get("currentNumber", "0x0")),
        })

    unique_class = Counter(v["app_class"] for v in unique_by_codehash.values())

    manifest = {
        "corpus_dir": str(corpus_dir),
        "fixture_count": len(rows),
        "block_range": {
            "min": min(blocks) if blocks else None,
            "max": max(blocks) if blocks else None,
        },
        "stratum_counts": dict(sorted(stratum_counts.items())),
        "app_class": {
            "logical": dict(sorted(logical_class.items())),
            "unique": dict(sorted(unique_class.items())),
        },
        "codehash_weighting": {
            "logical_total": sum(codehash_logical.values()),
            "unique_total": len(unique_by_codehash),
            "per_codehash": {
                ch: {
                    "logical_count": codehash_logical[ch],
                    "app_class": meta["app_class"],
                    "to": meta["to"],
                    "sample": meta["sample"],
                }
                for ch, meta in sorted(unique_by_codehash.items())
            },
        },
        "fixtures": sorted(rows, key=lambda r: r["file"]),
    }
    return manifest


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("corpus_dir", type=Path,
                    help="directory of <txhash>.json state_test fixtures")
    ap.add_argument("--out", type=Path, default=None,
                    help="output path (default: <corpus_dir>/manifest.json)")
    args = ap.parse_args(argv)

    if not args.corpus_dir.is_dir():
        print(f"error: {args.corpus_dir} is not a directory", file=sys.stderr)
        return 2

    manifest = scan(args.corpus_dir)
    out = args.out or (args.corpus_dir / "manifest.json")
    out.write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n",
                   encoding="utf-8")

    ac = manifest["app_class"]
    print(f"wrote {out}")
    print(f"  fixtures: {manifest['fixture_count']}")
    br = manifest["block_range"]
    print(f"  block range: {br['min']} - {br['max']}")
    print(f"  app_class logical: {ac['logical']}")
    print(f"  app_class unique:  {ac['unique']}")
    cw = manifest["codehash_weighting"]
    print(f"  codehash logical_total={cw['logical_total']} "
          f"unique_total={cw['unique_total']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
