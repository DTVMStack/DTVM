#!/usr/bin/env python3
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Discover Cancun-era mainnet tx hashes across >=5 application classes.

This sampler feeds ``replay_to_fixture.py`` with a balanced ``--tx-list`` of
genuine Cancun-era transactions. It uses ``eth_getLogs`` over curated
contracts plus topic-only event scans to find candidate transactions in each
class, then applies a per-class quota so each class is represented.

Fork constraint: DTVM supports Cancun only. We sample strictly inside the
Cancun window (default blocks 20,000,000 - 22,400,000), safely below the
Prague activation at 22,431,084 and above Dencun at 19,426,587. Blob
transactions (type 0x3) are not filtered here (the log emitter is a contract,
not the blob carrier); the fixture generator drops any type-0x3 tx it sees.

Application classes (each backed by curated contracts / event topics):

  * stablecoin -- USDT / USDC / DAI ERC20 Transfer logs
  * dex        -- Uniswap V2 / V3 Swap logs (router + pool txns)
  * lending    -- Aave V3 Pool / Compound event logs
  * nft        -- Seaport OrderFulfilled + ERC721 Transfer logs
  * infra      -- Multicall3 / EntryPoint (account abstraction) activity

The output is a JSON document::

    {
      "generated_at": "...",
      "block_range": {"from": <int>, "to": <int>},
      "rpc": "<url>",
      "quota_per_class": <int>,
      "classes": {"stablecoin": [...], ...},
      "transactions": [
        {"hash": "0x..", "block": <int>, "app_class_hint": "stablecoin",
         "emitter": "0x..", "tx_type": <int|null>},
        ...
      ]
    }

The ``transactions`` list is what ``replay_to_fixture.py --tx-list`` reads
(it takes the first whitespace token of each line for a text file, but this
sampler also supports a JSON list; the generator is extended to accept both).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Reuse the hardened Rpc client (retry + throttle + pruned-state detection).
sys.path.insert(0, str(Path(__file__).resolve().parent))
from replay_to_fixture import Rpc, RpcError, hex_int  # noqa: E402

# ---------------------------------------------------------------------------
# event topics
# ---------------------------------------------------------------------------

# ERC20 / ERC721 Transfer(address,address,uint256)
TRANSFER_TOPIC = (
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
)
# Uniswap V3 Swap(address,address,int256,int256,uint160,uint128,int24)
UNIV3_SWAP_TOPIC = (
    "0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67"
)
# Uniswap V2 Swap(address,uint256,uint256,uint256,uint256,address)
UNIV2_SWAP_TOPIC = (
    "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822"
)
# Aave V3 Pool Supply(address,address,address,uint256,uint16)
AAVE_SUPPLY_TOPIC = (
    "0x2b627736bca15cd5381dcf80b0bf11fd197d01a037c52b927a881a10fb73ba61"
)
# Compound v3 (Comet) Supply(address,address,uint256)
COMET_SUPPLY_TOPIC = (
    "0xd1cf3d156d5f8f0d50f6c122ed609cec09d35c9b9fb3fff6ea0959134dae424e"
)
# Seaport OrderFulfilled(...)
SEAPORT_ORDER_TOPIC = (
    "0x9d9af8e38d66c62e2c12f0225249fd9d721c54b83f48d9352c97c6cacdcb6f31"
)

# ---------------------------------------------------------------------------
# curated contracts per class
# ---------------------------------------------------------------------------

USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
DAI = "0x6b175474e89094c44da98b954eedeac495271d0f"

# Uniswap V3 pools (high volume, frequent swaps)
UNIV3_USDC_WETH_005 = "0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640"
UNIV3_WETH_USDT_030 = "0x4e68ccd3e89f51c3074ca5072bbac773960dfa36"
# Uniswap V2 pairs
UNIV2_USDC_WETH = "0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc"
UNIV2_WETH_USDT = "0x0d4a11d5eeaac28ec3f61d100daf4d40471f1852"

AAVE_V3_POOL = "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2"
COMET_USDC = "0xc3d688b66703497daa19211eedff47f25384cdc3"

SEAPORT_15 = "0x00000000000000adc04c56bf30ac9d3c0aaf14dc"
SEAPORT_16 = "0x0000000000000068f116a894984e2db1123eb395"

MULTICALL3 = "0xca11bde05977b3631167028862be2a173976ca11"
ENTRYPOINT_07 = "0x0000000071727de22e5e9d8baf0edac6f37da032"
ENTRYPOINT_06 = "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789"

# class -> list of (address_or_None, topic) log queries to try in order.
# address=None means a topic-only scan (any emitter) within the block window.
CLASS_QUERIES = {
    "stablecoin": [
        (USDT, TRANSFER_TOPIC),
        (USDC, TRANSFER_TOPIC),
        (DAI, TRANSFER_TOPIC),
    ],
    "dex": [
        (UNIV3_USDC_WETH_005, UNIV3_SWAP_TOPIC),
        (UNIV3_WETH_USDT_030, UNIV3_SWAP_TOPIC),
        (UNIV2_USDC_WETH, UNIV2_SWAP_TOPIC),
        (UNIV2_WETH_USDT, UNIV2_SWAP_TOPIC),
    ],
    "lending": [
        (AAVE_V3_POOL, AAVE_SUPPLY_TOPIC),
        (AAVE_V3_POOL, None),
        (COMET_USDC, COMET_SUPPLY_TOPIC),
        (COMET_USDC, None),
    ],
    "nft": [
        (SEAPORT_16, SEAPORT_ORDER_TOPIC),
        (SEAPORT_15, SEAPORT_ORDER_TOPIC),
    ],
    "infra": [
        # EntryPoint emits UserOperationEvent / BeforeExecution logs; a wide
        # block window is needed (account-abstraction traffic is sparse).
        (ENTRYPOINT_07, None),
        (ENTRYPOINT_06, None),
    ],
}

# Some infra contracts (Multicall3) emit no logs of their own -- they only
# aggregate calls. For these we scan block transactions for ``to == addr``.
# class -> list of recipient addresses to harvest by block-tx scan.
CLASS_TX_SCAN = {
    "infra": [MULTICALL3],
}

# Per-class getLogs window scale. Sparse-event classes (lending, nft, infra)
# need a wider initial block window so a scan finds events before the budget
# runs out; dense classes (stablecoin, dex) stay at the base window.
CLASS_WINDOW_SCALE = {
    "stablecoin": 1,
    "dex": 1,
    "lending": 16,
    "nft": 16,
    "infra": 64,
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def scan_logs(rpc: Rpc, address, topic, from_block: int, to_block: int,
              window: int, want: int) -> list:
    """Return up to ``want`` (txhash, block, emitter) candidate tuples.

    Walks the [from_block, to_block] range in ``window``-sized chunks,
    shrinking a chunk on RPC error (the public endpoint caps result size and
    block span). Deduplicates by tx hash within this call.
    """
    out = []
    seen = set()
    start = from_block
    while start <= to_block and len(out) < want:
        end = min(start + window - 1, to_block)
        filt = {"fromBlock": hex(start), "toBlock": hex(end)}
        if address:
            filt["address"] = address
        if topic:
            filt["topics"] = [topic]
        try:
            logs = rpc.call("eth_getLogs", [filt])
        except RpcError as exc:
            msg = str(exc).lower()
            # Result-size / span limits -> shrink the window and retry.
            if window > 1 and ("limit" in msg or "range" in msg
                               or "too many" in msg or "more than" in msg
                               or "-32" in msg):
                window = max(1, window // 2)
                print(f"[scan] shrink window to {window} after: {exc}",
                      file=sys.stderr)
                continue
            print(f"[scan] getLogs failed {start}-{end}: {exc}",
                  file=sys.stderr)
            start = end + 1
            continue
        for lg in logs:
            h = str(lg["transactionHash"]).lower()
            if h in seen:
                continue
            seen.add(h)
            out.append((h, hex_int(lg.get("blockNumber")),
                        str(lg.get("address", "")).lower()))
            if len(out) >= want:
                break
        scope = address or "any-emitter"
        print(f"[scan] {scope} {start}-{end}: +{len(logs)} logs, "
              f"{len(out)}/{want} unique tx", file=sys.stderr)
        start = end + 1
    return out


def scan_block_txs(rpc: Rpc, recipients: list, from_block: int,
                   to_block: int, want: int, max_blocks: int) -> list:
    """Scan full blocks for transactions whose ``to`` is in ``recipients``.

    Walks forward from a rotating start until ``want`` matches are found or
    ``max_blocks`` blocks are inspected (a budget guard so a sparse recipient
    cannot exhaust the RPC quota). Returns (txhash, block, to) tuples.
    """
    targets = {a.lower() for a in recipients}
    out = []
    seen = set()
    n = from_block
    inspected = 0
    while n <= to_block and len(out) < want and inspected < max_blocks:
        try:
            blk = rpc.call("eth_getBlockByNumber", [hex(n), True])
        except RpcError as exc:
            print(f"[txscan] block {n} failed: {exc}", file=sys.stderr)
            n += 1
            inspected += 1
            continue
        for tx in (blk or {}).get("transactions", []):
            to = (tx.get("to") or "").lower()
            if to in targets:
                h = str(tx["hash"]).lower()
                if h not in seen:
                    seen.add(h)
                    out.append((h, hex_int(tx.get("blockNumber")), to))
                    if len(out) >= want:
                        break
        inspected += 1
        if inspected % 25 == 0:
            print(f"[txscan] block {n}: {len(out)}/{want} found "
                  f"({inspected} blocks)", file=sys.stderr)
        n += 1
    return out


def sample_class(rpc: Rpc, cls: str, queries: list, from_block: int,
                 to_block: int, window: int, quota: int) -> list:
    """Collect up to ``quota`` candidates for one class, spreading across the
    block range and across the class's curated queries for diversity."""
    collected = {}
    # Spread sampling: split the block range into per-query sub-windows so we
    # don't grab quota txns all from one 16-block neighbourhood.
    per_query = max(1, quota // max(1, len(queries))) + 2
    span = to_block - from_block + 1
    n = len(queries)
    win = window * CLASS_WINDOW_SCALE.get(cls, 1)
    for i, (addr, topic) in enumerate(queries):
        if len(collected) >= quota:
            break
        # sub-range for this query (rotate start across the full window)
        sub_from = from_block + (span * i) // n
        cands = scan_logs(rpc, addr, topic, sub_from, to_block, win,
                          per_query)
        for h, blk, emitter in cands:
            if h not in collected:
                collected[h] = {"hash": h, "block": blk,
                                "app_class_hint": cls, "emitter": emitter}
            if len(collected) >= quota:
                break
    # Harvest log-less infra recipients via a budgeted block-tx scan.
    if cls in CLASS_TX_SCAN and len(collected) < quota:
        need = quota - len(collected)
        # spread the scan start across the window so we don't always hit the
        # same neighbourhood
        start = from_block + (to_block - from_block) // 3
        txrows = scan_block_txs(rpc, CLASS_TX_SCAN[cls], start, to_block,
                                need, max_blocks=4000)
        for h, blk, to in txrows:
            if h not in collected:
                collected[h] = {"hash": h, "block": blk,
                                "app_class_hint": cls, "emitter": to}
            if len(collected) >= quota:
                break

    rows = sorted(collected.values(), key=lambda r: (r["block"], r["hash"]))
    return rows[:quota]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rpc", required=True, help="archive RPC URL")
    ap.add_argument("--from-block", type=int, default=20_000_000)
    ap.add_argument("--to-block", type=int, default=22_400_000)
    ap.add_argument("--quota", type=int, default=40,
                    help="target candidates per app class")
    ap.add_argument("--window", type=int, default=64,
                    help="initial getLogs block window (auto-shrinks)")
    ap.add_argument("--sleep", type=float, default=0.6,
                    help="min seconds between RPC calls")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--retries", type=int, default=5)
    ap.add_argument("--classes", default=",".join(CLASS_QUERIES),
                    help="comma list of classes to sample")
    ap.add_argument("--out", type=Path, required=True,
                    help="output tx-list JSON path")
    args = ap.parse_args(argv)

    if args.from_block < 19_426_587:
        print("error: from-block is before Dencun (19426587)", file=sys.stderr)
        return 2
    if args.to_block > 22_431_083:
        print("error: to-block reaches Prague (>=22431084)", file=sys.stderr)
        return 2

    rpc = Rpc(args.rpc, timeout=args.timeout, retries=args.retries,
              sleep_s=args.sleep)

    classes = [c.strip() for c in args.classes.split(",") if c.strip()]
    out_classes = {}
    all_tx = []
    seen_global = set()
    for cls in classes:
        if cls not in CLASS_QUERIES:
            print(f"[warn] unknown class {cls}, skipping", file=sys.stderr)
            continue
        print(f"=== sampling class {cls} (quota {args.quota}) ===",
              file=sys.stderr)
        rows = sample_class(rpc, cls, CLASS_QUERIES[cls], args.from_block,
                            args.to_block, args.window, args.quota)
        # global dedup (a tx may emit logs matching two classes)
        deduped = []
        for r in rows:
            if r["hash"] in seen_global:
                continue
            seen_global.add(r["hash"])
            deduped.append(r)
        out_classes[cls] = deduped
        all_tx.extend(deduped)
        print(f"[class] {cls}: {len(deduped)} unique tx", file=sys.stderr)

    all_tx.sort(key=lambda r: (r["app_class_hint"], r["block"], r["hash"]))
    doc = {
        "generated_at": now_iso(),
        "rpc": args.rpc,
        "block_range": {"from": args.from_block, "to": args.to_block},
        "quota_per_class": args.quota,
        "class_counts": {c: len(rows) for c, rows in out_classes.items()},
        "classes": out_classes,
        "transactions": all_tx,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n",
                        encoding="utf-8")
    print(f"wrote {args.out}: {len(all_tx)} tx across "
          f"{len([c for c in out_classes if out_classes[c]])} classes")
    for c, rows in out_classes.items():
        print(f"  {c}: {len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
