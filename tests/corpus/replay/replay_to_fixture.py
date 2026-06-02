#!/usr/bin/env python3
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Generate self-contained EEST ``state_test`` fixtures from mainnet txns.

Two capture modes are selected by ``--mode`` (default ``prestate``):

``prestate`` (default, preferred)
    Uses ``debug_traceTransaction`` with the ``prestateTracer`` in diffMode.
    The returned ``pre`` map IS the exact touched account/storage set with
    exact pre-execution values, so no per-slot ``eth_getStorageAt`` reads are
    needed. The EIP-2930 ``accessList`` is derived directly from that
    touched-set (address -> sorted storage keys), which is exact. The
    post-state diff and receipt status/gasUsed/logs are recorded in ``_info``
    for later differential use.

``createaccesslist`` (fallback)
    The debug-free, archive-only path. It does NOT use
``debug_traceTransaction``/prestateTracer (disabled on the free public
endpoint). Instead it captures the touched account/storage set from a union
of debug-free sources and reads each account's pre-state at block N-1 and
post-state at block N from an archive RPC.

Touched-set sources (unioned):
  * tx.from, tx.to, block.coinbase (always present)
  * the transaction's own EIP-2930 ``accessList`` (when type 1/2 carries one)
  * receipt log addresses (contracts that emitted events are touched)
  * ``eth_createAccessList`` re-execution from the N-1 base state, run with a
    sender-balance state override so the funds check cannot abort it

The ``eth_createAccessList`` set is best-effort: it re-executes the call
outside the same-block context, so it can under-approximate (revert) or
over-approximate relative to the exact prestateTracer set. The union with
the receipt log addresses recovers most of the real touched contracts. Any
residual divergence is what ``fixture_equal.py`` surfaces during validation.

Output schema matches the existing fixtures under
``mainnet-replay/state-tests/``:

  {"<name>": {"_info", "env", "pre", "post", "transaction"}}

with these additions over the original prestateTracer fixtures:
  * ``transaction.accessList`` is populated (the original gap this fixes).
  * ``_info.trace_source`` records the capture provenance.
  * ``_info.status`` / ``_info.gasUsed`` record the receipt outcome.
  * ``_info.post_diff`` / ``_info.logs`` (prestate mode) record the
    post-state diff and logs for later differential checking.

Output JSON is written with sorted keys for deterministic, idempotent runs.
A tx hash whose ``<txhash>.json`` already exists in ``--out-dir`` is skipped.
"""

from __future__ import annotations

import argparse
import http.client
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# Synthetic EEST test account. The original fixtures replace the real sender
# with this canonical test-vector key/address so the fixture is a pure state
# test (no real-signature dependency). We keep the same convention.
EEST_SECRET_KEY = (
    "0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8"
)
EEST_SENDER = "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b"
# The fixture signs with EEST_SENDER, so that account must exist in ``pre``
# with a nonce matching the (real) tx nonce and a balance covering gas +
# value, or the state test aborts the tx ("nonce too high" / insufficient
# funds) before any opcode runs. The real mainnet sender stays in ``pre``
# under its own address for state the called code may read.
EEST_SENDER_BALANCE = "0x" + "f" * 31

# Forks at or before Cancun. A tx whose block fork is newer (Prague+) is
# dropped: DTVM does not support Prague yet and the env/post schema differs.
CANCUN_FORK = "Cancun"
SUPPORTED_FORKS = {"Frontier", "Homestead", "Byzantium", "Constantinople",
                   "Istanbul", "Berlin", "London", "Shanghai", "Cancun"}

# diffMode prestateTracer request body.
PRESTATE_TRACER_CFG = {
    "tracer": "prestateTracer",
    "tracerConfig": {"diffMode": True},
}


class RpcError(RuntimeError):
    pass


class HistoricalStateUnavailable(RpcError):
    """Archive endpoint pruned the state at the requested block."""


class Rpc:
    """urllib JSON-RPC client with retry + inter-call throttle.

    Ported from the DTVMErc20Analyze base pipeline ``Rpc`` class, extended
    with a configurable ``sleep`` throttle between calls (free endpoints rate
    limit aggressively) and detection of the pruned-state error so callers
    can drop a fixture rather than crash.
    """

    def __init__(self, url: str, timeout: int = 120, retries: int = 4,
                 sleep_s: float = 0.0):
        self.url = url
        self.timeout = timeout
        self.retries = max(1, retries)
        self.sleep_s = sleep_s
        self.next_id = 1
        self._last_call = 0.0

    def _throttle(self) -> None:
        if self.sleep_s <= 0:
            return
        wait = self.sleep_s - (time.time() - self._last_call)
        if wait > 0:
            time.sleep(wait)

    def call(self, method: str, params: list | None = None):
        self._throttle()
        payload = {
            "jsonrpc": "2.0",
            "id": self.next_id,
            "method": method,
            "params": params or [],
        }
        self.next_id += 1
        last_exc: Exception | None = None
        for attempt in range(self.retries):
            try:
                req = urllib.request.Request(
                    self.url,
                    data=json.dumps(payload).encode(),
                    headers={
                        "content-type": "application/json",
                        # Some public endpoints (e.g. publicnode) reject the
                        # default Python-urllib User-Agent with HTTP 403.
                        "user-agent": "dtvm-replay/1.0",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    raw = resp.read()
                body = json.loads(raw)
                if body.get("error"):
                    msg = str(body["error"])
                    if "historical state" in msg and "not available" in msg:
                        raise HistoricalStateUnavailable(f"{method}: {msg}")
                    raise RpcError(f"{method}: {body['error']}")
                self._last_call = time.time()
                return body["result"]
            except HistoricalStateUnavailable:
                raise
            except (http.client.HTTPException, urllib.error.URLError,
                    ConnectionError, json.JSONDecodeError,
                    TimeoutError) as exc:
                last_exc = exc
                time.sleep(0.5 * (2 ** attempt))
        self._last_call = time.time()
        if last_exc:
            raise last_exc
        raise RpcError(f"{method}: unknown RPC failure")


# ---------------------------------------------------------------------------
# hex helpers
# ---------------------------------------------------------------------------

def hex_int(v) -> int:
    if v is None:
        return 0
    if isinstance(v, int):
        return v
    return int(v, 16)


def to_hex(n: int) -> str:
    return hex(n)


def norm_addr(a: str) -> str:
    return "0x" + a.lower().removeprefix("0x").rjust(40, "0")


def norm_slot(s: str) -> str:
    return "0x" + s.lower().removeprefix("0x").rjust(64, "0")


def norm_word(s: str) -> str:
    """Normalise a 32-byte storage value to canonical 0x + 64 hex."""
    body = s.lower().removeprefix("0x") or "0"
    return "0x" + body.rjust(64, "0")


# ---------------------------------------------------------------------------
# fork detection
# ---------------------------------------------------------------------------

def fork_for_block(rpc: Rpc, block_num: int, block: dict) -> str:
    """Best-effort fork classification from block header fields.

    We only need to separate "<= Cancun" (keep) from "Prague+" (drop). Cancun
    blocks carry ``excessBlobGas``/``blobGasUsed``; Prague is detected via the
    presence of ``requestsHash`` (EIP-7685) in the header.
    """
    if block.get("requestsHash") is not None:
        return "Prague"
    return CANCUN_FORK


# ---------------------------------------------------------------------------
# touched-set capture
# ---------------------------------------------------------------------------

def access_list_addresses(access_list) -> dict:
    out: dict = {}
    for entry in access_list or []:
        addr = norm_addr(entry["address"])
        out.setdefault(addr, set())
        for k in entry.get("storageKeys") or []:
            out[addr].add(norm_slot(k))
    return out


def merge_touched(dst: dict, src: dict) -> None:
    for addr, slots in src.items():
        dst.setdefault(addr, set()).update(slots)


def capture_touched(rpc: Rpc, tx: dict, receipt: dict, coinbase: str,
                    nminus1: str):
    """Union all debug-free touched-set sources.

    Returns (touched_map addr->slots, eip2930_access_list, capture_note).
    The returned access_list is the canonical EIP-2930 list to embed in the
    fixture transaction; it is the createAccessList result when available,
    otherwise the tx's own list, else an empty list.
    """
    touched: dict = {}
    note_parts: list = []

    sender = norm_addr(tx["from"])
    to = norm_addr(tx["to"]) if tx.get("to") else None
    touched.setdefault(sender, set())
    if to:
        touched.setdefault(to, set())
    touched.setdefault(norm_addr(coinbase), set())

    # 1. tx's own EIP-2930 access list
    own = access_list_addresses(tx.get("accessList"))
    merge_touched(touched, own)

    # 2. receipt log addresses (definitely touched contracts)
    for log in receipt.get("logs", []):
        touched.setdefault(norm_addr(log["address"]), set())

    # 3. eth_createAccessList re-execution with sender-balance override
    created_list: list = []
    call_obj = {
        "from": tx["from"],
        "data": tx.get("input", "0x"),
        "value": tx.get("value", "0x0"),
    }
    if to:
        call_obj["to"] = tx["to"]
    if tx.get("gas"):
        call_obj["gas"] = tx["gas"]
    overrides = {tx["from"]: {"balance": "0xffffffffffffffffffffffffffffffff"}}
    try:
        res = rpc.call("eth_createAccessList", [call_obj, nminus1, overrides])
        if isinstance(res, dict):
            created_list = res.get("accessList", []) or []
            merge_touched(touched, access_list_addresses(created_list))
            if res.get("error"):
                note_parts.append(f"createAccessList-reverted:{res['error']}")
            else:
                note_parts.append("createAccessList-ok")
    except HistoricalStateUnavailable:
        raise
    except RpcError as exc:
        note_parts.append(f"createAccessList-failed:{exc}")

    # Canonical EIP-2930 list to embed: prefer createAccessList result,
    # else the tx's own list.
    if created_list:
        embed = created_list
    elif tx.get("accessList"):
        embed = tx["accessList"]
    else:
        embed = []

    return touched, embed, "+".join(note_parts) if note_parts else "minimal"


# ---------------------------------------------------------------------------
# state reads
# ---------------------------------------------------------------------------

def read_account(rpc: Rpc, addr: str, block_tag: str, slots) -> dict:
    balance = rpc.call("eth_getBalance", [addr, block_tag])
    nonce = rpc.call("eth_getTransactionCount", [addr, block_tag])
    code = rpc.call("eth_getCode", [addr, block_tag])
    storage: dict = {}
    for slot in sorted(slots):
        val = rpc.call("eth_getStorageAt", [addr, slot, block_tag])
        # Only record non-zero slots; zero slots are the implicit default and
        # bloat the fixture. Matches the prestateTracer convention.
        if hex_int(val) != 0:
            storage[norm_slot(slot)] = norm_word(val)
    return {
        "balance": to_hex(hex_int(balance)),
        # nonce is an int in the existing fixtures, not hex
        "nonce": hex_int(nonce),
        "code": code if code and code != "0x" else "0x",
        "storage": storage,
    }


def build_pre(rpc: Rpc, touched: dict, nminus1: str) -> dict:
    pre: dict = {}
    for addr in sorted(touched):
        pre[addr] = read_account(rpc, addr, nminus1, touched[addr])
    return pre


# ---------------------------------------------------------------------------
# prestateTracer capture (preferred mode)
# ---------------------------------------------------------------------------

def trace_prestate(rpc: Rpc, txhash: str) -> dict:
    """Return the diffMode prestateTracer result {"pre":..., "post":...}.

    Raises HistoricalStateUnavailable if the archive pruned the block state,
    RpcError on any other RPC-level failure.
    """
    res = rpc.call("debug_traceTransaction", [txhash, PRESTATE_TRACER_CFG])
    if not isinstance(res, dict) or "pre" not in res:
        raise RpcError(f"prestateTracer: unexpected result shape for {txhash}")
    return res


def prestate_to_pre(pre_raw: dict) -> dict:
    """Convert a prestateTracer ``pre`` map into the fixture ``pre`` stanza.

    The tracer emits each touched account with any of balance/nonce/code/
    storage (absent fields default to the empty account). We normalise to the
    existing fixture account shape: balance (0x hex), nonce (int), code (0x..
    or "0x"), storage (non-zero slots only, canonical 0x+64 hex).
    """
    pre: dict = {}
    for addr_raw, acc in pre_raw.items():
        addr = norm_addr(addr_raw)
        storage = {}
        for slot, val in (acc.get("storage") or {}).items():
            if hex_int(val) != 0:
                storage[norm_slot(slot)] = norm_word(val)
        code = acc.get("code") or "0x"
        pre[addr] = {
            "balance": to_hex(hex_int(acc.get("balance", "0x0"))),
            "nonce": hex_int(acc.get("nonce", 0)),
            "code": code if code and code != "0x" else "0x",
            "storage": storage,
        }
    return dict(sorted(pre.items()))


def prestate_access_list(pre_raw: dict, sender: str, to: str | None) -> list:
    """Derive an exact EIP-2930 accessList from the prestate touched-set.

    Every touched account becomes an accessList entry; its storageKeys are the
    sorted set of slots the tracer reported for it. The sender and (for a
    call) the ``to`` account are conventionally excluded from EIP-2930 lists
    (they are always warm), matching how ``eth_createAccessList`` behaves.
    """
    skip = {sender}
    if to:
        skip.add(to)
    entries = []
    for addr_raw, acc in pre_raw.items():
        addr = norm_addr(addr_raw)
        if addr in skip:
            continue
        slots = sorted(norm_slot(s) for s in (acc.get("storage") or {}))
        if not slots:
            # Only include accounts that contribute storage keys; bare-address
            # warmth is not part of a minimal, meaningful accessList and would
            # bloat the fixture with every balance-touched EOA.
            continue
        entries.append({"address": addr, "storageKeys": slots})
    entries.sort(key=lambda e: e["address"])
    return entries


def summarize_post(post_raw: dict) -> dict:
    """Compact, deterministic summary of the post-state diff for ``_info``.

    Records, per changed address, the new balance/nonce (when present) and the
    set of changed storage slots with their new values. Used for later
    differential checks; not asserted by the state test itself.
    """
    out: dict = {}
    for addr_raw, acc in (post_raw or {}).items():
        addr = norm_addr(addr_raw)
        rec: dict = {}
        if "balance" in acc:
            rec["balance"] = to_hex(hex_int(acc["balance"]))
        if "nonce" in acc:
            rec["nonce"] = hex_int(acc["nonce"])
        if "code" in acc and acc["code"] not in (None, "0x", ""):
            rec["code"] = acc["code"]
        st = {}
        for slot, val in (acc.get("storage") or {}).items():
            st[norm_slot(slot)] = norm_word(val)
        if st:
            rec["storage"] = dict(sorted(st.items()))
        if rec:
            out[addr] = rec
    return dict(sorted(out.items()))


def summarize_logs(receipt: dict) -> list:
    """Deterministic list of receipt logs (address + topics + data)."""
    logs = []
    for lg in receipt.get("logs", []) or []:
        logs.append({
            "address": norm_addr(lg.get("address", "0x")),
            "topics": [str(t).lower() for t in (lg.get("topics") or [])],
            "data": str(lg.get("data", "0x")).lower(),
        })
    return logs


# ---------------------------------------------------------------------------
# fixture assembly
# ---------------------------------------------------------------------------

def build_env(block: dict) -> dict:
    return {
        "currentNumber": to_hex(hex_int(block["number"])),
        "currentTimestamp": to_hex(hex_int(block["timestamp"])),
        "currentGasLimit": to_hex(hex_int(block["gasLimit"])),
        "currentCoinbase": norm_addr(block["miner"]),
        "currentBaseFee": to_hex(hex_int(block.get("baseFeePerGas", "0x0"))),
        # Post-merge difficulty is 0; randomness lives in mixHash (prevRandao).
        "currentDifficulty": "0x0",
        "currentRandom": block.get("mixHash", "0x" + "0" * 64).lower(),
        "previousHash": block.get("parentHash", "0x" + "0" * 64).lower(),
    }


def build_transaction(tx: dict, access_list: list) -> dict:
    gas_price = tx.get("gasPrice") or tx.get("maxFeePerGas") or "0x0"
    return {
        "accessList": [
            {
                "address": norm_addr(e["address"]),
                "storageKeys": [norm_slot(k)
                                for k in (e.get("storageKeys") or [])],
            }
            for e in access_list
        ],
        "data": [tx.get("input", "0x")],
        "gasLimit": [to_hex(hex_int(tx["gas"]))],
        "gasPrice": to_hex(hex_int(gas_price)),
        "nonce": to_hex(hex_int(tx["nonce"])),
        "secretKey": EEST_SECRET_KEY,
        "sender": EEST_SENDER,
        "to": norm_addr(tx["to"]) if tx.get("to") else "",
        "value": [to_hex(hex_int(tx.get("value", "0x0")))],
    }


def build_post(receipt: dict) -> dict:
    """Build the post stanza.

    The original fixtures use placeholder zeros for hash/logs/txbytes (they do
    not assert the post state root). We mirror that exactly so generated
    fixtures are interchangeable with the originals. The real status + gasUsed
    are recorded in ``_info`` instead.
    """
    return {
        CANCUN_FORK: [
            {
                "hash": "0x" + "0" * 64,
                "logs": "0x" + "0" * 64,
                "indexes": {"data": 0, "gas": 0, "value": 0},
                "txbytes": "0x00",
            }
        ]
    }


def fixture_name(tx: dict, index_hint) -> str:
    to = (tx.get("to") or "0x").lower()
    selector = (tx.get("input", "0x") or "0x")[:10]
    if to and to != "0x":
        prefix = "0x" + to.removeprefix("0x")[:8]
    else:
        prefix = selector
    idx = index_hint if index_hint is not None else hex_int(tx.get(
        "transactionIndex", "0x0"))
    return f"replay_{prefix}_{idx}"


def build_fixture(rpc: Rpc, txhash: str, mode: str = "prestate",
                  app_class_hint: str | None = None,
                  allow_post_cancun: bool = False):
    """Return (txhash, fixture_dict) or None if the tx must be dropped.

    ``mode`` is ``prestate`` (debug_traceTransaction prestateTracer, exact) or
    ``createaccesslist`` (debug-free fallback).
    """
    tx = rpc.call("eth_getTransactionByHash", [txhash])
    if tx is None:
        print(f"[drop] {txhash}: tx not found", file=sys.stderr)
        return None

    tx_type = hex_int(tx.get("type", "0x0"))
    if tx_type == 3:
        print(f"[drop] {txhash}: blob tx (type 0x3) excluded", file=sys.stderr)
        return None

    if tx.get("blockNumber") is None:
        print(f"[drop] {txhash}: pending / no blockNumber", file=sys.stderr)
        return None
    block_num = hex_int(tx["blockNumber"])
    nminus1 = to_hex(block_num - 1)
    block_tag = to_hex(block_num)

    block = rpc.call("eth_getBlockByNumber", [block_tag, False])
    if block is None:
        print(f"[drop] {txhash}: block {block_num} not found", file=sys.stderr)
        return None

    fork = fork_for_block(rpc, block_num, block)
    if fork not in SUPPORTED_FORKS and not allow_post_cancun:
        print(f"[drop] {txhash}: fork {fork} > Cancun excluded",
              file=sys.stderr)
        return None

    receipt = rpc.call("eth_getTransactionReceipt", [txhash])
    if receipt is None:
        print(f"[drop] {txhash}: receipt not found", file=sys.stderr)
        return None

    sender = norm_addr(tx["from"])
    to = norm_addr(tx["to"]) if tx.get("to") else None

    if mode == "prestate":
        trace = trace_prestate(rpc, txhash)
        pre_raw = trace.get("pre", {}) or {}
        post_raw = trace.get("post", {}) or {}
        if not pre_raw:
            print(f"[drop] {txhash}: empty prestate", file=sys.stderr)
            return None
        # The coinbase is touched by fee payment; ensure it is present so the
        # state test can credit the priority fee even if the tracer omitted a
        # zero-delta coinbase.
        coinbase = norm_addr(block["miner"])
        pre = prestate_to_pre(pre_raw)
        if coinbase not in pre:
            pre[coinbase] = {"balance": "0x0", "nonce": 0,
                             "code": "0x", "storage": {}}
            pre = dict(sorted(pre.items()))
        access_list = prestate_access_list(pre_raw, sender, to)
        capture_note = (f"prestateTracer-diffMode pre={len(pre_raw)} "
                        f"post={len(post_raw)}")
        trace_source = "debug_traceTransaction-prestateTracer"
        source = ("dRPC debug_traceTransaction prestateTracer diffMode, "
                  f"txhash {txhash}")
        post_diff = summarize_post(post_raw)
        logs = summarize_logs(receipt)
    else:
        touched, embed, capture_note = capture_touched(
            rpc, tx, receipt, block["miner"], nminus1)
        pre = build_pre(rpc, touched, nminus1)
        access_list = embed
        trace_source = "debug-free-archive"
        source = ("archive eth_createAccessList + eth_getBalance/"
                  "getTransactionCount/getCode/getStorageAt, "
                  f"txhash {txhash}")
        post_diff = None
        logs = None

    env = build_env(block)
    transaction = build_transaction(tx, access_list)
    # Ensure the signing account (EEST_SENDER) is fundable and nonce-
    # consistent so the tx is admitted and its code actually executes.
    eest = norm_addr(EEST_SENDER)
    pre[eest] = {
        "balance": EEST_SENDER_BALANCE,
        "nonce": hex_int(tx["nonce"]),
        "code": "0x",
        "storage": {},
    }
    pre = dict(sorted(pre.items()))
    post = build_post(receipt)

    info = {
        "comment": "Real mainnet Cancun-era tx replay for u256 limb profiling",
        "source": source,
        "trace_source": trace_source,
        "capture": capture_note,
        "status": receipt.get("status"),
        "gasUsed": receipt.get("gasUsed"),
        "txType": to_hex(tx_type),
        "blockNumber": block_num,
        "labels": {
            "0": f"{(tx.get('to') or '0x')[:10]}|{txhash}|block {block_num}"
        },
    }
    if app_class_hint:
        info["app_class_hint"] = app_class_hint
    if post_diff is not None:
        info["post_diff"] = post_diff
    if logs is not None:
        info["logs"] = logs

    name = fixture_name(tx, None)
    fixture = {
        name: {
            "_info": info,
            "env": env,
            "pre": pre,
            "post": post,
            "transaction": transaction,
        }
    }
    return txhash, fixture


def write_fixture(out_dir: Path, txhash: str, fixture: dict) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{txhash}.json"
    path.write_text(
        json.dumps(fixture, indent=1, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def read_tx_list(path: Path) -> list:
    """Read tx hashes from a text or JSON tx-list.

    Text form: one hash per line, ``#`` comments allowed; the first
    whitespace token of each line is the hash.

    JSON form (as emitted by ``sample_cancun_txs.py``): an object with a
    ``transactions`` list of ``{hash, block, app_class_hint}`` records, or a
    bare list of such records / hash strings. Returns a list of
    ``(hash, app_class_hint)`` tuples (hint may be ``None``).
    """
    raw = path.read_text(encoding="utf-8")
    stripped = raw.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        doc = json.loads(raw)
        rows = doc.get("transactions", doc) if isinstance(doc, dict) else doc
        out = []
        for r in rows:
            if isinstance(r, str):
                out.append((r.strip(), None))
            elif isinstance(r, dict) and r.get("hash"):
                out.append((r["hash"].strip(), r.get("app_class_hint")))
        return out
    out = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append((line.split()[0], None))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--tx", help="single transaction hash")
    src.add_argument("--tx-list", type=Path,
                     help="text (one hash/line) or JSON tx-list file")
    ap.add_argument("--rpc", required=True, help="archive RPC URL")
    ap.add_argument("--out-dir", type=Path, default=Path("."),
                    help="output directory for <txhash>.json fixtures")
    ap.add_argument("--mode", choices=["prestate", "createaccesslist"],
                    default="prestate",
                    help="capture mode (default prestate; exact touched-set "
                         "via debug_traceTransaction prestateTracer)")
    ap.add_argument("--sleep", type=float, default=0.0,
                    help="min seconds between RPC calls (rate-limit throttle)")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--retries", type=int, default=4)
    ap.add_argument("--limit", type=int, default=None,
                    help="stop after writing this many new fixtures")
    ap.add_argument("--drop-log", type=Path, default=None,
                    help="append every dropped/failed tx + reason here")
    ap.add_argument("--allow-post-cancun", action="store_true",
                    help="diagnostic: do not drop blocks whose fork is newer "
                         "than Cancun (Prague+). Off by default per the "
                         "DTVM Cancun-only support window.")
    args = ap.parse_args(argv)

    rpc = Rpc(args.rpc, timeout=args.timeout, retries=args.retries,
              sleep_s=args.sleep)

    if args.tx:
        items = [(args.tx, None)]
    else:
        items = read_tx_list(args.tx_list)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    drop_fp = (args.drop_log.open("a", encoding="utf-8")
               if args.drop_log else None)

    def log_drop(h: str, reason: str) -> None:
        line = f"{h}\t{reason}"
        print(f"[droplog] {line}", file=sys.stderr)
        if drop_fp:
            drop_fp.write(line + "\n")
            drop_fp.flush()

    ok = skipped = dropped = failed = 0
    for h, hint in items:
        if args.limit is not None and ok >= args.limit:
            break
        out_path = args.out_dir / f"{h}.json"
        if out_path.exists():
            skipped += 1
            print(f"[skip] {h}: fixture exists", file=sys.stderr)
            continue
        try:
            result = build_fixture(
                rpc, h, mode=args.mode, app_class_hint=hint,
                allow_post_cancun=args.allow_post_cancun)
        except HistoricalStateUnavailable as exc:
            log_drop(h, f"historical-state-unavailable: {exc}")
            failed += 1
            continue
        except RpcError as exc:
            log_drop(h, f"rpc-error: {exc}")
            failed += 1
            continue
        except (urllib.error.URLError, http.client.HTTPException,
                ConnectionError, TimeoutError, OSError) as exc:
            # A transient network error that survived the Rpc retry loop must
            # not crash the whole run. Log it as a per-tx failure and keep
            # going; the tx can be re-attempted on the next (resumable) run.
            log_drop(h, f"network-error: {type(exc).__name__}: {exc}")
            failed += 1
            continue
        if result is None:
            log_drop(h, "dropped (see stderr for reason)")
            dropped += 1
            continue
        txhash, fixture = result
        path = write_fixture(args.out_dir, txhash, fixture)
        print(f"[ok] {txhash} -> {path}")
        ok += 1

    if drop_fp:
        drop_fp.close()
    print(f"done: {ok} written, {skipped} skipped, {dropped} dropped, "
          f"{failed} failed", file=sys.stderr)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
