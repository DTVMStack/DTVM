#!/usr/bin/env python3
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Canonical-semantic equality comparator for EEST ``state_test`` fixtures.

Two fixtures are *canonically equal* when they describe the same EVM
execution, ignoring representation noise:

  * JSON object key order
  * storage-map key order
  * hex casing and zero-padding (``0x0A`` == ``0xa`` == ``0x000a``)
  * integer-vs-hex encoding of scalar fields (nonce, gas)
  * the synthetic top-level case name (``replay_<...>``)

It compares the semantic payload: ``env``, the prestate (``pre``: balance,
nonce, code, storage), the embedded ``transaction`` (including the
``accessList``), and the execution outcome recorded in ``_info``
(status + gasUsed) plus the ``post`` stanza shape.

Usage::

    fixture_equal.py OLD.json NEW.json

Exit code 0 when equal, 1 when not equal (a structured diff is printed),
2 on usage/parse error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def hex_int(v):
    if v is None:
        return 0
    if isinstance(v, int):
        return v
    s = str(v).strip()
    if s == "":
        return 0
    return int(s, 16) if s.lower().startswith("0x") else int(s)


def canon_scalar(v) -> str:
    """Canonicalise a numeric scalar (hex or int) to ``0x``-lowercase-min."""
    return hex(hex_int(v))


def canon_addr(a) -> str:
    if a is None or a == "":
        return ""
    return "0x" + str(a).lower().removeprefix("0x").rjust(40, "0")


def canon_word(v) -> str:
    """Canonicalise a 32-byte word (storage value) to 0x + 64 lower hex."""
    return "0x" + format(hex_int(v), "064x")


def canon_code(c) -> str:
    if c is None:
        return "0x"
    s = str(c).lower()
    if not s.startswith("0x"):
        s = "0x" + s
    return s if s != "0x" else "0x"


def first_case(fixture: dict) -> dict:
    if not isinstance(fixture, dict) or not fixture:
        raise ValueError("fixture is not a non-empty object")
    name = next(iter(fixture))
    return fixture[name]


def canon_env(env: dict) -> dict:
    if not env:
        return {}
    out = {}
    for k in ("currentNumber", "currentTimestamp", "currentGasLimit",
              "currentBaseFee", "currentDifficulty"):
        if k in env:
            out[k] = canon_scalar(env[k])
    if "currentCoinbase" in env:
        out["currentCoinbase"] = canon_addr(env["currentCoinbase"])
    for k in ("currentRandom", "previousHash"):
        if k in env and env[k] is not None:
            out[k] = str(env[k]).lower()
    return out


def canon_account(acc: dict) -> dict:
    storage = {}
    for slot, val in (acc.get("storage") or {}).items():
        cv = canon_word(val)
        if cv != canon_word("0x0"):
            storage[canon_word(slot)] = cv
    return {
        "balance": canon_scalar(acc.get("balance", "0x0")),
        "nonce": canon_scalar(acc.get("nonce", "0x0")),
        "code": canon_code(acc.get("code", "0x")),
        "storage": dict(sorted(storage.items())),
    }


def canon_pre(pre: dict) -> dict:
    out = {}
    for addr, acc in (pre or {}).items():
        out[canon_addr(addr)] = canon_account(acc)
    return dict(sorted(out.items()))


def canon_access_list(al) -> list:
    norm = []
    for e in al or []:
        norm.append((
            canon_addr(e.get("address", "")),
            tuple(sorted(canon_word(k)
                         for k in (e.get("storageKeys") or []))),
        ))
    norm.sort()
    return [{"address": a, "storageKeys": list(ks)} for a, ks in norm]


def _as_list(v):
    return v if isinstance(v, list) else [v]


def canon_transaction(tx: dict) -> dict:
    out = {
        "data": [str(d).lower() for d in _as_list(tx.get("data", []))],
        "gasLimit": [canon_scalar(g) for g in _as_list(tx.get("gasLimit", []))],
        "value": [canon_scalar(v) for v in _as_list(tx.get("value", []))],
        "gasPrice": canon_scalar(tx.get("gasPrice", "0x0")),
        "nonce": canon_scalar(tx.get("nonce", "0x0")),
        "sender": canon_addr(tx.get("sender", "")),
        "to": canon_addr(tx.get("to", "")),
        "accessList": canon_access_list(tx.get("accessList")),
    }
    return out


def canon_post(post: dict) -> dict:
    """Canonicalise the post stanza by fork.

    The fixtures use placeholder hash/logs, so we compare the structural
    shape (fork name + per-fork entry count + indexes) rather than asserting
    a state root the debug-free path cannot recompute.
    """
    out = {}
    for fork, entries in (post or {}).items():
        rows = []
        for e in entries or []:
            rows.append({
                "hash": str(e.get("hash", "")).lower(),
                "logs": str(e.get("logs", "")).lower(),
                "indexes": e.get("indexes", {}),
                "txbytes": str(e.get("txbytes", "")).lower(),
            })
        out[fork] = rows
    return out


def canon_outcome(info: dict) -> dict:
    """Execution outcome recorded in ``_info`` (status + gasUsed).

    Older prestateTracer fixtures may not carry these fields; absence is
    represented as ``None`` so two fixtures both lacking it compare equal,
    while a present-vs-absent mismatch is surfaced.
    """
    out = {}
    if info is None:
        info = {}
    if "status" in info:
        out["status"] = canon_scalar(info.get("status"))
    if "gasUsed" in info:
        out["gasUsed"] = canon_scalar(info.get("gasUsed"))
    return out


def canonicalize(fixture: dict) -> dict:
    case = first_case(fixture)
    return {
        "env": canon_env(case.get("env", {})),
        "pre": canon_pre(case.get("pre", {})),
        "transaction": canon_transaction(case.get("transaction", {})),
        "post": canon_post(case.get("post", {})),
        "outcome": canon_outcome(case.get("_info", {})),
    }


def _diff(path: str, a, b, out: list) -> None:
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a:
                out.append(f"{path}.{k}: MISSING in OLD, NEW={b[k]!r}")
            elif k not in b:
                out.append(f"{path}.{k}: present in OLD={a[k]!r}, MISSING in NEW")
            else:
                _diff(f"{path}.{k}", a[k], b[k], out)
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append(f"{path}: list len OLD={len(a)} NEW={len(b)}")
        for i, (x, y) in enumerate(zip(a, b)):
            _diff(f"{path}[{i}]", x, y, out)
    else:
        if a != b:
            out.append(f"{path}: OLD={a!r} != NEW={b!r}")


def compare(old: dict, new: dict):
    ca = canonicalize(old)
    cb = canonicalize(new)
    diffs: list = []
    _diff("", ca, cb, diffs)
    diffs = [d.lstrip(".") for d in diffs]
    return (len(diffs) == 0), diffs


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("old", type=Path)
    ap.add_argument("new", type=Path)
    ap.add_argument("--json", action="store_true",
                    help="emit the diff as a JSON list on stderr")
    args = ap.parse_args(argv)

    try:
        old = json.loads(args.old.read_text(encoding="utf-8"))
        new = json.loads(args.new.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    equal, diffs = compare(old, new)
    if equal:
        print("EQUAL")
        return 0

    print("NOT EQUAL")
    if args.json:
        print(json.dumps(diffs, indent=1), file=sys.stderr)
    else:
        for d in diffs:
            print(f"  {d}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
