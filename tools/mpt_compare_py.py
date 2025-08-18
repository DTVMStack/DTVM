#!/usr/bin/env python3
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json, sys
from typing import Dict, Any

import rlp
from eth_hash.auto import keccak
from trie import HexaryTrie


def hex_to_int(hex_str: str) -> int:
    if hex_str is None:
        return 0
    s = hex_str.lower()
    if s in ("", "0x", "0", "0x0", "0x00"):
        return 0
    if s.startswith("0x"):
        return int(s, 16)
    return int(s, 16)


def int_to_minimal_bytes(value: int) -> bytes:
    if value == 0:
        return b""
    length = (value.bit_length() + 7) // 8
    return value.to_bytes(length, "big")


def to_0x(b: bytes) -> str:
    return "0x" + b.hex()


def bytes_no_0x(b: bytes) -> str:
    return b.hex()


def compute_storage_root(storage: Dict[str, str]) -> bytes:
    t = HexaryTrie(db={})
    if not storage:
        return t.root_hash
    for k_hex, v_hex in storage.items():
        if v_hex in ("", "0x", "0x00", "0"):
            continue
        key_bytes = bytes.fromhex(k_hex[2:] if k_hex.startswith("0x") else k_hex)
        key_hash = keccak(key_bytes)

        v_int = hex_to_int(v_hex)
        v_bytes = int_to_minimal_bytes(v_int)
        encoded_val = rlp.encode(v_bytes)
        t[key_hash] = encoded_val
    return t.root_hash


def calculate_state_root_from_json(accounts_json: Dict[str, Any]) -> Dict[str, Any]:
    state_trie = HexaryTrie(db={})
    empty_storage_root = HexaryTrie(db={}).root_hash

    processed = []
    for address_hex, acc in accounts_json.items():
        addr_bytes = bytes.fromhex(address_hex[2:] if address_hex.startswith("0x") else address_hex)
        addr_hash = keccak(addr_bytes)

        code_hex = acc.get("code", "0x")
        code_bytes = bytes.fromhex(code_hex[2:]) if code_hex and code_hex != "0x" else b""
        code_hash = keccak(code_bytes)

        nonce_bytes = int_to_minimal_bytes(hex_to_int(acc.get("nonce", "0x0")))
        balance_bytes = int_to_minimal_bytes(hex_to_int(acc.get("balance", "0x0")))

        storage_dict = acc.get("storage", {}) or {}
        storage_root = compute_storage_root(storage_dict) if storage_dict else empty_storage_root

        account_rlp = rlp.encode([nonce_bytes, balance_bytes, storage_root, code_hash])
        state_trie[addr_hash] = account_rlp

        processed.append({
            "address": address_hex.lower(),
            "addressHash": to_0x(addr_hash),
            "nonce": bytes_no_0x(nonce_bytes),
            "balance": bytes_no_0x(balance_bytes),
            "storageRoot": to_0x(storage_root),
            "codeHash": to_0x(code_hash),
            "accountRLP": to_0x(account_rlp),
        })

    return {"stateRoot": to_0x(state_trie.root_hash), "accounts": processed}


def main():
    if len(sys.argv) != 2:
        print("Usage: python mpt_compare_py.py <json_file>", file=sys.stderr)
        sys.exit(1)
    json_file = sys.argv[1]
    try:
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        result = calculate_state_root_from_json(data)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
