# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for build_manifest: keccak, classification, dual-weighting."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import build_manifest as bm  # noqa: E402


# Real USDT runtime-code prefix is irrelevant; we use synthetic codes so the
# codehash dedup is deterministic and self-contained.
CODE_A = "0x60016002"   # shared by two fixtures -> dedups in unique view
CODE_B = "0x60036004"   # unique


def make_fixture(name, to, code, selector, block, value="0x0"):
    data = selector + "00" * 32
    return {
        name: {
            "_info": {"status": "0x1", "gasUsed": "0x5208"},
            "env": {
                "currentNumber": hex(block),
                "currentCoinbase": "0x" + "ab" * 20,
            },
            "pre": {
                to: {"balance": "0x0", "nonce": 0, "code": code,
                     "storage": {}},
            },
            "transaction": {
                "data": [data],
                "gasLimit": ["0x5208"],
                "value": [value],
                "gasPrice": "0x1",
                "nonce": "0x0",
                "sender": "0x" + "cd" * 20,
                "to": to,
                "accessList": [],
            },
            "post": {"Cancun": [{"hash": "0x" + "0" * 64,
                                 "logs": "0x" + "0" * 64,
                                 "indexes": {"data": 0, "gas": 0, "value": 0},
                                 "txbytes": "0x00"}]},
        }
    }


class TestKeccak(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(
            bm.keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")

    def test_abc(self):
        self.assertEqual(
            bm.keccak256(b"abc").hex(),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")

    def test_codehash_empty_code(self):
        self.assertEqual(bm.codehash("0x"), bm.EMPTY_CODE_HASH)
        self.assertEqual(bm.codehash(""), bm.EMPTY_CODE_HASH)


class TestClassify(unittest.TestCase):
    def test_known_address_stablecoin(self):
        self.assertEqual(
            bm.classify("0xdac17f958d2ee523a2206206994597c13d831ec7",
                        "0xa9059cbb", True),
            "stablecoin")

    def test_erc20_heuristic(self):
        self.assertEqual(
            bm.classify("0x" + "12" * 20, "0xa9059cbb", True), "erc20")

    def test_swap_heuristic(self):
        self.assertEqual(
            bm.classify("0x" + "12" * 20, "0x38ed1739", True), "dex-router")

    def test_eoa_transfer(self):
        self.assertEqual(
            bm.classify("0x" + "12" * 20, "0x", False), "eoa-transfer")


class TestManifestCounts(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        # 3 USDT transfers (known stablecoin, shared CODE_A) -> logical 3,
        #   unique 1 by codehash
        usdt = "0xdac17f958d2ee523a2206206994597c13d831ec7"
        for i in range(3):
            fx = make_fixture(f"replay_usdt_{i}", usdt, CODE_A,
                              "0xa9059cbb", 100 + i)
            (self.dir / f"0x{i:064x}.json").write_text(json.dumps(fx))
        # 1 heuristic erc20 (different addr, CODE_A too -> same codehash as
        #   USDT, so unique should still collapse all CODE_A together)
        erc = "0x" + "12" * 20
        (self.dir / f"0x{10:064x}.json").write_text(
            json.dumps(make_fixture("replay_erc_0", erc, CODE_A,
                                    "0xa9059cbb", 105)))
        # 1 swap (CODE_B, unique codehash)
        router = "0x" + "34" * 20
        (self.dir / f"0x{11:064x}.json").write_text(
            json.dumps(make_fixture("replay_swap_0", router, CODE_B,
                                    "0x38ed1739", 110)))

    def test_block_range(self):
        m = bm.scan(self.dir)
        self.assertEqual(m["block_range"]["min"], 100)
        self.assertEqual(m["block_range"]["max"], 110)

    def test_fixture_count(self):
        m = bm.scan(self.dir)
        self.assertEqual(m["fixture_count"], 5)

    def test_logical_vs_unique_app_class(self):
        m = bm.scan(self.dir)
        logical = m["app_class"]["logical"]
        # 3 USDT -> stablecoin; 1 erc20 heuristic; 1 dex-router
        self.assertEqual(logical.get("stablecoin"), 3)
        self.assertEqual(logical.get("erc20"), 1)
        self.assertEqual(logical.get("dex-router"), 1)

    def test_codehash_dual_weight(self):
        m = bm.scan(self.dir)
        cw = m["codehash_weighting"]
        # 6 logical txns total? no, 5 fixtures
        self.assertEqual(cw["logical_total"], 5)
        # CODE_A shared by 4 fixtures (3 USDT + 1 erc), CODE_B by 1
        # -> 2 unique codehashes
        self.assertEqual(cw["unique_total"], 2)
        # the CODE_A codehash should carry logical_count 4
        ch_a = bm.codehash(CODE_A)
        self.assertEqual(cw["per_codehash"][ch_a]["logical_count"], 4)

    def test_unique_app_class_count(self):
        m = bm.scan(self.dir)
        # unique view dedups by codehash: CODE_A -> first-seen class
        # (stablecoin), CODE_B -> dex-router. So unique has 2 classes.
        unique = m["app_class"]["unique"]
        self.assertEqual(sum(unique.values()), 2)


if __name__ == "__main__":
    unittest.main()
