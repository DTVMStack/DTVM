# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for fixture_equal.canonical-semantic equality."""

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import fixture_equal  # noqa: E402


def base_fixture():
    return {
        "replay_0xdeadbeef_0": {
            "_info": {
                "status": "0x1",
                "gasUsed": "0x5208",
                "source": "archive ...",
            },
            "env": {
                "currentNumber": "0x10",
                "currentTimestamp": "0x61a8d289",
                "currentGasLimit": "0x1c9c380",
                "currentCoinbase": "0xAABBccDDeeff00112233445566778899aAbBcCdD",
                "currentBaseFee": "0x0a",
                "currentDifficulty": "0x0",
                "currentRandom": "0x" + "ab" * 32,
                "previousHash": "0x" + "cd" * 32,
            },
            "pre": {
                "0xdac17f958d2ee523a2206206994597c13d831ec7": {
                    "balance": "0x0de0b6b3a7640000",
                    "nonce": 7,
                    "code": "0x6060",
                    "storage": {
                        "0x01": "0x2a",
                        "0x02": "0x00",  # zero slot, should be ignored
                    },
                },
            },
            "transaction": {
                "data": ["0xA9059CBB"],
                "gasLimit": ["0x5208"],
                "value": ["0x00"],
                "gasPrice": "0x0a",
                "nonce": "0x07",
                "sender": "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
                "to": "0xDAC17F958D2EE523A2206206994597C13D831EC7",
                "accessList": [
                    {
                        "address": "0xDAC17F958D2EE523A2206206994597C13D831EC7",
                        "storageKeys": ["0x1", "0x02"],
                    }
                ],
            },
            "post": {
                "Cancun": [
                    {
                        "hash": "0x" + "0" * 64,
                        "logs": "0x" + "0" * 64,
                        "indexes": {"data": 0, "gas": 0, "value": 0},
                        "txbytes": "0x00",
                    }
                ]
            },
        }
    }


class TestFixtureEqual(unittest.TestCase):
    def test_identical_is_equal(self):
        a = base_fixture()
        b = copy.deepcopy(a)
        equal, diffs = fixture_equal.compare(a, b)
        self.assertTrue(equal, diffs)

    def test_case_name_ignored(self):
        a = base_fixture()
        b = copy.deepcopy(a)
        case = b.pop("replay_0xdeadbeef_0")
        b["replay_0xother_99"] = case
        equal, diffs = fixture_equal.compare(a, b)
        self.assertTrue(equal, diffs)

    def test_hex_casing_and_padding_ignored(self):
        a = base_fixture()
        b = copy.deepcopy(a)
        c = b["replay_0xdeadbeef_0"]
        # re-encode scalars with different casing/padding
        c["env"]["currentBaseFee"] = "0xA"          # was 0x0a
        c["transaction"]["gasPrice"] = "0x000A"     # was 0x0a
        c["pre"]["0xdac17f958d2ee523a2206206994597c13d831ec7"][
            "storage"]["0x01"] = "0x000000000000002A"  # was 0x2a
        equal, diffs = fixture_equal.compare(a, b)
        self.assertTrue(equal, diffs)

    def test_address_checksum_ignored(self):
        a = base_fixture()
        b = copy.deepcopy(a)
        c = b["replay_0xdeadbeef_0"]
        c["transaction"]["to"] = c["transaction"]["to"].lower()
        c["env"]["currentCoinbase"] = c["env"]["currentCoinbase"].upper(
        ).replace("0X", "0x")
        equal, diffs = fixture_equal.compare(a, b)
        self.assertTrue(equal, diffs)

    def test_storage_order_ignored(self):
        a = base_fixture()
        b = copy.deepcopy(a)
        acct = b["replay_0xdeadbeef_0"]["pre"][
            "0xdac17f958d2ee523a2206206994597c13d831ec7"]
        acct["storage"] = {"0x02": "0x00", "0x01": "0x2a"}  # reversed
        equal, diffs = fixture_equal.compare(a, b)
        self.assertTrue(equal, diffs)

    def test_access_list_order_ignored(self):
        a = base_fixture()
        b = copy.deepcopy(a)
        # add a second access list entry in both, reversed order in b
        for fx, rev in ((a, False), (b, True)):
            tx = fx["replay_0xdeadbeef_0"]["transaction"]
            extra = {"address": "0x" + "11" * 20, "storageKeys": ["0x05"]}
            if rev:
                tx["accessList"] = [extra] + tx["accessList"]
            else:
                tx["accessList"] = tx["accessList"] + [extra]
        equal, diffs = fixture_equal.compare(a, b)
        self.assertTrue(equal, diffs)

    def test_balance_diff_detected(self):
        a = base_fixture()
        b = copy.deepcopy(a)
        b["replay_0xdeadbeef_0"]["pre"][
            "0xdac17f958d2ee523a2206206994597c13d831ec7"][
            "balance"] = "0x01"
        equal, diffs = fixture_equal.compare(a, b)
        self.assertFalse(equal)
        self.assertTrue(any("balance" in d for d in diffs), diffs)

    def test_storage_value_diff_detected(self):
        a = base_fixture()
        b = copy.deepcopy(a)
        b["replay_0xdeadbeef_0"]["pre"][
            "0xdac17f958d2ee523a2206206994597c13d831ec7"][
            "storage"]["0x01"] = "0x99"
        equal, diffs = fixture_equal.compare(a, b)
        self.assertFalse(equal)

    def test_status_diff_detected(self):
        a = base_fixture()
        b = copy.deepcopy(a)
        b["replay_0xdeadbeef_0"]["_info"]["status"] = "0x0"
        equal, diffs = fixture_equal.compare(a, b)
        self.assertFalse(equal)
        self.assertTrue(any("status" in d for d in diffs), diffs)

    def test_env_diff_detected(self):
        a = base_fixture()
        b = copy.deepcopy(a)
        b["replay_0xdeadbeef_0"]["env"]["currentNumber"] = "0x11"
        equal, diffs = fixture_equal.compare(a, b)
        self.assertFalse(equal)


if __name__ == "__main__":
    unittest.main()
