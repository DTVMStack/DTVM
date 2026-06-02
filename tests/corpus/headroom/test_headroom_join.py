# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for headroom_join.py on synthetic CSV streams."""

import os
import tempfile
import unittest

import headroom_join as hj


def write_csv(path, header, rows):
    with open(path, "w", newline="") as f:
        f.write(header + "\n")
        for r in rows:
            f.write(",".join(str(x) for x in r) + "\n")


class HeadroomJoinTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.a = os.path.join(self.dir, "a.csv")
        self.b = os.path.join(self.dir, "b.csv")

    def test_limb_width_helper_via_histogram(self):
        # Two operands of one ADD site. operand 0: 3 of 4 rows fit u64.
        # operand 1: 0 of 2 rows fit u64.
        write_csv(
            self.a,
            "codehash,pc,opcode,operand_index,limb_width",
            [
                ("aa", 5, 1, 0, 1),
                ("aa", 5, 1, 0, 0),
                ("aa", 5, 1, 0, 1),
                ("aa", 5, 1, 0, 4),
                ("aa", 5, 1, 1, 2),
                ("aa", 5, 1, 1, 3),
            ],
        )
        rows = hj.read_stream_a(self.a)
        hist = hj.histogram_stream_a(rows)
        cell0 = hist[("aa", 5, 1)][0]
        cell1 = hist[("aa", 5, 1)][1]
        self.assertEqual(cell0, [3, 4])  # limb_width<=1 -> 3 of 4
        self.assertEqual(cell1, [0, 2])

    def test_join_and_missed_headroom(self):
        # Stream B says operand 0 proved U64 (PUSH), operand 1 only U256 (SLOAD).
        write_csv(
            self.a,
            "codehash,pc,opcode,operand_index,limb_width",
            [
                ("aa", 5, 1, 0, 1),  # dyn fits u64
                ("aa", 5, 1, 0, 1),
                ("aa", 5, 1, 1, 1),  # dyn fits u64 but analyzer says U256
                ("aa", 5, 1, 1, 1),
            ],
        )
        write_csv(
            self.b,
            "codehash,pc,opcode,lhs_range,rhs_range,lhs_source,rhs_source",
            [("aa", 5, 1, "U64", "U256", "PUSH", "SLOAD")],
        )
        a = hj.read_stream_a(self.a)
        b = hj.read_stream_b(self.b)
        table = hj.build_cross_table(a, b)
        self.assertEqual(len(table), 2)  # 2 operand slots joined

        by_src = {r["source_kind"]: r for r in hj.aggregate(table, "source_kind")}
        # PUSH operand: dyn=1.0, proved=1.0 -> missed 0.0
        self.assertAlmostEqual(by_src["PUSH"]["dynamic_u64_rate"], 1.0)
        self.assertAlmostEqual(by_src["PUSH"]["analyzer_proved_u64_rate"], 1.0)
        self.assertAlmostEqual(by_src["PUSH"]["missed_headroom"], 0.0)
        # SLOAD operand: dyn=1.0, proved=0.0 -> missed 1.0 (recoverable)
        self.assertAlmostEqual(by_src["SLOAD"]["dynamic_u64_rate"], 1.0)
        self.assertAlmostEqual(by_src["SLOAD"]["analyzer_proved_u64_rate"], 0.0)
        self.assertAlmostEqual(by_src["SLOAD"]["missed_headroom"], 1.0)

    def test_unmatched_keys_excluded(self):
        # Stream A key not present in Stream B must not appear in the join.
        write_csv(
            self.a,
            "codehash,pc,opcode,operand_index,limb_width",
            [("zz", 9, 2, 0, 1)],
        )
        write_csv(
            self.b,
            "codehash,pc,opcode,lhs_range,rhs_range,lhs_source,rhs_source",
            [("aa", 5, 1, "U64", "U64", "PUSH", "PUSH")],
        )
        a = hj.read_stream_a(self.a)
        b = hj.read_stream_b(self.b)
        table = hj.build_cross_table(a, b)
        self.assertEqual(table, [])

    def test_ternary_third_operand_dropped(self):
        # operand_index 2 (ternary modulus) has no Stream B slot -> dropped.
        write_csv(
            self.a,
            "codehash,pc,opcode,operand_index,limb_width",
            [
                ("aa", 7, 8, 0, 1),
                ("aa", 7, 8, 1, 1),
                ("aa", 7, 8, 2, 4),
            ],
        )
        write_csv(
            self.b,
            "codehash,pc,opcode,lhs_range,rhs_range,lhs_source,rhs_source",
            [("aa", 7, 8, "U64", "U64", "PUSH", "PUSH")],
        )
        a = hj.read_stream_a(self.a)
        b = hj.read_stream_b(self.b)
        table = hj.build_cross_table(a, b)
        idxs = sorted(r["operand_index"] for r in table)
        self.assertEqual(idxs, [0, 1])  # operand 2 dropped

    def test_opcode_name(self):
        self.assertEqual(hj.opcode_name(1), "ADD")
        self.assertEqual(hj.opcode_name(0x0A), "EXP")
        self.assertEqual(hj.opcode_name(0xFF), "0xff")

    def test_opcode_name_extended_consumers(self):
        # Comparison, bitwise and shift consumers added by the extended taps.
        self.assertEqual(hj.opcode_name(0x10), "LT")
        self.assertEqual(hj.opcode_name(0x14), "EQ")
        self.assertEqual(hj.opcode_name(0x15), "ISZERO")
        self.assertEqual(hj.opcode_name(0x16), "AND")
        self.assertEqual(hj.opcode_name(0x1A), "BYTE")
        self.assertEqual(hj.opcode_name(0x1D), "SAR")

    def test_unary_consumer_single_slot(self):
        # ISZERO is unary: Stream A emits operand_index 0 only; Stream B carries
        # the "NA" sentinel in the rhs slot. The join must yield exactly one
        # slot and never surface the "NA" rhs source.
        write_csv(
            self.a,
            "codehash,pc,opcode,operand_index,limb_width",
            [
                ("aa", 3, 0x15, 0, 1),
                ("aa", 3, 0x15, 0, 4),
            ],
        )
        write_csv(
            self.b,
            "codehash,pc,opcode,lhs_range,rhs_range,lhs_source,rhs_source",
            [("aa", 3, 0x15, "U256", "NA", "SLOAD", "NA")],
        )
        a = hj.read_stream_a(self.a)
        b = hj.read_stream_b(self.b)
        table = hj.build_cross_table(a, b)
        self.assertEqual(len(table), 1)
        self.assertEqual(table[0]["operand_index"], 0)
        self.assertEqual(table[0]["source_kind"], "SLOAD")
        self.assertNotIn("NA", [r["source_kind"] for r in table])

    def test_new_source_kinds_aggregate(self):
        # The extended producer tags (ENV, AND, SHIFT, COMPARE) must survive the
        # join and aggregate distinctly by source_kind.
        write_csv(
            self.a,
            "codehash,pc,opcode,operand_index,limb_width",
            [
                ("bb", 1, 0x16, 0, 1),
                ("bb", 1, 0x16, 1, 1),
            ],
        )
        write_csv(
            self.b,
            "codehash,pc,opcode,lhs_range,rhs_range,lhs_source,rhs_source",
            [("bb", 1, 0x16, "U64", "U256", "ENV", "AND")],
        )
        a = hj.read_stream_a(self.a)
        b = hj.read_stream_b(self.b)
        table = hj.build_cross_table(a, b)
        by_src = {r["source_kind"]: r for r in hj.aggregate(table, "source_kind")}
        self.assertIn("ENV", by_src)
        self.assertIn("AND", by_src)
        self.assertAlmostEqual(by_src["ENV"]["analyzer_proved_u64_rate"], 1.0)
        self.assertAlmostEqual(by_src["AND"]["analyzer_proved_u64_rate"], 0.0)


if __name__ == "__main__":
    unittest.main()
