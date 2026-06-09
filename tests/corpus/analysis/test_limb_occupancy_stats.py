# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for limb_occupancy_stats.py."""

import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO

import limb_occupancy_stats as los


def write_csv(path, rows):
    header = "codehash,pc,opcode,operand_index,limb_width,limb_mask"
    with open(path, "w", newline="") as f:
        f.write(header + "\n")
        for r in rows:
            f.write(",".join(str(x) for x in r) + "\n")


class ClassifyTest(unittest.TestCase):
    def test_classify_group(self):
        self.assertEqual(los.classify_group(0b0000), "ZERO")
        self.assertEqual(los.classify_group(0b0001), "U64")
        self.assertEqual(los.classify_group(0b0011), "U128-DENSE")
        self.assertEqual(los.classify_group(0b0111), "U192-U256-DENSE")
        self.assertEqual(los.classify_group(0b1111), "U192-U256-DENSE")
        # low limb zero, higher limb set -> high-sparse
        self.assertEqual(los.classify_group(0b0010), "HIGH-SPARSE")
        self.assertEqual(los.classify_group(0b1000), "HIGH-SPARSE")
        self.assertEqual(los.classify_group(0b1100), "HIGH-SPARSE")
        # v0 set with a gap below a set high limb -> mid-gap
        self.assertEqual(los.classify_group(0b0101), "MID-GAP")
        self.assertEqual(los.classify_group(0b1001), "MID-GAP")
        self.assertEqual(los.classify_group(0b1101), "MID-GAP")

    def test_width_from_mask_matches_limbwidth(self):
        self.assertEqual(los.width_from_mask(0b0000), 0)
        self.assertEqual(los.width_from_mask(0b0001), 1)
        self.assertEqual(los.width_from_mask(0b0010), 2)
        self.assertEqual(los.width_from_mask(0b0011), 2)
        self.assertEqual(los.width_from_mask(0b0100), 3)
        self.assertEqual(los.width_from_mask(0b1000), 4)


class NonU64SplitTest(unittest.TestCase):
    def test_split_counts(self):
        # (mask, width): one u64 (excluded), one dense, one high-sparse,
        # one mid-gap.
        items = [
            (0b0001, 1),  # u64 -> excluded
            (0b0011, 2),  # dense
            (0b0010, 2),  # high-sparse (low zero)
            (0b0101, 3),  # mid-gap
        ]
        hs, dense, mid, total = los.non_u64_split(items)
        self.assertEqual((hs, dense, mid, total), (1, 1, 1, 3))


class SiteRepresentativeTest(unittest.TestCase):
    def test_majority_mask_per_site(self):
        # One site (h,0,0) observed 3x mask=1 and 1x mask=3 -> representative 1.
        rows = [
            ("h", 0, 0x01, 0, 1, 1),
            ("h", 0, 0x01, 0, 1, 1),
            ("h", 0, 0x01, 0, 1, 1),
            ("h", 0, 0x01, 0, 2, 3),
        ]
        sites = los.site_representative_masks(rows)
        self.assertEqual(len(sites), 1)
        mask, width, opcode = sites[0]
        self.assertEqual(mask, 1)
        self.assertEqual(width, 1)
        self.assertEqual(opcode, 0x01)


class EndToEndTest(unittest.TestCase):
    def test_report_runs_and_csv_columns(self):
        d = tempfile.mkdtemp()
        a = os.path.join(d, "a.csv")
        write_csv(
            a,
            [
                ("aa", 0, 0x01, 0, 1, 1),  # u64
                ("aa", 0, 0x01, 1, 2, 3),  # u128-dense
                ("aa", 4, 0x02, 0, 2, 2),  # high-sparse single (MUL)
                ("aa", 4, 0x02, 1, 4, 8),  # high-sparse single
            ],
        )
        md_path = os.path.join(d, "rep.md")
        csv_path = os.path.join(d, "occ.csv")
        with redirect_stdout(StringIO()):
            rc = los.main(["--stream-a", a, "--out-md", md_path,
                           "--out-csv", csv_path])
        self.assertEqual(rc, 0)
        with open(md_path) as f:
            md = f.read()
        self.assertIn("Grouped occupancy summary", md)
        self.assertIn("HIGH-SPARSE", md)
        # raw CSV has all 16 mask rows plus header.
        with open(csv_path) as f:
            lines = f.read().strip().splitlines()
        self.assertEqual(len(lines), 17)
        self.assertTrue(lines[0].startswith("limb_mask,label,group"))

    def test_missing_mask_column_errors(self):
        d = tempfile.mkdtemp()
        a = os.path.join(d, "a.csv")
        with open(a, "w") as f:
            f.write("codehash,pc,opcode,operand_index,limb_width\n")
            f.write("aa,0,1,0,1\n")
        with self.assertRaises(SystemExit):
            los.read_stream_a(a)


if __name__ == "__main__":
    unittest.main()
