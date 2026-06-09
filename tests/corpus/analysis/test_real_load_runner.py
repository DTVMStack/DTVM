# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit test for tools/run_real_load_profile.py analyze-only mode."""

import importlib.util
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path


REPO = Path(__file__).resolve().parents[3]
RUNNER_PATH = REPO / "tools/run_real_load_profile.py"

spec = importlib.util.spec_from_file_location("run_real_load_profile", RUNNER_PATH)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def make_fixture(name, to, code, selector, block):
    return {
        name: {
            "_info": {"status": "0x1", "gasUsed": "0x5208"},
            "env": {
                "currentNumber": hex(block),
                "currentCoinbase": "0x" + "ab" * 20,
            },
            "pre": {
                to: {
                    "balance": "0x0",
                    "nonce": 0,
                    "code": code,
                    "storage": {},
                },
            },
            "transaction": {
                "data": [selector + "00" * 32],
                "gasLimit": ["0x5208"],
                "value": ["0x0"],
                "gasPrice": "0x1",
                "nonce": "0x0",
                "sender": "0x" + "cd" * 20,
                "to": to,
                "accessList": [],
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


class RealLoadRunnerTest(unittest.TestCase):
    def test_analyze_only_generates_reports_and_summary(self):
        root = Path(tempfile.mkdtemp())
        corpus = root / "corpus"
        profile = corpus / "runtime-profile"
        out = root / "out"
        corpus.mkdir()
        profile.mkdir()

        to = "0x" + "12" * 20
        fixture = make_fixture("replay_synthetic", to, "0x60016002", "0xa9059cbb", 100)
        write(corpus / ("0x" + "1" * 64 + ".json"), json.dumps(fixture))

        write(
            profile / "stream_a_limb.csv",
            "\n".join(
                [
                    "codehash,pc,opcode,operand_index,limb_width,limb_mask",
                    "aa,5,1,0,1,1",
                    "aa,5,1,1,1,1",
                    "aa,6,2,0,2,3",
                    "aa,6,2,1,1,1",
                    "",
                ]
            ),
        )
        write(
            profile / "stream_b_range.csv",
            "\n".join(
                [
                    "codehash,pc,opcode,lhs_range,rhs_range,lhs_source,rhs_source,path,lhs_const,rhs_const",
                    "aa,5,1,U64,U256,PUSH,SLOAD,CONST_U64,1,0",
                    "aa,6,2,U256,U64,MLOAD,PUSH,FULL,0,1",
                    "",
                ]
            ),
        )
        write(profile / "app_class_map.json", json.dumps({"aa": "stablecoin"}))

        with redirect_stdout(StringIO()):
            rc = runner.main(
                [
                    "--analyze-only",
                    "--corpus",
                    str(corpus),
                    "--profile-dir",
                    str(profile),
                    "--out-dir",
                    str(out),
                    "--quiet",
                ]
            )
        self.assertEqual(rc, 0)

        summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["fixture_count"], 1)
        self.assertEqual(summary["stream_rows"]["stream_a_limb"], 4)
        self.assertEqual(summary["stream_rows"]["stream_b_range"], 2)
        self.assertAlmostEqual(
            summary["range_gap"]["runtime_narrow_but_static_unknown_ratio"],
            1.0 / 3.0,
        )
        self.assertAlmostEqual(
            summary["fastpath"]["ADD"]["exec"]["fast_hit_pct"], 1.0
        )
        self.assertAlmostEqual(summary["fastpath"]["MUL"]["exec"]["fast_hit_pct"], 0.0)
        self.assertAlmostEqual(summary["occupancy"]["U64"]["exec_pct"], 0.75)
        self.assertTrue((out / "reports/range_gap_report.md").exists())
        self.assertTrue((out / "reports/fastpath_hitrate.md").exists())
        self.assertTrue((out / "reports/limb_occupancy_report.md").exists())

    def test_analyze_only_rejects_smoke_suite_mismatch(self):
        root = Path(tempfile.mkdtemp())
        corpus = root / "corpus"
        corpus.mkdir()

        with self.assertRaises(SystemExit):
            runner.main(
                [
                    "--analyze-only",
                    "--suite",
                    "smoke",
                    "--corpus",
                    str(corpus),
                    "--profile-dir",
                    str(corpus / "runtime-profile"),
                    "--out-dir",
                    str(root / "out"),
                    "--quiet",
                ]
            )

    def test_smoke_selection_prefers_contract_calls(self):
        root = Path(tempfile.mkdtemp())
        corpus = root / "corpus"
        corpus.mkdir()
        for name in ("00_eoa.json", "01_call.json", "02_call.json"):
            write(corpus / name, "{}")

        manifest = {
            "fixtures": [
                {
                    "app_class": "dex-router",
                    "file": "00_eoa.json",
                    "stratum": "data-to-eoa",
                },
                {
                    "app_class": "dex-router",
                    "file": "01_call.json",
                    "stratum": "contract-call",
                },
                {
                    "app_class": "dex-router",
                    "file": "02_call.json",
                    "stratum": "contract-call",
                },
            ]
        }

        target = runner.prepare_smoke_corpus(corpus, manifest, root / "out", 1)
        self.assertTrue((target / "01_call.json").exists())
        self.assertFalse((target / "00_eoa.json").exists())

    def test_smoke_default_samples_multiple_contracts_per_class(self):
        args = runner.parse_args(["--suite", "smoke"])
        self.assertEqual(args.smoke_per_class, 4)


if __name__ == "__main__":
    unittest.main()
