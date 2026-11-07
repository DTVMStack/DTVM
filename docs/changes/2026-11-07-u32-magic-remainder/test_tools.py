# SPDX-License-Identifier: Apache-2.0
"""Regression checks for invalid paired data and benchmark child cleanup."""
import ast
import gzip
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from sample_data import load_paired_samples


class PairedDataTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.manifest = {
            "rounds": 2,
            "binaries": {k: {} for k in ["main", "candidate", "wasmtime"]},
            "jobs": [{"name": "rem-3", "iterations": 1}],
        }
        self.rows = [
            {
                "case": "rem-3",
                "engine": engine,
                "round": index,
                "exit": 0,
                "wall_ms": 1 + index,
            }
            for engine in self.manifest["binaries"]
            for index in range(2)
        ]

    def write(self, compressed=False):
        (self.folder / "manifest.json").write_text(json.dumps(self.manifest))
        text = "".join(json.dumps(row) + "\n" for row in self.rows)
        if compressed:
            with gzip.open(self.folder / "samples.jsonl.gz", "wt") as stream:
                stream.write(text)
        else:
            (self.folder / "samples.jsonl").write_text(text)

    def test_complete_compressed_data_preserves_rounds(self):
        self.write(compressed=True)
        groups, _ = load_paired_samples(self.folder, ["wall_ms"])
        self.assertEqual(set(groups["rem-3"]["candidate"]), {0, 1})

    def test_incomplete_round_is_rejected_instead_of_intersected(self):
        self.rows.pop()
        self.write()
        with self.assertRaisesRegex(ValueError, "incomplete process pairs"):
            load_paired_samples(self.folder, ["wall_ms"])

    def test_duplicate_round_is_not_overwritten(self):
        self.rows.append(dict(self.rows[0]))
        self.write()
        with self.assertRaisesRegex(ValueError, "duplicate sample"):
            load_paired_samples(self.folder, ["wall_ms"])

    def test_failed_measured_process_cannot_enter_statistics(self):
        self.rows[0]["exit"] = 1
        self.write()
        with self.assertRaisesRegex(ValueError, "failed measured process"):
            load_paired_samples(self.folder, ["wall_ms"])

    def test_nonfinite_metric_is_rejected(self):
        self.rows[0]["wall_ms"] = float("nan")
        self.write()
        with self.assertRaisesRegex(ValueError, "invalid positive timing"):
            load_paired_samples(self.folder, ["wall_ms"])

    def test_missing_successful_case_is_rejected(self):
        self.rows = [
            {"case": "rem-3", "engine": engine, "round": -1, "exit": 0}
            for engine in self.manifest["binaries"]
        ]
        self.write()
        with self.assertRaisesRegex(ValueError, "missing measured case"):
            load_paired_samples(self.folder, ["wall_ms"])

    def test_failed_warmup_case_is_excluded(self):
        self.manifest["jobs"].append({"name": "excluded", "iterations": 1})
        self.rows.extend(
            {"case": "excluded", "engine": engine, "round": -1, "exit": 1}
            for engine in self.manifest["binaries"]
        )
        self.write()
        groups, _ = load_paired_samples(self.folder, ["wall_ms"])
        self.assertNotIn("excluded", groups)

    def test_cli_does_not_write_summary_for_partial_data(self):
        self.rows.pop()
        self.write()
        script = Path(__file__).with_name("summarize.py")
        result = subprocess.run(
            [sys.executable, str(script), str(self.folder)], capture_output=True
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.folder / "summary.csv").exists())

    def test_sign_cli_rejects_noop_as_hot_family(self):
        names = [
            "rem-" + str(d) for d in [3, 7, 10, 20, 255, 1900, 2100, 65521, 4294967295]
        ]
        self.manifest["jobs"] = [{"name": name, "iterations": 0} for name in names]
        self.rows = [
            {**row, "case": name, "warm_ms": 1.0} for name in names for row in self.rows
        ]
        self.write()
        script = Path(__file__).with_name("sign_tests.py")
        result = subprocess.run(
            [sys.executable, str(script), str(self.folder)], capture_output=True
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"positive-iteration", result.stderr)


class ChildCleanupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Extract the real collector without executing the CLI/input generator.
        path = Path(__file__).with_name("micro_bench.py")
        tree = ast.parse(path.read_text())
        function = next(
            n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run"
        )
        namespace = {
            "os": os,
            "subprocess": subprocess,
            "selectors": selectors,
            "time": time,
            "env": os.environ.copy(),
        }
        exec(
            compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec"),
            namespace,
        )
        cls.collect = staticmethod(namespace["run"])

    def invoke(self, program, expect_timeout=False, expect_failure=False):
        children = []
        real_popen = subprocess.Popen

        def spawn(*args, **kwargs):
            proc = real_popen(*args, **kwargs)
            children.append(proc)
            return proc

        with mock.patch.object(subprocess, "Popen", side_effect=spawn):
            if expect_timeout:
                with self.assertRaises(TimeoutError):
                    self.collect([sys.executable, "-c", program], timeout_s=0.2)
                result = None
            elif expect_failure:
                with self.assertRaises(RuntimeError):
                    self.collect([sys.executable, "-c", program], timeout_s=5)
                result = None
            else:
                result = self.collect([sys.executable, "-c", program], timeout_s=5)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)
        self.assertTrue(children[0].stdout.closed)
        self.assertTrue(children[0].stderr.closed)
        return result

    def test_successful_packets(self):
        data, receipts, _ = self.invoke("import os; os.write(1, b'x' * 48)")
        self.assertEqual(data, b"x" * 48)
        self.assertEqual(len(receipts), 2)

    def test_timeout_with_open_pipes(self):
        self.invoke("import time; time.sleep(30)", expect_timeout=True)

    def test_timeout_after_both_output_pipes_close(self):
        self.invoke(
            "import os,time; os.close(1); os.close(2); time.sleep(30)",
            expect_timeout=True,
        )

    def test_failed_child_is_reaped_and_streams_closed(self):
        self.invoke(
            "import os; os.write(2, b'failure'); raise SystemExit(3)",
            expect_failure=True,
        )


class ArgumentTests(unittest.TestCase):
    def test_invalid_divisors_fail_before_creating_output(self):
        script = Path(__file__).with_name("micro_bench.py")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "unused"
            for value in ["0", "4294967296", "3,3"]:
                with self.subTest(divisors=value):
                    result = subprocess.run(
                        [
                            sys.executable,
                            str(script),
                            "--main",
                            "unused",
                            "--candidate",
                            "unused",
                            "--wasmtime",
                            "unused",
                            "--out",
                            str(out),
                            "--divisors",
                            value,
                        ],
                        capture_output=True,
                    )
                    self.assertEqual(result.returncode, 2)
                    self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
