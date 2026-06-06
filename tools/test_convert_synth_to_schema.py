"""Tests for convert_synth_to_schema.py.

Each test invokes the converter as a subprocess so the CLI contract is
exercised end-to-end (matches Phase 5 invocation pattern). Uses stdlib
unittest only (no pytest dependency).

    python3 tools/test_convert_synth_to_schema.py -v
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = REPO / "tools" / "convert_synth_to_schema.py"


def _scalar_rule(name: str, lhs: str, rhs: str, inputs, delta_dmir=-1, coverage=None):
    return {
        "name": name,
        "status": "synthesized",
        "source": "pattern_config",
        "inputs": list(inputs),
        "lhs": lhs,
        "rhs": rhs,
        "cost": {
            "lhs": {
                "dmir_inst": 1,
                "select_depth": 0,
                "adc_chain": 0,
                "runtime_calls": 0,
            },
            "rhs": {
                "dmir_inst": 0,
                "select_depth": 0,
                "adc_chain": 0,
                "runtime_calls": 0,
            },
            "delta": {
                "dmir_inst": delta_dmir,
                "select_depth": 0,
                "adc_chain": 0,
                "runtime_calls": 0,
            },
        },
        "validation": {"modes": ["smt"], "coverage": list(coverage or [])},
    }


def _carry_rule(name: str):
    return {
        "name": name,
        "status": "synthesized",
        "source": "enumerator",
        "inputs": ["x", "y", "c"],
        "lhs": "(adc x y c)",
        "rhs": "(adc x y c)",
        "cost": {
            "lhs": {"dmir_inst": 1, "select_depth": 0, "adc_chain": 1, "runtime_calls": 0},
            "rhs": {"dmir_inst": 1, "select_depth": 0, "adc_chain": 1, "runtime_calls": 0},
            "delta": {"dmir_inst": 0, "select_depth": 0, "adc_chain": 0, "runtime_calls": 0},
        },
        "validation": {"modes": ["smt"], "coverage": []},
    }


def _run(rules, extra_args=None, with_report=False):
    fp = tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w")
    json.dump({"rules": rules}, fp)
    fp.close()
    out = pathlib.Path(fp.name).with_suffix(".out.json")
    cmd = [
        sys.executable,
        str(SCRIPT),
        "--input",
        fp.name,
        "--output",
        str(out),
        "--coverage-default",
        "synthetic_e9_audit",
    ]
    report = None
    if with_report:
        report = pathlib.Path(fp.name).with_suffix(".rep.json")
        cmd += ["--report", str(report)]
    cmd += list(extra_args or [])
    subprocess.check_call(cmd)
    parsed_out = json.loads(out.read_text())
    if report is not None:
        return parsed_out, json.loads(report.read_text())
    return parsed_out


class ConverterTests(unittest.TestCase):
    def test_simple_rule_converts_with_full_schema(self):
        out = _run([_scalar_rule("synth-and-self-001", "(and x x)", "x", ["x"])])
        self.assertGreaterEqual(out["version"], 1)
        self.assertEqual(len(out["rules"]), 1)
        rec = out["rules"][0]
        self.assertEqual(rec["name"], "synth-and-self-001")
        self.assertEqual(rec["status"], "candidate")
        self.assertEqual(rec["ir_width"], 64)
        self.assertEqual(rec["lhs"], "(and x x)")
        self.assertEqual(rec["rhs"], "x")
        self.assertEqual(rec["validation"]["modes"], ["smt"])
        self.assertEqual(rec["validation"]["coverage"], ["synthetic_e9_audit"])
        self.assertEqual(rec["cost"]["delta"]["dmir_inst"], -1)

    def test_carry_shape_skipped_by_default(self):
        out = _run([_carry_rule("synth-adc-001")])
        self.assertEqual(len(out["rules"]), 0)
        self.assertEqual(out["skipped"][0]["name"], "synth-adc-001")
        self.assertEqual(out["skipped"][0]["reason"], "unsupported_shape")

    def test_carry_shape_kept_when_allowed(self):
        out = _run([_carry_rule("synth-adc-002")], extra_args=["--allow-carry-select"])
        self.assertEqual(len(out["rules"]), 1)
        self.assertEqual(out["rules"][0]["name"], "synth-adc-002")

    def test_existing_coverage_passthrough(self):
        rule = _scalar_rule(
            "synth-pre-002", "(xor x x)", "0:i64", ["x"], coverage=["already_present"]
        )
        out = _run([rule])
        self.assertEqual(out["rules"][0]["validation"]["coverage"], ["already_present"])

    def test_report_counts_match_input(self):
        rules = [
            _scalar_rule("synth-and-001", "(and x x)", "x", ["x"]),
            _carry_rule("synth-adc-skip"),
        ]
        _, rep = _run(rules, with_report=True)
        self.assertEqual(rep["input_count"], 2)
        self.assertEqual(rep["converted_count"] + rep["skipped_count"], 2)


class DupMapTests(unittest.TestCase):
    def test_emits_dup_map_when_prod_rules_provided(self):
        # candidate that duplicates a prod rule by exact (lhs, rhs)
        cand = _scalar_rule("synth-and-self-dup", "(and x x)", "x", ["x"])
        # candidate that has no production analogue
        novel = _scalar_rule(
            "synth-novel-001", "(and (and x y) (xor x y))", "0:i64", ["x", "y"]
        )
        prod_rules = [
            {"name": "dmir_and_self_to_self", "lhs": "(and x x)", "rhs": "x"},
        ]
        prod_fp = tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w")
        json.dump({"version": 1, "rules": prod_rules}, prod_fp)
        prod_fp.close()

        fp = tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w")
        json.dump({"rules": [cand, novel]}, fp)
        fp.close()
        out = pathlib.Path(fp.name).with_suffix(".out.json")
        dup_out = pathlib.Path(fp.name).with_suffix(".dup.json")
        cmd = [
            sys.executable, str(SCRIPT),
            "--input", fp.name,
            "--output", str(out),
            "--prod-rules", prod_fp.name,
            "--dup-map-output", str(dup_out),
            "--coverage-default", "synthetic_e9_audit",
        ]
        subprocess.check_call(cmd)
        dup_map = json.loads(dup_out.read_text())
        self.assertEqual(dup_map["synth-and-self-dup"], "dmir_and_self_to_self")
        self.assertNotIn("synth-novel-001", dup_map)
        self.assertEqual(len(dup_map), 1)


if __name__ == "__main__":
    unittest.main()
