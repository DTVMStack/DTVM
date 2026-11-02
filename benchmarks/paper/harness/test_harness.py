"""Regression tests for case selection and benchmark failure reporting.

Run from the repository root:
    python3 -m unittest discover -s benchmarks/paper/harness -p 'test_*.py'
"""

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import run as harness


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.catalog = harness.read_json(harness.CATALOG_PATH)
        self.cases = harness.load_cases(self.catalog)

    def select(self, preset, scale, only=None, suites=None):
        return harness.select_cases(
            self.cases, preset, self.catalog, only, scale, suites
        )

    def test_paper_presets_select_paper_iterations(self):
        for preset, iterations in (("fib", "500000000"), ("overflow", "100000000")):
            with self.subTest(preset=preset):
                cases = self.select(preset, "paper")
                self.assertEqual(len(cases), 2)
                self.assertTrue(all(c["id"].endswith("_paper") for c in cases))
                self.assertTrue(all(c["args"][0] == iterations for c in cases))

    def test_dev_and_smoke_presets_keep_dev_iterations(self):
        for preset in ("fib", "overflow"):
            self.assertTrue(all(c["scale"] == "dev" for c in self.select(preset, "dev")))
        smoke = self.select("smoke", "paper")
        self.assertEqual(len(smoke), 5)
        self.assertTrue(all(c.get("scale", "dev") == "dev" for c in smoke))

    def test_explicit_cases_override_scale_but_obey_suite_filter(self):
        cases = self.select("fib", "paper", ["fib_iter_dev"])
        self.assertEqual([c["id"] for c in cases], ["fib_iter_dev"])
        self.assertEqual(self.select("fib", "paper", ["fib_iter_dev"], ["wapm"]), [])

    @staticmethod
    def sample(ok=True, timeout=False):
        return dict(ok=ok, exit=None if timeout else (0 if ok else 1),
                    timeout=timeout, wall_s=0.1,
                    output="success" if ok else "measurement failed")

    def measure(self, samples, warmup=0):
        with patch.object(harness, "time_once", side_effect=samples):
            return harness.run_cell(
                ["fake"], Path("."), None, warmup, len(samples) - warmup,
                1.0, None, False
            )

    def test_partial_failure_is_not_a_successful_cell(self):
        cell = self.measure([self.sample(), self.sample(False), self.sample(False, True)])
        self.assertFalse(cell["ok"])
        self.assertTrue(cell["timeout"])
        self.assertEqual(cell["sample_exits"], [0, 1, None])
        self.assertEqual(cell["failed_samples"], 2)
        self.assertEqual(cell["timed_out_samples"], 1)
        self.assertEqual(cell["samples_s"], [0.1])
        cell.update(bench="atax", fairness="same-wasm", runtime="dtvm", mode="interp")
        self.assertIn("| fail |", harness.markdown_table([cell]))

    def test_failed_output_survives_later_success(self):
        cell = self.measure([self.sample(False), self.sample()])
        self.assertFalse(cell["ok"])
        self.assertIn("measurement failed", cell["output_tail"])

    def test_silent_timeout_does_not_erase_failure_output(self):
        timeout = self.sample(False, True)
        timeout["output"] = ""
        cell = self.measure([self.sample(False), timeout, self.sample()])
        self.assertFalse(cell["ok"])
        self.assertIn("measurement failed", cell["output_tail"])
        self.assertEqual(cell["timed_out_samples"], 1)

    def test_launch_error_is_a_failed_measurement(self):
        for error in (FileNotFoundError("missing loader"), OSError("Exec format error")):
            with self.subTest(error=error):
                with patch.object(harness.subprocess, "run", side_effect=error):
                    cell = harness.run_cell(
                        ["broken"], Path("."), None, 0, 2, 1, None, False
                    )
                self.assertFalse(cell["ok"])
                self.assertFalse(cell["timeout"])
                self.assertEqual(cell["failed_samples"], 2)
                self.assertEqual(cell["sample_exits"], [None, None])
                self.assertIn(str(error), cell["output_tail"])

    def test_real_launch_errors_are_saved_and_next_cell_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            binary = tmp / "broken-dtvm"
            binary.write_text("#!/nonexistent/paper-bench-interpreter\n")
            binary.chmod(0o755)
            out = tmp / "results"
            proc = subprocess.run([
                sys.executable, str(Path(harness.__file__).resolve()),
                "--cases", "atax", "--runtimes", "dtvm",
                "--dtvm", str(binary), "--dtvm-modes", "interp,singlepass",
                "--cpu", "-1", "--warmup", "0", "--repeats", "1",
                "--out", str(out)
            ], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 1, proc.stderr)
            result = json.loads((out / "results.json").read_text())
            self.assertEqual(len(result["runs"]), 2)
            for cell in result["runs"]:
                self.assertFalse(cell["ok"])
                self.assertIn("FileNotFoundError", cell["output_tail"])

    def test_all_successful_samples_pass(self):
        cell = self.measure([self.sample(), self.sample(), self.sample()])
        self.assertTrue(cell["ok"])
        self.assertEqual(cell["failed_samples"], 0)
        self.assertFalse(cell["timeout"])

    def test_warmup_failure_prevents_measurement(self):
        cell = self.measure([self.sample(False, True), self.sample()], warmup=1)
        self.assertFalse(cell["ok"])
        self.assertTrue(cell["timeout"])
        self.assertEqual(cell["sample_exits"], [])
        self.assertIn("measurement failed", cell["output_tail"])

    def run_main(self, args, samples=(), wasmtime=None):
        with tempfile.TemporaryDirectory() as out:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                with patch.object(harness, "time_once", side_effect=samples), \
                        patch.object(harness, "require_wasm"), \
                        patch.object(harness, "resolve_wasmtime", return_value=wasmtime), \
                        patch.object(harness, "resolve_dtvm", return_value=Path("/fake/dtvm")):
                    code = harness.main([
                        "--cases", "atax", "--cpu", "-1", "--warmup", "0",
                        "--repeats", "3", "--out", out, *args
                    ])
            filename = "commands.json" if "--dry-run" in args else "results.json"
            return code, json.loads((Path(out) / filename).read_text())



    def test_empty_execution_plan_fails(self):
        code, result = self.run_main([
            "--runtimes", "dtvm", "--dtvm-modes", "interp",
            "--cases", "jacobi-2d"
        ])
        self.assertEqual(code, 1)
        self.assertEqual(result["runs"], [])

    def test_partial_failure_propagates_to_results_and_exit_status(self):
        code, result = self.run_main(
            ["--runtimes", "dtvm", "--dtvm-modes", "interp"],
            [self.sample(), self.sample(False), self.sample(False, True)]
        )
        self.assertEqual(code, 1)
        self.assertEqual(result["runs"][0]["failed_samples"], 2)
        self.assertTrue(result["runs"][0]["timeout"])
        self.assertIn("measurement failed", result["runs"][0]["output_tail"])

    def test_statistics_use_separate_samples_and_commands(self):
        for flags in (["--stats"],):
            commands = []

            def sample(cmd, *args):
                commands.append(cmd)
                rec = self.sample()
                if "--enable-statistics" in cmd:
                    rec["wall_s"] = 9.0
                    rec["output"] = "Total compilation time: 12 ms (12345 μs)\n"
                return rec

            with self.subTest(flags=flags):
                code, result = self.run_main(
                    ["--runtimes", "dtvm", "--dtvm-modes", "interp", *flags],
                    sample
                )
                self.assertEqual(code, 0)
                self.assertEqual(len(commands), 6)
                self.assertTrue(all("--enable-statistics" not in c for c in commands[:3]))
                self.assertTrue(all("--enable-statistics" in c for c in commands[3:]))
                cell = result["runs"][0]
                self.assertEqual(cell["samples_s"], [0.1] * 3)
                self.assertEqual(cell["median_s"], 0.1)
                self.assertEqual(cell["instrumented"]["median_s"], 9.0)


    def test_failed_wall_pass_does_not_start_instrumented_pass(self):
        code, result = self.run_main(
            ["--runtimes", "dtvm", "--dtvm-modes", "interp", "--stats"],
            [self.sample(False)] * 3
        )
        self.assertEqual(code, 1)
        self.assertIsNone(result["runs"][0]["instrumented"])

    def test_stats_dry_run_exposes_both_commands(self):
        code, result = self.run_main([
            "--runtimes", "dtvm", "--dtvm-modes", "interp",
            "--stats", "--dry-run"
        ])
        self.assertEqual(code, 0)
        cmd = result["commands"][0]
        self.assertNotIn("--enable-statistics", cmd["command"])
        self.assertIn("--enable-statistics", cmd["instrumented_command"])

    def test_stats_keeps_wasmtime_on_one_uninstrumented_pass(self):
        commands = []

        def sample(cmd, *args):
            commands.append(cmd)
            return self.sample()

        code, result = self.run_main(
            ["--runtimes", "dtvm,wasmtime", "--dtvm-modes", "interp",
             "--stats"], sample, Path("/fake/wasmtime")
        )
        self.assertEqual(code, 0)
        self.assertEqual(len(commands), 9)
        self.assertTrue(all(c[0] == "/fake/wasmtime" for c in commands[-3:]))
        self.assertTrue(all("--enable-statistics" not in c for c in commands[-3:]))
        self.assertIsNone(result["runs"][1]["instrumented"])


    def test_explicit_runtime_paths_do_not_fall_back(self):
        for resolver, var in ((harness.resolve_dtvm, "DTVM"),
                              (harness.resolve_wasmtime, "WASMTIME")):
            with self.subTest(runtime=var):
                with patch.dict(os.environ, {var: sys.executable}):
                    with contextlib.redirect_stderr(io.StringIO()):
                        with self.assertRaises(SystemExit) as exc:
                            resolver("/nonexistent/paper-bench-runtime")
                    self.assertEqual(exc.exception.code, 2)
                with patch.dict(os.environ, {var: "/nonexistent/paper-bench-runtime"}):
                    self.assertEqual(resolver(sys.executable), Path(sys.executable).resolve())
                    with contextlib.redirect_stderr(io.StringIO()):
                        with self.assertRaises(SystemExit):
                            resolver(None)

    def test_build_script_can_run_outside_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            llvm = tmp / "llvm"
            llvm.mkdir()
            (llvm / "LLVMConfig.cmake").touch()
            fake = tmp / "cmake"
            fake.write_text("#!" + sys.executable + "\n" +
                "import os,sys,json\nfrom pathlib import Path\n" +
                "with open(os.environ['CMAKE_TEST_LOG'], 'a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')\n" +
                "if '--build' in sys.argv:\n" +
                " p=Path(sys.argv[2])/'dtvm';p.parent.mkdir(parents=True,exist_ok=True);p.touch();p.chmod(0o755)\n")
            fake.chmod(0o755)
            env = dict(os.environ, PATH=str(tmp) + os.pathsep + os.environ.get("PATH", ""),
                       LLVM_DIR=str(llvm), BUILD_DIR=str(tmp / "build"),
                       CMAKE_TEST_LOG=str(tmp / "cmake.jsonl"), JOBS="1")
            script = harness.HARNESS_DIR / "build_dtvm.sh"
            proc = subprocess.run(["bash", str(script)], cwd=tmp, env=env,
                                  capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            args = json.loads((tmp / "cmake.jsonl").read_text().splitlines()[0])
            self.assertEqual(args[args.index("-S") + 1], str(harness.REPO_ROOT))


if __name__ == "__main__":
    unittest.main()
