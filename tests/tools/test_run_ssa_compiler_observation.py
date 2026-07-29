import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = (
    Path(__file__).parents[2] / "tools" / "run_ssa_compiler_observation.py"
)
SPEC = importlib.util.spec_from_file_location(
    "run_ssa_compiler_observation", SCRIPT
)
run_ssa_compiler_observation = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = run_ssa_compiler_observation
SPEC.loader.exec_module(run_ssa_compiler_observation)


def observation(value: int) -> dict:
    return {
        "total_ns": value * 10,
        "emitted_code_bytes": value * 20,
        "phases_ns": {
            "frontend": value * 5,
            "register_allocation": value,
            "observation_overhead": value * 2,
        },
        "mir_after_frontend": {
            "basic_blocks": value,
            "instructions": value * 2,
        },
        "cg_before_phi": {
            "basic_blocks": value * 3,
            "instructions": value * 4,
            "virtual_registers": value * 5,
        },
        "cg_after_ra": {
            "stack_slot_loads": value * 6,
        },
    }


class SSACompilerObservationTest(unittest.TestCase):
    def test_parse_observations(self) -> None:
        output = (
            "noise\n"
            f"{run_ssa_compiler_observation.OBSERVATION_PREFIX}"
            '{"schema_version":1,"total_ns":12}\n'
        )
        self.assertEqual(
            run_ssa_compiler_observation.parse_observations(output),
            [{"schema_version": 1, "total_ns": 12}],
        )

    def test_load_target_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.json"
            address = "0x" + "aa" * 20
            path.write_text(
                json.dumps(
                    {
                        "MainnetReplay_x": {
                            "transaction": {"to": address},
                            "pre": {address: {"code": "0x60016000"}},
                        }
                    }
                ),
                encoding="utf-8",
            )
            fingerprint, size = (
                run_ssa_compiler_observation.load_target_fingerprint(
                    path, "MainnetReplay_x"
                )
            )
        self.assertEqual(size, 4)
        self.assertEqual(
            fingerprint,
            f"0x{run_ssa_compiler_observation.fnv1a64(bytes.fromhex('60016000')):016x}",
        )

    def test_compare_observations_excludes_observation_overhead(self) -> None:
        comparison = run_ssa_compiler_observation.compare_observations(
            observation(2), observation(6)
        )
        self.assertEqual(comparison["compile_time"]["ratio"], 3)
        self.assertEqual(comparison["dominant_s1_phase"], "frontend")

    def test_select_target_observation_requires_unique_match(self) -> None:
        expected = {
            "bytecode_fingerprint_fnv1a64": "0xabc",
            "bytecode_size": 4,
        }
        self.assertIs(
            run_ssa_compiler_observation.select_target_observation(
                [expected], "0xabc", 4
            ),
            expected,
        )
        with self.assertRaises(
            run_ssa_compiler_observation.ExperimentError
        ):
            run_ssa_compiler_observation.select_target_observation(
                [expected, expected], "0xabc", 4
            )


if __name__ == "__main__":
    unittest.main()
