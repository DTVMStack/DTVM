#!/usr/bin/env python3
"""Collect S0/S1 compiler observations on a deduplicated replay fixture set."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


OBSERVATION_PREFIX = "[DTVM_EVM_COMPILER_OBSERVATION] "


class ExperimentError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".part")
    content = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    with temporary.open("wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def fnv1a64(data: bytes) -> int:
    result = 14695981039346656037
    for byte in data:
        result ^= byte
        result = (result * 1099511628211) & ((1 << 64) - 1)
    return result


def parse_observations(output: str) -> list[dict[str, Any]]:
    observations = []
    for line in output.splitlines():
        if not line.startswith(OBSERVATION_PREFIX):
            continue
        try:
            observation = json.loads(line[len(OBSERVATION_PREFIX) :])
        except json.JSONDecodeError as exc:
            raise ExperimentError("malformed compiler observation record") from exc
        if not isinstance(observation, dict):
            raise ExperimentError("compiler observation record is not an object")
        observations.append(observation)
    return observations


def load_target_fingerprint(
    fixture_path: Path, expected_test_name: str
) -> tuple[str, int]:
    with fixture_path.open("r", encoding="utf-8") as stream:
        fixture = json.load(stream)
    if not isinstance(fixture, dict) or expected_test_name not in fixture:
        raise ExperimentError(
            f"fixture {fixture_path} has no test {expected_test_name}"
        )
    case = fixture[expected_test_name]
    transaction = case.get("transaction", {})
    target_address = transaction.get("to")
    pre = case.get("pre", {})
    target = pre.get(target_address)
    if target is None and isinstance(target_address, str):
        target = pre.get(target_address.lower())
    code = target.get("code") if isinstance(target, dict) else None
    if not isinstance(code, str) or not code.startswith("0x"):
        raise ExperimentError(f"fixture {fixture_path} has no target bytecode")
    try:
        bytecode = bytes.fromhex(code[2:])
    except ValueError as exc:
        raise ExperimentError(f"fixture {fixture_path} has invalid bytecode") from exc
    return f"0x{fnv1a64(bytecode):016x}", len(bytecode)


def select_target_observation(
    observations: list[dict[str, Any]],
    fingerprint: str,
    bytecode_size: int,
) -> dict[str, Any]:
    matches = [
        item
        for item in observations
        if item.get("bytecode_fingerprint_fnv1a64") == fingerprint
        and item.get("bytecode_size") == bytecode_size
    ]
    if len(matches) != 1:
        raise ExperimentError(
            f"expected one target observation for {fingerprint}/{bytecode_size}, "
            f"found {len(matches)}"
        )
    return matches[0]


def ratio(numerator: float, denominator: float) -> float | None:
    return numerator / denominator if denominator else None


def compare_observations(
    s0: dict[str, Any], s1: dict[str, Any]
) -> dict[str, Any]:
    s0_mir = s0["mir_after_frontend"]
    s1_mir = s1["mir_after_frontend"]
    s0_cg = s0["cg_before_phi"]
    s1_cg = s1["cg_before_phi"]
    s0_ra = s0["cg_after_ra"]
    s1_ra = s1["cg_after_ra"]
    metrics = {
        "compile_time": (s0["total_ns"], s1["total_ns"]),
        "frontend_time": (s0["phases_ns"]["frontend"], s1["phases_ns"]["frontend"]),
        "mir_basic_blocks": (s0_mir["basic_blocks"], s1_mir["basic_blocks"]),
        "mir_instructions": (s0_mir["instructions"], s1_mir["instructions"]),
        "cg_basic_blocks": (s0_cg["basic_blocks"], s1_cg["basic_blocks"]),
        "cg_instructions": (s0_cg["instructions"], s1_cg["instructions"]),
        "virtual_registers": (
            s0_cg["virtual_registers"],
            s1_cg["virtual_registers"],
        ),
        "ra_stack_slot_loads": (
            s0_ra["stack_slot_loads"],
            s1_ra["stack_slot_loads"],
        ),
        "emitted_code_bytes": (
            s0["emitted_code_bytes"],
            s1["emitted_code_bytes"],
        ),
    }
    result = {}
    for name, (s0_value, s1_value) in metrics.items():
        result[name] = {
            "s0": s0_value,
            "s1": s1_value,
            "ratio": ratio(s1_value, s0_value),
        }
    phases = {
        name: duration
        for name, duration in s1["phases_ns"].items()
        if name != "observation_overhead"
    }
    result["dominant_s1_phase"] = max(phases, key=phases.get)
    return result


def summarize(fixtures: list[dict[str, Any]]) -> dict[str, Any]:
    metric_names = (
        "compile_time",
        "frontend_time",
        "mir_basic_blocks",
        "mir_instructions",
        "cg_basic_blocks",
        "cg_instructions",
        "virtual_registers",
        "ra_stack_slot_loads",
        "emitted_code_bytes",
    )
    metrics: dict[str, Any] = {}
    for name in metric_names:
        values = [
            item["comparison"][name]["ratio"]
            for item in fixtures
            if item["comparison"][name]["ratio"] is not None
        ]
        metrics[name] = {
            "count": len(values),
            "median_ratio": statistics.median(values) if values else None,
            "geometric_mean_ratio": (
                math.exp(statistics.fmean(math.log(value) for value in values))
                if values and all(value > 0 for value in values)
                else None
            ),
        }
    dominant_counts: dict[str, int] = {}
    for item in fixtures:
        phase = item["comparison"]["dominant_s1_phase"]
        dominant_counts[phase] = dominant_counts.get(phase, 0) + 1
    return {
        "completed_fixtures": len(fixtures),
        "metrics": metrics,
        "dominant_s1_phase_counts": dominant_counts,
    }


def run_variant(
    executable: Path,
    fixture_path: Path,
    test_name: str,
    revision: str,
    cpu: int | None,
    expected_ssa: bool,
) -> dict[str, Any]:
    fingerprint, bytecode_size = load_target_fingerprint(fixture_path, test_name)
    with tempfile.TemporaryDirectory(prefix="dtvm-compiler-observe-") as directory:
        isolated_fixture = Path(directory) / fixture_path.name
        isolated_fixture.symlink_to(fixture_path.resolve())
        test_filter = f"*{test_name}_{revision}_0"
        command = [
            str(executable.resolve()),
            f"--gtest_filter={test_filter}",
        ]
        if cpu is not None:
            command = ["taskset", "-c", str(cpu), *command]
        environment = os.environ.copy()
        environment.update(
            {
                "DTVM_EVM_COMPILER_OBSERVE": "1",
                "DTVM_TEST_DIR": directory,
                "DTVM_TEST_REVISION": revision,
                "DTVM_TEST_MODE": "multipass",
            }
        )
        completed = subprocess.run(
            command,
            check=False,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    if completed.returncode != 0 or "[  PASSED  ] 1 test." not in completed.stdout:
        raise ExperimentError(
            f"{executable} failed for {test_name} (exit {completed.returncode})"
        )
    observation = select_target_observation(
        parse_observations(completed.stdout), fingerprint, bytecode_size
    )
    if observation.get("compile_succeeded") is not True:
        raise ExperimentError(f"compiler observation failed for {test_name}")
    if observation.get("stack_ssa_enabled") is not expected_ssa:
        raise ExperimentError(f"SSA mode mismatch for {test_name}")
    return observation


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--s0", type=Path, required=True)
    parser.add_argument("--s1", type=Path, required=True)
    parser.add_argument("--performance-set", type=Path, required=True)
    parser.add_argument("--fixture-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", default="Osaka")
    parser.add_argument("--cpu", type=int)
    parser.add_argument("--resume", action="store_true")
    return parser.parse_args()


def build_metadata(arguments: argparse.Namespace) -> dict[str, Any]:
    return {
        "performance_set": str(arguments.performance_set.resolve()),
        "performance_set_sha256": sha256_file(arguments.performance_set),
        "fixture_dir": str(arguments.fixture_dir.resolve()),
        "revision": arguments.revision,
        "cpu": arguments.cpu,
        "executables": {
            "S0": {
                "path": str(arguments.s0.resolve()),
                "sha256": sha256_file(arguments.s0),
            },
            "S1": {
                "path": str(arguments.s1.resolve()),
                "sha256": sha256_file(arguments.s1),
            },
        },
    }


def main() -> int:
    arguments = parse_arguments()
    for path in (arguments.s0, arguments.s1, arguments.performance_set):
        if not path.is_file():
            raise ExperimentError(f"file not found: {path}")
    if not arguments.fixture_dir.is_dir():
        raise ExperimentError(f"fixture directory not found: {arguments.fixture_dir}")

    with arguments.performance_set.open("r", encoding="utf-8") as stream:
        manifest = json.load(stream)
    records = manifest.get("fixtures")
    if not isinstance(records, list):
        raise ExperimentError("performance set has no fixtures array")

    metadata = build_metadata(arguments)
    results: list[dict[str, Any]] = []
    if arguments.resume and arguments.output.exists():
        with arguments.output.open("r", encoding="utf-8") as stream:
            previous = json.load(stream)
        if previous.get("metadata") != metadata:
            raise ExperimentError("cannot resume: experiment metadata changed")
        results = previous.get("fixtures", [])

    completed_positions = {item["position"] for item in results}
    for record_index, record in enumerate(records, start=1):
        position = int(record["position"])
        if position in completed_positions:
            continue
        fixture_path = arguments.fixture_dir / record["fixture"]
        test_name = record["test_name"]
        order = ("S0", "S1") if position % 2 else ("S1", "S0")
        observations: dict[str, dict[str, Any]] = {}
        print(
            f"[{record_index}/{len(records)}] position={position} "
            f"{record['module_code_hash']} "
            f"order={','.join(order)}",
            flush=True,
        )
        for variant in order:
            observations[variant] = run_variant(
                arguments.s0 if variant == "S0" else arguments.s1,
                fixture_path,
                test_name,
                arguments.revision,
                arguments.cpu,
                expected_ssa=variant == "S1",
            )
        result = {
            "position": position,
            "fixture": record["fixture"],
            "fixture_sha256": sha256_file(fixture_path),
            "test_name": test_name,
            "transaction_hash": record.get("transaction_hash"),
            "module_code_hash": record.get("module_code_hash"),
            "frequency": int(record.get("frequency", 1)),
            "observations": observations,
            "comparison": compare_observations(
                observations["S0"], observations["S1"]
            ),
        }
        results.append(result)
        results.sort(key=lambda item: item["position"])
        atomic_json(
            arguments.output,
            {
                "schema_version": 1,
                "status": "in_progress",
                "metadata": metadata,
                "fixtures": results,
                "summary": summarize(results),
            },
        )

    final = {
        "schema_version": 1,
        "status": "completed",
        "metadata": metadata,
        "fixtures": results,
        "summary": summarize(results),
    }
    atomic_json(arguments.output, final)
    print(json.dumps(final["summary"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ExperimentError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)
