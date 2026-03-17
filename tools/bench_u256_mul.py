#!/usr/bin/env python3
"""
Benchmark dynamic U256 MUL workloads through `evmc run --bench`.

The synthetic `synth/MUL` benchmark in multipass JIT can constant-fold away the
multiply chain. This helper keeps the operands runtime-dependent so the lowering
under test remains in the hot path.
"""

import argparse
import re
import statistics
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional


DEFAULT_INPUT_32 = (
    "0102030405060708090a0b0c0d0e0f10"
    "1112131415161718191a1b1c1d1e1f20"
)
DEFAULT_INPUT_64 = DEFAULT_INPUT_32 + DEFAULT_INPUT_32


@dataclass(frozen=True)
class BenchmarkCase:
    name: str
    code: str
    input_hex: str
    description: str


@dataclass(frozen=True)
class BenchmarkSample:
    time_ns: int
    gas_used: int
    output_hex: str


TIME_RE = re.compile(r"Time:\s+(\d+) ns")
GAS_RE = re.compile(r"Gas used:\s+(\d+)")
OUTPUT_RE = re.compile(r"Output:\s+([0-9a-fA-F]*)")


def build_square_loop_case(iterations: int) -> BenchmarkCase:
    if iterations <= 0 or iterations > 255:
        raise ValueError("square-loop iterations must be in [1, 255]")

    loop_counter = (1 << 256) - iterations
    loop_counter_hex = f"{loop_counter:064x}"
    jumpdest_offset = 35
    jumpdest_hex = f"{jumpdest_offset:02x}"

    code = (
        "5f35"
        f"7f{loop_counter_hex}"
        "5b"
        "8180029150"
        f"6001018060{jumpdest_hex}57"
        "505f5260205ff3"
    )

    return BenchmarkCase(
        name=f"square-loop-{iterations}",
        code=code,
        input_hex=DEFAULT_INPUT_32,
        description=f"{iterations} runtime-dependent squarings in a compact loop",
    )


def default_cases() -> Dict[str, BenchmarkCase]:
    return {
        "single-mul": BenchmarkCase(
            name="single-mul",
            code="6000356020350260005260206000f3",
            input_hex=DEFAULT_INPUT_64,
            description="One runtime-dependent CALLDATALOAD x CALLDATALOAD multiply",
        ),
        "single-square": BenchmarkCase(
            name="single-square",
            code="5f3580025f5260205ff3",
            input_hex=DEFAULT_INPUT_32,
            description="One runtime-dependent CALLDATALOAD squared via DUP1 MUL",
        ),
        "square-loop-255": build_square_loop_case(255),
        "square-loop-64": build_square_loop_case(64),
    }


def run_case(
    evmc_bin: Path,
    library: Path,
    mode: str,
    revision: Optional[str],
    case: BenchmarkCase,
    cpu: Optional[str] = None,
) -> BenchmarkSample:
    cmd = [
        str(evmc_bin),
        "--vm",
        f"{library},mode={mode}",
        "run",
        case.code,
        "--input",
        case.input_hex,
        "--bench",
    ]
    if revision:
        cmd.extend(["--rev", revision])
    if cpu is not None:
        cmd = ["taskset", "-c", cpu, *cmd]
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=True,
    )
    output = proc.stdout

    time_match = TIME_RE.search(output)
    gas_match = GAS_RE.search(output)
    result_match = OUTPUT_RE.search(output)
    if time_match is None or gas_match is None or result_match is None:
        raise RuntimeError(f"failed to parse evmc output:\n{output}")

    return BenchmarkSample(
        time_ns=int(time_match.group(1)),
        gas_used=int(gas_match.group(1)),
        output_hex=result_match.group(1),
    )


def benchmark_library(
    evmc_bin: Path,
    library: Path,
    mode: str,
    revision: Optional[str],
    cases: Iterable[BenchmarkCase],
    repeat: int,
    warmup: int,
    cpu: Optional[str],
) -> Dict[str, List[BenchmarkSample]]:
    results: Dict[str, List[BenchmarkSample]] = {}
    for case in cases:
        samples: List[BenchmarkSample] = []
        for _ in range(warmup):
            run_case(evmc_bin, library, mode, revision, case, cpu)
        for _ in range(repeat):
            samples.append(run_case(evmc_bin, library, mode, revision, case, cpu))
        results[case.name] = samples
    return results


def benchmark_libraries_interleaved(
    evmc_bin: Path,
    current_library: Path,
    baseline_library: Path,
    mode: str,
    revision: Optional[str],
    cases: Iterable[BenchmarkCase],
    repeat: int,
    warmup: int,
    cpu: Optional[str],
) -> tuple[Dict[str, List[BenchmarkSample]], Dict[str, List[BenchmarkSample]]]:
    current_results: Dict[str, List[BenchmarkSample]] = {}
    baseline_results: Dict[str, List[BenchmarkSample]] = {}
    for case in cases:
        current_samples: List[BenchmarkSample] = []
        baseline_samples: List[BenchmarkSample] = []
        for _ in range(warmup):
            run_case(evmc_bin, current_library, mode, revision, case, cpu)
            run_case(evmc_bin, baseline_library, mode, revision, case, cpu)
        for rep in range(repeat):
            if rep % 2 == 0:
                current_samples.append(
                    run_case(evmc_bin, current_library, mode, revision, case, cpu)
                )
                baseline_samples.append(
                    run_case(evmc_bin, baseline_library, mode, revision, case, cpu)
                )
            else:
                baseline_samples.append(
                    run_case(evmc_bin, baseline_library, mode, revision, case, cpu)
                )
                current_samples.append(
                    run_case(evmc_bin, current_library, mode, revision, case, cpu)
                )
        current_results[case.name] = current_samples
        baseline_results[case.name] = baseline_samples
    return current_results, baseline_results


def median_time_ns(samples: List[BenchmarkSample]) -> float:
    return statistics.median(sample.time_ns for sample in samples)


def format_delta(current: float, baseline: float) -> str:
    if baseline == 0:
        return "n/a"
    delta = (current - baseline) / baseline * 100.0
    return f"{delta:+.2f}%"


def print_report(
    title: str,
    library: Path,
    cases: Iterable[BenchmarkCase],
    samples_by_case: Dict[str, List[BenchmarkSample]],
    baseline_by_case: Optional[Dict[str, List[BenchmarkSample]]] = None,
) -> None:
    print(f"\n[{title}] {library}")
    print(
        f"{'case':<18} {'median(ns)':>10} {'min':>8} {'max':>8} "
        f"{'gas':>8} {'delta':>9}"
    )
    for case in cases:
        samples = samples_by_case[case.name]
        times = [sample.time_ns for sample in samples]
        gas_used = samples[0].gas_used
        output_hex = samples[0].output_hex
        if any(sample.gas_used != gas_used or sample.output_hex != output_hex for sample in samples):
            raise RuntimeError(f"inconsistent result for case {case.name}")

        delta = "   n/a"
        if baseline_by_case is not None:
            delta = format_delta(median_time_ns(samples), median_time_ns(baseline_by_case[case.name]))

        print(
            f"{case.name:<18} {median_time_ns(samples):>10.1f} {min(times):>8} {max(times):>8} "
            f"{gas_used:>8} {delta:>9}"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run dynamic U256 MUL microbenchmarks through evmc",
    )
    parser.add_argument(
        "--evmc-bin",
        type=Path,
        required=True,
        help="Path to the evmc binary from the evmone for_test checkout",
    )
    parser.add_argument(
        "--library",
        type=Path,
        required=True,
        help="Path to the libdtvmapi.so under test",
    )
    parser.add_argument(
        "--baseline-library",
        type=Path,
        help="Optional baseline libdtvmapi.so to compare against",
    )
    parser.add_argument(
        "--mode",
        default="multipass",
        help="VM mode forwarded to the EVMC config string",
    )
    parser.add_argument(
        "--revision",
        default=None,
        help="Optional EVM revision forwarded to `evmc run`",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=5,
        help="How many full evmc runs to execute per case",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=1,
        help="How many warmup runs to discard per case/library",
    )
    parser.add_argument(
        "--taskset-cpu",
        default=None,
        help="Optional CPU affinity passed to `taskset -c` for every evmc run",
    )
    parser.add_argument(
        "--case",
        action="append",
        dest="case_names",
        help="Benchmark case to run. Can be specified multiple times.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    cases_by_name = default_cases()

    if args.case_names:
        unknown = [name for name in args.case_names if name not in cases_by_name]
        if unknown:
            print(f"unknown case(s): {', '.join(unknown)}", file=sys.stderr)
            return 2
        cases = [cases_by_name[name] for name in args.case_names]
    else:
        cases = list(cases_by_name.values())

    for case in cases:
        print(f"{case.name}: {case.description}")

    baseline_results = None
    if args.baseline_library is not None:
        current_results, baseline_results = benchmark_libraries_interleaved(
            args.evmc_bin,
            args.library,
            args.baseline_library,
            args.mode,
            args.revision,
            cases,
            args.repeat,
            args.warmup,
            args.taskset_cpu,
        )
    else:
        current_results = benchmark_library(
            args.evmc_bin,
            args.library,
            args.mode,
            args.revision,
            cases,
            args.repeat,
            args.warmup,
            args.taskset_cpu,
        )

    print_report("current", args.library, cases, current_results, baseline_results)
    if baseline_results is not None:
        print_report("baseline", args.baseline_library, cases, baseline_results)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
