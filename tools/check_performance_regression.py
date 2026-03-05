#!/usr/bin/env python3
"""
Performance regression checker for evmone benchmarks.

Usage:
  # Save baseline results
  python check_performance_regression.py --save-baseline baseline.json

  # Check for regressions against baseline
  python check_performance_regression.py --baseline baseline.json

  # Check with custom threshold (default 10%)
  python check_performance_regression.py --baseline baseline.json --threshold 0.15

Exit codes:
  0 - No significant regression detected
  1 - Performance regression detected (> threshold)
  2 - Script error (execution failed, file not found, etc.)
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class BenchmarkResult:
    name: str
    time_ns: float  # Time in nanoseconds
    cpu_time_ns: float
    iterations: int


def run_benchmark(
    lib_path: str,
    mode: str,
    benchmark_dir: str,
    extra_args: Optional[List[str]] = None,
    repetitions: int = 3,
) -> List[BenchmarkResult]:
    """Run benchmark and parse JSON output.

    Uses --benchmark_out to write JSON results to a temporary file so that
    the human-readable benchmark progress streams to stdout/stderr in real
    time (important for CI visibility).

    When *repetitions* > 1, each benchmark runs N times and only the
    median aggregate is kept, significantly reducing noise from ASLR and
    shared-runner contention.
    """
    env = {"EVMONE_EXTERNAL_OPTIONS": f"{lib_path},mode={mode}"}

    fd, json_out_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)

    cmd: List[str] = []

    if shutil.which("taskset"):
        cmd.extend(["taskset", "-c", "0"])

    cmd.extend([
        "./build/bin/evmone-bench",
        benchmark_dir,
        f"--benchmark_out={json_out_path}",
        "--benchmark_out_format=json",
    ])

    if repetitions > 1:
        cmd.append(f"--benchmark_repetitions={repetitions}")
        cmd.append("--benchmark_report_aggregates_only=true")

    if extra_args:
        cmd.extend(extra_args)

    if not any(arg.startswith("--benchmark_filter") for arg in cmd):
        # We include external/total/* for standard benchmarks and synthetic benchmarks
        cmd.append("--benchmark_filter=external/total/.*")

    print(f"Running: {' '.join(cmd)}")
    print(f"Environment: EVMONE_EXTERNAL_OPTIONS={env['EVMONE_EXTERNAL_OPTIONS']}")
    sys.stdout.flush()

    result = subprocess.run(
        cmd,
        env={**subprocess.os.environ, **env},
    )

    if result.returncode != 0:
        print(f"Benchmark execution failed with code {result.returncode}")
        try:
            os.unlink(json_out_path)
        except OSError:
            pass
        sys.exit(2)

    try:
        with open(json_out_path, "r") as f:
            json_data = f.read()
    finally:
        try:
            os.unlink(json_out_path)
        except OSError:
            pass

    return parse_benchmark_json(json_data)


def parse_benchmark_json(json_output: str) -> List[BenchmarkResult]:
    """Parse Google Benchmark JSON output.

    When the output contains aggregate entries (from ``--benchmark_repetitions``),
    only the **median** aggregate is kept and the ``_median`` suffix is stripped
    from names so they match the non-repetition format.  Otherwise individual
    iteration results are returned.
    """
    try:
        data = json.loads(json_output)
    except json.JSONDecodeError as e:
        print(f"Failed to parse JSON: {e}")
        sys.exit(2)

    benchmarks = data.get("benchmarks", [])
    has_aggregates = any(b.get("run_type") == "aggregate" for b in benchmarks)

    results = []
    for benchmark in benchmarks:
        if has_aggregates:
            if benchmark.get("aggregate_name") != "median":
                continue
            name = benchmark["name"]
            if name.endswith("_median"):
                name = name[:-len("_median")]
        else:
            if benchmark.get("run_type") != "iteration":
                continue
            name = benchmark["name"]

        results.append(
            BenchmarkResult(
                name=name,
                time_ns=benchmark.get("real_time", 0),
                cpu_time_ns=benchmark.get("cpu_time", 0),
                iterations=benchmark.get("iterations", 1),
            )
        )

    return results


def load_baseline(path: str) -> List[BenchmarkResult]:
    """Load baseline results from JSON file."""
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"::error::Baseline file not found: {path}")
        sys.exit(2)
    except json.JSONDecodeError as e:
        print(f"::error::Failed to parse baseline JSON: {e}")
        sys.exit(2)

    results = []
    for item in data:
        results.append(
            BenchmarkResult(
                name=item["name"],
                time_ns=item["time_ns"],
                cpu_time_ns=item["cpu_time_ns"],
                iterations=item["iterations"],
            )
        )

    return results


def save_baseline(results: List[BenchmarkResult], path: str) -> None:
    """Save baseline results to JSON file."""
    data = []
    for r in results:
        data.append({
            "name": r.name,
            "time_ns": r.time_ns,
            "cpu_time_ns": r.cpu_time_ns,
            "iterations": r.iterations,
        })

    with open(path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"Saved {len(results)} benchmark results to {path}")


def compare_benchmarks(
    current: List[BenchmarkResult],
    baseline: List[BenchmarkResult],
    threshold: float,
    min_regressions: int = 5,
    min_time_ns: float = 5000.0,
) -> Tuple[bool, List[dict]]:
    """
    Compare current results against baseline.

    A regression is only flagged if at least ``min_regressions`` individual
    benchmarks exceed the threshold.  This prevents CI noise on shared
    runners from causing false positives when a single outlier spikes.

    Benchmarks whose baseline time is below ``min_time_ns`` are excluded
    from regression counting because percentage changes on sub-microsecond
    timings are dominated by measurement overhead and ASLR noise.

    Returns:
        (has_regression, comparison_details)
    """
    baseline_map = {b.name: b for b in baseline}
    current_map = {c.name: c for c in current}

    baseline_names = set(baseline_map.keys())
    current_names = set(current_map.keys())

    missing = baseline_names - current_names
    new = current_names - baseline_names

    if missing:
        print(f"::warning::Missing benchmarks (in baseline but not in current): {missing}")
    if new:
        print(f"::notice::New benchmarks (in current but not in baseline): {new}")

    comparisons = []
    regression_count = 0
    skipped_small = 0

    for name in sorted(baseline_names & current_names):
        b = baseline_map[name]
        c = current_map[name]

        time_change = (c.time_ns - b.time_ns) / b.time_ns
        cpu_change = (c.cpu_time_ns - b.cpu_time_ns) / b.cpu_time_ns

        max_change = max(time_change, cpu_change)

        too_small = b.time_ns < min_time_ns
        is_regression = max_change > threshold and not too_small
        if is_regression:
            regression_count += 1
        if too_small and max_change > threshold:
            skipped_small += 1

        comparisons.append({
            "name": name,
            "baseline_time_ns": b.time_ns,
            "current_time_ns": c.time_ns,
            "time_change": time_change,
            "cpu_change": cpu_change,
            "max_change": max_change,
            "is_regression": is_regression,
        })

    has_regression = regression_count >= min_regressions

    if skipped_small > 0:
        print(
            f"::notice::{skipped_small} micro-benchmark(s) exceeded threshold but "
            f"excluded (baseline < {min_time_ns/1000:.1f}us)."
        )
    if regression_count > 0 and not has_regression:
        print(
            f"::notice::{regression_count} benchmark(s) exceeded threshold but "
            f"below min_regressions={min_regressions}; treating as noise."
        )

    return has_regression, comparisons


def print_comparison_table(comparisons: List[dict], threshold: float) -> None:
    """Print a formatted comparison table."""
    if not comparisons:
        print("No benchmarks to compare.")
        return

    # GitHub Actions annotation messages
    print("\n" + "=" * 100)
    print(f"{'Benchmark':<60} {'Baseline(μs)':<15} {'Current(μs)':<15} {'Change':<12} {'Status'}")
    print("=" * 100)

    regression_count = 0
    for comp in comparisons:
        name = comp["name"]
        baseline_us = comp["baseline_time_ns"] / 1000
        current_us = comp["current_time_ns"] / 1000
        change_pct = comp["max_change"] * 100
        status = "✓ PASS" if not comp["is_regression"] else "✗ FAIL"

        # Truncate long names
        display_name = name if len(name) < 60 else name[:57] + "..."

        print(f"{display_name:<60} {baseline_us:<15.2f} {current_us:<15.2f} {change_pct:>+10.1f}%  {status}")

        if comp["is_regression"]:
            regression_count += 1
            # GitHub Actions warning annotation
            print(f"::warning title=Performance Regression::{name} regressed by {change_pct:.1f}% (threshold: {threshold*100:.0f}%)")

    print("=" * 100)
    print(f"\nTotal benchmarks: {len(comparisons)}")
    print(f"Regressions (> {threshold*100:.0f}%): {regression_count}")


def _short_name(name: str) -> str:
    """Extract a short display name from the full benchmark name.

    Benchmark names typically look like 'external/some_case/variant'.
    We strip the leading 'external/' prefix to keep the table compact.
    """
    if name.startswith("external/"):
        return name[len("external/"):]
    return name


def generate_markdown_summary(
    comparisons: List[dict],
    threshold: float,
    has_regression: bool,
) -> str:
    """Generate a concise Markdown summary of benchmark comparison results."""
    lines: List[str] = []

    regression_count = sum(1 for c in comparisons if c["is_regression"])

    lines.append(
        f"**Performance Benchmark Results** (threshold: {threshold*100:.0f}%)"
    )
    lines.append("")

    if not comparisons:
        lines.append("_No benchmarks to compare._")
        return "\n".join(lines)

    # Markdown table header
    lines.append("| Benchmark | Baseline (us) | Current (us) | Change | Status |")
    lines.append("|-----------|--------------|-------------|--------|--------|")

    for comp in comparisons:
        name = _short_name(comp["name"])
        baseline_us = comp["baseline_time_ns"] / 1000
        current_us = comp["current_time_ns"] / 1000
        change_pct = comp["max_change"] * 100
        status = "PASS" if not comp["is_regression"] else "**REGRESSED**"

        lines.append(
            f"| {name} | {baseline_us:.2f} | {current_us:.2f} "
            f"| {change_pct:+.1f}% | {status} |"
        )

    lines.append("")
    lines.append(
        f"**Summary**: {len(comparisons)} benchmarks, "
        f"{regression_count} regressions"
    )

    return "\n".join(lines)


def generate_baseline_summary(results: List[BenchmarkResult]) -> str:
    """Generate a concise Markdown summary for a baseline-save run."""
    lines: List[str] = []
    lines.append("**Baseline Benchmark Results**")
    lines.append("")
    lines.append("| Benchmark | Time (us) |")
    lines.append("|-----------|----------|")

    for r in results:
        name = _short_name(r.name)
        time_us = r.time_ns / 1000
        lines.append(f"| {name} | {time_us:.2f} |")

    lines.append("")
    lines.append(f"**Total**: {len(results)} benchmarks collected")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Check for performance regressions in evmone benchmarks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Save baseline after a known-good commit
  python check_performance_regression.py --save-baseline baseline.json

  # Check current commit against baseline in CI
  python check_performance_regression.py --baseline baseline.json

  # Check with custom threshold (15% instead of default 10%)
  python check_performance_regression.py --baseline baseline.json --threshold 0.15

  # Specify different library or benchmark directory
  python check_performance_regression.py --baseline baseline.json --lib ./other.so --mode jit
""",
    )

    parser.add_argument(
        "--baseline",
        metavar="PATH",
        help="Path to baseline JSON file for comparison",
    )
    parser.add_argument(
        "--save-baseline",
        metavar="PATH",
        help="Run benchmarks and save results to file (use this to create baseline)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.15,
        help="Regression threshold as ratio (default: 0.15 = 15%%)",
    )
    parser.add_argument(
        "--lib",
        default="./libdtvmapi.so",
        help="Path to the library to benchmark (default: ./libdtvmapi.so)",
    )
    parser.add_argument(
        "--mode",
        default="interpreter",
        help="Mode for the library (default: interpreter)",
    )
    parser.add_argument(
        "--benchmark-dir",
        default="test/evm-benchmarks/benchmarks",
        help="Path to benchmark directory (default: test/evm-benchmarks/benchmarks)",
    )
    parser.add_argument(
        "--output-summary",
        metavar="PATH",
        help="Write a concise Markdown summary to the given file (for PR comments)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose output",
    )
    parser.add_argument(
        "--benchmark-filter",
        default=None,
        help="Custom regex filter forwarded to evmone-bench --benchmark_filter (default: external/*)",
    )
    parser.add_argument(
        "--min-regressions",
        type=int,
        default=5,
        help="Minimum number of regressed benchmarks before flagging overall failure (default: 5). "
             "Prevents CI noise from causing false positives.",
    )
    parser.add_argument(
        "--min-time-ns",
        type=float,
        default=5000.0,
        help="Exclude benchmarks whose baseline time is below this value (in nanoseconds) "
             "from regression counting. Sub-microsecond timings are dominated by "
             "measurement noise. (default: 5000 = 5us)",
    )
    parser.add_argument(
        "--benchmark-repetitions",
        type=int,
        default=3,
        help="Run each benchmark N times and use the median. "
             "Reduces ASLR and shared-runner noise. (default: 3)",
    )

    args = parser.parse_args()

    if not args.baseline and not args.save_baseline:
        parser.error("Either --baseline or --save-baseline must be specified")

    bench_extra = None
    if args.benchmark_filter:
        bench_extra = [f"--benchmark_filter={args.benchmark_filter}"]

    # Run benchmarks
    try:
        current_results = run_benchmark(
            lib_path=args.lib,
            mode=args.mode,
            benchmark_dir=args.benchmark_dir,
            extra_args=bench_extra,
            repetitions=args.benchmark_repetitions,
        )
    except Exception as e:
        print(f"::error::Failed to run benchmarks: {e}")
        sys.exit(2)

    if not current_results:
        print("::error::No benchmark results found")
        sys.exit(2)

    print(f"Collected {len(current_results)} benchmark results")

    # Save baseline mode
    if args.save_baseline:
        save_baseline(current_results, args.save_baseline)
        if args.output_summary:
            summary_md = generate_baseline_summary(current_results)
            with open(args.output_summary, "w") as f:
                f.write(summary_md)
            print(f"Wrote baseline summary to {args.output_summary}")
        return 0

    # Compare mode
    baseline_results = load_baseline(args.baseline)
    print(f"Loaded {len(baseline_results)} baseline results from {args.baseline}")

    has_regression, comparisons = compare_benchmarks(
        current_results,
        baseline_results,
        args.threshold,
        min_regressions=args.min_regressions,
        min_time_ns=args.min_time_ns,
    )

    print_comparison_table(comparisons, args.threshold)

    # Write Markdown summary for PR comments
    if args.output_summary:
        summary_md = generate_markdown_summary(
            comparisons, args.threshold, has_regression
        )
        with open(args.output_summary, "w") as f:
            f.write(summary_md)
        print(f"Wrote comparison summary to {args.output_summary}")

    regression_count = sum(1 for c in comparisons if c["is_regression"])

    print("\n" + "=" * 100)
    if has_regression:
        print(
            f"::error::Performance regression detected! "
            f"{regression_count} benchmarks exceeded {args.threshold*100:.0f}% threshold "
            f"(min required: {args.min_regressions})."
        )
        print("RESULT: FAIL")
        return 1
    else:
        if regression_count > 0:
            print(
                f"::notice::{regression_count} benchmark(s) exceeded threshold "
                f"but below minimum of {args.min_regressions}; treated as CI noise."
            )
        print("::notice::No significant performance regression detected.")
        print("RESULT: PASS")
        return 0


if __name__ == "__main__":
    sys.exit(main())
