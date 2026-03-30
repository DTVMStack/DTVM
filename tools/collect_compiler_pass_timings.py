#!/usr/bin/env python3

import argparse
import json
import os
import pathlib
import statistics
import subprocess
import sys
import tempfile
from collections import defaultdict


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run dtvm with compiler pass timing enabled and aggregate the JSON output."
    )
    parser.add_argument("--dtvm", required=True, help="Path to the dtvm executable")
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--input", help="Input EVM file to compile")
    input_group.add_argument(
        "--manifest",
        help="JSON manifest that lists multiple benchmark inputs",
    )
    parser.add_argument("--runs", type=int, default=1, help="Number of process runs")
    parser.add_argument(
        "--case",
        dest="cases",
        action="append",
        default=[],
        help="Optional case name filter when --manifest is used",
    )
    parser.add_argument(
        "--output",
        help="Optional path to save the aggregated timing summary as JSON",
    )
    parser.add_argument(
        "--allow-nonzero",
        action="store_true",
        help="Keep timings when dtvm exits non-zero but still writes a timing file",
    )
    parser.add_argument(
        "dtvm_args",
        nargs=argparse.REMAINDER,
        help="Extra arguments passed to dtvm after '--'",
    )
    return parser.parse_args()


def load_records(path: pathlib.Path):
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("records", [])


def build_stats(values):
    if not values:
        return {
            "mean": 0.0,
            "median": 0.0,
            "p95": 0.0,
            "min": 0.0,
            "max": 0.0,
        }
    ordered = sorted(values)
    p95_index = max(0, (len(ordered) * 95 + 99) // 100 - 1)
    return {
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "p95": ordered[p95_index],
        "min": min(values),
        "max": max(values),
    }


def aggregate(records_per_run):
    phases = defaultdict(list)
    phase_shares = defaultdict(list)
    totals = []
    record_count = 0
    for records in records_per_run:
        record_count += len(records)
        for record in records:
            total_time = record["total_time_ms"]
            totals.append(total_time)
            for phase in record["phases"]:
                phases[phase["name"]].append(phase["time_ms"])
                if total_time > 0:
                    phase_shares[phase["name"]].append(
                        phase["time_ms"] * 100.0 / total_time
                    )

    summary = {
        "runs": len(records_per_run),
        "record_count": record_count,
        "total_time_ms": {
            "mean": statistics.fmean(totals) if totals else 0.0,
            "median": statistics.median(totals) if totals else 0.0,
        },
        "phases": {},
    }
    for name, values in sorted(phases.items()):
        summary["phases"][name] = {
            **build_stats(values),
            "share_of_total_pct": build_stats(phase_shares[name]),
        }
    return summary


def normalize_dtvm_args(raw_args):
    extra_args = list(raw_args)
    if extra_args and extra_args[0] == "--":
        extra_args = extra_args[1:]
    return extra_args


def collect_records(dtvm_path, input_path, runs, allow_nonzero, extra_args):
    all_records = []
    for _ in range(runs):
        with tempfile.TemporaryDirectory() as tmp_dir:
            timing_path = pathlib.Path(tmp_dir) / "compiler_pass_timing.json"
            env = os.environ.copy()
            env["DTVM_COMPILER_PASS_TIMING_JSON"] = str(timing_path)
            proc = subprocess.run(
                [str(dtvm_path), str(input_path), *extra_args],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            if proc.returncode != 0 and not allow_nonzero:
                sys.stderr.write(proc.stderr)
                raise RuntimeError(f"dtvm exited with code {proc.returncode}")
            if not timing_path.exists():
                sys.stderr.write("timing file was not written\n")
                raise RuntimeError("timing file was not written")
            all_records.append(load_records(timing_path))
    return all_records


def load_manifest(path):
    manifest_path = pathlib.Path(path).resolve()
    with manifest_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    cases = []
    for entry in data.get("cases", []):
        if isinstance(entry, str):
            input_path = manifest_path.parent / entry
            name = pathlib.Path(entry).stem
        else:
            input_path = manifest_path.parent / entry["input"]
            name = entry["name"]
        cases.append(
            {
                "name": name,
                "input": input_path.resolve(),
            }
        )
    return cases


def filter_cases(cases, wanted_names):
    if not wanted_names:
        return cases
    wanted = set(wanted_names)
    filtered = [case for case in cases if case["name"] in wanted]
    missing = sorted(wanted - {case["name"] for case in filtered})
    if missing:
        raise RuntimeError(f"unknown manifest case(s): {', '.join(missing)}")
    return filtered


def collect_single_case(dtvm_path, input_path, runs, allow_nonzero, extra_args):
    records_per_run = collect_records(
        dtvm_path, input_path, runs, allow_nonzero, extra_args
    )
    return {
        "input": str(input_path),
        "summary": aggregate(records_per_run),
    }


def main():
    args = parse_args()
    dtvm_path = pathlib.Path(args.dtvm).resolve()
    extra_args = normalize_dtvm_args(args.dtvm_args)

    if args.input:
        summary = collect_single_case(
            dtvm_path,
            pathlib.Path(args.input).resolve(),
            args.runs,
            args.allow_nonzero,
            extra_args,
        )
        output_data = summary["summary"]
        output_data["input"] = summary["input"]
    else:
        manifest_cases = filter_cases(load_manifest(args.manifest), args.cases)
        case_summaries = []
        overall_records = []
        for case in manifest_cases:
            records_per_run = collect_records(
                dtvm_path,
                case["input"],
                args.runs,
                args.allow_nonzero,
                extra_args,
            )
            overall_records.extend(records_per_run)
            case_summaries.append(
                {
                    "name": case["name"],
                    "input": str(case["input"]),
                    "summary": aggregate(records_per_run),
                }
            )

        output_data = {
            "manifest": str(pathlib.Path(args.manifest).resolve()),
            "case_count": len(case_summaries),
            "cases": case_summaries,
            "overall": aggregate(overall_records),
        }

    output = json.dumps(output_data, indent=2)
    if args.output:
        pathlib.Path(args.output).write_text(output + "\n", encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        sys.exit(1)
