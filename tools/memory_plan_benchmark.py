#!/usr/bin/env python3
"""Run paired MemoryExpansionPlan tx replay benchmarks.

The script is intentionally report-oriented: it separates completed JIT rows
from timeouts, builds paired-valid comparisons only when both variants finish
with the same return code, and summarizes MemoryExpansionPlan telemetry using
the stable EVM-MEM log keys.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import shlex
import statistics
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any


STAT_LINE_RE = re.compile(
    r"statistics\.cpp:\d+\] (?P<label>[A-Za-z ()]+):\s+"
    r"(?P<count>\d+) times, avg (?P<avg_ms>[0-9.]+)ms, total "
    r"(?P<total_ms>[0-9.]+)ms(?:, (?P<pct>[0-9.]+)%)?"
)
STAT_TOTAL_RE = re.compile(r"statistics\.cpp:\d+\] Total:\s+(?P<total_ms>[0-9.]+)ms")
MEM_LINE_RE = re.compile(r"\[(?P<tag>EVM-MEM-(?:SUMMARY|BLOCK))\]\s+(?P<body>.*)$")
KEY_VALUE_RE = re.compile(r"(?P<key>[A-Za-z0-9_]+)=(?P<value>-?[0-9]+)")
GAS_USED_RE = re.compile(r"\b(?:gas_used|gasUsed|gas used)\b\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)")
GAS_LEFT_RE = re.compile(r"\b(?:gas_left|gasLeft|gas left)\b\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)")


@dataclass(frozen=True)
class PreparedReplay:
    dataset: str
    tx_hash: str
    prepared_path: Path
    command: list[str]


def parse_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    except ValueError:
        return None


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    if len(values) == 1:
        return float(values[0])
    ordered = sorted(values)
    idx = (len(ordered) - 1) * pct
    lo = math.floor(idx)
    hi = math.ceil(idx)
    if lo == hi:
        return float(ordered[lo])
    frac = idx - lo
    return float(ordered[lo] * (1.0 - frac) + ordered[hi] * frac)


def summarize(values: list[float]) -> dict[str, Any]:
    if not values:
        return {
            "count": 0,
            "sum": None,
            "mean": None,
            "median": None,
            "min": None,
            "max": None,
            "p95": None,
        }
    return {
        "count": len(values),
        "sum": float(sum(values)),
        "mean": float(statistics.fmean(values)),
        "median": float(statistics.median(values)),
        "min": float(min(values)),
        "max": float(max(values)),
        "p95": percentile(values, 0.95),
    }


def parse_statistics(text: str) -> dict[str, Any]:
    phases: dict[str, dict[str, Any]] = {}
    total_ms: float | None = None
    for line in text.splitlines():
        match = STAT_LINE_RE.search(line)
        if match:
            label = match.group("label").strip().lower().replace(" ", "_")
            phases[label] = {
                "count": int(match.group("count")),
                "avg_ms": float(match.group("avg_ms")),
                "total_ms": float(match.group("total_ms")),
                "pct": float(match.group("pct")) if match.group("pct") else None,
            }
            continue
        total_match = STAT_TOTAL_RE.search(line)
        if total_match:
            total_ms = float(total_match.group("total_ms"))
    return {"phases": phases, "total_ms": total_ms}


def parse_kv_line(body: str) -> dict[str, int]:
    return {m.group("key"): int(m.group("value")) for m in KEY_VALUE_RE.finditer(body)}


def parse_memory_logs(text: str) -> dict[str, Any]:
    summary: dict[str, int] = {}
    blocks: list[dict[str, int]] = []
    for line in text.splitlines():
        match = MEM_LINE_RE.search(line)
        if not match:
            continue
        values = parse_kv_line(match.group("body"))
        if match.group("tag") == "EVM-MEM-SUMMARY":
            for key, value in values.items():
                if key.endswith("_max"):
                    summary[key] = max(summary.get(key, 0), value)
                else:
                    summary[key] = summary.get(key, 0) + value
        else:
            blocks.append(values)

    block_totals: dict[str, int] = {}
    for block in blocks:
        for key, value in block.items():
            if key.endswith("_max"):
                block_totals[key] = max(block_totals.get(key, 0), value)
            else:
                block_totals[key] = block_totals.get(key, 0) + value

    plan_blocks = [b for b in blocks if b.get("memory_expansion_plan", 0)]
    top_plan_blocks = sorted(
        plan_blocks,
        key=lambda b: (
            b.get("memory_expansion_plan_estimated_reduced_expansions", 0),
            b.get("memory_expansion_plan_covered_ops", 0),
            b.get("memory_expansion_plan_required_size", 0),
        ),
        reverse=True,
    )[:20]
    return {
        "summary": summary,
        "block_totals": block_totals,
        "block_count": len(blocks),
        "plan_block_count": len(plan_blocks),
        "top_plan_blocks": top_plan_blocks,
    }


def parse_gas(text: str) -> dict[str, int | None]:
    gas_used = None
    gas_left = None
    used_match = GAS_USED_RE.search(text)
    left_match = GAS_LEFT_RE.search(text)
    if used_match:
        gas_used = parse_int(used_match.group(1))
    if left_match:
        gas_left = parse_int(left_match.group(1))
    return {"gas_used": gas_used, "gas_left": gas_left}


def load_prepared(
    prepared_root: Path,
    limit: int | None,
    dataset_filter: str | None,
    tx_hash_filter: str | None,
) -> list[PreparedReplay]:
    items: list[PreparedReplay] = []
    for prepared_path in sorted(prepared_root.glob("*/*/prepared.json")):
        payload = json.loads(prepared_path.read_text(encoding="utf-8"))
        command = payload.get("command") or []
        if not isinstance(command, list) or not all(isinstance(v, str) for v in command):
            raise ValueError(f"invalid command in {prepared_path}")
        if not command:
            raise ValueError(f"missing command in {prepared_path}")
        dataset = str(payload.get("dataset") or prepared_path.parts[-3])
        tx_hash = str(payload.get("tx_hash") or prepared_path.parts[-2]).lower()
        if dataset_filter is not None and dataset != dataset_filter:
            continue
        if tx_hash_filter is not None and tx_hash != tx_hash_filter.lower():
            continue
        items.append(
            PreparedReplay(
                dataset=dataset,
                tx_hash=tx_hash,
                prepared_path=prepared_path,
                command=command,
            )
        )
        if limit is not None and len(items) >= limit:
            break
    return items


def build_command(item: PreparedReplay, dtvm_path: Path, mode: str) -> list[str]:
    cmd = list(item.command)
    cmd[0] = str(dtvm_path)
    for idx, token in enumerate(cmd):
        if token in {"-m", "--mode"} and idx + 1 < len(cmd):
            cmd[idx + 1] = mode
        elif token.endswith(".evm.hex"):
            cmd[idx] = str((item.prepared_path.parent / "bytecode.evm.hex").resolve())
        elif token == "--load-state" and idx + 1 < len(cmd):
            cmd[idx + 1] = str((item.prepared_path.parent / "state.json").resolve())

    if "--enable-statistics" not in cmd:
        cmd.append("--enable-statistics")
    if "--log-level" in cmd:
        log_idx = cmd.index("--log-level")
        if log_idx + 1 < len(cmd):
            cmd[log_idx + 1] = "debug"
    else:
        cmd.extend(["--log-level", "debug"])
    return cmd


def run_one(item: PreparedReplay, dtvm_path: Path, mode: str, timeout: float) -> dict[str, Any]:
    cmd = build_command(item, dtvm_path, mode)
    start = time.perf_counter()
    timed_out = False
    stdout = ""
    stderr = ""
    returncode: int | None = None
    error: str | None = None

    def to_text(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="ignore")
        return str(value)

    try:
        result = subprocess.run(
            cmd,
            cwd=Path.cwd(),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        stdout = result.stdout
        stderr = result.stderr
        returncode = result.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = to_text(exc.stdout)
        stderr = to_text(exc.stderr)
        error = f"timeout after {timeout}s"
    except OSError as exc:
        error = str(exc)
    end = time.perf_counter()

    text = stdout + "\n" + stderr
    return {
        "dataset": item.dataset,
        "tx_hash": item.tx_hash,
        "prepared_path": str(item.prepared_path),
        "command_shell": shlex.join(cmd),
        "returncode": returncode,
        "timed_out": timed_out,
        "error": error,
        "wall_time_ms": (end - start) * 1000.0,
        "stdout_bytes": len(stdout.encode("utf-8", errors="ignore")),
        "stderr_bytes": len(stderr.encode("utf-8", errors="ignore")),
        "stdout_tail": stdout[-1000:],
        "stderr_tail": stderr[-1000:],
        "statistics": parse_statistics(text),
        "memory": parse_memory_logs(text),
        "gas": parse_gas(text),
    }


def nested_int(row: dict[str, Any], path: list[str]) -> int:
    cur: Any = row
    for part in path:
        cur = (cur or {}).get(part)
    return int(cur) if isinstance(cur, int) else 0


def sum_key(rows: list[dict[str, Any]], path: list[str]) -> int:
    return sum(nested_int(row, path) for row in rows)


def max_key(rows: list[dict[str, Any]], path: list[str]) -> int:
    return max((nested_int(row, path) for row in rows), default=0)


def phase_ms(row: dict[str, Any], name: str) -> float | None:
    value = (((row.get("statistics") or {}).get("phases") or {}).get(name) or {}).get("total_ms")
    return float(value) if value is not None else None


def total_ms(row: dict[str, Any]) -> float | None:
    value = (row.get("statistics") or {}).get("total_ms")
    return float(value) if value is not None else None


def has_jit(row: dict[str, Any]) -> bool:
    return phase_ms(row, "jit_compilation") is not None


def direct_memory_ops(rows: list[dict[str, Any]]) -> int:
    block_total = sum_key(rows, ["memory", "block_totals", "direct_ops"])
    if block_total:
        return block_total
    return (
        sum_key(rows, ["memory", "summary", "mload_expand"])
        + sum_key(rows, ["memory", "summary", "mstore_expand"])
        + sum_key(rows, ["memory", "summary", "mstore8_expand"])
        + sum_key(rows, ["memory", "summary", "mcopy_expand"])
        + sum_key(rows, ["memory", "summary", "prechecked_mload_ops"])
        + sum_key(rows, ["memory", "summary", "prechecked_mstore_ops"])
        + sum_key(rows, ["memory", "summary", "prechecked_mstore8_ops"])
        + sum_key(rows, ["memory", "summary", "prechecked_mcopy_ops"])
    )


def summarize_plan(rows: list[dict[str, Any]]) -> dict[str, Any]:
    direct_ops = direct_memory_ops(rows)
    covered = sum_key(rows, ["memory", "summary", "memory_expansion_plan_covered_ops"])
    plan_count = sum_key(rows, ["memory", "summary", "memory_expansion_plan_count"])
    reusable = sum_key(rows, ["memory", "summary", "memory_expansion_plan_reusable"])
    estimated = sum_key(
        rows,
        ["memory", "summary", "memory_expansion_plan_estimated_reduced_expansions"],
    )
    if estimated == 0:
        estimated = max(0, covered - plan_count)
    return {
        "direct_memory_ops": direct_ops,
        "plan_count": plan_count,
        "plan_precheck": sum_key(rows, ["memory", "summary", "memory_expansion_plan_precheck"]),
        "plan_grouping": sum_key(rows, ["memory", "summary", "memory_expansion_plan_grouping"]),
        "plan_reusable": reusable,
        "plan_reusable_ratio": reusable / plan_count if plan_count else None,
        "plan_covered_ops": covered,
        "hit_rate_direct_ops": covered / direct_ops if direct_ops else None,
        "estimated_reduced_expansions": estimated,
        "covered_mload": sum_key(rows, ["memory", "summary", "memory_expansion_plan_covered_mload_ops"]),
        "covered_mstore": sum_key(rows, ["memory", "summary", "memory_expansion_plan_covered_mstore_ops"]),
        "covered_mstore8": sum_key(rows, ["memory", "summary", "memory_expansion_plan_covered_mstore8_ops"]),
        "covered_mcopy": sum_key(rows, ["memory", "summary", "memory_expansion_plan_covered_mcopy_ops"]),
        "required_size_sum": sum_key(rows, ["memory", "summary", "memory_expansion_plan_required_size_sum"]),
        "required_size_max": max_key(rows, ["memory", "summary", "memory_expansion_plan_required_size_max"]),
        "grouping_candidates": sum_key(rows, ["memory", "summary", "memory_expansion_plan_grouping_candidates"]),
        "precheck_candidates": sum_key(rows, ["memory", "summary", "memory_expansion_plan_precheck_candidates"]),
        "rejected_no_candidate": sum_key(rows, ["memory", "summary", "memory_expansion_plan_rejected_no_candidate"]),
        "rejected_unknown_interval": sum_key(rows, ["memory", "summary", "memory_expansion_plan_rejected_unknown_interval"]),
        "rejected_invalid_range": sum_key(rows, ["memory", "summary", "memory_expansion_plan_rejected_invalid_range"]),
        "rejected_overflow": sum_key(rows, ["memory", "summary", "memory_expansion_plan_rejected_overflow"]),
        "rejected_too_large": sum_key(rows, ["memory", "summary", "memory_expansion_plan_rejected_too_large"]),
        "rejected_zero_size": sum_key(rows, ["memory", "summary", "memory_expansion_plan_rejected_zero_size"]),
        "rejected_unprofitable": sum_key(rows, ["memory", "summary", "memory_expansion_plan_rejected_unprofitable"]),
    }


def summarize_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_dataset: dict[str, list[dict[str, Any]]] = {}
    exit_codes: dict[str, int] = {}
    for row in rows:
        by_dataset.setdefault(row["dataset"], []).append(row)
        key = str(row.get("returncode"))
        exit_codes[key] = exit_codes.get(key, 0) + 1

    def phase_values(name: str) -> list[float]:
        return [v for row in rows if (v := phase_ms(row, name)) is not None]

    top_blocks: list[dict[str, Any]] = []
    for row in rows:
        for block in (row.get("memory") or {}).get("top_plan_blocks", []):
            item = dict(block)
            item["dataset"] = row["dataset"]
            item["tx_hash"] = row["tx_hash"]
            top_blocks.append(item)

    return {
        "runs": len(rows),
        "completed": sum(1 for row in rows if not row.get("timed_out")),
        "timeouts": sum(1 for row in rows if row.get("timed_out")),
        "jit_rows": sum(1 for row in rows if has_jit(row)),
        "completed_no_jit": sum(1 for row in rows if not row.get("timed_out") and not has_jit(row)),
        "exit_codes": exit_codes,
        "wall_time_ms": summarize([float(row["wall_time_ms"]) for row in rows]),
        "statistics_total_ms": summarize([v for row in rows if (v := total_ms(row)) is not None]),
        "jit_compilation_ms": summarize(phase_values("jit_compilation")),
        "execution_ms": summarize(phase_values("execution")),
        "plan": summarize_plan(rows),
        "datasets": {
            dataset: {
                "runs": len(dataset_rows),
                "statistics_total_ms": summarize([v for row in dataset_rows if (v := total_ms(row)) is not None]),
                "jit_compilation_ms": summarize([v for row in dataset_rows if (v := phase_ms(row, "jit_compilation")) is not None]),
                "plan": summarize_plan(dataset_rows),
            }
            for dataset, dataset_rows in sorted(by_dataset.items())
        },
        "top_plan_blocks": sorted(
            top_blocks,
            key=lambda b: (
                b.get("memory_expansion_plan_estimated_reduced_expansions", 0),
                b.get("memory_expansion_plan_covered_ops", 0),
            ),
            reverse=True,
        )[:20],
    }


def run_variant(
    name: str,
    dtvm_path: Path,
    items: list[PreparedReplay],
    args: argparse.Namespace,
    output_path: Path,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    resolved_dtvm = dtvm_path.resolve()
    with output_path.open("w", encoding="utf-8") as handle:
        if args.jobs <= 1:
            for idx, item in enumerate(items, start=1):
                print(f"[{name}] {idx}/{len(items)} {item.dataset} {item.tx_hash}", flush=True)
                row = run_one(item, resolved_dtvm, args.mode, args.timeout_seconds)
                row["variant"] = name
                rows.append(row)
                handle.write(json.dumps(row, sort_keys=True) + "\n")
                handle.flush()
            return rows

        with ThreadPoolExecutor(max_workers=args.jobs) as executor:
            futures = {
                executor.submit(run_one, item, resolved_dtvm, args.mode, args.timeout_seconds): item
                for item in items
            }
            for idx, future in enumerate(as_completed(futures), start=1):
                item = futures[future]
                try:
                    row = future.result()
                except Exception as exc:
                    row = {
                        "dataset": item.dataset,
                        "tx_hash": item.tx_hash,
                        "prepared_path": str(item.prepared_path),
                        "returncode": None,
                        "timed_out": False,
                        "error": str(exc),
                        "wall_time_ms": 0.0,
                        "statistics": {"phases": {}, "total_ms": None},
                        "memory": {"summary": {}, "block_totals": {}, "top_plan_blocks": []},
                        "gas": {"gas_used": None, "gas_left": None},
                    }
                row["variant"] = name
                rows.append(row)
                handle.write(json.dumps(row, sort_keys=True) + "\n")
                handle.flush()
                print(
                    f"[{name}] done {idx}/{len(items)} {item.dataset} {item.tx_hash} "
                    f"timeout={row.get('timed_out')} rc={row.get('returncode')}",
                    flush=True,
                )
    return rows


def paired_report(off_rows: list[dict[str, Any]], on_rows: list[dict[str, Any]]) -> dict[str, Any]:
    off_by_key = {(row["dataset"], row["tx_hash"]): row for row in off_rows}
    pairs: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    for on in on_rows:
        key = (on["dataset"], on["tx_hash"])
        off = off_by_key.get(key)
        if off is None:
            continue
        reasons: list[str] = []
        if off.get("timed_out") or on.get("timed_out"):
            reasons.append("timeout")
        if off.get("returncode") != on.get("returncode"):
            reasons.append("returncode")
        if total_ms(off) is None or total_ms(on) is None or not has_jit(off) or not has_jit(on):
            reasons.append("missing_stats_or_jit")
        if reasons:
            excluded.append(
                {
                    "dataset": on["dataset"],
                    "tx_hash": on["tx_hash"],
                    "reasons": reasons,
                    "returncode_off": off.get("returncode"),
                    "returncode_on": on.get("returncode"),
                    "timeout_off": bool(off.get("timed_out")),
                    "timeout_on": bool(on.get("timed_out")),
                }
            )
            continue
        pairs.append({"off": off, "on": on})

    def deltas(metric) -> list[float]:
        return [float(metric(pair["on"]) - metric(pair["off"])) for pair in pairs]

    by_dataset: dict[str, list[dict[str, Any]]] = {}
    for pair in pairs:
        by_dataset.setdefault(pair["on"]["dataset"], []).append(pair)

    return {
        "total_pairs": len(on_rows),
        "valid_pairs": len(pairs),
        "excluded_pairs": excluded,
        "statistics_total_delta_ms": summarize(deltas(total_ms)),
        "jit_delta_ms": summarize(deltas(lambda row: phase_ms(row, "jit_compilation"))),
        "wall_delta_ms": summarize(deltas(lambda row: float(row["wall_time_ms"]))),
        "datasets": {
            dataset: {
                "valid_pairs": len(dataset_pairs),
                "statistics_total_delta_ms": summarize(
                    [float(total_ms(p["on"]) - total_ms(p["off"])) for p in dataset_pairs]
                ),
                "jit_delta_ms": summarize(
                    [
                        float(phase_ms(p["on"], "jit_compilation") - phase_ms(p["off"], "jit_compilation"))
                        for p in dataset_pairs
                    ]
                ),
                "plan": summarize_plan([p["on"] for p in dataset_pairs]),
            }
            for dataset, dataset_pairs in sorted(by_dataset.items())
        },
        "top_positive_jit_delta": sorted(
            [
                {
                    "dataset": p["on"]["dataset"],
                    "tx_hash": p["on"]["tx_hash"],
                    "jit_delta_ms": phase_ms(p["on"], "jit_compilation") - phase_ms(p["off"], "jit_compilation"),
                    "plan": summarize_plan([p["on"]]),
                }
                for p in pairs
            ],
            key=lambda row: row["jit_delta_ms"],
            reverse=True,
        )[:10],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepared-root", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--dtvm-on", required=True)
    parser.add_argument("--dtvm-off", required=True)
    parser.add_argument("--mode", default="multipass")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--dataset", default=None)
    parser.add_argument("--tx-hash", default=None)
    parser.add_argument("--timeout-seconds", type=float, default=900.0)
    parser.add_argument("--jobs", type=int, default=1)
    args = parser.parse_args()

    prepared_root = Path(args.prepared_root).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    items = load_prepared(prepared_root, args.limit, args.dataset, args.tx_hash)
    if not items:
        raise RuntimeError(f"no prepared replays found under {prepared_root}")

    off_rows = run_variant("off", Path(args.dtvm_off), items, args, output_dir / "runs_off.jsonl")
    on_rows = run_variant("on", Path(args.dtvm_on), items, args, output_dir / "runs_on.jsonl")
    report = {
        "prepared_root": str(prepared_root),
        "dtvm_on": str(Path(args.dtvm_on).resolve()),
        "dtvm_off": str(Path(args.dtvm_off).resolve()),
        "count": len(items),
        "off": summarize_rows(off_rows),
        "on": summarize_rows(on_rows),
        "paired": paired_report(off_rows, on_rows),
    }
    (output_dir / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
