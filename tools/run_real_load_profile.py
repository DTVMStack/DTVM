#!/usr/bin/env python3
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Run or analyze the DTVM real-load U256 profiling suite.

The suite is intentionally metric-first rather than wall-clock-first. It uses
mainnet replay fixtures to answer three questions:

* how often U256 operands are dynamically narrow;
* how often the multipass JIT proves those operands narrow;
* which lowering paths the JIT actually emits.

The capture path requires a DTVM build configured with
ZEN_ENABLE_EVM_ARITH_PROFILE=ON, then runs the EVM once in interpreter mode
with ZEN_EVM_LIMB_PROFILE and once in multipass mode with
ZEN_EVM_RANGE_PROFILE.
The analyze-only path consumes an existing runtime-profile directory and
regenerates reports plus a compact summary.json.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shlex
import shutil
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = Path.home() / "dtvm-perf-corpora/mainnet-replay/cancun-suite"
DEFAULT_OUT_DIR = REPO / "build/real-load-profile/latest"
DEFAULT_DTVM_LIB = REPO / "build/lib/libdtvmapi.so"
DEFAULT_EVMONE_STATETEST = Path.home() / "evmone/build/bin/evmone-statetest"

ANALYSIS_DIR = REPO / "tests/corpus/analysis"
REPLAY_DIR = REPO / "tests/corpus/replay"


def eprint(*args):
    print(*args, file=sys.stderr)


def require_file(path: Path, description: str, executable: bool = False) -> None:
    if not path.exists():
        raise SystemExit(f"missing {description}: {path}")
    if executable and not os.access(path, os.X_OK):
        raise SystemExit(f"{description} is not executable: {path}")


def ensure_clean_file(path: Path) -> None:
    if path.exists():
        path.unlink()


def run_logged(
    cmd: list[str],
    log_path: Path,
    *,
    env: dict[str, str] | None = None,
    allow_nonzero: bool = False,
) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as log:
        log.write("$ " + shlex.join(cmd) + "\n\n")
        log.flush()
        proc = subprocess.run(
            cmd,
            cwd=REPO,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    if proc.returncode != 0 and not allow_nonzero:
        raise SystemExit(
            f"command failed with exit {proc.returncode}; see {log_path}"
        )
    return proc.returncode


def count_csv_rows(path: Path) -> int:
    with path.open(newline="") as f:
        reader = csv.reader(f)
        next(reader, None)
        return sum(1 for _ in reader)


def read_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")


def load_or_build_manifest(corpus: Path, out_path: Path, logs_dir: Path) -> dict:
    script = REPLAY_DIR / "build_manifest.py"
    require_file(script, "manifest builder")
    run_logged(
        [sys.executable, str(script), str(corpus), "--out", str(out_path)],
        logs_dir / "build_manifest.log",
    )
    return read_json(out_path)


def prepare_smoke_corpus(
    corpus: Path, manifest: dict, out_dir: Path, per_class: int
) -> Path:
    target = out_dir / "corpus-smoke"
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)

    def smoke_rank(fixture: dict) -> tuple[str, int, str]:
        # Prefer real contract calls. Data-to-EOA fixtures exercise the replay
        # harness, but they do not load deployed bytecode and therefore cannot
        # produce Stream B rows for the JIT range tap.
        stratum_rank = 0 if fixture.get("stratum") == "contract-call" else 1
        return (
            fixture.get("app_class", "unknown"),
            stratum_rank,
            fixture.get("file", ""),
        )

    selected: list[dict] = []
    per_app_seen: dict[str, int] = defaultdict(int)
    for fixture in sorted(manifest.get("fixtures", []), key=smoke_rank):
        cls = fixture.get("app_class", "unknown")
        if per_app_seen[cls] >= per_class:
            continue
        selected.append(fixture)
        per_app_seen[cls] += 1
    if not selected:
        raise SystemExit("smoke suite selection produced no fixtures")

    def materialize_fixture(src: Path, dst: Path) -> None:
        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.symlink(src, dst)
            return
        except OSError as symlink_error:
            try:
                os.link(src, dst)
                return
            except OSError as link_error:
                try:
                    shutil.copy2(src, dst)
                    return
                except OSError as copy_error:
                    raise SystemExit(
                        "failed to materialize smoke fixture "
                        f"{src} -> {dst}; symlink failed: {symlink_error}; "
                        f"hardlink failed: {link_error}; copy failed: {copy_error}"
                    ) from copy_error

    for fixture in selected:
        src = corpus / fixture["file"]
        if not src.exists():
            raise SystemExit(f"manifest fixture is missing: {src}")
        materialize_fixture(src, target / fixture["file"])
    return target


def capture_stream(
    *,
    evmone_statetest: Path,
    dtvm_lib: Path,
    corpus: Path,
    mode: str,
    env_name: str,
    output_csv: Path,
    log_path: Path,
    strict: bool,
) -> int:
    ensure_clean_file(output_csv)
    env = os.environ.copy()
    env["EVMONE_EXTERNAL_OPTIONS"] = (
        f"{dtvm_lib},mode={mode},enable_gas_metering=true"
    )
    env[env_name] = str(output_csv)
    rc = run_logged(
        [str(evmone_statetest), str(corpus), "--vm", "external_vm"],
        log_path,
        env=env,
        allow_nonzero=not strict,
    )
    if not output_csv.exists() or output_csv.stat().st_size == 0:
        raise SystemExit(
            f"{env_name} did not produce {output_csv}; see {log_path}. "
            "For ZEN_EVM_LIMB_PROFILE, rebuild DTVM with "
            "-DZEN_ENABLE_EVM_ARITH_PROFILE=ON."
        )
    return rc


def analyze(
    *,
    stream_a: Path,
    stream_b: Path,
    app_class_map: Path | None,
    reports_dir: Path,
    logs_dir: Path,
    fixture_count: int,
) -> dict[str, Path]:
    require_file(stream_a, "Stream A limb profile")
    require_file(stream_b, "Stream B range profile")
    reports_dir.mkdir(parents=True, exist_ok=True)

    histogram = reports_dir / "site_histogram.csv"
    range_gap_md = reports_dir / "range_gap_report.md"
    range_gap_csv = reports_dir / "range_gap_crosstable.csv"
    fastpath_md = reports_dir / "fastpath_hitrate.md"
    fastpath_csv = reports_dir / "fastpath_hitrate.csv"
    occupancy_md = reports_dir / "limb_occupancy_report.md"
    occupancy_csv = reports_dir / "limb_occupancy.csv"

    run_logged(
        [
            sys.executable,
            str(ANALYSIS_DIR / "runtime_histogram.py"),
            "--stream-a",
            str(stream_a),
            "--out-csv",
            str(histogram),
        ],
        logs_dir / "runtime_histogram.log",
    )

    range_gap_cmd = [
        sys.executable,
        str(ANALYSIS_DIR / "range_gap_join.py"),
        "--stream-a",
        str(stream_a),
        "--stream-b",
        str(stream_b),
        "--out-md",
        str(range_gap_md),
        "--out-csv",
        str(range_gap_csv),
    ]
    if app_class_map is not None and app_class_map.exists():
        range_gap_cmd.extend(["--app-class-map", str(app_class_map)])
    run_logged(range_gap_cmd, logs_dir / "range_gap_join.log")

    run_logged(
        [
            sys.executable,
            str(ANALYSIS_DIR / "fastpath_stats.py"),
            "--stream-b",
            str(stream_b),
            "--histogram",
            str(histogram),
            "--out-md",
            str(fastpath_md),
            "--out-csv",
            str(fastpath_csv),
            "--fixture-count",
            str(fixture_count),
        ],
        logs_dir / "fastpath_stats.log",
    )

    run_logged(
        [
            sys.executable,
            str(ANALYSIS_DIR / "limb_occupancy_stats.py"),
            "--stream-a",
            str(stream_a),
            "--out-md",
            str(occupancy_md),
            "--out-csv",
            str(occupancy_csv),
        ],
        logs_dir / "limb_occupancy_stats.log",
    )

    return {
        "histogram": histogram,
        "range_gap_md": range_gap_md,
        "range_gap_csv": range_gap_csv,
        "fastpath_md": fastpath_md,
        "fastpath_csv": fastpath_csv,
        "occupancy_md": occupancy_md,
        "occupancy_csv": occupancy_csv,
    }


def summarize_range_gap(path: Path) -> dict:
    dyn_mass = 0.0
    unproven_mass = 0.0
    slots = 0
    by_source: dict[str, dict[str, float]] = defaultdict(
        lambda: {"slots": 0, "dyn": 0.0, "proved": 0.0}
    )
    with path.open(newline="") as f:
        for row in csv.DictReader(f):
            dyn = float(row["dynamic_u64_rate"])
            proved = int(row["analyzer_proved_u64"])
            slots += 1
            dyn_mass += dyn
            if not proved:
                unproven_mass += dyn
            src = row["source_kind"]
            by_source[src]["slots"] += 1
            by_source[src]["dyn"] += dyn
            by_source[src]["proved"] += proved
    ratio = unproven_mass / dyn_mass if dyn_mass else 0.0
    source_rows = []
    for source, data in by_source.items():
        n = data["slots"]
        dyn_rate = data["dyn"] / n if n else 0.0
        proved_rate = data["proved"] / n if n else 0.0
        source_rows.append(
            {
                "source_kind": source,
                "slots": int(n),
                "dynamic_u64_rate": dyn_rate,
                "analyzer_proved_u64_rate": proved_rate,
                "static_gap": dyn_rate - proved_rate,
            }
        )
    source_rows.sort(key=lambda r: r["static_gap"], reverse=True)
    return {
        "runtime_narrow_but_static_unknown_ratio": ratio,
        "dynamic_u64_slot_mass": dyn_mass,
        "unproven_dynamic_u64_slot_mass": unproven_mass,
        "joined_operand_slots": slots,
        "top_static_gap_by_source": source_rows[:8],
    }


def summarize_fastpath(path: Path) -> dict:
    out: dict[str, dict[str, dict[str, float | int]]] = {}
    with path.open(newline="") as f:
        for row in csv.DictReader(f):
            opcode = row["opcode_name"]
            weighting = row["weighting"]
            out.setdefault(opcode, {})[weighting] = {
                "total": int(row["total"]),
                "fast_total": int(row["fast_total"]),
                "fast_hit_pct": float(row["fast_hit_pct"]),
                "folded": int(row["FOLDED"]),
                "full": int(row["FULL"]),
            }
    return out


def summarize_occupancy(path: Path) -> dict:
    groups: dict[str, dict[str, float | int]] = defaultdict(
        lambda: {
            "exec_count": 0,
            "exec_pct": 0.0,
            "site_count": 0,
            "site_pct": 0.0,
        }
    )
    with path.open(newline="") as f:
        for row in csv.DictReader(f):
            group = row["group"]
            g = groups[group]
            g["exec_count"] += int(row["exec_count"])
            g["exec_pct"] += float(row["exec_pct"])
            g["site_count"] += int(row["site_count"])
            g["site_pct"] += float(row["site_pct"])
    return dict(groups)


def build_summary(
    *,
    args: argparse.Namespace,
    manifest: dict,
    run_corpus: Path,
    stream_a: Path,
    stream_b: Path,
    reports: dict[str, Path],
    statetest_returncodes: dict[str, int],
) -> dict:
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "suite": args.suite,
        "corpus": str(args.corpus),
        "run_corpus": str(run_corpus),
        "fixture_count": manifest.get("fixture_count"),
        "block_range": manifest.get("block_range"),
        "stratum_counts": manifest.get("stratum_counts"),
        "app_class": manifest.get("app_class"),
        "stream_rows": {
            "stream_a_limb": count_csv_rows(stream_a),
            "stream_b_range": count_csv_rows(stream_b),
            "site_histogram": count_csv_rows(reports["histogram"]),
        },
        "statetest_returncodes": statetest_returncodes,
        "range_gap": summarize_range_gap(reports["range_gap_csv"]),
        "fastpath": summarize_fastpath(reports["fastpath_csv"]),
        "occupancy": summarize_occupancy(reports["occupancy_csv"]),
        "outputs": {name: str(path) for name, path in reports.items()},
    }
    return summary


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    ap.add_argument("--profile-dir", type=Path, default=None)
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    ap.add_argument("--dtvm-lib", type=Path, default=DEFAULT_DTVM_LIB)
    ap.add_argument("--evmone-statetest", type=Path, default=DEFAULT_EVMONE_STATETEST)
    ap.add_argument("--suite", choices=("full", "smoke"), default="full")
    ap.add_argument(
        "--smoke-per-class",
        type=int,
        default=4,
        help="fixtures selected per app_class when --suite=smoke",
    )
    ap.add_argument(
        "--analyze-only",
        action="store_true",
        help="skip VM execution and consume an existing runtime-profile directory",
    )
    ap.add_argument(
        "--strict-statetest",
        action="store_true",
        help="fail immediately when evmone-statetest returns non-zero",
    )
    ap.add_argument(
        "--quiet",
        action="store_true",
        help="only print the summary.json path",
    )
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    args.corpus = args.corpus.expanduser().resolve()
    args.out_dir = args.out_dir.expanduser().resolve()
    if args.profile_dir is not None:
        args.profile_dir = args.profile_dir.expanduser().resolve()
    else:
        args.profile_dir = (
            args.corpus / "runtime-profile" if args.analyze_only else None
        )
    if args.analyze_only and args.suite != "full":
        raise SystemExit(
            "--analyze-only cannot combine with --suite smoke; pass the smoke "
            "corpus as --corpus and use --suite full for that profile"
        )

    if not args.corpus.is_dir():
        raise SystemExit(f"corpus directory does not exist: {args.corpus}")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = args.out_dir / "raw"
    reports_dir = args.out_dir / "reports"
    logs_dir = args.out_dir / "logs"
    raw_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    manifest_path = reports_dir / "manifest.json"
    manifest = load_or_build_manifest(args.corpus, manifest_path, logs_dir)
    run_corpus = args.corpus
    if args.suite == "smoke":
        run_corpus = prepare_smoke_corpus(
            args.corpus, manifest, args.out_dir, args.smoke_per_class
        )
        manifest = load_or_build_manifest(run_corpus, manifest_path, logs_dir)

    statetest_returncodes: dict[str, int] = {}
    if args.analyze_only:
        profile_dir = args.profile_dir
        if profile_dir is None:
            raise SystemExit("--analyze-only requires --profile-dir")
        stream_a = profile_dir / "stream_a_limb.csv"
        stream_b = profile_dir / "stream_b_range.csv"
        app_class_map = profile_dir / "app_class_map.json"
    else:
        require_file(args.dtvm_lib, "DTVM EVMC library")
        require_file(args.evmone_statetest, "evmone-statetest", executable=True)
        stream_a = raw_dir / "stream_a_limb.csv"
        stream_b = raw_dir / "stream_b_range.csv"
        statetest_returncodes["interpreter"] = capture_stream(
            evmone_statetest=args.evmone_statetest,
            dtvm_lib=args.dtvm_lib,
            corpus=run_corpus,
            mode="interpreter",
            env_name="ZEN_EVM_LIMB_PROFILE",
            output_csv=stream_a,
            log_path=logs_dir / "stream_a_interpreter.log",
            strict=args.strict_statetest,
        )
        statetest_returncodes["multipass"] = capture_stream(
            evmone_statetest=args.evmone_statetest,
            dtvm_lib=args.dtvm_lib,
            corpus=run_corpus,
            mode="multipass",
            env_name="ZEN_EVM_RANGE_PROFILE",
            output_csv=stream_b,
            log_path=logs_dir / "stream_b_multipass.log",
            strict=args.strict_statetest,
        )
        app_class_map = args.corpus / "runtime-profile/app_class_map.json"

    reports = analyze(
        stream_a=stream_a,
        stream_b=stream_b,
        app_class_map=app_class_map,
        reports_dir=reports_dir,
        logs_dir=logs_dir,
        fixture_count=int(manifest.get("fixture_count", 0)),
    )
    summary = build_summary(
        args=args,
        manifest=manifest,
        run_corpus=run_corpus,
        stream_a=stream_a,
        stream_b=stream_b,
        reports=reports,
        statetest_returncodes=statetest_returncodes,
    )
    summary_path = args.out_dir / "summary.json"
    write_json(summary_path, summary)

    if args.quiet:
        print(summary_path)
    else:
        h = summary["range_gap"]
        eprint(f"summary: {summary_path}")
        eprint(
            "runtime_narrow_but_static_unknown_ratio: "
            f"{h['runtime_narrow_but_static_unknown_ratio']:.3f}"
        )
        eprint(f"fixture_count: {summary.get('fixture_count')}")
        eprint(f"reports: {reports_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
