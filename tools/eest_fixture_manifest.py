#!/usr/bin/env python3
"""Inventory pinned EEST state fixtures and record successful DTVM runs."""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import pathlib
import re
import sys
from typing import Any, Iterable


def _case_record(
    relative_path: pathlib.PurePath,
    test_name: str,
    revision: str,
    case_index: int,
    case: Any,
) -> bytes:
    record = [relative_path.as_posix(), test_name, revision, case_index, case]
    return (
        json.dumps(record, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()
        + b"\n"
    )


def build_manifest(
    state_tests: pathlib.Path,
    *,
    release: str,
    asset: str,
    url: str,
    sha256: str,
    required_revisions: Iterable[str],
    expected_case_set_sha256: str | None = None,
    dtvm_commit: str | None = None,
    mode: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    """Build a deterministic inventory for an extracted EEST state-test tree."""
    state_tests = state_tests.resolve()
    if not state_tests.is_dir():
        raise ValueError(f"state-test directory does not exist: {state_tests}")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", sha256):
        raise ValueError("fixture SHA-256 must contain exactly 64 hexadecimal characters")
    if expected_case_set_sha256 is not None and not re.fullmatch(
        r"[0-9a-fA-F]{64}", expected_case_set_sha256
    ):
        raise ValueError("expected case-set SHA-256 must contain exactly 64 hexadecimal characters")

    required = tuple(dict.fromkeys(required_revisions))
    if not required:
        raise ValueError("at least one required revision must be specified")
    if (mode is None) != (status is None):
        raise ValueError("mode and status must be specified together")
    if mode is not None and not dtvm_commit:
        raise ValueError("a DTVM commit is required for an execution manifest")

    revision_tests: collections.Counter[str] = collections.Counter()
    revision_cases: collections.Counter[str] = collections.Counter()
    revision_hashes: dict[str, Any] = collections.defaultdict(hashlib.sha256)
    case_set_hash = hashlib.sha256()
    json_files = 0
    tests = 0
    cases = 0

    fixture_paths = sorted(
        path
        for path in state_tests.rglob("*.json")
        if path.is_file() and path.name != "index.json"
    )
    for path in fixture_paths:
        json_files += 1
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"cannot load fixture {path}: {error}") from error
        if not isinstance(document, dict):
            raise ValueError(f"fixture root must be an object: {path}")

        relative_path = path.relative_to(state_tests)
        for test_name in sorted(document):
            test = document[test_name]
            if not isinstance(test, dict) or not isinstance(test.get("post"), dict):
                raise ValueError(f"state test lacks an object-valued post field: {path}::{test_name}")
            tests += 1
            for revision in sorted(test["post"]):
                revision_entries = test["post"][revision]
                if not isinstance(revision_entries, list):
                    raise ValueError(
                        f"post entries must be a list: {path}::{test_name}::{revision}"
                    )
                revision_tests[revision] += 1
                revision_cases[revision] += len(revision_entries)
                cases += len(revision_entries)
                for case_index, case in enumerate(revision_entries):
                    record = _case_record(relative_path, test_name, revision, case_index, case)
                    case_set_hash.update(record)
                    revision_hashes[revision].update(record)

    missing = [revision for revision in required if revision_cases[revision] == 0]
    if missing:
        raise ValueError("required revisions have no state-test cases: " + ", ".join(missing))
    unexpected = sorted(set(revision_cases).difference(required))
    if unexpected:
        raise ValueError("fixture contains unrecognized revisions: " + ", ".join(unexpected))
    case_set_digest = case_set_hash.hexdigest()
    if (
        expected_case_set_sha256 is not None
        and case_set_digest != expected_case_set_sha256.lower()
    ):
        raise ValueError(
            "case-set SHA-256 mismatch: "
            f"expected {expected_case_set_sha256.lower()}, got {case_set_digest}"
        )

    revisions = [
        {
            "name": revision,
            "tests": revision_tests[revision],
            "cases": revision_cases[revision],
            "case_set_sha256": revision_hashes[revision].hexdigest(),
        }
        for revision in sorted(revision_cases)
    ]
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "fixture": {
            "repository": "ethereum/execution-spec-tests",
            "release": release,
            "asset": asset,
            "url": url,
            "sha256": sha256.lower(),
        },
        "inventory": {
            "json_files": json_files,
            "tests": tests,
            "cases": cases,
            "case_set_sha256": case_set_digest,
            "revisions": revisions,
        },
    }
    if mode is not None:
        if status != "passed":
            raise ValueError("only a successful completed run can be recorded")
        manifest["execution"] = {
            "dtvm_commit": dtvm_commit,
            "mode": mode,
            "status": status,
            "passed_cases": cases,
            "failed_cases": 0,
            "errored_cases": 0,
            "excluded_cases": 0,
        }
    return manifest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-tests", required=True, type=pathlib.Path)
    parser.add_argument("--release", required=True)
    parser.add_argument("--asset", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--required-revision", action="append", required=True)
    parser.add_argument("--expected-case-set-sha256")
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--dtvm-commit")
    parser.add_argument("--mode", choices=("interpreter", "multipass"))
    parser.add_argument("--status", choices=("passed",))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        manifest = build_manifest(
            args.state_tests,
            release=args.release,
            asset=args.asset,
            url=args.url,
            sha256=args.sha256,
            required_revisions=args.required_revision,
            expected_case_set_sha256=args.expected_case_set_sha256,
            dtvm_commit=args.dtvm_commit,
            mode=args.mode,
            status=args.status,
        )
    except ValueError as error:
        print(f"EEST manifest error: {error}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
