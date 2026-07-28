#!/usr/bin/env python3
"""Validate the change-document declaration used for pull request handoff."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


CHANGE_DOC_PATTERN = re.compile(
    r"docs/changes/\d{4}-\d{2}-\d{2}-[a-z0-9]+(?:-[a-z0-9]+)*/README\.md"
)
DECLARATION_PATTERN = re.compile(r"\s*(Change doc|N/A):\s*(.*?)\s*")
HTML_COMMENT_PATTERN = re.compile(r"<!--.*?-->", re.DOTALL)
PLACEHOLDERS = {
    "-",
    "<path>",
    "<reason>",
    "<specific reason>",
    "n/a",
    "none",
    "reason",
    "tbd",
    "todo",
}


class GateError(ValueError):
    """A declaration or repository state failed validation."""


@dataclass(frozen=True)
class Declaration:
    kind: str
    value: str


@dataclass(frozen=True)
class ValidationInput:
    body: str
    base_ref: str
    head_ref: str


def parse_declaration(body: str) -> Declaration:
    """Extract exactly one declaration from Markdown, ignoring HTML comments."""
    visible_body = HTML_COMMENT_PATTERN.sub("", body)
    matches: list[Declaration] = []

    for line in visible_body.splitlines():
        match = DECLARATION_PATTERN.fullmatch(line)
        if match:
            matches.append(Declaration(match.group(1), match.group(2).strip()))

    if not matches:
        raise GateError(
            "missing declaration; add either 'Change doc: <path>' or "
            "'N/A: <specific reason>'"
        )
    if len(matches) != 1:
        raise GateError("provide exactly one Change doc or N/A declaration")

    declaration = matches[0]
    if not declaration.value:
        raise GateError(f"{declaration.kind} declaration must not be empty")

    normalized = declaration.value.casefold()
    if normalized in PLACEHOLDERS:
        raise GateError(f"{declaration.kind} declaration still contains a placeholder")

    if declaration.kind == "Change doc":
        if not CHANGE_DOC_PATTERN.fullmatch(declaration.value):
            raise GateError(
                "change document must match "
                "docs/changes/YYYY-MM-DD-<slug>/README.md"
            )
    elif len(re.sub(r"\s+", "", declaration.value)) < 8:
        raise GateError("N/A reason must be specific, not a short label")

    return declaration


def run_git(repo: Path, arguments: Sequence[str]) -> str:
    """Run one read-only Git command and return stdout."""
    result = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise GateError(f"git {' '.join(arguments)} failed: {detail}")
    return result.stdout


def validate_repository(
    repo: Path,
    declaration: Declaration,
    base_ref: str,
    head_ref: str,
    include_worktree: bool = False,
) -> list[str]:
    """Validate revisions, the comparison range, and a declared path."""
    run_git(repo, ["rev-parse", "--verify", f"{base_ref}^{{commit}}"])
    run_git(repo, ["rev-parse", "--verify", f"{head_ref}^{{commit}}"])
    changed_paths = {
        path
        for path in run_git(
            repo, ["diff", "--name-only", f"{base_ref}...{head_ref}"]
        ).splitlines()
        if path
    }

    if include_worktree:
        for arguments in (
            ["diff", "--name-only"],
            ["diff", "--cached", "--name-only"],
            ["ls-files", "--others", "--exclude-standard"],
        ):
            changed_paths.update(
                path for path in run_git(repo, arguments).splitlines() if path
            )

    if declaration.kind == "Change doc":
        if include_worktree:
            document_path = repo / declaration.value
            if not document_path.is_file():
                raise GateError(
                    f"change document does not exist in the worktree: "
                    f"{declaration.value}"
                )
        else:
            run_git(repo, ["cat-file", "-e", f"{head_ref}:{declaration.value}"])

    return sorted(changed_paths)


def load_event(path: Path) -> ValidationInput:
    """Load pull request body and revisions from a GitHub event payload."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        pull_request = payload["pull_request"]
        body = pull_request.get("body") or ""
        base_ref = pull_request["base"]["sha"]
        head_ref = pull_request["head"]["sha"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise GateError(f"invalid pull request event payload: {error}") from error

    if not isinstance(body, str):
        raise GateError("pull request body must be text")
    return ValidationInput(body=body, base_ref=base_ref, head_ref=head_ref)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Require one Change doc path or one explicit N/A reason. "
            "The tool validates declarations, not semantic exemptions."
        )
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--declaration",
        help="literal local declaration, such as 'Change doc: docs/changes/...'",
    )
    source.add_argument(
        "--event-path",
        type=Path,
        help="GitHub pull request event JSON; CI normally passes GITHUB_EVENT_PATH",
    )
    parser.add_argument(
        "--base-ref",
        help="base revision for local validation; required with --declaration",
    )
    parser.add_argument(
        "--head-ref",
        default="HEAD",
        help="head revision for local validation (default: HEAD)",
    )
    parser.add_argument(
        "--repo",
        type=Path,
        default=Path.cwd(),
        help="repository root (default: current directory)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.event_path:
            validation_input = load_event(args.event_path)
        else:
            if not args.base_ref:
                parser.error("--base-ref is required with --declaration")
            validation_input = ValidationInput(
                body=args.declaration,
                base_ref=args.base_ref,
                head_ref=args.head_ref,
            )

        declaration = parse_declaration(validation_input.body)
        changed_paths = validate_repository(
            args.repo.resolve(),
            declaration,
            validation_input.base_ref,
            validation_input.head_ref,
            include_worktree=not bool(args.event_path),
        )
    except GateError as error:
        print(f"Change-document gate failed: {error}", file=sys.stderr)
        return 1

    print(f"OK: {declaration.kind}: {declaration.value}")
    print(
        f"Compared {len(changed_paths)} changed path(s) between "
        f"{validation_input.base_ref} and {validation_input.head_ref}."
    )
    if declaration.kind == "N/A":
        print(
            "Reviewer check required: confirm the reason satisfies the "
            "semantic skip criteria."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
