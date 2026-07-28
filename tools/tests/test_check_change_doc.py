#!/usr/bin/env python3
"""Tests for tools/check_change_doc.py."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "check_change_doc.py"
REPO_ROOT = SCRIPT_PATH.parents[1]
SPEC = importlib.util.spec_from_file_location("check_change_doc", SCRIPT_PATH)
assert SPEC and SPEC.loader
CHECK_CHANGE_DOC = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK_CHANGE_DOC
SPEC.loader.exec_module(CHECK_CHANGE_DOC)


class ParseDeclarationTests(unittest.TestCase):
    def test_accepts_change_document_path(self) -> None:
        declaration = CHECK_CHANGE_DOC.parse_declaration(
            "Change doc: docs/changes/2026-07-28-change-gate/README.md"
        )
        self.assertEqual(declaration.kind, "Change doc")

    def test_accepts_specific_exemption(self) -> None:
        declaration = CHECK_CHANGE_DOC.parse_declaration(
            "N/A: comment-only clarification with no behavior change"
        )
        self.assertEqual(declaration.kind, "N/A")

    def test_ignores_template_examples_in_html_comments(self) -> None:
        declaration = CHECK_CHANGE_DOC.parse_declaration(
            "<!-- N/A: <specific reason> -->\n"
            "Change doc: docs/changes/2026-07-28-change-gate/README.md"
        )
        self.assertEqual(declaration.kind, "Change doc")

    def test_rejects_both_declarations(self) -> None:
        with self.assertRaisesRegex(CHECK_CHANGE_DOC.GateError, "exactly one"):
            CHECK_CHANGE_DOC.parse_declaration(
                "Change doc: docs/changes/2026-07-28-change-gate/README.md\n"
                "N/A: comment-only clarification with no behavior change"
            )

    def test_rejects_empty_declaration(self) -> None:
        with self.assertRaisesRegex(CHECK_CHANGE_DOC.GateError, "must not be empty"):
            CHECK_CHANGE_DOC.parse_declaration("Change doc:")

    def test_rejects_placeholder_reason(self) -> None:
        with self.assertRaisesRegex(CHECK_CHANGE_DOC.GateError, "placeholder"):
            CHECK_CHANGE_DOC.parse_declaration("N/A: <specific reason>")

    def test_rejects_noncanonical_path(self) -> None:
        with self.assertRaisesRegex(CHECK_CHANGE_DOC.GateError, "must match"):
            CHECK_CHANGE_DOC.parse_declaration("Change doc: docs/change.md")


class RepositoryValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary_directory.name)
        self.git("init")
        self.git("config", "user.name", "Test User")
        self.git("config", "user.email", "test@example.com")
        (self.repo / "README.md").write_text("base\n", encoding="utf-8")
        self.git("add", "README.md")
        self.git("commit", "-m", "base")
        self.base_ref = self.git("rev-parse", "HEAD").strip()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def git(self, *arguments: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.repo), *arguments],
            check=True,
            capture_output=True,
            text=True,
        ).stdout

    def test_validates_document_at_head_revision(self) -> None:
        relative_path = "docs/changes/2026-07-28-change-gate/README.md"
        document_path = self.repo / relative_path
        document_path.parent.mkdir(parents=True)
        document_path.write_text("# Change\n", encoding="utf-8")
        self.git("add", relative_path)
        self.git("commit", "-m", "add change document")
        head_ref = self.git("rev-parse", "HEAD").strip()

        declaration = CHECK_CHANGE_DOC.parse_declaration(
            f"Change doc: {relative_path}"
        )
        changed_paths = CHECK_CHANGE_DOC.validate_repository(
            self.repo, declaration, self.base_ref, head_ref
        )

        self.assertEqual(changed_paths, [relative_path])

    def test_rejects_missing_document_at_head_revision(self) -> None:
        declaration = CHECK_CHANGE_DOC.parse_declaration(
            "Change doc: docs/changes/2026-07-28-missing/README.md"
        )
        with self.assertRaisesRegex(CHECK_CHANGE_DOC.GateError, "cat-file"):
            CHECK_CHANGE_DOC.validate_repository(
                self.repo, declaration, self.base_ref, "HEAD"
            )

    def test_accepts_untracked_document_during_local_preparation(self) -> None:
        relative_path = "docs/changes/2026-07-28-local-change/README.md"
        document_path = self.repo / relative_path
        document_path.parent.mkdir(parents=True)
        document_path.write_text("# Local change\n", encoding="utf-8")
        declaration = CHECK_CHANGE_DOC.parse_declaration(
            f"Change doc: {relative_path}"
        )

        changed_paths = CHECK_CHANGE_DOC.validate_repository(
            self.repo,
            declaration,
            self.base_ref,
            "HEAD",
            include_worktree=True,
        )

        self.assertEqual(changed_paths, [relative_path])


class PolicyIntegrationTests(unittest.TestCase):
    def test_workflow_covers_bug_fixes_and_closed_skip_set(self) -> None:
        workflow = (
            REPO_ROOT / ".agents/skills/dev-workflow/SKILL.md"
        ).read_text(encoding="utf-8")

        self.assertIn("optimizations, and bug fixes", workflow)
        self.assertIn("typo-only, comment-only, test-only", workflow)
        self.assertIn("runtime semantics, determinism, gas accounting", workflow)
        self.assertNotIn("simple bug fix or typo, skip", workflow)

    def test_status_transition_and_pull_request_gate_stay_wired(self) -> None:
        policy = (REPO_ROOT / "docs/changes/README.md").read_text(encoding="utf-8")
        template = (
            REPO_ROOT / ".github/pull_request_template.md"
        ).read_text(encoding="utf-8")
        ci_workflow = (
            REPO_ROOT / ".github/workflows/commit-lint.yml"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "Implementation and required verification are complete; "
            "merge is not required",
            policy,
        )
        self.assertIn("\nChange doc:\n", template)
        self.assertIn(
            "python3 tools/check_change_doc.py --event-path", ci_workflow
        )
        self.assertIn("types: [opened, synchronize, reopened, edited]", ci_workflow)


if __name__ == "__main__":
    unittest.main()
