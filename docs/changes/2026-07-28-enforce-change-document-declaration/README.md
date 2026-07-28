# Change: Enforce change-document declarations

- **Status**: Implemented
- **Date**: 2026-07-28
- **Tier**: Light
- **Review**: Pending independent review

## Overview

Require every pull request to declare either the change document that governs
the work or a concrete reason why no change document is needed. Align the
project guidance and development workflow on the same exemption criteria and
status transitions.

## Motivation

The project currently has conflicting entry rules. The agent guide and
development workflow allow simple bug fixes to skip proposal work, while the
change-proposal guide requires a Light document for bug fixes with design
implications. The workflow description also emphasizes features, and neither
the pull request template nor CI checks the final classification. These gaps
allow behavior-changing fixes to reach review without a change document.

## Impact

The change affects development-process contracts in the agent guide,
development workflow, pull request template, and CI. A small Python tool
validates declarations locally and in GitHub Actions.

The exemption remains explicit and reviewable. Typo-only, comment-only,
test-only, and clearly behavior-preserving trivial fixes may use `N/A` with a
specific reason. Changes to runtime semantics, determinism, gas accounting,
compiler scheduling, module contracts, security, or bug fixes with design
implications require at least a Light change document.

CI validates the declaration, not the semantic classification. It therefore
does not infer that every `src/` change needs a document. Reviewers retain
responsibility for rejecting an invalid exemption.

The declaration accepts exactly one of these forms:

```text
Change doc: docs/changes/YYYY-MM-DD-<slug>/README.md
N/A: <specific reason>
```

For a path declaration, the validator checks the repository-relative naming
convention and confirms that the file exists at the pull request head. For an
exemption, it rejects empty and placeholder reasons. The same tool reads a
literal declaration during local preparation and the pull request event
payload in CI.

Status transitions have one definition across the project:

- `Proposed` begins when the initial document is ready for review.
- `Accepted` begins after explicit approval and before implementation starts.
- `Implemented` begins after implementation and required verification are
  complete. Merge is not part of this transition, so the document can describe
  the verified state in the implementation pull request.

## Checklist

- [x] Align the DTVMDotfiles agent-guide SSOT with the project policy
- [x] Update the development workflow trigger, exemptions, and status mapping
- [x] Add a pull request declaration and a local/CI validation tool
- [x] Add automated tests and document the tool contract
- [x] Regenerate and check skill mirrors
- [x] Run the relevant build and tests

## Verification

- The validator test suite passes 12 tests covering accepted declarations,
  rejected placeholders and duplicates, repository path checks, pre-commit
  worktree handling, and policy wiring.
- The generated Claude skill mirrors match their `.agents/skills/` sources.
- The validator accepts both the governing change-document declaration and a
  specific `N/A` declaration in local mode.
- The repository format check passes, the GitHub Actions workflow parses as
  YAML, and `git diff --check` reports no whitespace errors.
- The CI-derived Release configuration builds `dtvmapi`; the post-change build
  reports no additional work because no C++ inputs changed.
- DTVMDotfiles release preflight, release, drift detection, skill-state check,
  and agent-skill integration test pass.

`dtvm_local_test.sh --auto` selected the conservative multipass evmone unit and
state-test suites for the mixed tooling and CI paths. Its preflight stopped
before execution because the local evmone binaries and EEST fixture corpus are
not installed. No runtime source changed, and this missing environment is
reported rather than replaced with a different test category.
