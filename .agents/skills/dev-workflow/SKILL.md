---
name: dev-workflow
description: Development workflow for features, enhancements, refactors, optimizations, and bug fixes. Classify change-document requirements, plan implementation, execute with gates, and verify.
---

# Development Workflow

Use this workflow for implementation work that changes repository behavior or
development contracts. It covers change-document classification, planning,
execution, verification, and optional post-merge archiving.

## Phase A - Propose

1. Classify the change before editing implementation files:
   - **Full**: cross-module, architecture, new capabilities, breaking changes
   - **Light**: single-module, well-scoped, limited blast radius, or a bug fix
     with design implications
   - **N/A**: only typo-only, comment-only, test-only, or clearly
     behavior-preserving trivial fixes

   Any change to runtime semantics, determinism, gas accounting, compiler
   scheduling, a module contract, or security requires at least a Light
   document. File count alone never makes such a change exempt.

2. For an exempt change, record a specific `N/A` reason and continue to
   Phase C. Otherwise, create a change document:
   - Full tier: copy `docs/changes/template.md` to `docs/changes/YYYY-MM-DD-<slug>/README.md`
   - Light tier: copy `docs/changes/template-light.md` to `docs/changes/YYYY-MM-DD-<slug>/README.md`

3. Fill in the document and set its status to `Proposed`.
4. After explicit approval, change the status to `Accepted` before
   implementation starts.

## Phase B - Plan

For changes with an accepted proposal:

1. Consult relevant module specs in `docs/modules/<module>/spec.md`
2. Identify affected files, contracts, and tests
3. Break the implementation into concrete, ordered steps
4. Present the plan for confirmation before proceeding

## Phase C - Execute

Implement with quality gates:

1. **Build gate**: ensure the code compiles after each logical unit of work
2. **Test gate**: run existing tests after each unit; add new tests for new behavior
3. **Review gate**: check for determinism violations, memory safety, and spec compliance

Mark each step complete as you go.

## Phase D - Verify and Handoff

1. Run the full build and test suite
2. Update affected module specs in `docs/modules/` if contracts changed
3. After implementation and required verification are complete, update the
   change document status to `Implemented`
4. Before creating a commit or pull request, validate exactly one declaration:
   - `Change doc: docs/changes/YYYY-MM-DD-<slug>/README.md`
   - `N/A: <specific reason>`
5. After merge, use the `archive` skill only when the user explicitly requests
   archiving

## Notes

- Always consult module specs before modifying code in unfamiliar areas
- When code conflicts with specs, code takes precedence, but update specs afterward
- CI checks that the declaration is present and the referenced path exists.
  Reviewers decide whether an `N/A` reason satisfies the semantic skip criteria.
