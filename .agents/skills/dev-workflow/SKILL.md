---
name: dev-workflow
description: Feature development workflow. Propose a change, plan implementation, execute with gates, and verify.
---

# Development Workflow

End-to-end workflow for implementing changes: propose, plan, execute, verify, and optionally archive.

## Phase A - Propose

1. Determine the change tier:
   - **Full**: cross-module, architecture, new capabilities, breaking changes
   - **Light**: single-module, well-scoped, limited blast radius

2. Create a change document:
   - Full tier: copy `docs/changes/template.md` to `docs/changes/YYYY-MM-DD-<slug>/README.md`
   - Light tier: copy `docs/changes/template-light.md` to `docs/changes/YYYY-MM-DD-<slug>/README.md`

3. Fill in the document and set status to `Proposed`

4. Add the entry to the table in `docs/changes/README.md`

## Phase B - Plan

After the change proposal is accepted:

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

## Phase D - Verify and Archive

1. Run the full build and test suite
2. Update affected module specs in `docs/modules/` if contracts changed
3. Update the change document status to `Implemented`
4. Optionally use the `archive` skill to move the completed change to `docs/_archive/`

## Notes

- If the change is a simple bug fix or typo, skip to Phase C directly
- Always consult module specs before modifying code in unfamiliar areas
- When code conflicts with specs, code takes precedence, but update specs afterward
