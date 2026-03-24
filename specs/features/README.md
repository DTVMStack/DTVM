# Feature Specifications

This directory stores feature specification documents for incremental development. Each feature uses the `NNN-short-name` numbering format.

## Workflow

1. Use `speckit-specify` to create the feature specification
2. Use `speckit-clarify` to clarify requirements
3. Use `speckit-plan` to generate technical design
4. Use `speckit-tasks` to generate task lists
5. Use `speckit-implement` to execute implementation
6. Upon completion, use `speckit-archive` to archive to `_archive/`

## Notes

- By default, no branches are created; feature specifications are created in `specs/features/` on the current branch
- Feature specifications should not duplicate module SSOT content; use reference links instead
- Each feature should be independently testable and deliverable
