---
name: speckit-implement
description: Execute the implementation plan, processing and executing all tasks defined in tasks.md.
---

# Code Implementation

Execute the implementation plan, processing and executing all tasks defined in tasks.md.

## User Input

Your input serves as the context.

## Execution Steps

### 1. Setup

Run `.specify/scripts/bash/check-prerequisites.sh --json --require-tasks --include-tasks` from the repo root and parse:
- FEATURE_DIR
- AVAILABLE_DOCS list

All paths must be absolute paths.

### 2. Checklist Status (if FEATURE_DIR/checklists/ exists)

- Scan all checklist files in the checklists/ directory
- For each checklist, count:
  - Total items: all lines matching `- [ ]` or `- [X]` or `- [x]`
  - Completed items: lines matching `- [X]` or `- [x]`
  - Incomplete items: lines matching `- [ ]`
- Create status table:

```text
| Checklist | Total | Completed | Incomplete | Status |
|-----------|-------|-----------|------------|--------|
| ux.md     | 12    | 12        | 0          | ✓ PASS |
| test.md   | 8     | 5         | 3          | ✗ FAIL |
```

- Determine overall status:
  - **PASS**: all checklists have 0 incomplete items
  - **FAIL**: one or more checklists have incomplete items

- **If any checklist is incomplete**:
  - Display the table with incomplete item counts
  - **Stop** and ask: "Some checklists are incomplete. Do you want to proceed with implementation anyway? (yes/no)"
  - Wait for user response before continuing
  - If the user says "no" or "wait" or "stop", halt execution
  - If the user says "yes" or "proceed" or "continue", continue to step 3

- **If all checklists are complete**:
  - Display the table showing all checklists passed
  - Automatically continue to step 3

### 3. Load and Analyze Implementation Context

- **Required**: read tasks.md for the full task list and execution plan
- **Required**: read plan.md for tech stack, architecture, and file structure
- **If exists**: read data-model.md for entities and relationships
- **If exists**: read contracts/ for API specifications and test requirements
- **If exists**: read research.md for technical decisions and constraints
- **If exists**: read quickstart.md for integration scenarios

### 4. Project Setup Verification

- **Required**: create/verify ignore files based on actual project setup

**Detection and creation logic**:
- Check if the repo is a git repository (if so, create/verify .gitignore)
- Create appropriate ignore files based on the project's technologies

### 5. Parse tasks.md Structure and Extract

- Task phases: Setup, Tests, Core, Integration, Polish
- Task dependencies: sequential vs. parallel execution rules
- Task details: ID, description, file paths, parallel marker [P]
- Execution flow: order and dependency requirements

### 6. Execute Implementation by Task Plan

- **Execute phase by phase**: complete each phase before moving to the next
- **Respect dependencies**: run sequential tasks in order; parallel tasks [P] can run together
- **Follow TDD methodology**: execute test tasks before their corresponding implementation tasks
- **File-based coordination**: tasks affecting the same file must run sequentially
- **Validation checkpoints**: verify each phase completion before continuing

### 7. Implementation Execution Rules

- **Setup first**: initialize project structure, dependencies, configuration
- **Tests first**: write tests for contracts, entities, and integration scenarios if needed
- **Core development**: implement models, services, CLI commands, endpoints
- **Integration work**: database connections, middleware, logging, external services
- **Polish and verification**: unit tests, performance optimization, documentation

### 8. Progress Tracking and Error Handling

- Report progress after each completed task
- If any non-parallel task fails, halt execution
- For parallel tasks [P], continue successful tasks and report failed ones
- Provide clear error messages and debugging context
- If implementation cannot continue, suggest next steps
- **Important**: for completed tasks, ensure the task is marked as [X] in the tasks file

### 9. Completion Verification

- Verify all required tasks are completed
- Check that implemented features match the original spec
- Verify tests pass and coverage meets requirements
- Confirm implementation follows the technical plan
- Report final status and a summary of completed work

**Note**: this command assumes a complete task breakdown exists in tasks.md. If tasks are incomplete or missing, suggest running `speckit-tasks` first to regenerate the task list.
