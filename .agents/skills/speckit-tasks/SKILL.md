---
name: speckit-tasks
description: Generate an actionable, dependency-ordered tasks.md task list based on available design artifacts.
---

# Task List Generation

Generate an actionable, dependency-ordered tasks.md based on available design artifacts.

## User Input

Your input serves as the context.

## Handoff Points

- **Analyze For Consistency** → invoke `/speckit-analyze`: "Run a project analysis for consistency" (send: true)
- **Implement Project** → invoke `/speckit-implement`: "Start the implementation in phases" (send: true)

## Execution Steps

### 1. Setup

Run `.specify/scripts/bash/check-prerequisites.sh --json` from the repo root and parse:
- FEATURE_DIR
- AVAILABLE_DOCS list

All paths must be absolute paths.

### 2. Load Design Documents

Read from FEATURE_DIR:

**Required**:
- plan.md (tech stack, libraries, structure)
- spec.md (User Stories and their priorities)

**Optional**:
- data-model.md (entities)
- contracts/ (API endpoints)
- research.md (decisions)
- quickstart.md (test scenarios)

Note: not all projects will have all documents. Generate tasks based on available content.

### 3. Execute Task Generation Workflow

- Load plan.md and extract tech stack, libraries, project structure
- Load spec.md and extract User Stories and their priorities (P1, P2, P3, etc.)
- If data-model.md exists: extract entities and map to User Stories
- If contracts/ exists: map endpoints to User Stories
- If research.md exists: extract decisions for setup tasks
- Generate tasks organized by User Story (see task generation rules below)
- Generate a dependency graph showing User Story completion order
- Create parallel execution examples for each User Story
- Validate task completeness (each User Story has all required tasks, independently testable)

### 4. Generate tasks.md

Use `.specify/templates/tasks-template.md` as the structure, filling in:
- Correct feature name from plan.md
- Phase 1: setup tasks (project initialization)
- Phase 2: foundation tasks (blocking prerequisites for all User Stories)
- Phase 3+: one phase per User Story (ordered by priority from spec.md)
- Each phase includes: story goal, independent test criteria, tests (if requested), implementation tasks
- Final phase: polish and cross-cutting concerns
- All tasks must follow the strict checklist format (see task generation rules below)
- Clear file paths for each task
- Dependency section showing story completion order
- Parallel execution examples for each story
- Implementation strategy section (MVP-first, incremental delivery)

### 5. Report

Output the generated tasks.md path and summary:
- Total task count
- Task count per User Story
- Identified parallelization opportunities
- Independent test criteria per story
- Suggested MVP scope (typically just User Story 1)
- Format validation: confirm all tasks follow the checklist format (checkbox, ID, labels, file paths)

tasks.md should be immediately executable — each task must be specific enough for an LLM to complete without additional context.

## Task Generation Rules

**Key**: tasks must be organized by User Story to enable independent implementation and testing.

**Tests are optional**: only generate test tasks when explicitly requested in the feature spec or when the user requests a TDD approach.

### Checklist Format (Required)

Each task must strictly follow this format:

```text
- [ ] [TaskID] [P?] [Story?] Description with file path
```

**Format components**:

1. **Checkbox**: always start with `- [ ]` (markdown checkbox)
2. **Task ID**: sequential number in execution order (T001, T002, T003...)
3. **[P] marker**: include only when the task is parallelizable (different files, no dependency on incomplete tasks)
4. **[Story] label**: required only for User Story phase tasks
   - Format: [US1], [US2], [US3], etc. (maps to User Stories in spec.md)
   - Setup phase: no story label
   - Foundation phase: no story label
   - User Story phases: must have story label
   - Polish phase: no story label
5. **Description**: clear action with precise file paths

**Examples**:
- ✅ Correct: `- [ ] T001 Create project structure per implementation plan`
- ✅ Correct: `- [ ] T005 [P] Implement authentication middleware in src/middleware/auth.py`
- ✅ Correct: `- [ ] T012 [P] [US1] Create User model in src/models/user.py`
- ✅ Correct: `- [ ] T014 [US1] Implement UserService in src/services/user_service.py`
- ❌ Wrong: `- [ ] Create User model` (missing ID and story label)
- ❌ Wrong: `T001 [US1] Create model` (missing checkbox)
- ❌ Wrong: `- [ ] [US1] Create User model` (missing task ID)
- ❌ Wrong: `- [ ] T001 [US1] Create model` (missing file path)

### Task Organization

1. **From User Stories (spec.md)** - primary organization:
   - Each User Story (P1, P2, P3...) has its own phase
   - Map all related components to their story:
     - Models needed for that story
     - Services needed for that story
     - Endpoints/UI needed for that story
     - If tests requested: story-specific tests
   - Mark story dependencies (most stories should be independent)

2. **From contracts**:
   - Map each contract/endpoint → to the User Story it serves
   - If tests requested: each contract → contract test task [P] before implementation in that story phase

3. **From data model**:
   - Map each entity to the User Story that needs it
   - If an entity serves multiple stories: place in the earliest story or setup phase
   - Relationships → service layer tasks in the corresponding story phase

4. **From setup/infrastructure**:
   - Shared infrastructure → setup phase (Phase 1)
   - Foundation/blocking tasks → foundation phase (Phase 2)
   - Story-specific setup → within that story phase

### Phase Structure

- **Phase 1**: Setup (project initialization)
- **Phase 2**: Foundation (blocking prerequisites — must complete before User Stories)
- **Phase 3+**: User Stories in priority order (P1, P2, P3...)
  - Within each story: tests (if requested) → models → services → endpoints → integration
  - Each phase should be a complete, independently testable increment
- **Final phase**: Polish and cross-cutting concerns
