---
name: speckit-dev-workflow
description: Full Spec-Kit feature development workflow. From natural language description to implementation completion, batch requirements clarification and planning first, then push implementation through in one pass, and finally sync SSOT, roadmap, and documentation.
---

# Full Development Workflow

Starting from a single requirements description, proceed through batch clarification, planning confirmation, push through to implementation completion, and sync all related documentation.

## Workflow Overview

```
Phase 1: Specify    — Generate feature spec draft (invoke /speckit-specify)
Phase 2: Clarify    — Batch ambiguity questions, await user confirmation (invoke /speckit-clarify)
Phase 3: Plan       — Generate technical design artifacts (invoke /speckit-plan)
Phase 4: Tasks      — Generate executable task list (invoke /speckit-tasks)
Phase 5: Implement  — Execute implementation by tasks (invoke /speckit-implement)
Phase 6: Doc Sync   — Sync SSOT / roadmap / README / AGENTS.md
Phase 7: Validate   — lint + build + test verification
```

**Key Checkpoints**:
- Phase 2 presents all ambiguity questions at once. **After the user answers, proceed immediately to Phase 3 without additional confirmation**
- Phase 4 presents a task summary to the user for confirmation. **Implementation begins only after confirmation**
- Workflow ends after Phase 7 passes completely

Refer to the corresponding standalone skill for detailed execution logic of each phase; this workflow handles orchestration and checkpoint control.

## User Input

Your input serves as the feature description.

## Execution Steps

### Phase 1 — Specify

Invoke `create-new-feature.sh` to create the feature directory scaffold. The script **automatically generates the `spec.md` template file**.

> ⚠️ **`spec.md` has already been created by the script**. When filling in spec content later, you must use edit tools. **Do not use file creation tools** (this will cause a "File already exists" error).

### Phase 2 — Clarify (Key Differentiator of This Workflow)

**Standard speckit-clarify behavior allows multi-round follow-ups; this workflow requires batch questioning in one pass.**

Scan spec.md, identify uncertainties that affect architecture or implementation paths (tech stack, process model, data model, API contracts, build/release, scope boundaries, etc.), and present **all questions at once** (up to 5), each with 2-4 options and a recommended default. Wait for the user to answer all before continuing.

After answers are confirmed:
1. Write back to the `## Clarifications` section of `spec.md`
2. Sync key constraints to corresponding FR and Assumptions
3. **Proceed immediately to Phase 3 (Plan)** without waiting for further instructions

### Phase 3 — Plan (Artifact Checklist)

Follow the `speckit-plan` skill. **The following artifacts must all be generated in the feature directory**:

| File | Description |
|------|------|
| `research.md` | Key technical decisions (Decision / Rationale / Alternatives considered) |
| `data-model.md` | New entities, DTO types, field descriptions, state machine enums |
| `contracts/` | API endpoint OpenAPI or interface descriptions (if new endpoints exist) |
| `quickstart.md` | Developer quickstart: setup steps, end-to-end flow examples, API call examples |
| `plan.md` | Architecture overview, phase breakdown, key pseudocode |

After all artifacts are generated, **proceed immediately to Phase 4** without waiting for confirmation.

### Phase 4 — Tasks

After generating `tasks.md`, present a task summary (task count, phase overview) to the user. **Begin Phase 5 implementation only after user confirmation**.

### Phase 5 — Implement

Execute implementation according to the task list, marking each task as `[X]` upon completion.

### Phase 6 — Doc Sync

Review after implementation is complete. **Modify only if there are changes**:

| File | When to Modify |
|------|---------|
| `specs/modules/*/contracts/interfaces.md` | New/changed API endpoints, SSE contracts, error codes |
| `specs/modules/*/data-model.md` | New entities or DTO types |
| `specs/mvp-roadmap.md` | Change feature status from `🚧 In Progress` to `✅ Completed` |
| `README.md` | New user-facing commands, URLs, or installation step changes |
| `AGENTS.md` | New dev commands, Agent-callable APIs, common error codes |

**When unsure whether modification is needed**: state the rationale explicitly; do not force modifications.

### Phase 7 — Validate

Run lint / test / build commands per project conventions sequentially. If any fail, **fix in place** and re-run. Do not skip. Workflow ends after all pass.

## Completion Checklist

- [ ] `spec.md` contains FR numbering and `## Clarifications` section
- [ ] `research.md` generated with key technical decisions and alternatives
- [ ] `data-model.md` generated with new entities, DTO types, state machine enums
- [ ] `contracts/` generated (if new API endpoints exist)
- [ ] `quickstart.md` generated with setup steps and end-to-end flow examples
- [ ] `plan.md` generated with architecture description and phased path
- [ ] All implementation tasks completed
- [ ] Affected `specs/modules/` SSOT updated
- [ ] `specs/mvp-roadmap.md` status updated
- [ ] lint / test / build verification all passed
