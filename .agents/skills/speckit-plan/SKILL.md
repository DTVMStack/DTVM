---
name: speckit-plan
description: Execute the implementation planning workflow, generating design artifacts (research.md, data-model.md, contracts/, quickstart.md, plan.md) using plan templates.
---

# Technical Design Planning

Execute the implementation planning workflow and generate design artifacts.

## User Input

Your input serves as the context.

## Handoff Points

- **Create Tasks** → invoke `/speckit-tasks`: "Break the plan into tasks" (send: true)
- **Create Checklist** → invoke `/speckit-checklist`: "Create a checklist for the following domain..."

## Execution Steps

### 1. Setup

Run `.specify/scripts/bash/setup-plan.sh --json` from the repo root and parse the JSON for:
- FEATURE_SPEC
- IMPL_PLAN
- SPECS_DIR
- BRANCH

### 2. Load Context

Read:
- FEATURE_SPEC (feature spec)
- `.specify/memory/constitution.md` (project principles)
- IMPL_PLAN template (already copied)

### 3. Execute Planning Workflow

Follow the IMPL_PLAN template structure:
- Fill in the technical context (mark unknowns as "NEEDS CLARIFICATION")
- Fill in the principles check section from the constitution
- Evaluate gate criteria (error if violations are unproven)
- **Phase 0**: generate research.md (resolve all NEEDS CLARIFICATION)
- **Phase 1**: generate data-model.md, contracts/, quickstart.md
- **Phase 1**: run agent script to update agent context
- Re-evaluate principles check after design

### 4. Stop and Report

The command ends after Phase 2 planning. Report the branch, IMPL_PLAN path, and generated artifacts.

## Phase Details

### Phase 0: Outline and Research

1. Extract unknowns from technical context:
   - Each NEEDS CLARIFICATION → research task
   - Each dependency → best practices task
   - Each integration → patterns task

2. Generate and dispatch research agents

3. Consolidate findings in `research.md` using the format:
   - Decision: [what was chosen]
   - Rationale: [why it was chosen]
   - Alternatives considered: [what else was evaluated]

**Output**: research.md with all NEEDS CLARIFICATION resolved

### Phase 1: Design and Contracts

**Prerequisite**: `research.md` complete

1. Extract entities from the feature spec → `data-model.md`:
   - Entity names, fields, relationships
   - Validation rules from requirements
   - State transitions (if applicable)

2. Generate API contracts from functional requirements:
   - Each user action → endpoint
   - Use standard REST/GraphQL patterns
   - Output OpenAPI/GraphQL schemas to `/contracts/`

3. Agent context update:
   - Run `.specify/scripts/bash/update-agent-context.sh cursor-agent`
   - The script detects which AI agent is being used
   - Update the corresponding agent-specific context file
   - Only add new technologies from the current plan
   - Preserve manual additions between markers

**Output**: data-model.md, /contracts/*, quickstart.md, agent-specific files

## Key Rules

- Use absolute paths
- Error on gate failure or unresolved clarifications
