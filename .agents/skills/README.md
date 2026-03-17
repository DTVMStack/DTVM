# Spec-Kit Sub-skills

This directory contains the complete set of Spec-Kit workflow sub-skills for specification-driven development.

## Skill List

| Skill | Name | Description |
|------|----------|----------|
| `speckit-specify` | Feature Spec Generation | Generate spec.md from natural language descriptions |
| `speckit-clarify` | Requirements Clarification | Batch questions to clarify ambiguities in specs |
| `speckit-plan` | Technical Design Planning | Generate design artifacts (research.md, data-model.md, plan.md, etc.) |
| `speckit-tasks` | Task List Generation | Generate executable tasks.md |
| `speckit-implement` | Code Implementation | Execute implementation according to the task list |
| `speckit-dev-workflow` | Full Development Workflow | Orchestrate all phases end-to-end |
| `speckit-constitution` | Project Principles | Define project development principles and constraints |
| `speckit-checklist` | Checklists | Generate domain-specific checklists |
| `speckit-analyze` | Project Analysis | Analyze project consistency |
| `speckit-taskstoissues` | Tasks to Issues | Convert tasks.md into issue tickets |
| `speckit-archive` | Feature Archival | Archive completed features after verifying preconditions |

## Quick Start

### Using Sub-skills Individually

```bash
# 1. Create a feature spec
/skills/speckit-specify "Add user authentication"

# 2. Clarify requirements (if ambiguities exist)
/skills/speckit-clarify

# 3. Technical design
/skills/speckit-plan

# 4. Generate task list
/skills/speckit-tasks

# 5. Execute implementation
/skills/speckit-implement

# 6. Archive completed features
/skills/speckit-archive
```

### Using the Full Workflow

```bash
# Complete all steps in one go
/skills/speckit-dev-workflow "Add user authentication"
```

### SDD Initialization for Existing Projects

```bash
# Analyze the project and generate an SDD initialization plan (companion skill at claude/skills/speckit-ssot-sdd-init-plan)
/skills/speckit-ssot-sdd-init-plan
```

## Directory Structure

Copy these skills to the project's `.agents/skills/` directory:

```
project-root/
└── .agents/
    └── skills/
        ├── speckit-specify/
        │   └── SKILL.md
        ├── speckit-clarify/
        │   └── SKILL.md
        ├── speckit-plan/
        │   └── SKILL.md
        ├── speckit-tasks/
        │   └── SKILL.md
        ├── speckit-implement/
        │   └── SKILL.md
        ├── speckit-dev-workflow/
        │   └── SKILL.md
        ├── speckit-constitution/
        │   └── SKILL.md
        ├── speckit-checklist/
        │   └── SKILL.md
        ├── speckit-analyze/
        │   └── SKILL.md
        ├── speckit-taskstoissues/
        │   └── SKILL.md
        └── speckit-archive/
            └── SKILL.md
```

## Skill Design Principles

### English-First

- Metadata (name, description) uses English for Claude Code recognition
- Content is in English for broader accessibility

### Independent and Composable

Each sub-skill is independent and can be:
- Invoked individually
- Combined sequentially
- Orchestrated within a workflow

### Template and Script Dependencies

These skills depend on the following project resources:

- `.specify/scripts/bash/*.sh` - Helper scripts
- `.specify/templates/*.md` - Document templates
- `specs/` - SSOT directory structure

Ensure these resources are in place before invoking these skills.
