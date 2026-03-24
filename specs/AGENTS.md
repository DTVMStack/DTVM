# AI Agent Behavior Rules

SDD workflow guidelines for AI coding assistants.

## SDD Workflow

This project uses the Spec-Kit + SSOT spec-driven development model:

1. **Module Specifications** (`specs/modules/`): Each module has `spec.md` and `data-model.md` defining module boundaries, API contracts, and data models
2. **Feature Development** (`specs/features/`): New features follow the speckit workflow: specify -> clarify -> plan -> tasks -> implement
3. **Change Management**: Architecture-level changes are managed through the proposal process in `specs/features/`

## Available Skills

The following speckit sub-skills are located in `.agents/skills/`:

| Skill | Purpose |
|-------|---------|
| `speckit-specify` | Create feature specifications from natural language |
| `speckit-clarify` | Clarify ambiguities in specifications |
| `speckit-plan` | Generate technical design artifacts |
| `speckit-tasks` | Generate actionable task lists |
| `speckit-implement` | Execute implementation by tasks |
| `speckit-dev-workflow` | Complete development workflow orchestration |
| `speckit-constitution` | Define project principles |
| `speckit-checklist` | Generate checklists |
| `speckit-analyze` | Analyze consistency |
| `speckit-taskstoissues` | Convert tasks to issues |
| `speckit-archive` | Archive completed features |

## Change Decision Tree

```
New requirement?
├─ Bug fix (restore intended behavior)? → Fix directly
├─ Formatting/comments/typos? → Fix directly
├─ New feature/capability? → Create feature specification
├─ Breaking change? → Create feature specification
├─ Architecture change? → Create feature specification
└─ Uncertain? → Create feature specification (safer)
```

## Guidelines

- Before modifying module code, consult `specs/modules/<module>/spec.md` for module contracts
- For new feature development, prefer `speckit-dev-workflow` or step-by-step sub-skills
- Do not duplicate module SSOT content in feature specifications; use references
- When code conflicts with specifications, code takes precedence, but specifications should be updated to stay in sync
- Follow `docs/COMMIT_CONVENTION.md` for commit conventions
- Maintain determinism: avoid introducing host-specific non-deterministic behavior
- Prefer modifying code within `src/`; only modify `third_party/` when explicitly required
