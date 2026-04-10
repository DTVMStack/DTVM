# Change Proposals

This directory tracks proposed, accepted, and rejected changes to the DTVM project.

## Naming Convention

Each change lives in its own directory:

```
docs/changes/YYYY-MM-DD-<slug>/README.md
```

- `YYYY-MM-DD`: date the proposal was created
- `<slug>: short kebab-case description (e.g., add-risc-v-frontend)`

## Status Definitions

| Status | Meaning |
|--------|---------|
| **Proposed** | Under review, not yet approved for implementation |
| **Accepted** | Approved, ready for implementation |
| **Implemented** | Implementation complete and merged |
| **Rejected** | Declined with documented rationale |

## Tiers

### Full Tier

Use for changes that affect architecture, cross-module contracts, or introduce new capabilities. Uses the [full template](template.md).

Typical triggers:
- New module or major subsystem
- Breaking API changes
- Cross-cutting performance optimizations
- Changes to determinism or security guarantees

### Light Tier

Use for smaller, well-scoped changes with limited blast radius. Uses the [light template](template-light.md).

Typical triggers:
- Single-module improvements
- Bug fixes with design implications
- Non-breaking enhancements

## Current Proposals

Each active proposal lives in its own subdirectory. Browse `docs/changes/*/README.md`
to see all current proposals, or use:

```bash
ls docs/changes/*/README.md
```

## Workflow

1. Copy the appropriate template into a new `YYYY-MM-DD-<slug>/` directory
2. Fill in the change document
3. Follow the `dev-workflow` skill for implementation
4. After merging, move the completed change to `docs/_archive/`
