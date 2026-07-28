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
| **Proposed** | Initial document is ready for review; implementation is not approved |
| **Accepted** | Explicitly approved before implementation starts |
| **Implemented** | Implementation and required verification are complete; merge is not required for this transition |
| **Rejected** | Declined with documented rationale |

Set `Proposed` when the initial document is ready for review. Set `Accepted`
only after explicit approval and before implementation begins. Set
`Implemented` after the implementation and required build, test, and spec
updates are complete, before pull request handoff.

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

### When a Change Document Is Not Required

A pull request may declare `N/A` only for:

- typo-only changes;
- comment-only changes;
- test-only changes;
- clearly behavior-preserving trivial fixes.

The declaration must include a specific reason. Changes to runtime semantics,
determinism, gas accounting, compiler scheduling, module contracts, or security
require at least a Light document. A bug fix with design implications also
requires at least a Light document, regardless of file count.

## Current Proposals

| Date | Name | Status | Tier | Description |
|------|------|--------|------|-------------|
| 2026-03-10 | [evm-stack-ssa-lifting](2026-03-10-evm-stack-ssa-lifting/README.md) | Implemented | Full | True-SSA stack lifting for EVM multipass JIT |
| 2026-04-11 | [evm-shared-jump-resolution](2026-04-11-evm-shared-jump-resolution/README.md) | Implemented | Light | Extract shared jump target resolution pass into bytecode cache |
| 2026-04-14 | [handlecompare-bounds-check](2026-04-14-handlecompare-bounds-check/README.md) | Implemented | Light | Add bounds check before macro-fusion read in handleCompare |
| 2026-04-14 | [from-raw-pointer-safety-checks](2026-04-14-from-raw-pointer-safety-checks/README.md) | Accepted | Light | Add null/alignment safety checks to `from_raw_pointer` in Rust bindings |
| 2026-05-13 | [evm-ngram-macro-ops](2026-05-13-evm-ngram-macro-ops/README.md) | Implemented | Full | Initial EVM n-gram macro-op lowering and specialized keccak helpers for multipass JIT |
| 2026-07-21 | [evm-memory-alias-and-expansion](2026-07-21-evm-memory-alias-and-expansion/README.md) | Implemented | Full | Stronger memory alias proofs, wider precheck/expansion coverage, DSE, load forwarding, grouping, and MCOPY roadmap |
| 2026-07-28 | [enforce-change-document-declaration](2026-07-28-enforce-change-document-declaration/README.md) | Implemented | Light | Require a change-document path or explicit exemption on every pull request |

Each active proposal lives in its own subdirectory. Browse `docs/changes/*/README.md`
to see all current proposals, or use:

```bash
ls docs/changes/*/README.md
```

## Workflow

1. Copy the appropriate template into a new `YYYY-MM-DD-<slug>/` directory
2. Fill in the change document
3. Change `Proposed` to `Accepted` after explicit approval and before implementation
4. Follow the `dev-workflow` skill for implementation
5. Change `Accepted` to `Implemented` after implementation and verification complete
6. Before pull request handoff, validate a change-document path or an explicit `N/A` reason
7. After merging, use the `archive` skill only when archiving is explicitly requested
