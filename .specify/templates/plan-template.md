# Implementation Plan: [Feature Name]

**Branch**: `[###-feature-name]` | **Date**: [DATE] | **Spec**: [link]
**Input**: Feature specification from `/specs/features/[###-feature-name]/spec.md`

**Description**: This template is filled by the `speckit-plan` skill.

## Summary

[Extracted from feature specification: main requirements + technical approach from research]

## Technical Context

<!--
  Required: Replace the following with project-specific technical details.
  This structure serves only as a reference guide for the iteration process.
-->

**Language/Version**: [e.g. Python 3.11, Swift 5.9, Rust 1.75, or TBD]
**Key Dependencies**: [e.g. FastAPI, UIKit, LLVM, or TBD]
**Storage**: [If applicable, e.g. PostgreSQL, CoreData, file system, or N/A]
**Tests**: [e.g. pytest, XCTest, cargo test, or TBD]
**Target Platform**: [e.g. Linux server, iOS 15+, WASM, or TBD]
**Project Type**: [Monolith/Web/Mobile—determines source structure]
**Performance Goals**: [Domain-specific, e.g. 1000 req/s, 10k lines/sec, 60 fps, or TBD]
**Constraints**: [Domain-specific, e.g. <200ms p95, <100MB memory, offline-capable, or TBD]
**Scale/Scope**: [Domain-specific, e.g. 10k users, 1M LOC, 50 pages, or TBD]

## Constitution Check

*Gate: Must pass before Phase 0 research. Re-check after Phase 1 design.*

[Gate items determined by constitution document]

## Project Structure

### Documentation (this feature)

```text
specs/features/[###-feature]/
├── plan.md              # This file (speckit-plan skill output)
├── research.md          # Phase 0 output (speckit-plan skill)
├── data-model.md        # Phase 1 output (speckit-plan skill)
├── quickstart.md        # Phase 1 output (speckit-plan skill)
├── contracts/           # Phase 1 output (speckit-plan skill)
└── tasks.md             # Phase 2 output (speckit-tasks skill—not created by speckit-plan)
```

### Source Code (repository root)
<!--
  Required: Replace the placeholder directory tree below with the specific layout for this feature.
  Remove unused options and expand the selected structure to actual paths
  (e.g. apps/admin, packages/something). The delivered plan
  should not contain Option labels.
-->

```text
# [Delete if unused] Option 1: Monolith project (default)
src/
├── models/
├── services/
├── cli/
└── lib/

tests/
├── contract/
├── integration/
└── unit/

# [Delete if unused] Option 2: Web app (when "frontend" + "backend" detected)
backend/
├── src/
│   ├── models/
│   ├── services/
│   └── api/
└── tests/

frontend/
├── src/
│   ├── components/
│   ├── pages/
│   └── services/
└── tests/

# [Delete if unused] Option 3: Mobile + API (when "iOS/Android" detected)
api/
└── [same structure as backend above]

ios/ or android/
└── [Platform-specific structure: feature modules, UI flows, platform tests]
```

**Structure Decision**: [Record the selected structure and reference the actual directories above]

## Complexity Tracking

> **Fill only when constitution check has violations requiring justification**

| Violation | Why Needed | Simpler Alternatives Rejected and Reason |
|-----------|------------|------------------------------------------|
| [e.g. 4th subproject] | [Current requirement] | [Why 3 subprojects are insufficient] |
| [e.g. Repository pattern] | [Specific problem] | [Why direct database access is insufficient] |
