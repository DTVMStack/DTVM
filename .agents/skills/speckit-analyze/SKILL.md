---
name: speckit-analyze
description: Analyze project consistency, checking consistency and completeness between specs, designs, and implementations.
---

# Project Analysis

Analyze project consistency, checking consistency and completeness between specs, designs, and implementations.

## User Input

Your input serves as the context.

## Execution Steps

### 1. Collect Project Artifacts

Identify and collect all relevant project artifacts:
- Feature specs (`specs/features/*/spec.md`)
- Module specs (`specs/modules/*/spec.md`)
- Design documents (`research.md`, `data-model.md`, `plan.md`)
- Task lists (`tasks.md`)
- Implementation code

### 2. Analyze Consistency

Check the following consistency aspects:

#### Spec to Design
- All requirements in the feature spec have corresponding entries in the design
- Data model matches entities defined in the spec
- API contracts are consistent with User Stories

#### Design to Tasks
- All components in the design have corresponding implementation tasks
- Task dependencies are consistent with design dependencies
- Test tasks cover all design components

#### Tasks to Implementation
- All tasks are completed (or correctly tracked)
- Implementation matches task descriptions
- Documentation is consistent with the implementation

#### SSOT Consistency
- Feature specs correctly reference module SSOT
- No duplicate definitions
- Updates are correctly propagated to module specs

### 3. Identify Issues

Flag the following types of issues:
- Missing requirements or features
- Inconsistent naming or terminology
- Conflicting definitions
- Orphaned or unconnected components
- Outdated documentation

### 4. Generate Report

Generate an analysis report containing:

#### Summary
- Overall consistency score
- Number and severity of issues

#### Detailed Findings
- Description of each issue
- Affected files
- Suggested fixes

#### Recommendations
- Issues to fix with priority
- Improvement suggestions

### 5. Output Report

Write the report to:
- Console output (summary)
- File (detailed report): `FEATURE_DIR/analysis/CONSISTENCY_REPORT.md`

### 6. Report

Report analysis results, including:
- Consistency score
- Number of issues found
- High-priority issues
- Suggested next steps
