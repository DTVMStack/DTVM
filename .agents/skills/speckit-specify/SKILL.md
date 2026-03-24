---
name: speckit-specify
description: Create or update a feature specification from a natural language description. Generate feature directory structure, spec.md template, with smart numbering and branch management support.
---

# Feature Spec Generation

Create or update a feature specification (spec.md) from a natural language feature description.

## User Input

Your input (the feature description in the conversation) serves as the feature description.

## Handoff Points

- **Build Technical Plan** → invoke `/speckit-plan`: "Create a plan for the spec. I am building with..."
- **Clarify Spec Requirements** → invoke `/speckit-clarify`: "Clarify specification requirements" (send: true)

## Execution Steps

### 1. Generate a Concise Short Name

Analyze the feature description and extract the most meaningful keywords:

- Use a 2-4 word short name to capture the feature essence
- Use action-noun format (e.g., "add-user-auth", "fix-payment-bug")
- Preserve technical terms and abbreviations (OAuth2, API, JWT, etc.)
- Keep it concise but sufficiently descriptive
- Feature directory will be created as `specs/features/NNN-short-name` (e.g., `specs/features/001-user-auth`)
- Branch references use the `feature/` prefix (e.g., `feature/001-user-auth`) — note: branches are not created by default

**Examples**:
- "I want to add user authentication" → feature: `001-user-auth`
- "Implement OAuth2 integration for the API" → feature: `002-oauth2-api-integration`
- "Create a dashboard for analytics" → feature: `003-analytics-dashboard`
- "Fix payment processing timeout bug" → feature: `004-fix-payment-timeout`

### 2. Initialize Feature Spec Directory

**a. Determine numbering source** (global max strategy):
- Existing feature directories: `specs/features/[0-9]+-*`
- Existing local/remote git feature branches (if git is available)
- Use the highest number + 1 as the next feature number

**b. Use `create-new-feature.sh` to create the feature scaffold**:
- Default mode (recommended): do not switch branches, only create `specs/features/NNN-short-name/`
- Optional: add `--switch-branch` or `--worktree` only when explicitly requested
- Example (default):
  ```bash
  .specify/scripts/bash/create-new-feature.sh --json --number 5 --short-name "user-auth" "Add user authentication"
  ```
- Example (with branch):
  ```bash
  .specify/scripts/bash/create-new-feature.sh --json --switch-branch --number 5 --short-name "user-auth" "Add user authentication"
  ```
- Example (worktree):
  ```bash
  .specify/scripts/bash/create-new-feature.sh --json --worktree --number 5 --short-name "user-auth" "Add user authentication"
  ```

**c. Parse the script's JSON output**:
- `FEATURE_DIR`
- `SPEC_FILE`
- `BRANCH_NAME` (if created)
- `WORKTREE_PATH` (if worktree mode)

**Important**:
- This repo defaults to a single-branch workflow; branch creation is not required
- Numbering is based on the global max feature index, not the short-name local index
- This script must be run exactly once

### 3. Load Spec Template

Load `.specify/templates/spec-template.md` to understand the required sections.

### 4. Execution Flow

1. **Parse input**: get the feature description from the conversation
   - If empty: error "No feature description provided"

2. **Extract key concepts**: identify from the description
   - Actors
   - Actions
   - Data
   - Constraints

3. **For unclear aspects**:
   - Make reasonable assumptions based on context and industry standards
   - Only flag `[NEEDS CLARIFICATION: specific question]` when:
     - The choice significantly affects feature scope or user experience
     - Multiple reasonable interpretations exist with different implications
     - No reasonable default value exists
   - **Limit**: at most 3 `[NEEDS CLARIFICATION]` markers
   - Prioritize by impact: scope > security/privacy > UX > technical details

4. **Fill in user scenarios and test sections**
   - If user flows cannot be determined: error "Cannot determine user scenarios"

5. **Generate functional requirements**
   - Each requirement must be testable
   - Use reasonable defaults for unspecified details (document in the assumptions section)

6. **Define success criteria**
   - Create measurable, technology-agnostic outcomes
   - Include quantitative metrics (time, performance, count) and qualitative measures (user satisfaction, task completion rate)
   - Each criterion must be verifiable without implementation details

7. **Identify key entities** (if data is involved)

8. **Return**: SUCCESS (spec is ready for planning)

### 5. Write Spec to SPEC_FILE

Use the template structure, replacing placeholders with specific details derived from the feature description, while preserving section order and headings.

### 6. Spec Quality Validation

**a. Create spec quality checklist**:
Create checklist file at `FEATURE_DIR/checklists/requirements.md`

**b. Run validation checks**:
Validate the spec against each checklist item

**c. Handle validation results**:
- **If all items pass**: mark checklist as complete
- **If items fail** (excluding `[NEEDS CLARIFICATION]`): update spec and re-validate
- **If `[NEEDS CLARIFICATION]` markers remain**: present options to the user

### 7. Report Completion

Return feature ID, spec file path, checklist results, and readiness for the next phase (`/speckit-clarify` or `/speckit-plan`).

**Note**: by default, the script does not create or switch branches. Spec files are created in `specs/features/` on the current branch. Use `--switch-branch` or `--worktree` flags to create branches.

## General Guidelines

### Quick Guide

- Focus on **what the user needs** and **why**
- Avoid **how to implement** (no tech stack, API, code structure)
- Write for business stakeholders, not developers
- Do not create any checklists embedded in the spec

### Section Requirements

- **Required sections**: must be completed for every feature
- **Optional sections**: include only when relevant
- When a section is not applicable, remove it entirely (do not leave as "N/A")

### AI Generation Guidelines

When creating specs:

1. **Make reasonable assumptions**: use context, industry standards, and common patterns to fill gaps
2. **Document assumptions**: record reasonable defaults in the assumptions section
3. **Limit clarifications**: at most 3 `[NEEDS CLARIFICATION]` markers
4. **Prioritize clarifications**: scope > security/privacy > UX > technical details
5. **Think like a tester**: every vague requirement should fail the "testable and unambiguous" checklist item

**Reasonable default examples** (do not ask about these):
- Data retention: industry-standard domain practices
- Performance targets: standard web/mobile app expectations unless stated otherwise
- Error handling: user-friendly messages with appropriate fallbacks
- Authentication method: standard session or OAuth2 for web apps
- Integration pattern: RESTful API unless stated otherwise

### Success Criteria Guidelines

Success criteria must be:

1. **Measurable**: include specific metrics (time, percentages, counts, ratios)
2. **Technology-agnostic**: do not mention frameworks, languages, databases, or tools
3. **User-centric**: describe outcomes from the user/business perspective, not system internals
4. **Verifiable**: can be tested/verified without knowing implementation details

**Good examples**:
- "Users can complete checkout within 3 minutes"
- "System supports 10,000 concurrent users"
- "95% of searches return results within 1 second"
- "Task completion rate improves by 40%"

**Bad examples** (implementation-centric):
- "API response time under 200ms" (too technical)
- "Database can handle 1000 TPS" (implementation detail)
- "React components render efficiently" (framework-specific)
- "Redis cache hit rate exceeds 80%" (technology-specific)
