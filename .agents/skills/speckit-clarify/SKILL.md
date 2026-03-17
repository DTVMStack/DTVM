---
name: speckit-clarify
description: Identify under-specified areas in the current feature spec by asking up to 5 highly targeted clarification questions, and encode the answers back into the spec.
---

# Requirements Clarification

Identify and reduce ambiguities or missing decision points in the active feature spec, recording clarifications directly in the spec file.

## User Input

Your input serves as the context.

## Handoff Points

- **Build Technical Plan** → invoke `/speckit-plan`: "Create a plan for the spec. I am building with..."

## Execution Steps

### Goal

Detect and reduce ambiguities or missing decision points in the active feature spec, and record clarifications directly in the spec file.

**Note**: This clarification workflow is expected to run (and complete) before invoking `/speckit-plan`. If the user explicitly states they are skipping clarification (e.g., an exploratory spike), proceed but warn about increased downstream rework risk.

### 1. Run Prerequisite Check

Run `.specify/scripts/bash/check-prerequisites.sh --json --paths-only` from the repo root **once**. Parse the minimal JSON payload fields:
- `FEATURE_DIR`
- `FEATURE_SPEC`
- (Optionally capture `IMPL_PLAN`, `TASKS` for future chaining flows)

If JSON parsing fails, abort and instruct the user to re-run `/speckit-specify` or verify the feature branch environment.

### 2. Load and Analyze Current Spec

Load the current spec file. Perform a structured ambiguity and coverage scan using the following taxonomy. For each category, flag its status: **Clear / Partial / Missing**.

Generate an internal coverage map for prioritization (do not output the raw map unless no questions will be asked):

**Feature Scope and Behavior**:
- Core user goals and success criteria
- Explicit out-of-scope declarations
- User role/persona differentiation

**Domain and Data Model**:
- Entities, attributes, relationships
- Identity and uniqueness rules
- Lifecycle/state transitions
- Data volume/scale assumptions

**Interaction and UX Flows**:
- Key user journeys/sequences
- Error/empty/loading states
- Accessibility or localization notes

**Non-functional Quality Attributes**:
- Performance (latency, throughput targets)
- Scalability (horizontal/vertical, limits)
- Reliability and availability (uptime, recovery expectations)
- Observability (logging, metrics, tracing signals)
- Security and privacy (authN/Z, data protection, threat assumptions)
- Compliance/regulatory constraints (if applicable)

**Integration and External Dependencies**:
- External services/APIs and their failure modes
- Data import/export formats
- Protocol/versioning assumptions

**Edge Cases and Failure Handling**:
- Negative scenarios
- Rate limiting/throttling
- Conflict resolution (e.g., concurrent edits)

**Constraints and Trade-offs**:
- Technical constraints (language, storage, hosting)
- Explicit trade-offs or rejected alternatives

**Terminology and Consistency**:
- Canonical glossary terms
- Synonyms to avoid / deprecated terms

**Completion Signals**:
- Acceptance criteria testability
- Measurable definition-of-done style metrics

**Miscellaneous/Placeholders**:
- TODO markers / unresolved decisions
- Vague adjectives without quantification ("robust", "intuitive")

For each category with **Partial** or **Missing** status, add a candidate question opportunity unless:
- The clarification would not materially change the implementation or verification strategy
- The information is best deferred to the planning phase (note internally)

### 3. Generate Prioritized Question Queue

Generate (internally) a prioritized queue of up to 5 candidate clarification questions. **Do not output all questions at once**.

Apply these constraints:
- Maximum 5 questions for the entire session
- Each question must be answerable by:
  - Short multiple-choice (2-5 distinct, mutually exclusive options), or
  - A single word/phrase answer (explicitly constrained: "answer in <=5 words")
- Only include questions whose answers materially affect architecture, data modeling, task decomposition, test design, UX behavior, operational readiness, or compliance verification
- Ensure balanced category coverage: try to cover the highest-impact unresolved categories first; avoid asking two low-impact questions when a single high-impact area (e.g., security posture) remains unresolved
- Exclude already-answered questions, trivial style preferences, or planning-level execution details (unless they block correctness)
- Prioritize clarifications that reduce downstream rework risk or prevent inconsistent acceptance tests
- If more than 5 categories remain unresolved, select the top 5 by (impact × uncertainty) heuristic

### 4. Sequential Questioning Loop (Interactive)

- Ask exactly one question at a time
- For **multiple-choice questions**:
  - **Analyze all options** and determine the **most suitable option** based on:
    - Best practices for the project type
    - Common patterns in similar implementations
    - Risk reduction (security, performance, maintainability)
    - Alignment with any explicit project goals or constraints visible in the spec
  - Highlight your **recommended option** at the top with clear reasoning (1-2 sentences explaining why it is the best choice)
  - Format as: `**Recommended:** [X] - <reasoning>`
  - Then present all options as a Markdown table
  - After the table add: `You can reply with the option letter (e.g. "A"), accept the recommended option by saying "yes" or "recommended", or provide your own short answer.`
- For **short-answer style** (no meaningful discrete options):
  - Provide your **suggested answer** based on best practices and context
  - Format as: `**Suggested answer:** <your proposed answer> - <brief reasoning>`
  - Then output: `Format: short answer (<=5 words). You can accept the suggestion by saying "yes" or "suggested", or provide your own answer.`
- After the user answers:
  - If the user replies "yes", "recommended", or "suggested", use your previously stated recommendation/suggestion as the answer
  - Otherwise, validate the answer maps to an option or meets the <=5-word constraint
  - If ambiguous, ask for quick disambiguation (still counts as the same question; do not advance)
  - Once satisfactory, record it in working memory (do not write to disk yet) and move to the next queued question
- **Stop asking further questions** when:
  - All critical ambiguities resolve early (remaining queued items become unnecessary), or
  - The user signals completion ("done", "good", "no more", etc.), or
  - You reach 5 questions
- Never reveal future queued questions ahead of time
- If no valid questions exist at the start, immediately report that no critical ambiguities were found

### 5. Integration After Each Accepted Answer (Incremental Update Approach)

- Maintain an in-memory representation of the spec (loaded once at start) plus the original file content
- For the first integrated answer in this session:
  - Ensure a `## Clarifications` section exists (if missing, create it after the spec template's top-level context/overview section)
  - Under it, create (if not present) a `### Session YYYY-MM-DD` subheading for today
- Append a bullet line immediately after acceptance: `- Q: <question> → A: <final answer>`
- Then immediately apply the clarification to the most appropriate section:
  - Feature ambiguity → update or add bullet points in functional requirements
  - User interaction/role differentiation → update User Stories or role subsection (if present) with clarified roles, constraints, or scenarios
  - Data shape/entity → update data model (add fields, types, relationships) preserving ordering; document added constraints concisely
  - Non-functional constraints → add/modify measurable criteria in non-functional/quality attributes section (convert vague adjectives to metrics or explicit goals)
  - Edge cases/negative flows → add new bullet points under edge cases/error handling (or create such subsection if the template provides a placeholder)
  - Terminology conflicts → normalize terms throughout the spec; preserve original terms only if necessary by adding `(formerly referred to as "X")` once
- If a clarification invalidates an earlier ambiguous statement, replace that statement rather than duplicating; do not leave outdated contradictory text
- Save the spec file after each integration to minimize risk of context loss (atomic overwrite)
- Preserve formatting: do not reorder unrelated sections; keep heading hierarchy intact
- Keep each inserted clarification minimal and testable (avoid narrative drift)

### 6. Validation (After Each Write Plus Final Pass)

- The clarification session contains exactly one bullet per accepted answer (no duplicates)
- Total questions asked (accepted) ≤ 5
- Updated sections have no residual ambiguous placeholders that the new answer was intended to resolve
- No contradictory earlier statements remain (scan for now-invalid alternative choices that were removed)
- Markdown structure is valid; only new headings allowed: `## Clarifications`, `### Session YYYY-MM-DD`
- Terminology consistency: use the same canonical terms across all updated sections

### 7. Write Updated Spec Back to `FEATURE_SPEC`

### 8. Report Completion (After Questioning Loop Ends or Early Termination)

- Number of questions asked and answered
- Path to the updated spec
- Sections touched (list names)
- Coverage summary table listing each taxonomy category and its status:
  - **Resolved** (was Partial/Missing and has been addressed)
  - **Deferred** (exceeded question quota or better suited for planning)
  - **Clear** (already sufficient)
  - **Outstanding** (still Partial/Missing but low impact)
- If any Outstanding or Deferred items exist, suggest whether to proceed to `speckit-plan` or re-run `speckit-clarify` after planning
- Suggested next command

## Behavioral Rules

- If no meaningful ambiguities are found (or all potential questions are low-impact), respond: "No critical ambiguities warranting formal clarification detected." and suggest proceeding
- If the spec file is missing, instruct the user to run `speckit-specify` first (do not create a new spec here)
- Never exceed 5 total questions asked (disambiguation retries for a single question do not count as a new question)
- Avoid speculative tech-stack questions unless the lack of a tech stack blocks feature clarity
- Respect user early-termination signals ("stop", "done", "proceed", etc.)
- If no questions were asked due to full coverage, output a compact coverage summary (all categories Clear) then suggest moving forward
- If quota is reached while high-impact categories remain unresolved, explicitly flag them under Deferred with rationale
