---
name: openspec-proposal-clarify
description: Clarify-first OpenSpec proposal (ask blockers, confirm decisions, then scaffold & validate).
argument-hint: request or feature description
---

$ARGUMENTS
<!-- OPENSPEC:START -->
**Guardrails**
- Favor straightforward, minimal implementations first and add complexity only when it is requested or clearly required.
- Keep changes tightly scoped to the requested outcome.
- Refer to `openspec/AGENTS.md` (located inside the `openspec/` directory - run `ls openspec` or `openspec update` if you don't see it) if you need additional OpenSpec conventions or clarifications.
- Do not write any code during the proposal stage. Only create design documents (proposal.md, tasks.md, design.md, and spec deltas). Implementation happens in the apply stage after approval.

**Clarify Gate (MANDATORY)**
- Before creating or editing any files, identify all decisions that must be made.
- If there is **any [Blocker] question**, you MUST:
  1) Use the AskUserQuestion tool to gather decisions (following the Output Contract below),
  2) STOP and wait for the user's answers,
  3) Only continue after Blockers are resolved.
- Until Blockers are resolved:
  - Do NOT scaffold `openspec/changes/<id>/...`
  - Do NOT run `openspec validate`
  - Do NOT draft proposal/tasks/design/spec deltas
  - Do NOT edit any repository files

**Decision hygiene**
- Prefer explicit user decisions over assumptions.
- Use AskUserQuestion tool for ALL decision points requiring user input.
- Use assumptions ONLY for [Non-blocker] items; label them clearly as `Assumption` and include risk/impact.
- If the user's answers are incomplete or ambiguous, use AskUserQuestion tool again with follow-up questions (max 4 follow-ups).

**Using the AskUserQuestion Tool**
The AskUserQuestion tool allows you to gather user decisions interactively. Use it when:

1. **Multiple valid approaches exist** - When there are 2-4 reasonable ways to implement something
2. **User preferences matter** - When the choice depends on user priorities or constraints
3. **Trade-offs need validation** - When different options have different implications
4. **Architectural decisions required** - When the choice affects system structure or patterns

**AskUserQuestion Best Practices:**
- Group related questions together (max 4 questions per call)
- For each question, provide:
  - A clear question with context
  - 2-4 well-defined options with labels
  - Descriptions explaining what each option means
  - Set `multiSelect: true` only when multiple options can be chosen
- Mark question headers clearly (max 12 characters)
- Recommended option should be listed first with "(Recommended)" suffix

**Clarify Output Contract**
- Use AskUserQuestion tool for at most **8 questions** total, grouped by theme (2 calls max if needed).
- For each question:
  - Mark as **[Blocker]** or **[Non-blocker]** in your own planning
  - Provide a **recommended option** + brief rationale (first option with "(Recommended)")
  - Provide **2–4 options** (A/B/C/…)
  - State the **impact** (scope/risk/timeline) in option descriptions
- AskUserQuestion automatically allows "Other" for custom input

**Blocker categories (cover if relevant)**
- Goal & non-goals (what success looks like; what we will NOT do)
- Interfaces & UX (APIs/CLI/UI shape; error modes)
- Data & migration (schema/state changes; backward compatibility)
- Security & permissions (access control; audit logging)
- Acceptance criteria (how we validate; required tests)

**Answer format**
- AskUserQuestion presents options to the user in a structured UI
- User can select predefined options or provide custom input via "Other"
- After receiving answers, output a Decision Log containing:
  - Confirmed choices (summarized)
  - Remaining open questions (if any)
  - Assumptions taken (if any, and why)

**Steps**
0) **Clarify-first (NO FILE WRITES)**
   - Review `openspec/project.md`, run `openspec list` and `openspec list --specs`, and inspect related code or docs (e.g., via `rg`/`ls`) to ground the request in current behavior.
   - Identify all decisions that must be made.
   - Categorize decisions as [Blocker] or [Non-blocker].
   - Use AskUserQuestion tool to gather decisions for Blockers (and Non-blockers if user input would improve quality).
   - If any [Blocker] exists, STOP and wait for user answers.

1) **Decision Log (still NO FILE WRITES)**
   - After receiving user answers from AskUserQuestion, output a Decision Log containing:
     - Confirmed choices (summarized from user selections)
     - Remaining open questions (if any)
     - Assumptions taken (if any, and why)
   - If Blockers remain or answers are incomplete, use AskUserQuestion tool with follow-ups (max 4) and STOP again.

2) **Scaffold the change**
   - Choose a unique verb-led `change-id` and scaffold `proposal.md`, `tasks.md`, and `design.md` (when needed) under `openspec/changes/<id>/`.

3) **Write the proposal docs**
   - Map the change into concrete capabilities or requirements, breaking multi-scope efforts into distinct spec deltas with clear relationships and sequencing.
   - Capture architectural reasoning in `design.md` when the solution spans multiple systems, introduces new patterns, or demands trade-off discussion before committing to specs.
   - Draft spec deltas in `changes/<id>/specs/<capability>/spec.md` (one folder per capability) using `## ADDED|MODIFIED|REMOVED Requirements` with at least one `#### Scenario:` per requirement and cross-reference related capabilities when relevant.
   - Draft `tasks.md` as an ordered list of small, verifiable work items that deliver user-visible progress, include validation (tests, tooling), and highlight dependencies or parallelizable work.

4) **Validate strictly**
   - Validate with `openspec validate <id> --strict --no-interactive` and resolve every issue before sharing the proposal.

**Reference**
- Use `openspec show <id> --json --deltas-only` or `openspec show <spec> --type spec` to inspect details when validation fails.
- Search existing requirements with `rg -n "Requirement:|Scenario:" openspec/specs` before writing new ones.
- Explore the codebase with `rg <keyword>`, `ls`, or direct file reads so proposals align with current implementation realities.
<!-- OPENSPEC:END -->
