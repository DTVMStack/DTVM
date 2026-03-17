---
name: speckit-taskstoissues
description: Convert tasks in tasks.md into issue tickets, supporting platforms such as GitHub and GitLab.
---

# Tasks to Issues

Convert tasks in tasks.md into issue tickets, supporting platforms such as GitHub and GitLab.

## User Input

Your input serves as the context.

## Execution Steps

### 1. Load Task File

Load the task list from `FEATURE_DIR/tasks.md`.

### 2. Parse Tasks

Parse the task file and extract:
- Task ID
- Task description
- Task labels (e.g., [US1], [P])
- File paths
- Dependencies

### 3. Determine Target Platform

Determine the target platform for issue creation:
- GitHub (via `gh` CLI or API)
- GitLab (via `glab` CLI or API)
- Other platforms (generate a generic format)

### 4. Convert Tasks to Issues

Create an issue for each task, including:

#### Issue Title
- Task ID + short description
- Remove file paths (place in the body instead)

#### Issue Body
- Full task description
- File paths
- Related User Story (if any)
- Dependent tasks (if any)
- Acceptance criteria (extracted from tasks.md)

#### Labels
- Priority (inferred from the task)
- User Story label
- Phase label (Setup, Core, Integration, etc.)
- Technical labels (inferred from file paths)

### 5. Manage Issue Dependencies

- Create issues in order
- Set dependencies using issue references
- Consider the platform's dependency management features

### 6. Create Issues

Create issues using the appropriate method:

**GitHub (via CLI)**:
```bash
gh issue create --title "TITLE" --body "BODY" --labels "LABELS"
```

**GitLab (via CLI)**:
```bash
glab issue create --title "TITLE" --description "BODY" --labels "LABELS"
```

**Fallback**: generate an importable CSV/JSON file

### 7. Report

Report:
- Number of issues created
- Issue URL list
- Any failures or warnings
- Task ID to issue number mapping

### 8. Update Task File (Optional)

If the user requests, update `tasks.md` to include issue references.
