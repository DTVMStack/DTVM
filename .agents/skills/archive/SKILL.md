---
name: archive
description: Archive completed change proposals from docs/changes/ to docs/_archive/ after verifying preconditions.
---

# Feature Archival

Archive completed change proposals from `docs/changes/` to `docs/_archive/<YYYY-MM>/`.

## When to Use

- After a change is implemented, tested, reviewed, and merged
- As the final step of the `dev-workflow` skill

## Preconditions

All of the following must be true before archiving:

| # | Condition | How to Verify |
|---|-----------|---------------|
| 1 | Implementation complete | All checklist items in the change doc are done |
| 2 | Build and tests pass | Run the project's build and test commands |
| 3 | Code review approved | PR has been approved |
| 4 | Branch merged | Feature branch merged into target branch |
| 5 | Module specs updated | Related specs in `docs/modules/` reflect any contract changes |

If conditions are not met, report what is missing and suggest completing those first.

## Steps

### 1. Identify the Change

If the user specifies a change, locate it. Otherwise, list changes in `docs/changes/` with status `Implemented` for the user to choose.

### 2. Verify Preconditions

Check each precondition:

1. Read the change document and verify all checklist items are complete
2. Check git status: whether the branch has been merged (`git branch --merged`)
3. Check whether affected module specs were updated

Present a summary:

```
Archive check: YYYY-MM-DD-<slug>

  Tasks: N/N complete
  Branch: merged into main
  Module specs: updated / needs sync
  Tests/review: user confirmation required

Proceed?
```

### 3. Execute

After confirmation:

1. Create `docs/_archive/<YYYY-MM>/` if it does not exist
2. Move the change directory: `docs/changes/YYYY-MM-DD-<slug>/` to `docs/_archive/<YYYY-MM>/<slug>/`
3. Update the table in `docs/changes/README.md` (remove or mark the entry)
4. Add the entry to `docs/_archive/README.md`

### 4. Cleanup (Optional)

Ask the user:
- **Branch cleanup**: `git branch -d <branch-name>` (if merged)
- **Worktree cleanup**: `git worktree remove <path>` (if used)

## Batch Archival

If multiple changes are ready, list them all and let the user select which to archive.

## Notes

- Archived specs are historical reference only and should not be modified
- If an archived change needs rework, create a new change proposal referencing the original
