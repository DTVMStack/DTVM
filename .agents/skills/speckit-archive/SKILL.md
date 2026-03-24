---
name: speckit-archive
description: Feature archival. Archive completed features from specs/features/ to specs/_archive/ after verifying preconditions, and clean up branches and worktrees.
---

# Feature Archival

Archive completed and merged feature specs from `specs/features/` to `specs/_archive/<YYYY-MM>/`, ensuring all preconditions are met before archival.

## When to Use

- After feature development, testing, and review are all complete, and the PR has been merged
- As the final step (Phase 8) of `speckit-dev-workflow`
- Periodic cleanup of completed but unarchived features

## Archival Preconditions

**All of the following conditions must be met before archival:**

| # | Condition | Verification Method |
|---|------|---------|
| 1 | All tasks completed | All tasks in `tasks.md` are marked `[X]` |
| 2 | Tests/lint/build pass | Run the project's designated verification commands |
| 3 | Code review approved | PR has been approved |
| 4 | PR merged | Feature branch has been merged into the target branch |
| 5 | SSOT modules updated | Related modules in `specs/modules/` have synced changes |

If conditions are not met, report the missing items to the user and suggest completing them first.

## Execution Steps

### Step 1: Identify Features to Archive

If the user specifies a feature number or name, locate it directly. Otherwise, scan the `specs/features/` directory and list all features with their status for the user to choose from.

### Step 2: Verify Preconditions

Check the 5 preconditions one by one:

1. Read `specs/features/<NNN>-<slug>/tasks.md` and count completed vs. incomplete tasks
2. Check Git status: whether the feature branch has been merged (`git branch --merged`)
3. Check recent modifications to related files in `specs/modules/` (whether they were updated during feature development)

Summarize the check results for the user:

```
Archival precondition check: <NNN>-<slug>

✅ Tasks completed: 15/15 (all complete)
✅ Branch merged: feature/<NNN>-<slug> → main
⚠️ SSOT update: please confirm specs/modules/ has been synced
⬜ Tests/review: user confirmation required

Proceed with archival?
```

### Step 3: Execute Archival

After confirmation, execute:

1. Create archive directory `specs/_archive/<YYYY-MM>/` (if it does not exist)
2. Move the feature directory: `specs/features/<NNN>-<slug>/` → `specs/_archive/<YYYY-MM>/<NNN>-<slug>/`

### Step 4: Cleanup (Optional)

Ask the user if cleanup is needed:

- **Worktree cleanup**: `git worktree remove <worktree-path>` (if worktree mode was used)
- **Branch cleanup**: `git branch -d feature/<NNN>-<slug>` (if the branch has been merged)

### Step 5: Completion Report

```
Archival complete: <NNN>-<slug>

📦 Archived to: specs/_archive/<YYYY-MM>/<NNN>-<slug>/
🧹 Branch feature/<NNN>-<slug> deleted (if cleanup was selected)
🧹 Worktree removed (if cleanup was selected)
```

## Batch Archival

If there are multiple features to archive, batch operations are supported:

1. List all features that meet the conditions
2. User selects features to archive (all or some)
3. Execute archival steps for each feature sequentially

## Notes

- Archived feature specs **should not be modified**; they serve as historical reference only
- If an archived feature needs rework, create a new feature proposal referencing the original spec
- The `_archive/` directory should be under version control as part of the project history
