#!/usr/bin/env bash

# Check if current directory is a git worktree or if worktrees exist for this repo
# Exit 0 (success) with "WORKTREE=true" if in worktree or worktrees exist
# Exit 1 (failure) with "WORKTREE=false" if not

SCRIPT_DIR="$(CDPATH="" cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

# Check if currently in a worktree
if is_worktree; then
    echo "WORKTREE=true"
    exit 0
fi

# Not in a worktree, check if worktrees exist for this repository
if git rev-parse --show-toplevel >/dev/null 2>&1; then
    # Check if there are additional worktrees (git worktree list shows main repo + worktrees)
    # Main repo line has format: /path/to/repo                    commit [branch]
    # Worktree lines have the same format
    # Count lines with [branch] suffix - these are worktrees (main repo also shows this)
    # If more than 1 line, there are additional worktrees
    worktree_count=$(git worktree list 2>/dev/null | wc -l)
    if [ "$worktree_count" -gt 1 ]; then
        echo "WORKTREE=true"
        exit 0
    fi
fi

echo "WORKTREE=false"
exit 1
