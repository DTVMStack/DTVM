#!/usr/bin/env bash
# Common functions and variables for all scripts

# Get repository root, with fallback for non-git repositories
get_repo_root() {
    if git rev-parse --show-toplevel >/dev/null 2>&1; then
        git rev-parse --show-toplevel
    else
        # Fall back to script location for non-git repos
        local script_dir="$(CDPATH="" cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        (cd "$script_dir/../../.." && pwd)
    fi
}

# Get current branch, with fallback for non-git repositories
get_current_branch() {
    # First check if SPECIFY_FEATURE environment variable is set
    if [[ -n "${SPECIFY_FEATURE:-}" ]]; then
        echo "$SPECIFY_FEATURE"
        return
    fi

    # Then check git if available
    if git rev-parse --abbrev-ref HEAD >/dev/null 2>&1; then
        git rev-parse --abbrev-ref HEAD
        return
    fi

    # For non-git repos, try to find the latest feature directory
    local repo_root=$(get_repo_root)
    local features_dir="$repo_root/specs/features"

    if [[ -d "$features_dir" ]]; then
        local latest_feature=""
        local highest=0

        for dir in "$features_dir"/*; do
            if [[ -d "$dir" ]]; then
                local dirname=$(basename "$dir")
                if [[ "$dirname" =~ ^([0-9]{3})- ]]; then
                    local number=${BASH_REMATCH[1]}
                    number=$((10#$number))
                    if [[ "$number" -gt "$highest" ]]; then
                        highest=$number
                        latest_feature=$dirname
                    fi
                fi
            fi
        done

        if [[ -n "$latest_feature" ]]; then
            echo "$latest_feature"
            return
        fi
    fi

    echo "main"  # Final fallback
}

# Check if we have git available
has_git() {
    git rev-parse --show-toplevel >/dev/null 2>&1
}

check_feature_branch() {
    local branch="$1"
    local has_git_repo="$2"

    # For non-git repos, we can't enforce branch naming but still provide output
    if [[ "$has_git_repo" != "true" ]]; then
        echo "[specify] Warning: Git repository not detected; skipped branch validation" >&2
        return 0
    fi

    # Support both "feature/###-xxx" and "###-xxx" formats
    if [[ ! "$branch" =~ ^(feature/)?[0-9]{3}- ]]; then
        echo "ERROR: Not on a feature branch. Current branch: $branch" >&2
        echo "Feature branches should be named like: feature/001-feature-name or 001-feature-name" >&2
        return 1
    fi

    return 0
}

get_feature_dir() { echo "$1/specs/features/$2"; }

# Find feature directory by numeric prefix instead of exact branch match
# This allows multiple branches to work on the same spec (e.g., 004-fix-bug, 004-add-feature)
find_feature_dir_by_prefix() {
    local repo_root="$1"
    local branch_name="$2"
    local features_dir="$repo_root/specs/features"

    # Remove feature/ prefix if present (support both "feature/###-xxx" and "###-xxx")
    branch_name="${branch_name#feature/}"

    # Extract numeric prefix from branch (e.g., "004" from "004-whatever")
    if [[ ! "$branch_name" =~ ^([0-9]{3})- ]]; then
        # If branch doesn't have numeric prefix, fall back to exact match
        echo "$features_dir/$branch_name"
        return
    fi

    local prefix="${BASH_REMATCH[1]}"

    # Search for directories in specs/features/ that start with this prefix
    local matches=()
    if [[ -d "$features_dir" ]]; then
        for dir in "$features_dir"/"$prefix"-*; do
            if [[ -d "$dir" ]]; then
                matches+=("$(basename "$dir")")
            fi
        done
    fi

    # Handle results
    if [[ ${#matches[@]} -eq 0 ]]; then
        # No match found - return the branch name path (will fail later with clear error)
        echo "$features_dir/$branch_name"
    elif [[ ${#matches[@]} -eq 1 ]]; then
        # Exactly one match - perfect!
        echo "$features_dir/${matches[0]}"
    else
        # Multiple matches - this shouldn't happen with proper naming convention
        echo "ERROR: Multiple spec directories found with prefix '$prefix': ${matches[*]}" >&2
        echo "Please ensure only one spec directory exists per numeric prefix." >&2
        echo "$features_dir/$branch_name"  # Return something to avoid breaking the script
    fi
}

get_feature_paths() {
    local repo_root=$(get_repo_root)
    local current_branch=$(get_current_branch)
    local has_git_repo="false"

    if has_git; then
        has_git_repo="true"
    fi

    # Use prefix-based lookup to support multiple branches per spec
    local feature_dir=$(find_feature_dir_by_prefix "$repo_root" "$current_branch")

    printf 'REPO_ROOT=%q\n' "$repo_root"
    printf 'CURRENT_BRANCH=%q\n' "$current_branch"
    printf 'HAS_GIT=%q\n' "$has_git_repo"
    printf 'FEATURE_DIR=%q\n' "$feature_dir"
    printf 'FEATURE_SPEC=%q\n' "$feature_dir/spec.md"
    printf 'IMPL_PLAN=%q\n' "$feature_dir/plan.md"
    printf 'TASKS=%q\n' "$feature_dir/tasks.md"
    printf 'RESEARCH=%q\n' "$feature_dir/research.md"
    printf 'DATA_MODEL=%q\n' "$feature_dir/data-model.md"
    printf 'QUICKSTART=%q\n' "$feature_dir/quickstart.md"
    printf 'CONTRACTS_DIR=%q\n' "$feature_dir/contracts"
}

check_file() { [[ -f "$1" ]] && echo "  ✓ $2" || echo "  ✗ $2"; }
check_dir() { [[ -d "$1" && -n $(ls -A "$1" 2>/dev/null) ]] && echo "  ✓ $2" || echo "  ✗ $2"; }

# Detect if current directory is a git worktree
# Worktree has .git as a file (pointing to main repo's worktrees ref), normal repo has .git as a directory
is_worktree() {
    if [ -f ".git" ]; then
        # Check if .git file content points to worktrees
        grep -q "worktrees" ".git" 2>/dev/null && return 0
    fi
    return 1
}

# Get main repository root (parent directory for worktree)
get_main_repo_root() {
    if is_worktree; then
        # Worktree path is typically /path/to/main_repo/.git/worktrees/xxx
        # Simpler approach: get worktree root via git rev-parse, then get its parent
        local wt_root=$(git rev-parse --show-toplevel)
        local wt_parent=$(dirname "$wt_root")
        # If parent contains .git directory, it's the main repo
        if [ -d "$wt_parent/.git" ]; then
            echo "$wt_parent"
        else
            # Alternative: extract main repo path from .git file content
            local git_file=".git"
            if [ -f "$git_file" ]; then
                # .git file content format: gitdir: /Users/user/repos/main_repo/.git/worktrees/feature-name
                local gitdir=$(grep "^gitdir:" "$git_file" | sed 's/gitdir: //' | sed 's/\/.git\/worktrees\/.*//')
                if [ -n "$gitdir" ]; then
                    echo "$gitdir"
                else
                    echo "$wt_root"
                fi
            else
                echo "$wt_root"
            fi
        fi
    else
        git rev-parse --show-toplevel
    fi
}

# Get worktree path (based on main repo name)
get_worktree_path() {
    local main_repo="$1"
    local feature_name="$2"

    # Get main repo name
    local repo_name=$(basename "$main_repo")

    # Construct worktree path
    echo "${main_repo}_${feature_name}"
}
