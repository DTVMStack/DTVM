#!/usr/bin/env bash

set -e

JSON_MODE=false
SHORT_NAME=""
BRANCH_NUMBER=""
WORKTREE_MODE=false
WORKTREE_PATH=""
ARGS=()
i=1
while [ $i -le $# ]; do
    arg="${!i}"
    case "$arg" in
        --json)
            JSON_MODE=true
            ;;
        --short-name)
            if [ $((i + 1)) -gt $# ]; then
                echo 'Error: --short-name requires a value' >&2
                exit 1
            fi
            i=$((i + 1))
            next_arg="${!i}"
            # Check if the next argument is another option (starts with --)
            if [[ "$next_arg" == --* ]]; then
                echo 'Error: --short-name requires a value' >&2
                exit 1
            fi
            SHORT_NAME="$next_arg"
            ;;
        --number)
            if [ $((i + 1)) -gt $# ]; then
                echo 'Error: --number requires a value' >&2
                exit 1
            fi
            i=$((i + 1))
            next_arg="${!i}"
            if [[ "$next_arg" == --* ]]; then
                echo 'Error: --number requires a value' >&2
                exit 1
            fi
            BRANCH_NUMBER="$next_arg"
            ;;
        --worktree)
            WORKTREE_MODE=true
            ;;
        --help|-h)
            echo "Usage: $0 [--json] [--short-name <name>] [--number N] [--worktree] <feature_description>"
            echo ""
            echo "Options:"
            echo "  --json              Output in JSON format"
            echo "  --short-name <name> Provide a custom short name (2-4 words) for the branch"
            echo "  --number N          Specify branch number manually (overrides auto-detection)"
            echo "  --worktree          Create a new git worktree instead of a regular branch"
            echo "  --help, -h          Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 'Add user authentication system' --short-name 'user-auth'"
            echo "  $0 'Implement OAuth2 integration for API' --number 5"
            echo "  $0 'Add user authentication' --worktree"
            exit 0
            ;;
        *)
            ARGS+=("$arg")
            ;;
    esac
    i=$((i + 1))
done

FEATURE_DESCRIPTION="${ARGS[*]}"
if [ -z "$FEATURE_DESCRIPTION" ]; then
    echo "Usage: $0 [--json] [--short-name <name>] [--number N] <feature_description>" >&2
    exit 1
fi

# Function to find the repository root by searching for existing project markers
find_repo_root() {
    local dir="$1"
    while [ "$dir" != "/" ]; do
        if [ -d "$dir/.git" ] || [ -d "$dir/.specify" ]; then
            echo "$dir"
            return 0
        fi
        dir="$(dirname "$dir")"
    done
    return 1
}

# Function to get highest number from specs directory
get_highest_from_specs() {
    local specs_dir="$1"
    local highest=0

    if [ -d "$specs_dir" ]; then
        for dir in "$specs_dir"/*; do
            [ -d "$dir" ] || continue
            dirname=$(basename "$dir")
            number=$(echo "$dirname" | grep -o '^[0-9]\+' || echo "0")
            number=$((10#$number))
            if [ "$number" -gt "$highest" ]; then
                highest=$number
            fi
        done
    fi

    echo "$highest"
}

# Function to get highest number from git branches
get_highest_from_branches() {
    local highest=0

    # Get all branches (local and remote)
    branches=$(git branch -a 2>/dev/null || echo "")

    if [ -n "$branches" ]; then
        while IFS= read -r branch; do
            # Clean branch name: remove leading markers and remote prefixes
            clean_branch=$(echo "$branch" | sed 's/^[* ]*//; s|^remotes/[^/]*/||')

            # Remove feature/ prefix if present
            clean_branch=$(echo "$clean_branch" | sed 's|^feature/||')

            # Extract feature number if branch matches pattern ###-*
            if echo "$clean_branch" | grep -q '^[0-9]\{3\}-'; then
                number=$(echo "$clean_branch" | grep -o '^[0-9]\{3\}' || echo "0")
                number=$((10#$number))
                if [ "$number" -gt "$highest" ]; then
                    highest=$number
                fi
            fi
        done <<< "$branches"
    fi

    echo "$highest"
}

# Function to check existing branches (local and remote) and return next available number
check_existing_branches() {
    local specs_dir="$1"

    # Fetch all remotes to get latest branch info (suppress errors if no remotes)
    git fetch --all --prune 2>/dev/null || true

    # Get highest number from ALL branches (not just matching short name)
    local highest_branch=$(get_highest_from_branches)

    # Get highest number from ALL specs (not just matching short name)
    local highest_spec=$(get_highest_from_specs "$specs_dir")

    # Take the maximum of both
    local max_num=$highest_branch
    if [ "$highest_spec" -gt "$max_num" ]; then
        max_num=$highest_spec
    fi

    # Return next number
    echo $((max_num + 1))
}

# Function to clean and format a branch name
clean_branch_name() {
    local name="$1"
    echo "$name" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g' | sed 's/-\+/-/g' | sed 's/^-//' | sed 's/-$//'
}

# Resolve repository root. Prefer git information when available, but fall back
# to searching for repository markers so the workflow still functions in repositories that
# were initialised with --no-git.
SCRIPT_DIR="$(CDPATH="" cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if git rev-parse --show-toplevel >/dev/null 2>&1; then
    REPO_ROOT=$(git rev-parse --show-toplevel)
    HAS_GIT=true
else
    REPO_ROOT="$(find_repo_root "$SCRIPT_DIR")"
    if [ -z "$REPO_ROOT" ]; then
        echo "Error: Could not determine repository root. Please run this script from within the repository." >&2
        exit 1
    fi
    HAS_GIT=false
fi

# Load common functions for worktree detection
source "$SCRIPT_DIR/common.sh"

cd "$REPO_ROOT"

SPECS_DIR="$REPO_ROOT/specs"
FEATURES_DIR="$SPECS_DIR/features"
mkdir -p "$FEATURES_DIR"

# Function to generate branch name with stop word filtering and length filtering
generate_branch_name() {
    local description="$1"

    # Common stop words to filter out
    local stop_words="^(i|a|an|the|to|for|of|in|on|at|by|with|from|is|are|was|were|be|been|being|have|has|had|do|does|did|will|would|should|could|can|may|might|must|shall|this|that|these|those|my|your|our|their|want|need|add|get|set)$"

    # Convert to lowercase and split into words
    local clean_name=$(echo "$description" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/ /g')

    # Filter words: remove stop words and words shorter than 3 chars (unless they're uppercase acronyms in original)
    local meaningful_words=()
    for word in $clean_name; do
        # Skip empty words
        [ -z "$word" ] && continue

        # Keep words that are NOT stop words AND (length >= 3 OR are potential acronyms)
        if ! echo "$word" | grep -qiE "$stop_words"; then
            if [ ${#word} -ge 3 ]; then
                meaningful_words+=("$word")
            elif echo "$description" | grep -q "\b${word^^}\b"; then
                # Keep short words if they appear as uppercase in original (likely acronyms)
                meaningful_words+=("$word")
            fi
        fi
    done

    # If we have meaningful words, use first 3-4 of them
    if [ ${#meaningful_words[@]} -gt 0 ]; then
        local max_words=3
        if [ ${#meaningful_words[@]} -eq 4 ]; then max_words=4; fi

        local result=""
        local count=0
        for word in "${meaningful_words[@]}"; do
            if [ $count -ge $max_words ]; then break; fi
            if [ -n "$result" ]; then result="$result-"; fi
            result="$result$word"
            count=$((count + 1))
        done
        echo "$result"
    else
        # Fallback to original logic if no meaningful words found
        local cleaned=$(clean_branch_name "$description")
        echo "$cleaned" | tr '-' '\n' | grep -v '^$' | head -3 | tr '\n' '-' | sed 's/-$//'
    fi
}

# Generate branch name
if [ -n "$SHORT_NAME" ]; then
    # Use provided short name, just clean it up
    BRANCH_SUFFIX=$(clean_branch_name "$SHORT_NAME")
else
    # Generate from description with smart filtering
    BRANCH_SUFFIX=$(generate_branch_name "$FEATURE_DESCRIPTION")
fi

# Determine branch number
if [ -z "$BRANCH_NUMBER" ]; then
    if [ "$HAS_GIT" = true ]; then
        # Check existing branches on remotes
        BRANCH_NUMBER=$(check_existing_branches "$FEATURES_DIR")
    else
        # Fall back to local directory check
        HIGHEST=$(get_highest_from_specs "$FEATURES_DIR")
        BRANCH_NUMBER=$((HIGHEST + 1))
    fi
fi

# Force base-10 interpretation to prevent octal conversion (e.g., 010 → 8 in octal, but should be 10 in decimal)
FEATURE_NUM=$(printf "%03d" "$((10#$BRANCH_NUMBER))")
FEATURE_NAME="${FEATURE_NUM}-${BRANCH_SUFFIX}"
GIT_BRANCH_NAME="feature/${FEATURE_NAME}"

# GitHub enforces a 244-byte limit on branch names
# Validate and truncate if necessary
MAX_BRANCH_LENGTH=244
if [ ${#GIT_BRANCH_NAME} -gt $MAX_BRANCH_LENGTH ]; then
    # Calculate how much we need to trim from suffix
    # Account for: "feature/" (8) + feature number (3) + hyphen (1) = 12 chars
    MAX_SUFFIX_LENGTH=$((MAX_BRANCH_LENGTH - 12))

    # Truncate suffix at word boundary if possible
    TRUNCATED_SUFFIX=$(echo "$BRANCH_SUFFIX" | cut -c1-$MAX_SUFFIX_LENGTH)
    # Remove trailing hyphen if truncation created one
    TRUNCATED_SUFFIX=$(echo "$TRUNCATED_SUFFIX" | sed 's/-$//')

    ORIGINAL_BRANCH_NAME="$GIT_BRANCH_NAME"
    FEATURE_NAME="${FEATURE_NUM}-${TRUNCATED_SUFFIX}"
    GIT_BRANCH_NAME="feature/${FEATURE_NAME}"

    >&2 echo "[specify] Warning: Branch name exceeded GitHub's 244-byte limit"
    >&2 echo "[specify] Original: $ORIGINAL_BRANCH_NAME (${#ORIGINAL_BRANCH_NAME} bytes)"
    >&2 echo "[specify] Truncated to: $GIT_BRANCH_NAME (${#GIT_BRANCH_NAME} bytes)"
fi

if [ "$HAS_GIT" = true ]; then
    if [ "$WORKTREE_MODE" = true ]; then
        # Create worktree
        WORKTREE_PATH=$(get_worktree_path "$REPO_ROOT" "$FEATURE_NAME")

        # Ensure parent directory exists
        mkdir -p "$(dirname "$WORKTREE_PATH")"

        # Create worktree on new branch (-b must come before path)
        git worktree add -b "$GIT_BRANCH_NAME" "$WORKTREE_PATH"

        echo "[specify] Worktree created at: $WORKTREE_PATH"
        echo "[specify] Please navigate to this directory to continue."
    else
        # Regular branch creation
        git checkout -b "$GIT_BRANCH_NAME"
    fi
else
    >&2 echo "[specify] Warning: Git repository not detected; skipped branch/worktree creation for $GIT_BRANCH_NAME"
fi

# Determine where to create the feature directory
if [ "$WORKTREE_MODE" = true ]; then
    # In worktree mode, use worktree root for specs
    WORKTREE_SPECS_DIR="$WORKTREE_PATH/specs/features"
    FEATURE_DIR="$WORKTREE_SPECS_DIR/$FEATURE_NAME"
    mkdir -p "$FEATURE_DIR"

    # Template path is always in the main repo (worktree has .specify too, but template should be shared)
    TEMPLATE="$REPO_ROOT/.specify/templates/spec-template.md"
    SPEC_FILE="$FEATURE_DIR/spec.md"
    if [ -f "$TEMPLATE" ]; then cp "$TEMPLATE" "$SPEC_FILE"; else touch "$SPEC_FILE"; fi
else
    # Normal mode: use main repo for specs
    FEATURE_DIR="$FEATURES_DIR/$FEATURE_NAME"
    mkdir -p "$FEATURE_DIR"

    TEMPLATE="$REPO_ROOT/.specify/templates/spec-template.md"
    SPEC_FILE="$FEATURE_DIR/spec.md"
    if [ -f "$TEMPLATE" ]; then cp "$TEMPLATE" "$SPEC_FILE"; else touch "$SPEC_FILE"; fi
fi

# Set the SPECIFY_FEATURE environment variable for the current session
# Use FEATURE_NAME (without feature/ prefix) for directory lookup compatibility
export SPECIFY_FEATURE="$FEATURE_NAME"

if $JSON_MODE; then
    if [ "$WORKTREE_MODE" = true ]; then
        printf '{"BRANCH_NAME":"%s","FEATURE_NAME":"%s","SPEC_FILE":"%s","FEATURE_NUM":"%s","WORKTREE_PATH":"%s","WORKTREE_MODE":"true"}\n' "$GIT_BRANCH_NAME" "$FEATURE_NAME" "$SPEC_FILE" "$FEATURE_NUM" "$WORKTREE_PATH"
    else
        printf '{"BRANCH_NAME":"%s","FEATURE_NAME":"%s","SPEC_FILE":"%s","FEATURE_NUM":"%s"}\n' "$GIT_BRANCH_NAME" "$FEATURE_NAME" "$SPEC_FILE" "$FEATURE_NUM"
    fi
else
    echo "BRANCH_NAME: $GIT_BRANCH_NAME"
    echo "FEATURE_NAME: $FEATURE_NAME"
    echo "SPEC_FILE: $SPEC_FILE"
    echo "FEATURE_NUM: $FEATURE_NUM"
    if [ "$WORKTREE_MODE" = true ]; then
        echo "WORKTREE_PATH: $WORKTREE_PATH"
        echo "WORKTREE_MODE: true"
        echo "Please navigate to $WORKTREE_PATH to continue."
    fi
    echo "SPECIFY_FEATURE environment variable set to: $FEATURE_NAME"
fi
