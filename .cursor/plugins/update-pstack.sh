#!/bin/sh
# Replace .cursor/plugins/pstack from current github.com/cursor/plugins main.
set -eu

REPO_ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
DEST="$REPO_ROOT/.cursor/plugins/pstack"
SOURCE_NOTE="$REPO_ROOT/.cursor/plugins/SOURCE.md"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

git clone --depth 1 --filter=blob:none --sparse https://github.com/cursor/plugins.git "$TMP/cursor-plugins"
cd "$TMP/cursor-plugins"
git sparse-checkout set pstack
SHA=$(git rev-parse HEAD)
PSTACK_TOUCH=$(git log -1 --format=%H -- pstack)
VERSION=$(python3 -c 'import json; print(json.load(open("pstack/plugin.json"))["version"])')
DATE=$(date -u +%Y-%m-%d)

rm -rf "$DEST"
cp -a pstack "$DEST"

cat > "$SOURCE_NOTE" <<EOF
# Vendored Cursor plugin: pstack

DTVM vendors the official Cursor marketplace plugin **pstack** as a
copy under \`.cursor/plugins/pstack\`. This is not a DTVM first-party
skill pack. Do not merge pstack skills into \`.agents/skills/\` or
\`.claude/skills/\`.

## Pin (checked ${DATE})

| Field | Value |
| --- | --- |
| Marketplace repo | https://github.com/cursor/plugins |
| Plugin directory | \`pstack/\` |
| Homepage | https://github.com/cursor/plugins/tree/main/pstack |
| License | MIT (\`pstack/LICENSE\`, Copyright (c) 2026 Lauren Tan) |
| Manifest version | \`${VERSION}\` (root \`plugin.json\` and \`.cursor-plugin/plugin.json\`) |
| \`cursor/plugins\` \`main\` SHA | \`${SHA}\` |
| Last commit that touched \`pstack/\` | \`${PSTACK_TOUCH}\` |

## Why a copy at \`.cursor/plugins/pstack\`

Official install is \`/add-plugin pstack\` (project or user scope). This
repo also keeps the plugin in-tree so contributors share the same
pinned tree.

Cursor does **not** document auto-discovery of a project
\`.cursor/plugins/\` folder. Documented load paths are:

1. Marketplace install (\`/add-plugin pstack\`)
2. \`~/.cursor/plugins/local/<name>\` (user-local; not committable)
3. A project \`workspaceOpen\` hook that returns \`pluginPaths\`
   (https://cursor.com/docs/hooks)

A symlink to a tree outside the plugin parent is skipped for
\`~/.cursor/plugins/local\`. Submoduling the entire \`cursor/plugins\`
marketplace would pull every official plugin. A copy of only \`pstack/\`
plus the hook is the smallest updateable install that Cursor can load
from this repository.

The hook lives in \`.cursor/hooks.json\` and
\`.cursor/hooks/register-pstack.sh\`. It fires in the Cursor desktop app
and CLI. Hosted Cloud Agents do not run \`workspaceOpen\`; use
\`/add-plugin pstack\` there.

## Refresh

From the repository root:

\`\`\`bash
.cursor/plugins/update-pstack.sh
\`\`\`

That script replaces \`.cursor/plugins/pstack\` from current
\`cursor/plugins\` \`main\` and rewrites this pin file. Review the diff
and commit.
EOF

echo "Updated pstack to version ${VERSION} at cursor/plugins ${SHA}"
