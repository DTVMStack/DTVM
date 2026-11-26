#!/bin/sh
# Register the in-tree pstack plugin for this workspace.
# Cursor workspaceOpen hooks must print JSON with absolute pluginPaths.
# See https://cursor.com/docs/hooks (workspaceOpen).
set -eu

ROOT="${CURSOR_PROJECT_DIR:-}"
if [ -z "$ROOT" ]; then
  ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
fi
PLUGIN="$ROOT/.cursor/plugins/pstack"

if [ ! -f "$PLUGIN/plugin.json" ] && [ ! -f "$PLUGIN/.cursor-plugin/plugin.json" ]; then
  printf '{"pluginPaths":[]}\n'
  exit 0
fi

if command -v python3 >/dev/null 2>&1; then
  python3 -c 'import json,sys; print(json.dumps({"pluginPaths":[sys.argv[1]]}))' "$PLUGIN"
else
  printf '{"pluginPaths":["%s"]}\n' "$PLUGIN"
fi
