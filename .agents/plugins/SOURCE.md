# Vendored plugin: pstack

DTVM vendors the official Cursor marketplace plugin **pstack** as a
third-party plugin package under `.agents/plugins/pstack`. This is not
a DTVM first-party skill pack. Do not merge pstack skills into
`.agents/skills/` or `.claude/skills/`.

## Pin (checked 2026-11-26)

| Field | Value |
| --- | --- |
| Marketplace repo | https://github.com/cursor/plugins |
| Plugin directory | `pstack/` |
| Homepage | https://github.com/cursor/plugins/tree/main/pstack |
| License | MIT (`pstack/LICENSE`, Copyright (c) 2026 Lauren Tan) |
| Manifest version | `0.15.48` (root `plugin.json` and `.cursor-plugin/plugin.json`) |
| `cursor/plugins` `main` SHA | `b7b93c36be9bcc36a74db438e0fd385d660bc559` |
| Last commit that touched `pstack/` | `9e278fe4d4ecd8bfe98b1b79bf4be662efb338cc` |

## Why a copy at `.agents/plugins/pstack`

Official install is `/add-plugin pstack` (project or user scope). This
repo also keeps the plugin in-tree so contributors share the same
pinned tree.

The plugin package lives under `.agents/plugins/` as a third-party
bundle, separate from first-party skills in `.agents/skills/`. Cursor
does **not** auto-discover `.agents/plugins/`. Documented Cursor load
paths are:

1. Marketplace install (`/add-plugin pstack`)
2. `~/.cursor/plugins/local/<name>` (user-local; not committable)
3. A project `workspaceOpen` hook that returns `pluginPaths`
   (https://cursor.com/docs/hooks)

A thin Cursor hook in `.cursor/hooks.json` and
`.cursor/hooks/register-pstack.sh` points `pluginPaths` at this shared
copy. It fires in the Cursor desktop app and CLI. Hosted Cloud Agents
do not run `workspaceOpen`; use `/add-plugin pstack` there.

Submoduling the entire `cursor/plugins` marketplace would pull every
official plugin. A copy of only `pstack/` plus the hook is the
smallest updateable install that Cursor can load from this repository.

## Refresh

From the repository root:

```bash
.agents/plugins/update-pstack.sh
```

That script replaces `.agents/plugins/pstack` from current
`cursor/plugins` `main` and rewrites this pin file. Review the diff
and commit.
