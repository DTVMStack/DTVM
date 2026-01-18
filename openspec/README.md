# OpenSpec for DTVM

OpenSpec is a spec-driven development methodology for the DTVM project. It provides a structured approach to planning, documenting, and implementing changes through formal specifications.

## What is OpenSpec?

OpenSpec organizes development work into:

- **Specifications (`specs/`)**: The source of truth for what IS built - documented requirements with testable scenarios
- **Changes (`changes/`)**: Proposals for what SHOULD change - planned modifications before implementation
- **Archives (`changes/archive/`)**: Historical record of completed changes

## Directory Structure

```
openspec/
├── README.md               # This file
├── AGENTS.md               # Instructions for AI coding assistants
├── project.md              # Project conventions and context
├── architecture.md         # System architecture overview
├── coding-style.md         # Code style guidelines
├── testing.md              # Testing methodology
├── specs/                  # Current specifications
│   ├── evm-execution/      # EVM module loading and execution
│   ├── evm-jit/            # EVM JIT compilation pipeline
│   ├── evm-tests/          # EVM test harness and fixtures
│   └── evmc-vm-interface/  # EVMC API implementation
└── changes/                # Pending and archived changes
    └── archive/            # Completed changes
```

## Quick Start

### View Current State

```bash
# List all specifications
openspec list --specs

# List active changes
openspec list

# Show a specific spec or change
openspec show <item>
```

### Creating a Change Proposal

1. **Check existing specs**: Review what's already documented
2. **Create change directory**: `mkdir -p openspec/changes/<change-id>`
3. **Write proposal.md**: Explain why and what changes
4. **Create spec deltas**: Document requirement changes
5. **Create tasks.md**: List implementation steps
6. **Validate**: `openspec validate <change-id> --strict`

### Implementing Changes

1. Read `proposal.md` to understand the change
2. Read `design.md` if it exists for technical decisions
3. Follow `tasks.md` as implementation checklist
4. Update task status as work progresses
5. Archive after deployment

## Specification Format

Each specification includes requirements with testable scenarios:

```markdown
### Requirement: Feature Name
The system SHALL provide...

#### Scenario: Success case
- **WHEN** user performs action
- **THEN** expected result
```

Key conventions:
- Use **SHALL/MUST** for normative requirements
- Every requirement needs at least one scenario
- Scenarios use `#### Scenario:` format (4 hashtags)

## When to Create a Proposal

**Create proposal for:**
- New features or capabilities
- Breaking changes (API, schema)
- Architecture changes
- Performance optimizations (that change behavior)
- Security pattern updates

**Skip proposal for:**
- Bug fixes (restore intended behavior)
- Typos, formatting, comments
- Non-breaking dependency updates
- Configuration changes
- Tests for existing behavior

## Related Documentation

- [AGENTS.md](AGENTS.md) - Detailed instructions for AI assistants
- [project.md](project.md) - Project conventions and domain context
- [architecture.md](architecture.md) - System architecture overview
- [coding-style.md](coding-style.md) - Code style guidelines
- [testing.md](testing.md) - Testing methodology

## CLI Reference

```bash
openspec list                  # List active changes
openspec list --specs          # List specifications
openspec show [item]           # Display change or spec
openspec validate [item]       # Validate changes or specs
openspec archive <change-id>   # Archive after deployment
openspec init [path]           # Initialize OpenSpec
openspec update [path]         # Update instruction files
```

## Slash Commands (Codex and Cursor)

Repo-local slash commands are provided for OpenSpec workflows:
- `/openspec-proposal` - scaffold a proposal
- `/openspec-apply` - implement an approved change
- `/openspec-archive` - archive a deployed change

Command definitions live in `.codex/prompts/` and `.cursor/commands/` and should remain in sync.

## Contributing

When contributing to DTVM:

1. Review existing specs in `openspec/specs/` for the area you're working on
2. Check pending changes in `openspec/changes/` for conflicts
3. For new features or breaking changes, create a change proposal first
4. Ensure your implementation matches the specification requirements
5. Update or create tests that verify the scenarios

Remember: **Specs are truth. Changes are proposals. Keep them in sync.**
