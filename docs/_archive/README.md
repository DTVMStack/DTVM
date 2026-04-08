# Feature Archive

This directory stores completed and archived feature specifications and historical change records.

## Directory Structure

```
_archive/
├── YYYY-MM/
│   └── short-name/
│       ├── proposal.md
│       ├── design.md  (optional)
│       ├── tasks.md
│       └── specs/     (delta specs, if any)
```

All entries follow the `YYYY-MM/short-name/` convention, grouped by the month they were archived.

## Current Entries

| Month   | Feature                    | Description                          |
|---------|----------------------------|--------------------------------------|
| 2026-01 | add-evmc-vm-interface-lib  | EVMC VM interface library support    |
| 2026-02 | add-clz-opcode             | CLZ opcode for EVM execution and JIT |
| 2026-02 | add-jit-suitability-checker| JIT suitability checker for EVM      |
| 2026-03 | add-evm-jit-fallback       | EVM JIT fallback mechanism           |
| 2026-04 | update-evm-memory-block-precheck | EVM block-local memory precheck optimization |

## Notes

- Archived specifications are for historical reference only and should not be modified.
- If rework is needed, create a new change proposal under `docs/changes/` referencing the original.
