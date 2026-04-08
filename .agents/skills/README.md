# Agent Skills

Specialized skills for AI agents working on DTVM.

**This directory is the single source of truth (SSOT) for all agent skills.**
`.claude/skills/` contains auto-generated mirrors — do not edit mirrors directly.
To regenerate mirrors after changes, run:

```bash
python3 .agents/tooling/generate_skill_mirrors.py
```

## Available Skills

| Skill | Description |
|-------|-------------|
| `dev-workflow` | End-to-end feature development: propose, plan, execute, verify, archive |
| `archive` | Archive completed change proposals to `docs/_archive/` |
| `dtvm-perf-profile` | Performance profiling with hardware counters |
| `dmir-compiler-analysis` | DMIR compiler analysis and cost model reference |

## Directory Structure

```
.agents/skills/
├── README.md
├── dev-workflow/SKILL.md
├── archive/SKILL.md
├── dtvm-perf-profile/SKILL.md
└── dmir-compiler-analysis/SKILL.md
```
