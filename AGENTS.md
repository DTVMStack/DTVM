# DTVM Agent Guide

Instructions for AI assistants working in this repo.

## Project Snapshot

- DTVM is a deterministic VM with EVM ABI compatibility; most core code is C/C++ in `src/`.
- Preserve determinism and avoid host-specific, non-deterministic behavior.
- Prefer touching `third_party/` only when explicitly required.

## Repository Map

- `src/`: core runtime, compiler, execution engines
- `tests/`: WAST spec tests (`tests/wast`), EVM spec tests (`tests/evm_spec_test`), dMIR tests (`tests/mir`)
- `docs/`: build and usage guides (`docs/start.md`, `docs/user-guide.md`)
- `evmc/`: EVM compatibility components
- `rust_crate/`: Rust bindings
- `tools/`: helper scripts and utilities
- `docs/`: documentation, module specifications, change proposals, and feature specs

## Build (CMake)

- Default interpreter build:
  - `cmake -B build -DCMAKE_BUILD_TYPE=Debug`
  - `cmake --build build`
- Singlepass JIT:
  - `cmake -B build -DCMAKE_BUILD_TYPE=Debug -DZEN_ENABLE_SINGLEPASS_JIT=ON`
- Multipass JIT (LLVM 15 required; x86-64 only):
  - `cmake -B build -DCMAKE_BUILD_TYPE=Debug -DZEN_ENABLE_MULTIPASS_JIT=ON -DLLVM_DIR=<llvm>/lib/cmake/llvm`
- Common flags: `ZEN_ENABLE_SPEC_TEST`, `ZEN_ENABLE_ASAN`, `ZEN_ENABLE_JIT_LOGGING`, `ZEN_ENABLE_JIT_BOUND_CHECK`

## Tests

- Spec tests require `ZEN_ENABLE_SPEC_TEST` at build time.
- Run from build output:
  - `ctest --verbose`
  - `./build/specUnitTests <mode>` where mode is `0` (interpreter), `1` (singlepass), `2` (multipass)
  - `./build/specUnitTests <case> <mode>` for a single `.wast` case (omit suffix)
- WAST test sources live under `tests/wast` (see `src/tests/CMakeLists.txt` for categories).
- MIR tests:
  - `pip install lit`
  - `cd tests/compiler && ./test_mir.sh` (also see `docs/start.md`)

## Change Discipline

- Keep edits minimal and localized; follow existing patterns.
- Update or add tests when behavior changes; call out if tests were not run.
- When asked to commit, follow `docs/COMMIT_CONVENTION.md`.

## Workflow

Use the `dev-workflow` skill for feature development. It covers the full cycle: propose, plan, implement, verify, and archive.

For archiving completed features, use the standalone `archive` skill.

## Change Decision Tree

```
New requirement?
├─ Bug fix (restore intended behavior)? -> Fix directly
├─ Formatting/comments/typos?           -> Fix directly
├─ New feature/capability?              -> Create change proposal in docs/changes/
├─ Breaking change?                     -> Create change proposal in docs/changes/
├─ Architecture change?                 -> Create change proposal in docs/changes/
└─ Uncertain?                           -> Create change proposal (safer)
```

## Change Proposals

New changes go in `docs/changes/YYYY-MM-DD-<slug>/README.md`.

Choose a tier:
- **Full**: architecture changes, cross-module impact, new capabilities
- **Light**: single-module improvements, well-scoped enhancements

See `docs/changes/README.md` for naming conventions and status definitions.

## Module Consultation

Before modifying code in a module, consult `docs/modules/<module>/spec.md` for boundaries, API contracts, and invariants.

## General Guidelines

- Do not duplicate module SSOT content in change proposals; use references
- When code conflicts with specifications, code takes precedence, but update specs to stay in sync
- Follow `docs/COMMIT_CONVENTION.md` for commit conventions
- Maintain determinism: avoid introducing host-specific non-deterministic behavior
- Prefer modifying code within `src/`; only modify `third_party/` when explicitly required

## Agent Skills

Skills are defined in `.agents/skills/` (single source of truth). `.claude/skills/` contains auto-generated mirrors for Claude Code; do not edit mirrors directly. After modifying any skill, regenerate mirrors:

```bash
python3 .agents/tooling/generate_skill_mirrors.py
```

## Documentation Pointers

- Overview: `README.md`
- Build/testing: `docs/start.md`
- Usage details: `docs/user-guide.md`
