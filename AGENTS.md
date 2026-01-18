<!-- OPENSPEC:START -->
# OpenSpec Instructions

These instructions are for AI assistants working in this project.

Always open `@/openspec/AGENTS.md` when the request:
- Mentions planning or proposals (words like proposal, spec, change, plan)
- Introduces new capabilities, breaking changes, architecture shifts, or big performance/security work
- Sounds ambiguous and you need the authoritative spec before coding

Use `@/openspec/AGENTS.md` to learn:
- How to create and apply change proposals
- Spec format and conventions
- Project structure and guidelines

Keep this managed block so 'openspec update' can refresh the instructions.

<!-- OPENSPEC:END -->

# DTVM Agent Guide

Instructions for working in this repo beyond the OpenSpec block.

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
- `openspec/`: spec-driven change proposals and references

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

## Documentation Pointers

- Overview: `README.md`
- Build/testing: `docs/start.md`
- Usage details: `docs/user-guide.md`
