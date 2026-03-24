# DTVM Project Constitution

The authoritative document for project principles and development constraints. All development activities (including AI-assisted development) should follow the principles defined in this document.

---

## Project Vision

### Purpose and Goals

DTVM (DeTerministic Virtual Machine) is a next-generation deterministic virtual machine for blockchain, addressing performance, determinism, and ecosystem compatibility challenges in blockchain networks. Built on WebAssembly while maintaining full EVM ABI compatibility.

### Core Values

1. **Determinism first**: All execution paths (except WASI) must produce identical results on any platform — this is the foundation of blockchain consensus
2. **High-performance execution**: Provide multi-tier optimizations (O0~O2) through a Lazy-JIT compilation framework (dMIR intermediate representation), balancing compilation efficiency and execution speed
3. **Ecosystem compatibility**: Support EVM and WASM compatibility
4. **Security and trust**: Support TEE native execution (Intel SGX), minimizing the trusted computing base

### Target Users

- Blockchain platform developers (integrating DTVM as an execution engine)
- Smart contract developers (developing contracts using multi-language SDKs)
- Blockchain infrastructure researchers
- Wasm users
- Agent users requiring secure tool sandboxing

### Definition of Success

- Pass all WebAssembly spec tests and EVM spec tests
- Cross-platform (x86-64 / ARM64, Linux / macOS) execution results are fully consistent
- Performance exceeds mainstream comparable VM implementations
- Stable operation under SGX environments

---

## Technical Constraints

### Architecture Patterns

- **Modular layered architecture**: modules under `src/` are organized by function (runtime, compiler, singlepass, evm, host, etc.), with each module's boundaries and contracts defined by spec.md files under `specs/modules/`
- **IR-driven**: all frontend instruction sets (Wasm, EVM, future RISC-V) are uniformly translated to dMIR, then the backend generates target code
- **Multiple execution modes**: interpreter, singlepass JIT (single-pass compilation), multipass JIT (multi-pass optimized compilation, depends on LLVM 15)
- **EVMC interface**: EVM compatibility provided through the standard EVMC interface

### Platform Requirements

| Dimension | Supported Range |
|------|----------|
| CPU Architecture | x86-64, ARM64 (aarch64) |
| Operating System | Linux, macOS (Darwin) |
| TEE | Intel SGX (optional) |
| Compiler | GCC >= 9.4.0 |
| LLVM | 15 (required only for multipass JIT) |

### Dependency Management

- **Third-party code**: stored uniformly in `third_party/`, modify only when explicitly required
- **LLVM**: external dependency for multipass JIT, configured via CMake `LLVM_DIR`
- **Docker**: development environment image available at `dtvmdev1/dtvm-dev-x64:main`

---

## Quality Standards

### Code Style

- Compilation options enforce `-Wall -Wextra`, disable RTTI (`-fno-rtti`)
- Naming and formatting follow existing project patterns (refer to existing code in `src/`)
- Comments should only explain non-obvious intent, trade-offs, or constraints; avoid narrative comments

### Determinism Guarantees

**Highest-priority constraint**: all execution paths must be deterministic.

- Prohibit non-deterministic system calls such as `rand()`, `time()` from affecting execution results
- Prohibit depending on uninitialized memory
- Prohibit depending on pointer address ordering
- Floating-point operations must handle NaN canonicalization
- Memory allocation patterns must not affect execution semantics

### Testing Requirements

| Test Type | Tool | Description |
|----------|------|------|
| Wasm spec tests | specUnitTests | All three execution modes (0/1/2) must pass |
| EVM spec tests | `tests/evm_spec_test/` | EVM compatibility verification |
| dMIR tests | lit + `tests/mir/` | Intermediate representation correctness |
| Memory safety | ASan (`ZEN_ENABLE_ASAN`) | No memory leaks or out-of-bounds access |

- Any behavioral change must include test updates or new tests
- Test results across all three execution modes must be consistent
- If tests were not run, this must be explicitly stated in the change description

### Performance Benchmarks

- JIT compilation should not introduce unexpected latency
- The interpreter serves as the functional baseline; JIT modes should outperform the interpreter
- Focus on gas metering accuracy and overhead

---

## Development Process

### Git Workflow

- Branch-based development, merged to the main branch via Pull Requests
- Fork → Branch → Implement → Test → PR → Review → Merge
- Follow the contribution process in [CONTRIBUTING.md](../../CONTRIBUTING.md)

### Commit Convention

Strictly follow [Conventional Commits](https://www.conventionalcommits.org/), see `docs/COMMIT_CONVENTION.md` for details:

```
<type>[optional scope]: <description>
```

- **type**: feat / fix / docs / style / refactor / perf / test / build / ci / chore
- **scope**: core / runtime / compiler / evm / tools / deps / ci / test / docs, etc.
- **description**: imperative mood, present tense, lowercase first letter, no period
- Commit format is automatically validated via GitHub Actions

### Spec-Kit + SSOT Development Model

This project adopts specification-driven development (SDD):

1. **Module specs** (`specs/modules/`): each module has `spec.md` and `data-model.md`, defining module boundaries, API contracts, and data models
2. **Feature development** (`specs/features/`): new features follow the speckit workflow: specify → clarify → plan → tasks → implement
3. **Change management**: architecture-level changes are managed through the proposal process in `specs/features/`

### Change Decision Tree

```
New requirement?
├─ Bug fix (restoring expected behavior)? → Fix directly
├─ Formatting/comments/typo fix? → Fix directly
├─ New feature/capability? → Create feature spec
├─ Breaking change? → Create feature spec
├─ Architecture change? → Create feature spec
└─ Unsure? → Create feature spec (safer)
```

### Code Review Requirements

- All changes are merged after PR review
- Review focus: determinism guarantees, memory safety, test coverage, module boundary compliance
- AI-assisted development changes also require human review

---

## Security and Compliance

### Deterministic Execution Security

- The VM execution engine is a safety-critical component; any non-deterministic behavior may cause blockchain forks
- Gas metering must be precise to prevent DoS attacks
- Memory bounds checking (`ZEN_ENABLE_JIT_BOUND_CHECK`) is enabled in production
- Stack overflow protection and virtual stack support

### TEE Security

- C++17 STL is disabled in SGX mode (`ZEN_DISABLE_CXX17_STL`)
- Minimize TCB (Trusted Computing Base)
- Non-essential dependencies such as spdlog are disabled in SGX mode

### Memory Safety

- Use ASan for memory leak detection
- JIT-compiled code must include bounds checks
- CPU exception mechanism (`ZEN_ENABLE_CPU_EXCEPTION`) implements Wasm traps

### License Compliance

- Main project: Apache License 2.0
- LLVM-related code: Apache 2.0 + BSD 3-Clause
- All source files must include the copyright header: `Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.`
- Third-party component license information is recorded in the `NOTICE` file
- Contributors must agree to the CLA (Contributor License Agreement)

---

## Team Collaboration

### Communication Protocols

- Technical discussions are conducted through GitHub Issues and Pull Requests
- Major design decisions are recorded in proposal documents under the specs directory
- AI-assisted development follows the behavioral guidelines in `AGENTS.md` and `specs/AGENTS.md`

### Decision Process

- Bug fixes and minor changes: developer makes autonomous decisions, confirmed via PR review
- New features/architecture changes: go through the speckit workflow, implemented after spec review
- Breaking changes: must be noted with `BREAKING CHANGE` in the commit message

### Knowledge Management

- Module contracts are documented in `specs/modules/`
- Build and usage guides are in `docs/`
- Constitution and memory documents are in `.specify/memory/`
- AI Agent behavioral rules are in `AGENTS.md` and `specs/AGENTS.md`

### Editing Discipline

- Keep changes minimal and localized; follow existing patterns
- Prefer modifying code in `src/`; modify `third_party/` only when explicitly required
- When code conflicts with specs, code takes precedence, but specs must be updated accordingly
- Do not duplicate module SSOT content in feature specs; use references instead

---

## Repository Structure

```
DTVM/
├── src/                    # Core source code
│   ├── runtime/            # Runtime
│   ├── compiler/           # Compiler
│   ├── singlepass/         # Singlepass JIT
│   ├── evm/                # EVM support
│   ├── host/               # Host interface
│   ├── action/             # Action processing
│   ├── cli/                # Command-line interface
│   ├── common/             # Common components
│   ├── platform/           # Platform abstraction
│   ├── utils/              # Utility functions
│   ├── vm/                 # VM core
│   ├── wni/                # Wasm Native Interface
│   ├── entrypoint/         # Entry points
│   └── tests/              # Tests
├── tests/                  # Test cases
│   ├── wast/               # Wasm spec tests
│   ├── evm_spec_test/      # EVM spec tests
│   └── mir/                # dMIR tests
├── evmc/                   # EVMC compatibility layer
├── rust_crate/             # Rust bindings
├── third_party/            # Third-party dependencies
├── tools/                  # Helper tools
├── docs/                   # Documentation
├── specs/                  # SDD specs
│   ├── modules/            # Module specs
│   └── features/           # Feature specs
├── .agents/skills/         # AI Agent skills
└── .specify/               # Spec-Kit configuration
```

---

*Last updated: 2026-03-13*
