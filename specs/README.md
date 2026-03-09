# DTVM SSOT (Single Source of Truth)

The authoritative source for all module specifications, architecture designs, and feature specifications in the DTVM project, following the Spec-Driven Development (SDD) methodology.

## Project Overview

DTVM (DeTerministic Virtual Machine) is a next-generation blockchain virtual machine built on WebAssembly (Wasm) while maintaining full Ethereum Virtual Machine (EVM) ABI compatibility.

Key goals:
- Deterministic JIT execution with enhanced performance
- EVM ABI compatibility and multi-language ecosystem support
- TEE-native security and hardware-optimized efficiency
- AI-powered smart contract development through SmartCogent integration

## Tech Stack

- **Core Language**: C++ (C++17)
- **Runtime Support**: C, Rust APIs
- **Build System**: CMake
- **JIT Backend**: Customized implementation based on LLVM 15
- **Target Architectures**: x86-64, ARM64
- **Smart Contract Languages**: Solidity, C/C++, Rust, Java, Golang, AssemblyScript
- **Security**: Intel SGX TEE support
- **Testing**: CTest + Google Test, WebAssembly spec tests

## Architecture Patterns

- **Modular Design**: Independent adaptation layers for different instruction sets (Wasm, EVM, future RISC-V)
- **Unified IR**: All instruction sets translate to Deterministic Middle Intermediate Representation (dMIR)
- **Hybrid Execution**: Multiple execution modes with dynamic switching support
- **Plugin Architecture**: Extensible runtime system for different blockchain environments

## Key Constraints

- **Deterministic Execution**: All operations must be deterministic across platforms and runs
- **Gas Metering**: Precise resource consumption tracking for blockchain environments
- **Memory Safety**: Strict boundary checking and memory management
- **Cross-Platform**: Consistent behavior across x86-64 and ARM64 architectures
- **TEE Compatibility**: Minimal Trusted Computing Base (TCB) for SGX environments

## Directory Structure

```
specs/
├── README.md                  # This file - project SSOT overview
├── AGENTS.md                  # AI Agent behavior rules
├── architecture/              # Global architecture design
├── code-style/                # Coding style guidelines
├── testing/                   # Testing guide
├── data-model/                # Global data model
├── modules/                   # Module specifications (SSOT core)
├── features/                  # Feature specifications (incremental development)
└── _archive/                  # Archived completed features
```

## External Dependencies

- **LLVM 15**: Required for multipass JIT compilation mode
- **CMake**: Build system and dependency management
- **WebAssembly Spec Tests**: Official compliance validation test suite
- **Intel SGX SDK**: Trusted execution environment support

## Related Documentation

- Build & Testing: [docs/start.md](../docs/start.md)
- User Guide: [docs/user-guide.md](../docs/user-guide.md)
- API Reference: [docs/API.md](../docs/API.md)
- Commit Convention: [docs/COMMIT_CONVENTION.md](../docs/COMMIT_CONVENTION.md)
- Versioning: [docs/VERSIONING.md](../docs/VERSIONING.md)
