# DTVM Architecture

This document provides a high-level overview of DTVM's architecture, including its module structure, execution modes, and compilation pipeline.

## Overview

DTVM (DeTerministic Virtual Machine) is a blockchain virtual machine that executes WebAssembly (Wasm) and EVM bytecode with deterministic guarantees. The core engine (ZetaEngine) provides a lazy-JIT compilation framework with multiple execution modes.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Input Programs                                │
│              Wasm Bytecode  │  EVM Bytecode  │  (Future: RISC-V)    │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      Adaptation Layers                               │
│         Wasm Frontend   │   EVM Frontend   │   (Future: RISC-V)     │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│          Deterministic Middle Intermediate Representation (dMIR)     │
│               Unified IR with deterministic guarantees               │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
            ┌───────────┐   ┌───────────┐   ┌───────────┐
            │Interpreter│   │Singlepass │   │ Multipass │
            │   Mode    │   │  JIT Mode │   │ JIT Mode  │
            └───────────┘   └───────────┘   └───────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        Native Code Execution                         │
│                      x86-64  │  ARM64 (singlepass only)              │
└─────────────────────────────────────────────────────────────────────┘
```

## Execution Modes

### Interpreter Mode
- Direct bytecode interpretation without compilation
- Lowest startup latency, suitable for short-lived contracts
- Platform-independent execution

### Singlepass JIT Mode
- Single-pass compilation to native code
- Fast compilation with reasonable runtime performance
- Supports both x86-64 and ARM64 architectures
- No LLVM dependency

### Multipass JIT Mode (Lazy-JIT)
- LLVM-based multi-pass optimization
- Two sub-modes:
  - **FLAT Mode**: Function Level fAst Transpile - rapid execution
  - **FLAS Mode**: Function Level Adaptive hot-Switching - optimized performance
- Highest runtime performance for long-running contracts
- Currently x86-64 only
- Requires LLVM 15

## Module Structure

```
src/
├── action/          # Module loading, instantiation, and compilation wrappers
├── cli/             # Command-line interface
├── common/          # Shared types, errors, opcodes, memory pools
├── compiler/        # Multipass JIT compiler with LLVM backend
├── entrypoint/      # JIT code execution entry points
├── evm/             # EVM bytecode interpreter and cache
├── host/            # Host API implementations (WASI, EVM, spectest)
├── platform/        # Platform abstractions (POSIX, SGX)
├── runtime/         # Core runtime: modules, instances, isolation, memory
├── singlepass/      # Single-pass JIT compiler (x64, ARM64)
├── tests/           # Test framework and fixtures
├── utils/           # Utility functions and helpers
├── vm/              # EVMC VM interface implementation
└── wni/             # WebAssembly Native Interface declarations
```

## Key Components

### Runtime (`src/runtime/`)
- **Runtime**: Core driver managing execution modes and configuration
- **Module**: Wasm/EVM module representation with bytecode and metadata
- **Instance**: Per-execution state (memory, stack, globals)
- **Isolation**: Sandboxed execution environment
- **Memory**: Memory management with mmap pool mechanism
- **CodeHolder**: JIT code storage and management

### Compiler (`src/compiler/`)
- **Frontend**: Bytecode parsing and validation (Wasm/EVM)
- **MIR**: Middle Intermediate Representation for optimization
- **CGIR**: Code Generation IR for target-specific lowering
- **Target**: Architecture-specific code generators (x64)
- **Context**: Compilation state and configuration

### EVM Support (`src/evm/`, `src/vm/`)
- **EVMModule**: EVM bytecode container with JIT compilation
- **Interpreter**: EVM opcode execution with gas metering
- **BytecodeCache**: Jump destinations, PUSH immediates, gas chunks
- **EVMC Interface**: Standard Ethereum VM connector API (version 12)

## Compilation Pipeline

### Wasm Compilation
```
Wasm Bytecode → Parser → Validator → MIR → Optimizer → CGIR → Native Code
```

### EVM Compilation
```
EVM Bytecode → BytecodeCache → EVM MIR → Optimizer → CGIR → Native Code
```

## Platform Support

| Feature          | x86-64 | ARM64 |
|------------------|--------|-------|
| Interpreter      | ✓      | ✓     |
| Singlepass JIT   | ✓      | ✓     |
| Multipass JIT    | ✓      | ✗     |
| Intel SGX TEE    | ✓      | ✗     |

## External Interfaces

### C/C++ API
- `src/zetaengine.h` - C++ API
- `src/zetaengine-c.h` - C API
- `libzetaengine.a` - Static library

### Rust API
- `rust_crate/` - Rust bindings and SDK

### EVMC API
- `src/vm/dt_evmc_vm.h` - EVMC interface implementation
- Compatible with EVMC ABI version 12

## Determinism Guarantees

DTVM ensures deterministic execution through:
- Unified dMIR representation across platforms
- Strict floating-point semantics
- Deterministic memory layout
- Platform-independent gas metering
- Consistent opcode behavior across revisions

## Security Features

- Memory safety with bounds checking
- Gas metering for resource limiting
- Intel SGX TEE support for trusted execution
- Minimal Trusted Computing Base (TCB)
- Static linking for deployment isolation

