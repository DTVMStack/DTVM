# DTVM Module Index

This directory is the SSOT (Single Source of Truth) for all module specifications. Each module contains `spec.md` (boundaries and contracts) and `data-model.md` (data model).

**Division principle: Strictly by directory.** Each module corresponds to one (or a few closely related) directory; specs describe only the code under that directory. Cross-module functional chains are described through cross-references.

## Module List

### Foundation Layer

| Module | Directory | Responsibility |
|--------|-----------|----------------|
| [common](common/) | `src/common/` | Shared types, error system, memory pools, opcode definitions, trap handling |
| [platform](platform/) | `src/platform/` | OS/hardware abstraction layer (POSIX memory mapping, SGX enclave support) |
| [utils](utils/) | `src/utils/` | Logging, backtrace, thread-safe containers, statistics, perf integration, WASM/EVM utility functions |

### Core Runtime Layer

| Module | Directory | Responsibility |
|--------|-----------|----------------|
| [runtime](runtime/) | `src/runtime/` + `src/entrypoint/` | Core runtime (Runtime/Instance/Module/Memory/Isolation/VNMI/WNI), including EVMModule/EVMInstance lifecycle management, JIT native call bridging |

### Execution Engine Layer

| Module | Directory | Responsibility |
|--------|-----------|----------------|
| [action](action/) | `src/action/` | Module/function loading (WASM + EVM), WASM interpreter, JIT orchestration entry, EVM bytecode traversal |
| [evm](evm/) | `src/evm/` | EVM interpreter core: opcode handling, Gas calculation, bytecode cache, EVM constants and revision definitions |
| [singlepass](singlepass/) | `src/singlepass/` | Single-pass JIT compiler (AsmJit, x64/AArch64 backends) |
| [compiler](compiler/) | `src/compiler/` | Multi-pass compilation pipeline: WASM frontend + EVM frontend -> dMIR -> CgIR -> register allocation -> x86 backend |

### Host Interface Layer

| Module | Directory | Responsibility |
|--------|-----------|----------------|
| [host](host/) | `src/host/` + `src/wni/` | Host modules (WASI, env, spectest, EVM ABI mock, EVM crypto/Keccak, WNI interface) |

### Application and Integration Layer

| Module | Directory | Responsibility | Spec Granularity |
|--------|-----------|----------------|------------------|
| [cli](cli/) | `src/cli/` | dtvm CLI tool | spec + data-model |
| [vm-interface](vm-interface/) | `src/vm/` + `evmc/` | EVMC shared library interface (dtvmapi.so), WrappedHost bridging | spec + data-model |
| [rust-bindings](rust-bindings/) | `rust_crate/` | Rust FFI bindings and Rust API | spec + data-model |
| [tests](tests/) | `src/tests/` + `tests/` | Test infrastructure (WAST spec/EVM state/Solidity/MIR/C API) | spec + data-model |
| [tools](tools/) | `tools/` | Development helper scripts (formatting, compilation, performance checks, etc.) | spec only |

## Inter-Module Dependencies

Dependency direction: lower layer -> upper layer

```
common, platform, utils (foundation)
    -> runtime (core)
        -> action, evm (execution)
            -> singlepass, compiler (JIT)
        -> host (host)
    -> cli, vm-interface, rust-bindings (application)
```

## EVM Execution Chain (Cross-Module)

EVM's complete execution flow spans multiple modules; specs describe it through cross-references:

1. **vm-interface**: EVMC execute() entry point
2. **runtime**: EVMModule/EVMInstance lifecycle
3. **action**: EVMModuleLoader loading, performEVMJITCompile orchestration
4. **evm**: BaseInterpreter interpretation execution, opcode handling, Gas calculation
5. **compiler**: evm_frontend/ EVM->dMIR compilation, evm_compiler.* JIT orchestration
