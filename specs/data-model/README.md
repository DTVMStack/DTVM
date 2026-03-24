# DTVM Global Data Model

This directory defines core data types and entity relationships shared across modules.

## Core Type System

DTVM's core types are defined in `src/common/` and shared by all modules:

### Wasm Types (`src/common/type.h`)
- Value types: `i32`, `i64`, `f32`, `f64`, `v128`, `funcref`, `externref`
- Function types: `FunctionType` (parameters + return values)
- Opcodes: `src/common/wasm_defs/*.def`

### Error System (`src/common/errors.h`)
- `ErrorPhase`: Load / Validate / Instantiate / Execute
- `ErrorCode`: Specific error codes (defined in `errors.def`)
- `MayBe<T>`: Return value wrapper with error

### Memory Management (`src/common/mem_pool.h`)
- `MemPool`: Memory pool allocator
- `ConstStringPool`: String constant pool

## Cross-Module Shared Types

### Defined in common (used by 10+ modules)

| Type | Definition | Used By | Description |
|------|-----------|---------|-------------|
| `ErrorCode` | `common/errors.h` | all modules | Unified error code enumeration |
| `ErrorPhase` | `common/errors.h` | runtime, action, compiler | Error phase classification |
| `MayBe<T>` | `common/errors.h` | runtime, action, compiler | Error-bearing return wrapper |
| `WASMType` | `common/type.h` | runtime, action, compiler, singlepass | Wasm value type enumeration |
| `FunctionType` | `common/type.h` | runtime, action, compiler, host | Function signature descriptor |
| `Opcode` | `common/opcode.h` | action, compiler, singlepass | Wasm opcode enumeration |
| `MemPool` | `common/mem_pool.h` | runtime, compiler, singlepass | Memory pool allocator |
| `ConstStringPool` | `common/mem_pool.h` | runtime, action | Deduplicated string storage |
| `TypedValue` | `common/type.h` | runtime, action, cli, tests | Tagged union of Wasm values |
| `RunMode` | `common/defines.h` | runtime, cli, vm-interface | Execution mode selector |
| `InputFormat` | `common/defines.h` | runtime, cli, vm-interface | Input bytecode format |
| `EVMU256Type` | `common/type.h` | evm, compiler, host, tests | 256-bit unsigned integer (EVM stack word) |

### Defined in runtime (used by 5+ modules)

| Type | Definition | Used By | Description |
|------|-----------|---------|-------------|
| `Runtime` | `runtime/runtime.h` | action, evm, cli, vm-interface | Central execution coordinator |
| `Module` | `runtime/module.h` | action, compiler, singlepass | Wasm module representation |
| `EVMModule` | `runtime/evm_module.h` | action, evm, compiler, vm-interface | EVM module with JIT support |
| `Instance` | `runtime/instance.h` | action, host, singlepass | Per-execution state |
| `EVMInstance` | `runtime/evm_instance.h` | evm, action, host | EVM execution instance |
| `Isolation` | `runtime/isolation.h` | runtime, vm-interface | Sandboxed execution environment |
| `RuntimeConfig` | `runtime/runtime.h` | cli, vm-interface | Runtime configuration options |
| `CodeHolder` | `runtime/code_holder.h` | compiler, singlepass | JIT compiled code storage |

### Defined in evm (used by 3+ modules)

| Type | Definition | Used By | Description |
|------|-----------|---------|-------------|
| `EVMBytecodeCache` | `evm/bytecode_cache.h` | evm, action, compiler | Cached jump/gas/push analysis |
| `EVMFrame` | `evm/interpreter.h` | evm, action | EVM execution frame |
| `InterpreterExecContext` | `evm/interpreter.h` | evm, action | Interpreter execution context |

### External Dependencies (evmc)

| Type | Source | Used By | Description |
|------|--------|---------|-------------|
| `evmc_vm` | `evmc/evmc.h` | vm-interface | VM instance handle |
| `evmc_host_interface` | `evmc/evmc.h` | vm-interface, host, evm | Host callback table |
| `evmc_message` | `evmc/evmc.h` | vm-interface, evm, cli | Transaction/call parameters |
| `evmc_result` | `evmc/evmc.h` | vm-interface, evm | Execution result |
| `evmc_revision` | `evmc/evmc.h` | evm, compiler, vm-interface | EVM protocol revision |

## EVM Execution Pipeline Type Flow

```
vm-interface: evmc_message, evmc_host_interface
    -> runtime: EVMModule, EVMInstance, Isolation
        -> action: EVMModuleLoader, EVMByteCodeVisitor
            -> evm: EVMBytecodeCache, EVMFrame, InterpreterExecContext
            -> compiler: EVMFrontendContext, MModule, CompileContext
```

## Detailed References

- Compiler type system: [docs/compiler/type.md](../../docs/compiler/type.md)
- Memory management: [docs/common/memory_management.md](../../docs/common/memory_management.md)
