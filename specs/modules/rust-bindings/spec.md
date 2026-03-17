# rust-bindings Module Specification

> Directory: `rust_crate/`

## Boundaries and Responsibilities

The rust-bindings module provides DTVM's **Rust FFI bindings and Rust API**, responsible for:

- **C FFI bindings**: Call zetaengine static library (`Zen*` C APIs) via `extern "C"`; bridge from Rust to DTVM C++ core
- **Runtime encapsulation**: Wrap C pointers as Rust types (`ZenRuntime`, `ZenModule`, `ZenInstance`, etc.); manage lifecycle and resource release
- **EVM ABI compatibility layer**: EVM host function interface (`EvmHost` trait) and Rust implementations of 42 EVM host functions for WASM contracts
- **Gas metering**: Gas injection for WASM modules (`GasMeter`); custom rules via `Rules` trait
- **Memory safety**: Safe WASM linear memory access via `MemoryAccessor`, bounds checks, buffer size limit (16MB)

This module does not include: C++ core implementation (in `src/`), EVM bytecode interpreter (in `src/evm/`), external scripts such as `build_cpp_lib.sh` / `copy_deps.sh` used by build script.

## Core Concepts

### 1. FFI and C API Mapping

- **Runtime config**: `ZenRuntimeConfig` / `ZenRuntimeMode` (Interp=0, Singlepass=1, Multipass=2) map to `ZenCreateRuntimeConfig`, `ZenDeleteRuntimeConfig`
- **Runtime and module**: `ZenRuntime` holds `ZenRuntimeExtern*`; `ZenModule` holds `ZenModuleExtern*`; load WASM via `ZenLoadModuleFromFile` / `ZenLoadModuleFromBuffer`
- **Isolation and instance**: `ZenIsolation` holds `ZenIsolationExtern*`; `ZenInstance<T>` holds `ZenInstanceExtern*` and generic context `extra_ctx: T`
- **Host functions**: `ZenHostFuncDesc` describes name, arg types, ret types, C function pointer; `ZenHostModuleDesc` / `ZenHostModule` manage host module registration and loading

### 2. Host Function Registration and Calling Convention

- All host functions must take `*mut ZenInstanceExtern` as first parameter to recover Rust `ZenInstance<T>` from C (stored via `ZenSetInstanceCustomData`)
- `ZenHostFuncDesc` uses `ZenValueType` for `arg_types` / `ret_types`: 0=i32, 1=i64, 2=f32, 3=f64
- `ZenFilterHostFunctions` supports whitelist; only host functions with specified names enabled

### 3. EVM Host Abstraction and Implementation

- **EvmHost trait**: Unified EVM host interface; account, block, transaction, storage, code, contract, control, logs, fees, crypto, math operations
- **Host implementation**: Host functions (e.g. `get_address`, `storage_load`, `call_contract`) delegate via `instance.extra_ctx` to `EvmHost` impl
- **Memory read/write**: Host functions use `MemoryAccessor` for offset validation and read/write; params typically `(i32 offset, i32 length)` for WASM linear memory range

### 4. Gas Metering Flow

- **Rules trait**: Defines `instruction_cost`, `memory_grow_cost`, `call_per_local_cost`
- **ConstantCostRules**: Fixed cost per instruction, per-page memory growth, per-local-variable call
- **GasMeter::transform_default / transform_with_rules**: Parse WASM, inject `__instrumented_use_gas` calls, serialize output
- **validation**: Verify injected Gas correctness via control-flow graph and DFS

### 5. Errors and Exceptions

- **HostFunctionError**: OutOfBounds, InvalidParameter, ContextNotFound, MemoryAccessError, ExecutionError, GasError, StorageError, CallError, CryptoError, ArithmeticError
- **C-layer exception**: On host function failure, set via `ZenSetInstanceExceptionByHostapi(error_code)`; codes from `ZenGetErrCodeEnvAbort`, `ZenGetErrCodeGasLimitExceeded`, `ZenGetErrCodeOutOfBoundsMemory`

## External Contracts

| Dependent | Contract |
|-----------|----------|
| zetaengine | C static library; `Zen*` APIs; built and linked in `build.rs` via `build_cpp_lib.sh`, `copy_deps.sh` |
| utils_lib | C static library; linked with zetaengine |
| asmjit | Assembly JIT library; static link |
| parity-wasm | WASM parse/serialize for Gas injection |
| wat | WAT parsing for tests |
| num-bigint / sha2 / sha3 | EVM math and crypto (addmod, mulmod, expmod, sha256, keccak256) |

## Invariants and Permissions

- **Non-thread-safe**: `ZenRuntime::create_host_module`, `load_host_module`, `merge_host_module` marked `<not thread-safe>`
- **Instance lifecycle**: When `ZenInstance`'s `ptr` is non-null, `ZenIsolation`, `ZenModule`, `ZenRuntime` must live; Drop order: instance → isolation → module → runtime
- **CustomData invariant**: `ZenInstance` CustomData only stores `ZenInstance<T>*`; must not store other objects
- **Buffer size**: `MAX_BUFFER_SIZE = 16MB`; `validate_buffer_size` limits single memory op to prevent DoS

## Error Codes

| Error Code / Category | Source | Description |
|-----------------------|--------|-------------|
| HostFunctionError | evm::error | Host function execution error; function, message, category |
| TransformError | gas_metering::transform | Parse (WASM parse failure), Inject (Gas injection failure), Serialize (serialization failure) |
| C API error | core::extern | Error string via `ZenGetInstanceError`; numeric code via `ZenGetErrCode*` |

## Compatibility Strategy

- **FFI ABI**: Tightly bound to zetaengine C ABI; zetaengine interface changes require `core::extern` and wrapper type updates
- **EVM host function names**: Must match WASM contract imports from `env` (e.g. `getAddress`, `storageStore`, `callContract`)
- **EVM revision**: EvmHost trait and host implementations must stay in sync with DTVM EVM interpreter revisions

## Cross-References

| Module | Relation |
|--------|----------|
| [vm-interface](../vm-interface/spec.md) | Indirect VM execution entry via zetaengine |
| [runtime](../runtime/spec.md) | ZenRuntime maps to C++ Runtime; ZenIsolation to execution isolation |
| [host](../host/spec.md) | EvmHost and host implementations map to Host interface Rust abstraction |
| [evm](../evm/spec.md) | EVM host function semantics aligned with C++ evm module |
