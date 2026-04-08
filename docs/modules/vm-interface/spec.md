# vm-interface Module Specification

> Directory: `src/vm/` + `evmc/`

## Boundaries and Responsibilities

The vm-interface module implements DTVM's **EVMC shared library interface** (dtvmapi.so), responsible for:

- **EVMC ABI compatibility**: Implements EVMC ABI 12 `evmc_vm` interface; exports VM creation via `evmc_create_dtvmapi()`
- **EVM capability declaration**: Returns `EVMC_CAPABILITY_EVM1` from `get_capabilities()`; full EVM1 semantics
- **Runtime mode configuration**: `set_option()` for `mode` (interpreter/multipass) and `enable_gas_metering` (true/false)
- **Host interface bridging**: `WrappedHost` bridges C-style `evmc_host_interface` and `evmc_host_context` to C++ `evmc::Host` for execution engine
- **Module cache and isolation**: L1 cache by address (code_address + revision), top-level instance reuse, Managed Isolation lifecycle
- **Cross-platform deployment**: Static link libstdc++ and libgcc; symbol hiding (`-fvisibility=hidden`); minimal runtime deps

This module does not include: EVM bytecode compilation (compiler), interpreter/JIT implementation (evm/runtime), Host business logic (host).

## Core Concepts

### 1. EVMC ABI Compatibility

- VM instance created via `evmc_create_dtvmapi()`, returns `evmc_vm *` with `abi_version`, `name` ("dtvm"), `version` (PROJECT_VERSION) and full function pointers: `destroy`, `execute`, `get_capabilities`, `set_option`
- When client calls `evmc_vm::destroy()`, system must release all resources (cached modules, managed isolation, WrappedHost); no leaks

### 2. EVM Execution Capability

- `get_capabilities()` returns `EVMC_CAPABILITY_EVM1`; full EVM1 semantics
- `execute()` receives `evmc_host_interface`, `evmc_host_context`, `evmc_revision`, `evmc_message`, bytecode (Code/CodeSize); returns `evmc_result`
- Before execution, `WrappedHost::reinitialize()` injects Host interface and context; all Host calls (account, storage, call, logs, etc.) delegated via WrappedHost to client

### 3. Runtime Mode Configuration

- **mode**: `"interpreter"` → `RunMode::InterpMode`; `"multipass"` → `RunMode::MultipassMode`
- **enable_gas_metering**: `"true"` → MIR-level Gas metering; `"false"` → disabled
- Unknown option name → `EVMC_SET_OPTION_INVALID_NAME`; invalid value → `EVMC_SET_OPTION_INVALID_VALUE`

### 4. WrappedHost Bridging

- `WrappedHost` extends `evmc::Host`; holds polymorphic `evmc_host_interface *` and `evmc_host_context *`
- Constructor accepts `nullptr`; can reinit via `reinitialize(interface, context)` before each `execute()`
- All `evmc::Host` virtual methods (account_exists, get_storage, set_storage, get_balance, copy_code, call, get_tx_context, get_block_hash, emit_log, access_account, access_storage, get_transient_storage, set_transient_storage, selfdestruct) forward to C interface

### 5. Module Cache Strategy

- **L1 address cache**: Key `CodeAddrRevKey{code_address, revision}`; value `EVMModule *`
- **Validation**: `validateCodeMatch()` checks cached module Code against input Code (first/last 256 bytes) to avoid address reuse pollution
- **Eviction**: On validation failure, unload old module, erase cache entry, cold-load new module
- L0 pointer cache disabled (unsafe with address reuse); L0 state only for eviction consistency

### 6. Instance Reuse and Nested Calls

- **Top-level (depth == 0)**: Reuse `CachedInst`; destroy and recreate if module changes; interpreter mode also reuses `CachedCtx` (InterpreterExecContext)
- **Nested (depth > 0)**: Create temporary `EVMInstance` per call; `InstanceGuard` RAII calls `deleteEVMInstance` on exit
- `HostContextScope` saves/restores Host context at `execute()` entry/exit; exception safe

### 7. Managed Isolation and Resource Management

- `Runtime::createManagedIsolation()` creates managed isolation; `Runtime::deleteManagedIsolation()` destroys
- On DTVM destruct: first destroy `CachedInst`; unload all EVMModule per `AddrCache`; then `deleteManagedIsolation(Iso)`
- `InstanceGuard` ensures nested temporary instances freed on exception path

### 8. JIT Fallback (Optional)

- With `ZEN_ENABLE_JIT_PRECOMPILE_FALLBACK`, for bytecode unsuited to JIT (per `EVMAnalyzer`), use `ScopedConfig` to temporarily switch to interpreter

## External Contracts

| Dependent Module | Contract |
|------------------|----------|
| runtime | `Runtime::newEVMRuntime()`, `loadEVMModule()`, `unloadEVMModule()`, `createManagedIsolation()`, `deleteManagedIsolation()`; `Isolation::createEVMInstance()`, `deleteEVMInstance()`; `callEVMMain()` |
| evm | `InterpreterExecContext`, `BaseInterpreter` for interpreter fast path |
| common | `RunMode`, `InputFormat`, `RuntimeConfig` |
| compiler | `EVMAnalyzer` (JIT fallback optional) |
| evmc (library) | `evmc.h`, `evmc.hpp`, `utils.h`, `helpers.h`: `evmc_vm`, `evmc_host_interface`, `evmc_host_context`, `evmc_message`, `evmc_result`, `evmc_revision`, `evmc_set_option_result`, etc. |

## Invariants and Permissions

- **Determinism**: Same input produces same `evmc_result`; no host-dependent non-determinism
- **Exception safety**: `HostContextScope`, `InstanceGuard` guarantee Host context restore and temporary instance release on exception
- **Cache consistency**: Code of modules in `AddrCache` must match bytecode at code_address for key (header/tail check)
- **Single-thread**: EVMInstance does not support concurrent execution (aligned with runtime/evm)

## Error Codes

| Error Code / Return | Source | Description |
|---------------------|--------|-------------|
| EVMC_FAILURE | evmc_result | Module load, instance creation, or execution failure |
| EVMC_SUCCESS | evmc_result | Success |
| EVMC_SET_OPTION_SUCCESS | set_option | Option set success |
| EVMC_SET_OPTION_INVALID_NAME | set_option | Unknown option name |
| EVMC_SET_OPTION_INVALID_VALUE | set_option | Invalid option value |
| EVMC_CAPABILITY_EVM1 | get_capabilities | EVM1 capability |

## Compatibility Strategy

- **EVMC ABI**: Follow EVMC ABI 12; compatible with common EVM clients (e.g. Geth, Erigon)
- **Cross-platform**: Static link C++ stdlib and libgcc via `-static-libstdc++`, `-static-libgcc` to reduce libstdc++ version dependency
- **Symbol export**: `EVMC_EXPORT` for `evmc_create_dtvmapi`; other symbols hidden; `-Wl,--exclude-libs,ALL` for static libs

## Cross-References

| Dependency | Description |
|------------|-------------|
| [runtime](../runtime/spec.md) | EVM module and instance lifecycle, managed isolation, callEVMMain |
| [evm](../evm/spec.md) | InterpreterExecContext, BaseInterpreter interpreter path |
| [common](../common/spec.md) | RunMode, InputFormat, RuntimeConfig |
| [compiler](../compiler/spec.md) | EVMAnalyzer, JIT fallback decision |

| Depended By | Description |
|-------------|-------------|
| rust-bindings | Indirect VM execution entry via zetaengine C library |
| External EVM clients | dtvmapi.so, evmc_create_dtvmapi() |
