# host Module Specification

> Directory: `src/host/` + `src/wni/`

## Boundaries and Responsibilities

The host module implements DTVM's **host environment interface**, bridging Wasm/EVM execution with the external world, including:

- **WASI (wasi_snapshot_preview1)**: System-call interface compatible with wasi-libc: file descriptors, paths, clocks, environment variables, process, random, sockets, etc.
- **env**: Base environment API (abort, and conditionally compiled libc built-ins or Mock Chain test stubs)
- **spectest**: Wasm spec test helper; debug output (`print`, `print_i32`, `print_f32`, etc.) and `call_wasm` invocation
- **evmabimock**: EVM ABI-compatible mock host; simulates on-chain environment (storage, call, block, transaction, crypto, etc.) for Wasm-EVM adapter tests
- **evm/crypto**: EVM crypto; Keccak-256 hash for EVM precompiled contracts
- **wni**: WNI (Wasm Native Interface) infrastructure; macros, type extraction, boilerplate generation for host modules

This module does not include: runtime instance management, JIT compilation, evmc Host implementation (evmc directory), VM entry.

## Core Concepts

### 1. WNI Host Module Registration

- Submodules define exports via `EXPORT_MODULE_NAME` + `AUTO_GENERATED_FUNCS_DECL` + `FUNCTION_LISTS`
- `wni/helper.h` provides `VALIDATE_APP_ADDR`, `ADDR_APP_TO_NATIVE`, `ADDR_NATIVE_TO_APP`, `FuncTypeExtracter`, `ExtractNativeFuncType`
- `wni/boilerplate.cpp` included to generate `loadNativeModule`, `unloadNativeModule`, and `BuiltinModuleDesc MODULE_DESC_NAME`
- Reserved functions `vnmi_init_ctx`, `vnmi_destroy_ctx` called by runtime at instantiation for module-level context create/destroy

### 2. WASI Implementation

- Based on Wasmtime’s sandboxed-system-primitives (SSP); types and functions from `wasmtime_ssp.h`
- `WASIContext` holds `fd_table`, `fd_prestats`, `argv_environ_values`, `VNMIEnv*` as shared WASI state
- WASI functions receive app addresses in Wasm linear memory; validated with `VALIDATE_APP_ADDR` and converted with `ADDR_APP_TO_NATIVE` before access
- Memory via `vmenv->allocMem()` / `vmenv->freeMem()` using runtime allocator

### 3. env Module Variants

- `ZEN_ENABLE_BUILTIN_LIBC`: libc.inc.cpp implementations of `strlen`, `puts`, `printf`, `memcpy`, etc.
- `ZEN_ENABLE_MOCK_CHAIN_TEST`: mock_chain.inc.cpp stubs for JIT compilation tests
- `ZEN_ENABLE_ASSEMBLYSCRIPT_TEST`: abort takes (a,b,c,d) four parameters
- `ZEN_ENABLE_BUILTIN_LIBC` or mock: abort takes single code parameter

### 4. spectest Module

- No context; `vnmi_init_ctx` returns `nullptr`
- `print` family: output i32/f32/f64 etc. in fixed format to stdout
- `call_wasm`: calls Wasm function at given index via `instance->getRuntime()->callWasmFunction()`

### 5. EVM ABI Mock

- `EVMAbiMockContext` holds current contract code (with 4-byte big-endian length prefix) and storage map (key hex => value bytes32)
- Associated with `Instance` via `instance->setCustomData()` / `instance->getCustomData()`
- All blockchain APIs (getAddress, getBlockHash, storageStore, etc.) return mock data; sub-contract call/create fails

### 6. EVM Crypto

- `CryptoInterface` defines pure virtual interface for `keccak256`
- `CryptoHost` implements it with `ethash::keccak256` (from keccak.hpp)
- `CryptoProvider` singleton; `getInstance()` and `setInstance()` for injection

## External Contracts

| Dependent Module | Contract |
|------------------|----------|
| runtime | `Instance` (getWASIContext, getCustomData, getRuntime, setExceptionByHostapi, exit, validatedAppAddr, getNativeMemoryAddr, getMemoryOffset), `VNMIEnv`, `BuiltinModuleDesc`, `NativeFuncDesc` |
| common | `ErrorCode` (EnvAbort, WASIProcRaise, InstanceExit), `getErrorWithExtraMessage`, `TypedValue` |
| utils | `zen::utils::toHex` |
| wasmtime_ssp | `fd_table`, `fd_prestats`, `argv_environ_values`, `__wasi_*` types and `wasmtime_ssp_*` functions |
| ethash | `ethash::keccak256`, `ethash_hash256` |

## Invariants and Permissions

- **Address validation**: All pointers/offsets from Wasm must be validated with `VALIDATE_APP_ADDR(offset, size)` before access
- **Determinism**: WASI/spectest/evmabimock should produce reproducible behavior for same input; random interface (random_get) by SSP implementation
- **Context lifecycle**: Context allocated in `vnmi_init_ctx` must be fully freed in `vnmi_destroy_ctx`
- **EVMAbiMockContext**: With evmabimock, `Instance` must have `EVMAbiMockContext*` set to CustomData before invocation

## Error Codes

| Error Code / Return | Source | Description |
|---------------------|--------|-------------|
| ErrorCode::EnvAbort | env, evmabimock | Host API abnormal termination with extra message |
| ErrorCode::WASIProcRaise | wasi | Set when process receives signal |
| ErrorCode::InstanceExit | wasi, evmabimock | proc_exit or finish causes instance exit |
| wasi_errno_t -1 | wasi | Address validation failure or invalid context |
| __WASI_ESUCCESS (0) | wasi | Success |
| __WASI_EBADF, etc. | wasmtime_ssp | Specific WASI errno; see wasmtime_ssp.h |

## Compatibility Strategy

- **WASI**: Match wasi-libc / WASI snapshot preview1; type definitions and layout from wasi/api.h
- **EVM ABI Mock**: Mocks EVM precompiled and blockchain environment; does not guarantee real-chain behavior; testing only
- **ethash**: Keccak-256 implementation follows Ethereum/Ethash specification

## Cross-References

| Dependency | Description |
|------------|-------------|
| [runtime](../runtime/spec.md) | Instance, VNMIEnv, BuiltinModuleDesc |
| [common](../common/spec.md) | ErrorCode, TypedValue |
| [utils](../utils/spec.md) | toHex |

| Depended By | Description |
|-------------|-------------|
| runtime | HostModule, BuiltinModuleDesc loading |
| evm | evmc::Host account/storage/call interface |
| cli | WASI, env, evmabimock host module assembly |
| tests | evm::crypto::keccak256, precompiled implementation |

- [host data model](./data-model.md)
