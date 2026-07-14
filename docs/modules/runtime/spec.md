# runtime Module Specification

> Directory: `src/runtime/` + `src/entrypoint/`

## Boundaries and Responsibilities

The runtime module is DTVM's **core runtime**, responsible for:

1. **Runtime lifecycle**: Create, initialize, and clean up singleton Runtime
2. **Module management**: Load, merge, and unload WASM modules (Module), EVM modules (EVMModule), and host modules (HostModule)
3. **Instance lifecycle**: Create and manage WASM Instance and EVMInstance through Isolation
4. **Memory**: WASM linear memory allocator (WasmMemoryAllocator); malloc, single mmap, bucket mmap backends
5. **Isolation domain**: Instance isolation; manages instance pool and WNI environment
6. **VNMI / WNI interfaces**: VNMIEnv (native module interface) and WNIEnv (WASM native interface) for host functions and native modules
7. **JIT call bridging**: entrypoint provides `callNative` assembly stubs for call boundary between JIT code and host/instance

## Core Concepts

### Runtime

- **Creation**: `Runtime::newRuntime(Config)` / `Runtime::newEVMRuntime(Config, EVMHost)` (when ZEN_ENABLE_EVM)
- **Responsibilities**: Symbol pool, memory pool, module pool, Isolation pool, WASI environment (optional)
- **Thread safety**: Most methods marked `not thread-safe`; `createManagedIsolation` / `deleteManagedIsolation` guarded by `Mtx`

### Module and Instance

- **Module**: Parsed WASM bytecode; type table, import/export table, code segment, data segment, JIT metadata
- **HostModule**: Native host module; described by `BuiltinModuleDesc`; load/unload functions via VNMI
- **EVMModule**: EVM bytecode module; Code, CodeSize, evmc::Host, diagnostic
  module name/codehash identity, JIT code (optional)
- **EVM codehash cache**: Runtime-owned in-process cache that maps EVM
  runtime bytecode identity and JIT-relevant config to an `EVMModule`, allowing
  compile-once/execute-many benchmark flows to reuse analyzer results,
  bytecode cache, fallback decision, and JIT code without changing the existing
  filename-based module pool.
- **Instance**: Instantiated Module; function table, tables, memory, globals, etc.
- **EVMInstance**: EVM-specific instance; EVM stack, memory, message stack, execution cache, etc.

### Isolation

- **Managed**: `createManagedIsolation` / `deleteManagedIsolation`; lifecycle owned by Runtime
- **Unmanaged**: `createUnmanagedIsolation`; caller must ensure lifecycle subset of Runtime
- **Instance pools**: `InstancePool`, `EVMInstancePool`; Isolation owns instances

### Memory

- **WasmMemoryAllocator**: Per module/thread-local; supports:
  - `WM_MEMORY_DATA_TYPE_MALLOC`: Ordinary heap allocation
  - `WM_MEMORY_DATA_TYPE_SINGLE_MMAP`: Single mmap block (for CPU trap memory checks)
  - `WM_MEMORY_DATA_TYPE_BUCKET_MMAP`: Multi-copy bucket mmap (shared init data, faster instance creation)

### VNMI / WNI

- **VNMIEnv**: Runtime interface for host modules (HostModule); `allocMem`, `freeMem`, `newSymbol`, `freeSymbol`
- **WNIEnv**: Interface for native modules inside WASM instance; address conversion (`getNativeAddr` / `getAppAddr`), user context (`getUserDefinedCtx`), exception throw, etc.

### Entrypoint

- **callNative**: Assembly JIT call stub:
  - Save/restore callee-saved registers
  - Layout parameters by ABI (FP regs, GPRs, stack params)
  - Set Instance `JITStackBoundary`, `GlobalVarData`, `Memories`, etc. (Singlepass JIT)
- **Platforms**: x86_64 (`callNative_x86_64.S`), aarch64 (`callNative_aarch64.S`)
- **Helpers**: `rollbackWasmVirtualStack`, `startWasmFuncStack` (virtual stack)

## External Contracts

### Dependencies

- **common**: `Error`, `ErrorCode`, `TypedValue`, `WASMType`, `ConstStringPool`, `SysMemPool`
- **action**: `Interpreter`, `ModuleLoader`, `HostModuleLoader`, `FunctionLoader`, `Instantiator`, `performJITCompile`
- **platform**: `mapFile`, `unmapFile`, memory-related
- **evm** (optional): `evm::DEFAULT_REVISION`, `evm::Interpreter`, EVM execution logic
- **evmc** (optional): `evmc::Host`, `evmc::Result`, `evmc_message`

### Depended By

- **action**: Loading, instantiation, JIT compilation
- **host**: WASI, spectest host modules; VNMIEnv
- **compiler**: Multipass JIT uses Module JIT metadata, Instance layout
- **evm**: EVM interpreter and JIT use EVMInstance, EVMModule

## Invariants and Permissions

1. **Instance and Runtime**: Instance must be used within Runtime lifetime; Isolation lifetime must be subset of Runtime
2. **Module and Instance**: Instance holds read-only Module reference; before unloading Module, ensure no live Instance references
3. **Memory**: `WasmMemoryAllocator` is not thread-safe; each thread gets its own allocator via `ThreadLocalMemAllocatorMap`
4. **JIT calls**: `callNative` entry must satisfy ABI; `callNative` / `callNative_end` used for JIT stack unwinding
5. **Symbols**: `newSymbol` / `freeSymbol` not thread-safe; symbols released by `RuntimeObjectDestroyer` when unloading Module

## Error Codes

runtime propagates errors via `common::Error` / `common::ErrorCode`; common runtime-related:

- `InvalidFilePath`, `InvalidRawData`, `FileAccessFailed`: Load failures
- `OutOfBoundsMemory`, `CallStackExhausted`: Execution memory/stack overflow
- `GasLimitExceeded`: Gas exhausted
- `InstanceExit`: Instance exit via `Instance::exit`
- EVM: `EVMStackOverflow`, `EVMStackUnderflow`, `EVMBadJumpDestination`, `EVMInvalidInstruction`, `EVMStaticModeViolation`, etc.

## Compatibility Strategy

1. **Config**: `RuntimeConfig` controls RunMode (Interp / Singlepass / Multipass), WASI, statistics, JIT thread count; changes require `validate()`
2. **Compile options**: Behavior controlled by `ZEN_ENABLE_EVM`, `ZEN_ENABLE_JIT`, `ZEN_ENABLE_SINGLEPASS_JIT`, `ZEN_ENABLE_MULTIPASS_JIT`, `ZEN_ENABLE_BUILTIN_WASI`, `ZEN_ENABLE_CPU_EXCEPTION`, `ZEN_ENABLE_VIRTUAL_STACK`, `ZEN_ENABLE_DWASM`, etc.
3. **ABI**: entrypoint assembly depends on `Instance`, `MemoryInstance` layout; layout changes require offset updates in assembly
4. **Statistics coverage**: EVM replay timing may include bytecode source read/decode, module-load diagnostics, top-level EVM execution timing, JIT/interpreter execution bodies, and coarse host account/storage/call diagnostics in addition to JIT compilation, instantiation, and CLI-scoped phases. Nested EVM CALL/CREATE re-entry does not add separate top-level `Execution` records, but diagnostic host-call and module-create phases may include nested work.
5. **EVM diagnostic identity**: EVMModule records the loader-provided module
   name and bytecode keccak256 codehash for diagnostics such as
   `JIT_MODULE_PROFILE`. These fields are observational only and must not drive
   execution semantics or fallback decisions.
6. **EVM codehash cache scope**: `getOrCompileCachedEVMModule()` is
   Runtime-local and not thread-safe. Its key includes bytecode Keccak-256,
   code size, EVM revision, run mode, JIT-relevant config flags, and memory
   specialization profile. Cached modules are owned until Runtime teardown and
   are not removed by `unloadEVMModule()`, which continues to operate on the
   filename/module-name pool. Lookup metadata reports hit/miss, codehash,
   bytecode size, cache entry count, fallback-to-interpreter state, whether the
   cached module has native JIT code, and JIT code size when available.
7. **EVM nested call reuse**: Mocked EVM host internal CALL module lookup uses
   the Runtime codehash cache before storing the per-transaction local module
   pointer. This keeps account/state isolation unchanged while allowing nested
   calls to reuse compiled code across transactions in the same Runtime.

## Cross-References

| Dependency | Description |
|------------|-------------|
| [common](../common/) | Error codes and Error type |
| [action](../action/) | Loading, instantiation, JIT trigger |
| [evm](../evm/) | EVM execution and cache |
| [platform](../platform/) | Memory mapping and platform abstraction |
| [compiler](../compiler/) | Multipass JIT and EVM JIT |

| Depended By | Description |
|-------------|-------------|
| action | Loading, instantiation, JIT orchestration |
| host | HostModule, VNMIEnv, BuiltinModuleDesc |
| compiler | Module, Instance, EVMModule, CodeMemPool |
| evm | EVMInstance, EVMModule |
| cli | Runtime, Module, Instance, Isolation, HostModule |
| vm-interface | EVMModule, EVMInstance, managed isolation, callEVMMain |
| tests | Execution environment and instances |
