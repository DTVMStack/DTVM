# singlepass Module Specification

> Directory: `src/singlepass/`

## Boundaries and Responsibilities

The singlepass module is DTVM's **single-pass JIT compiler**; responsibilities:

1. **Input**: Takes loaded WASM module (`runtime::Module`); compiles **internal functions** only (no imports)
2. **Output**: Generates directly executable native code in module's `JITCodeMemPool`; writes `CodeEntry::JITCodePtr` for each function entry
3. **Scope**: WASM only; no EVM/dMIR; uses AsmJit; x64 and AArch64 backends
4. **Compilation**: Single pass over WASM bytecode; driven by `action::WASMByteCodeVisitor`; generates while traversing; no intermediate IR
5. **Out of scope**: Module loading, verification, interpretation, EVM execution; handled by `runtime`, `compiler`, `evm`, etc.

## Core Concepts

### Compilation Pipeline

1. **Init**: `OnePassCompiler::initModule()` inits DataLayout, CodePatcher, ABI
2. **Per-function compilation**: For each internal function, create `asmjit::CodeHolder`; generate via `WASMByteCodeVisitor` + platform CodeGen (e.g. `X64OnePassCodeGenImpl`)
3. **Flatten and relocate**: For each function, `Holder.flatten()`, `Holder.resolveUnresolvedLinks()`
4. **Memory allocation**: Allocate executable buffer from `Mod->getJITCodeMemPool()`; copy and redirect in function order
5. **Code patching**: `CodePatcher::finalizeModule()` patches in-module `call` instructions (same-module calls)
6. **Execute permission**: After `mprotect(JITCode, CodeSize, PROT_READ | PROT_EXEC)`, set module JIT code and size

### Architecture Abstraction

- **OnePassCompiler\<Impl\>**: Template-driven; `Impl` provides `OnePassABI`, `OnePassDataLayout`, `CodePatcher`, `OnePassCodeGenImpl`
- **x64**: `X86OnePassCompiler`; AMD64 SysV ABI; fixed regs (e.g. r15=instance, r14=global, r13=memory_base, r12=memory_size, rbx=gas)
- **a64**: `A64OnePassCompiler`; AArch64 ABI; corresponding regs (e.g. x28=instance, x27=global, x26=memory_base, x25=memory_size, x22=gas)

### Stack and Data Layout

- **Globals**: Laid out per Module import/internal order; accessed via `global_base + offset`
- **Locals**: Params prefer ABI param regs; overflow and locals on stack; DataLayout assigns stack frame offsets
- **Temporary space**: Scoped temp regs (short-lived) vs Temp regs (across bytecode); stack temps from `getTempStackOperand`

### Exceptions and Traps

- **WASM traps**: Handled by software checks or CPU exception (`ZEN_ENABLE_CPU_EXCEPTION`)
- **Exception labels**: `CurFuncState.ExceptLabels` maps `ErrorCode` to `asmjit::Label`; `ExceptionExitLabel` for return to interpreter/parent frame
- **Stack overflow**: Prolog checks `JITStackBoundary` (or dWASM `StackCost`); overflow triggers `CallStackExhausted`

## External Contracts

### Dependent Modules

| Module | Use |
|--------|-----|
| `runtime` | `Module`, `Instance`, `CodeEntry`, `TypeEntry`, `MemoryInstance`, `TableInstance` |
| `action` | `WASMByteCodeVisitor`; traverses WASM bytecode and calls CodeGen |
| `common` | `ErrorCode`, `WASMType`, `BinaryOperator`, `CompareOperator`, `UnaryOperator`, type utilities |
| `platform` | `mprotect` for executable memory |
| `utils` | `Statistics`, `JitDumpWriter` (optional) |

### Instance Layout Assumptions

Module validates `Instance` key member offsets with `ZEN_STATIC_ASSERT`:

- `GlobalVarData` = 0x40
- `Memories` = 0x50
- `MemoryInstance::MemBase` = 0x10
- `MemoryInstance::MemSize` = 0x08
- `JITStackSize` = 0x68
- `JITStackBoundary` = 0x70

Update these assertions when changing `Instance` layout.

### Calling Convention

- First parameter is always `Instance*` (module instance pointer)
- Other params follow platform ABI (x64: SysV; a64: AArch64); integers and floats use corresponding param regs or stack

## Invariants and Permissions

### Compile-Time Invariants

- `NumInternalFunctions > 0`
- Each `CodeEntry` and `TypeEntry` non-null
- `CodeHolder` must have `flatten` and `resolveUnresolvedLinks` done before `compile()` returns
- Internal `call` targets known at `finalizeModule`; patch offset and target within `INT32_MAX`

### Runtime Assumptions

- JIT code pages already `mprotect`ed to `PROT_READ | PROT_EXEC`
- Before JIT call, `Instance`'s `Memories`, `Tables`, `JITFuncPtrs`, etc. correctly initialized
- Gas: `Instance::Gas` valid before call; JIT maintains via `loadGasVal`/`saveGasVal` and `subGasVal`

### Register Usage Convention

- **Fixed**: instance, global_base, memory_base, memory_size, gas, call_target assigned by ABI
- **Callee-saved**: Save in prolog, restore in epilog (x64 e.g. rbx, r12–r15)
- **Scoped / Temp**: Tracked by MachineState; avoid clobber across calls

## Error Codes

| Error Code | Meaning | Trigger |
|------------|---------|---------|
| `AsmJitFailed` | AsmJit emission failure | `OnePassErrorHandler::handleError` |
| `MmapFailed` | JIT code memory allocation failed | `CodeMemPool.allocate` returns null |
| `CallStackExhausted` | Stack overflow | Prolog stack boundary check |
| `OutOfBoundsMemory` | Memory out of bounds | load/store in software memory-check mode |
| `UndefinedElement` | Table out of bounds | call_indirect table index check |
| `UninitializedElement` | Table entry uninitialized | call_indirect entry is -1 |
| `IndirectCallTypeMismatch` | Indirect call type mismatch | call_indirect type check |
| `IntegerOverflow` | Integer overflow | checked arithmetic, div-by-zero paths |
| `IntegerDivByZero` | Integer division by zero | idiv/rem divisor 0 |
| `InvalidConversionToInteger` | Invalid float to integer | NaN or out of range |
| `GasLimitExceeded` | Gas exhausted | `handleGasCall` check |
| `Unreachable` | Unreachable instruction | `handleUnreachableImpl` |

## Compatibility Strategy

### Build Options

- **`ZEN_BUILD_TARGET_X86_64`**: x64 backend
- **`ZEN_BUILD_TARGET_AARCH64`**: AArch64 backend
- **`ZEN_ENABLE_SINGLEPASS_JIT`**: Enable singlepass JIT (CMake)
- **`ZEN_ENABLE_SINGLEPASS_JIT_LOGGING`**: AsmJit debug logs
- **`ZEN_ENABLE_CPU_EXCEPTION`**: CPU exception for WASM traps
- **`ZEN_ENABLE_DWASM`**: dWASM extensions (StackCost, InHostAPI)
- **`ZEN_ENABLE_STACK_CHECK_CPU`**: CPU-based stack overflow check (guard page pre-access)
- **`ZEN_ENABLE_LINUX_PERF`**: Generate perf JIT map

### Platform Differences

- x64: Uses LZCNT/TZCNT/POPCNT; software fallback if missing (e.g. BSR+cmov, SWAR popcount)
- AArch64: Similar structure; ABI and reg allocation implemented separately

### Relation to Multipass

- singlepass and multipass (LLVM) are mutually exclusive; at most one used per module
- Chosen by build and runtime config; module interface (`JITCodePtr`, calling convention) stays consistent

## Cross-References

| Dependency | Description |
|------------|-------------|
| [compiler](../compiler/spec.md) | Compiler overview |
| [runtime](../runtime/spec.md) | Module, Instance, CodeEntry, TypeEntry |
| [action](../action/spec.md) | WASMByteCodeVisitor |
| [common](../common/spec.md) | ErrorCode, WASMType, operators |
| [platform](../platform/spec.md) | mprotect |
| [utils](../utils/spec.md) | Statistics, JitDumpWriter |

| Depended By | Description |
|-------------|-------------|
| action | performJITCompile, WASMByteCodeVisitor driver |

- Data model: `specs/modules/singlepass/data-model.md`
- Build: `docs/start.md` (`ZEN_ENABLE_SINGLEPASS_JIT`)
