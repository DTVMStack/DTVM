# action Module Specification

> Directory: `src/action/`

## Boundaries and Responsibilities

The action module is responsible for DTVM's **module loading**, **WASM interpretation execution**, **JIT orchestration entry**, and **bytecode traversal**; it is the hub connecting frontend bytecode with backend execution.

### Scope of Responsibilities

| Subdomain | Responsibility | Main Files |
|-----------|----------------|------------|
| WASM module loading | Parse WASM binary format, populate `runtime::Module` | `module_loader.h/cpp`, `function_loader.h/cpp` |
| Host module loading | Populate `runtime::HostModule` from C API or dynamically loaded functions | `module_loader.h/cpp` |
| EVM module loading | Copy EVM bytecode to `runtime::EVMModule` | `evm_module_loader.h` |
| WASM interpreter | Interpret WASM bytecode instruction-by-instruction, execute stack-based VM | `interpreter.h/cpp` |
| Instantiation | Create Instance from Module (globals, functions, tables, memory) | `instantiator.h/cpp` |
| JIT entry | Dispatch by run mode to Singlepass/Multipass/EVM JIT | `compiler.h/cpp` |
| WASM bytecode traversal | Decode WASM instructions and invoke `IRBuilder` to generate IR | `bytecode_visitor.h` |
| EVM bytecode traversal | Decode EVM instructions and invoke `IRBuilder` to generate IR | `evm_bytecode_visitor.h` |
| Arithmetic Hook | Parse checked arithmetic imports and hook to Module | `hook.h` |

### Responsibilities Outside This Module

- **compiler/**: dMIR generation, register allocation, machine code emission
- **runtime/**: Module / Instance data structures, memory allocation
- **evmc/**: EVM execution semantics, Host interface implementation

## Core Concepts

### 1. Module Loading Pipeline

```
WASM binary ──► ModuleLoader ──► runtime::Module
                                    │
                    FunctionLoader ──┴──► CodeEntry (per function)
Host module   ──► HostModuleLoader ──► runtime::HostModule

EVM bytecode ──► EVMModuleLoader ──► runtime::EVMModule
```

- **ModuleLoader**: Inherits from `LoaderCommon`, parses Type/Import/Func/Table/Memory/Global/Export/Start/Elem/DataCount/Code/Data sections in WASM specification order.
- **FunctionLoader**: Performs control-flow verification and stack type checking for each function body; computes `MaxStackSize`, `MaxBlockDepth`.
- **EVMModuleLoader**: Copies raw EVM bytecode by length; supports empty bytecode (retains non-null code pointer).

### 2. Interpretation Execution Model

- **InterpStack**: Interpreter value stack (`Bottom`/`Top`/`TopBoundary`), holds locals, frames, control stack, and value stack.
- **InterpFrame**: Single frame contains `FunctionInstance`, `Ip`, value stack pointer, control stack pointer, local pointer; supports `valuePeek`/`valuePush`/`valuePop`/`blockPush`/`blockPop`.
- **BaseInterpreter**: Main interpretation loop, driven by `InterpreterExecContext`; distinguishes Native/ByteCode calls via `callFuncInst`.
- **BlockInfo**: Control structure info (`TargetAddr`, `ValueStackPtr`, `CellNum`, `LabelType`).

### 3. Instantiation Flow

**Instantiator::instantiate** order:

1. `instantiateGlobals`: Copy import/internal globals, initialize per `InitExpr`.
2. `instantiateFunctions`: Fill `FunctionInstance` (Native uses FuncPtr, ByteCode uses CodePtr).
3. `instantiateTables`: Set table size and initialize element segment.
4. `instantiateMemories`: Allocate linear memory and run data segment initialization.
5. (Optional) `instantiateWasi`: If WASI is enabled, initialize WASI context.
6. If `StartFuncIdx` exists, execute start function.

### 4. JIT Orchestration

- **performJITCompile(runtime::Module &)**: Dispatch by `RunMode` to Singlepass or Multipass JIT; supports Lazy/Eager modes.
- **performEVMJITCompile(runtime::EVMModule &)** (`ZEN_ENABLE_EVM`): Multipass EVM JIT only; singlepass not supported.

### 5. Bytecode Visitors

- **WASMByteCodeVisitor&lt;IRBuilder&gt;**: Traverses WASM function body, invokes IRBuilder `handle*` for each opcode; supports macro fusion (Compare+If, Compare+BrIf, Compare+Select).
- **EVMByteCodeVisitor&lt;IRBuilder&gt;** (`COMPILER` namespace, defined in `action/`): Uses `EVMAnalyzer` for basic block analysis, handles JUMPDEST, dead code, stack-height checks; calls `handleUndefined` or fallback for undefined opcodes.

## External Contracts

### Dependent Modules

| Dependency | Use |
|------------|-----|
| `common` | `ErrorCode`, `WASMType`, `SectionType`, arithmetic/type utilities |
| `runtime` | `Module`, `Instance`, `HostModule`, `EVMModule`, `FunctionInstance`, etc. |
| `utils` | `readLEBNumber`, `validateUTF8String`, `addOverflow`, etc. |
| `entrypoint` | `callNativeGeneral` (Native calls) |
| `singlepass` (optional) | `JITCompiler::compile` |
| `compiler` (optional) | `EagerJITCompiler`, `EagerEVMJITCompiler`, `EVMAnalyzer`, `evm_mir_compiler` |

### Provided Interfaces

- `HostModuleLoader::load()`
- `ModuleLoader::load()`
- `EVMModuleLoader::load()` (`ZEN_ENABLE_EVM`)
- `FunctionLoader::load()`
- `Instantiator::instantiate(Instance &)`
- `performJITCompile(Module &)`, `performEVMJITCompile(EVMModule &)` (`ZEN_ENABLE_EVM`)
- `BaseInterpreter::interpret()`
- `WASMByteCodeVisitor::compile()`, `EVMByteCodeVisitor::compile()` (templates, used by compiler)
- `resolveCheckedArithmeticFunction()` (`ZEN_ENABLE_CHECKED_ARITHMETIC`)

## Invariants and Permissions

### Loading Phase

- `LoaderCommon`'s `Ptr` must not exceed `End`; out-of-bounds throws `UnexpectedEnd`.
- Sections must increase by `SectionOrder`; otherwise `JunkAfterLastSection`.
- Name section must follow Data section.
- `NumInternalFunctions` must equal `NumCodeSegments`; otherwise `FuncCodeInconsistent`.

### Interpretation Execution

- `InterpStack`'s `Top` must not exceed `TopBoundary`.
- Frame allocation failure (stack overflow) returns `nullptr`; caller throws `CallStackExhausted`.
- Under `ZEN_ENABLE_DWASM`, stack usage exceeding `PresetReservedStackSize` throws `DWasmCallStackExceed`.

### Instantiation

- Table/memory/global counts limited by Preset constants; excess throws `TooMany*`.
- Element/data segment offset and size must not be out of bounds; otherwise `ElementsSegmentDoesNotFit` / `DataSegmentDoesNotFit`.

## Error Codes

`common::ErrorCode` used by action module mainly from `Load`, `Instantiation`, `Execution` phases:

| Phase | Error Code Examples |
|-------|---------------------|
| Load | `MagicNotDetected`, `UnknownBinaryVersion`, `UnexpectedEnd`, `TooLongName`, `InvalidUTF8Encoding`, `UnknownTypeIdx`, `UnknownFunction`, `IncompatibleImportType`, `TypeMismatch*`, `FuncCodeInconsistent`, `SectionSizeTooLarge`, `ModuleSizeTooLarge`, `UnsupportedOpcode`, `InvalidRawData`, etc. |
| Instantiation | `DataSegmentDoesNotFit`, `ElementsSegmentDoesNotFit`, `MemorySizeTooLarge`, `DWasmModuleFormatInvalid` |
| Execution | `IntegerOverflow`, `IntegerDivByZero`, `OutOfBoundsMemory`, `InvalidConversionToInteger`, `CallStackExhausted`, `IndirectCallTypeMismatch`, `UndefinedElement`, `Unreachable`, `UninitializedElement`, `GasLimitExceeded`, `EVMStackOverflow`, `EVMStackUnderflow`, `DWasmCallStackExceed` |

## Compatibility Strategy

- **WASM version**: Follow module magic and version fields; only accept `WasmVersion`-matching version.
- **EVM version**: Align `EVMAnalyzer::getRevision()` with EVMC instruction set; undefined opcodes handled by IRBuilder (fallback/interpreter).
- **Optional features**:
  - `ZEN_ENABLE_SPEC_TEST`: table/memory/global imports and `spectest` patch.
  - `ZEN_ENABLE_EVM`: `EVMModuleLoader`, `EVMByteCodeVisitor`, `performEVMJITCompile`.
  - `ZEN_ENABLE_CHECKED_ARITHMETIC`: `resolveCheckedArithmeticFunction` and arithmetic Hook.
  - `ZEN_ENABLE_BUILTIN_WASI`: `instantiateWasi`.
  - `ZEN_ENABLE_DWASM`: block depth, local count, opcode count limits and stack cost calculation.

## Cross-References

| Dependency | Description |
|------------|-------------|
| [compiler](../compiler/spec.md) | JIT implementation, IRBuilder, EVM frontend |
| [runtime](../runtime/spec.md) | Module, Instance, HostModule, EVMModule |
| [evm](../evm/spec.md) | EVM execution and Host interface |
| [common](../../../src/common/errors.def) | ErrorCode, WASMType, SectionType, etc. |

| Depended By | Description |
|-------------|-------------|
| runtime | Loading, instantiation, JIT orchestration |
| compiler | performJITCompile, performEVMJITCompile |
| singlepass | WASMByteCodeVisitor |
| evm | EVMModuleLoader |
