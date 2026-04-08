# compiler Module Specification

> Directory: `src/compiler/`

## Boundaries and Responsibilities

The compiler module is responsible for DTVM's multi-pass JIT compilation pipeline, compiling **WASM** or **EVM** bytecode into x86-64 machine code.

### Scope

- **WASM frontend**: Translate WASM bytecode to dMIR (`wasm_frontend/`, `frontend/`)
- **EVM frontend**: Translate EVM bytecode to dMIR (`evm_frontend/`, `evm_compiler.*`)
- **dMIR layer**: Intermediate representation (`mir/`), supporting constants, variables, basic blocks, instructions (including EVM-specific instructions such as `EvmUmul128Instruction`)
- **CgIR layer**: Code-generation-oriented IR (`cgir/`), containing basic blocks, instructions, registers
- **MIR→CgIR lowering**: `target/x86/x86lowering*.cpp`, `cgir/lowering.h`
- **Register allocation**: FastRA (`fast_ra`) and Greedy RA (`reg_alloc_greedy`)
- **x86 backend**: Machine code generation (`target/x86/x86_mc_lowering.cpp`, `x86_mc_inst_lower.*`), ELF output
- **EVM JIT suitability analysis**: Detect RA-expensive patterns before compilation, decide whether to fall back to interpreter

### Out of Scope

- Interpreter execution (provided by `evm/`, `runtime/`)
- Singlepass JIT (located in `src/singlepass/`)
- Module loading, instance creation (provided by `runtime/`)

---

## Core Concepts

### Multi-pass Compilation Pipeline

1. **Frontend→dMIR**: `WasmMirBuilder` / `EVMMirBuilder` translate source/bytecode to `MModule` + `MFunction` (dMIR)
2. **dMIR optimization**: `DeadMBasicBlockElim`, `MVerifier`
3. **dMIR→CgIR**: `X86CgLowering`, `X86CgPeephole`
4. **Register allocation**: `FastRA` or `CgRAGreedy` + `CgRegisterCoalescer`, `CgVirtRegMap`, `CgLiveIntervals`, etc.
5. **Post-RA processing**: `PrologEpilogInserter`, `ExpandPostRAPseudos`
6. **Machine code emission**: `X86MCLowering` → ELF `.text` section
7. **Linking and memory protection**: `emitObjectBuffer`, `mprotect`

### Frontend Context

- **WasmFrontendContext**: WASM module reference, thread context
- **EVMFrontendContext**: EVM bytecode, Gas metering toggle, Gas chunk metadata, `evmc_revision`

### Compilation Entry Points

- **EagerJITCompiler**: WASM full compilation
- **LazyJITCompiler**: WASM on-demand compilation (multi-threaded)
- **EagerEVMJITCompiler**: EVM full compilation (Multipass only)
- **MIRTextJITCompiler**: Compile from MIR text (testing/debugging)

---

## External Contracts

### Upstream Dependencies

| Module | Usage |
|------|------|
| `runtime/` | `Module`, `Instance`, `EVMModule`, `CodeEntry`, `CodeMemPool` |
| `action/` | `vm_eval_stack`, `vm_eval_stack.h` (EVM stack) |
| `evm/`, `evmc/` | EVM semantics, instruction table, `evmc_opcode` |
| `common/` | `ErrorCode`, `WASMType`, `MemPool`, `ThreadPool` |
| `platform/` | `mprotect`, memory allocation |
| `utils/` | `Statistics`, `JitDumpWriter` (perf integration) |
| LLVM | `TargetMachine`, `MCContext`, `TargetInstrInfo`, `TargetRegisterInfo` |

### Downstream Consumers

| Module | Invocation |
|------|----------|
| `action/` | `performMultipassJITCompile` / `performEVMJITCompile` calls `EagerJITCompiler::compile()` / `EagerEVMJITCompiler::compile()` |
| `vm/` | Indirectly via the action layer |

---

## Invariants and Permissions

### Compilation Context Invariants

- When `CompileContext::Inited == true`, `MemPool`, `CodePtr`, `FuncOffsetMap`, etc. are in a valid state
- `EVMFrontendContext` must have `Bytecode`, `BytecodeSize`, `GasMeteringEnabled`, `GasChunkInfo` (if chunk metering is enabled) set before `compile()`

### dMIR Invariants

- `MBasicBlock`s in `MFunction` are connected by control flow; `MInstruction`s belong to an `MBasicBlock` or are embedded as expressions in another `MInstruction`
- `MVerifier` must pass before entering CgIR lowering

### EVM JIT Invariants

- Only Multipass mode is supported; Singlepass does not provide EVM JIT
- JIT suitability analysis should be performed before compilation; if it does not pass, fall back to interpreter

---

## Error Codes

From `common/errors.h`, used by the compiler module:

| Error Code | Description |
|--------|------|
| `MIRVerifyingFailed` | dMIR verification failed |
| `ObjectFileCreationFailed` | ELF object file creation failed |
| `UnexpectedObjectFileFormat` | Not ELF format |
| `ObjectFileResolvingFailed` | Cannot resolve .text section or relocations |
| `NoMatchedInstruction` | No matching target instruction |
| `MmapFailed` | JIT code memory allocation failed |

---

## Compatibility Strategy

### EVM JIT and Multipass-only

- **Multipass-only EVM JIT**: EVM bytecode is compiled only in Multipass JIT mode; if run mode is Singlepass, report an error and reject EVM JIT
- **Lazy not supported**: EVM currently supports Eager compilation only; warn and skip when Lazy is requested

### JIT Suitability Analysis

`EVMAnalyzer::analyze()` must be run before compilation to detect the following patterns and decide whether to fall back to interpreter:

| Threshold | Description |
|------|------|
| `MAX_JIT_BYTECODE_SIZE` (0x6000) | Bytecode size exceeds limit |
| `MAX_JIT_MIR_ESTIMATE` (50000) | Linear MIR estimate exceeds limit |
| `MAX_CONSECUTIVE_RA_EXPENSIVE` (128) | Consecutive RA-expensive opcodes exceed limit |
| `MAX_BLOCK_RA_EXPENSIVE` (256) | RA-expensive count in a single basic block exceeds limit |
| `MAX_DUP_FEEDBACK_PATTERN` (64) | DUPn + RA-expensive pattern exceeds limit |

**RA-expensive opcode classification**: SHL (0x1b), SHR (0x1c), SAR (0x1d), MUL (0x02), SIGNEXTEND (0x0b).

### EVM Frontend Context and Gas

- Enable/disable Gas metering based on runtime config (`setGasMeteringEnabled`)
- Provide bytecode, gas chunk end/cost arrays for chunk-based metering
- Use register to hold gas when `ZEN_ENABLE_EVM_GAS_REGISTER` is enabled

### Machine Code and Module Binding

- Machine code is written to `EVMModule::getJITCodeMemPool()` or the corresponding `Module` pool
- Entry point is the code pointer corresponding to FuncIdx 0
- Code section is protected via `mprotect(JITCode, size, PROT_READ | PROT_EXEC)`

### JIT Statistics and perf

- Compilation start/end times are recorded in `utils::StatisticPhase::JITCompilation`
- When `ZEN_ENABLE_LINUX_PERF` is enabled, perf JIT dump symbols (e.g., `EVMBB*`) are emitted for generated blocks

---

## Cross-References

| Dependency | Description |
|------|------|
| [evm](../evm/) | EVM semantics, instruction table, evmc_opcode |
| [runtime](../runtime/) | Module, EVMModule, CodeMemPool, Instance |
| [action](../action/) | performMultipassJITCompile, performEVMJITCompile, vm_eval_stack |
| [common](../common/) | ErrorCode, WASMType, MemPool, ThreadPool |
| [platform](../platform/) | mprotect, memory allocation |
| [utils](../utils/) | Statistics, JitDumpWriter |

| Depended by | Description |
|--------|------|
| action | performJITCompile, performEVMJITCompile invocations |
| vm-interface | EVMAnalyzer, JIT fallback decisions |

- [EVM JIT spec (archived)](../../_archive/2026-02/add-jit-suitability-checker/specs/evm-jit/spec.md): EVM JIT requirements (Multipass-only, suitability analysis, RA-expensive classification)
