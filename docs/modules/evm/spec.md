# evm Module Specification

> Directory: `src/evm/`

## Boundaries and Responsibilities

The evm module implements DTVM's **EVM interpreter core**, responsible for:

- **Opcode handling**: Dispatch and execute EVM opcodes per revision (evmc_revision) based on EVMC instruction table
- **Gas calculation**: Base Gas metering, memory expansion, storage read/write, EIP-2929 cold/warm access Gas rules
- **Bytecode cache construction**: Build JumpDestMap, PushValueMap, GasChunkEnd/GasChunkCost for interpreter fast path and chunked Gas metering
- **EVM constants and revisions**: Stack depth, memory limits, contract size limits, Gas constants, default revision, etc.

This module does not include: module loading (runtime), JIT compilation (compiler), Host interface implementation (host), VM entry (vm-interface).

## Core Concepts

### 1. EVM Module Loading and Bytecode Storage

- Bytecode held by `EVMModule` (runtime module); evm module only obtains `Code`, `CodeSize`, and `getBytecodeCache()` via `const EVMModule *`
- Module loading and persistence handled by runtime/action; evm has no file I/O

### 2. Bytecode Cache Construction

- `buildBytecodeCache()` called before first interpretation or JIT execution (`EVMModule::getBytecodeCache()` lazy init)
- **JumpDestMap**: PC-indexed; marks valid JUMPDEST (excludes PUSH data region)
- **PushValueMap**: PC-indexed; stores PUSHn immediates (big-endian, zero-padded)
- **GasChunkEnd / GasChunkCost**: SPP (Structured Precharging Pass) chunked Gas metering; pre-charge straight-line Gas; block boundaries at JUMPDEST, control-flow terminators, SSTORE, CALL/CREATE, etc.

### 3. Interpretation Context and Stack Safety

- **EVMFrame**: Single-frame execution state; Stack (1024 slots), Memory, CallData, evmc_message, evmc_tx_context, PC, Sp, Value, GasRefundSnapshot
- **InterpreterExecContext**: Multi-frame management (FrameStack), execution status, return data, evmc::Result
- **BaseInterpreter**: Main loop; gets current frame from `Context.getCurFrame()` and executes
- Stack ops `push()`/`pop()`/`peek()` throw `EVMStackOverflow`/`EVMStackUnderflow` on overflow/underflow (common::ErrorCode)
- `MAXSTACK = 1024`, aligned with EVM spec

### 4. Instance-Level Gas Metering and Memory Expansion

- Gas deducted from `Frame->Msg.gas`; set `EVMC_OUT_OF_GAS` on failure
- Memory expansion formula: `cost = (new_words²/512 + 3*new_words) - (current_words²/512 + 3*current_words)`; bounded by `MAX_REQUIRED_MEMORY_SIZE` (16MB)
- Storage (SSTORE) uses `SSTORE_COSTS[Rev][Status]` by revision and storage status; Gas refund aggregated at `EVMInstance` level

### 5. Message Stack and Return Data Handling

- Call/create ops initiate subcalls via `Frame->Host->call()`; return data written to `InterpreterExecContext::ReturnData`
- RETURN/REVERT copy specified range from `Frame->Memory` into return data and `freeBackFrame()` back to parent frame
- STOP or execution beyond CodeSize clears ReturnData and ends

### 6. Opcode Semantics by Revision

- Opcode availability via `evmc_get_instruction_names_table(Revision)`; undefined yields `EVMC_UNDEFINED_INSTRUCTION`
- Gas table from `evmc_get_instruction_metrics_table(Revision)`
- Special rules examples: PUSH0 only Shanghai+; EXP EXP_BYTE_GAS 10 before Spurious Dragon; EIP-2929 cold/warm account/storage; EIP-3860 initcode size limit, etc.

### 7. JIT Fallback Support

- `InterpreterExecContext::restoreStateFromInstance()` restores stack, memory, PC from `EVMInstance` for fallback to interpreter when JIT hits exception
- Ensures interpreter and JIT share same execution semantics and Gas rules

## External Contracts

| Dependent Module | Contract |
|------------------|----------|
| runtime | `EVMInstance`, `EVMModule` provide execution context, module, bytecode cache; `clearReturnDataBuffer()` clears return data |
| action | `EVMModuleLoader` loads bytecode; `performEVMJITCompile` orchestrates JIT compilation (not this module) |
| host | `evmc::Host` provides account, storage, call, logs, crypto, etc. |
| common | `Byte`, `ErrorCode` (EVMStackOverflow, EVMStackUnderflow, EVMFrameNotFound, etc.), `getError()` |
| evmc | `evmc_message`, `evmc_tx_context`, `evmc_revision`, `evmc_instruction_metrics`, `evmc_opcode` |

## Invariants and Permissions

- **Determinism**: Same inputs (bytecode, message, Host state, Revision) produce same output; no host-dependent non-determinism
- **Stack invariants**: `Sp <= MAXSTACK`; `pop`/`peek` require `Sp > 0` or enough slots
- **PC validity**: JUMP/JUMPI targets must have `Dest < CodeSize` and `JumpDestMap[Dest] == 1`
- **Static mode**: When `Msg.flags & EVMC_STATIC`, forbid SSTORE, LOG, CALL with value, SELFDESTRUCT, TSTORE

## Error Codes

| Error Code | Source | Description |
|------------|--------|-------------|
| EVMC_OUT_OF_GAS | evmc | Insufficient Gas |
| EVMC_STACK_OVERFLOW | evmc | Stack overflow |
| EVMC_STACK_UNDERFLOW | evmc | Stack underflow |
| EVMC_UNDEFINED_INSTRUCTION | evmc | Undefined opcode |
| EVMC_INVALID_INSTRUCTION | evmc | Invalid instruction (0xfe) |
| EVMC_BAD_JUMP_DESTINATION | evmc | Invalid jump target |
| EVMC_INVALID_MEMORY_ACCESS | evmc | RETURNDATACOPY out of bounds, etc. |
| EVMC_STATIC_MODE_VIOLATION | evmc | Storage write in static mode |
| EVMC_REVERT | evmc | REVERT normal termination |
| EVMStackOverflow | common | Stack overflow (throw) |
| EVMStackUnderflow | common | Stack underflow (throw) |
| EVMFrameNotFound | common | EVMFrame is empty |

## Compatibility Strategy

- Default revision: `DEFAULT_REVISION = EVMC_CANCUN`
- Supported revisions from EVMC library (Frontier ~ Experimental); opcodes and Gas table switch by Revision
- New EIPs: update `gas_storage_cost`, `opcode_handlers`, and evmc dependency in sync

## Cross-References

### EVM Execution Chain (Cross-Module)

EVM's full execution flow spans multiple modules:

1. **vm-interface** (`src/vm/`): EVMC `execute()` entry; `execute()` in `dt_evmc_vm.cpp` receives `evmc_message`; find/create `EVMModule` and `EVMInstance`
2. **runtime** (`src/runtime/`): `EVMModule` lifecycle, `EVMInstance` creation, `getBytecodeCache()` lazy build
3. **action** (`src/action/`): `EVMModuleLoader` loads bytecode; `performEVMJITCompile` orchestrates JIT compilation (if enabled)
4. **evm** (`src/evm/`): **BaseInterpreter** interpretation, opcode handling, Gas calculation (**this module**)
5. **compiler** (`src/compiler/`): `evm_frontend` compiles EVM bytecode to dMIR; `evm_compiler.*` orchestrates multi-pass JIT; actual JIT code not in evm module

### EVM JIT and Interpreter Collaboration

- Multi-pass JIT implemented in **compiler** module; evm module has no JIT code generation
- JIT execution can fall back to interpreter via `restoreStateFromInstance()`
- Interpreter and JIT share same `evmc_instruction_metrics` and `SSTORE_COSTS`; ensures cross-mode Gas consistency

| Depended By | Description |
|-------------|-------------|
| vm-interface | InterpreterExecContext, BaseInterpreter interpreter path |
| compiler | EVM semantics, instruction tables, evmc_opcode |
| tests | ZenMockedEVMHost, evmc_revision |
