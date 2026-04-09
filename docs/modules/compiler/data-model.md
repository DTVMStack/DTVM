# compiler Module Data Model

## Entity Relationship Diagram (Mermaid classDiagram)

```mermaid
classDiagram
    direction TB

    subgraph Compilation Context
        CompileContext
        WasmFrontendContext
        EVMFrontendContext
        ContextObject
    end

    subgraph dMIR
        MModule
        MFunction
        MFunctionType
        MBasicBlock
        MInstruction
        Variable
        MType
        MConstantInt
        MConstantFloat
    end

    subgraph CgIR
        CgFunction
        CgBasicBlock
        CgInstruction
        CgOperand
        CgRegisterInfo
    end

    subgraph EVM Frontend
        EVMAnalyzer
        EVMMirBuilder
        JITSuitabilityResult
    end

    subgraph JIT Compiler
        JITCompilerBase
        WasmJITCompiler
        EagerJITCompiler
        LazyJITCompiler
        EVMJITCompiler
        EagerEVMJITCompiler
    end

    CompileContext <|-- WasmFrontendContext
    CompileContext <|-- EVMFrontendContext
    ContextObject <|-- MModule
    ContextObject <|-- MFunction
    ContextObject <|-- MBasicBlock

    MModule "1" --> "*" MFunction : contains
    MModule "1" --> "*" MFunctionType : FuncTypes
    MFunction "1" --> "*" MBasicBlock : BasicBlocks
    MFunction "1" --> "*" Variable : Variables
    MFunction "1" --> "1" MFunctionType : FuncType
    MBasicBlock "1" --> "*" MInstruction : Instructions
    MInstruction --> "*" MInstruction : Operands
    MInstruction --> "1" MType : Type
    Variable --> "1" MType : Type

    CompileContext "1" --> "1" CgFunction : builds
    MFunction "1" --> "1" CgFunction : corresponds to
    CgFunction "1" --> "*" CgBasicBlock : CgBasicBlocks
    CgBasicBlock "1" --> "*" CgInstruction : CgInstructions
    CgInstruction --> "*" CgOperand : Operands

    EVMAnalyzer --> JITSuitabilityResult : analyze()
    EVMFrontendContext --> EVMMirBuilder : buildEVMFunction()
    EVMMirBuilder --> MFunction : compile()

    JITCompilerBase <|-- WasmJITCompiler
    JITCompilerBase <|-- MIRTextJITCompiler
    WasmJITCompiler <|-- EagerJITCompiler
    WasmJITCompiler <|-- LazyJITCompiler
    JITCompilerBase <|-- EVMJITCompiler
    EVMJITCompiler <|-- EagerEVMJITCompiler
```

---

## Core Entities (Key Fields and Methods)

### Compilation Context

| Entity | Key Fields | Key Methods |
|------|----------|----------|
| **CompileContext** | `MemPool`, `ThreadMemPool`, `CodeMPool`, `FuncTypeSet`, `PtrTypeSet`, `IntConstants`, `FPConstants`, `CodePtr`, `CodeSize`, `FuncOffsetMap`, `ExternRelocs`, `MCCtx`, `MCL` | `initialize()`, `finalize()`, `reinitialize()`, `getMCLowering()`, `getOrCreateFuncMCSymbol()` |
| **WasmFrontendContext** | Extends `CompileContext`, references `runtime::Module` | Used for WASM frontend |
| **EVMFrontendContext** | `Bytecode`, `BytecodeSize`, `GasMeteringEnabled`, `GasChunkEnd`, `GasChunkCost`, `GasChunkSize`, `Revision`, `GasRegisterEnabled` | `setBytecode()`, `setGasMeteringEnabled()`, `setGasChunkInfo()`, `setRevision()`, `getMIRTypeFromEVMType()` |

### dMIR Layer

| Entity | Key Fields | Key Methods |
|------|----------|----------|
| **MModule** | `FuncTypes`, `Functions` | `addFuncType()`, `getFuncType()`, `addFunction()`, `getFunction()`, `getNumFunctions()` |
| **MFunction** | `FuncIdx`, `FuncType`, `Variables`, `BasicBlocks`, `Instructions`, `ExceptionSetBBs` | `createBasicBlock()`, `appendBlock()`, `createVariable()`, `createInstruction()`, `getGasRegisterVarIdx()` (EVM) |
| **MFunctionType** | `RetType`, `ParamTypes` (via `getSubTypes()`) | `getNumParams()`, `param_begin()`, `param_end()`, `getReturnType()` |
| **MBasicBlock** | `Idx`, `Instructions`, `Successors` | `addSuccessor()`, `getIdx()` |
| **MInstruction** | `_opcode`, `_kind`, `_type`, `_operand_num`, `_parent` (BB or parent instruction) | `getOpcode()`, `getKind()`, `getType()`, `getOperand()`, `setOperand()`, `isStatement()`, `isTerminator()` |
| **Variable** | `VarIdx`, `Type` | `getVarIdx()`, `getType()` |
| **MType** | Static `I8`, `I16`, `I32`, `I64`, `F32`, `F64`, `VOID` | - |

### CgIR Layer

| Entity | Key Fields | Key Methods |
|------|----------|----------|
| **CgFunction** | `MIRFunc`, `CgBasicBlocks`, `RegInfo`, `EvictAdvisor` | `createCgBasicBlock()`, `appendCgBasicBlock()`, `createCgInstruction()`, `getRegInfo()` |
| **CgBasicBlock** | `CgInstructions`, `Successors` | `addSuccessor()`, `getIdx()` |
| **CgInstruction** | Machine instruction opcode, operand list | `getOpcode()`, `getOperand()` |
| **CgOperand** | `createRegOperand()`, `createImmOperand()`, `createMemOperand()` | - |

### EVM Frontend

| Entity | Key Fields | Key Methods |
|------|----------|----------|
| **EVMAnalyzer** | `BlockInfos`, `JITResult`, `Revision` | `analyze()`, `getBlockInfos()`, `getJITSuitability()` |
| **EVMMirBuilder** | `Ctx`, `CurFunc`, `CurBB`, `InstanceAddr`, `JumpDestTable`, `JumpDestBodyTable`, `GasRegVar` | `compile()`, `loadEVMInstanceAttr()`, `meterOpcode()`, `handlePush()`, `handleMul()`, `handleShift()`, etc. |
| **EVMMirBuilder::Operand** | `Instr`, `Var`, `Type`, `U256Components`, `U256VarComponents`, `ConstValue`, `IsConstant`, `IsU256MultiComponent` | `getInstr()`, `getVar()`, `getType()`, `getU256Components()`, `isU256MultiComponent()` |

### JIT Compiler

| Entity | Key Fields | Key Methods |
|------|----------|----------|
| **JITCompilerBase** | - | `compileMIRToCgIR()`, `emitObjectBuffer()` |
| **WasmJITCompiler** | `WasmMod`, `NumInternalFunctions`, `Config`, `Stats` | `compileWasmToMC()` |
| **EagerJITCompiler** | - | `compile()` |
| **LazyJITCompiler** | `StubBuilder`, `MainContext`, `Mod`, `CompileStatuses`, `GreedyRACodePtrs`, `ThreadPool` | `compile()`, `dispatchCompileTask()`, `compileFunction()`, `compileFunctionOnRequest()` |
| **EVMJITCompiler** | `EVMMod`, `Config`, `Stats` | `compileEVMToMC()` |
| **EagerEVMJITCompiler** | - | `compile()` |

---

## Enumerations

### EVMType (EVM Frontend Types)

| Value | Description |
|----|------|
| `VOID` | No value |
| `UINT8` | Byte |
| `UINT32` | Intermediate value |
| `UINT64` | Gas calculation |
| `UINT256` | Primary 256-bit integer |
| `BYTES32` | 32-byte fixed array |
| `ADDRESS` | 20-byte address |
| `BYTES` | Dynamic byte array |

### MInstruction::Kind

| Value | Description |
|----|------|
| `CONSTANT` | Constant |
| `UNARY` | Unary operation |
| `BINARY` | Binary operation |
| `ADC` | Add with carry |
| `CMP` | Compare |
| `CONVERSION` | Type conversion |
| `SELECT` | Select |
| `DREAD` | Read variable |
| `LOAD` | Load |
| `OVERFLOW_I128_BINARY` | WASM overflow binary |
| `EVM_UMUL128` | EVM 128-bit unsigned multiply |
| `EVM_UMUL128_HI` | EVM 128-bit multiply high |
| `DASSIGN` | Assignment |
| `STORE` | Store |
| `BR` | Unconditional branch |
| `BR_IF` | Conditional branch |
| `SWITCH` | Switch |
| `RETURN` | Return |
| `WASM_CHECK` | WASM check |
| `CALL` | Call |

### LazyJITCompiler::CompileStatus

| Value | Description |
|----|------|
| `None` | Not compiled |
| `Pending` | Pending compilation |
| `InProgress` | Compiling |
| `Done` | Completed |

---

## DTO / Shared Types

### JITSuitabilityResult

```cpp
struct JITSuitabilityResult {
  bool ShouldFallback = false;
  size_t BytecodeSize = 0;
  size_t MirEstimate = 0;
  size_t RAExpensiveCount = 0;
  size_t MaxConsecutiveExpensive = 0;
  size_t MaxBlockExpensiveCount = 0;
  size_t DupFeedbackPatternCount = 0;
};
```

### EVMAnalyzer::BlockInfo

```cpp
struct BlockInfo {
  uint64_t EntryPC = 0;
  int32_t MaxStackHeight = 0;
  int32_t MinStackHeight = 0;
  int32_t MinPopHeight = 0;
  int32_t StackHeightDiff = 0;
  bool IsJumpDest = false;
  bool HasUndefinedInstr = false;
  uint32_t RAExpensiveCount = 0;
};
```

### CompileContext::ExternRelocations

```cpp
struct ExternRelocations {
  uint64_t Offset;
  int64_t Addend;
  uint32_t CalleeFuncIdx;
};
```

### FunctionTypeKeyInfo / PointerTypeKeyInfo

Used for `DenseSet` deduplication of `MFunctionType`, `MPointerType` key and hash.

### EVMMirBuilder::U256Value / U256Inst / U256Var / U256ConstInt

- `U256Value`: `std::array<uint64_t, 4>`, little-endian [low, mid-low, mid-high, high]
- `U256Inst`: `std::array<MInstruction*, 4>`
- `U256Var`: `std::array<Variable*, 4>`
- `U256ConstInt`: `std::array<MConstantInt*, 4>`

### Type Aliases (common_defs.h)

| Alias | Definition |
|------|------|
| `VariableIdx` | `uint32_t` |
| `OperandNum` | `uint16_t` |
| `BlockNum` | `uint32_t` |
| `CompileMemPool` | `MonotonicMemPool` |
| `CompileVector` | `std::vector<T, CompileAllocator<T>>` |
| `CompileUnorderedMap` | `std::unordered_map<... CompileAllocator<...>>` |

### RA-expensive Threshold Constants (evm_analyzer.h)

| Constant | Value |
|------|-----|
| `MAX_JIT_BYTECODE_SIZE` | 0x6000 |
| `MAX_JIT_MIR_ESTIMATE` | 0x50000 |
| `MAX_CONSECUTIVE_RA_EXPENSIVE` | 0x3000 |
| `MAX_BLOCK_RA_EXPENSIVE` | 0x3000 |
| `MAX_DUP_FEEDBACK_PATTERN` | 0x3000 |
