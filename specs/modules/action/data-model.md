# action Module Data Model

## Entity Relationship Diagram (Mermaid classDiagram)

```mermaid
classDiagram
    class LoaderCommon {
        #runtime::Module Mod
        #const Byte* Start
        #const Byte* End
        #const Byte* Ptr
        +readByte() Byte
        +readBytes(size_t) Bytes
        +readI32() int32_t
        +readI64() int64_t
        +readU32() uint32_t
        +readValType() WASMType
        +readBlockType() WASMType
    }

    class ModuleLoader {
        +load() void
        -loadModuleHeader() void
        -loadModuleBody() void
        -loadSection() void
        -readName() WASMSymbol
        -readLimits() Limits
        -resolveImportFunction() const void*
    }

    class HostModuleLoader {
        -runtime::HostModule Mod
        +load() void
    }

    class FunctionLoader {
        +load() void
        -pushBlock() void
        -popBlock() void
        -popValueType() WASMType
        -pushValueType() void
        -checkBranch() ControlBlock
    }

    class EVMModuleLoader {
        -runtime::EVMModule Mod
        -const Byte* Data
        -size_t ModuleSize
        +load() void
    }

    class InterpFrame {
        +FunctionInstance* FuncInst
        +const uint8_t* Ip
        +uint32_t* ValueBasePtr
        +uint32_t* ValueStackPtr
        +BlockInfo* CtrlStackPtr
        +uint32_t* LocalPtr
        +InterpFrame* PrevFrame
        +valuePeek() T
        +valuePush() void
        +valuePop() T
        +blockPush() void
        +blockPop() void
    }

    class BlockInfo {
        +const uint8_t* TargetAddr
        +uint32_t* ValueStackPtr
        +uint32_t CellNum
        +LabelType LabelType
    }

    class InterpStack {
        +uint8_t* TopBoundary
        +uint8_t* Top
        +uint8_t* Bottom
        +push() void
        +pop() T
        +top() uint8_t*
    }

    class InterpreterExecContext {
        -Instance* ModInst
        -InterpStack* Stack
        -InterpFrame* CurFrame
        +allocFrame() InterpFrame*
        +freeFrame() void
        +getCurFrame() InterpFrame*
        +getInterpStack() InterpStack*
        +getInstance() Instance*
    }

    class BaseInterpreter {
        -InterpreterExecContext Context
        +interpret() void
    }

    class Instantiator {
        +instantiate() void
        -instantiateGlobals() void
        -instantiateFunctions() void
        -instantiateTables() void
        -instantiateMemories() void
        -initMemoryByDataSegments() void
    }

    class VMEvalStack {
        +push() void
        +pop() Operand
        +peek() Operand
        +getTop() Operand
        +getSize() uint32_t
        +empty() bool
    }

    class WASMByteCodeVisitor {
        +compile() bool
        -decode() bool
    }

    class EVMByteCodeVisitor {
        +compile() bool
        -decode() bool
    }

    LoaderCommon <|-- ModuleLoader
    LoaderCommon <|-- FunctionLoader
    InterpStack --* InterpreterExecContext
    InterpFrame --* InterpreterExecContext
    BlockInfo --o InterpFrame
    BaseInterpreter --> InterpreterExecContext
    ModuleLoader --> runtime::Module
    FunctionLoader --> runtime::CodeEntry
    EVMModuleLoader --> runtime::EVMModule
    Instantiator --> runtime::Instance
    WASMByteCodeVisitor --> VMEvalStack
    EVMByteCodeVisitor --> VMEvalStack
```

## Core Entities (Key Fields and Methods)

### LoaderCommon

Base class providing byte stream reading capability.

| Field | Type | Description |
|-----|------|------|
| Mod | runtime::Module& | Target module |
| Start, End, Ptr | const Byte* | Current parsing range and cursor |

| Method | Description |
|-----|------|
| readByte/readBytes | Read raw bytes |
| readI32/readI64/readU32 | LEB128 integers |
| readValType/readBlockType/readRefType | WASM types |
| readF32/readF64 | Floating-point numbers |
| readPlainU32 | Raw 4 bytes |

### ModuleLoader

WASM module parser, inherits LoaderCommon.

| Internal Type | Description |
|---------|------|
| Limits | pair&lt;uint32_t, Optional&lt;uint32_t&gt;&gt; |
| TableType | pair&lt;uint32_t, uint32_t&gt; |
| MemoryType | pair&lt;uint32_t, uint32_t&gt; |
| GlobalType | pair&lt;WASMType, bool&gt; |

| Method | Description |
|-----|------|
| load | Entry point, parses header and body |
| loadModuleHeader/Body | Magic number, version, sections |
| loadTypeSection etc. | Per-section parsing |
| resolveImportFunction | Resolve import functions from Host module |

### FunctionLoader

Single-function validation and metadata extraction, inherits LoaderCommon.

| Internal Type | Description |
|---------|------|
| ControlBlockType | Variant&lt;WASMType, const TypeEntry*&gt;, block type |
| ControlBlock | Control block (StackPolymorphic, LabelType, StartPtr, ElsePtr, EndPtr, InitStackSize, etc.) |

| Field | Description |
|-----|------|
| FuncIdx, FuncTypeEntry, FuncCodeEntry | Current function index and type/code entries |
| StackSize, MaxStackSize, MaxBlockDepth | Stack and block depth statistics |
| ControlBlocks, ValueTypes | Control stack and value type stack |

| Method | Description |
|-----|------|
| load | Traverse opcodes, perform type and structure validation |
| pushBlock/popBlock | Control block push/pop |
| popValueType/pushValueType | Value type stack operations |
| checkBranch | Validate br/br_if/br_table targets |

### InterpFrame

Single interpretation frame, contains function, IP, value stack and control stack pointers.

| Field | Type | Description |
|-----|------|------|
| FuncInst | FunctionInstance* | Current function instance |
| Ip | const uint8_t* | Instruction pointer |
| ValueBasePtr/ValueStackPtr/ValueBoundary | uint32_t* | Value stack |
| CtrlBasePtr/CtrlStackPtr/CtrlBoundary | BlockInfo* | Control stack |
| LocalPtr | uint32_t* | Local variable base address |
| PrevFrame | InterpFrame* | Caller frame |

| Method | Description |
|-----|------|
| valuePeek/valuePush/valuePop/valueGet/valueSet | Value stack access |
| blockPush/blockPop | Control stack operations |

### InterpStack

Interpreter physical stack, allocated by Runtime.

| Field | Description |
|-----|------|
| TopBoundary, Top, Bottom | Stack boundaries and current top |

| Method | Description |
|-----|------|
| push&lt;T&gt;/pop&lt;T&gt; | Typed push/pop |
| top | Return Top pointer |

### InterpreterExecContext

Interpretation execution context, holds stack and current frame.

| Method | Description |
|-----|------|
| allocFrame | Allocate new frame on stack |
| freeFrame | Reclaim frame and roll back stack top |
| getCurFrame/setCurFrame | Current frame read/write |

### Instantiator

Instantiate Module into Instance.

| Method | Description |
|-----|------|
| instantiate | Sequentially instantiate globals, functions, tables, memory; optional WASI; execute start |
| instantiateGlobals/Functions/Tables/Memories | Sub-steps |
| initMemoryByDataSegments | Data segment initialization |
| instantiateWasi | WASI context (ZEN_ENABLE_BUILTIN_WASI) |

### VMEvalStack&lt;Operand&gt;

Generic value stack used during JIT compilation.

| Method | Description |
|-----|------|
| push/pop | Push/pop |
| peek(Index) | Element at Index from stack top |
| getTop | Top element |
| getSize/empty | Size and empty check |

### WASMByteCodeVisitor&lt;IRBuilder&gt;

WASM bytecode visitor, converts instructions to IRBuilder calls.

| Field | Description |
|-----|------|
| Builder | IRBuilder reference |
| Ctx | CompilerContext pointer |
| Stack | VMEvalStack&lt;Operand&gt; |
| CurMod, CurFunc | Current module and function code |

| Method | Description |
|-----|------|
| compile | Entry, initFunction + decode + finalizeFunctionBase |
| decode | Main loop, dispatch by opcode to handle* |
| handleBlock/handleLoop/handleIf/handleCall/handleLoad/... | Per-instruction handling |

### EVMByteCodeVisitor&lt;IRBuilder&gt;

EVM bytecode visitor (COMPILER namespace).

| Field | Description |
|-----|------|
| Builder, Ctx | IRBuilder and CompilerContext |
| Stack | VMEvalStack&lt;Operand&gt; |
| InDeadCode | Dead code flag |
| PC | Program counter |

| Method | Description |
|-----|------|
| compile | initEVM + decode + finalizeEVMBase |
| decode | Main loop, with EVMAnalyzer for basic block and stack height checks |
| handleBeginBlock/handleEndBlock | Block boundary handling |
| handlePush/handleDup/handleSwap/handleJump/... | Per-EVM-instruction handling |

## Enumerations

| Enum | Source | Description |
|-----|------|------|
| BinaryOperator | interpreter.cpp (internal) | BO_ADD, BO_SUB, BO_MUL, BO_DIV, BO_DIV_S, BO_REM_S/U, BO_AND/OR/XOR, BO_SHL/SHR, BO_ROTL/ROTR, BO_MIN/MAX, BO_COPYSIGN, BC_CLZ/CTZ/POP_COUNT_*, BM_SQRT/FLOOR/CEIL/TRUNC/NEAREST/ABS/NEG, etc. |
| LabelType | common | LABEL_BLOCK, LABEL_LOOP, LABEL_IF, LABEL_FUNCTION |
| SectionType | common | SEC_CUSTOM, SEC_TYPE, SEC_IMPORT, SEC_FUNC, SEC_TABLE, SEC_MEMORY, SEC_GLOBAL, SEC_EXPORT, SEC_START, SEC_ELEM, SEC_DATACOUNT, SEC_CODE, SEC_DATA |
| NameSectionType | common | NAMESEC_FUNCTION, NAMESEC_MODULE, NAMESEC_LOCAL, etc. |

## DTO / Shared Types

| Type | Definition Location | Description |
|-----|----------|------|
| BlockInfo | interpreter.h | Control block metadata (TargetAddr, ValueStackPtr, CellNum, LabelType) |
| ControlBlock | function_loader.h | FunctionLoader internal control block (StackPolymorphic, LabelType, BlockType, StartPtr, ElsePtr, EndPtr, InitStackSize, InitNumValues) |
| ControlBlockType | function_loader.h | Block type (Variant&lt;WASMType, const TypeEntry*&gt;) |
| CacheValue | interpreter.cpp | BaseInterpreterImpl block address cache (ElsePtr, EndPtr) |
| Limits | module_loader.cpp | pair&lt;uint32_t, Optional&lt;uint32_t&gt;&gt; (min, max?) |
| TableType / MemoryType / GlobalType | module_loader.h | Type/size pair |

