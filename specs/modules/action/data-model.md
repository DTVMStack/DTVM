# action 模块数据模型

## 实体关系图 (Mermaid classDiagram)

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

## 核心实体 (关键字段和方法)

### LoaderCommon

基类，提供字节流读取能力。

| 字段 | 类型 | 说明 |
|-----|------|------|
| Mod | runtime::Module& | 目标模块 |
| Start, End, Ptr | const Byte* | 当前解析区间与游标 |

| 方法 | 说明 |
|-----|------|
| readByte/readBytes | 读取原始字节 |
| readI32/readI64/readU32 | LEB128 整数 |
| readValType/readBlockType/readRefType | WASM 类型 |
| readF32/readF64 | 浮点数 |
| readPlainU32 | 原始 4 字节 |

### ModuleLoader

WASM 模块解析器，继承 LoaderCommon。

| 内部类型 | 说明 |
|---------|------|
| Limits | pair&lt;uint32_t, Optional&lt;uint32_t&gt;&gt; |
| TableType | pair&lt;uint32_t, uint32_t&gt; |
| MemoryType | pair&lt;uint32_t, uint32_t&gt; |
| GlobalType | pair&lt;WASMType, bool&gt; |

| 方法 | 说明 |
|-----|------|
| load | 入口，解析 header 与 body |
| loadModuleHeader/Body | 魔数、版本、各 section |
| loadTypeSection 等 | 各 section 具体解析 |
| resolveImportFunction | 从 Host 模块解析导入函数 |

### FunctionLoader

单函数体验证与元数据提取，继承 LoaderCommon。

| 内部类型 | 说明 |
|---------|------|
| ControlBlockType | Variant&lt;WASMType, const TypeEntry*&gt;，块类型 |
| ControlBlock | 控制块（StackPolymorphic、LabelType、StartPtr、ElsePtr、EndPtr、InitStackSize 等） |

| 字段 | 说明 |
|-----|------|
| FuncIdx, FuncTypeEntry, FuncCodeEntry | 当前函数索引与类型/代码入口 |
| StackSize, MaxStackSize, MaxBlockDepth | 栈与块深度统计 |
| ControlBlocks, ValueTypes | 控制栈与值类型栈 |

| 方法 | 说明 |
|-----|------|
| load | 遍历 opcode，做类型与结构校验 |
| pushBlock/popBlock | 控制块压栈/出栈 |
| popValueType/pushValueType | 值类型栈操作 |
| checkBranch | 校验 br/br_if/br_table 目标 |

### InterpFrame

单解释帧，包含函数、IP、值栈与控制栈指针。

| 字段 | 类型 | 说明 |
|-----|------|------|
| FuncInst | FunctionInstance* | 当前函数实例 |
| Ip | const uint8_t* | 指令指针 |
| ValueBasePtr/ValueStackPtr/ValueBoundary | uint32_t* | 值栈 |
| CtrlBasePtr/CtrlStackPtr/CtrlBoundary | BlockInfo* | 控制栈 |
| LocalPtr | uint32_t* | 局部变量基址 |
| PrevFrame | InterpFrame* | 调用者帧 |

| 方法 | 说明 |
|-----|------|
| valuePeek/valuePush/valuePop/valueGet/valueSet | 值栈访问 |
| blockPush/blockPop | 控制栈操作 |

### InterpStack

解释器物理栈，由 Runtime 分配。

| 字段 | 说明 |
|-----|------|
| TopBoundary, Top, Bottom | 栈边界与当前顶 |

| 方法 | 说明 |
|-----|------|
| push&lt;T&gt;/pop&lt;T&gt; | 类型化压栈/弹栈 |
| top | 返回 Top 指针 |

### InterpreterExecContext

解释执行上下文，持有栈与当前帧。

| 方法 | 说明 |
|-----|------|
| allocFrame | 在栈上分配新帧 |
| freeFrame | 回收帧并回退栈顶 |
| getCurFrame/setCurFrame | 当前帧读写 |

### Instantiator

将 Module 实例化为 Instance。

| 方法 | 说明 |
|-----|------|
| instantiate | 依次实例化全局、函数、表、内存，可选 WASI，执行 start |
| instantiateGlobals/Functions/Tables/Memories | 各子步骤 |
| initMemoryByDataSegments | 数据段初始化 |
| instantiateWasi | WASI 上下文（ZEN_ENABLE_BUILTIN_WASI） |

### VMEvalStack&lt;Operand&gt;

JIT 编译时使用的泛型值栈。

| 方法 | 说明 |
|-----|------|
| push/pop | 压栈/弹栈 |
| peek(Index) | 距栈顶 Index 处的元素 |
| getTop | 栈顶元素 |
| getSize/empty | 大小与空判断 |

### WASMByteCodeVisitor&lt;IRBuilder&gt;

WASM 字节码遍历器，将指令转成 IRBuilder 调用。

| 字段 | 说明 |
|-----|------|
| Builder | IRBuilder 引用 |
| Ctx | CompilerContext 指针 |
| Stack | VMEvalStack&lt;Operand&gt; |
| CurMod, CurFunc | 当前模块与函数代码 |

| 方法 | 说明 |
|-----|------|
| compile | 入口，initFunction + decode + finalizeFunctionBase |
| decode | 主循环，按 opcode 分发到 handle* |
| handleBlock/handleLoop/handleIf/handleCall/handleLoad/... | 各类指令处理 |

### EVMByteCodeVisitor&lt;IRBuilder&gt;

EVM 字节码遍历器（COMPILER 命名空间）。

| 字段 | 说明 |
|-----|------|
| Builder, Ctx | IRBuilder 与 CompilerContext |
| Stack | VMEvalStack&lt;Operand&gt; |
| InDeadCode | 死代码标记 |
| PC | 程序计数器 |

| 方法 | 说明 |
|-----|------|
| compile | initEVM + decode + finalizeEVMBase |
| decode | 主循环，结合 EVMAnalyzer 做基本块与栈高检查 |
| handleBeginBlock/handleEndBlock | 块边界处理 |
| handlePush/handleDup/handleSwap/handleJump/... | 各类 EVM 指令处理 |

## 枚举

| 枚举 | 来源 | 说明 |
|-----|------|------|
| BinaryOperator | interpreter.cpp（内部） | BO_ADD, BO_SUB, BO_MUL, BO_DIV, BO_DIV_S, BO_REM_S/U, BO_AND/OR/XOR, BO_SHL/SHR, BO_ROTL/ROTR, BO_MIN/MAX, BO_COPYSIGN, BC_CLZ/CTZ/POP_COUNT_*, BM_SQRT/FLOOR/CEIL/TRUNC/NEAREST/ABS/NEG 等 |
| LabelType | common | LABEL_BLOCK, LABEL_LOOP, LABEL_IF, LABEL_FUNCTION |
| SectionType | common | SEC_CUSTOM, SEC_TYPE, SEC_IMPORT, SEC_FUNC, SEC_TABLE, SEC_MEMORY, SEC_GLOBAL, SEC_EXPORT, SEC_START, SEC_ELEM, SEC_DATACOUNT, SEC_CODE, SEC_DATA |
| NameSectionType | common | NAMESEC_FUNCTION, NAMESEC_MODULE, NAMESEC_LOCAL 等 |

## DTO / 共享类型

| 类型 | 定义位置 | 说明 |
|-----|----------|------|
| BlockInfo | interpreter.h | 控制块元数据（TargetAddr, ValueStackPtr, CellNum, LabelType） |
| ControlBlock | function_loader.h | FunctionLoader 内部控制块（StackPolymorphic, LabelType, BlockType, StartPtr, ElsePtr, EndPtr, InitStackSize, InitNumValues） |
| ControlBlockType | function_loader.h | 块类型（Variant&lt;WASMType, const TypeEntry*&gt;） |
| CacheValue | interpreter.cpp | BaseInterpreterImpl 内块地址缓存（ElsePtr, EndPtr） |
| Limits | module_loader.cpp | pair&lt;uint32_t, Optional&lt;uint32_t&gt;&gt;（min, max?） |
| TableType / MemoryType / GlobalType | module_loader.h | 类型/大小对 |
