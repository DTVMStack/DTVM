# action 模块规范

> 目录: `src/action/`

## 边界与职责

action 模块负责 DTVM 的**模块加载**、**WASM 解释执行**、**JIT 编排入口**及**字节码遍历**，是连接前端字节码与后端执行的枢纽。

### 职责范围

| 子域 | 职责 | 主要文件 |
|-----|------|---------|
| WASM 模块加载 | 解析 WASM 二进制格式，填充 `runtime::Module` | `module_loader.h/cpp`, `function_loader.h/cpp` |
| Host 模块加载 | 从 C API 或动态加载函数填充 `runtime::HostModule` | `module_loader.h/cpp` |
| EVM 模块加载 | 将 EVM 字节码拷贝至 `runtime::EVMModule` | `evm_module_loader.h` |
| WASM 解释器 | 逐条解释 WASM 字节码，执行栈式 VM | `interpreter.h/cpp` |
| 实例化 | 从 Module 创建 Instance（全局量、函数、表、内存） | `instantiator.h/cpp` |
| JIT 入口 | 按运行模式分发到 Singlepass/Multipass/EVM JIT | `compiler.h/cpp` |
| WASM 字节码遍历 | 解码 WASM 指令并调用 `IRBuilder` 生成 IR | `bytecode_visitor.h` |
| EVM 字节码遍历 | 解码 EVM 指令并调用 `IRBuilder` 生成 IR | `evm_bytecode_visitor.h` |
| 算术 Hook | 解析 checked arithmetic 导入并挂钩到 Module | `hook.h` |

### 不在本模块的职责

- **compiler/**：dMIR 生成、寄存器分配、机器码发射
- **runtime/**：Module / Instance 数据结构、内存分配
- **evmc/**：EVM 执行语义、Host 接口实现

## 核心概念

### 1. 模块加载链路

```
WASM 二进制 ──► ModuleLoader ──► runtime::Module
                                    │
                    FunctionLoader ──┴──► CodeEntry (每函数)
Host 模块   ──► HostModuleLoader ──► runtime::HostModule

EVM 字节码  ──► EVMModuleLoader ──► runtime::EVMModule
```

- **ModuleLoader**：继承 `LoaderCommon`，按 WASM 规范顺序解析 Type/Import/Func/Table/Memory/Global/Export/Start/Elem/DataCount/Code/Data 等 section。
- **FunctionLoader**：对每个函数体做控制流验证与栈类型校验，计算 `MaxStackSize`、`MaxBlockDepth`。
- **EVMModuleLoader**：将原始 EVM 字节码按长度拷贝，支持空字节码（保留非空 code 指针）。

### 2. 解释执行模型

- **InterpStack**：解释器用值栈（`Bottom`/`Top`/`TopBoundary`），用于存放局部变量、帧、控制栈与值栈。
- **InterpFrame**：单帧包含 `FunctionInstance`、`Ip`、值栈指针、控制栈指针、局部变量指针；支持 `valuePeek`/`valuePush`/`valuePop`/`blockPush`/`blockPop`。
- **BaseInterpreter**：主解释循环，基于 `InterpreterExecContext` 调度，通过 `callFuncInst` 区分 Native/ByteCode 调用。
- **BlockInfo**：控制结构信息（`TargetAddr`、`ValueStackPtr`、`CellNum`、`LabelType`）。

### 3. 实例化流程

**Instantiator::instantiate** 顺序：

1. `instantiateGlobals`：拷贝导入/内部全局，按 `InitExpr` 初始化。
2. `instantiateFunctions`：填充 `FunctionInstance`（Native 用 FuncPtr，ByteCode 用 CodePtr）。
3. `instantiateTables`：设置表大小并初始化 element segment。
4. `instantiateMemories`：分配线性内存并执行 data segment 初始化。
5. （可选）`instantiateWasi`：若启用 WASI，初始化 WASI 上下文。
6. 若存在 `StartFuncIdx`，执行 start 函数。

### 4. JIT 编排

- **performJITCompile(runtime::Module &)**：根据 `RunMode` 分发至 Singlepass 或 Multipass JIT；支持 Lazy/Eager 模式。
- **performEVMJITCompile(runtime::EVMModule &)**（`ZEN_ENABLE_EVM`）：仅支持 Multipass EVM JIT，不支持 singlepass。

### 5. 字节码访问器

- **WASMByteCodeVisitor&lt;IRBuilder&gt;**：遍历 WASM 函数体，对每条 opcode 调用 IRBuilder 的 `handle*` 接口；支持宏融合（Compare+If、Compare+BrIf、Compare+Select）。
- **EVMByteCodeVisitor&lt;IRBuilder&gt;**（`COMPILER` 命名空间，定义于 `action/`）：基于 `EVMAnalyzer` 做基本块分析，处理 JUMPDEST、死代码、栈高检查；对未定义 opcode 调用 `handleUndefined` 或 fallback。

## 外部契约

### 依赖的模块

| 依赖 | 用途 |
|-----|------|
| `common` | `ErrorCode`、`WASMType`、`SectionType`、算术/类型工具 |
| `runtime` | `Module`、`Instance`、`HostModule`、`EVMModule`、`FunctionInstance` 等 |
| `utils` | `readLEBNumber`、`validateUTF8String`、`addOverflow` 等 |
| `entrypoint` | `callNativeGeneral`（Native 调用） |
| `singlepass`（可选） | `JITCompiler::compile` |
| `compiler`（可选） | `EagerJITCompiler`、`EagerEVMJITCompiler`、`EVMAnalyzer`、`evm_mir_compiler` |

### 对外提供的接口

- `HostModuleLoader::load()`
- `ModuleLoader::load()`
- `EVMModuleLoader::load()`（`ZEN_ENABLE_EVM`）
- `FunctionLoader::load()`
- `Instantiator::instantiate(Instance &)`
- `performJITCompile(Module &)`、`performEVMJITCompile(EVMModule &)`（`ZEN_ENABLE_EVM`）
- `BaseInterpreter::interpret()`
- `WASMByteCodeVisitor::compile()`、`EVMByteCodeVisitor::compile()`（模板，供 compiler 使用）
- `resolveCheckedArithmeticFunction()`（`ZEN_ENABLE_CHECKED_ARITHMETIC`）

## 权限与不变量

### 加载阶段

- `LoaderCommon` 的 `Ptr` 不得越过 `End`；越界时抛出 `UnexpectedEnd`。
- Section 必须按 `SectionOrder` 递增，否则 `JunkAfterLastSection`。
- Name section 必须位于 Data section 之后。
- `NumInternalFunctions` 必须等于 `NumCodeSegments`，否则 `FuncCodeInconsistent`。

### 解释执行

- `InterpStack` 的 `Top` 不得超过 `TopBoundary`。
- 帧分配失败（栈溢出）时返回 `nullptr`，上层抛出 `CallStackExhausted`。
- `ZEN_ENABLE_DWASM` 下，栈消耗超过 `PresetReservedStackSize` 时抛出 `DWasmCallStackExceed`。

### 实例化

- 表/内存/全局数量受 Preset 常量限制；超标抛出 `TooMany*`。
- 元素段/数据段偏移与大小不得越界，否则 `ElementsSegmentDoesNotFit` / `DataSegmentDoesNotFit`。

## 错误码

action 模块使用的 `common::ErrorCode` 主要来自 `Load`、`Instantiation`、`Execution` 阶段：

| 阶段 | 错误码示例 |
|-----|-----------|
| Load | `MagicNotDetected`, `UnknownBinaryVersion`, `UnexpectedEnd`, `TooLongName`, `InvalidUTF8Encoding`, `UnknownTypeIdx`, `UnknownFunction`, `IncompatibleImportType`, `TypeMismatch*`, `FuncCodeInconsistent`, `SectionSizeTooLarge`, `ModuleSizeTooLarge`, `UnsupportedOpcode`, `InvalidRawData` 等 |
| Instantiation | `DataSegmentDoesNotFit`, `ElementsSegmentDoesNotFit`, `MemorySizeTooLarge`, `DWasmModuleFormatInvalid` |
| Execution | `IntegerOverflow`, `IntegerDivByZero`, `OutOfBoundsMemory`, `InvalidConversionToInteger`, `CallStackExhausted`, `IndirectCallTypeMismatch`, `UndefinedElement`, `Unreachable`, `UninitializedElement`, `GasLimitExceeded`, `EVMStackOverflow`, `EVMStackUnderflow`, `DWasmCallStackExceed` |

## 兼容性策略

- **WASM 版本**：遵循模块魔数与版本字段，仅接受 `WasmVersion` 对应版本。
- **EVM 版本**：通过 `EVMAnalyzer` 的 `getRevision()` 与 EVMC 指令集对应；未定义 opcode 由 IRBuilder 处理（fallback/interpreter）。
- **可选特性**：
  - `ZEN_ENABLE_SPEC_TEST`：支持 table/memory/global 导入及 `spectest` 补丁。
  - `ZEN_ENABLE_EVM`：启用 `EVMModuleLoader`、`EVMByteCodeVisitor`、`performEVMJITCompile`。
  - `ZEN_ENABLE_CHECKED_ARITHMETIC`：启用 `resolveCheckedArithmeticFunction` 与算术 Hook。
  - `ZEN_ENABLE_BUILTIN_WASI`：启用 `instantiateWasi`。
  - `ZEN_ENABLE_DWASM`：启用块深度、局部变量、opcode 数量限制及栈代价计算。

## 交叉引用

| 依赖 | 说明 |
|------|------|
| [compiler](../compiler/spec.md) | JIT 实现、IRBuilder、EVM 前端 |
| [runtime](../runtime/spec.md) | Module、Instance、HostModule、EVMModule |
| [evm](../evm/spec.md) | EVM 执行与 Host 接口 |
| [common](../../../src/common/errors.def) | ErrorCode、WASMType、SectionType 等 |

| 被依赖 | 说明 |
|--------|------|
| runtime | 加载、实例化、JIT 编排 |
| compiler | performJITCompile、performEVMJITCompile |
| singlepass | WASMByteCodeVisitor |
| evm | EVMModuleLoader |
