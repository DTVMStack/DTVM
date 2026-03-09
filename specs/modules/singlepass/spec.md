# singlepass 模块规范

> 目录: `src/singlepass/`

## 边界与职责

singlepass 模块是 DTVM 的**单遍 JIT 编译器**，职责如下：

1. **输入**：接收已加载的 WASM 模块 (`runtime::Module`)，仅编译**内部函数**（不含导入函数）。
2. **输出**：在模块的 `JITCodeMemPool` 中生成可直接执行的本机代码，并将 `CodeEntry::JITCodePtr` 写入各函数入口。
3. **范围**：仅处理 WASM，不涉及 EVM/dMIR；使用 AsmJit 生成机器码，支持 x64 与 AArch64 两种后端。
4. **编译方式**：单遍遍历 WASM 字节码，通过 `action::WASMByteCodeVisitor` 驱动，边遍历边生成，无中间 IR。
5. **不负责**：模块加载、验证、解释执行、EVM 执行；这些由 `runtime`、`compiler`、`evm` 等模块承担。

## 核心概念

### 编译流水线

1. **初始化**：`OnePassCompiler::initModule()` 初始化 DataLayout、CodePatcher、ABI。
2. **逐函数编译**：对每个内部函数创建 `asmjit::CodeHolder`，通过 `WASMByteCodeVisitor` + 平台特定 CodeGen（如 `X64OnePassCodeGenImpl`）生成机器码。
3. **平坦化与重定位**：对每个函数执行 `Holder.flatten()`、`Holder.resolveUnresolvedLinks()`。
4. **内存分配**：从 `Mod->getJITCodeMemPool()` 分配可执行缓冲区，按函数顺序拷贝并重定向。
5. **代码补丁**：`CodePatcher::finalizeModule()` 修补模块内 `call` 指令（同模块内函数调用）。
6. **执行权限**：`mprotect(JITCode, CodeSize, PROT_READ | PROT_EXEC)` 后设置模块的 JIT 代码与大小。

### 架构抽象

- **OnePassCompiler\<Impl\>**：模板驱动，`Impl` 提供 `OnePassABI`、`OnePassDataLayout`、`CodePatcher`、`OnePassCodeGenImpl`。
- **x64**：`X86OnePassCompiler`，使用 AMD64 SysV ABI，固定寄存器分配（如 r15=instance、r14=global、r13=memory_base、r12=memory_size、rbx=gas）。
- **a64**：`A64OnePassCompiler`，使用 AArch64 ABI，对应寄存器（如 x28=instance、x27=global、x26=memory_base、x25=memory_size、x22=gas）。

### 栈与数据布局

- **全局变量**：按 Module 中导入/内部全局顺序布局，通过 `global_base + offset` 访问。
- **局部变量**：参数优先使用 ABI 参数寄存器，溢出部分与本地变量放在栈上，由 DataLayout 分配栈帧偏移。
- **临时空间**：Scoped 临时寄存器（短生命周期）与 Temp 寄存器（跨字节码保持）区分；栈上临时由 `getTempStackOperand` 分配。

### 异常与陷阱

- **WASM 陷阱**：通过软件检查或 CPU 异常（`ZEN_ENABLE_CPU_EXCEPTION`）处理。
- **异常标签**：`CurFuncState.ExceptLabels` 按 `ErrorCode` 映射到 `asmjit::Label`；`ExceptionExitLabel` 用于从 JIT 返回解释器/父帧。
- **栈溢出**：在 prolog 中检查 `JITStackBoundary`（或 dWASM 的 `StackCost`），超出则触发 `CallStackExhausted`。

## 外部契约

### 依赖模块

| 模块 | 用途 |
|------|------|
| `runtime` | `Module`、`Instance`、`CodeEntry`、`TypeEntry`、`MemoryInstance`、`TableInstance` |
| `action` | `WASMByteCodeVisitor`，遍历 WASM 字节码并回调 CodeGen |
| `common` | `ErrorCode`、`WASMType`、`BinaryOperator`、`CompareOperator`、`UnaryOperator`、类型工具 |
| `platform` | `mprotect` 设置内存可执行 |
| `utils` | `Statistics`、`JitDumpWriter`（可选） |

### Instance 布局假设

模块通过 `ZEN_STATIC_ASSERT` 校验 `Instance` 关键成员偏移：

- `GlobalVarData` = 0x40
- `Memories` = 0x50
- `MemoryInstance::MemBase` = 0x10
- `MemoryInstance::MemSize` = 0x08
- `JITStackSize` = 0x68
- `JITStackBoundary` = 0x70

修改 `Instance` 布局时需同步更新这些断言。

### 调用约定

- 第一个参数固定为 `Instance*`（模块实例指针）。
- 其余参数遵循平台 ABI（x64: SysV；a64: AArch64 标准），整数与浮点分别使用对应参数寄存器或栈传递。

## 权限与不变量

### 编译期不变量

- `NumInternalFunctions > 0`：至少有一个内部函数。
- 每个 `CodeEntry` 与 `TypeEntry` 非空。
- `CodeHolder` 在 `compile()` 返回前已完成 `flatten` 与 `resolveUnresolvedLinks`。
- 内部 `call` 目标在 `finalizeModule` 时已确定，补丁偏移与目标地址在 `INT32_MAX` 范围内。

### 运行时假设

- JIT 代码页已 `mprotect` 为 `PROT_READ | PROT_EXEC`。
- 调用 JIT 函数前，`Instance` 的 `Memories`、`Tables`、`JITFuncPtrs` 等已正确初始化。
- Gas 相关：`Instance::Gas` 在调用前有效；JIT 内通过 `loadGasVal`/`saveGasVal` 与 `subGasVal` 维护。

### 寄存器使用约定

- **固定用途**：instance、global_base、memory_base、memory_size、gas、call_target 等由 ABI 固定分配。
- **Callee-saved**：需在 prolog 保存、epilog 恢复（x64 如 rbx、r12–r15）。
- **Scoped / Temp**：由 MachineState 跟踪可用性，避免跨调用破坏。

## 错误码

| 错误码 | 含义 | 触发场景 |
|--------|------|----------|
| `AsmJitFailed` | AsmJit 生成失败 | `OnePassErrorHandler::handleError` |
| `MmapFailed` | JIT 代码内存分配失败 | `CodeMemPool.allocate` 返回空 |
| `CallStackExhausted` | 栈溢出 | prolog 中检查栈边界 |
| `OutOfBoundsMemory` | 内存越界 | 软件内存检查模式下的 load/store |
| `UndefinedElement` | 表越界 | call_indirect 表索引检查 |
| `UninitializedElement` | 表项未初始化 | call_indirect 表项为 -1 |
| `IndirectCallTypeMismatch` | 间接调用类型不匹配 | call_indirect 类型检查 |
| `IntegerOverflow` | 整数溢出 | checked 算术、除零特殊路径 |
| `IntegerDivByZero` | 整数除零 | idiv/rem 除数为 0 |
| `InvalidConversionToInteger` | 浮点转整数无效 | NaN 或超出范围 |
| `GasLimitExceeded` | Gas 耗尽 | `handleGasCall` 检查 |
| `Unreachable` | 不可达指令 | `handleUnreachableImpl` |

## 兼容性策略

### 构建选项

- **`ZEN_BUILD_TARGET_X86_64`**：启用 x64 后端。
- **`ZEN_BUILD_TARGET_AARCH64`**：启用 AArch64 后端。
- **`ZEN_ENABLE_SINGLEPASS_JIT`**：是否启用 singlepass JIT（CMake 选项）。
- **`ZEN_ENABLE_SINGLEPASS_JIT_LOGGING`**：输出 AsmJit 调试日志。
- **`ZEN_ENABLE_CPU_EXCEPTION`**：使用 CPU 异常处理 WASM 陷阱。
- **`ZEN_ENABLE_DWASM`**：dWASM 扩展（如 StackCost、InHostAPI）。
- **`ZEN_ENABLE_STACK_CHECK_CPU`**：基于 CPU 的栈溢出检查（预访问 guard 页）。
- **`ZEN_ENABLE_LINUX_PERF`**：生成 perf JIT 映射。

### 平台差异

- x64：依赖 LZCNT/TZCNT/POPCNT 指令，缺失时使用软件 fallback（如 BSR+cmov、SWAR popcount）。
- AArch64：结构类似，ABI 与寄存器分配独立实现。

### 与 multipass 的关系

- singlepass 与 multipass（LLVM）为互斥执行引擎，同一时刻模块仅使用其一。
- 选择由构建与运行时配置决定，模块接口（`JITCodePtr`、调用约定）保持一致。

## 交叉引用

| 依赖 | 说明 |
|------|------|
| [compiler](../compiler/spec.md) | 编译器总览 |
| [runtime](../runtime/spec.md) | Module、Instance、CodeEntry、TypeEntry |
| [action](../action/spec.md) | WASMByteCodeVisitor |
| [common](../common/spec.md) | ErrorCode、WASMType、operators |
| [platform](../platform/spec.md) | mprotect |
| [utils](../utils/spec.md) | Statistics、JitDumpWriter |

| 被依赖 | 说明 |
|--------|------|
| action | performJITCompile、WASMByteCodeVisitor 驱动 |

- 数据模型：`specs/modules/singlepass/data-model.md`
- 构建说明：`docs/start.md`（`ZEN_ENABLE_SINGLEPASS_JIT`）
