# runtime 模块规范

> 目录: `src/runtime/` + `src/entrypoint/`

## 边界与职责

runtime 模块是 DTVM 的**核心运行时**，负责：

1. **Runtime 生命周期**：单例 Runtime 的创建、初始化、清理
2. **Module 管理**：WASM 模块 (Module)、EVM 模块 (EVMModule)、宿主模块 (HostModule) 的加载、合并、卸载
3. **Instance 生命周期**：通过 Isolation 创建和管理 WASM Instance、EVMInstance
4. **Memory**：WASM 线性内存分配器 (WasmMemoryAllocator)，支持 malloc、single mmap、bucket mmap 三种后端
5. **Isolation 域**：实例隔离域，管理实例池和 WNI 环境
6. **VNMI / WNI 接口**：原生模块接口 (VNMIEnv) 与 WASM 原生接口 (WNIEnv)，供宿主函数和 native 模块调用
7. **JIT 调用桥接**：entrypoint 提供 `callNative` 汇编桩，实现 JIT 编译代码与宿主/实例之间的调用边界

## 核心概念

### Runtime

- **创建**：`Runtime::newRuntime(Config)` / `Runtime::newEVMRuntime(Config, EVMHost)`（仅当 ZEN_ENABLE_EVM）
- **职责**：符号池、内存池、模块池、Isolation 池、WASI 环境（可选）
- **线程安全**：大部分方法标注 `not thread-safe`；`createManagedIsolation` / `deleteManagedIsolation` 使用 `Mtx` 保护

### Module 与 Instance

- **Module**：WASM 字节码的解析结果，持有类型表、导入/导出表、代码段、数据段、JIT 元数据
- **HostModule**：原生宿主模块，由 `BuiltinModuleDesc` 描述，通过 VNMI 加载/卸载函数
- **EVMModule**：EVM 字节码模块，持有 Code、CodeSize、evmc::Host、JIT 代码（可选）
- **Instance**：Module 的实例化结果，包含函数表、表、内存、全局变量等运行时状态
- **EVMInstance**：EVM 专用实例，持有 EVM 栈、内存、消息栈、执行缓存等

### Isolation

- **托管**：`createManagedIsolation` / `deleteManagedIsolation`，由 Runtime 管理生命周期
- **非托管**：`createUnmanagedIsolation`，调用方需保证生命周期为 Runtime 子集
- **实例池**：`InstancePool`、`EVMInstancePool`，Isolation 持有实例所有权

### Memory

- **WasmMemoryAllocator**：按模块/线程局部分配，支持：
  - `WM_MEMORY_DATA_TYPE_MALLOC`：普通堆分配
  - `WM_MEMORY_DATA_TYPE_SINGLE_MMAP`：单块 mmap（用于 CPU trap 内存检查）
  - `WM_MEMORY_DATA_TYPE_BUCKET_MMAP`：多副本 bucket mmap（共享初始化数据、加速实例创建）

### VNMI / WNI

- **VNMIEnv**：宿主模块 (HostModule) 使用的运行时接口，提供 `allocMem`、`freeMem`、`newSymbol`、`freeSymbol`
- **WNIEnv**：WASM 实例内 native 模块使用的接口，提供地址转换 (`getNativeAddr` / `getAppAddr`)、用户上下文 (`getUserDefinedCtx`)、异常抛出等

### Entrypoint

- **callNative**：汇编实现的 JIT 调用桩，负责：
  - 保存/恢复被调用者保存寄存器
  - 根据 ABI 布局参数（浮点寄存器、整数寄存器、栈参数）
  - 设置 Instance 的 `JITStackBoundary`、`GlobalVarData`、`Memories` 等（Singlepass JIT）
- **平台**：x86_64 (`callNative_x86_64.S`)、aarch64 (`callNative_aarch64.S`)
- **辅助**：`rollbackWasmVirtualStack`、`startWasmFuncStack`（虚拟栈场景）

## 外部契约

### 依赖

- **common**：`Error`、`ErrorCode`、`TypedValue`、`WASMType`、`ConstStringPool`、`SysMemPool`
- **action**：`Interpreter`、`ModuleLoader`、`HostModuleLoader`、`FunctionLoader`、`Instantiator`、`performJITCompile`
- **platform**：`mapFile`、`unmapFile`、内存相关
- **evm**（可选）：`evm::DEFAULT_REVISION`、`evm::Interpreter`、EVM 执行逻辑
- **evmc**（可选）：`evmc::Host`、`evmc::Result`、`evmc_message`

### 被依赖

- **action**：加载、实例化、JIT 编译
- **host**：WASI、spectest 等宿主模块，使用 VNMIEnv
- **compiler**：Multipass JIT 使用 Module 的 JIT 元数据、Instance 布局
- **evm**：EVM 解释器、EVM JIT 使用 EVMInstance、EVMModule

## 权限与不变量

1. **Instance 与 Runtime**：Instance 必须在 Runtime 存活期内使用，且 Isolation 生命周期为 Runtime 子集
2. **Module 与 Instance**：Instance 持有 Module 只读引用；卸载 Module 前须确保无活跃 Instance 引用
3. **内存**：`WasmMemoryAllocator` 非线程安全，每个线程通过 `ThreadLocalMemAllocatorMap` 获取独立 allocator
4. **JIT 调用**：`callNative` 入口须满足 ABI 约定；`callNative` / `callNative_end` 用于 JIT 栈回溯
5. **符号**：`newSymbol` / `freeSymbol` 非线程安全；释放 Module 时由 `RuntimeObjectDestroyer` 统一释放符号

## 错误码

runtime 模块通过 `common::Error` / `common::ErrorCode` 传播错误，常见与 runtime 相关者包括：

- `InvalidFilePath`、`InvalidRawData`、`FileAccessFailed`：加载失败
- `OutOfBoundsMemory`、`CallStackExhausted`：执行期内存/栈越界
- `GasLimitExceeded`：Gas 耗尽
- `InstanceExit`：实例主动退出 (`Instance::exit`)
- EVM 相关：`EVMStackOverflow`、`EVMStackUnderflow`、`EVMBadJumpDestination`、`EVMInvalidInstruction`、`EVMStaticModeViolation` 等

## 兼容性策略

1. **配置**：`RuntimeConfig` 控制 RunMode (Interp / Singlepass / Multipass)、WASI、统计、JIT 线程数等；变更需验证 `validate()`
2. **编译选项**：大量行为受 `ZEN_ENABLE_EVM`、`ZEN_ENABLE_JIT`、`ZEN_ENABLE_SINGLEPASS_JIT`、`ZEN_ENABLE_MULTIPASS_JIT`、`ZEN_ENABLE_BUILTIN_WASI`、`ZEN_ENABLE_CPU_EXCEPTION`、`ZEN_ENABLE_VIRTUAL_STACK`、`ZEN_ENABLE_DWASM` 等宏影响
3. **ABI**：entrypoint 汇编依赖 `Instance`、`MemoryInstance` 等结构体布局；修改 layout 须同步更新汇编中的 offset

## 交叉引用

| 依赖 | 说明 |
|------|------|
| [common](../common/) | 错误码与 Error 类型 |
| [action](../action/) | 加载、实例化、JIT 触发 |
| [evm](../evm/) | EVM 执行与缓存 |
| [platform](../platform/) | 内存映射与平台抽象 |
| [compiler](../compiler/) | Multipass JIT 与 EVM JIT |

| 被依赖 | 说明 |
|--------|------|
| action | 加载、实例化、JIT 编排 |
| host | HostModule、VNMIEnv、BuiltinModuleDesc |
| compiler | Module、Instance、EVMModule、CodeMemPool |
| evm | EVMInstance、EVMModule |
| cli | Runtime、Module、Instance、Isolation、HostModule |
| vm-interface | EVMModule、EVMInstance、托管隔离、callEVMMain |
| tests | 执行环境与实例 |
