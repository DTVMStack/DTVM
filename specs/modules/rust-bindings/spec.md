# rust-bindings 模块规范

> 目录: `rust_crate/`

## 边界与职责

rust-bindings 模块提供 DTVM 的 **Rust FFI 绑定和 Rust API**，负责：

- **C FFI 绑定**：通过 `extern "C"` 声明调用 zetaengine 静态库（`Zen*` 系列 C API），实现从 Rust 到 DTVM C++ 核心的桥接
- **运行时封装**：将 C 指针封装为 Rust 类型（`ZenRuntime`、`ZenModule`、`ZenInstance` 等），管理生命周期与资源释放
- **EVM ABI 兼容层**：提供 EVM 宿主函数接口（`EvmHost` trait）及 42 个 EVM 宿主函数的 Rust 实现，供 WASM 合约调用
- **Gas 计量**：对 WASM 模块进行 Gas 注入（`GasMeter`），支持自定义规则（`Rules` trait）
- **内存安全**：通过 `MemoryAccessor`、边界检查、缓冲区大小限制（16MB）提供安全的 WASM 线性内存访问

本模块不包含：C++ 核心实现（位于 `src/`）、EVM 字节码解释器（位于 `src/evm/`）、构建脚本所依赖的 `build_cpp_lib.sh` / `copy_deps.sh` 等外部脚本。

## 核心概念

### 1. FFI 与 C API 映射

- **运行时配置**：`ZenRuntimeConfig` / `ZenRuntimeMode`（Interp=0、Singlepass=1、Multipass=2）对应 `ZenCreateRuntimeConfig`、`ZenDeleteRuntimeConfig`
- **运行时与模块**：`ZenRuntime` 持有 `ZenRuntimeExtern*`；`ZenModule` 持有 `ZenModuleExtern*`；通过 `ZenLoadModuleFromFile` / `ZenLoadModuleFromBuffer` 加载 WASM
- **隔离与实例**：`ZenIsolation` 持有 `ZenIsolationExtern*`；`ZenInstance<T>` 持有 `ZenInstanceExtern*` 及泛型上下文 `extra_ctx: T`
- **宿主函数**：`ZenHostFuncDesc` 描述名称、参数类型、返回类型、C 函数指针；`ZenHostModuleDesc` / `ZenHostModule` 管理宿主模块的注册与加载

### 2. 宿主函数注册与调用约定

- 所有宿主函数第一参数必须为 `*mut ZenInstanceExtern`，用于从 C 层回传 Rust `ZenInstance<T>`（通过 `ZenSetInstanceCustomData` 存储）
- `ZenHostFuncDesc` 的 `arg_types` / `ret_types` 使用 `ZenValueType` 编码：0=i32、1=i64、2=f32、3=f64
- `ZenFilterHostFunctions` 支持白名单过滤，仅启用指定名称的宿主函数

### 3. EVM Host 抽象与实现

- **EvmHost trait**：统一 EVM 宿主接口，包含账户、区块、交易、存储、代码、合约、控制、日志、费用、密码学、数学等操作
- **Host 实现**：宿主函数（如 `get_address`、`storage_load`、`call_contract` 等）通过 `instance.extra_ctx` 获取 `EvmHost` 实现并委托
- **内存读写**：宿主函数使用 `MemoryAccessor` 进行偏移校验与读写，参数通常为 `(i32 offset, i32 length)` 表示 WASM 线性内存区间

### 4. Gas 计量流程

- **Rules trait**：定义 `instruction_cost`、`memory_grow_cost`、`call_per_local_cost`
- **ConstantCostRules**：每指令固定成本、每页内存增长成本、每局部变量调用成本
- **GasMeter::transform_default / transform_with_rules**：解析 WASM、注入 `__instrumented_use_gas` 调用、序列化输出
- **validation**：通过控制流图与 DFS 验证注入 Gas 的正确性

### 5. 错误与异常

- **HostFunctionError**：涵盖 OutOfBounds、InvalidParameter、ContextNotFound、MemoryAccessError、ExecutionError、GasError、StorageError、CallError、CryptoError、ArithmeticError
- **C 层异常**：宿主函数失败时通过 `ZenSetInstanceExceptionByHostapi(error_code)` 设置异常；错误码由 `ZenGetErrCodeEnvAbort`、`ZenGetErrCodeGasLimitExceeded`、`ZenGetErrCodeOutOfBoundsMemory` 获取

## 外部契约

| 依赖方 | 契约说明 |
|--------|----------|
| zetaengine | C 静态库，提供 `Zen*` 系列 API；需在 `build.rs` 中通过 `build_cpp_lib.sh`、`copy_deps.sh` 构建并链接 |
| utils_lib | C 静态库，与 zetaengine 一起链接 |
| asmjit | 汇编 JIT 库，静态链接 |
| parity-wasm | WASM 解析与序列化，用于 Gas 注入 |
| wat | WAT 解析，用于测试 |
| num-bigint / sha2 / sha3 | EVM 数学与密码学运算（addmod、mulmod、expmod、sha256、keccak256） |

## 权限与不变量

- **非线程安全**：`ZenRuntime::create_host_module`、`load_host_module`、`merge_host_module` 等均标注为 `<not thread-safe>`
- **实例生命周期**：`ZenInstance` 的 `ptr` 非空时，对应的 `ZenIsolation`、`ZenModule`、`ZenRuntime` 必须存活；Drop 时按 instance → isolation → module → runtime 顺序释放
- **CustomData 不变量**：`ZenInstance` 的 CustomData 仅用于存储 `ZenInstance<T>*`，用户不得用于存储其它对象
- **缓冲区大小**：`MAX_BUFFER_SIZE = 16MB`，`validate_buffer_size` 限制单次内存操作，防止 DoS

## 错误码

| 错误码/分类 | 来源 | 说明 |
|-------------|------|------|
| HostFunctionError | evm::error | 宿主函数执行错误，含 function、message、category |
| TransformError | gas_metering::transform | Parse（WASM 解析失败）、Inject（Gas 注入失败）、Serialize（序列化失败） |
| C API 错误 | core::extern | 通过 `ZenGetInstanceError` 获取错误字符串；`ZenGetErrCode*` 获取数值码 |

## 兼容性策略

- **FFI ABI**：与 zetaengine 的 C ABI 强绑定，zetaengine 接口变更需同步更新 `core::extern` 与封装类型
- **EVM 宿主函数命名**：与 WASM 合约导入的 `env` 模块函数名一致（如 `getAddress`、`storageStore`、`callContract`）
- **EVM 修订版本**：EvmHost trait 与宿主函数实现需与 DTVM EVM 解释器支持的修订版本保持一致

## 交叉引用

| 模块 | 引用关系 |
|------|----------|
| [vm-interface](../vm-interface/spec.md) | 通过 zetaengine 间接调用 VM 执行入口 |
| [runtime](../runtime/spec.md) | ZenRuntime 对应 C++ Runtime 概念；ZenIsolation 对应执行隔离 |
| [host](../host/spec.md) | EvmHost 与宿主函数实现对应 Host 接口的 Rust 抽象 |
| [evm](../evm/spec.md) | EVM 宿主函数语义与 C++ evm 模块一致 |
