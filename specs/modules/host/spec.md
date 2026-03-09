# host 模块规范

> 目录: `src/host/` + `src/wni/`

## 边界与职责

host 模块实现 DTVM 的 **宿主环境接口**，为 Wasm/EVM 执行提供与外部世界的桥接能力，包括：

- **WASI (wasi_snapshot_preview1)**：提供与 wasi-libc 兼容的系统调用接口，包括文件描述符、路径、时钟、环境变量、进程、随机数、套接字等
- **env**：基础环境 API，含 `abort`，以及条件编译的 libc 内置实现或 Mock Chain 测试桩
- **spectest**：Wasm 规范测试辅助模块，提供 `print`、`print_i32`、`print_f32` 等调试输出和 `call_wasm` 调用
- **evmabimock**：EVM ABI 兼容的 Mock 宿主，模拟链上环境（存储、调用、区块、交易、密码学等），用于 Wasm-EVM 适配层测试
- **evm/crypto**：EVM 密码学实现，提供 Keccak-256 哈希，供 EVM 预编译合约使用
- **wni**：WNI (Wasm Native Interface) 基础设施，提供宿主模块的宏、类型提取和 boilerplate 代码生成

本模块不包含：runtime 实例管理、JIT 编译、evmc Host 实现（evmc 目录）、VM 入口。

## 核心概念

### 1. WNI 宿主模块注册机制

- 各子模块通过 `EXPORT_MODULE_NAME` + `AUTO_GENERATED_FUNCS_DECL` + `FUNCTION_LISTS` 定义导出
- `wni/helper.h` 提供 `VALIDATE_APP_ADDR`、`ADDR_APP_TO_NATIVE`、`ADDR_NATIVE_TO_APP`、`FuncTypeExtracter`、`ExtractNativeFuncType`
- `wni/boilerplate.cpp` 被 include 后生成 `loadNativeModule`、`unloadNativeModule` 和 `BuiltinModuleDesc MODULE_DESC_NAME`
- 保留函数 `vnmi_init_ctx`、`vnmi_destroy_ctx` 由 runtime 在实例化时调用，用于创建/销毁模块级上下文

### 2. WASI 实现

- 基于 Wasmtime 的 sandboxed-system-primitives (SSP)，使用 `wasmtime_ssp.h` 中的类型与函数
- `WASIContext` 持有 `fd_table`、`fd_prestats`、`argv_environ_values`、`VNMIEnv*`，作为 WASI 调用的共享状态
- WASI 函数接收 Wasm 线性内存中的 app 地址，通过 `VALIDATE_APP_ADDR` 校验后用 `ADDR_APP_TO_NATIVE` 转换访问
- 内存分配通过 `vmenv->allocMem()` / `vmenv->freeMem()` 使用 runtime 分配器

### 3. env 模块变体

- `ZEN_ENABLE_BUILTIN_LIBC`：启用 libc.inc.cpp 中的 `strlen`、`puts`、`printf`、`memcpy` 等基础实现
- `ZEN_ENABLE_MOCK_CHAIN_TEST`：启用 mock_chain.inc.cpp 中的桩实现，用于 JIT 编译测试
- `ZEN_ENABLE_ASSEMBLYSCRIPT_TEST`：abort 接受 (a,b,c,d) 四参数
- `ZEN_ENABLE_BUILTIN_LIBC` 或 mock 场景：abort 接受单参数 code

### 4. spectest 模块

- 无上下文，`vnmi_init_ctx` 返回 `nullptr`
- `print` 系列：将 i32/f32/f64 等以固定格式输出到 stdout
- `call_wasm`：通过 `instance->getRuntime()->callWasmFunction()` 调用指定索引的 Wasm 函数

### 5. EVM ABI Mock

- `EVMAbiMockContext` 存储当前合约代码（含 4 字节大端长度前缀）和存储映射（key hex => value bytes32）
- 通过 `instance->setCustomData()` / `instance->getCustomData()` 与 `Instance` 关联
- 所有区块链相关 API（getAddress、getBlockHash、storageStore 等）返回 Mock 数据，子合约调用/创建返回失败

### 6. EVM 密码学

- `CryptoInterface` 定义 `keccak256` 的纯虚接口
- `CryptoHost` 使用 `ethash::keccak256`（来自 keccak.hpp）实现
- `CryptoProvider` 单例，支持 `getInstance()` 和 `setInstance()` 注入

## 外部契约

| 依赖模块   | 契约说明 |
|------------|----------|
| runtime    | `Instance`（getWASIContext、getCustomData、getRuntime、setExceptionByHostapi、exit、validatedAppAddr、getNativeMemoryAddr、getMemoryOffset）、`VNMIEnv`、`BuiltinModuleDesc`、`NativeFuncDesc` |
| common     | `ErrorCode`（EnvAbort、WASIProcRaise、InstanceExit）、`getErrorWithExtraMessage`、`TypedValue` |
| utils      | `zen::utils::toHex` |
| wasmtime_ssp | `fd_table`、`fd_prestats`、`argv_environ_values`、`__wasi_*` 类型及 `wasmtime_ssp_*` 函数 |
| ethash     | `ethash::keccak256`、`ethash_hash256` |

## 权限与不变量

- **地址校验**：所有从 Wasm 传入的指针/偏移在访问前必须通过 `VALIDATE_APP_ADDR(offset, size)` 校验
- **确定性**：WASI/spectest/evmabimock 在相同输入下应产生可复现行为；随机数接口（random_get）由 SSP 实现
- **上下文生命周期**：`vnmi_init_ctx` 分配的上下文必须在 `vnmi_destroy_ctx` 中完整释放
- **EVMAbiMockContext**：使用 evmabimock 时，`Instance` 必须在调用前设置 `EVMAbiMockContext*` 到 CustomData

## 错误码

| 错误码 / 返回值 | 来源        | 说明 |
|-----------------|-------------|------|
| ErrorCode::EnvAbort | env, evmabimock | 宿主 API 异常终止，带额外消息 |
| ErrorCode::WASIProcRaise | wasi | 进程收到信号时设置 |
| ErrorCode::InstanceExit | wasi, evmabimock | proc_exit 或 finish 导致实例退出 |
| wasi_errno_t -1 | wasi | 地址校验失败或无效上下文 |
| __WASI_ESUCCESS (0) | wasi | 操作成功 |
| __WASI_EBADF 等 | wasmtime_ssp | 具体 WASI errno，见 wasmtime_ssp.h |

## 兼容性策略

- **WASI**：与 wasi-libc / WASI snapshot preview1 保持一致，类型定义和布局参考 wasi/api.h
- **EVM ABI Mock**：模拟 EVM 预编译和区块链环境，不保证与真实链行为一致，仅用于测试
- **ethash**：Keccak-256 实现遵循 Ethereum/Ethash 规范

## 交叉引用

| 依赖 | 说明 |
|------|------|
| [runtime](../runtime/spec.md) | Instance、VNMIEnv、BuiltinModuleDesc |
| [common](../common/spec.md) | ErrorCode、TypedValue |
| [utils](../utils/spec.md) | toHex |

| 被依赖 | 说明 |
|--------|------|
| runtime | HostModule、BuiltinModuleDesc 加载 |
| evm | evmc::Host 账户/存储/调用接口 |
| cli | WASI、env、evmabimock 宿主模块装配 |
| tests | evm::crypto::keccak256、预编译实现 |

- [host 数据模型](./data-model.md)
