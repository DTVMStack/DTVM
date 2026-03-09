# vm-interface 模块规范

> 目录: `src/vm/` + `evmc/`

## 边界与职责

vm-interface 模块实现 DTVM 的 **EVMC 共享库接口**（dtvmapi.so），负责：

- **EVMC ABI 兼容**：实现 EVMC ABI 版本 12 的 `evmc_vm` 接口，通过 `evmc_create_dtvmapi()` 导出 VM 实例创建入口
- **EVM 执行能力声明**：通过 `get_capabilities()` 返回 `EVMC_CAPABILITY_EVM1`，声明完整的 EVM1 执行能力
- **运行时模式配置**：通过 `set_option()` 支持 `mode`（interpreter/multipass）和 `enable_gas_metering`（true/false）的动态配置
- **Host 接口桥接**：`WrappedHost` 将 C 风格 `evmc_host_interface` 与 `evmc_host_context` 桥接到 C++ `evmc::Host`，供执行引擎调用
- **模块缓存与隔离管理**：基于地址（code_address + revision）的 L1 缓存、顶层调用的实例复用、托管隔离（Managed Isolation）生命周期管理
- **跨平台部署**：静态链接 libstdc++ 与 libgcc，符号隐藏（`-fvisibility=hidden`），最小化运行时依赖

本模块不包含：EVM 字节码编译（compiler）、解释/JIT 实现细节（evm/runtime）、Host 业务逻辑实现（host）。

## 核心概念

### 1. EVMC ABI 兼容性

- VM 实例通过 `evmc_create_dtvmapi()` 创建，返回 `evmc_vm *`，具备 `abi_version`、`name`（"dtvm"）、`version`（PROJECT_VERSION）及完整函数指针：`destroy`、`execute`、`get_capabilities`、`set_option`
- 客户端通过 `evmc_vm::destroy()` 销毁实例时，系统须释放所有已分配资源（缓存模块、托管隔离、WrappedHost），禁止内存泄漏

### 2. EVM 执行能力

- `get_capabilities()` 返回 `EVMC_CAPABILITY_EVM1`，表明支持完整 EVM1 语义
- `execute()` 接收 `evmc_host_interface`、`evmc_host_context`、`evmc_revision`、`evmc_message`、字节码（Code/CodeSize），返回 `evmc_result`
- 执行前通过 `WrappedHost::reinitialize()` 将 Host 接口与上下文注入，执行期间所有 Host 调用（账户、存储、调用、日志等）均通过 WrappedHost 委托给客户端

### 3. 运行时模式配置

- **mode**：`"interpreter"` → `RunMode::InterpMode`；`"multipass"` → `RunMode::MultipassMode`
- **enable_gas_metering**：`"true"` → 启用 MIR 级 Gas 计费；`"false"` → 禁用
- 未知 option 名称返回 `EVMC_SET_OPTION_INVALID_NAME`；非法值返回 `EVMC_SET_OPTION_INVALID_VALUE`

### 4. WrappedHost 桥接

- `WrappedHost` 继承 `evmc::Host`，内部持有多态 `evmc_host_interface *` 与 `evmc_host_context *`
- 构造时支持 `nullptr`，可通过 `reinitialize(interface, context)` 在每次 `execute()` 调用前动态重初始化
- 所有 `evmc::Host` 虚方法（account_exists、get_storage、set_storage、get_balance、copy_code、call、get_tx_context、get_block_hash、emit_log、access_account、access_storage、get_transient_storage、set_transient_storage、selfdestruct）均转发至 C 接口

### 5. 模块缓存策略

- **L1 地址缓存**：以 `CodeAddrRevKey{code_address, revision}` 为键，映射到 `EVMModule *`
- **校验机制**：`validateCodeMatch()` 校验缓存模块的 Code 与传入 Code 头部/尾部各 256 字节一致，防止地址重用导致缓存污染
- **驱逐**：校验失败时卸载旧模块、擦除缓存条目，再冷加载新模块
- L0 指针缓存已禁用（地址重用场景下不安全），L0 状态变量仅用于驱逐时的一致性更新

### 6. 实例复用与嵌套调用

- **顶层调用（depth == 0）**：复用 `CachedInst`，若模块变化则销毁旧实例并创建新实例；解释器模式额外复用 `CachedCtx`（InterpreterExecContext）
- **嵌套调用（depth > 0）**：为每次调用创建临时 `EVMInstance`，由 `InstanceGuard` RAII 在退出时调用 `deleteEVMInstance`
- `HostContextScope` 在 `execute()` 入口/出口保存并恢复 Host 上下文，保证异常安全

### 7. 托管隔离与资源管理

- `Runtime::createManagedIsolation()` 创建托管隔离；`Runtime::deleteManagedIsolation()` 销毁
- DTVM 析构时：先销毁 `CachedInst`，再按 `AddrCache` 卸载所有 EVMModule，最后 `deleteManagedIsolation(Iso)`
- `InstanceGuard` 确保嵌套调用的临时实例在异常路径下亦被正确释放

### 8. JIT Fallback（可选）

- 当 `ZEN_ENABLE_JIT_PRECOMPILE_FALLBACK` 开启时，对不适合 JIT 的字节码（由 `EVMAnalyzer` 判定）使用 `ScopedConfig` 临时切换为 interpreter 模式执行

## 外部契约

| 依赖模块   | 契约说明 |
|------------|----------|
| runtime    | `Runtime::newEVMRuntime()`、`loadEVMModule()`、`unloadEVMModule()`、`createManagedIsolation()`、`deleteManagedIsolation()`；`Isolation::createEVMInstance()`、`deleteEVMInstance()`；`callEVMMain()` |
| evm        | `InterpreterExecContext`、`BaseInterpreter` 用于解释器快速路径 |
| common     | `RunMode`、`InputFormat`、`RuntimeConfig` |
| compiler   | `EVMAnalyzer`（仅 JIT fallback 可选依赖） |
| evmc（库） | `evmc.h`、`evmc.hpp`、`utils.h`、`helpers.h`：`evmc_vm`、`evmc_host_interface`、`evmc_host_context`、`evmc_message`、`evmc_result`、`evmc_revision`、`evmc_set_option_result` 等 |

## 权限与不变量

- **确定性**：相同输入产生相同 `evmc_result`，禁止主机相关非确定性行为
- **异常安全**：`HostContextScope`、`InstanceGuard` 保证异常时 Host 上下文恢复、临时实例释放
- **缓存一致性**：`AddrCache` 中模块的 Code 须与键对应的 code_address 处字节码一致（头部/尾部校验）
- **单线程**：EVMInstance 不支持多线程并发执行（与 runtime/evm 一致）

## 错误码

| 错误码 / 返回值      | 来源           | 说明 |
|----------------------|----------------|------|
| EVMC_FAILURE         | evmc_result    | 模块加载失败、实例创建失败、执行失败 |
| EVMC_SUCCESS         | evmc_result    | 执行成功 |
| EVMC_SET_OPTION_SUCCESS | set_option | 选项设置成功 |
| EVMC_SET_OPTION_INVALID_NAME | set_option | 未知 option 名称 |
| EVMC_SET_OPTION_INVALID_VALUE | set_option | option 值非法 |
| EVMC_CAPABILITY_EVM1 | get_capabilities | 声明 EVM1 能力 |

## 兼容性策略

- **EVMC ABI 版本**：遵循 EVMC ABI 12，与主流 EVM 客户端（如 Geth、Erigon）兼容
- **跨平台部署**：通过 `-static-libstdc++`、`-static-libgcc` 静态链接 C++ 标准库与 libgcc，减少目标环境对特定 libstdc++ 版本的依赖
- **符号导出**：`EVMC_EXPORT` 用于 `evmc_create_dtvmapi`，其余符号隐藏，`-Wl,--exclude-libs,ALL` 排除静态库符号

## 交叉引用

| 依赖 | 说明 |
|------|------|
| [runtime](../runtime/spec.md) | EVM 模块与实例生命周期、托管隔离、callEVMMain |
| [evm](../evm/spec.md) | InterpreterExecContext、BaseInterpreter 解释器路径 |
| [common](../common/spec.md) | RunMode、InputFormat、RuntimeConfig |
| [compiler](../compiler/spec.md) | EVMAnalyzer、JIT fallback 决策 |

| 被依赖 | 说明 |
|--------|------|
| rust-bindings | 通过 zetaengine C 库间接调用 VM 执行入口 |
| 外部 EVM 客户端 | dtvmapi.so、evmc_create_dtvmapi() |
