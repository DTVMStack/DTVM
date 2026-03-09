# cli 模块规范

> 目录: `src/cli/`

## 边界与职责

cli 模块是 DTVM 的命令行入口，提供单进程、单文件的 WASM/EVM 执行能力。

**核心职责**:

- **命令行解析**: 使用 CLI11 解析输入文件、运行模式、Gas 限制、日志级别等选项
- **运行时创建**: 根据 `RuntimeConfig` 创建 WASM 或 EVM `Runtime`
- **模块加载与执行**: 加载 WASM/EVM 模块，创建隔离与实例，调用入口函数或 main
- **Host 模块装配**: 可选加载 WASI、env、evmabimock 等内置 host 模块
- **状态持久化（EVM）**: 支持 `--load-state` / `--save-state` 读写 EVM MockedHost 状态
- **基准测试**: 支持 `--num-extra-compilations` / `--num-extra-executions` 进行额外编译/执行以测量性能

**排除在边界外**:

- 解析库（CLI11）的实现细节
- `Runtime`、`Module`、`Instance` 等由 runtime 模块定义
- EVM Host 实现由 `tests/evm_test_host.hpp` 和 `evm` 模块提供

## 核心概念

| 概念 | 描述 |
|------|------|
| **INPUT_FILE** | 必需位置参数，WASM 或 EVM 字节码文件路径 |
| **运行模式** | `interpreter`、`singlepass`（WASM 专有）、`multipass`，映射到 `RunMode` |
| **输入格式** | `wasm` 或 `evm`，映射到 `InputFormat`，决定走 WASM 流程还是 EVM 流程 |
| **入口调用** | 若指定 `--function` 则调用该函数，否则调用 WASM main；EVM 模式下为合约部署或调用 |
| **EVM 消息** | `--deploy` 时为 `EVMC_CREATE`，否则 `EVMC_CALL`；`--contract-address`、`--sender`、`--calldata` 参与构造 `evmc_message` |
| **exitMain** | 统一退出逻辑：输出统计、停止 Profiler（若启用）、返回退出码 |

## 外部契约

### 依赖的运行时 API

```cpp
// 创建运行时
std::unique_ptr<Runtime> Runtime::newRuntime(RuntimeConfig);
std::unique_ptr<Runtime> Runtime::newEVMRuntime(RuntimeConfig, evmc::Host*);  // ZEN_ENABLE_EVM

// WASM 流程
MayBe<Module*> loadModule(Filename, EntryHint);
bool unloadModule(Module*);
Isolation* createManagedIsolation();
MayBe<Instance*> Iso->createInstance(Module&, GasLimit);
bool callWasmMain(Instance&, Results);
bool callWasmFunction(Instance&, FuncName, Args, Results);
bool Iso->deleteInstance(Instance*);
bool deleteManagedIsolation(Isolation*);

// EVM 流程（ZEN_ENABLE_EVM）
MayBe<EVMModule*> loadEVMModule(Filename, evmc_revision);
bool unloadEVMModule(EVMModule*);
MayBe<EVMInstance*> Iso->createEVMInstance(EVMModule&, GasLimit);
void callEVMMain(EVMInstance&, evmc_message, evmc::Result&);
bool Iso->deleteEVMInstance(EVMInstance*);
```

### 依赖的工具 API

```cpp
// zen::utils
std::optional<std::vector<uint8_t>> fromHex(std::string_view);
std::string toHex(uint8_t*, size_t);
evmc::address parseAddress(std::string);
evmc::address computeCreateAddress(evmc::address, uint64_t nonce);
bool readBinaryFile(path, std::vector<uint8_t>&);
bool saveState(evmc::MockedHost const&, path);
bool loadState(evmc::MockedHost&, path);

// zen::utils (logging)
std::shared_ptr<ILogger> createConsoleLogger(name, LoggerLevel);
void zen::setGlobalLogger(ILogger);

// zen::utils (others)
void printTypedValueArray(std::vector<TypedValue> const&);
```

### Host 模块描述符（可选）

- `ZEN_ENABLE_BUILTIN_WASI`: `wasi_snapshot_preview1`
- `ZEN_ENABLE_BUILTIN_ENV`: `env`
- `ZEN_ENABLE_EVMABI_TEST`: `env`（复用 evmabimock 上下文）

## 权限与不变量

- **单主流程**: `main()` 为单线程、顺序执行，无并发 CLI 子命令
- **配置校验**: 创建 `Runtime` 前依赖 `RuntimeConfig::validate()`；`--enable-gdb-tracing-hook` 时强制禁用 multipass 多线程
- **EVM 模式限制**: EVM 运行时不支持 `singlepass`；`Config.Mode != RunMode::SinglepassMode`
- **隔离与实例生命周期**: `createManagedIsolation` → `createInstance` / `createEVMInstance` → 调用 → `deleteInstance` / `deleteEVMInstance` → `deleteManagedIsolation`
- **Benchmark 模式**: `--benchmark` 且 `NDEBUG` 下使用 `_exit()` 或 `::exit()` 提前终止，避免释放资源以缩短测量时间

## 错误码

| 来源 | 含义 |
|------|------|
| `EXIT_FAILURE` | 解析失败、运行时创建失败、模块/实例加载失败、Host 模块加载失败、调用失败、状态保存失败等 |
| `EXIT_SUCCESS` | WASM 模式下未启用 WASI 时的默认成功码 |
| `Inst->getExitCode()` | WASM 模式下启用 WASI 时，由 WASI `proc_exit` 设置的退出码 |
| `evmc_status_code` | EVM 模式下，将 `ExeResult.status_code` 直接作为进程退出码（如 `EVMC_SUCCESS`、`EVMC_REVERT` 等） |

解析或初始化阶段的失败统一返回 `EXIT_FAILURE`，不输出 `evmc_status_code`。

## 兼容性策略

- **编译宏**: 行为由 `ZEN_ENABLE_EVM`、`ZEN_ENABLE_BUILTIN_WASI`、`ZEN_ENABLE_BUILTIN_ENV`、`ZEN_ENABLE_EVMABI_TEST`、`ZEN_ENABLE_MULTIPASS_JIT`、`ZEN_ENABLE_PROFILER` 等控制
- **EVM 选项**: 仅在 `ZEN_ENABLE_EVM` 下提供 `--format evm`、`--calldata`、`--evm-revision`、`--deploy`、`--contract-address`、`--sender`、`--save-state`、`--load-state` 等
- **singlepass 选项**: 在 `ZEN_ENABLE_EVM` 构建下，`--mode` 不提供 `singlepass`
- **Multipass 选项**: 仅在 `ZEN_ENABLE_MULTIPASS_JIT` 下提供 `--disable-multipass-greedyra`、`--disable-multipass-multithread`、`--num-multipass-threads`、`--enable-multipass-lazy`、`--enable-evm-gas`、`--entry-hint`
- **EVM 版本**: 支持 `frontier` 至 `osaka` 等 `evmc_revision`，默认 `EVMC_CANCUN`

## 交叉引用

- [runtime 模块](../runtime/spec.md): `Runtime`、`RuntimeConfig`、`Module`、`Instance`、`Isolation`、`HostModule`
- [common 模块](../common/spec.md): `InputFormat`、`RunMode`、`TypedValue`、`Error`、`MayBe`
- [utils 模块](../utils/spec.md): 日志、地址解析、hex 转换、状态持久化
- [evm 模块](../evm/spec.md): EVM 执行、`evmc_revision`、`DEFAULT_REVISION`
- [host 模块](../host/spec.md): WASI、env、evmabimock 等 host 模块
