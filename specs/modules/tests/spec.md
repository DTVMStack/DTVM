# tests 模块规范

> 目录: `src/tests/` + `tests/`

## 边界与职责

tests 模块为 DTVM 提供**测试基础设施**，负责：

- **WAST 规范测试**：WebAssembly 规范一致性测试，解析 `.wast`/`.json`，执行 `assert_return`、`assert_trap` 等断言
- **EVM Assembly 单元测试**：单操作码级别的 EVM 字节码测试（`.easm` → `.hex` + `.expected` YAML）
- **Ethereum State 测试**：官方 Ethereum 状态转换测试套件（JSON pre/post 状态、交易执行）
- **Solidity 合约测试**：端到端智能合约测试（编译后 JSON + `test_cases.json`）
- **dMIR 测试**：中间表示验证（`.ir` + lit/FileCheck）
- **C API 测试**：`zetaengine-c.h` 对外接口验证
- **Evmone 集成测试**：Evmone 单元测试框架对接（`ZEN_ENABLE_LIBEVM`）

本模块不包含：EVM 解释器实现（evm）、Host 实现（host）、编译器实现（compiler）。

## 核心概念

### 1. WAST 规范测试 (specUnitTests)

- **SpecTest**：解析 `.wast` 转 JSON，枚举测试用例 `(category, unit)`，执行 `module`/`action`/`assert_*` 命令
- **CommandID**：`Module`、`Action`、`Register`、`AssertReturn`、`AssertTrap`、`AssertExhaustion`、`AssertMalformed`、`AssertInvalid`、`AssertUnlinkable`、`AssertUninstantiable`
- **运行模式**：通过 `RuntimeConfig` 选择 interpreter / singlepass / multipass，`specUnitTests <case> <mode>`
- **目录**：`tests/wast/`（`spec/test/core`、`proposals`、`gas`、`exception`、`multipass`、`dwasm` 等）
- **依赖**：`wast2json` 将 `.wast` 转为 JSON，`RunSpecTests.cmake` 作为 CTest 包装

### 2. EVM Assembly Sample Tests

- **evmInterpTests**：遍历 `tests/evm_asm/*.hex`，按 `.expected` YAML 校验 `status`、`stack`、`memory`、`storage`、`transient_storage`、`return`、`events`
- **输入格式**：`.easm`（文本指令）经 `tools/easm2bytecode.py` 转为 `.hex` 字节码
- **期望格式**：YAML，支持 `status`（SUCCESS/REVERT 等）、`error_code`、`stack`、`memory`、`storage`、`transient_storage`、`return`、`events`
- **Host**：`ZenMockedEVMHost` 提供 Mock 账户、存储、调用能力

### 3. Ethereum State Test Execution

- **evmStateTests**：加载 `tests/evm_spec_test/state_tests/` 下 JSON，按 `pre`/`env`/`transaction`/`post` 执行
- **StateTestFixture**：`TestName`、`PreState`、`Environment`、`Transaction`、`Post`
- **Fork 支持**：`post` 按 fork（Frontier~Prague）索引，`DTVM_TEST_REVISION` 环境变量过滤
- **验证**：`verifyPostState` 比对状态根、日志哈希；`verifyStateRoot`、`verifyLogsHash`
- **预置**：`parsePreAccounts`、`parseStateTestFile`、`createTransactionFromIndex`

### 4. Test Utilities and Fixtures

- **evm_test_helpers.h**：`TempHexFile`、`addAccountToMockedHost`、`calculateLogsHash`、`verifyStateRoot`、`verifyPostState`、`mapForkToRevision`、`decimalToHex`、`padAddressTo32Bytes`
- **evm_test_fixtures.h**：`ParsedAccount`、`ParsedTransaction`、`StateTestFixture`、`ForkPostResult`、`parsePreAccounts`、`parseStateTestFile`、`findJsonFiles`
- **evm_test_host.hpp**：`ZenMockedEVMHost`（递归 Host、CALL 子调用、Gas 计费、预暖存储、自毁等）
- **solidity_test_helpers.h**：`SolidityTestCase`、`SolcContractData`、`SolidityContractTestData`、`EVMTestEnvironment`、`DeployedContract`、`deployContract`、`executeContractCall`、`parseTestCaseJson`、`computeFunctionSelector`、`encodeAbiParam`
- **test_utils.h**：`findExecutableDir()` 定位可执行目录

### 5. Solidity Contract Tests

- **solidityContractTests**：按 `RunSpecTests.cmake` 驱动，遍历 `tests/evm_solidity/*/` 目录
- **结构**：每目录含 `*.sol`、`contract.json`（solc 输出）、`test_cases.json`（函数名、calldata、期望）
- **准备**：`tools/solc_batch_compile.sh` 批量编译
- **执行**：部署合约 → 调用函数 → 校验 `evmc_status_code` 与返回值

### 6. MIR 测试

- **目录**：`tests/mir/*.ir`
- **工具**：`lit` + `ircompiler`，`test_mir.sh`
- **格式**：dMIR 文本 + FileCheck 指令

### 7. C API 测试

- **cAPITests**：使用 `ZenRuntimeRef`、`ZenCreateRuntime`、`ZenLoadHostModule`、`ZenCreateInstance` 等 C API
- **用例**：加载内嵌 WASM、注册 Host 函数、调用导出函数

### 8. Evmone Fallback 测试

- **evmFallbackExecutionTests**：需 `ZEN_ENABLE_LIBEVM`，验证 JIT 异常时回退到解释器
- **依赖**：dtvmapi 库

## 外部契约

| 依赖模块   | 契约说明 |
|------------|----------|
| runtime    | `Runtime`、`EVMInstance`、`Isolation`、`EVMModule` 提供执行环境 |
| evm        | `Interpreter`、`ZenMockedEVMHost`、`evmc_revision` |
| host       | `evm::crypto::keccak256`、预编译实现 |
| common     | `TypedValue`、`RunMode`、`ErrorCode` |
| utils      | `toHex`、`parseUint256`、`parseAddress`、`parseBytes32`、`parseHexData`、`stripHexPrefix`、RLP 编码 |
| evmc       | `evmc::MockedHost`、`evmc_message`、`evmc_tx_context`、`evmc_revision` |
| rapidjson  | JSON 解析与生成 |
| yaml-cpp   | EVM `.expected` 解析 |
| googletest | `gtest`、`TestWithParam` |

## 权限与不变量

- **确定性**：测试结果与执行顺序无关，无主机相关非确定性行为
- **隔离性**：各测试用例间状态隔离，无共享可变全局
- **前置条件**：EVM 测试需 `tools/easm2bytecode.sh`/`solc_batch_compile.sh` 预处理；State 测试需 JSON 符合 Ethereum 规范
- **构建开关**：`ZEN_ENABLE_SPEC_TEST` 启用测试目标；`ZEN_ENABLE_EVM` 启用 EVM 相关；`ZEN_ENABLE_LIBEVM` 启用 evmone 集成

## 错误码

| 错误码           | 来源          | 说明 |
|------------------|---------------|------|
| 测试失败         | gtest         | 断言失败、期望不匹配 |
| JSON 解析失败    | rapidjson     | `HasParseError` |
| 文件 I/O 失败    | evm_test_*    | 临时文件创建失败、目录不存在 |
| EVMC 状态码      | evmc          | `EVMC_*` 执行结果 |

## 兼容性策略

- **Fork 兼容**：State 测试按 `evmc_revision` 选择 `post` 分支，新 fork 需扩展 `mapForkToRevision`
- **格式兼容**：EVM `.expected` YAML、State JSON 遵循 Ethereum 测试套件约定；WAST 遵循 WebAssembly 规范
- **工具链**：`wast2json`、`solc`、`lit` 版本依赖见 `docs/start.md`、`tools/requirements.txt`

## 交叉引用

- [specs/testing/README.md](../testing/README.md) — 完整测试指南
- [specs/modules/evm/spec.md](./evm/spec.md) — EVM 解释器规范
- [specs/modules/runtime/spec.md](./runtime/spec.md) — 运行时与实例
- [AGENTS.md](../../AGENTS.md) — 构建与测试命令
