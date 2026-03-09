# evm 模块规范

> 目录: `src/evm/`

## 边界与职责

evm 模块实现 DTVM 的 **EVM 解释器核心**，负责：

- **操作码处理**：基于 EVMC 的指令集表，按修订版本（evmc_revision）分发并执行 EVM 操作码
- **Gas 计算**：基础 Gas 计费、内存扩展、存储读写、EIP-2929 冷热访问等的 Gas 规则
- **字节码缓存构建**：构建 JumpDestMap、PushValueMap、GasChunkEnd/GasChunkCost，用于解释器快速路径和 Gas 分块计费
- **EVM 常量与修订版本**：栈深度、内存上限、合约大小限制、Gas 常数、默认修订版本等

本模块不包含：模块加载（runtime）、JIT 编译（compiler）、Host 接口实现（host）、VM 入口（vm-interface）。

## 核心概念

### 1. EVM 模块加载与字节码存储

- 字节码由 `EVMModule`（runtime 模块）持有，evm 模块仅通过 `const EVMModule *` 获取 `Code`、`CodeSize` 和 `getBytecodeCache()`
- 模块加载与持久化由 runtime/action 负责，evm 不涉及文件 I/O

### 2. 字节码缓存构建

- `buildBytecodeCache()` 在首次解释执行或 JIT 执行前被调用（`EVMModule::getBytecodeCache()` 惰性初始化）
- **JumpDestMap**：按 PC 索引，标记有效 JUMPDEST（排除 PUSH 数据区）
- **PushValueMap**：按 PC 索引，存储 PUSHn 立即数（大端、零填充）
- **GasChunkEnd / GasChunkCost**：SPP（Structured Precharging Pass）分块 Gas 计费，将直线段 Gas 预扣，块边界在 JUMPDEST、控制流终结符、SSTORE、CALL/CREATE 等操作码处

### 3. 解释执行上下文与栈安全

- **EVMFrame**：单帧执行状态，包含 Stack（1024 槽）、Memory、CallData、evmc_message、evmc_tx_context、PC、Sp、Value、GasRefundSnapshot
- **InterpreterExecContext**：多帧管理（FrameStack）、执行状态（Status）、返回数据（ReturnData）、evmc::Result
- **BaseInterpreter**：主循环，从 `Context.getCurFrame()` 获取当前帧并执行
- 栈操作 `push()`/`pop()`/`peek()` 在溢出/下溢时抛出 `EVMStackOverflow`/`EVMStackUnderflow`（common::ErrorCode）
- `MAXSTACK = 1024`，与 EVM 规范一致

### 4. 实例级 Gas 计费与内存扩展

- Gas 从 `Frame->Msg.gas` 扣减，失败时设置 `EVMC_OUT_OF_GAS`
- 内存扩展公式：`cost = (new_words²/512 + 3*new_words) - (current_words²/512 + 3*current_words)`，受 `MAX_REQUIRED_MEMORY_SIZE`（16MB）约束
- 存储操作（SSTORE）使用 `SSTORE_COSTS[Rev][Status]` 按修订版本和存储状态计费；Gas refund 在 `EVMInstance` 级别汇总

### 5. 消息栈与返回数据处理

- 调用/创建操作通过 `Frame->Host->call()` 发起子调用，返回数据写入 `InterpreterExecContext::ReturnData`
- RETURN/REVERT 将 `Frame->Memory` 中指定区间拷贝为返回数据，并 `freeBackFrame()` 返回父帧
- STOP 或执行到 CodeSize 外时清空 ReturnData 并结束

### 6. 按修订版本的操作码语义

- 操作码可用性由 `evmc_get_instruction_names_table(Revision)` 判定，未定义则 `EVMC_UNDEFINED_INSTRUCTION`
- Gas 表由 `evmc_get_instruction_metrics_table(Revision)` 提供
- 特殊规则示例：PUSH0 仅 Shanghai+；EXP 的 EXP_BYTE_GAS 在 Spurious Dragon 前为 10；EIP-2929 冷热账户/存储；EIP-3860 initcode 大小限制等

### 7. JIT Fallback 支持

- `InterpreterExecContext::restoreStateFromInstance()` 从 `EVMInstance` 恢复栈、内存、PC，用于 JIT 执行遇异常时回退到解释器
- 保证解释器与 JIT 共享相同的执行语义和 Gas 规则

## 外部契约

| 依赖模块   | 契约说明 |
|------------|----------|
| runtime    | `EVMInstance`、`EVMModule` 提供执行上下文、模块、字节码缓存；`clearReturnDataBuffer()` 清空返回数据 |
| action     | `EVMModuleLoader` 加载字节码；`performEVMJITCompile` 编排 JIT 编译（非本模块） |
| host       | `evmc::Host` 提供账户、存储、调用、日志、密码学等 |
| common     | `Byte`、`ErrorCode`（EVMStackOverflow、EVMStackUnderflow、EVMFrameNotFound 等）、`getError()` |
| evmc       | `evmc_message`、`evmc_tx_context`、`evmc_revision`、`evmc_instruction_metrics`、`evmc_opcode` |

## 权限与不变量

- **确定性**：相同输入（字节码、消息、Host 状态、Revision）产生相同输出，禁止主机相关非确定性行为
- **栈不变量**：`Sp <= MAXSTACK`；`pop`/`peek` 前需 `Sp > 0` 或满足所需槽数
- **PC 合法性**：JUMP/JUMPI 目标必须 `Dest < CodeSize` 且 `JumpDestMap[Dest] == 1`
- **静态模式**：`Msg.flags & EVMC_STATIC` 时禁止 SSTORE、LOG、CALL with value、SELFDESTRUCT、TSTORE

## 错误码

| 错误码                     | 来源        | 说明 |
|---------------------------|-------------|------|
| EVMC_OUT_OF_GAS          | evmc        | Gas 不足 |
| EVMC_STACK_OVERFLOW      | evmc        | 栈溢出 |
| EVMC_STACK_UNDERFLOW     | evmc        | 栈下溢 |
| EVMC_UNDEFINED_INSTRUCTION | evmc      | 未定义操作码 |
| EVMC_INVALID_INSTRUCTION | evmc        | 非法指令（0xfe） |
| EVMC_BAD_JUMP_DESTINATION | evmc       | 非法跳转目标 |
| EVMC_INVALID_MEMORY_ACCESS | evmc      | RETURNDATACOPY 越界等 |
| EVMC_STATIC_MODE_VIOLATION | evmc      | 静态模式下写存储 |
| EVMC_REVERT              | evmc        | REVERT 正常终止 |
| EVMStackOverflow         | common      | 栈溢出（throw） |
| EVMStackUnderflow        | common      | 栈下溢（throw） |
| EVMFrameNotFound         | common      | EVMFrame 为空 |

## 兼容性策略

- 默认修订版本：`DEFAULT_REVISION = EVMC_CANCUN`
- 支持修订版本由 EVMC 库定义（Frontier ~ Experimental），操作码与 Gas 表随 Revision 切换
- 新 EIP 引入时，需同步更新 `gas_storage_cost`、`opcode_handlers` 及 evmc 依赖版本

## 交叉引用

### EVM 执行全链路（跨模块）

EVM 的完整执行流程跨越多个模块：

1. **vm-interface** (`src/vm/`): EVMC `execute()` 入口，`dt_evmc_vm.cpp` 中 `execute()` 接收 `evmc_message`，查找/创建 `EVMModule` 与 `EVMInstance`
2. **runtime** (`src/runtime/`): `EVMModule` 生命周期、`EVMInstance` 创建、`getBytecodeCache()` 惰性构建
3. **action** (`src/action/`): `EVMModuleLoader` 加载字节码，`performEVMJITCompile` 编排 JIT 编译（若启用）
4. **evm** (`src/evm/`): **BaseInterpreter** 解释执行、操作码处理、Gas 计算（**本模块**）
5. **compiler** (`src/compiler/`): `evm_frontend` 将 EVM 字节码编译为 dMIR，`evm_compiler.*` 编排多遍 JIT，实际 JIT 代码不在 evm 模块

### EVM JIT 与解释器协作

- 多遍 JIT 编译在 **compiler** 模块实现，evm 模块不包含 JIT 代码生成
- JIT 执行时可通过 `restoreStateFromInstance()` 回退到解释器（fallback）
- 解释器与 JIT 共用相同的 `evmc_instruction_metrics` 和 `SSTORE_COSTS` 等 Gas 规则，保证跨模式 Gas 一致性

| 被依赖 | 说明 |
|--------|------|
| vm-interface | InterpreterExecContext、BaseInterpreter 解释器路径 |
| compiler | EVM 语义、指令表、evmc_opcode |
| tests | ZenMockedEVMHost、evmc_revision |
