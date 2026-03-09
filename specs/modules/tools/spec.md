# tools 模块规范

> 目录: `tools/`

## 边界与职责

tools 模块提供**开发辅助脚本**，负责：

- **代码格式化**：C/C++、CMake、EVM ASM 的格式检查与自动修正
- **EVM 测试工具**：EVM 汇编转字节码、EVM 测试运行器、状态根/MPT 比对
- **Solidity 编译**：批量编译 Solidity 合约为 JSON
- **静态分析**：clang-tidy 并行运行、性能回归检查
- **调试辅助**：GDB 追踪、CPU trace 收集

本模块不包含：构建系统（CMake）、测试框架（gtest/ctest）、核心运行时逻辑。

## 核心概念

### 1. 格式化 (format.sh)

- **check**：检查 CMake、C/C++、EVM ASM 格式，失败则退出
- **format**：自动格式化 CMake（cmake-format）、C/C++（clang-format）、EVM ASM（去尾空格、补末尾换行）
- **tidy-check**：clang-tidy 命名规范检查（需 build 目录）
- **依赖**：clang-format、clang-tidy、cmake-format

### 2. EVM 字节码与测试

| 脚本 | 职责 |
|------|------|
| easm2bytecode.py | EVM 汇编（.easm）→ 字节码（.hex），opcode 映射表 |
| easm2bytecode.sh | 批量调用 easm2bytecode.py |
| run_evm_tests.py | 驱动 dtvm CLI 执行 evm_asm 测试，统计 succ/fail/ignore，支持 --format evm、--mode |

### 3. Solidity 编译

- **solc_batch_compile.sh**：遍历 `tests/evm_solidity/*/`，对目录名同名 `.sol` 调用 solc，输出 `contract.json`（含 bin、bin-runtime、ABI）
- **依赖**：solc、solc-select、jq

### 4. MPT / 状态根比对

| 脚本 | 职责 |
|------|------|
| mpt_compare_py.py | Python 实现 MPT 状态根计算，用于与 C++ `mpt_compare_cpp` 对照 |
| compare_mpt.sh | 调用 MPT 比对工具 |

### 5. 静态分析与性能

| 脚本 | 职责 |
|------|------|
| run-clang-tidy.py | LLVM 风格并行 clang-tidy，基于 compile_commands.json |
| check_performance_regression.py | 运行 evmone benchmark，与 baseline 对比，阈值可配置（默认 10%） |

### 6. 调试与追踪

| 脚本 | 职责 |
|------|------|
| gdb_trace.py | GDB 驱动 dtvm，捕获 backtrace、CPU 追踪日志 |
| collect_cpu_trace.py | 收集 CPU 追踪数据 |
| bug_finder.py | 二分搜索触发异常的 `GREEDY_FUNC_IDX_*` 范围（实验性） |

### 7. 杂项

| 脚本 | 职责 |
|------|------|
| function_selector.py | 计算 Solidity 函数选择器（keccak256 前 4 字节） |
| requirements.txt | Python 依赖（PyYAML、rlp、eth-hash、trie 等） |

## 外部契约

| 外部依赖 | 用途 |
|----------|------|
| clang-format | C/C++ 格式化 |
| clang-tidy | 静态检查 |
| cmake-format | CMake 格式化 |
| solc / solc-select | Solidity 编译 |
| dtvm | EVM/WASM 执行（run_evm_tests、bug_finder） |
| gdb | 调试追踪 |
| Python 3 | PyYAML、Crypto、rlp、eth-hash、trie |

## 权限与不变量

- **只读偏好**：格式化脚本默认 check 不修改文件，format 才写入
- **路径**：默认以项目根为工作目录，相对路径指向 `tests/`、`build/`
- **幂等**：easm2bytecode、solc_batch_compile 可重复执行

## 兼容性策略

- **工具链版本**：依赖系统/流水线安装的 clang、solc、Python；`requirements.txt` 锁定 pip 依赖
- **平台**：format.sh、easm2bytecode.sh 为 bash；Python 脚本跨平台

## 交叉引用

- [specs/testing/README.md](../testing/README.md) — 测试运行说明
- [docs/start.md](../../docs/start.md) — 构建与依赖
- [specs/modules/tests/spec.md](./tests/spec.md) — 测试模块
