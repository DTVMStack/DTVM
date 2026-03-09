# DTVM 项目宪法

项目原则与开发约束的权威文档。所有开发活动（包括 AI 辅助开发）应遵循本文档定义的原则。

---

## 项目愿景

### 目的与目标

DTVM（DeTerministic Virtual Machine）是面向区块链的下一代确定性虚拟机，解决区块链网络中的性能、确定性和生态兼容性问题。基于 WebAssembly 构建，同时保持完整的 EVM ABI 兼容性。

### 核心价值

1. **确定性优先**：非WASI的所有执行路径必须在任意平台上产生完全一致的结果，这是区块链共识的基础
2. **高性能执行**：通过 Lazy-JIT 编译框架（dMIR 中间表示）提供多层级优化（O0~O2），在编译效率和执行速度之间取得平衡
3. **生态兼容**：支持 EVM 和 WASM 兼容
4. **安全可信**：支持 TEE 原生执行（Intel SGX），最小化可信计算基

### 目标用户

- 区块链平台开发者（集成 DTVM 作为执行引擎）
- 智能合约开发者（使用多语言 SDK 开发合约）
- 区块链基础设施研究人员
- Wasm用户
- 需要安全工具沙箱的Agent用户

### 成功定义

- 通过全部 WebAssembly 规范测试和 EVM 规范测试
- 跨平台（x86-64 / ARM64、Linux / macOS）执行结果完全一致
- 性能优于主流同类虚拟机实现
- SGX 环境下稳定运行

---

## 技术约束

### 架构模式

- **模块化分层架构**：`src/` 下按功能划分模块（runtime、compiler、singlepass、evm、host 等），各模块通过 `specs/modules/` 下的 spec.md 定义边界与契约
- **中间表示驱动**：所有前端指令集（Wasm、EVM、未来的 RISC-V）统一翻译为 dMIR，再由后端生成目标代码
- **多执行模式**：interpreter（解释执行）、singlepass JIT（单遍编译）、multipass JIT（多遍优化编译，依赖 LLVM 15）
- **EVMC 接口**：通过标准 EVMC 接口提供 EVM 兼容性

### 平台要求

| 维度 | 支持范围 |
|------|----------|
| CPU 架构 | x86-64、ARM64（aarch64） |
| 操作系统 | Linux、macOS（Darwin） |
| TEE | Intel SGX（可选） |
| 编译器 | GCC >= 9.4.0 |
| LLVM | 15（仅 multipass JIT 需要） |

### 依赖管理

- **第三方代码**：统一存放在 `third_party/`，仅在明确需要时修改
- **LLVM**：multipass JIT 的外部依赖，通过 CMake `LLVM_DIR` 配置
- **Docker**：提供 `dtvmdev1/dtvm-dev-x64:main` 开发环境镜像

---

## 质量标准

### 代码风格

- 编译选项强制 `-Wall -Wextra`，禁用 RTTI（`-fno-rtti`）
- 命名和格式遵循项目现有模式（参考 `src/` 中既有代码）
- 注释只用于解释非显而易见的意图、权衡或约束，不使用叙述性注释

### 确定性保证

**最高优先级约束**：所有执行路径必须是确定性的。

- 禁止使用 `rand()`、`time()` 等非确定性系统调用影响执行结果
- 禁止依赖未初始化内存
- 禁止依赖指针地址排序
- 浮点运算必须处理 NaN 规范化
- 内存分配模式不得影响执行语义

### 测试要求

| 测试类型 | 工具 | 说明 |
|----------|------|------|
| Wasm 规范测试 | specUnitTests | 三种执行模式（0/1/2）全部通过 |
| EVM 规范测试 | `tests/evm_spec_test/` | EVM 兼容性验证 |
| dMIR 测试 | lit + `tests/mir/` | 中间表示正确性 |
| 内存安全 | ASan（`ZEN_ENABLE_ASAN`） | 无内存泄漏和越界 |

- 任何行为变更必须附带测试更新或新增测试
- 三种执行模式的测试结果必须一致
- 如未运行测试，必须在变更说明中明确指出

### 性能基准

- JIT 编译不应引入超出预期的延迟
- 解释器作为功能基准，JIT 模式性能应优于解释器
- 关注 gas 计量的准确性和开销

---

## 开发流程

### Git 工作流

- 基于分支开发，通过 Pull Request 合并到主分支
- Fork → Branch → Implement → Test → PR → Review → Merge
- 遵循 [CONTRIBUTING.md](../../CONTRIBUTING.md) 的贡献流程

### 提交规范

严格遵循 [Conventional Commits](https://www.conventionalcommits.org/)，详见 `docs/COMMIT_CONVENTION.md`：

```
<type>[optional scope]: <description>
```

- **type**：feat / fix / docs / style / refactor / perf / test / build / ci / chore
- **scope**：core / runtime / compiler / evm / tools / deps / ci / test / docs 等
- **description**：祈使句、现在时、首字母小写、无句号
- 通过 GitHub Actions 自动验证提交格式

### Spec-Kit + SSOT 开发模型

本项目采用规范驱动开发（SDD）：

1. **模块规范**（`specs/modules/`）：每个模块有 `spec.md` 和 `data-model.md`，定义模块边界、API 契约和数据模型
2. **功能开发**（`specs/features/`）：新功能遵循 speckit 工作流：specify → clarify → plan → tasks → implement
3. **变更管理**：架构级变更通过 `specs/features/` 中的提案流程管理

### 变更决策树

```
新需求？
├─ 修复 Bug（恢复预期行为）？ → 直接修复
├─ 格式/注释/拼写修正？ → 直接修复
├─ 新功能/能力？ → 创建功能规范
├─ 破坏性变更？ → 创建功能规范
├─ 架构变更？ → 创建功能规范
└─ 不确定？ → 创建功能规范（更安全）
```

### 代码审查要求

- 所有变更通过 PR 审查后合并
- 审查重点：确定性保证、内存安全、测试覆盖、模块边界合规
- AI 辅助开发的变更同样需要人工审查

---

## 安全与合规

### 确定性执行安全

- 虚拟机执行引擎是安全关键组件，任何非确定性行为可能导致区块链分叉
- Gas 计量必须精确，防止 DoS 攻击
- 内存边界检查（`ZEN_ENABLE_JIT_BOUND_CHECK`）在生产环境中启用
- 栈溢出保护和虚拟栈支持

### TEE 安全

- SGX 模式下禁用 C++17 STL（`ZEN_DISABLE_CXX17_STL`）
- 最小化 TCB（可信计算基）
- SGX 模式下禁用 spdlog 等非必要依赖

### 内存安全

- 使用 ASan 进行内存泄漏检测
- JIT 编译生成的代码必须包含边界检查
- CPU 异常机制（`ZEN_ENABLE_CPU_EXCEPTION`）实现 Wasm trap

### 许可证合规

- 项目主体：Apache License 2.0
- LLVM 相关代码：Apache 2.0 + BSD 3-Clause
- 所有源文件必须包含版权头：`Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.`
- 第三方组件许可信息记录在 `NOTICE` 文件中
- 贡献者需同意 CLA（Contributor License Agreement）

---

## 团队协作

### 沟通协议

- 技术讨论通过 GitHub Issues 和 Pull Requests 进行
- 重大设计决策通过 specs 目录下的提案文档记录
- AI 辅助开发遵循 `AGENTS.md` 和 `specs/AGENTS.md` 中的行为准则

### 决策流程

- Bug 修复和小改动：开发者自主决策，PR 审查确认
- 新功能/架构变更：通过 speckit 工作流，经规范审查后实施
- 破坏性变更：必须在提交信息中标注 `BREAKING CHANGE`

### 知识管理

- 模块契约文档化在 `specs/modules/` 中
- 构建和使用指南在 `docs/` 中
- 宪法和记忆文档在 `.specify/memory/` 中
- AI Agent 行为规则在 `AGENTS.md` 和 `specs/AGENTS.md` 中

### 编辑纪律

- 保持修改最小化和局部化，遵循既有模式
- 优先修改 `src/` 中的代码，仅在明确需要时修改 `third_party/`
- 代码与规范冲突时，代码优先，但需同步更新规范
- 不在功能规范中重复模块 SSOT 内容，使用引用

---

## 仓库结构

```
DTVM/
├── src/                    # 核心源码
│   ├── runtime/            # 运行时
│   ├── compiler/           # 编译器
│   ├── singlepass/         # Singlepass JIT
│   ├── evm/                # EVM 支持
│   ├── host/               # Host 接口
│   ├── action/             # Action 处理
│   ├── cli/                # 命令行接口
│   ├── common/             # 公共组件
│   ├── platform/           # 平台抽象
│   ├── utils/              # 工具函数
│   ├── vm/                 # VM 核心
│   ├── wni/                # Wasm Native Interface
│   ├── entrypoint/         # 入口点
│   └── tests/              # 测试
├── tests/                  # 测试用例
│   ├── wast/               # Wasm 规范测试
│   ├── evm_spec_test/      # EVM 规范测试
│   └── mir/                # dMIR 测试
├── evmc/                   # EVMC 兼容层
├── rust_crate/             # Rust 绑定
├── third_party/            # 第三方依赖
├── tools/                  # 辅助工具
├── docs/                   # 文档
├── specs/                  # SDD 规范
│   ├── modules/            # 模块规范
│   └── features/           # 功能规范
├── .agents/skills/         # AI Agent 技能
└── .specify/               # Spec-Kit 配置
```

---

*最后更新：2026-03-13*
