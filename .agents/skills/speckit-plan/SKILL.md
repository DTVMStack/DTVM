---
name: speckit-plan
description: 执行实现计划工作流程，使用计划模板生成设计工件（research.md、data-model.md、contracts/、quickstart.md、plan.md）。
---

# 技术设计规划

执行实现计划工作流程，生成设计工件。

## 用户输入

你输入的内容即为上下文。

## 交接点

- **Create Tasks** → 调用 `/speckit-tasks`："Break the plan into tasks"（send: true）
- **Create Checklist** → 调用 `/speckit-checklist`："Create a checklist for the following domain..."

## 执行步骤

### 1. 设置

从仓库根目录运行 `.specify/scripts/bash/setup-plan.sh --json` 并解析 JSON 获取：
- FEATURE_SPEC
- IMPL_PLAN
- SPECS_DIR
- BRANCH

### 2. 加载上下文

读取：
- FEATURE_SPEC（功能规格）
- `.specify/memory/constitution.md`（项目原则）
- IMPL_PLAN 模板（已复制）

### 3. 执行计划工作流程

按照 IMPL_PLAN 模板结构：
- 填写技术上下文（标记未知项为 "NEEDS CLARIFICATION"）
- 从 constitution 填写原则检查部分
- 评估门槛（违规未证明时错误）
- **阶段 0**：生成 research.md（解决所有 NEEDS CLARIFICATION）
- **阶段 1**：生成 data-model.md、contracts/、quickstart.md
- **阶段 1**：运行 agent 脚本更新 agent 上下文
- 设计后重新评估原则检查

### 4. 停止并报告

命令在阶段 2 规划后结束。报告分支、IMPL_PLAN 路径和生成的工件。

## 阶段详情

### 阶段 0: 大纲与研究

1. 从技术上下文提取未知项：
   - 每个 NEEDS CLARIFICATION → 研究任务
   - 每个依赖 → 最佳实践任务
   - 每个集成 → 模式任务

2. 生成并派发研究代理

3. 在 `research.md` 中整合发现，使用格式：
   - Decision: [选择了什么]
   - Rationale: [为什么选择]
   - Alternatives considered: [还评估了什么]

**输出**：research.md，所有 NEEDS CLARIFICATION 已解决

### 阶段 1: 设计与合约

**前置条件**：`research.md` 完成

1. 从功能规格提取实体 → `data-model.md`：
   - 实体名称、字段、关系
   - 来自需求的验证规则
   - 状态转换（如适用）

2. 从功能需求生成 API 合约：
   - 每个用户操作 → 端点
   - 使用标准 REST/GraphQL 模式
   - 将 OpenAPI/GraphQL schema 输出到 `/contracts/`

3. Agent 上下文更新：
   - 运行 `.specify/scripts/bash/update-agent-context.sh cursor-agent`
   - 脚本检测使用的是哪个 AI agent
   - 更新相应的 agent 特定上下文文件
   - 只添加当前计划中的新技术
   - 保留标记之间的手动添加

**输出**：data-model.md、/contracts/*、quickstart.md、agent 特定文件

## 关键规则

- 使用绝对路径
- 门槛失败或未解决的澄清时错误
