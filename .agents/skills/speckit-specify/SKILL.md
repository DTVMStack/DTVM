---
name: speckit-specify
description: 从自然语言描述创建或更新功能规格说明书。生成功能目录结构、spec.md 模板，并支持智能编号和分支管理。
---

# 功能规格生成

根据自然语言功能描述创建或更新功能规格说明书（spec.md）。

## 用户输入

你输入的内容（对话中的功能描述）即为功能描述。

## 交接点

- **Build Technical Plan** → 调用 `/speckit-plan`："Create a plan for the spec. I am building with..."
- **Clarify Spec Requirements** → 调用 `/speckit-clarify`："Clarify specification requirements"（send: true）

## 执行步骤

### 1. 生成简洁的短名称

分析功能描述，提取最有意义的关键词：

- 使用 2-4 个词的短名称来概括功能本质
- 使用动作-名词格式（如 "add-user-auth", "fix-payment-bug"）
- 保留技术术语和缩写（OAuth2, API, JWT 等）
- 保持简洁但足够描述功能
- 功能目录将创建为 `specs/features/NNN-short-name`（如 `specs/features/001-user-auth`）
- 分支引用使用 `feature/` 前缀（如 `feature/001-user-auth`）- 注意：默认不创建分支

**示例**：
- "I want to add user authentication" → feature: `001-user-auth`
- "Implement OAuth2 integration for the API" → feature: `002-oauth2-api-integration`
- "Create a dashboard for analytics" → feature: `003-analytics-dashboard`
- "Fix payment processing timeout bug" → feature: `004-fix-payment-timeout`

### 2. 初始化功能规格目录

**a. 确定编号来源**（全局最大策略）：
- 现有功能目录: `specs/features/[0-9]+-*`
- 现有本地/远程 git 功能分支（如果 git 可用）
- 使用最高编号 + 1 作为下一个功能编号

**b. 使用 `create-new-feature.sh` 创建功能脚手架**：
- 默认模式（推荐）：不切换分支，只创建 `specs/features/NNN-short-name/`
- 可选：仅在明确请求时添加 `--switch-branch` 或 `--worktree`
- 示例（默认）：
  ```bash
  .specify/scripts/bash/create-new-feature.sh --json --number 5 --short-name "user-auth" "Add user authentication"
  ```
- 示例（带分支）：
  ```bash
  .specify/scripts/bash/create-new-feature.sh --json --switch-branch --number 5 --short-name "user-auth" "Add user authentication"
  ```
- 示例（worktree）：
  ```bash
  .specify/scripts/bash/create-new-feature.sh --json --worktree --number 5 --short-name "user-auth" "Add user authentication"
  ```

**c. 解析脚本的 JSON 输出**：
- `FEATURE_DIR`
- `SPEC_FILE`
- `BRANCH_NAME`（如果创建）
- `WORKTREE_PATH`（如果 worktree 模式）

**重要**：
- 此仓库默认使用单分支工作流；不要求创建分支
- 编号基于全局最大功能索引，而非短名称本地索引
- 必须只运行此脚本一次

### 3. 加载规格模板

加载 `.specify/templates/spec-template.md` 了解所需章节。

### 4. 执行流程

1. **解析输入**：从对话中获取功能描述
   - 如果为空：错误 "No feature description provided"

2. **提取关键概念**：从描述中识别
   - 参与者 (actors)
   - 动作 (actions)
   - 数据 (data)
   - 约束 (constraints)

3. **对于不明确的方面**：
   - 根据上下文和行业标准做出合理假设
   - 仅在以下情况下标记 `[NEEDS CLARIFICATION: 具体问题]`：
     - 选择显著影响功能范围或用户体验
     - 存在多种合理解释但影响不同
     - 没有合理的默认值
   - **限制**：最多 3 个 `[NEEDS CLARIFICATION]` 标记
   - 按影响优先级排序：范围 > 安全/隐私 > 用户体验 > 技术细节

4. **填写用户场景和测试部分**
   - 如果无法确定用户流程：错误 "Cannot determine user scenarios"

5. **生成功能需求**
   - 每个需求必须可测试
   - 对未指定的细节使用合理默认值（在假设部分记录）

6. **定义成功标准**
   - 创建可衡量的、技术无关的结果
   - 包含定量指标（时间、性能、数量）和定性措施（用户满意度、任务完成率）
   - 每个标准必须在没有实现细节的情况下可验证

7. **识别关键实体**（如涉及数据）

8. **返回**：SUCCESS（规格已准备好规划）

### 5. 将规格写入 SPEC_FILE

使用模板结构，将占位符替换为从功能描述中派生的具体细节，同时保留章节顺序和标题。

### 6. 规格质量验证

**a. 创建规格质量清单**：
在 `FEATURE_DIR/checklists/requirements.md` 创建清单文件

**b. 运行验证检查**：
根据每个清单项验证规格

**c. 处理验证结果**：
- **如果所有项目通过**：标记清单完成
- **如果项目失败**（排除 `[NEEDS CLARIFICATION]`）：更新规格并重新验证
- **如果 `[NEEDS CLARIFICATION]` 标记仍然存在**：向用户呈现选项

### 7. 报告完成

返回功能 ID、规格文件路径、清单结果，以及下一阶段的准备情况（`/speckit-clarify` 或 `/speckit-plan`）。

**注意**：默认情况下，脚本不创建或切换分支。规格文件在当前分支的 `specs/features/` 中创建。使用 `--switch-branch` 或 `--worktree` 标志来创建分支。

## 通用指南

### 快速指南

- 专注于**用户需要什么**和**为什么**
- 避免**如何实现**（无技术栈、API、代码结构）
- 为业务利益相关者编写，而非开发者
- 不要创建嵌入在规格中的任何清单

### 章节要求

- **必填章节**：每个功能必须完成
- **可选章节**：仅在相关时包含
- 当章节不适用时，完全删除（不要留作 "N/A"）

### AI 生成指南

创建规格时：

1. **做出合理假设**：使用上下文、行业标准和常见模式来填补空白
2. **记录假设**：在假设部分记录合理的默认值
3. **限制澄清**：最多 3 个 `[NEEDS CLARIFICATION]` 标记
4. **优先考虑澄清**：范围 > 安全/隐私 > 用户体验 > 技术细节
5. **像测试人员一样思考**：每个模糊的需求都应该无法通过"可测试且明确"的清单项

**合理默认值示例**（不要问这些）：
- 数据保留：行业标准的领域实践
- 性能目标：除非另有说明，否则为标准 Web/移动应用期望
- 错误处理：带有适当回退的用户友好消息
- 认证方法：Web 应用的标准会话或 OAuth2
- 集成模式：除非另有说明，否则为 RESTful API

### 成功标准指南

成功标准必须：

1. **可衡量**：包含具体指标（时间、百分比、数量、比率）
2. **技术无关**：不提及框架、语言、数据库或工具
3. **以用户为中心**：从用户/业务角度描述结果，而非系统内部
4. **可验证**：可以在不知道实现细节的情况下测试/验证

**好的示例**：
- "用户可以在 3 分钟内完成结账"
- "系统支持 10,000 并发用户"
- "95% 的搜索在 1 秒内返回结果"
- "任务完成率提高 40%"

**坏的示例**（以实现为中心）：
- "API 响应时间低于 200ms"（太技术化）
- "数据库可处理 1000 TPS"（实现细节）
- "React 组件高效渲染"（特定于框架）
- "Redis 缓存命中率超过 80%"（特定于技术）
