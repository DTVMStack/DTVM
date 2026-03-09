---
name: speckit-tasks
description: 基于可用的设计工件生成可操作的、依赖有序的 tasks.md 任务列表。
---

# 任务列表生成

基于可用的设计工件生成可操作的、依赖有序的 tasks.md。

## 用户输入

你输入的内容即为上下文。

## 交接点

- **Analyze For Consistency** → 调用 `/speckit-analyze`："Run a project analysis for consistency"（send: true）
- **Implement Project** → 调用 `/speckit-implement`："Start the implementation in phases"（send: true）

## 执行步骤

### 1. 设置

从仓库根目录运行 `.specify/scripts/bash/check-prerequisites.sh --json` 并解析：
- FEATURE_DIR
- AVAILABLE_DOCS 列表

所有路径必须是绝对路径。

### 2. 加载设计文档

从 FEATURE_DIR 读取：

**必需**：
- plan.md（技术栈、库、结构）
- spec.md（User Story及其优先级）

**可选**：
- data-model.md（实体）
- contracts/（API 端点）
- research.md（决策）
- quickstart.md（测试场景）

注意：并非所有项目都有所有文档。基于可用内容生成任务。

### 3. 执行任务生成工作流程

- 加载 plan.md 并提取技术栈、库、项目结构
- 加载 spec.md 并提取User Story及其优先级（P1、P2、P3 等）
- 如果 data-model.md 存在：提取实体并映射到User Story
- 如果 contracts/ 存在：映射端点到User Story
- 如果 research.md 存在：提取设置任务的决策
- 按User Story组织生成任务（见下面的任务生成规则）
- 生成依赖关系图，显示User Story完成顺序
- 为每个User Story创建并行执行示例
- 验证任务完整性（每个User Story具有所有需要的任务，可独立测试）

### 4. 生成 tasks.md

使用 `.specify/templates/tasks-template.md` 作为结构，填写：
- 来自 plan.md 的正确功能名称
- 阶段 1：设置任务（项目初始化）
- 阶段 2：基础任务（所有User Story的阻塞前提条件）
- 阶段 3+：每个User Story一个阶段（按 spec.md 中的优先级顺序）
- 每个阶段包括：故事目标、独立测试标准、测试（如请求）、实现任务
- 最后阶段：完善和跨领域关注点
- 所有任务必须遵循严格的检查清单格式（见下面的任务生成规则）
- 每个任务的清晰文件路径
- 显示故事完成顺序的依赖关系部分
- 每个故事的并行执行示例
- 实现策略部分（MVP 优先、增量交付）

### 5. 报告

输出生成的 tasks.md 路径和摘要：
- 总任务数
- 每个User Story的任务数
- 已识别的并行机会
- 每个故事的独立测试标准
- 建议的 MVP 范围（通常只是User Story 1）
- 格式验证：确认所有任务遵循检查清单格式（复选框、ID、标签、文件路径）

tasks.md 应该立即可执行 - 每个任务必须足够具体，以便 LLM 可以在没有额外上下文的情况下完成它。

## 任务生成规则

**关键**：任务必须按User Story组织，以实现独立实现和测试。

**测试是可选的**：仅在功能规格中明确请求或用户请求 TDD 方法时才生成测试任务。

### 检查清单格式（必需）

每个任务必须严格遵循此格式：

```text
- [ ] [TaskID] [P?] [Story?] Description with file path
```

**格式组件**：

1. **复选框**：始终以 `- [ ]` 开头（markdown 复选框）
2. **任务 ID**：按执行顺序的序号（T001、T002、T003...）
3. **[P] 标记**：仅在任务可并行化时包含（不同的文件，对未完成任务无依赖）
4. **[Story] 标签**：仅User Story阶段任务需要
   - 格式：[US1]、[US2]、[US3] 等（映射到 spec.md 中的User Story）
   - 设置阶段：无故事标签
   - 基础阶段：无故事标签
   - User Story阶段：必须有故事标签
   - 完善阶段：无故事标签
5. **描述**：带有精确文件路径的清晰操作

**示例**：
- ✅ 正确：`- [ ] T001 Create project structure per implementation plan`
- ✅ 正确：`- [ ] T005 [P] Implement authentication middleware in src/middleware/auth.py`
- ✅ 正确：`- [ ] T012 [P] [US1] Create User model in src/models/user.py`
- ✅ 正确：`- [ ] T014 [US1] Implement UserService in src/services/user_service.py`
- ❌ 错误：`- [ ] Create User model`（缺少 ID 和故事标签）
- ❌ 错误：`T001 [US1] Create model`（缺少复选框）
- ❌ 错误：`- [ ] [US1] Create User model`（缺少任务 ID）
- ❌ 错误：`- [ ] T001 [US1] Create model`（缺少文件路径）

### 任务组织

1. **从User Story (spec.md)** - 主要组织：
   - 每个User Story（P1、P2、P3...）都有自己的阶段
   - 将所有相关组件映射到其故事：
     - 该故事需要的模型
     - 该故事需要的服务
     - 该故事需要的端点/UI
     - 如果请求测试：该故事特定的测试
   - 标记故事依赖关系（大多数故事应该是独立的）

2. **从合约**：
   - 将每个合约/端点 → 映射到其服务的User Story
   - 如果请求测试：每个合约 → 该故事阶段中实现前的合约测试任务 [P]

3. **从数据模型**：
   - 将每个实体映射到需要它的User Story
   - 如果实体服务于多个故事：放在最早的故事或设置阶段
   - 关系 → 相应故事阶段中的服务层任务

4. **从设置/基础设施**：
   - 共享基础设施 → 设置阶段（阶段 1）
   - 基础/阻塞任务 → 基础阶段（阶段 2）
   - 故事特定设置 → 在该故事阶段内

### 阶段结构

- **阶段 1**：设置（项目初始化）
- **阶段 2**：基础（阻塞前提条件 - 必须在User Story之前完成）
- **阶段 3+**：按优先级顺序的User Story（P1、P2、P3...）
  - 每个故事内：测试（如请求）→ 模型 → 服务 → 端点 → 集成
  - 每个阶段应该是完整的、可独立测试的增量
- **最后阶段**：完善和跨领域关注点
