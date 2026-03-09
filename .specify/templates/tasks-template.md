# 任务列表：[功能名称]

**输入**：设计文档来自 `/specs/features/[###-feature-name]/`
**前置条件**：plan.md（必需）、spec.md（User Story 必需）、research.md、data-model.md、contracts/

**测试**：以下示例包含测试任务。测试为可选——仅在功能规格中明确要求时才包含。

**组织方式**：任务按 User Story 分组，以支持每个 Story 的独立实现和测试。

## 格式：`[ID] [P?] [Story] 描述`

- **[P]**：可并行执行（不同文件，无依赖）
- **[Story]**：所属 User Story（例如 US1、US2、US3）
- 描述中包含精确的文件路径

## 路径约定

- **单体项目**：仓库根目录下 `src/`、`tests/`
- **Web 应用**：`backend/src/`、`frontend/src/`
- **移动端**：`api/src/`、`ios/src/` 或 `android/src/`
- 以下路径假设单体项目——根据 plan.md 结构调整

<!--
  ============================================================================
  重要：以下任务为示例占位，仅作说明之用。

  speckit-tasks 技能必须根据以下内容替换为实际任务：
  - spec.md 中的 User Story（含优先级 P1、P2、P3...）
  - plan.md 中的 Functional Requirements
  - data-model.md 中的实体
  - contracts/ 中的端点

  任务必须按 User Story 组织，使每个 Story 可以：
  - 独立实现
  - 独立测试
  - 作为 MVP 增量交付

  不要在生成的 tasks.md 文件中保留这些示例任务。
  ============================================================================
-->

## Phase 1：项目搭建（共享基础设施）

**目的**：项目初始化和基本结构

- [ ] T001 按实现计划创建项目结构
- [ ] T002 初始化 [语言] 项目，配置 [框架] 依赖
- [ ] T003 [P] 配置代码检查和格式化工具

---

## Phase 2：基础设施（阻塞前置条件）

**目的**：必须在任何 User Story 开始前完成的核心基础设施

**⚠️ 关键**：在此阶段完成前，不可开始任何 User Story

基础任务示例（根据项目调整）：

- [ ] T004 搭建数据库 Schema 和迁移框架
- [ ] T005 [P] 实现认证/授权框架
- [ ] T006 [P] 搭建 API 路由和中间件结构
- [ ] T007 创建所有故事依赖的基础模型/实体
- [ ] T008 配置错误处理和日志基础设施
- [ ] T009 搭建环境配置管理

**Checkpoint**：基础设施就绪——User Story 实现现在可以开始

---

## Phase 3：User Story 1 - [标题] (Priority: P1) 🎯 MVP

**目标**：[简要描述此故事交付什么]

**独立测试**：[如何验证此故事独立运行]

### User Story 1 的测试（可选——仅在明确要求时包含）⚠️

> **注意：先编写这些测试，确保实现前它们会失败**

- [ ] T010 [P] [US1] 端点 [endpoint] 的契约测试 tests/contract/test_[name].py
- [ ] T011 [P] [US1] 用户旅程 [journey] 的集成测试 tests/integration/test_[name].py

### User Story 1 的实现

- [ ] T012 [P] [US1] 创建 [Entity1] 模型 src/models/[entity1].py
- [ ] T013 [P] [US1] 创建 [Entity2] 模型 src/models/[entity2].py
- [ ] T014 [US1] 实现 [Service] src/services/[service].py（依赖 T012、T013）
- [ ] T015 [US1] 实现 [endpoint/feature] src/[location]/[file].py
- [ ] T016 [US1] 添加校验和错误处理
- [ ] T017 [US1] 添加 User Story 1 操作的日志

**Checkpoint**：此时 User Story 1 应完全可用并可独立测试

---

## Phase 4：User Story 2 - [标题] (Priority: P2)

**目标**：[简要描述此故事交付什么]

**独立测试**：[如何验证此故事独立运行]

### User Story 2 的测试（可选——仅在明确要求时包含）⚠️

- [ ] T018 [P] [US2] 端点 [endpoint] 的契约测试 tests/contract/test_[name].py
- [ ] T019 [P] [US2] 用户旅程 [journey] 的集成测试 tests/integration/test_[name].py

### User Story 2 的实现

- [ ] T020 [P] [US2] 创建 [Entity] 模型 src/models/[entity].py
- [ ] T021 [US2] 实现 [Service] src/services/[service].py
- [ ] T022 [US2] 实现 [endpoint/feature] src/[location]/[file].py
- [ ] T023 [US2] 与 User Story 1 组件集成（如需要）

**Checkpoint**：此时 User Story 1 和 2 应都能独立工作

---

## Phase 5：User Story 3 - [标题] (Priority: P3)

**目标**：[简要描述此故事交付什么]

**独立测试**：[如何验证此故事独立运行]

### User Story 3 的测试（可选——仅在明确要求时包含）⚠️

- [ ] T024 [P] [US3] 端点 [endpoint] 的契约测试 tests/contract/test_[name].py
- [ ] T025 [P] [US3] 用户旅程 [journey] 的集成测试 tests/integration/test_[name].py

### User Story 3 的实现

- [ ] T026 [P] [US3] 创建 [Entity] 模型 src/models/[entity].py
- [ ] T027 [US3] 实现 [Service] src/services/[service].py
- [ ] T028 [US3] 实现 [endpoint/feature] src/[location]/[file].py

**Checkpoint**：所有 User Story 现在应都能独立运行

---

[根据需要添加更多 User Story 阶段，遵循相同模式]

---

## Phase N：打磨与横切关注点

**目的**：影响多个 User Story 的改进

- [ ] TXXX [P] 更新 docs/ 中的文档
- [ ] TXXX 代码清理和重构
- [ ] TXXX 跨故事的性能优化
- [ ] TXXX [P] 补充单元测试（如有要求）tests/unit/
- [ ] TXXX 安全加固
- [ ] TXXX 运行 quickstart.md 验证

---

## 依赖与执行顺序

### 阶段依赖

- **搭建（Phase 1）**：无依赖——可立即开始
- **基础设施（Phase 2）**：依赖搭建完成——阻塞所有 User Story
- **User Story（Phase 3+）**：均依赖基础设施阶段完成
  - User Story 之间可并行推进（如有人手）
  - 或按优先级顺序推进（P1 → P2 → P3）
- **打磨（最终阶段）**：依赖所有目标 User Story 完成

### User Story 间依赖

- **User Story 1（P1）**：基础设施（Phase 2）完成后可开始——不依赖其他 Story
- **User Story 2（P2）**：基础设施（Phase 2）完成后可开始——可能与 US1 集成但应可独立测试
- **User Story 3（P3）**：基础设施（Phase 2）完成后可开始——可能与 US1/US2 集成但应可独立测试

### 各 User Story 内部

- 测试（如包含）必须先编写并确认失败后再实现
- 模型先于服务
- 服务先于端点
- 核心实现先于集成
- 当前 Story 完成后再进入下一优先级

### 并行机会

- 所有标记 [P] 的搭建任务可并行执行
- 所有标记 [P] 的基础设施任务可在 Phase 2 内并行执行
- 基础设施阶段完成后，所有 User Story 可并行启动（如团队有余力）
- User Story 内所有标记 [P] 的测试可并行执行
- Story 内标记 [P] 的模型可并行执行
- 不同 User Story 可由不同团队成员并行开发

---

## 并行示例：User Story 1

```bash
# 同时启动 User Story 1 的所有测试（如有要求）：
Task: "端点 [endpoint] 的契约测试 tests/contract/test_[name].py"
Task: "用户旅程 [journey] 的集成测试 tests/integration/test_[name].py"

# 同时启动 User Story 1 的所有模型：
Task: "创建 [Entity1] 模型 src/models/[entity1].py"
Task: "创建 [Entity2] 模型 src/models/[entity2].py"
```

---

## 实现策略

### MVP 优先（仅 User Story 1）

1. 完成 Phase 1：搭建
2. 完成 Phase 2：基础设施（关键——阻塞所有 Story）
3. 完成 Phase 3：User Story 1
4. **暂停验证**：独立测试 User Story 1
5. 可部署/演示时上线

### 增量交付

1. 完成搭建 + 基础设施 → 基础就绪
2. 添加 User Story 1 → 独立测试 → 部署/演示（MVP!）
3. 添加 User Story 2 → 独立测试 → 部署/演示
4. 添加 User Story 3 → 独立测试 → 部署/演示
5. 每个 Story 在不破坏已有 Story 的前提下增加价值

### 并行团队策略

多名开发者时：

1. 团队共同完成搭建 + 基础设施
2. 基础设施完成后：
   - 开发者 A：User Story 1
   - 开发者 B：User Story 2
   - 开发者 C：User Story 3
3. 各 Story 独立完成并集成

---

## 注意事项

- [P] 任务 = 不同文件，无依赖
- [Story] 标签将任务映射到具体 User Story 以便追溯
- 每个 User Story 应可独立完成和测试
- 先验证测试失败再开始实现
- 每个任务或逻辑组完成后提交
- 在任何 Checkpoint 暂停以独立验证 Story
- 避免：模糊的任务、同文件冲突、破坏独立性的跨 Story 依赖
