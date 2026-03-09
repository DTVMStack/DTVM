---
name: speckit-dev-workflow
description: 完整的 Spec-Kit 功能开发工作流。从自然语言描述到实现完成，先批量完成需求澄清和规划，再一次性推进实现，最后同步 SSOT、路线图和文档。
---

# 完整开发工作流

从一句需求描述出发，经过批量澄清、规划确认，一次性推进到实现完成，并同步所有相关文档。

## 工作流概述

```
Phase 1: Specify    — 生成功能规格草稿（调用 /speckit-specify）
Phase 2: Clarify    — 批量提出歧义问题，等待用户一次性确认（调用 /speckit-clarify）
Phase 3: Plan       — 生成技术设计产物（调用 /speckit-plan）
Phase 4: Tasks      — 生成可执行任务列表（调用 /speckit-tasks）
Phase 5: Implement  — 按任务执行实现（调用 /speckit-implement）
Phase 6: Doc Sync   — 同步 SSOT / roadmap / README / AGENTS.md
Phase 7: Validate   — lint + build + test 验证
```

**关键节点**：
- Phase 2 一次性提出所有歧义问题，**等用户回答后立即进入 Phase 3，无需再次确认**
- Phase 4 结束后向用户展示任务摘要确认，**确认后**才开始实现
- Phase 7 全部通过后工作流结束

各阶段的具体执行细节参见对应的独立 skill；本 workflow 负责编排和节点控制。

## 用户输入

你输入的内容即为功能描述。

## 执行步骤

### Phase 1 — Specify

调用 `create-new-feature.sh` 创建功能目录脚手架，脚本会**自动生成 `spec.md` 模板文件**。

> ⚠️ **`spec.md` 已由脚本创建**，后续填写规格内容时必须使用编辑工具编辑，**不能使用创建文件工具**（会报 "File already exists" 错误）。

### Phase 2 — Clarify（本 workflow 的核心差异点）

**标准 speckit-clarify 的行为是可以多轮追问的；本 workflow 要求一次性批量提问。**

扫描 spec.md，识别影响架构或实现路径的不确定项（技术栈、进程模型、数据模型、API 契约、构建/发布、范围边界等），**一次性**提出所有问题（最多 5 个），每题附 2-4 个选项和推荐默认值，等用户全部回答后再继续。

答案确认后：
1. 写回 `spec.md` 的 `## Clarifications` 节
2. 将关键约束同步到对应 FR 和 Assumptions
3. **立即进入 Phase 3（Plan）**，无需等待进一步指令

### Phase 3 — Plan（产物清单）

参考 `speckit-plan` skill 执行，**必须在功能目录下生成以下全部产物**：

| 文件 | 说明 |
|------|------|
| `research.md` | 关键技术决策（Decision / Rationale / Alternatives considered） |
| `data-model.md` | 新增实体、DTO 类型、字段说明、状态机枚举 |
| `contracts/` | API 端点 OpenAPI 或 interface 描述（如有新端点） |
| `quickstart.md` | 开发者快速上手：启动步骤、完整流程示例、API 调用示例 |
| `plan.md` | 架构概览、阶段划分、关键伪代码 |

所有产物生成完成后，无需等待确认，**立即进入 Phase 4**。

### Phase 4 — Tasks

生成 `tasks.md` 后，向用户展示任务摘要（任务数、分阶段概览），**等用户确认后**才开始 Phase 5 实现。

### Phase 5 — Implement

按任务列表执行实现，每个任务完成后标记为 `[X]`。

### Phase 6 — Doc Sync

实现完成后审查，**有变更才修改**：

| 文件 | 何时修改 |
|------|---------|
| `specs/modules/*/contracts/interfaces.md` | 新增/变更 API 端点、SSE 契约、错误码 |
| `specs/modules/*/data-model.md` | 新增实体或 DTO 类型 |
| `specs/mvp-roadmap.md` | 将功能行状态从 `🚧 规划中` 改为 `✅ 已完成` |
| `README.md` | 新增用户可见命令、URL 或安装步骤变化 |
| `AGENTS.md` | 新增开发命令、Agent 可调用 API、常见错误码 |

**不确定是否需要修改时**：明确说明判断依据，不强行修改。

### Phase 7 — Validate

按项目约定的 lint / test / build 命令依次执行，任一失败则**就地修复**后重新运行，不跳过。全部通过后工作流结束。

## 完成检查清单

- [ ] `spec.md` 含 FR 编号和 `## Clarifications` 节
- [ ] `research.md` 已生成，含关键技术决策及备选方案
- [ ] `data-model.md` 已生成，含新增实体、DTO 类型、状态机枚举
- [ ] `contracts/` 已生成（如有新 API 端点）
- [ ] `quickstart.md` 已生成，含启动步骤和完整流程示例
- [ ] `plan.md` 已生成，含架构描述和分阶段路径
- [ ] 所有实现任务已完成
- [ ] 受影响的 `specs/modules/` SSOT 已更新
- [ ] `specs/mvp-roadmap.md` 状态已更新
- [ ] lint / test / build 验证全部通过
