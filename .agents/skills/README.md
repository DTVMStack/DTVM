# Spec-Kit 子技能集

本目录包含完整的 Spec-Kit 工作流子技能，用于规范驱动开发。

## 技能列表

| 技能 | 中文名称 | 功能描述 |
|------|----------|----------|
| `speckit-specify` | 功能规格生成 | 从自然语言描述生成 spec.md |
| `speckit-clarify` | 需求澄清 | 批量提问澄清规格中的歧义点 |
| `speckit-plan` | 技术设计规划 | 生成设计产物（research.md, data-model.md, plan.md 等） |
| `speckit-tasks` | 任务列表生成 | 生成可执行的 tasks.md |
| `speckit-implement` | 代码实现 | 按任务列表执行实现 |
| `speckit-dev-workflow` | 完整开发工作流 | 编排所有阶段，一次性完成 |
| `speckit-constitution` | 项目原则 | 定义项目开发原则和约束 |
| `speckit-checklist` | 检查清单 | 生成领域特定的检查清单 |
| `speckit-analyze` | 项目分析 | 分析项目一致性 |
| `speckit-taskstoissues` | 任务转工单 | 将 tasks.md 转为 issue 工单 |
| `speckit-archive` | 功能归档 | 验证前置条件后将已完成功能移至归档 |

## 快速开始

### 单独使用子技能

```bash
# 1. 创建功能规格
/skills/speckit-specify "Add user authentication"

# 2. 澄清需求（如有歧义）
/skills/speckit-clarify

# 3. 技术设计
/skills/speckit-plan

# 4. 生成任务列表
/skills/speckit-tasks

# 5. 执行实现
/skills/speckit-implement

# 6. 归档已完成功能
/skills/speckit-archive
```

### 使用完整工作流

```bash
# 一次性完成所有步骤
/skills/speckit-dev-workflow "Add user authentication"
```

### 现有项目 SDD 初始化

```bash
# 分析项目并生成 SDD 初始化计划（配套技能，位于 claude/skills/speckit-ssot-sdd-init-plan）
/skills/speckit-ssot-sdd-init-plan
```

## 目录结构

将这些技能复制到项目的 `.agents/skills/` 目录：

```
项目根目录/
└── .agents/
    └── skills/
        ├── speckit-specify/
        │   └── SKILL.md
        ├── speckit-clarify/
        │   └── SKILL.md
        ├── speckit-plan/
        │   └── SKILL.md
        ├── speckit-tasks/
        │   └── SKILL.md
        ├── speckit-implement/
        │   └── SKILL.md
        ├── speckit-dev-workflow/
        │   └── SKILL.md
        ├── speckit-constitution/
        │   └── SKILL.md
        ├── speckit-checklist/
        │   └── SKILL.md
        ├── speckit-analyze/
        │   └── SKILL.md
        ├── speckit-taskstoissues/
        │   └── SKILL.md
        └── speckit-archive/
            └── SKILL.md
```

## 技能设计原则

### 中文优先

- 元数据（name, description）使用英文，便于 Claude Code 识别
- 内容全部使用中文，便于国内团队使用

### 独立可组合

每个子技能都是独立的，可以：
- 单独调用
- 按顺序组合
- 在工作流中编排

### 模板和脚本依赖

这些技能依赖于项目中的以下资源：

- `.specify/scripts/bash/*.sh` - 辅助脚本
- `.specify/templates/*.md` - 文档模板
- `specs/` - SSOT 目录结构

确保在调用这些技能之前，这些资源已经就位。
