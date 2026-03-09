---
name: speckit-taskstoissues
description: 将 tasks.md 中的任务转换为 issue 工单，支持 GitHub、GitLab 等平台。
---

# 任务转工单

将 tasks.md 中的任务转换为 issue 工单，支持 GitHub、GitLab 等平台。

## 用户输入

你输入的内容即为上下文。

## 执行步骤

### 1. 加载任务文件

从 `FEATURE_DIR/tasks.md` 加载任务列表。

### 2. 解析任务

解析任务文件，提取：
- 任务 ID
- 任务描述
- 任务标签（如 [US1]、[P]）
- 文件路径
- 依赖关系

### 3. 确定目标平台

确定 issue 创建的目标平台：
- GitHub（通过 `gh` CLI 或 API）
- GitLab（通过 `glab` CLI 或 API）
- 其他平台（生成通用格式）

### 4. 转换任务为 Issue

为每个任务创建 issue，包括：

#### Issue 标题
- 任务 ID + 简短描述
- 移除文件路径（放在正文中）

#### Issue 正文
- 完整任务描述
- 文件路径
- 相关User Story（如有）
- 依赖任务（如有）
- 验收标准（从 tasks.md 提取）

#### Labels
- 优先级（从任务推导）
- User Story标签
- 阶段标签（Setup、Core、Integration 等）
- 技术标签（从文件路径推导）

### 5. 管理 Issue 依赖

- 按顺序创建 issue
- 使用 issue 引用设置依赖
- 考虑平台的依赖管理功能

### 6. 创建 Issue

使用适当的方法创建 issue：

**GitHub（通过 CLI）**：
```bash
gh issue create --title "TITLE" --body "BODY" --labels "LABELS"
```

**GitLab（通过 CLI）**：
```bash
glab issue create --title "TITLE" --description "BODY" --labels "LABELS"
```

**备用**：生成可导入的 CSV/JSON 文件

### 7. 报告

报告：
- 创建的 issue 数量
- Issue URL 列表
- 任何失败或警告
- 任务 ID 到 issue 编号的映射

### 8. 更新任务文件（可选）

如果用户请求，更新 `tasks.md` 以包含 issue 引用。
