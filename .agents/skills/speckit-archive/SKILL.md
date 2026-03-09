---
name: speckit-archive
description: 功能归档。验证前置条件后将已完成功能从 specs/features/ 移至 specs/_archive/，并清理分支和 worktree。
---

# 功能归档

将已完成并合并的功能规格从 `specs/features/` 归档到 `specs/_archive/<YYYY-MM>/`，确保归档前所有前置条件已满足。

## 何时使用

- 功能开发、测试、审查全部完成，PR 已合并后
- 作为 `speckit-dev-workflow` 的最后一步（Phase 8）
- 定期清理已完成但未归档的功能

## 归档前置条件

**以下条件必须全部满足才能归档：**

| # | 条件 | 验证方式 |
|---|------|---------|
| 1 | 所有任务已完成 | `tasks.md` 中所有任务标记为 `[X]` |
| 2 | 测试/lint/构建通过 | 运行项目约定的验证命令 |
| 3 | 代码审查通过 | PR 已获批准（approved） |
| 4 | PR 已合并 | 功能分支已合并到目标分支 |
| 5 | SSOT 模块已更新 | `specs/modules/` 中的相关模块已同步变更 |

如果条件不满足，向用户报告缺失项并建议先完成。

## 执行步骤

### 步骤 1：识别待归档功能

如果用户指定了功能编号或名称，直接定位。否则扫描 `specs/features/` 目录，列出所有功能及其状态供用户选择。

### 步骤 2：验证前置条件

逐项检查上述 5 个前置条件：

1. 读取 `specs/features/<NNN>-<slug>/tasks.md`，统计已完成和未完成任务数
2. 检查 Git 状态：功能分支是否已合并（`git branch --merged`）
3. 检查 `specs/modules/` 相关文件的最近修改（是否在功能开发期间有更新）

将检查结果汇总展示给用户：

```
归档前置条件检查：<NNN>-<slug>

✅ 任务完成：15/15（全部完成）
✅ 分支已合并：feature/<NNN>-<slug> → main
⚠️ SSOT 更新：请确认 specs/modules/ 已同步
⬜ 测试/审查：需用户确认

是否继续归档？
```

### 步骤 3：执行归档

确认后执行：

1. 创建归档目录 `specs/_archive/<YYYY-MM>/`（如不存在）
2. 移动功能目录：`specs/features/<NNN>-<slug>/` → `specs/_archive/<YYYY-MM>/<NNN>-<slug>/`

### 步骤 4：清理（可选）

询问用户是否需要清理：

- **Worktree 清理**：`git worktree remove <worktree-path>`（如果使用了 worktree 模式）
- **分支清理**：`git branch -d feature/<NNN>-<slug>`（如果分支已合并）

### 步骤 5：完成报告

```
归档完成：<NNN>-<slug>

📦 已归档到：specs/_archive/<YYYY-MM>/<NNN>-<slug>/
🧹 分支 feature/<NNN>-<slug> 已删除（如选择清理）
🧹 Worktree 已移除（如选择清理）
```

## 批量归档

如果有多个待归档功能，支持批量操作：

1. 列出所有满足条件的功能
2. 用户选择要归档的功能（全部或部分）
3. 逐个执行归档步骤

## 注意事项

- 归档后的功能规格**不再修改**，仅作历史参考
- 如果发现归档的功能需要返工，应创建新的功能提案引用原始规格
- `_archive/` 目录应纳入版本控制，作为项目历史的一部分
