# 实现计划：[功能名称]

**分支**：`[###-feature-name]` | **日期**：[DATE] | **规格**：[link]
**输入**：功能规格来自 `/specs/features/[###-feature-name]/spec.md`

**说明**：本模板由 `speckit-plan` 技能填写。

## 摘要

[从功能规格中提取：主要需求 + 来自调研的技术方案]

## 技术上下文

<!--
  必填：将以下内容替换为项目的具体技术细节。
  此处结构仅作为迭代过程的参考指引。
-->

**语言/版本**：[例如 Python 3.11、Swift 5.9、Rust 1.75 或 待澄清]
**主要依赖**：[例如 FastAPI、UIKit、LLVM 或 待澄清]
**存储**：[如适用，例如 PostgreSQL、CoreData、文件 或 不适用]
**测试**：[例如 pytest、XCTest、cargo test 或 待澄清]
**目标平台**：[例如 Linux 服务器、iOS 15+、WASM 或 待澄清]
**项目类型**：[单体/Web/移动端——决定源代码结构]
**性能目标**：[领域相关，例如 1000 req/s、10k lines/sec、60 fps 或 待澄清]
**约束**：[领域相关，例如 <200ms p95、<100MB 内存、离线可用 或 待澄清]
**规模/范围**：[领域相关，例如 10k 用户、1M LOC、50 个页面 或 待澄清]

## 宪法检查

*门禁：必须在 Phase 0 调研前通过。Phase 1 设计后再次检查。*

[根据宪法文件确定的门禁项]

## 项目结构

### 文档（本功能）

```text
specs/features/[###-feature]/
├── plan.md              # 本文件（speckit-plan 技能输出）
├── research.md          # Phase 0 输出（speckit-plan 技能）
├── data-model.md        # Phase 1 输出（speckit-plan 技能）
├── quickstart.md        # Phase 1 输出（speckit-plan 技能）
├── contracts/           # Phase 1 输出（speckit-plan 技能）
└── tasks.md             # Phase 2 输出（speckit-tasks 技能——非 speckit-plan 创建）
```

### 源代码（仓库根目录）
<!--
  必填：将以下占位目录树替换为本功能的具体布局。
  删除未使用的选项，并将所选结构展开为真实路径
  （例如 apps/admin、packages/something）。交付的计划
  不应包含 Option 标签。
-->

```text
# [未使用则删除] 选项 1：单体项目（默认）
src/
├── models/
├── services/
├── cli/
└── lib/

tests/
├── contract/
├── integration/
└── unit/

# [未使用则删除] 选项 2：Web 应用（检测到 "frontend" + "backend" 时）
backend/
├── src/
│   ├── models/
│   ├── services/
│   └── api/
└── tests/

frontend/
├── src/
│   ├── components/
│   ├── pages/
│   └── services/
└── tests/

# [未使用则删除] 选项 3：移动端 + API（检测到 "iOS/Android" 时）
api/
└── [同上 backend 结构]

ios/ 或 android/
└── [平台特定结构：功能模块、UI 流程、平台测试]
```

**结构决策**：[记录所选结构并引用上面的实际目录]

## 复杂度追踪

> **仅在宪法检查存在需要说明理由的违规时填写**

| 违规项 | 为什么需要 | 被拒绝的更简单替代方案及原因 |
|--------|-----------|---------------------------|
| [例如第 4 个子项目] | [当前需求] | [为什么 3 个子项目不够] |
| [例如 Repository 模式] | [具体问题] | [为什么直接数据库访问不够] |
