# Change: EVM SUB 的双 u64 操作数 wrap-form 窄 lowering

- **Status**: Proposed
- **Date**: 2026-06-10
- **Tier**: Light

## Overview

EVM SUB 的结果在下溢时回绕到 2^256 量级,因此**结果**不能窄化——但当两个
操作数都已被 range 分析证明为 u64 时,**计算**可以:`(a - b) mod 2^256` 恒等于
`{a₀-b₀ 的回绕差, 借位广播, 借位广播, 借位广播}`,对全部输入位级精确。本变更
把这类 SUB 从「8 次 protectUnsafeValue spill + SUB/SBB 链」降为「1 sub +
1 比较 + 1 取负 + 借位复用」。EEST Cancun 配对测量:SUB fast-path 命中率
site 加权 **18.4% → 42.1%(+23.8pp)**,925 站点迁移,其余 op 完全不变;
全部正确性套件通过,端到端基准中性。

## Motivation

EEST Cancun 上 SUB 是 FULL 路径站点数最大的算子(3,893 个,占比超过 ADD 的
4 倍),其中 50.2% 的站点两个操作数都已被静态证明 u64(循环计数、gas 运算、
长度差等模式)——但 SUB 此前只有常量 RHS 快路径(`handleSubU64Const`),
动态 u64 对全部落到通用 4-limb 路径。通用路径为保护 SBB 进位链不被 x86
lowering 中的标志位破坏,先把全部 8 个操作数 limb 经 `protectUnsafeValue`
物化成变量,这是已知的 spill 压力来源。

值域分析路线图曾评估「SUB 结果窄化」并正确推迟(需要 a≥b 的关系事实,当前
格不携带)。本变更走的是另一条不依赖该前提的路:**保持结果 U256 标签,只
收窄计算形态**——下溢回绕由借位广播精确表达,无需任何无下溢证明。

## Changes

`src/compiler/evm_frontend/evm_mir_compiler.h`(`handleBinaryArithmetic`
BO_SUB 分支,插在 ADD Phase-1 之后、常量路径之前):

- Gate:`Operand::bothFitU64(LHSOp, RHSOp)` 且两侧均非常量(常量情形仍走
  既有折叠/恒等/`handleSubU64Const` 路径,顺序未变)。
- Lowering:`Diff = sub(a₀, b₀)`;`Borrow = zext(a₀ <ᵤ b₀)`;
  `Fill = 0 - Borrow`(i64 下 0-1 = 全一,精确表达上 192 位的回绕填充);
  Fill 经一次临时变量物化、按 limb 重读(多 parent 保守模式)。无 SBB 链,
  故无需标志位保护屏障。
- 结果返回**默认 U256 range**——不附加任何窄化声明,这是本变更的核心
  soundness 约束;analyzer 的 SUB transfer(`evm_analyzer.h:1645`,pushTop
  = U256)保持对称。
- 新增 `SubFastRangeU64Count` 计数器并接入 `[EVM-ARITH-SUMMARY]` 谓词与
  日志行(review 发现的缺口)。

## Soundness

- 回绕代数:a,b ∈ [0,2^64) 时,a≥b → `{a₀-b₀,0,0,0}`;a<b →
  `{(a₀-b₀) mod 2^64, ~0, ~0, ~0}`(= 2^256-(b-a))。两名独立 reviewer 分别
  以 400 万边界对暴力枚举与 442 边界对计算验证,零不匹配。
- U64 标签来源审计(两名 reviewer 独立完成):upstream/main 上全部标签
  生产者(常量自动派生、比较结果、AND-const、analyzer 入口导入)的高 limb
  均结构性为零,无可携带非零高 limb 的标签源。
- a₀/b₀ 双消费(sub 与比较)与既有 ADD Phase-1 同构;CgIR lowering 按指针
  memoize,无重复发射。
- review 修正:删除了 Diff 上冗余的 `protectUnsafeValue`(单消费者、无
  SBB 链,屏障无必要——与 `handleSubU64Const` 的既有注释一致)。

## Verification

- 6 个差分 fixture + `EVMSubWrapDifferentialTest`(interp vs multipass 逐
  字节一致 + JITCompiled 断言):无下溢、**下溢全一填充**(5-7 → 2^256-2)、
  相等、回绕边界(0 - (2^64-1),limb0=1 + 48 个 F)、动态零 RHS、单侧宽
  对照(不触发)。6/6 通过,golden 套件无回归。
- multipass evmone-unittests 223/223;multipass evmone-statetest
  `-k fork_Cancun` 2723/2723(review 修复后复跑);format check 通过,无
  新增警告。
- 双独立 review:Opus(7 类全部 verified-clean,2 个质量项已采纳/修正)+
  Codex(1 个 MINOR——计数器未接入 summary 日志,已修)。

## Measurements

EEST Cancun 配对(38,808 行 Stream B,28,109 共享站点,site 加权,测量
分支带 tap、不随本 PR 提交):

| 指标 | base | 本变更 | Δ |
|---|---:|---:|---:|
| SUB fast-path 命中率 | 18.4% | **42.1%** | **+23.8pp**(925 站点 FULL→NARROW_U64) |
| 其余全部 op | — | — | 逐站点完全不变(隔离干净) |

与已开 PR 的叠加效应:本测量在不含 range-标签消费 PR(#534)的底座上做;
该 PR 的 ENV/比较标签会制造更多 u64 对,两者叠加时本路径覆盖站点从 925
增至约 1,594(由 #534 测量数据推算),为方向性预估。

evmone-bench 27-bench(median of 5 + 离群点 15 reps 复测):median +0.62%,
全部离群点(含与 SUB 无关的基准双向波动)复测后回到各自 cv 噪声带,体量最
大最稳的 snailtracer +0.4%(cv 0.9-1.1%)。结论:**端到端中性,无回归**;
收益形态为每站点 7 个 spill + SBB 链的生成码消除,本套件热点不隔离该模式。

## Known limitations

1. 真实主网负载上,跨块 widening 使动态 u64 对在 FULL SUB 站点上几乎不存在
   (执行加权 ≈0);本路径在真实负载的收益依赖跨块精度工作(stack-lift 系列)
   落地后解锁。EEST 的 in-block 对(循环/gas 模式)是当前可收割部分。
2. 与既有窄化路径相同,标签信任在 `ZEN_ENABLE_EVM_STACK_SSA_LIFT=ON`
  (默认与 CI 均 OFF)下扩展到 analyzer 导入路径,该路径开启前应完成
   transfer soundness 重审(同 const-shift 变更文档的记录)。

## Checklist

- [x] Implementation complete
- [x] Tests added/updated
- [ ] Module specs in `docs/modules/` updated (if affected)
- [x] Build and tests pass
