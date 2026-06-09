# Change: EVM 常量移位 lowering 的静态 guard 消解与死项剪枝

- **Status**: Proposed
- **Date**: 2026-06-10
- **Tier**: Light

## Overview

multipass JIT 对常量移位量的 SHL/SHR/SAR 仍发射运行时 `>= 256` guard(每
limb 一个 Select)与 range 上已证为零的源 limb 计算。本变更在编译期消解这些
死代码:常量移位量 ≥256 时 SHL/SHR 直接折叠为常量零;<256 时省去整条
`IsLargeShift` 链与每 limb 的 Select;值操作数已证 U64/U128 时再剪掉死源项。
**纯生成码精简,不引入新的 range 声明**;两名独立 reviewer 全攻击面 clean,
全部正确性套件通过,端到端基准中性(无回归)。

## Motivation

真实主网负载上,SHL FULL 执行的 92.5%、SHR 的 99.6% 移位量是编译期常量
(Solidity 的存储槽/地址打包模式)。现有 const-amount 快路径虽然避免了动态
移位的逐 limb select 级联,但仍保留:

1. `isU256GreaterOrEqual(Shift, 256)` 比较链——对完整常量静态可判;
2. 每个结果 limb 一个 `Select(IsLargeShift, fill, R)` + spill——guard 恒假时
   是死代码;
3. 对已证 U64/U128 的被移位值,高位源 limb 的 shl/ushr/or 项——按 Range
   契约语义为零。

`getConstShiftAmount` 只读 limb0,高 limb 非零的常量(如 2^64)历史上依赖
运行时 guard 兜底——静态消解必须用完整 256-bit 常量判定,这是本变更的核心
正确性约束。

## Changes

全部在 `src/compiler/evm_frontend/evm_mir_compiler.{h,cpp}`:

1. **静态大移位消解**(`handleShift`):移位量为常量时用
   `u256ValueToIntx` 取完整 256-bit 值。≥256:SHL/SHR_U 返回常量零
   Operand(EVM 语义下结果恒为 0,与既有 Phase-0 双常量折叠一致;常量
   构造器自动派生 U64 tag,比旧的动态零更精确);SAR 保持原流程(填充值
   依赖被移位值符号位)。<256:不再构造 `IsLargeShift`,向 helper 传
   nullptr。
2. **helper 接受 nullptr guard**:三个 helper 的 const-amount 路径在
   nullptr 时跳过每 limb 的 Select(SAR 的越界 sign-fill 来自 R 的默认初始
   值,与被删的 Select 无关,保留不动);动态路径入口加
   `ZEN_ASSERT(IsLargeShift != nullptr)` 防御。
3. **range-aware 源 limb 剪枝**(仅 SHL/SHR_U const 路径):新增
   `LiveLimbs` 参数(U64→1、U128→2、默认 4),源 limb 下标 ≥ LiveLimbs 的
   shifted/carry 项不发射;双项皆死时该 limb 为共享零常量。SAR 刻意排除
   (其填充符号相关,剪枝将构成新的 range 声明)。

## Soundness

- 2^64 陷阱(limb0 小、高 limb 非零的常量):静态判定用完整常量,≥256 即
  折叠/保留 guard,nullptr 只在完整常量 <256 时传入。
- 项活性代数(SHL 取 `Value[SrcIdx]`/`Value[SrcIdx-1]`,SHR_U 取
  `Value[SrcIdx]`/`Value[SrcIdx+1]`):Codex 用参考实现对全部
  (CompShift × ShiftMod × LiveLimbs ∈ {1,2,4}) × 移位量 0-255 做了穷举
  对照;Opus 手工核对了 Shifted-dead/Carry-live 等边界(如 U64 值 << 200)。
- 提前返回发生在两个操作数 pop 之后,EVM 栈操作数纯值无副作用,丢弃未物化
  的 value 表达式安全。
- 结果 range tag:SHR_U 保持既有 `ValueOp.getRange()` 透传(剪枝恰好使
  零 limb 结构化为零,强化而非违反);SHL 保持 U256;唯一变化是 ≥256 折叠
  产物从动态零变为常量零(tag 更精确,方向安全)。

## Verification

- 新增 12 个差分 fixture(`tests/evm_asm/`)+ `EVMConstShiftDifferentialTest`
  套件:覆盖跨 limb 进位(<<96)、源剪枝(u64 值 <<200 / >>8)、≥256 折叠、
  2^64 陷阱、SAR 正负 sign-fill、动态移位量回归对照。12/12 通过,interp 与
  multipass 输出逐字节一致且 multipass 确实 JIT 编译。
- multipass evmone-unittests 223/223;multipass evmone-statetest
  `-k fork_Cancun` 2723/2723;golden 套件无回归;`tools/format.sh check`
  通过;无新增警告。
- 双独立 review:Opus(7 攻击面全部 verified-clean,无缺陷)+ Codex
  (穷举验证,1 个 NIT 即上述更精确的常量零 tag)。

## Measurements

evmone-bench 27-bench(multipass,vs upstream/main baseline,median of 5):
median delta **-0.08%**;对移位重点基准与全部 >3% 离群点以 15 reps 复测,
全部落回各自 cv 噪声带(blake2b_shifts +1.3% @cv 2.4-3.4%、sha1_shifts
+0.2%、signextend -0.1%、weierstrudel -1.8%)。

结论:**端到端中性,无回归**。收益形态是每个常量移位站点的生成码缩减
(4 个 Select + 一条 4-limb 比较链,窄值另省死源项),该缩减在本基准套件的
热点构成中不可测;在编译产物体积与寄存器压力上的效果未单独量化。

## Known limitations

1. 源 limb 剪枝信任 Range 契约。块内 AND-mask/常量产生的窄值高 limb 物理
   为零;经 `EntryStackRanges` 跨块导入的窄 tag 依赖 analyzer 的 sound
   over-approximation(经查 `meetRange=max` 单调、SHL transfer 为 U256,
   当前成立)。该路径由 `ZEN_ENABLE_EVM_STACK_SSA_LIFT` 门控,默认与 CI
   均 OFF;若未来默认开启,应先重审 analyzer transfer 的 soundness 并补
   lift-ON 下跨块窄 tag 的差分 fixture。
2. 现有差分 fixture 的窄值均来自物理置零的生产者(AND-mask),未覆盖
   仅靠 analyzer tag 证明的跨块路径(同上,lift 系列后续)。

## Checklist

- [x] Implementation complete
- [x] Tests added/updated
- [ ] Module specs in `docs/modules/` updated (if affected)
- [x] Build and tests pass
