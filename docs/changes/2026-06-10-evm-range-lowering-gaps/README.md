# Change: EVM lowering 消费 value-range 标签(bool/compare/bitwise 快路径)

- **Status**: Proposed
- **Date**: 2026-06-10
- **Tier**: Light

## Overview

multipass JIT 的 range 分析此前已能证明大量操作数为 u64,但多个 lowering
路径不消费该证明,仍发射全宽 4-limb 序列。本变更让五类 lowering 消费已有的
ValueRange 标签:在 EEST Cancun 套件上,fast-path 命中率 site 加权从 78.72%
提升到 **80.02%**(+364 个站点转入窄路径,零反向回归),其中 **ISZERO 从
23.2% 提升到 85.9%**。全部正确性套件通过,新增 21 个对抗性差分 fixture。

## Motivation

真实负载分析(见 `2026-06-02-real-load-analysis-suite`)量化了两类缺口:
分析侧(静态证不出,占主)与 lowering 侧(已证出但 builder 不消费)。本变更
关闭 lowering 侧缺口中可立即收割的部分:

- **ISZERO**:deferred zero-test 物化时无条件 OR-fold 全部 4 limb,且其 0/1
  结果丢失 U64 标签——真实负载上 58.5% 的 ISZERO FULL 执行操作数已被静态
  证明 u64。
- **JUMPI**:条件 lowering 对已标 U64 的条件仍 OR-fold 4 limb;ISZERO 结果
  作条件时先物化成 0/1 再被整条链重算一遍(`LT;ISZERO;JUMPI` 循环退出模式
  付三层冗余)。
- **OR/XOR**:只有 const-u64 快路径,无 range 窄化——真实负载上 51.8% 的
  OR FULL 执行有至少一侧已证 u64。
- **SLT/SGT**:连 const 快路径都没有(真实负载 SLT FULL 执行的 22.4% 是
  `slt(x, 小常量)` 形态)。
- **环境 opcode 生产者**(PC/GAS/CALLDATASIZE/CODESIZE/MSIZE/
  RETURNDATASIZE):`convertSingleInstrToU256Operand` 结构性零填高 limb 却
  返回默认 U256,造成 builder/analyzer 双 SSOT 背离(analyzer 已标 U64)。

## Changes

全部在 `src/compiler/evm_frontend/evm_mir_compiler.{h,cpp}`:

1. **ISZERO deferred zero-test 携带 range**:`createDeferredZeroTest` 增加
   `BaseRange` 参数(新成员 `DeferredBaseRange`),deferred Operand 自身
   Range 标为 U64(其物化值恒为 0/1,结构性成立)。`handleCompareEQZ` 按
   base range 折叠 1/2/4 个 limb。所有创建/物化点(含 ISZERO 嵌套翻转的
   range 传播)同步更新。
2. **JUMPI 条件融合与窄化**:deferred zero-test 条件不再物化,直接按
   base range 折叠后与 0 比较(EQ/NE 按否定标志选择谓词);非 deferred 条件
   按 Range 契约只折叠可能非零的 limb。Dest 与分支/跳转表逻辑不变。
3. **OR/XOR range 窄化路径**:双操作数均证 U64(非常量)→ 单条 i64 op +
   高 limb 置零,结果标 U64;恰一侧证 U64 → 低 limb op + 宽侧高 limb 直通
   (与既有 const-u64 路径同构),结果标宽侧 range。
4. **SLT/SGT 对 u64 常量的快路径**:u64 常量高 limb 为零,作为 signed-256
   是非负值,故 `slt(x, c)` 可降为「符号位 ∨ (高 limb 全零 ∧ limb0 无符号
   比较)」。新增 `handleCompareSltRhsU64`/`handleCompareSgtRhsU64`,与既有
   无符号比较 helper 相同的三层 range tier(U64/U128/默认)。两个常量侧
   均覆盖(`c <s x ⟺ x >s c` 互换)。
5. **环境 opcode 结果标 U64**:`convertSingleInstrToU256Operand` 返回值附
   `ValueRange::U64`——limbs[1..3] 为字面零,值按构造落在 `[0, 2^64-1]`,
   与调用方意图无关地成立。消除一处现存 builder/analyzer 背离。

## Soundness

- Range 契约:`U64` 标签仅表示高 limb 语义为零;所有新路径只在标签已证明处
  收窄读取宽度,不引入新的标签来源(变更 5 除外,其正确性由函数结构保证)。
- SLT/SGT:limb0 在 `[2^63, 2^64-1]` 的操作数是正的 256-bit 值,新路径用
  无符号谓词(`ICMP_ULT/UGT`)比较 limb0,负数情形由 limb3 的符号位判定
  短路——三层 tier 的真值表经两名独立 reviewer(Opus、Codex)边界枚举核对
  (2^63、2^64、2^128、2^192、2^255、-1、相等、c=0、c≥2^63)。
- analyzer/builder 对称:ISZERO、比较结果、OR/XOR、环境 opcode 的 builder
  结果 range 与 analyzer transfer(`evm_analyzer.h`)一致或更宽,无
  builder-narrower-than-truth 状态。
- JUMPI 现在依赖 Range 契约的正确性(过窄的上游标签会导致错分支而非仅变慢),
  已在代码注释中显式记录。

## Verification

- **差分 fixture(新增,随 PR 提交)**:21 个 `.easm` + `.expected`
  (`tests/evm_asm/`),覆盖每条新路径的窄路径触发与全路径保留两侧,对抗值
  含 2^64、2^128、2^192、-1、limb0-MSB(`0x8000000000000000` 无符号谓词
  硬门)、high-sparse;`EVMRangeNarrowingDifferentialTest` 断言 interp 与
  multipass 输出逐字节一致且 multipass 确实 JIT 编译。21/21 通过,
  golden 套件 178/178 无回归。
- **multipass evmone-unittests**:223/223。
- **multipass evmone-statetest `-k fork_Cancun`**:2723/2723。
- **ctest 全量**:11/11(solidityContractTests 需复制 gitignored 的
  `tests/evm_solidity/*/*.json` 生成物到 worktree,属环境数据非回归)。
- `tools/format.sh check` 通过;构建无新增警告。
- **双独立 review**:Opus(全六攻击面 CLEAN)+ Codex(除一项既有问题外
  verified-clean,见 Known limitations)。

## Measurements

### Fast-path 命中率(EEST Cancun,site 加权,配对测量)

测量方法:在带 Stream B tap 的测量分支上(tap 仅测量用,不随本 PR 提交),
base 与 base+本变更各 capture 一次,28,109 个共享站点逐点配对。

| op | base | 本变更 | Δ | 迁移站点 |
|---|---:|---:|---:|---|
| ISZERO | 23.2% | **85.9%** | **+62.7pp** | 316 × FULL→NARROW_U64 |
| SGT | 80.6% | 95.0% | +14.4pp | 20 × FULL→CONST_U64 |
| SLT | 61.5% | 66.7% | +5.2pp | 9 × FULL→CONST_U64 |
| ADD | 75.1% | 75.6% | +0.5pp | 17 × FULL→NARROW_U128(环境 opcode 标签解锁) |
| OR | 98.7% | 98.9% | +0.2pp | 2 × FULL→NARROW_U64 |
| **总体** | **78.72%** | **80.02%** | **+1.29pp** | +364 站点,零反向迁移 |

JUMPI 融合不在 tap 覆盖内(JUMPI 非算术 op),其收益体现在生成码形态
(省去物化-再折叠往返与 3 条冗余 OR),不计入上表。

### 真实负载语料(mainnet replay,247 笔)

当前 upstream/main 的 deep-entry-risk gate(`evm_module.cpp:112`,
`hasUnresolvedNonLiftedDeepEntryRisk`)在 stack-lift 默认关闭的生产配置下
把语料中 27 个合约的 20 个送回解释器——真实负载的 JIT 覆盖率问题先于
lowering 质量问题存在(stack-lift 系列工作正在解决)。仍可编译的 7 个合约
切片上配对测量:总体 exec 加权命中率 26.7% → 45.3%,其中 ISZERO
0% → 100%(13 站点)、SLT 0% → 100%。该切片执行质量过小,只作方向性佐证,
不作 headline。

### 性能(evmone-bench,27-bench,multipass,vs upstream/main baseline)

27-bench 全量(`--benchmark_filter='^external/total/(main|micro)/'`,
median of 5 reps):median delta **-0.23%**,落在本机 multipass ±2pp 运行
方差内。对首轮离群点(`narrow_compare_u128/loop` +11.8%、
`swap_math/received` -12.7%)以 15 reps 复测:两者均为亚微秒级噪声,复测
后分别为 -3.0% 与 -0.2%。体量最大、方差最小的 `snailtracer`(48.4µs,
cv 1.5%)在两轮独立运行中分别 -1.1% 与 -1.3%,方向一致。

结论:**无性能回归**;聚合中性,最重的真实程序基准呈一致的小幅改善。窄化
收益的主要形态是生成码精简(每站点省 3-9 个 MIR 节点与若干 spill),在
calldata 驱动的真实合约负载上的端到端体现受 JIT 覆盖率限制(见下节)。

## Known limitations

1. **SSA-lift 路径的既有交互**(Codex review 发现,非本变更引入):
   `ZEN_ENABLE_EVM_STACK_SSA_LIFT=ON`(默认 OFF,CI OFF)时,
   `evm_lifted_stack_lifter.h` 的 `getOperandIdentityKey()` 不识别 deferred
   operand,live-out 的 deferred zero-test 会触发断言或错误合并。该暴露面
   在本变更前即存在(deferred 机制与其跨块生命周期均未变);修复属
   stack-lift 后续系列,建议在该系列中为 deferred 增加 identity key 处理。
2. 真实负载命中率的执行加权口径受 JIT 覆盖率限制(见上),待 stack-lift
   落地后可用 `tools/run_real_load_profile.py` 复测完整 27 合约口径。

## Checklist

- [x] Implementation complete
- [x] Tests added/updated
- [ ] Module specs in `docs/modules/` updated (if affected)
- [x] Build and tests pass
