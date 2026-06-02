# 真实负载测试套件 + 分析精度 headroom 量化

## 执行摘要

构建了一套基于真实主网交易的 EVM 测试套件,并用它量化了 DTVM multipass JIT
value-range 分析的精度缺口。核心结论:**在真实合约负载下,被静态分析器漏证的
动态-u64 操作数质量占比 65.2%**(`runtime_narrow_but_static_unknown_ratio =
0.652`)。该缺口集中在操作数来源(SLOAD/MLOAD/CALLDATALOAD/PRIOR_ARITH)处,
而 PUSH 常量已被完全证明(missed = 0)——直接为 ValueRange roadmap 的
source-tagging 类任务(T-R2)定了收益上界。

测量来自 225 笔真实 Cancun 交易,跨 5 个应用类别;所有 5 类的 missed_headroom
都在 0.36–0.66 区间,说明该缺口是普遍现象,而非单一合约类型的伪影。

## 背景

历史测量(见 `2026-05-30-u256-valuerange-precision-roadmap`)已确认 DTVM 的瓶颈
不是操作数分布(真实合约 99.95% 算术操作数本就是 u64-magnitude),而是**分析
精度**——`range_u64` 动态快路径命中率 0%。但此前缺少:

1. 一套可复现、分层、自包含的真实负载语料(此前 fixture 为 ad-hoc 抓取)。
2. 一个能把「运行时确实窄」与「编译期能否证明窄」对齐量化的工具。

本次交付补齐这两块。

## 交付物

### 1. 真实负载 fixture 生成器与语料 (`tests/corpus/replay/`)

- `replay_to_fixture.py` — 真实交易 → 自包含 EEST `state_test` JSON 生成器。
  默认 `prestate` 模式(`debug_traceTransaction` prestateTracer + diffMode),
  从精确 touched-set 推导 `accessList`、补全完整 `env`、记录 post-diff/receipt。
  保留 `createaccesslist` 作为 debug-free archive 回退。
- `sample_cancun_txs.py` — 跨 5 个应用类别(stablecoin/dex/lending/nft/infra)
  经 `eth_getLogs` + curated 合约采样 tx hash。
- `build_manifest.py` — corpus manifest,含 codehash 双权重(按 tx 频率的
  logical 视图 + 按 codehash 去重的 unique 视图)与 app_class 分布。
- `fixture_equal.py` — canonical-semantic-equality 比较器(忽略 JSON key 序、
  storage map 序、hex 大小写/零填充)。

语料:`~/dtvm-perf-corpora/mainnet-replay/cancun-suite/`,225 笔,block 区间
20,000,000–21,800,125(真 Cancun,Prague 之前),0 blob,5 类均衡。

### 2. 双 tap 插桩 (`src/evm/arith_profile.{h,cpp}` + taps)

env-gated、release 构建默认休眠(无 env 时零开销、JIT 汇编不变):

- **Stream A**(`ZEN_EVM_LIMB_PROFILE`,interpreter):每个算术操作数的运行时
  significant-limb 宽度。Tap 点:`opcode_handlers.h`(binary/ternary)、
  `opcode_handlers.cpp`(EXP/SIGNEXTEND)。
- **Stream B**(`ZEN_EVM_RANGE_PROFILE`,multipass):每个算术站点的静态
  value-range + 新增的 operand SOURCE 分类。新增 `Operand::SourceKind`
  (`evm_mir_compiler.h`),在 producer 处打标(PUSH/CALLDATALOAD/SLOAD/MLOAD/
  KECCAK/PRIOR_ARITH),tap 在 visitor 算术 handler(`evm_bytecode_visitor.h`)。

join key:两引擎均无 codehash,故用同一份 bytecode 的 FNV-1a 64-bit 哈希
(`fnv1aCodeHash`)+ `pc` 作为 `(codehash, pc)` 联结键,两侧对齐验证通过。

### 3. Offline joiner (`tests/corpus/headroom/`)

- `headroom_join.py` — 按 `(codehash, pc, opcode)` 联结两路 CSV,产出交叉表:
  `source_kind × dynamic_u64_rate × analyzer_proved_u64_rate × missed_headroom`,
  并按 source_kind / opcode / app_class 分组 + 总体 headline 指标。
- `test_headroom_join.py` — 5 个单测(全过)。

## 结果

总体 **`runtime_narrow_but_static_unknown_ratio = 0.652`**(2330 个联结操作数槽,
2205 动态-u64 质量中 1438 被漏证)。

### 按操作数来源

| source_kind | slots | dynamic_u64 | proved_u64 | missed |
|---|---:|---:|---:|---:|
| SLOAD | 9 | 1.000 | 0.000 | 1.000 |
| MLOAD | 178 | 0.996 | 0.000 | 0.996 |
| PRIOR_ARITH | 170 | 0.986 | 0.029 | 0.957 |
| OTHER | 1175 | 0.937 | 0.027 | 0.910 |
| CALLDATALOAD | 27 | 0.741 | 0.000 | 0.741 |
| PUSH | 771 | 0.947 | 0.947 | 0.000 |

读法:SLOAD/MLOAD/CALLDATALOAD/PRIOR_ARITH 的操作数运行时几乎全是 u64,但
静态几乎证不出(proved≈0);PUSH 已被完全证明(缺口 0)。这与 roadmap 假设
一致:收益在 SOURCE 处,不在结果处。

### 按 opcode

| opcode | slots | dynamic_u64 | proved_u64 | missed |
|---|---:|---:|---:|---:|
| ADD | 1962 | 0.974 | 0.349 | 0.625 |
| DIV | 28 | 0.643 | 0.036 | 0.607 |
| SUB | 284 | 0.799 | 0.218 | 0.581 |
| MUL | 54 | 0.870 | 0.352 | 0.519 |

ADD 槽位最多(1962),缺口 0.625,是 source-tagging 的首要受益 opcode。

### 按应用类别

| app_class | slots | dynamic_u64 | proved_u64 | missed |
|---|---:|---:|---:|---:|
| nft | 1144 | 0.963 | 0.303 | 0.660 |
| infra | 582 | 0.966 | 0.333 | 0.632 |
| dex | 136 | 0.934 | 0.346 | 0.588 |
| stablecoin | 426 | 0.894 | 0.387 | 0.507 |
| lending | 28 | 0.821 | 0.464 | 0.357 |

5 类缺口均在 0.36–0.66,缺口是普遍现象。

完整报告:`tests/corpus/headroom/headroom_report.md`;原始交叉表:
`headroom_crosstable.csv`。

## 正确性验证

C++ 插桩由 compiler-agent 实现并验证(env 全关时):
- multipass evmone-unittests 223/223;interpreter 215/215。
- cancun statetest(`-k fork_Cancun`)multipass 60/60、interpreter 60/60;
  istanbul 6/6。
- 无 env 时两路 tap 均不产出 CSV,release 构建零影响。

后续 Python(生成器/joiner)与 corpus 数据改动不触及 VM C++,不影响上述结论。
joiner 单测 5/5;生成器对现有语料做 determinism 回归(两次生成 byte-identical)。

## 已知限制

1. **join key 用 FNV-1a 而非真实 codehash**:DTVM 不计算 codehash;FNV-1a 足够
   作联结键,但与 manifest 的 keccak codehash 不同,app_class 桥接需离线由
   `pre[to].code` 重算 FNV-1a(24 个 to-合约覆盖全 5 类;sub-frame 代码归
   `unknown`,占比极小)。
2. **source_kind 仅来自 JIT**:interpreter 无 Operand 抽象,SOURCE 分类只能从
   Stream B 取,左联结到 Stream A;未被 JIT 编译的 `(codehash,pc)` 无 source。
3. **fixture 用 EEST 测试账户签名**:`transaction.sender` 替换为标准测试账户
   并把其注入 `pre`(nonce 匹配真实 tx + 大余额),真实 sender 仍留在 `pre`。
   这改变 `tx.origin`/顶层 `msg.sender`,对算术 profiling 可接受。
4. **插桩为测量用途**:env-gated 常驻 tap,非临时 fprintf;是否随 PR 落地或
   revert 待定。

## 后续

headroom 数据已定 source-tagging 的收益上界(0.652)。下一步是按本数据驱动
ValueRange roadmap 的 T-R2(在 producer 处对 CALLDATALOAD/SLOAD/MLOAD 标
U64)与 T-R1(比较路径 range fast path),并用本套件复测命中率抬升。
