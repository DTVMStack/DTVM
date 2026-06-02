# 真实负载测试套件 + 分析精度 headroom 量化

## 执行摘要

构建了一套基于真实主网交易的 EVM 测试套件,并用它量化了 DTVM multipass JIT
value-range 分析的精度缺口。核心结论(扩桩后的权威值,覆盖算术+比较+位运算
consumer):**在真实合约负载下,被静态分析器漏证的动态-u64 操作数质量占比
60.0%**(`runtime_narrow_but_static_unknown_ratio = 0.600`,4652 个联结操作数
槽)。该缺口集中在操作数来源(SLOAD/CALL_RET/MLOAD/CALLDATALOAD/PRIOR_ARITH 等
missed≈0.68–1.0)处,而 PUSH 常量已被完全证明(missed = 0)——直接为
ValueRange roadmap 的 source-tagging 类任务(T-R2)定了收益上界。

测量来自 225 笔真实 Cancun 交易,跨 5 个应用类别。同时用 4-bit limb 占用掩码
做了完整形态分布:真实负载下 u64 占 81.5%(执行加权)、zero 10.5%,而 high-
sparse(`{0,x,0,0}` 这类低位为零、高位非零)只占 0.69%——即便在非 u64 操作数里
也只占 8.7%(执行加权),87.6% 是稠密低位。high-sparse 可忽略这一结论得到本语料
独立确认。

> 注:首版(仅算术 consumer)headline 为 0.652 / 2330 槽;扩桩加入比较+位运算
> consumer 后口径变为 0.600 / 4652 槽。下文表格以扩桩后的权威值为准。

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

## 复现

语料固定在 `~/dtvm-perf-corpora/mainnet-replay/cancun-suite/`(225 个
`<txhash>.json`,内部 test 名形如 `replay_0x…`)。对其跑 statetest **不要**加
`-k fork_Cancun`——该语料 test 名不带 fork 后缀,加了会匹配 0 个 test:

```bash
EVMONE_EXTERNAL_OPTIONS="$(pwd)/build/lib/libdtvmapi.so,mode=multipass,enable_gas_metering=true" \
  ~/evmone/build/bin/evmone-statetest \
  ~/dtvm-perf-corpora/mainnet-replay/cancun-suite \
  --vm external_vm
```

headroom 量化另跑双 tap 插桩(`ZEN_EVM_LIMB_PROFILE` / `ZEN_EVM_RANGE_PROFILE`
env 开启的插桩构建),再用 `tests/corpus/headroom/headroom_join.py` 离线联结两
路 CSV。注意:下文「正确性验证」用的是标准 EEST 套件的 Cancun 子集,那里**仍
需** `-k fork_Cancun`——与本节 replay 语料相反,两者名字都带 "cancun" 但是不同
套件。

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

## 扩桩(第二轮:覆盖更多 consumer + 拆细 source + occupancy)

首版只在算术 consumer 上量 headroom、producer 只分 6 类(OTHER 占约一半)。
第二轮扩桩:

**consumer 扩展**(新增量 headroom 的算子):比较 LT/GT/SLT/SGT/EQ/ISZERO、
位运算 AND/OR/XOR/NOT/BYTE/SHL/SHR/SAR——解锁 roadmap T-R1(比较)/T-R3
(AND-mask)的缺口测量。

**producer 拆细**(`SourceKind` 追加,OTHER 联结槽占比 ~50% → 33%):新增
`AND` / `SHIFT` / `BITWISE` / `COMPARE` / `ENV`(25 个环境 opcode),并接线一直
空着的 `CALL_RET`(CALL/CALLCODE/DELEGATECALL/STATICCALL 的成功标志)。

**occupancy 掩码**:Stream A 增 `limb_mask`(4-bit,bit i = limb[i]≠0),区分
high-sparse 与 dense u128(`limb_width` 会把两者压成同一值)。产出完整 16-mask
分布报告 `tests/corpus/headroom/limb_occupancy_report.md`。

### 插桩清单(以落地代码为准)

CONSUMER tap(在该 opcode 上量 headroom):

| opcode | Stream A(运行时 limb) | Stream B(静态 range+source) |
|---|:---:|:---:|
| ADD SUB MUL DIV SDIV MOD SMOD ADDMOD MULMOD | ✓ | ✓ |
| EXP SIGNEXTEND | ✓ | ✗(B 未 tap,不参与联结) |
| LT GT SLT SGT EQ ISZERO | ✓ | ✓ |
| AND OR XOR NOT BYTE SHL SHR SAR | ✓ | ✓ |

PRODUCER source tag(operand 来源):PUSH / CALLDATALOAD / SLOAD / MLOAD /
KECCAK / PRIOR_ARITH(算术结果)/ AND / SHIFT(SHL/SHR/SAR)/ BITWISE
(OR/XOR/NOT/BYTE)/ COMPARE(比较结果)/ ENV(25 个环境 opcode)/ CALL_RET /
OTHER(默认残差)。DUP/SWAP 按值拷贝 Operand,标签自动传播。无法 tap:
`RETURNDATALOAD`(本 evmc 无 EIP-7069)。

### 扩桩后权威结果

headline **`runtime_narrow_but_static_unknown_ratio = 0.600`**(4652 联结槽);
join 覆盖 Stream A 2597 站点 / Stream B 23167 站点 / shared 2446。

按来源(missed_headroom 降序):SLOAD 1.00、CALL_RET 1.00、OTHER 0.925、
MLOAD 0.884、PRIOR_ARITH 0.880、SHIFT 0.698、CALLDATALOAD 0.676、ENV 0.659、
BITWISE 0.489、AND 0.324、COMPARE 0.233、PUSH 0.000、KECCAK 0.000。

occupancy(执行加权 / 站点加权):ZERO 10.5%/10.6%、U64 81.5%/77.4%、
U128-dense 0.63%/0.85%、U192-U256-dense 6.3%/8.7%、HIGH-SPARSE 0.69%/2.13%、
MID-GAP 0.29%/0.34%。high-sparse 主要出现在 SHR(13%)/DIV(23%)/BYTE(32%);
ADD/MUL/SHL 几乎不产生。

正确性(env 全关):multipass unittests 223/223、interpreter 215/215;插桩单测
14/14(headroom 8 + occupancy 6)。

## runtime 数据持久化(供后续分析)

为避免后续分析重跑 VM,把 runtime 测量数据落到语料旁(repo 外)的持久目录
`~/dtvm-perf-corpora/mainnet-replay/cancun-suite/runtime-profile/`:

| 文件 | 行数 | 内容 |
|---|---:|---|
| `stream_a_limb.csv` | 61,498 | 原始逐次执行(interpreter,含 limb_width+limb_mask) |
| `stream_b_range.csv` | 26,984 | 原始逐次编译(JIT,静态 range+source) |
| `site_histogram.csv` | 4,931 | per-site 聚合直方图(每站点 mask×16 + width×5 + 执行次数) |
| `app_class_map.json` | 24 | FNV-1a→app_class 桥接 |

`site_histogram.csv` 是分析就绪形态——已校验能无损还原原始流(total 61498、
u64 56611/92.05% 双向一致),后续分析只用它即可,不必碰原始流或 VM。聚合脚本
`tests/corpus/headroom/runtime_histogram.py`,目录自带 `README.md` 记 schema 与
复现步骤。

## 后续

headroom 数据已定 source-tagging 的收益上界(0.600)。下一步按本数据驱动
ValueRange roadmap:T-R2(producer 处对 CALLDATALOAD/SLOAD/MLOAD 标 U64)、
T-R1(比较路径 range fast path,COMPARE 已能量到 0.233 缺口)、T-R3(AND-mask,
AND 缺口 0.324),并用本套件复测命中率抬升。OTHER 仍占联结槽 33%,可继续给
残余 producer 打标进一步拆细。
