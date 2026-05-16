# Problem Statement v3 — DTVM EVM SPP Pipeline Overhaul

(v3 incorporates iter-2 outside-lens findings: Sourcify methodology
must use BigQuery/Parquet + archive RPC; resolver belongs in
`src/evm/analysis/` not `src/common/`; bootstrap CI gate must be
"lower bound ≥ 15%" consistently; strata add optimizer fields and
proxy/impl label; PR B/C section restated as "future consumers" not
"commitments".)

## Context

`src/evm/evm_cache.cpp` 的 SPP gas-metering pipeline 经历了两次大改:

1. **PR #446**(已合并 upstream/main `d44eb8e`)— 把 `O(D×J)` 显式 over-approx dyn-jump 边换成 `O(N)` implicit-pred-count + reachability stitch
2. **本 session 已 commit 但未 push 的 dom-CHK 工作** — `O(N²/64)` 迭代位集 dominator 换成 CHK + Tarjan Enter/Exit `O(N+E)`。N=100k 合成 demo 上 933ms → 44ms = 21× build-time 加速

## Caveat on the 21× number (iter-1 finding)

EIP-170 mainnet runtime code 上限 24576 bytes,因此 production contract 装不下 100k JUMPDEST。21× 是 **algorithmic stress hygiene** 信号(防 DoS),**不是 production perf headline**。本 spec 把 21× 数字仅作为 worst-case 边界保留;production 收益必须由 real-corpus 数字证明。

## Goal (scoped to 3 sequential PRs, not 1)

Iter-1 反馈双双指向"1 PR 包全 phase 是 review-cost / rollback-boundary 错误"。Spec 重新组织为 **3 sequential PR**,本 dev-cycle 直接交付 **PR A**;PR B/C 由后续 dev-cycle 接续。

| PR | 范围 | Rollback boundary |
|-----|------|-------------------|
| **PR A (本 dev-cycle)** | dom-CHK(本地已 commit) + P0 instrumentation + real-corpus harness + test matrix + bootstrap-CI bench methodology | dom 算法 + tooling/bench infra,可独立 rollback |
| **PR B (next dev-cycle)** | P1 jump-target precision via **extracted cache-safe `ConstantJumpResolver` 库**(`src/common/`),`EVMAnalyzer` 和 `evm_cache` 都 call 它 — 避免 layer inversion | precision 提升,独立 rollback;P0 corpus 数据决定值不值得做 |
| **PR C (next dev-cycle)** | P2 SCC condensation DAG scheduler;feature-flag + shadow-compare rollout | 删除 `findBackEdges + RevTopo + InCycle + Loops` 4-pass 替换为 SCC + DAG topo;最后才删 `buildLoopsUsingDominance` |

**Why this dev-cycle 只做 PR A**:
- dom-CHK 已经本地完成(2 commit on `perf/dom-chk-bytecode-cache`),搬到新分支即可
- P0 是 P1/P2 的 prerequisite — 没 corpus 数据,P2 优先级无法 justify(iter-1 共识)
- PR A 工作量足够小可单独 ship;PR B/C 是 follow-up

## PR A 内容详化(本 dev-cycle 实际产物)

### A1. 把 dom-CHK 2 个 commit 搬到新 branch
- 新 branch `perf/evm-spp-foundation`(或类似)off `upstream/main`
- `cherry-pick a1fc6db 993feb3` 或 squash 后 cherry-pick

### A2. P0 instrumentation
- 在 `buildGasChunksSPP` 各 named phase 上加 `std::chrono::steady_clock` 计时,**编译期 opt-in**(`-DZEN_EVM_CACHE_PROFILE=ON`)避免生产路径噪声
- 每个 phase 输出到 stdout 或 stderr,可被 harness 收集
- Phase 细分:`buildGasBlocks` / `buildCFGEdges` / `splitCriticalEdges` / `computeReachable` + stitch / `computeDomInfo` / `findBackEdges` / `computeReverseTopo` / `computeInCycle` / `buildLoopsUsingDominance` / `lemma614Update + writeback`

### A3. Real-corpus harness
- **Acquisition pipeline**(per Sourcify DB docs + Solidity metadata docs):
  1. Pull verified-deployment rows from **Sourcify BigQuery export** (主) 或
     Parquet snapshot — 不要 scrape API/web index 当采样器
  2. Filter:`chain_id = 1`(mainnet),`block_number` 在 Cancun-era pinned range,
     `match_type IN ('exact', 'match')`(partial-match 单独标记保留作 secondary stratum)
  3. Join `contract_deployments` × `compiled_contracts` × `sourcify_matches.metadata`,
     抽出 `address`, `runtime_codehash`, Solidity `compiler.version`,
     `settings.optimizer.{enabled,runs}`, `settings.viaIR`,
     proxy/implementation label(EIP-1967/UUPS pattern detection,或 metadata 标识)
  4. 用 **archive RPC** `eth_getCode(address, block)` 取 pinned-block runtime
     bytecode(非 Sourcify deployment_bytecode — 后者可能与 chain state 不同步)
  5. **codehash-dedupe** runtime bytecode(非 address-dedupe — 防 proxy/impl pair 重复计入)
- **Multi-dim stratified sampling**(目标 N=80-120 contracts,提高 bootstrap CI 稳定性):
  - code size decile(EIP-170 cap 24576B 分 10 段)
  - JUMPDEST density quartile
  - dyn-jump ratio quartile
  - Solidity major version
  - **optimizer 设置**:`enabled` × `runs` 离散分桶(`runs ∈ {0/disabled, 1-200, 201-1000, >1000}`)
  - **viaIR** 启用与否
  - **proxy vs implementation** 标签
- Pin block range:hardfork = Cancun;具体 block range **[19426587, 21000000]**(Cancun mainnet activation block 至 2024 年底);`eth_getCode` snapshot at fixed **block 21000000** (2024-12-04)
- Storage:`tests/corpus/evm-cache/` 下存:
  - `metadata.json` — codehash → 所有 strata 字段 + 来源 address
  - `<codehash>.hex` — runtime bytecode(gitignored,acquisition script idempotent)
- **Acquisition script** `tests/corpus/evm-cache/fetch_sourcify_corpus.py`(~300 LOC):
  调用 BigQuery + archive RPC,过滤 EIP-170 size,采样,dedupe,落盘
- **Histogram analysis** `tests/corpus/evm-cache/analyze_corpus.py`:统计 code size /
  JD count / dyn-jump ratio / SCC count / optimizer-setting × JD-density 分布,生成
  `distribution.md` Markdown 表

### A4. Bootstrap-CI bench methodology
- **Threshold (single consistent gate)**: 比较 `branch` 与 `upstream/main`,
  对每 contract 取 **paired ratio** `t_new[i] / t_old[i]`,计算 corpus 中位数
  的 **1000-resample BCa bootstrap 95% CI**;要求 **CI lower bound 对应的
  improvement ≥ 15%**(即 `1 - upper_ratio_ci_bound ≥ 0.15`)。
- 不用 ">0" 框架(那只证明 effect ≠ 0,与"声明 15% 提速"不等价 — 引 Kalibera/Jones
  2012 "Rigorous Benchmarking in Reasonable Time")
- Per-contract:20× repetitions,每次 fresh process(避免 warm-cache 偏差),
  collect raw timings (μs)
- Harness:`tools/bench_evm_cache.sh`(~300 LOC),调用 instrumented
  `evmCacheComplexityDemo`(扩展接受 `--bytecode <file>` 参数读 corpus),
  输出 CSV `(contract_hash, run_idx, total_us, phase_us...)`
- Analysis script(Python,~250 LOC):读 CSV,paired-ratio bootstrap BCa,
  生成 Markdown 表,包括 per-phase 拆分 + per-stratum 分组

### A5. Test matrix expansion(`src/tests/evm_cache_tests.cpp`)
- 5 个新 GTest:
  - `Dominators_SelfLoop_*`(1-node back-edge)
  - `Dominators_IrreducibleSCC_*`(两个外部入口进同一环 — `UseLinearSPP=false` fallback)
  - `Dominators_NestedSharedExit_*`(嵌套循环共享 exit edge)
  - `Dominators_CriticalEdgeEmptySplit_*`(`splitCriticalEdges` 写回语义)
  - `Dominators_DynTargetInStaticLoop_*`(dyn-target JUMPDEST 嵌在 static loop 内 — 同时压 stitch × CHK × `UseLinearSPP`)
- Random-walk path-total-gas fuzz(K=1000 paths, depth≤32):验证 `sum(Cost[path]) == sum(CostSPP[path]) + tracked_shifts` invariant

### A6. PR-level acceptance criteria for PR A
- 现有 9/9 evmCacheTests + 5 新增 = 14/14 all pass
- multipass unittests 223/223 / interpreter 215/215 / statetest fork_Cancun 2723/2723 全过
- format check / build clean / no new warnings 在 changed files
- corpus histogram 报告产出(`tests/corpus/evm-cache/distribution.md`)— 给 PR B/C 排序的数据
- dom-CHK 部分 vs `upstream/main` 在 corpus 中位数 wall-clock 上 bootstrap-CI 下界 > 15%(否则证明 dom-CHK 在 real workload 上 marginal,需要更窄 scope)

### A7. Acceptance criteria 不包括(因为没 P1/P2 代码)
- P1 / P2 自身的 perf 数字
- Invariant P1 audit
- SCC DAG 等价证明
- 这些是 PR B / PR C 的 acceptance,不是 PR A

## Future consumers of PR A data (not commitments)

PR A 的 `distribution.md` 数据驱动 P1/P2 启动决策,**但 P1/P2 设计不在本
spec 内**。下面只列出 PR A 输出必须支持 future dev-cycle 做出的 triage 问题:

- **PR B(P1 jump-target precision)** 触发条件:corpus 中 dyn-jump ratio
  中位数 > 某阈值(具体阈值由 distribution.md 决定);如 < 阈值,P1 收益太
  小,不立项
- **PR C(P2 SCC condensation DAG)** 触发条件:profile per-phase 数据显示
  `findBackEdges` + `RevTopo` + `InCycle` + `buildLoopsUsingDominance` 合计
  占 cache-build 总时间的显著比例(具体阈值由 P0 profile 决定)

PR B/C 的 file layout 和 lattice 设计、Invariant P1 写法、SCC scheduler 是
否能与 `buildLoopsUsingDominance` 等价等具体技术 spec **不属于本 dev-cycle**,
在 future dev-cycle 的 Phase 0.5 + Phase 1 单独处理。本 spec 只承诺 PR A
harness/instrumentation 收集足够数据让 future spec 写出。

## Evidence Base (refined)

3 份 red-team 报告 + iter-1 motivation red-team(2 份)— 一共 5 份 adversarial review。

- `/home/abmcar/.claude/jobs/3d8995d3/redteam-scc-dag.md` — SCC DAG 在 reducible CFG 上可证明 metering 等价
- `/home/abmcar/.claude/jobs/3d8995d3/redteam-precision-plus-omitted.md` — P1 EVMAnalyzer 路径(本 v2 已修正为 extracted summary library 避免 layer inversion)
- `/home/abmcar/.claude/jobs/3d8995d3/redteam-cleanups.md` — bench methodology
- `~/changes/2026-05-16-evm-spp-overhaul/reviews/motivation-1-{opus,codex}.md` — iter-1 motivation red-team

Iter-1 findings 已被本 v2 全部 address:

| Iter-1 finding | v2 addressed by |
|---|---|
| 1-PR 包全部 review-cost 过高 | 拆 3 PR,本 dev-cycle 只做 PR A |
| 5% 阈值结构上不可测 | 改 ≥15% + bootstrap CI |
| N=100k 不是 production 信号 | Caveat 章节明说;real-corpus 替代 |
| EVMAnalyzer 直接 wire 是 layer inversion | 抽取 `src/common/evm_jump_resolver` |
| Bundle coherence(P0 drives 但 bundled) | 拆 PR 后 P0 数据天然 driver |
| Macro duration estimates 违规 | v2 删除所有 duration 估算 |
| AbstractValue lattice 闭包问题 | PR B 加 explicit Invariant P1 clause |
| PR #446 lesson 泛化 | PR B 加 corpus-level `GasChunkCostSPP[]` diff oracle |
| Real-corpus methodology | Sourcify 分层 + codehash-dedupe + 多维 strata |

## Out of Scope (本 dev-cycle 不做)

- P1 实现(PR B,future dev-cycle)
- P2 实现(PR C,future dev-cycle)
- 磁盘持久化 cache(P3,multi-month,未来项目)
- Online runtime metering 替换 SPP(已 SKIP)
- 建议二 Semi-NCA over CHK(已 SKIP)
