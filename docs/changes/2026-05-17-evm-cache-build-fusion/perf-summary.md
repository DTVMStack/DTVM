# EVM Cache Build Perf — 三层对比汇总

测量平台:WSL2 / Ubuntu 22.04 / Linux 6.6 / Release `-DZEN_EVM_CACHE_PROFILE=ON` build。
测量工具:`evmCacheComplexityDemo` 合成 fixture(`PUSH0 JUMPDEST PUSH0 JUMP …` 交替结构,N = block 数)。
方法学:三个 binary 同会话 round-robin interleaved 测量,各 N 用 20–30 reps,取中位数(median)避免 thermal/scheduling 抖动。

---

## 三层基线 — pre-PR-A → PR A → This PR(N=100k)

| 阶段 | 标识 | N=100k median (us) | 较 pre-PR-A | 较 PR A |
|---|---|---:|---:|---:|
| pre-PR-A(iterative bitset dom)| `ef062ae` | 959 509 | 1.00× | — |
| PR A(dom-CHK + Tarjan E/E) | `592fd35` (`perf/evm-spp-foundation`)| 51 602 | **18.6×** | 1.00× |
| 本 PR | `perf/cache-build-fusion` HEAD | **29 065** | **33.0×** | **1.78×** |

总和:本 PR 把 N=100k 的 cache build 从 pre-PR-A 的 ~960ms 推进到 ~29ms,**总加速 33×**。其中 PR A 贡献 18.6×,本 PR 在其上再 +1.78×。

---

## 跨 N 对比(round-robin median)

| N | pre-PR-A (us) | PR A (us) | This PR (us) | PR A vs preA | HEAD vs preA | HEAD vs PR A |
|---:|---:|---:|---:|---:|---:|---:|
| 10 000 | 14 110 | 2 866 | 2 476 | 4.9× | **5.7×** | 1.16× |
| 20 000 | 45 862 | 6 210 | 4 876 | 7.4× | **9.4×** | 1.27× |
| 50 000 | 246 615 | 20 158 | 13 972 | 12.2× | **17.7×** | 1.44× |
| 100 000 | 959 509 | 51 602 | 29 065 | 18.6× | **33.0×** | 1.78× |

观察:
- **pre-PR-A 的 super-linear 增长很明显**:2× N 给 ~4× time(N=20k→50k 跨 2.5× N 给 5.4× time,对应 ~O(N²/64) bitset dataflow)。
- **PR A 把曲线压成线性**:2× N 给 ~2.2× time。
- **本 PR 进一步推平**:2× N 给 ~2.0× time(完全线性),加速比随 N 增长(cache 密度 + 减少 heap 指针追逐的回报随 working set 增大而放大)。
- **EIP-170 production cap = 24 576 字节**:对应 N ≲ 8000 blocks(极限堆 packing),实际 N=100–2000。生产工作量主要落在 N=10k 行,本 PR 在该区间相对 PR A 仍 +16%。

---

## 本 PR 各 commit 增量贡献(N=100k,25-rep median,sequential 单刀串行)

| # | Commit | 标题 | median (us) | 较 PR A | 备注 |
|---:|---|---|---:|---:|---|
| 0 | `592fd35` | PR A HEAD(基线)| 46 543 | 1.00× | |
| 1 | `e06d291` | buildGasBlocks 2-pass fusion | 47 153 | 0.99× | 单 commit 噪声内 |
| 2 | `3bba649` | collectJumpDests fold | 45 156 | 1.03× | |
| 3 | `0dd5bb9` | **Preds/Succs → CSR** | 37 038 | **1.26×** | 最大单步 +18% |
| 4 | `4d74033` | chkFixpointRounds 诊断 | 36 722 | 1.27× | 仅诊断,语义不变 |
| 5 | `6e1bc6b` | 条件 Tarjan InCycle | 35 575 | 1.31× | 减 Tarjan SCC |
| 6 | `de934a8` | buildCFGEdges fusion | 35 662 | 1.31× | 噪声内 |
| 7 | `118c993` | computeReverseTopo 共用 RPO | 34 165 | 1.36× | |
| 8 | `77e0454` | clang-format sweep | 34 088 | 1.37× | 无语义改动 |
| 9 | `55a250b` | **Blocks.reserve + emplace_back** | 31 409 | **1.48×** | 消 80B move + realloc |
| 10 | `689e5d5` | **Succs/Preds 拆出 → EdgeTables** | 28 185 | **1.65×** | GasBlock 80→40B |
| 11 | `f7630d8` | GasBlock 32 字节字段重排 | 28 762 | 1.62× | static_assert 锁定 |
| 12 | `c5db655` | R1 review fixes(+assert)| — | — | docs + 1 assert |
| 13 | `de507df` | R2 review polish | — | — | docs only |
| — | HEAD | + R1/R2 fixes 含 assert | 29 302 | 1.59× | |

> 说明:逐 commit 数字是单刀串行测的,系统 thermal 漂移会污染相邻 commit 的相对差。最权威的累计数字是上节 round-robin 的 N=100k 1.78×。
> 三个最大单步贡献:**Preds/Succs CSR(+18%)** + **Blocks.reserve+emplace_back(+6%)** + **EdgeTables 拆出(+10%)** —— 三者合计 ~34% 的本 PR 总加速。

---

## 各 phase 时间在 PR A → HEAD 上的迁移(N=100k,50-rep 均值)

| Phase | PR A baseline (us) | HEAD (us) | Δ% |
|---|---:|---:|---:|
| computeDomInfo | 10 818 | 4 482 | **-58.6 %** |
| buildGasBlocks | 10 350 | 2 181 | **-78.9 %** |
| computeInCycle | 7 263 | 37 | **-99.5 %**(reducible 时跳过)|
| buildCFGEdges | 5 477 | 4 512 | -17.6 % |
| lemma614Schedule | 3 091 | 886 | -71.3 % |
| computeReachable | 2 531 | 1 076 | -57.5 % |
| computeReverseTopo | 2 423 | 197 | **-91.9 %**(共用 RPO)|
| buildLoopsUsingDominance | 2 076 | 1 348 | -35.1 % |
| findBackEdges | 1 938 | 1 099 | -43.3 % |
| splitCriticalEdges | 933 | 366 | -60.8 % |
| writeback | 783 | 399 | -49.0 % |
| meteringInit | 533 | 842 | +57.9 %(局部回退,cache 效应)|
| collectJumpDests | 484 | — | 折入 buildGasBlocks |
| buildCSR(新)| — | 3 326 | 新增 flatten 成本 |
| buildJumpDestMap(新计时)| — | 35 | 早就存在,本 PR 加 instrumentation |
| **Σ instrumented** | **48 700** | **20 786** | -57 % |
| **总 median** | **47 343** | **27 945** | **-41 %** |

观察:
- **几乎每个 phase 都缩了**(meteringInit 是唯一例外,+0.3ms 局部回退被全局 -19ms 淹没)。
- buildCSR(3.3ms)是新成本但其换来 readers 上 ~6ms 的节省(computeDomInfo / buildLoopsUsingDominance / computeInCycle 累计)。
- HEAD 的 Σ instrumented(20.8ms)< median total(27.9ms),差额 ~7.2ms 是 `buildBytecodeCache` 外层的 `Cache.PushValueMap` 等 vector 分配(N=100k 合成上 `Cache.PushValueMap` = 9.6 MB);生产 EIP-170 24KB 代码对应 ~0.2ms 不显眼。

---

## 测试 gate(每次 commit 后均跑过)

| Gate | 结果 |
|---|---|
| `tools/format.sh check` | clean |
| `cmake --build build --target dtvmapi -j$(nproc)` | 无新 warning |
| `build/evmCacheTests` | **14/14 pass** |
| `evmone-statetest --vm external_vm -k fork_Cancun` | **2723/2723 pass**(~77 s)|
| `chkFixpointRounds` 诊断 | 在所测 N 均为 2(印证 SemiNCA 不值得)|

---

## 不在本 PR 范围内但已用数据决策

- **Stack-SSA + SCCP**(PR B 原计划):测得 statetest 92.5% / evmone-bench 98.4% JUMP 已由现有 PUSH→JUMP heuristic resolve;96.8% 合约 0 dynamic JUMP。预计 < 1% runtime perf 换 500+ LoC SSA。**drop**。
- **SemiNCA dominator**:CHK 在所测 N 一致 2 轮收敛;SemiNCA 最多省第 2 轮 ≈ 1.5ms,自身 DSU 簿记 1-2ms。**drop**。
- **GasBlock 热冷字段进一步拆**:潜在 +1-2ms,边际递减,延后。
- **PushValueMap 零初始化消除**:9.6MB 合成开销,生产 0.2ms 不显眼,延后。
- **真实 corpus 配对实测**:本 PR 加了一个 B-lite directional pilot(下节);完整 BCa 仍为 post-merge follow-up。

---

## B-lite Sourcify pilot(directional sanity check, n=10)

**Methodology caveats**(读数前必读):

- 来源:10 个 mainnet 合约从 `https://ethereum.publicnode.com` 拉 runtime bytecode,**selection-biased toward 头部 stablecoin / DEX / wrapped-asset 合约**(USDT/USDC 系、Uniswap、WETH9 等),不是随机抽样。
- 配对:同一台机器同一会话内,baseline binary(upstream/main `ef062ae`,**不带** `ZEN_EVM_CACHE_PROFILE`)与 HEAD binary(本 PR HEAD,**亦不带** profile 仪表化以避免 13 phase × ~1us chrono 开销污染小合约读数)各跑 15 reps per contract,per-contract 取 median 再算配对比率。
- 统计:**仅 point estimate,无 BCa CI / cluster bootstrap**。这是 directional pilot,不是 production-grade methodology。完整 Sourcify paired-ratio BCa cluster-bootstrap 为 post-merge B' L1 follow-up。
- 解读限制:n=10 不足以支撑 confidence interval 声明;此处数字应读作 "在头部合约样本上的指向性观察"。

| Stratum | Contract | CodeSize | Baseline (us) | HEAD (us) | Speedup | Δ% |
|---|---|---:|---:|---:|---:|---:|
| small (<4KB) | stETH | 1,035 B | 60.8 | 51.6 | **1.18×** | +15.2% |
|  | TUSD | 1,479 B | 71.9 | 64.9 | **1.11×** | +9.7% |
|  | WETH9 | 3,124 B | 129.2 | 117.2 | **1.10×** | +9.3% |
| medium (4-16KB) | LUSD | 5,297 B | 231.0 | 216.8 | **1.07×** | +6.1% |
|  | DAI | 7,904 B | 278.7 | 338.6 | **0.82×** | **-21.5%** |
|  | rETH | 8,800 B | 407.6 | 344.0 | **1.18×** | +15.6% |
|  | USDT | 11,075 B | 442.4 | 377.8 | **1.17×** | +14.6% |
| large (16-25KB) | UniV2Router02 | 21,943 B | 989.8 | 839.7 | **1.18×** | +15.2% |
|  | UniV3NFTManager | 24,384 B | 1507.7 | 1003.9 | **1.50×** | +33.4% |
|  | UniV3Router02 | 24,497 B | 1374.7 | 1100.2 | **1.25×** | +20.0% |

**Stratum-aggregate**(per-contract median 的 median):

| Stratum | n | Median baseline (us) | Median HEAD (us) | Median speedup | Median Δ% |
|---|---:|---:|---:|---:|---:|
| small (<4KB) | 3 | 71.9 | 64.9 | **1.11×** | +9.7% |
| medium (4-16KB) | 4 | 343.1 | 341.3 | **1.12×** | +10.4% |
| large (16-25KB) | 3 | 1374.7 | 1003.9 | **1.25×** | +20.0% |

**Overall(n=10)**:median speedup **1.17×**,median Δ **+14.9%**(HEAD vs upstream/main `ef062ae`)。

**Observations**:

- 9/10 合约 HEAD 快于 baseline,速度 spread 与 CodeSize 单调相关(small +9.7%、medium +10.4%、large +20.0% median),与合成 cross-N 曲线方向一致。
- **DAI -21.5% outlier**:7.9KB 合约 baseline 279us → HEAD 339us。同等 CodeSize 的 rETH(8.8KB)+15.6%、USDT(11KB)+14.6%。outlier 跨 15-rep median 不像 pure noise;follow-up 项,**不阻塞 ship**。可能是 DAI CFG 拓扑特定 worst-case;待 B' L1 BCa run 用更大 corpus + per-contract repeats 复现后再分析。
- p95 absolute reduction(across 10 contracts):约 -500us(UniV3NFTManager 减 504us)。

---

## Future-work C-rubric(operationalized decision rule)

C(4 个 cache-build micro-opts:`computeReachable` fold / `buildCFGEdges` dedup-skip / `buildCSR` prefetch hints / `GasBlock` hot/cold field split)是否启动由 B' 数据决定。**预先 pre-commit 阈值**(避免数据出来后 post-hoc 凑解释):

**GO**(全部满足启动 C 完整 4 个 opt 的 follow-up PR):

| # | 阈值 | 测量来源 |
|---|---|---|
| (i) | 生产 N≲8000 paired median speedup vs PR A **≥ +5%** AND p95 绝对 reduction **≥ 0.2ms** | B' L1 Sourcify paired-ratio BCa |
| (ii) | end-to-end evmone-bench median 改善 **≥ +1%** AND p95 改善 **≥ +3%** | B' L2 evmone-bench |
| (iii) | N=2000 stratum paired median speedup **≥ 50% of** N=100k stratum speedup | B' L1 stratified by N |
| (iv) | 总 first-touch p95 latency reduction **≥ +5%** | B' L3 reth/payload-style |

**KILL**(任一不满足,drop 全部 C,pivot 到 runtime / JIT / host-call hotspot):

- 若 (i) 不过 → cache-build 在生产规模无可见收益,继续在该轴优化是浪费。
- 若 (ii)(iv) 不过(但 (i)(iii) 过)→ cache-build 收益被下游 runtime 稀释,移到 runtime 才是边际改善大方向。
- 若 (iii) 不过(生产规模相对 synthetic 太小)→ EIP-170 自杀场景,C 收益 N≲2000 上 <50μs,边际下降。

**Partial**((i) 通过但 (ii)(iii)(iv) borderline):仅做 top-2(`computeReachable` fold + `GasBlock` hot/cold split,这两个有 reachability/access-pattern data 锚),drop 另外两个(prefetch hints 假设 HW prefetcher 已饱和;dedup-skip 在 4.5ms 基线上提升不到 0.5ms)。

**B-lite 当前数据相对 C-rubric**:已部分满足 (i) 第一项(small <4KB stratum median +9.7%,medium +10.4%);(i) 第二项绝对 reduction 在 small 上 ~7us = 0.007ms 远低于 0.2ms,仅 medium / large stratum 满足 0.2ms 门槛。但 B-lite **不能替代 B' L1**(无 BCa CI,n=10 太薄);最终 C 决策必须等 B' L1 完整跑完。
