# R1 Phase 2 A/B — cross-block absinterp vs SPP / R1 第二阶段对照

Date: 2026-10-08. Same VM and RelWithDebInfo + multipass + LLVM 15 build as
Phase 1 (`artifacts/r1-baseline-report.md`). **No end-to-end % speedup is
claimed.**

日期：2026-10-08。硬件与 Phase 1 相同。**不宣称端到端加速百分比。**

---

## Verdict / 结论

**R1 should be demoted from a main-paper H2 runtime-speedup claim.**

The worklist is correct and fail-closed. On the 12 paper runtime hexes it
does **not** unlock SPP: `n_chunks_shifted = 0` in every SPP-on cell, because
every contract except `counter` still has ≥1 unresolved JUMP/JUMPI and
therefore still stamps **all** JUMPDESTs with `ImplicitDynamicPredCount`.
`counter` already had 0 unresolved in Phase 1 and still shifts 0 chunks
(lemma614 has no profitable singleton-pred shift on that CFG).

R1 **应从论文主主张 H2（运行时加速）降级**。分析本身正确且 fail-closed；
但 12 个论文 runtime hex 上 **SPP 仍然移动 0 个 chunk**。除 `counter` 外
每份合约仍有未解析跳转，因此所有 JUMPDEST 仍被打上隐式动态前驱。
`counter` 在 Phase 1 已是 0 unresolved，SPP 同样移动 0 chunk。

What R1 *does* deliver:

- Working Const / ConstSet / Top worklist feeding existing
  `buildCFGEdges` / `lemma614Update` (no GasSection rewrite, no interpreter
  `GasChunkCost` change).
- Unit tests: over-approx ⊇ both callers; Top / mix stays today’s semantics;
  `GasChunkCost` on ≡ off.
- Two real corpus deltas: `uniswapv2_factory` −1 unresolved, `uniswapv2_router`
  −2 unresolved (1 ConstSet). Not enough to clear implicit preds.
- Measured compile-time cost: typically **+7% … +6×** cache-build µs.

R1 实际交付：工作的 absinterp、单测、factory/router 上极少数量减少、以及
可测的 JIT 编译期代价。

---

## 1. Classification of today’s unresolved PCs / 未解析 PC 分类

Heuristic walk (not adjacent-PUSH) on the Solidity **runtime** slice:
`artifacts/r1/unresolved_classify.csv` + `_summary.csv`.
Phase-1 cache counts remain ground truth for “resolved vs not”.

| contract | jumps | unres (no adj PUSH) | SWAP1;JUMP heuristic | top_calldata | top_computed | unknown |
|---|---:|---:|---:|---:|---:|---:|
| counter_evm | 12 | 0 | 0 | 0 | 0 | 0 |
| generative_nft_evm | 16 | 1 | 1 | 0 | 0 | 0 |
| fib_evm | 28 | 6 | 5 | 0 | 0 | 1 |
| merkle_evm | 39 | 5 | 2 | 0 | 0 | 3 |
| poseidon_evm | 60 | 8 | 1 | 1 | 0 | 6 |
| ecdsa_evm | 90 | 17 | 5 | 0 | 1 | 11 |
| erc20_evm | 125 | 79 | 1 | 0 | 2 | 2 |
| uniswapv2_erc20_evm | 287 | 212 | 7 | 0 | 2 | 72 |
| uniswapv2_factory_evm | 413 | 391 | 11 | 1 | 4 | 28 |
| uniswapv2_router_evm | 695 | 658 | 15 | 5 | 1 | 50 |
| erc1155_evm | 1043 | 806 | 142 | 0 | 18 | 29 |
| erc721_evm | 1066 | 896 | 169 | 0 | 17 | 23 |

**ConstSet-style internal returns** (`SWAP1;JUMP`) are common on the large
ERC / Uniswap contracts. **Top dispatchers / computed dests** are enough to
fail-close the *whole* commit: one reached `Top` jump keeps
`ImplicitDynamicPredCount` on every JUMPDEST.

The SWAP1;JUMP heuristic is syntactic. `generative_nft` PC 204 is
`ADDMOD; SWAP1; JUMP` — a **computed** dest, not a pure return. That single
unresolved jump is enough to keep all 13 JUMPDESTs blocked.

`SWAP1;JUMP` 是 ConstSet 的主要形态；但任意一个到达的 Top/计算跳转就会
fail-close。nft 的唯一未解析点其实是 ADDMOD 后的计算跳转。

---

## 2. Where AbsValue lives / AbsValue 放在哪里

| Piece | Location |
|---|---|
| `AbsValue` = Const / ConstSet / Top | `src/evm/evm_absinterp.cpp` (intern cap 16, stack depth 64, iter `n_blocks*8`) |
| API | `resolveJumpTargetsCrossBlock(...)` in `src/evm/evm_absinterp.h` |
| Cache maps | `EVMBytecodeCache::ResolvedJumpTargets` (single) + `ResolvedJumpMultiTargets` (ConstSet) |
| Pipeline | local pass → **R1 worklist** → `buildGasBlocks` → `buildCFGEdges` (multi edges) → unchanged `lemma614Update` |
| Kill switch | `buildBytecodeCache(..., EnableR1=true)` or `ZEN_EVM_DISABLE_R1=1` |

Fail-closed: reached Top **or** non-convergence → do not commit new/multi.
`invalidate_suspect`: a Top jump forbids ConstSet commit. SSA still reads
only the single-target map.

---

## 3. 2×2 ablation (same 12 hexes) / 2×2 对照

Raw: `artifacts/r1/r1_phase2_ab.csv`. Slice = Solidity runtime.
`spp=off` leaves `GasChunkCostSPP` empty, so `spp_zeroed` / `n_chunks_shifted`
are **only meaningful for `spp=on`**.

Gate: **pass.** `n_unresolved` and `n_jd_blocked` on ≤ off; no crash;
`GasChunkCost` identical in unit tests; fibonacci(20) output `0x1A6D` both ways.

门槛：**通过。**

### 3.1 Counts, SPP on (`r1=off` vs `r1=on`)

| contract | unres off | unres on | Δ | JD blocked | chunks shifted | spp_zeroed | n_multi |
|---|---:|---:|---:|---:|---:|---:|---:|
| counter_evm | 0 | 0 | 0 | 0 | **0** | 0 | 0 |
| generative_nft_evm | 1 | 1 | 0 | 13 | **0** | 0 | 0 |
| fib_evm | 6 | 6 | 0 | 17 | **0** | 0 | 0 |
| merkle_evm | 4 | 4 | 0 | 34 | **0** | 0 | 0 |
| poseidon_evm | 8 | 8 | 0 | 55 | **0** | 0 | 0 |
| ecdsa_evm | 14 | 14 | 0 | 85 | **0** | 0 | 0 |
| erc20_evm | 79 | 79 | 0 | 95 | **0** | 0 | 0 |
| uniswapv2_erc20_evm | 212 | 212 | 0 | 291 | **0** | 0 | 0 |
| uniswapv2_factory_evm | 391 | 390 | **−1** | 352 | **0** | 0 | 0 |
| uniswapv2_router_evm | 659 | 657 | **−2** | 561 | **0** | 0 | **1** |
| erc1155_evm | 806 | 806 | 0 | 999 | **0** | 0 | 0 |
| erc721_evm | 896 | 896 | 0 | 1036 | **0** | 0 | 0 |

`r1=on, spp=off` matches the unresolved/multi columns (analysis runs even
when SPP is skipped). Meter “zeroed” in those rows is an empty-SPP-array
artifact, not a real shift.

### 3.2 Cache-build / analysis wall time (JIT compile-time cost)

One-shot `build_us` from the 2×2 (`spp=on`) plus 5-repeat **median** on a
subset (`artifacts/r1/r1_phase2_repeat_build.csv`).

| contract | build_us off (1-shot) | build_us on (1-shot) | ratio | 5-rep median off | 5-rep median on | 5-rep ratio |
|---|---:|---:|---:|---:|---:|---:|
| counter_evm | 30.5 | 35.9 | 1.17 | 31.3 | 39.3 | 1.26 |
| fib_evm | 47.5 | 73.3 | 1.54 | 52.1 | 79.7 | 1.53 |
| generative_nft_evm | 45.2 | 144.9 | 3.21 | 41.0 | 184.0 | 4.49 |
| merkle_evm | 72.4 | 116.9 | 1.61 | — | — | — |
| ecdsa_evm | 150.3 | 280.4 | 1.87 | — | — | — |
| erc20_evm | 167.4 | 1045.4 | **6.24** | 164.9 | 954.2 | **5.79** |
| poseidon_evm | 203.8 | 290.2 | 1.42 | — | — | — |
| uniswapv2_erc20_evm | 272.3 | 346.5 | 1.27 | — | — | — |
| uniswapv2_factory_evm | 419.1 | 449.4 | 1.07 | 486.7 | 521.4 | 1.07 |
| erc721_evm | 510.2 | 586.7 | 1.15 | 541.9 | 575.8 | 1.06 |
| erc1155_evm | 550.3 | 587.6 | 1.07 | — | — | — |
| uniswapv2_router_evm | 696.8 | 675.1 | 0.97 | 751.7 | 738.6 | 0.98 |

R1’s extra cost is the worklist (and early abort on the first reached Top).
`erc20` / `generative_nft` pay the most relative overhead. Router/factory
are within noise. **This is compile-time, not execute-time.**

R1 的代价是工作表固定点（以及遇到 Top 后的 fail-close）。erc20 / nft
相对开销最大。这是 **缓存构建/JIT 编译期**，不是执行期。

### 3.3 Closest in-tree EVM execute / 最近的仓内执行

`test_vmbench` is still **out of tree** (paper contract-testbed).

Closest path: `dtvm --format evm --mode multipass --enable-evm-gas --gas-limit 21000000`
on extracted runtime hex, 50 extra executions. Log:
`artifacts/r1/r1_phase2_exec.log`.

| workload | r1 | JIT compile (stats) | process wall ms | output |
|---|---|---:|---:|---|
| fibonacci(20) | off | 8.146 ms | 33.2 | `0x1A6D` = F(20) |
| fibonacci(20) | on | 7.686 ms | 33.0 | `0x1A6D` (identical) |
| counter increment | off/on | ~3.7 ms | ~7.9 | **failed** (creation/runtime + calldata mismatch; same as Phase 1 smoke) |

No execute-time win is claimed. JIT numbers are single-run noise on a 4-wide
hypervisor. Path gas / return data for fib match.

不宣称执行期收益。`test_vmbench` 仍不可用。

---

## 4. Tests / 测试

`evmCacheTests`: 20/20 pass, including

- `EVMCacheR1.SingleCallerConst_ResolvesInternalReturn` — SWAP1;JUMP → Const 5
- `EVMCacheR1.TwoCallerConstSet_MultiTargetContainsBothReturns` — Multi {10,18}
- `EVMCacheR1.CalldataTop_StaysUnresolvedLikeToday`
- `EVMCacheR1.TopPlusConstSet_FailClosedNoMultiCommit`
- Existing implicit-dyn-pred / SPP fixtures unchanged

Reproduce:

```bash
cmake --build build-r1 --target evmCacheTests evmCacheComplexityDemo dtvm -j2
./build-r1/evmCacheTests
tools/r1_phase2_ab.sh build-r1/evmCacheComplexityDemo \
  benchmarks/paper/benchmarks/contracts/bench_bytecode artifacts/r1 build-r1/dtvm
```

---

## 5. Why SPP still shifts 0 / 为什么 SPP 仍为 0

1. `lemma614Update` refuses a shift into a node with
   `effectivePredCount != 1`, and `effectivePredCount` includes
   `ImplicitDynamicPredCount`.
2. `buildCFGEdges` still sets `ImplicitDynamicPredCount = DynamicJumpCount`
   on **every** JUMPDEST whenever any jump remains unresolved.
3. Fail-closed + one Top/computed jump ⇒ `DynamicJumpCount ≥ 1` ⇒ all JDs
   blocked ⇒ no chunk moves.
4. Even the fully-resolved `counter` CFG has no singleton-pred shift
   (Phase 1 already measured this). Clearing implicit preds is necessary
   but not sufficient.

所以：R1 即使再多解析 1–2 个跳转，只要还有 Top，SPP 就不能动。这不是实现
bug，是与今日 `ImplicitDynamicPredCount` 语义一致的 fail-closed 结果。

A follow-on that *partially* committed ConstSet while a Top dispatcher
remains would still leave every JD blocked, so it would not change this
SPP table.

---

## 6. Paper claim / 论文主张

| Claim | Phase-2 evidence |
|---|---|
| H2: R1 absinterp unlocks SPP / fewer meterGas on real contracts | **Demote.** 0 chunks shifted on the paper hex corpus. |
| R1 is a sound, testable analysis that feeds existing SPP | **Keep** as implementation / negative result. |
| Compile-time cost is small vs runtime win | **Cost is real** (up to ~6× cache-build on erc20); runtime win was not observed. |

Do not put an R1 EVM speedup number in the main paper table from this repo
alone. Revisit only if a later design can resolve **all** reached jumps
(including computed / calldata dests) or can stamp implicit preds on a
*subset* of JUMPDESTs without losing soundness.

不要仅凭本仓库把 R1 写成论文主表加速；除非后续能解析全部到达跳转，或在
保持可靠的前提下缩小 implicit-pred 的盖章范围。
