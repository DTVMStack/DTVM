# R1 Phase-1 baseline / R1 第一阶段基线

Date: 2026-10-08. **No end-to-end % speedup is claimed.** This run measures
today’s in-tree benches plus jump/SPP upper-bound counters. Cross-block
absinterp (full R1) is implemented in Phase 2; see
`artifacts/r1-phase2-ab.md` (R1 demoted from H2 on this corpus).

日期：2026-10-08。**不宣称端到端加速百分比。** 本报告只记录仓库内可复现
基准，以及今日块内 absinterp / SPP 的上界计数。完整跨块抽象解释见
`artifacts/r1-phase2-ab.md`（本语料上将 R1 从 H2 降级）。

---

## 1. What ran / 跑了什么

| Suite | Status | Notes |
|---|---|---|
| Paper PolyBench/C (30 wasm) | **completed** | Official `bench_polybench_timing.sh dtvm multipass` |
| Paper EVM `test_vmbench` | **blocked** | Runner lives in the external contract-testbed repo |
| Paper contract hex (12 `*_evm.hex`) | **completed** | Cache build + R1 counters + `dtvm` CLI calls |
| evmone-bench / CI perf job | skipped | Needs `ZEN_ENABLE_LIBEVM` + cloned evmone |
| WAPM / Wasmer / Wasmtime compare | skipped | Extra runtimes + network/hardware not required for R1 |

### Commands used / 实际命令

```bash
git submodule update --init evmc
git lfs pull --include 'benchmarks/paper/benchmarks/polybenchc/*.wasm'

cmake -S . -B build-r1 \
  -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DZEN_ENABLE_EVM=ON -DZEN_ENABLE_SINGLEPASS_JIT=OFF \
  -DZEN_ENABLE_SPEC_TEST=ON -DZEN_ENABLE_MULTIPASS_JIT=ON \
  -DLLVM_DIR=/opt/llvm15/lib/cmake/llvm
cmake --build build-r1 --target evmCacheComplexityDemo dtvm evmCacheTests -j2

# jump / SPP upper bounds (Solidity runtime slice)
tools/r1_baseline_stats.sh build-r1/evmCacheComplexityDemo \
  benchmarks/paper/benchmarks/contracts/bench_bytecode \
  artifacts/r1/r1_stats_runtime.csv runtime '*_evm.hex'

# cache-build wall-clock (existing harness)
mkdir -p artifacts/r1/evm_hex_corpus
cp benchmarks/paper/benchmarks/contracts/bench_bytecode/*_evm.hex artifacts/r1/evm_hex_corpus/
tools/bench_evm_cache.sh build-r1/evmCacheComplexityDemo \
  artifacts/r1/evm_hex_corpus 5 artifacts/r1/evm_cache_timing.csv

# paper PolyBench timing (1 warmup + 3 timed; process wall-clock)
DTVM=$PWD/build-r1/dtvm \
CASE_DIR=$PWD/benchmarks/paper/benchmarks/polybenchc \
OUT_DIR=$PWD/artifacts/r1 REPEATS=3 WARMUP=1 \
  benchmarks/paper/scripts/bench_polybench_timing.sh dtvm multipass

# closest in-tree EVM execute (runtime hex + calldata; not test_vmbench)
build-r1/dtvm --format evm --mode multipass --enable-evm-gas \
  --gas-limit 21000000 --enable-statistics --num-extra-executions 200 \
  --calldata 61047ff4…000014 artifacts/r1/runtime_hex/fib_evm.hex
```

Reproduce later: `tools/run_r1_baseline.sh` (same CMake flags; pulls LLVM 15
if `LLVM_DIR` is set).

### Hardware / 硬件

| Item | This VM | Paper contract notes |
|---|---|---|
| CPU | 4× “Intel Xeon Processor” @ **2400 MHz** (hypervisor) | c7 8C16G, Xeon **8369B** @ 2.70 GHz, turbo off |
| RAM | 15 GiB | 16 GiB |
| OS | Linux 6.12.94+ x86_64 | not recorded |
| Compiler | g++ 13.3.0, CMake 3.28.3 | paper DTVM pin used LLVM 15 |
| LLVM | **15.0.6** (`/opt/llvm15`) | 15.0.0 in paper docs |
| DTVM build | **RelWithDebInfo**, EVM + multipass, singlepass OFF | paper wasm: Release + singlepass+multipass; paper EVM path is evmone vs sol→wasm |

This is **not** the paper’s pinned c7 box. Numbers are a local baseline, not
a paper-table replacement.

本机不是论文 c7 机器。数字只作本仓库可复现基线，不能直接替换论文表。

### Blockers / 障碍

- Default `c++` on this image is Clang 18 and cannot find `-lstdc++`; **g++** works.
- `evmc` is a submodule; configure fails until `git submodule update --init evmc`.
- Paper `.wasm` files are **Git LFS** pointers until `git lfs pull`.
- `dtvm --gas-limit` default `UINT64_MAX` becomes `int64_t(-1)` → intrinsic-gas fail. Use `21000000`.
- `test_vmbench` (paper ERC20/Uniswap/… rdtsc loop) is **out of tree**.
- CLI `--benchmark` `_exit`s before flushing stats on RelWithDebInfo.

---

## 2. Baseline results / 基线结果

### 2.1 PolyBench/C — dtvm multipass (paper script)

Raw: `artifacts/r1/polybench_timing_dtvm_multipass.csv`  
Metric: process wall-clock ms, 1 warmup + 3 timed, **median**. Includes JIT
on each process (script spawns a fresh `dtvm` per timed run).

| case | median_ms | min_ms | mean_ms |
|---|---:|---:|---:|
| jacobi_1d | 25.698 | 23.948 | 25.780 |
| durbin | 30.675 | 29.351 | 30.294 |
| trisolv | 54.237 | 51.235 | 53.756 |
| gesummv | 58.439 | 57.808 | 58.795 |
| bicg | 80.473 | 79.360 | 80.649 |
| mvt | 82.479 | 77.857 | 83.700 |
| gemver | 90.730 | 84.900 | 93.955 |
| atax | 100.045 | 73.657 | 91.978 |
| syrk | 1896.990 | 1895.402 | 1896.935 |
| gemm | 2126.686 | 2123.158 | 2128.652 |
| trmm | 2191.770 | 2186.018 | 2253.363 |
| symm | 2612.498 | 2542.631 | 2595.140 |
| doitgen | 2667.978 | 2659.970 | 2694.501 |
| syr2k | 3469.244 | 3318.906 | 3560.512 |
| jacobi-2d | 3738.725 | 3675.804 | 3725.295 |
| 2mm | 4316.596 | 4210.546 | 4287.649 |
| fdtd-2d | 4256.942 | 4224.668 | 4258.690 |
| deriche | 4477.302 | 4457.766 | 4508.479 |
| heat-3d | 5195.261 | 5183.716 | 5199.435 |
| correlation | 5566.443 | 5220.335 | 5488.112 |
| covariance | 5567.659 | 5516.775 | 5775.851 |
| nussinov | 5660.515 | 5636.705 | 5675.615 |
| gramschmidt | 6292.613 | 6187.083 | 6328.861 |
| 3mm | 6518.627 | 6464.530 | 6530.648 |
| adi | 10453.212 | 10433.880 | 10476.068 |
| seidel-2d | 18193.820 | 18153.150 | 18230.048 |
| cholesky | 21060.204 | 19552.971 | 20990.228 |
| ludcmp | 22996.614 | 21588.973 | 22826.201 |
| lu | 24925.970 | 24880.000 | 25034.075 |
| floyd-warshall | 27871.948 | 27842.228 | 27899.204 |

All 30 cases exit 0. This is **Wasm**, not EVM; it is the repo’s intended
paper wall-clock path for DTVM vs Wasmtime. It does **not** exercise SPP.

30 个用例全部成功。这是 **Wasm** 路径，不是 EVM，因此不经过 SPP；它是仓库
文档里 DTVM vs Wasmtime 的论文墙钟路径。

### 2.2 EVM cache-build wall-clock (`evmCacheComplexityDemo`)

5 fresh processes / hex, `total` phase, **median µs**. SPP pipeline is on
(`EnableSPP=true`).

| contract | n_jumpdest (creation hex) | median_us |
|---|---:|---:|
| counter_evm | 6 | 32.5 |
| fib_evm | 18 | 53.9 |
| generative_nft_evm | 13 | 49.3 |
| merkle_evm | 34 | 78.6 |
| ecdsa_evm | 85 | 161.2 |
| erc20_evm | 95 | 214.7 |
| poseidon_evm | 55 | 240.1 |
| uniswapv2_erc20_evm | 291 | 316.5 |
| uniswapv2_factory_evm | 352 | 552.0 |
| erc1155_evm | 999 | 669.4 |
| erc721_evm | 1036 | 724.2 |
| uniswapv2_router_evm | 561 | 782.9 |

### 2.3 Closest in-tree EVM execute (`dtvm` CLI)

Not the paper `test_vmbench` rdtsc loop (10000 txs after deploy/mint).
Runtime bytecode was extracted from creation hex; `--gas-limit 21000000`.
CLI EVM path does **not** print an `Execution:` statistic phase; wall-clock
below includes JIT + 1+N instance creates.

| Workload | Mode | Extra execs | Wall ms | Output |
|---|---|---:|---:|---|
| fibonacci(20) | multipass | 200 | 98.8 | `0x1A6D` = 6765 = F(20) |
| fibonacci(20) | interpreter | 200 | 445.9 | same |
| increase() | multipass | 200 | 9.9 | no return data |
| Merkle `benchmark()` | multipass | 5 | 60.4 | `0x0` (likely empty host/state) |
| GenerativeNFT `generate(1)` | multipass | 5 | 33.2 | 32-byte hash |

Do **not** treat the multipass/interpreter wall ratio as an R1 gain. It is
engine-mode noise on a mocked host, not an absinterp×SPP ablation.

不要把 multipass/解释器墙钟比当成 R1 收益。

---

## 3. Jump / SPP upper-bound counts / 跳转与 SPP 上界

Source: `artifacts/r1/r1_stats_runtime.csv`  
Slice: Solidity **runtime** (CODECOPY+RETURN in the constructor; CBOR metadata
stripped). Creation-hex without extract over-counts (fib full unresolved
96.6% vs runtime 21.4%) because constructor + metadata are scanned as code.

Counters match `buildCFGEdges` today:

- **resolved** = `ResolvedJumpTargets` (block-local absinterp) **or** adjacent
  PUSH1..PUSH32 fallback
- **unresolved** = remaining JUMP/JUMPI → `HasUnresolvedDynamicSuccessor`
- if `unresolved > 0`, **every** JUMPDEST gets
  `ImplicitDynamicPredCount = unresolved` → `n_jd_blocked = n_jumpdest`
- `meterGas` sites ≈ nonzero `GasChunkCost` / `GasChunkCostSPP` at chunk starts
  (JIT skips `meterGas(0)`)

| contract | bytes | JD | JUMP | JUMPI | resolved | unresolved | unres % | JD blocked | chunks | meter≠0 before | meter≠0 after | SPP zeroed | SPP shifted |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| counter | 163 | 6 | 0 | 12 | 12 | **0** | 0.0 | **0** | 22 | 19 | 19 | 0 | **0** |
| generative_nft | 386 | 13 | 5 | 11 | 15 | **1** | 6.3 | **13** | 27 | 26 | 26 | 0 | 0 |
| merkle | 823 | 34 | 23 | 16 | 35 | 4 | 10.3 | 34 | 52 | 51 | 51 | 0 | 0 |
| poseidon | 9142 | 55 | 38 | 22 | 52 | 8 | 13.3 | 55 | 79 | 78 | 78 | 0 | 0 |
| ecdsa | 2407 | 85 | 64 | 26 | 76 | 14 | 15.6 | 85 | 133 | 128 | 128 | 0 | 0 |
| fib | 292 | 17 | 13 | 15 | 22 | 6 | 21.4 | 17 | 34 | 33 | 33 | 0 | 0 |
| erc20 | 2696 | 95 | 43 | 82 | 46 | 79 | 63.2 | 95 | 183 | 181 | 181 | 0 | 0 |
| uniswapv2_erc20 | 6022 | 291 | 229 | 58 | 75 | 212 | 73.9 | 291 | 366 | 364 | 364 | 0 | 0 |
| erc1155 | 10105 | 999 | 908 | 135 | 237 | 806 | 77.3 | 999 | 1129 | 1127 | 1127 | 0 | 0 |
| erc721 | 9670 | 1036 | 947 | 119 | 170 | 896 | 84.1 | 1036 | 1138 | 1136 | 1136 | 0 | 0 |
| uniswapv2_factory | 10128 | 352 | 259 | 154 | 22 | 391 | 94.7 | 352 | 580 | 576 | 576 | 0 | 0 |
| uniswapv2_router | 16599 | 561 | 422 | 273 | 36 | 659 | 94.8 | 561 | 908 | 906 | 906 | 0 | 0 |

Synthetic sanity (`CALLDATALOAD JUMP` + 8× JUMPDEST): unresolved=1,
JD blocked=8/8, SPP shifted=0.

### Interpretation / 解读 — is R1 worth a month as a **main** paper item?

**Keep R1 as enabling / H2 work. Do not promote it to a headline % claim
until Phase-2 A/B. Consider demoting it from “main paper item” if ConstSet
cannot clear the last Top jump or if SPP still does not shift.**

理由 / why:

1. **Blocked-SPP surface is huge.** 11/12 paper contracts have ≥1 unresolved
   dynamic jump. Today that stamps **100% of JUMPDESTs** with
   `ImplicitDynamicPredCount > 0`. One leftover JUMP (generative_nft: 1/16)
   is enough to freeze every JUMPDEST. That is exactly the over-approx R1
   wants to shrink.

2. **Unresolved rate is not uniform.** Compute/crypto contracts sit at
   6–21%; ERC / Uniswap sit at 63–95%. The high-rate set is the Solidity
   internal-call / `SWAP1; JUMP` story — R1’s design target. The low-rate
   set still has a 100% JD block.

3. **SPP is already a no-op on this corpus, even when jumps are fully
   resolved.** `counter` has 0 unresolved JUMP/JUMPI and still
   `n_chunks_shifted = 0` and `spp_zeroed = 0`. Every other contract is the
   same. So unblocking implicit dyn-preds is **necessary but not sufficient**
   for more `meterGas(0)` sites. Static multi-pred, gas-sensitive
   terminators, and loops still bind `lemma614Update`.

4. **Fail-closed risk.** If any JUMP stays Top (opaque dispatcher /
   `CALLDATALOAD; JUMP`), a conservative `invalidate_suspect` / “stamp all
   remaining Top sources on every JD” policy can keep SPP frozen after R1.
   Phase 2 must **classify** today’s unresolved PCs before promising SPP
   motion.

5. **Wall-clock evidence is Wasm, not EVM-SPP.** PolyBench proves the
   multipass bench path works on this VM. It says nothing about R1. Paper
   EVM rdtsc numbers need `test_vmbench`.

Honest paper stance: H2 = “tighter CFG → existing lemma614 consumer”,
supported by these counts. Not “contracts get −X%”.

论文诚实写法：H2 是「更紧的 CFG → 现有 lemma614 消费者」，用本表计数支撑。
不是「合约必然 −X%」。

---

## 4. Phase 2 next step / 第二阶段建议

1. **Classify unresolved JUMP/JUMPI** on the same 12 runtimes: dump PC +
   nearby opcodes. Split “internal return / ConstSet” vs “Top dispatcher”.
   If Top sources dominate, R1 will not clear `ImplicitDynamicPredCount`.
2. **Implement R1 in two increments** (design note §6):
   - week-slice: cross-block Const+Top only, fail-closed identical to main
   - full month: ConstSet + multi-target edges + `invalidate_suspect`
3. **A/B on the same hex**, 2×2 (`absinterp` × `SPP`), report
   unresolved / JD-blocked / nonzero `meterGas` **and** CLI/test_vmbench
   wall-clock. Gate: on ⇒ counts ≤ off; no required wall-clock win.
4. **Do not** rewrite GasSection or change interpreter `GasChunkCost`.
5. If A/B shows SPP still shifting 0 chunks (as `counter` already does),
   keep R1 as SSA/filtered-dispatch plumbing and **demote** it from the
   paper’s main performance claim.

---

## 5. Artifacts / 产物

| Path | Contents |
|---|---|
| `artifacts/r1/r1_stats_runtime.csv` | jump/SPP counters (runtime slice) |
| `artifacts/r1/r1_stats_auto.csv` | same, `--slice auto` |
| `artifacts/r1/r1_stats_full.csv` | creation hex, no extract |
| `artifacts/r1/evm_cache_timing.csv` | 5-run cache-build CSV |
| `artifacts/r1/polybench_timing_dtvm_multipass.csv` | 30-case paper script |
| `artifacts/r1/synthetic_r1_stats.csv` | dyn-dispatch sanity |
| `artifacts/r1/dtvm_*_*.log` | CLI fib/counter/merkle/nft |
| `tools/r1_baseline_stats.sh` | counter dump driver |
| `tools/run_r1_baseline.sh` | configure + bench + dump |
| `src/tests/evm_cache_complexity_demo.cpp` | `--dump-r1-stats` |
