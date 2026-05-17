# EVM Cache Build Perf — Three-Tier Comparison Summary

Measurement platform: WSL2 / Ubuntu 22.04 / Linux 6.6 / Release `-DZEN_EVM_CACHE_PROFILE=ON` build.
Measurement tool: `evmCacheComplexityDemo` synthetic fixture (`PUSH0 JUMPDEST PUSH0 JUMP …` alternating structure, N = block count).
Methodology: three binaries measured round-robin interleaved in the same session, 20–30 reps per N, median reported to suppress thermal / scheduling jitter.

---

## Three-tier baselines — pre-PR-A → PR A → This PR (N=100k)

| Tier | Identifier | N=100k median (us) | vs pre-PR-A | vs PR A |
|---|---|---:|---:|---:|
| pre-PR-A (iterative bitset dom) | `ef062ae` | 959 509 | 1.00× | — |
| PR A (dom-CHK + Tarjan E/E) | `592fd35` (`perf/evm-spp-foundation`) | 51 602 | **18.6×** | 1.00× |
| This PR | `perf/cache-build-fusion` HEAD | **29 065** | **33.0×** | **1.78×** |

In total, this PR drives the N=100k cache build from pre-PR-A's ~960 ms down to ~29 ms — **33× cumulative speedup**. Of that, PR A contributes 18.6× and this PR adds another 1.78× on top.

---

## Cross-N comparison (round-robin median)

| N | pre-PR-A (us) | PR A (us) | This PR (us) | PR A vs preA | HEAD vs preA | HEAD vs PR A |
|---:|---:|---:|---:|---:|---:|---:|
| 10 000 | 14 110 | 2 866 | 2 476 | 4.9× | **5.7×** | 1.16× |
| 20 000 | 45 862 | 6 210 | 4 876 | 7.4× | **9.4×** | 1.27× |
| 50 000 | 246 615 | 20 158 | 13 972 | 12.2× | **17.7×** | 1.44× |
| 100 000 | 959 509 | 51 602 | 29 065 | 18.6× | **33.0×** | 1.78× |

Observations:

- **pre-PR-A's super-linear growth is pronounced**: 2× N yields ~4× time (N=20k→50k spans 2.5× N and gives 5.4× time, consistent with the ~O(N²/64) bitset dataflow).
- **PR A flattens the curve to linear**: 2× N yields ~2.2× time.
- **This PR flattens further**: 2× N yields ~2.0× time (essentially linear), and the speedup ratio grows with N (cache density + reduced heap pointer chasing pay off more as the working set spills out of L2/L3).
- **EIP-170 production cap = 24 576 bytes**: corresponds to N ≲ 8000 blocks at the most pathological packing, practically N=100–2000. Real production workloads cluster around the N=10k row, where this PR still adds +16% vs PR A.

---

## Per-commit incremental contribution within this PR (N=100k, 25-rep median, single-shot serial)

| # | Commit | Title | median (us) | vs PR A | Notes |
|---:|---|---|---:|---:|---|
| 0 | `592fd35` | PR A HEAD (baseline) | 46 543 | 1.00× | |
| 1 | `e06d291` | buildGasBlocks 2-pass fusion | 47 153 | 0.99× | within single-commit noise |
| 2 | `3bba649` | collectJumpDests fold | 45 156 | 1.03× | |
| 3 | `0dd5bb9` | **Preds/Succs → CSR** | 37 038 | **1.26×** | largest single step, +18% |
| 4 | `4d74033` | chkFixpointRounds diagnostic | 36 722 | 1.27× | diagnostic only, semantically unchanged |
| 5 | `6e1bc6b` | conditional Tarjan InCycle | 35 575 | 1.31× | skips Tarjan SCC |
| 6 | `de934a8` | buildCFGEdges fusion | 35 662 | 1.31× | within noise |
| 7 | `118c993` | computeReverseTopo shares RPO | 34 165 | 1.36× | |
| 8 | `77e0454` | clang-format sweep | 34 088 | 1.37× | no semantic change |
| 9 | `55a250b` | **Blocks.reserve + emplace_back** | 31 409 | **1.48×** | drops 80B move + realloc |
| 10 | `689e5d5` | **Succs/Preds split → EdgeTables** | 28 185 | **1.65×** | GasBlock 80→40B |
| 11 | `f7630d8` | GasBlock 32-byte field reorder | 28 762 | 1.62× | static_assert locked |
| 12 | `c5db655` | Round-1 review fixes (+ assert) | — | — | docs + 1 assert |
| 13 | `de507df` | Round-2 review polish | — | — | docs only |
| — | HEAD | + Round-1/2 fixes incl. assert | 29 302 | 1.59× | |

> Note: per-commit numbers are measured single-shot serial, so system thermal drift can pollute the relative deltas between neighbouring commits. The authoritative cumulative number is the previous section's round-robin N=100k 1.78×.
> The three largest single-step contributions are **Preds/Succs CSR (+18%)** + **Blocks.reserve + emplace_back (+6%)** + **EdgeTables split (+10%)** — together accounting for ~34% of this PR's total speedup.

---

## Per-phase time migration from PR A to HEAD (N=100k, 50-rep mean)

| Phase | PR A baseline (us) | HEAD (us) | Δ% |
|---|---:|---:|---:|
| computeDomInfo | 10 818 | 4 482 | **-58.6 %** |
| buildGasBlocks | 10 350 | 2 181 | **-78.9 %** |
| computeInCycle | 7 263 | 37 | **-99.5 %** (skipped on reducible) |
| buildCFGEdges | 5 477 | 4 512 | -17.6 % |
| lemma614Schedule | 3 091 | 886 | -71.3 % |
| computeReachable | 2 531 | 1 076 | -57.5 % |
| computeReverseTopo | 2 423 | 197 | **-91.9 %** (shares RPO) |
| buildLoopsUsingDominance | 2 076 | 1 348 | -35.1 % |
| findBackEdges | 1 938 | 1 099 | -43.3 % |
| splitCriticalEdges | 933 | 366 | -60.8 % |
| writeback | 783 | 399 | -49.0 % |
| meteringInit | 533 | 842 | +57.9 % (local regression, cache effect) |
| collectJumpDests | 484 | — | folded into buildGasBlocks |
| buildCSR (new) | — | 3 326 | new flatten cost |
| buildJumpDestMap (newly timed) | — | 35 | pre-existing, this PR added the instrumentation |
| **Σ instrumented** | **48 700** | **20 786** | -57 % |
| **TOTAL median** | **47 343** | **27 945** | **-41 %** |

Observations:

- **Almost every phase shrank** (meteringInit is the only exception — its +0.3 ms local regression is dwarfed by the -19 ms global win).
- buildCSR (3.3 ms) is a new cost, but it buys ~6 ms back on the readers (computeDomInfo / buildLoopsUsingDominance / computeInCycle combined).
- HEAD's Σ instrumented (20.8 ms) < median total (27.9 ms); the ~7.2 ms gap is unprofiled outer-scope work in `buildBytecodeCache`, dominated by `Cache.PushValueMap` and similar vector allocations (`Cache.PushValueMap` = 9.6 MB at the synthetic N=100k). For production EIP-170 24 KB code the same outer allocation is ~0.2 ms — negligible.

---

## Test gates (re-run after every commit)

| Gate | Result |
|---|---|
| `tools/format.sh check` | clean |
| `cmake --build build --target dtvmapi -j$(nproc)` | no new warnings |
| `build/evmCacheTests` | **14/14 pass** |
| `evmone-statetest --vm external_vm -k fork_Cancun` | **2723/2723 pass** (~77 s) |
| `chkFixpointRounds` diagnostic | 2 at every measured N (confirms SemiNCA is not worth it) |

---

## Out of scope but already decided on data

- **Stack-SSA + SCCP** (originally planned as PR B): measurement shows statetest 92.5% / evmone-bench 98.4% of JUMPs are already resolved by the existing PUSH→JUMP heuristic; 96.8% of contracts have zero dynamic JUMPs. Expected < 1% runtime perf gain against 500+ LoC of SSA construction. **Drop**.
- **SemiNCA dominator**: CHK converges in exactly 2 rounds at every measured N; SemiNCA's best-case saving is the second sweep (~1.5 ms) against its own ~1-2 ms of DSU bookkeeping. **Drop**.
- **GasBlock hot/cold field split**: potential +1–2 ms, diminishing returns; defer.
- **PushValueMap zero-init elimination**: 9.6 MB synthetic overhead; production cost is ~0.2 ms, not worth chasing; defer.
- **Real-corpus paired measurement**: this PR adds a directional B-lite pilot (next section); the full BCa harness remains a post-merge follow-up.

---

## B-lite Sourcify pilot (directional sanity check, n=10)

**Methodology caveats** (read before the numbers):

- Source: 10 mainnet contracts fetched via `eth_getCode` from `https://ethereum.publicnode.com`, **selection-biased toward high-traffic stablecoin / DEX / wrapped-asset contracts** (USDT/USDC cluster, Uniswap, WETH9, etc.) — not a random sample.
- Pairing: same machine, same session. The baseline binary (upstream/main `ef062ae`, **without** `ZEN_EVM_CACHE_PROFILE`) and the HEAD binary (this PR's HEAD, **also without** profile instrumentation to avoid the ~13 phase × ~1 µs chrono overhead distorting small-contract readings) each run 15 reps per contract, per-contract median, then the paired ratio.
- Statistics: **point estimate only, no BCa CI / cluster bootstrap**. This is a directional pilot, not production-grade methodology. The full Sourcify paired-ratio BCa cluster-bootstrap is a post-merge B' L1 follow-up.
- Interpretation limits: n=10 is too thin to support any confidence-interval claim; treat the numbers as "directional signal on a head-contract sample."

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

**Stratum aggregate** (median of per-contract medians):

| Stratum | n | Median baseline (us) | Median HEAD (us) | Median speedup | Median Δ% |
|---|---:|---:|---:|---:|---:|
| small (<4KB) | 3 | 71.9 | 64.9 | **1.11×** | +9.7% |
| medium (4-16KB) | 4 | 343.1 | 341.3 | **1.12×** | +10.4% |
| large (16-25KB) | 3 | 1374.7 | 1003.9 | **1.25×** | +20.0% |

**Overall (n=10)**: median speedup **1.17×**, median Δ **+14.9%** (HEAD vs upstream/main `ef062ae`).

**Observations**:

- 9 / 10 contracts run faster on HEAD; the spread tracks `CodeSize` monotonically (small +9.7%, medium +10.4%, large +20.0% median), matching the synthetic cross-N curve direction.
- **DAI -21.5% outlier**: 7.9 KB contract, baseline 279 us → HEAD 339 us. Similarly-sized rETH (8.8 KB) shows +15.6% and USDT (11 KB) +14.6%. The outlier survives 15-rep medians, so it does not look like pure noise; logged as a follow-up item, **not a ship blocker**. Plausibly a DAI-specific CFG worst case for HEAD's access pattern; revisit once a larger B' L1 BCa corpus with more per-contract repeats lands.
- p95 absolute reduction (across the 10 contracts): roughly -500 us (UniV3NFTManager saves 504 us).

---

## Future-work C-rubric (operationalized decision rule)

Whether C (4 cache-build micro-opts: `computeReachable` fold / `buildCFGEdges` dedup-skip / `buildCSR` prefetch hints / `GasBlock` hot/cold field split) ships is decided by B' data. **Thresholds are pre-committed** to avoid post-hoc rationalization once numbers land:

**GO** (all clauses must hold to start a follow-up PR covering all 4 opts):

| # | Threshold | Measurement source |
|---|---|---|
| (i) | Production N ≲ 8000 paired median speedup vs PR A **≥ +5%** AND p95 absolute reduction **≥ 0.2 ms** | B' L1 Sourcify paired-ratio BCa |
| (ii) | End-to-end evmone-bench median improvement **≥ +1%** AND p95 improvement **≥ +3%** | B' L2 evmone-bench |
| (iii) | N=2000 stratum paired median speedup **≥ 50% of** N=100k stratum speedup | B' L1 stratified by N |
| (iv) | Total first-touch p95 latency reduction **≥ +5%** | B' L3 reth / payload-style |

**KILL** (any clause fails → drop all of C, pivot to a runtime / JIT / host-call hotspot):

- If (i) fails → cache-build has no visible payoff at production scale, so further work on this axis is wasted effort.
- If (ii) or (iv) fail while (i) and (iii) hold → the cache-build gain gets diluted downstream; runtime is where the marginal improvement lives.
- If (iii) fails (production-scale gain is much smaller than synthetic) → EIP-170 self-kill territory; C's gain at N ≲ 2000 would be <50 µs, marginal at best.

**Partial** ((i) holds but (ii)(iii)(iv) are borderline): ship only the top-2 (`computeReachable` fold + `GasBlock` hot/cold split — both backed by reachability / access-pattern data); drop the other two (prefetch hints assume the hardware prefetcher is not already saturated; dedup-skip on a 4.5 ms baseline produces < 0.5 ms saving).

**B-lite data against the C-rubric (current state)**: partially satisfies clause (i) first half (small <4KB stratum median +9.7%, medium +10.4%); the second half (≥ 0.2 ms absolute reduction) holds only on the medium and large strata — on small the absolute reduction is ~7 µs = 0.007 ms, well below the gate. But B-lite **cannot substitute for B' L1** (no BCa CI, n=10 too thin); the final C decision must wait for the full B' L1 run.
