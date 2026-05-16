# Phase 2 R2 Spec Review — Opus, DTVM senior reviewer

Scope: verify v2 closes 13 Opus + 3 Codex findings from R1; flag any new
issue.

## R1-fix verification

| # | R1 finding | Status | Evidence |
|---|---|---|---|
| 1 | 9/9 not 14/14 in Step 1 | ✓ | `README.md:80` "9/9 evmCacheTests"; `:231` Checklist "9/9 evmCacheTests pre-Step-5 pass" |
| 2 | Strata 7 dims, both docs | ✓ | `README.md:143` lists 7; `problem-statement.md:61-67` lists 7. Same set |
| 3 | Risk 1 phase from bench CSV | ✓ | `README.md:192-193` "Phase 数据来自 Step 7 bench CSV(`phase_us` 列),**不是** distribution.md" |
| 4 | `objdump` diff pipeline concrete | ✓ | `README.md:93-103` gives `nm -D` symbol diff + `objdump -d --disassemble='zen::evm::buildGasChunksSPP*'` pipeline |
| 5 | Warning baseline pinned | ✓ | `README.md:104` pins `upstream/main @ ef062ae`, saves to `/tmp/dtvm-warning-baseline.log` |
| 6 | 5 GTests concrete Succs | ✗ partial | `SelfLoop` and `IrreducibleSCC` have `Succs/Reachable` (`README.md:123-124`). `NestedSharedExit` (`:125`) literally says "CFG (略,Step 5 实现时给具体 Succs)". `CriticalEdgeEmptySplit` (`:126`) and `DynTargetInStaticLoop` (`:127`) also narrative-only. Bar set by ask was "at least IrreducibleSCC" → meets ask, but R1 finding 6 wanted all 5; still half-satisfied |
| 7 | `tracked_shifts` defined | ✓ | `README.md:222` "Step 5 在 `lemma614Update` 内部加 instrumentation(`#ifdef ZEN_EVM_CACHE_FUZZ_TRACE`),记录每次 `Metering[i] -= delta` 时 `(i, delta)` event" |
| 8 | Sourcify BigQuery dataset | ✓ | `README.md:135` names framework, `contract_deployments`/`compiled_contracts`/`sourcify_matches`, with "TBD-at-acquisition" for `project.dataset.table` — meets ask |
| 9 | Strata allocation algorithm | ✓ | `README.md:144-147` proportional + min-per-stratum + N_target=100 + 80-120 tolerance |
| 10 | BCa specs | ✓ | `README.md:114-118` cluster bootstrap on contracts, jackknife `a` (Efron 1987), paired-ratio per contract, 1000 resamples, gate `r_upper_CI ≤ 0.85` |
| 11 | proxy/impl PR-B-only flag | ✓ | `README.md:155` "`proxy-vs-impl` 标签是 future-use(PR B 触发条件判断用),本 PR 仅记录不 gate" |
| 12 | Interpreter 215 unique | ✓ | `README.md:173` "226 行 但 215 个 unique 测试名(11 duplicate entries),gate 是 **215/215 unique tests pass**" |
| 13 | Cancun block pinning | ✓ | `README.md:138-140` block 19426587 + range [19426587, 21000000] + snapshot block 21000000; `problem-statement.md:68` same |

R1 Codex points (Check 5, 6, 7): all closed — block range concrete (`README.md:138-140`); Alchemy archive RPC wording clarified (`:202` "Alchemy free tier **包含** archive `eth_getCode` 访问"); BigQuery dataset acknowledged TBD-at-acquisition framework (`:135`).

## Step coherence (14/14 grep)

`rg "14/14|14 evmCacheTests" README.md` finds only Step 5 (`:131`), Step 9 (`:171`), Checklist Step 5 (`:235`) — all **post** Step 5. Step 1 (`:80`) and Checklist Step 1 (`:231`) use 9/9. Coherent.

## Project-rule cross-check

- `dtvm-build-config.md`: spec uses raw cmake (Step 2), consistent with perf-baseline exception; CI job not mocked locally. OK.
- `dtvm-local-test.md`: `src/evm/` + `src/compiler/` neither touched — only `src/evm/evm_cache*`. Touches `src/tests/` and `tools/`. Step 9 runs multipass unittests 223 + interpreter 215 + statetest 2723 — over-cautious but no violation.
- `commit-conventions.md`: not dictated. OK.

## NEW issue introduced by v2 fix

⚠ **`IrreducibleSCC` CFG is reducible by DTVM's reducibility check.**

`README.md:124` (and `problem-statement.md:96`) defines:
- `Succs={0:{1,2}, 1:{3}, 2:{3}, 3:{4}, 4:{3,5}, 5:{}}`
- Expected: `IDom=[0,0,0,0,3,4]`, `buildLoopsUsingDominance` returns `false`, `UseLinearSPP=false`.

CHK trace on this CFG converges to `IDom=[0,0,0,0,3,4]` (matches spec). But back-edge `4→3` makes header=3, `collectNaturalLoop(4,3)` body = `{3,4}`. DTVM's reducibility check (`src/evm/evm_cache.cpp:1000`) is `Dom.dominates(header, body_node)` for every body node:
- `Dom.dominates(3, 3)` = true (self).
- `Dom.dominates(3, 4)` = true (`IDom[4]=3`).

So `buildLoopsUsingDominance` returns **`true`**, contradicting the spec's `UseLinearSPP=false` expectation. The CFG is structurally reducible — header 3 dominates its loop body — even though `{1,2}` are sibling entries from node 0. The spec confuses "two external entries to a header" with classical irreducibility ("two nodes in an SCC where neither dominates the other intra-cycle").

A genuine irreducible-SCC shape that fails DTVM's check: `Succs={0:{1,2}, 1:{2,3}, 2:{1,3}, 3:{}}` — 2-cycle `{1,2}` with both as external entries, neither dominates the other inside the cycle. Back-edge `2→1` (or `1→2`) yields loop body that includes a node not header-dominated.

Impact: as written, the test either fails (assertion contradicts code) or gets silently rewritten to assert `UseLinearSPP=true`, gutting its purpose (exercise the fallback path). R1 finding 4 (TDD risk) becomes acute.

## Verdict

R1 fixes 1-5, 7-13: closed. Fix 6 partially closed (3/5 tests still narrative). Codex 5-7: closed. **One NEW ⚠**: `IrreducibleSCC` CFG predicts wrong outcome — must redesign the fixture (swap to intra-cycle multi-entry shape, re-trace IDom, confirm `Dom.dominates(header, body)` fails for at least one node). Fix is mechanical but blocks Step 5 implementation per R1 finding 4 (TDD).

**REVISE**
