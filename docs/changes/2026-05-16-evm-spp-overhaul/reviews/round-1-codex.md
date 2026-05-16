# Phase 2 R1 Spec Review — skeptic

### Check 1: ✓ Cited line numbers / files exist
**Evidence**: `rg -n '([A-Za-z0-9_./-]+\.(cpp|h|hpp|md|txt|sh|py|cmake|CMakeLists\.txt)):[0-9]+' README.md` produced no matches.
**Finding**: The spec has file paths but no `src/file:line` references to resolve. Vacuous pass.

### Check 2: ✓ Cherry-pick claim
**Evidence**: `git rev-parse upstream/main` -> `ef062ae3add1ba1bd02ef0a176d26b415d14e929`. `git merge-base upstream/main a1fc6db17cbe418aa1f2a6c083e742432d601675` -> `ef062ae3add1ba1bd02ef0a176d26b415d14e929`. `git show --no-patch --format='%H %P%n%s' a1fc6db 993feb3` showed `a1fc6db17cbe418aa1f2a6c083e742432d601675` parent `ef062ae3...`, and `993feb3c0812e5ebe463501df8c75e1ec6e16c39` parent `a1fc6db...`. `git merge-tree ... | rg 'CONFLICT|<<<<<<<|changed in both'` found no conflict markers for both commits; `git diff --check upstream/main..993feb3 -- src/evm/evm_cache.cpp src/evm/evm_cache_for_testing.h src/tests/evm_cache_tests.cpp` -> `diff_check_exit=0`.
**Finding**: The two commits sit linearly on top of `upstream/main`; clean cherry-pick is supported.

### Check 3: ✓ Test names already taken?
**Evidence**: `rg -n 'Dominators_|SelfLoop|IrreducibleSCC|NestedSharedExit|CriticalEdgeEmptySplit|DynTargetInStaticLoop' src/tests/evm_cache_tests.cpp` listed existing tests only: `LinearChain_Correct` at `src/tests/evm_cache_tests.cpp:116`, `DiamondCFG_Correct` `:132`, `NestedLoop_Correct` `:150`, `DisjointRoots_SelfIdom` `:169`, `ClassCDescendant_SeedsAtInit` `:195`.
**Finding**: Proposed names in README `:86-90` are new; no naming conflict found.

### Check 4: ✓ `ZEN_` flag namespace
**Evidence**: `nl -ba CMakeLists.txt | sed -n '28,84p'` shows `option(ZEN_ENABLE_EVM ...)` at `CMakeLists.txt:32`, `ZEN_ENABLE_EVM_GAS_REGISTER` at `:49`, `ZEN_ENABLE_EVM_STACK_SSA_LIFT` at `:52`, and `ZEN_ENABLE_LINUX_PERF` at `:71`.
**Finding**: DTVM CMake options use `ZEN_`; `ZEN_EVM_CACHE_PROFILE` is namespace-consistent. `ZEN_ENABLE_EVM_CACHE_PROFILE` would match the dominant `ZEN_ENABLE_*` style more closely, but current naming is not invalid.

### Check 5: ✗ Cancun-era block range
**Evidence**: README only says `Cancun-era block range` at `README.md:96`; problem statement says `Cancun activation 后 ~1 month` at `problem-statement.md:68`. Ethereum execution-specs lists Cancun at block `19426587` on `2024-03-13`: https://github.com/ethereum/execution-specs . Local calculation: `python3 - <<'PY' ...` -> `19426587 216000 19642587`.
**Finding**: The spec still uses `~1 month`; it should pin a concrete range, e.g. `[19426587, 19642587]` or another explicitly justified end block.

### Check 6: ✗ `eth_getCode` / archive RPC
**Evidence**: ethereum.org documents `eth_getCode(address, QUANTITY|TAG)` and block-parameter semantics: https://ethereum.org/developers/docs/apis/json-rpc/#eth_getcode . Alchemy and QuickNode both document `eth_getCode`: https://www.alchemy.com/docs/reference/eth-getcode , https://www.quicknode.com/docs/ethereum/eth_getCode . Alchemy says archive methods including `eth_getCode` need archive data for blocks older than 128 blocks, but also says free tier has archive access: https://www.alchemy.com/docs/what-is-archive-data-on-ethereum . QuickNode says archive data is included across all plans: https://www.quicknode.com/answers/full-node-vs-archive-node/ .
**Finding**: The JSON-RPC interface is right, but README `:144` says Alchemy/Infura paid tier and README `:147` says QuickNode free tier. At least the Alchemy paid-tier assertion is contradicted by Alchemy docs; provider/access wording needs correction.

### Check 7: ✗ Sourcify BigQuery dataset name
**Evidence**: Sourcify docs say they provide a public BigQuery dataset and a Google account is needed: https://docs.sourcify.dev/docs/bigquery/ . Sourcify DB docs say verified contracts couple `contract_deployments` and `compiled_contracts`, and metadata is in `sourcify_matches`: https://docs.sourcify.dev/docs/repository/sourcify-database/ . Parquet docs list `sourcify_matches`, `compiled_contracts`, `contract_deployments`, etc.: https://docs.sourcify.dev/docs/repository/download-dataset/ . Local `bq` verification failed: `zsh:1: command not found: bq`.
**Finding**: The table names are grounded, but README `:96-98` does not pin actual BigQuery `project.dataset.table` names. This remains not directly executable.

### Check 8: ✓ `≥15% lower CI bound` measurement
**Evidence**: `problem-statement.md:79-82` defines ratio `t_new[i] / t_old[i]`, BCa CI on median, and gate `1 - upper_ratio_ci_bound >= 0.15`; README `:107` summarizes "lower bound ≥ 15%".
**Finding**: Internally consistent. For a time ratio, the worst-case improvement uses the upper ratio bound, so the formula is correct.

### Check 9: ✓ Out-of-scope conflicts
**Evidence**: README excludes PR B/C design at `README.md:187-192`; problem statement "Future consumers" uses trigger/threshold framing at `problem-statement.md:115-130`. Earlier problem-statement table still mentions `src/common/`, scheduler, feature-flag, and shadow-compare at `problem-statement.md:28-29`.
**Finding**: Cold-read mostly coherent. Minor leak remains before the neutral future-consumer section, but the spec does not make PR B/C designs PR A acceptance criteria.

### Check 10: ✓ Bench tool dependencies
**Evidence**: README `:61` says `numpy`, `scipy.stats`, optional `pandas` are declared in `tools/requirements.txt` and not bound into CMake. README `:62` says `google-cloud-bigquery` and `web3.py` are local one-time acquisition and not CI.
**Finding**: Dependencies are documented as tooling-only, not CI/build requirements.

### Check 11: ✓ 5 GTest fixtures constructive
**Evidence**: README names five cases at `README.md:84-92`. Two constructive sketches: `Dominators_SelfLoop`: `Succs={{0}}; Reachable={1}; IDom={0}`. `Dominators_IrreducibleSCC`: `Succs={{2},{2},{3},{2,4},{}}; Reachable={1,1,1,1,1}; IDom={0,1,2,2,2}` for two external roots into SCC `{2,3}` plus exit.
**Finding**: At least two fixtures are implementable from the spec names. The other three still need exact expected arrays before implementation.

REVISE
