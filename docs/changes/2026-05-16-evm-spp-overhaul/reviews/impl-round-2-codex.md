REVISE
## 1. Spec Honesty — PASS
README Results marks `total` strict gate `**FAIL**` (`README.md:329-331`) and says production gate `**FAIL**` with override prose (`README.md:394-414`). Addressed.

## 2. Commit Hygiene — PASS
Enum source: types `docs/perf/test/chore` allowed (`commitlint.config.js:19-28`), scopes `core/docs/tools` allowed (`commitlint.config.js:35-45`). Command: `git log ... | awk ...` output: `8a95175 PASS ...`, `b00efa1 PASS ...`, `04d0a55 PASS ...`, `92c6c04 PASS ...`, `a75ab11 PASS ...`, `9df8ee8 PASS ...`, `3c659f6 PASS ...`, `62ef503 PASS ...`, `1be3f39 PASS ...`, `48fada6 PASS ...`. Note: task says 9 commits, supplied range contains 10.

## 3. GTests Scope/Improper CFG — PASS
Dropped assertions are enumerated: loop count/header, `UseLinearSPP`, split-block cost/writeback, `InCycle`, dyn-target `GasChunkCostSPP`, K=1000 path-total fuzz (`README.md:271-283`). Test is renamed `IrreducibleImproperRegion` (`src/tests/evm_cache_tests.cpp:273`) and CFG is `3->{1,4}`, `4->{2,5}` (`src/tests/evm_cache_tests.cpp:274-280`). Command: `./build/evmCacheTests --gtest_filter=EVMCacheDominator.IrreducibleImproperRegion` -> `[  PASSED  ] 1 test.`

## 4. Bench Harness Cite — PASS
`tools/analyze_evm_cache_bench.py:13-16` cites BCa acceleration to “Efron & Tibshirani 1993, An Introduction to the Bootstrap, §14.3”.

## 5. Results Reproduction — REVISE
README says positional demo table is “9 reps, median” (`README.md:361-372`) and variance band is 20-30x (`README.md:380-384`). My command: 9 reps each for N=10000 and N=100000. Output: `N=10000 reps=9 ... speedup=4.77x`; `N=100000 reps=9 baseline_median_us=979931.021 treatment_median_us=50884.126 speedup=19.26x`. This misses the documented 20-30x band, though it still exceeds the 10x gate.

## 6. Dominator NIT — PASS
`DomInfo::dominates` now checks bounds before equality: bounds at `src/evm/evm_cache.cpp:639-642`, `A==B` at `src/evm/evm_cache.cpp:643-645`.

## A. IrreducibleSCC Replacement — PASS
Given IDom assertions `1<-0,2<-1,3<-2,4<-3,5<-4` (`src/tests/evm_cache_tests.cpp:288-293`), `3->1` and `4->2` are dominance back-edges. Hand trace: natural loops are {1,2,3} and {2,3,4}; they intersect but neither is subset. Production check returns false on this shape at `src/evm/evm_cache.cpp:1029-1039`.

## B. Helper Doc — PASS
Header says helper does NOT run `computeReachable`, `splitCriticalEdges`, or dyn-target stitch (`src/evm/evm_cache_for_testing.h:18-21`) and only dominator pass is exercised (`src/evm/evm_cache_for_testing.h:25-26`). Impl builds Succs/Preds then returns `computeDomInfo(...).IDom` (`src/evm/evm_cache.cpp:1470-1481`). Accurate.

## C. Step 5 Downgrade — PASS
The downgrade explicitly says shipped tests cover only `computeIDomForTesting` IDom output (`README.md:285-288`), end-to-end loop/SPP relies elsewhere (`README.md:289-291`), and fuzz is deferred (`README.md:293-297`). Adequate.

Build/tests: `cmake --build build --target dtvmapi evmCacheTests evmCacheComplexityDemo -j$(nproc)` -> `[1/2] Linking CXX executable evmCacheComplexityDemo`; `./build/evmCacheTests` -> `[  PASSED  ] 14 tests.`

Remaining issues: 1. Results variance claim needs refresh or broader rerun explanation.
