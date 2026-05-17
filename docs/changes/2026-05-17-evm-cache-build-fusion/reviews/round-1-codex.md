VERDICT: REVISE

## §1 Numbers reproduced

- Ran:
  `for n in 10000 100000; do echo "N=$n"; for i in $(seq 1 25); do build/evmCacheComplexityDemo "$n" 2>&1 | awk -F, -v run="$i" '/^synthetic/{print run ",total," $3} /^EVM_CACHE_PROFILE,chkFixpointRounds/{print run ",chkFixpointRounds," $3} /^EVM_CACHE_PROFILE,buildGasBlocks/{print run ",buildGasBlocks," $3}'; done; done`
- Got:
  - N=10000 total samples included `6,total,1809.583`, `13,total,2084.185`, `25,total,1885.755`; sorted median = `2054.900 us`.
  - N=100000 total samples included `1,total,26092.034`, `13,total,26737.925`, `25,total,24603.599`; sorted median = `25720.439 us`.
  - N=100000 `buildGasBlocks` samples included `1,buildGasBlocks,1986`, `13,buildGasBlocks,1823`, `25,buildGasBlocks,1759`; sorted median = `1824 us`.
  - Every synthetic sample printed `chkFixpointRounds,2`.
- Doc claimed:
  - N=10000 this PR = `2163 us`: docs/changes/2026-05-17-evm-cache-build-fusion/README.md:256.
  - N=100000 this PR = `27764 us`: docs/changes/2026-05-17-evm-cache-build-fusion/README.md:259.
  - N=100000 `buildGasBlocks` this PR = `2157 us`: docs/changes/2026-05-17-evm-cache-build-fusion/README.md:227.
  - `chkFixpointRounds` = 2 at every N: docs/changes/2026-05-17-evm-cache-build-fusion/README.md:124-129 and :286.
- Conclusion:
  - N=10000 drift = `(2054.900 - 2163) / 2163 = -5.0%` (borderline, just under/at threshold depending rounding).
  - N=100000 drift = `(25720.439 - 27764) / 27764 = -7.4%`: **drift > 5%; headline current-HEAD number did not reproduce**.
  - N=100000 `buildGasBlocks` drift = `(1824 - 2157) / 2157 = -15.4%`: phase number also drifted materially.
  - `chkFixpointRounds=2` reproduced for synthetic N=10k and N=100k in this run, but not "at every N" beyond the measured set.
- Stack-SSA percentages are **unverified / non-reproducible from this PR**. The doc says the numbers came from instrumentation (README.md:100-108) and then says the counter was removed (README.md:340-342). Current source has `DynamicJumpCount` only for behavior, not corpus reporting: src/evm/evm_cache.cpp:516-550.
- Baseline `47429 us` was not independently rebuilt in this review. The current worktree binary only verifies PR HEAD. Treat baseline speedup and `-41.5%` as **unverified** unless the baseline commit is rebuilt under the same config.

Gates run:

- `tools/format.sh check`
  - Exit code: `123`.
  - Output excerpt:
    - `src/singlepass/x64/assembler.h:34:3: error: code should be clang-formatted [-Wclang-format-violations]`
    - `src/platform/sgx/zen_sgx_file.h:65:31: error: code should be clang-formatted [-Wclang-format-violations]`
  - Doc claimed clean: docs/changes/2026-05-17-evm-cache-build-fusion/README.md:281 and :366. **Mismatch.**
- `build/evmCacheTests`
  - Exit code: `0`.
  - Output:
    - `[==========] Running 14 tests from 2 test suites.`
    - `[  PASSED  ] 14 tests.`
  - Matches doc: README.md:283 and :365.
- `cmake --build build --target dtvmapi -j$(nproc)`
  - Exit code: `1`.
  - Output: `ccache: error: failed to create temporary file for /home/abmcar/.cache/ccache/tmp/cpp_stdout.tmp.vOM4Ed.ii: Read-only file system`.
  - Re-run to isolate sandbox/ccache: `CCACHE_DISABLE=1 cmake --build build --target dtvmapi -j$(nproc)`.
  - Exit code: `0`.
  - Output: `[4/5] Creating library symlink lib/libdtvmapi.so.0.1 lib/libdtvmapi.so`.
  - Conclusion: build can succeed with ccache disabled; the exact documented command failed in this environment.
- Optional statetest:
  - Ran: `EVMONE_EXTERNAL_OPTIONS="$(pwd)/build/lib/libdtvmapi.so,mode=multipass,enable_gas_metering=true" ~/evmone/build/bin/evmone-statetest /home/abmcar/DTVM/tests/fixtures/fixtures/state_tests --vm external_vm -k fork_Cancun`
  - Exit code: `0`.
  - Output:
    - `[==========] Running 2723 tests from 101 test suites.`
    - `[==========] 2723 tests from 101 test suites ran. (76931 ms total)`
    - `[  PASSED  ] 2723 tests.`
  - Matches doc: README.md:284.

## §2 Commit ↔ doc alignment

- Ran: `git log --oneline perf/evm-spp-foundation..HEAD`
- Got:
  - `4f9f5be docs(docs): add change doc for evm-cache-build-fusion PR`
  - `f7630d8 perf(core): pack GasBlock to exact 32 bytes via field reorder`
  - `689e5d5 perf(core): split per-block Succs/Preds out of GasBlock into EdgeTables`
  - `55a250b perf(core): reserve Blocks + emplace_back to drop GasBlock move/realloc cost`
  - `77e0454 style(core): apply tools/format.sh to evm_cache.cpp after PR C work`
  - `118c993 perf(core): share computeDomInfo RPO with computeReverseTopo`
  - `de934a8 perf(core): fuse buildCFGEdges two passes into a single sweep`
  - `6e1bc6b perf(core): derive InCycle from natural loops on reducible CFGs`
  - `4d74033 perf(core): add chkFixpointRounds counter to diagnose CHK convergence`
  - `0dd5bb9 perf(core): flatten Preds/Succs into CSR for cache-locality on hot passes`
  - `3bba649 perf(core): fold collectJumpDests into buildGasBlocks single walk`
  - `e06d291 perf(core): fuse buildGasBlocks 2-pass into single bytecode walk`
- Conclusion: the branch range has **12 commits**, not 11, if the doc commit is counted. The implementation list in README.md:184-219 contains 11 non-doc commits, so the doc should say "11 implementation commits + doc commit" or scope the count explicitly.
- Commit hashes/messages listed in README.md:186-219 match the 11 implementation commits from `git log`.
- The `buildGasBlocks 9525 -> 2157 us (-77%)` table is cumulative from PR A baseline to final HEAD, not the `e06d291` per-commit delta:
  - `e06d291` commit body says `phase buildGasBlocks: 10614 us -> 9250 us (-13%)`.
  - `f7630d8` commit body says `phase buildGasBlocks: 2515 us -> 2157 us (-14%)`.
  - README.md:225-241 labels the table "PR A baseline" vs "This PR HEAD", so the cumulative interpretation is internally consistent.
- The doc's net diff claim is stale/wrong:
  - README.md:143-144 says `+236 / -171 lines`.
  - Ran: `git diff --stat perf/evm-spp-foundation..HEAD src/evm/evm_cache.cpp && git diff --numstat ...`
  - Got: `1 file changed, 312 insertions(+), 188 deletions(-)` and `312 188 src/evm/evm_cache.cpp`.

## §3 Code-level audits

### 3.1 GasBlock sizeof

- Source:
  - Layout comment: src/evm/evm_cache.cpp:222-232.
  - Struct fields: src/evm/evm_cache.cpp:233-246.
  - Static assert: src/evm/evm_cache.cpp:247-249.
- Ran a local `offsetof` probe with the same field order.
- Got: `sizeof=32 align=8 Start=0 End=4 LastPc=8 PrevPc=12 ImplicitDynamicPredCount=16 LastOpcode=20 PrevOpcode=21 Cost=24`.
- Conclusion: PASS. The doc/source offset annotations match clang/gcc layout rules on this target.

### 3.2 Blocks.reserve safety

- Source:
  - `Blocks.reserve(CodeSize)`: src/evm/evm_cache.cpp:407-415.
  - `GasBlock &Block = Blocks.emplace_back()`: src/evm/evm_cache.cpp:424.
  - `splitCriticalEdges` later appends blocks: src/evm/evm_cache.cpp:332-383.
- Safety conclusion:
  - The reference taken in `buildGasBlocks` is safe: no later `Blocks.emplace_back()` occurs while that `GasBlock &Block` is live in the inner loop.
  - The broad doc wording is too strong. README.md:31-33 says "`Blocks` is reserved up front to `CodeSize` so `emplace_back` never reallocates"; that is true for the original block construction only, not necessarily after `splitCriticalEdges` appends synthetic blocks at src/evm/evm_cache.cpp:377-382.
  - I do not see an outstanding `GasBlock&` across the `splitCriticalEdges` `Blocks.push_back`, so I do not see a current invalid-reference bug. The missing piece is an explicit statement that the no-realloc guarantee is limited to `buildGasBlocks`, not post-split graph mutation.

### 3.3 CSR build correctness

- Source:
  - `EdgeTables::resize`: src/evm/evm_cache.cpp:259-262.
  - CSR uses `Tables.size()`, not `Blocks.size()`: src/evm/evm_cache.cpp:301-315.
  - Initial edge-table resize from `Blocks.size()`: src/evm/evm_cache.cpp:1306-1308.
  - `splitCriticalEdges` grows both `Blocks` and `Edges`: src/evm/evm_cache.cpp:377-382.
  - CSR built after split: src/evm/evm_cache.cpp:1314-1324.
- Conclusion: current path keeps `Edges` aligned with `Blocks` because every split append is paired with `Edges.Succs.emplace_back()` and `Edges.Preds.emplace_back()`.
- Risk: no invariant check catches future drift. If `Edges.size() != Blocks.size()`, `buildAdjacencyCSR` silently sizes the graph from `Edges`, while later code indexes with `Blocks.size()` / `JumpDestBlocks` / `RevTopoIndex` at src/evm/evm_cache.cpp:1326-1408. Add an assert before CSR build or inside `buildAdjacencyCSR` taking expected node count.

### 3.4 Conditional InCycle correctness

- Source:
  - Tarjan SCC implementation: src/evm/evm_cache.cpp:565-653.
  - Natural-loop construction and reducibility checks: src/evm/evm_cache.cpp:1022-1107.
  - Conditional Tarjan skip: src/evm/evm_cache.cpp:1382-1408.
- The theorem in README.md:307-318 is asserted in doc and commit text, not proven in source. The code does include two structural checks: every loop member dominated by header (src/evm/evm_cache.cpp:1086-1094) and overlapping loops must be nested or disjoint (src/evm/evm_cache.cpp:1096-1107).
- The doc makes a false test-coverage claim:
  - README.md:145-147 says existing 14 tests include `IrreducibleImproperRegion`.
  - Ran: `rg -n "IrreducibleImproperRegion|irreducible|Tarjan fallback|UseLinearSPP=false" src/tests docs/changes/...`
  - Got no `IrreducibleImproperRegion` test in `src/tests/evm_cache_tests.cpp`; the only live test comment says "This test exercises only the IDom output..." and "Exercising the SPP reducibility fallback itself requires end-to-end buildBytecodeCache plumb and is deferred" at src/tests/evm_cache_tests.cpp:271-276.
- Conclusion: REVISE. The fallback branch exists and statetest passes, but the specific irreducible/Tarjan-fallback coverage claimed by this PR doc is not present in the current tests.

### 3.5 computeReverseTopo equivalence

- Source:
  - Old algorithm at `118c993^`: `computeReverseTopo(const CSRGraph&, BackEdges)` uses a stack and pre-marks successors visited before push: old src/evm/evm_cache.cpp:932-972 from `git show 118c993^:src/evm/evm_cache.cpp`.
  - New algorithm returns `reverse(Dom.RPO)`: src/evm/evm_cache.cpp:974-987.
  - New comment claims `computeDomInfo already runs exactly that DFS`: src/evm/evm_cache.cpp:974-979.
- Ran a small trace using the old source algorithm and the new `reverse(Dom.RPO)` traversal on two CFGs.
- Got:
  - `OverlappingBackEdgesIDom fixture`
  - `old: 1 0 3 2 5 4`
  - `reverse(Dom.RPO): 5 4 3 2 1 0`
  - `PR-A irreducible SCC shape`
  - `old: 1 2 0 3`
  - `reverse(Dom.RPO): 3 2 1 0`
- Conclusion: BLOCKER for the claim, not necessarily for behavior. The equivalence assertion in README.md:29-30 and commit `118c993` is not supported by tracing the previous algorithm. If the new order is still valid for `lemma614Schedule`, the doc/commit should justify validity directly, not claim equality with the old output.

## §4 Doc quality

- R1-R5 coverage is incomplete:
  - R2 says `IrreducibleImproperRegion` covers the fallback (README.md:314-316), but that test is absent and current tests explicitly defer the fallback plumbing (src/tests/evm_cache_tests.cpp:271-276).
  - R5 admits the Stack-SSA counter was removed (README.md:340-342), so the 92.5% / 98.4% decision data is not reproducible from this PR.
  - R1 covers reserve memory, but not the narrower truth that `reserve(CodeSize)` only guarantees no realloc during initial block construction, while `splitCriticalEdges` can append synthetic blocks later.
- The "Cross-N speedup scales with N because cache density compounds" sentence is plausible but not proven by the presented data. README.md:261-263 attributes the scaling to cache hierarchy effects, but the benchmark is a synthetic generator (README.md:270-274). It could also be generator/pathology-specific. Mark as hypothesis unless backed by hardware counters or a real-corpus paired run.
- Full-tier template:
  - Template requires Overview, Motivation, Impact, Implementation Plan, Compatibility Notes, Risks: docs/changes/template.md:7-49.
  - This doc has Overview/Motivation/Impact/Implementation Plan/Risks, but uses `### Compatibility` under Impact (README.md:172-175) instead of a top-level `## Compatibility Notes`. Mostly acceptable structurally, but not exact to template.
- Commit conventions:
  - Rule says commit/PR format is `<type>(<scope>): <subject>` and to read `commitlint.config.js`: .claude/rules/commit-conventions.md:13-22.
  - Allowed types include `perf`, `style`, `docs`; allowed scopes include `core`, `docs`: commitlint.config.js:15-47.
  - The implementation commit headers in `git log` conform to type/scope enums.

## §5 Verdict reasoning

REVISE.

This PR has good signs: `evmCacheTests` pass, optional statetest reproduced `2723/2723`, `GasBlock` really is 32 bytes, and the implementation commit list mostly aligns with the doc.

But the review should not pass as written because several factual claims are wrong or unsupported:

- Current HEAD N=100k median reproduced at `25720.439 us`, not doc `27764 us`; drift is `-7.4%`, above the requested 5% threshold.
- `tools/format.sh check` failed with exit code `123`, while the doc says clean.
- The doc claims a test named `IrreducibleImproperRegion` exercises the Tarjan fallback; current tests do not contain that test, and an existing comment says fallback plumbing is deferred.
- The `computeReverseTopo == reverse(Dom.RPO)` equivalence claim failed on a direct trace of the old algorithm vs new traversal.
- Stack-SSA corpus percentages and baseline `47429 us` were not reproducible from this PR as checked out.

Required doc/code fixes before PASS: correct the benchmark table with reproducible raw data or explain environment drift; fix or qualify the format gate; remove/replace the nonexistent test claim; either prove/test the InCycle fallback path or label it untested; and rewrite the `computeReverseTopo` claim from "same output" to a directly verified correctness argument.
