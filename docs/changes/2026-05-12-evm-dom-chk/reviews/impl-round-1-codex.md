# R1 implementation review - Codex skeptic

Worktree: `/home/abmcar/DTVM/.worktrees/perf-dom-lengauer-tarjan`

Reviewed current worktree contents, not only `/home/abmcar/.claude/jobs/3d8995d3/dom-chk-impl.diff`. The worktree contains uncommitted edits to `src/evm/evm_cache.cpp`, `src/tests/evm_cache_tests.cpp`, and untracked docs/header files.

## Findings

1. ✗ **Spec consistency: cited line numbers and grep claims are stale.**

   The change doc still cites old implementation lines. Examples:

   - `docs/changes/2026-05-12-evm-dom-chk/README.md:11` says `computeDominators` is at line 619, but `rg -n "computeDominators|computeDomInfo" src/evm/evm_cache.cpp` outputs:
     - `src/evm/evm_cache.cpp:627:static DomInfo computeDomInfo(...)`
     - no `computeDominators` hit.
   - `README.md:87-89` cites `evm_cache.cpp:631` / `660-664` for old init/class-C behavior. Current code has `Info.IDom.assign` at `src/evm/evm_cache.cpp:631`, while class A/B/C init is at `src/evm/evm_cache.cpp:647-660`.
   - `README.md:92` cites the Phase-7 stitch at `evm_cache.cpp:1087-1108`; current stitch is `src/evm/evm_cache.cpp:1227-1260`.
   - `README.md:174-176` lists old query lines 684/793/838. Current query sites are `src/evm/evm_cache.cpp:834`, `:943`, and `:990`.
   - `README.md:178-179` says `grep -n "bitsetTest(Dom" src/evm/evm_cache.cpp` returned three hits. Fresh command `rg -n "bitsetTest\\(Dom" src/evm/evm_cache.cpp` returned no output (exit 1).

2. ✗ **Result numbers are not reproducible exactly.**

   Current doc table at `README.md:256-259` claims `3.38 / 5.90 / 14.48 / 38.95 ms` for `10k/20k/50k/100k`. The user-provided older claim `2.85 / 5.52 / 14.66 / 40.07 ms` is no longer what the current doc says.

   Fresh command:

   ```sh
   for N in 10000 20000 50000 100000; do ./build/evmCacheComplexityDemo $N; done
   ```

   Output:

   ```text
   10000,2.878
   20000,5.978
   50000,16.355
   100000,38.719
   ```

   Thresholds still look satisfied for 20k and 100k, but the published exact table does not match the fresh run, especially 50k.

3. ✗ **Gate counts are partly wrong or unsupported.**

   - ✓ Multipass unit slice is verified. Command:

     ```sh
     EVMONE_EXTERNAL_OPTIONS=.../build/lib/libdtvmapi.so.0.1.0,mode=multipass \
       /home/abmcar/evmone/build/bin/evmone-unittests --gtest_filter="$(paste -sd: tests/evmone_unittests/EVMOneMultipassUnitTestsRunList.txt)"
     ```

     Output ended with:

     ```text
     [==========] 223 tests from 1 test suite ran. (8512 ms total)
     [  PASSED  ] 223 tests.
     ```

   - ✗ Interpreter count in the doc is wrong. `README.md:245` says `215/215`, but:

     ```text
     wc -l tests/evmone_unittests/EVMOneMultipassUnitTestsRunList.txt tests/evmone_unittests/EVMOneInterpreterUnitTestsRunList.txt
       223 tests/evmone_unittests/EVMOneMultipassUnitTestsRunList.txt
       226 tests/evmone_unittests/EVMOneInterpreterUnitTestsRunList.txt
       449 total
     ```

   - ✗ Statetest `2723/2723` is unsupported in this worktree. Command `find . -type f \( -iname '*run*list*.txt' -o -iname '*runlist*.txt' \)` found only the two evmone unit-test run lists, not a statetest run list. Counting current Cancun JSON post entries:

     ```sh
     find tests/evm_spec_test/state_tests -type f -name '*.json' -print0 |
       xargs -0 jq '[.[] | select(.post.Cancun != null) | .post.Cancun | length] | add // 0' |
       awk '{s+=$1} END {print s}'
     ```

     Output:

     ```text
     1798
     ```

     I did not run the slow statetest suite.

   - ✗ The user asked to verify `evmCacheTests 8/8`; current implementation has 9 tests. Current doc `README.md:247` says 9/9, and fresh `./build/evmCacheTests --gtest_color=no` output ends with:

     ```text
     [==========] 9 tests from 2 test suites ran. (0 ms total)
     [  PASSED  ] 9 tests.
     ```

4. ✗ **Format gate is not clean as written.**

   Command:

   ```sh
   tools/format.sh check
   ```

   Exit code: 123. Output starts with unrelated existing files such as:

   ```text
   src/singlepass/x64/assembler.h:34:3: error: code should be clang-formatted [-Wclang-format-violations]
   src/singlepass/x64/asm/assembler.h:340:50: error: code should be clang-formatted [-Wclang-format-violations]
   src/platform/sgx/zen_sgx_file.h:65:31: error: code should be clang-formatted [-Wclang-format-violations]
   ```

   Narrow check for changed files did pass:

   ```sh
   clang-format --dry-run -style=file -Werror src/evm/evm_cache.cpp src/evm/evm_cache_for_testing.h src/tests/evm_cache_tests.cpp
   ```

   Output: none; exit code 0.

5. ✗ **The exact compiler-warning grep is non-empty after a clean rebuild.**

   I first had to set `CCACHE_DIR=/tmp/codex-ccache CCACHE_TEMPDIR=/tmp/codex-ccache/tmp`, because default ccache tried to write `/home/abmcar/.cache/ccache/tmp` and failed under the sandbox.

   Commands:

   ```sh
   CCACHE_DIR=/tmp/codex-ccache CCACHE_TEMPDIR=/tmp/codex-ccache/tmp cmake --build build --target clean
   CCACHE_DIR=/tmp/codex-ccache CCACHE_TEMPDIR=/tmp/codex-ccache/tmp \
     cmake --build build --target dtvmapi -- -j$(nproc) 2>&1 |
     tee /tmp/dtvmapi-build-r1.log |
     grep -E "warning|error"
   ```

   Output includes 9 matches. One match is a false positive on `errors.cpp.o`; the rest are warnings in unrelated files, e.g.:

   ```text
   src/utils/others.cpp:86:10: warning: ignoring return value of 'size_t fread(...)' [-Wunused-result]
   src/common/traphandler.cpp:117:18: warning: cast between incompatible function types ... [-Wcast-function-type]
   src/common/evm_traphandler.cpp:133:18: warning: cast between incompatible function types ... [-Wcast-function-type]
   src/compiler/cgir/pass/cg_inline_spiller.cpp:1405:6: warning: ... defined but not used [-Wunused-function]
   ```

   Build itself succeeded (`/tmp/dtvmapi-build-r1.log` ends with `[100%] Built target dtvmapi`), and `grep -E "warning|error" /tmp/dtvmapi-build-r1.log | rg "evm_cache|evm_cache_tests|evm_cache_for_testing"` produced no output. Still, `README.md:243` claims the gate is clean, and the requested grep is not clean.

6. ✓ **`DomInfo::dominates` interval correctness is structurally sound for valid node IDs.**

   Current formula is at `src/evm/evm_cache.cpp:616-623`:

   ```cpp
   return Enter[A] <= Enter[B] && Exit[B] <= Exit[A];
   ```

   The DFS builds the dom tree by inverting `IDom` at `src/evm/evm_cache.cpp:788-791`, uses a single global `uint32_t Time = 0` at `src/evm/evm_cache.cpp:800`, assigns pre-order enter times at `:805` and `:812`, and assigns post-order exit times at `:815`. That is the standard ancestor interval invariant. The `A == B` fast path returns before bounds checking; all three production callers pass valid block IDs, so this is not a current blocker.

7. ✓ **Caller argument order preserves `(dominator, dominated)` semantics.**

   Fresh `rg -n "Dom\\.dominates" src/evm/evm_cache.cpp` output:

   ```text
   834:      if (Dom.dominates(To, static_cast<uint32_t>(From))) {
   943:      if (!Dom.dominates(To, static_cast<uint32_t>(From))) {
   990:      if (!Dom.dominates(Loop.Header, Node)) {
   ```

   These preserve the original semantic documented at `README.md:168-170`: the first argument is the dominator candidate, second is the dominated node.

8. ✗ **Doc internal consistency still needs revision.**

   - `README.md:188` says loop collection after the PR is `O(Σ |loop|)` interval-containment tests. The current code still performs bitset work: `Words = bitsetWordCount(NumBlocks)` at `src/evm/evm_cache.cpp:928`, ORs every word at `:954-956`, scans all nodes at `:965-979`, and uses bitset intersection/subset checks at `:1000-1004` and later parent selection. Dominance queries are O(1), but loop collection is not accurately described by that table row.
   - `README.md:317-318` says class C is handled "via the post-fixpoint sweep"; current design text says init seeding at `README.md:97-99`, and code implements init seeding at `src/evm/evm_cache.cpp:647-660`. The Risk section is stale.
   - The Risks section does **not** claim O(depth) query worst-case; `README.md:311-312` correctly says the query worst case is unchanged because Enter/Exit DFS is always `O(N + E)`. The remaining `O(depth)` mentions are outside Risks (`README.md:71`, `:73`, `:345`) and refer to `intersect` or a discarded first pass, not current queries.
   - `README.md:274` says "The four new GTests" but lists five, and `README.md:340-341` / `:361-362` still say four tests.

## Verdict

Verdict: REVISE — concrete blockers listed above.

Core implementation checks for interval dominance and the three caller argument orders pass. The blockers are review/documentation/gate integrity issues: stale spec line citations, non-reproducible exact timing table, wrong/unsupported gate counts, global format failure, non-empty warning grep, and inaccurate complexity/risk wording.
