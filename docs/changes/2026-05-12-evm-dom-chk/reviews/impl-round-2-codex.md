# R2 implementation review - Codex skeptic

Date: 2026-05-12
Reviewer persona: skeptical implementation reviewer
Round: R2
Worktree: `/home/abmcar/DTVM/.worktrees/perf-dom-lengauer-tarjan`

## Findings

1. ✓ **R1 stale line-number issue is fixed.**

   The spec now cites `computeDomInfo` at `src/evm/evm_cache.cpp:627` (`docs/changes/2026-05-12-evm-dom-chk/README.md:10-13`), and the current code has `computeDomInfo` at `src/evm/evm_cache.cpp:627-628`. The spec's current query-site table lists post-PR lines 834, 943, and 990 (`docs/changes/2026-05-12-evm-dom-chk/README.md:174-187`), and the current code has `Dom.dominates(...)` at `src/evm/evm_cache.cpp:834`, `src/evm/evm_cache.cpp:943`, and `src/evm/evm_cache.cpp:990`. The reachability stitch citation is also current: the spec cites `evm_cache.cpp:1231-1260` (`docs/changes/2026-05-12-evm-dom-chk/README.md:93-95`), and the code spans `src/evm/evm_cache.cpp:1227-1260`.

   Command evidence:
   ```sh
   rg -n "computeDominators|computeDomInfo|Dom\.dominates|bitsetTest\(Dom" src/evm/evm_cache.cpp
   ```
   Output:
   ```text
   627:static DomInfo computeDomInfo(const std::vector<GasBlock> &Blocks,
   834:      if (Dom.dominates(To, static_cast<uint32_t>(From))) {
   943:      if (!Dom.dominates(To, static_cast<uint32_t>(From))) {
   990:      if (!Dom.dominates(Loop.Header, Node)) {
   1261:  const DomInfo Dom = computeDomInfo(Blocks, Reachable);
   1438:  return computeDomInfo(Blocks, Reachable).IDom;
   ```
   The old `bitsetTest(Dom...)` claim is no longer present as a current-code claim; fresh command `rg -n "bitsetTest\(Dom" src/evm/evm_cache.cpp || echo "<no bitsetTest(Dom) matches>"` printed `<no bitsetTest(Dom) matches>`.

2. ✓ **Gate-7 reproducibility wording is now acceptable.**

   The spec's gate-7 row says single-run wall-clock varies and only the qualitative threshold claim is asserted (`docs/changes/2026-05-12-evm-dom-chk/README.md:257`); the thresholds are listed at `docs/changes/2026-05-12-evm-dom-chk/README.md:270-279`. A fresh run still meets the absolute thresholds and the 50k-to-100k growth heuristic:

   Command:
   ```sh
   CCACHE_DIR=/tmp/codex-ccache CCACHE_TEMPDIR=/tmp/codex-ccache/tmp cmake --build build --target evmCacheComplexityDemo -j$(nproc) >/tmp/dtvm-r2-complexity-build.log &&
   for n in 10000 20000 50000 100000; do ./build/evmCacheComplexityDemo "$n"; done
   ```
   Output:
   ```text
   10000,2.672
   20000,5.395
   50000,15.036
   100000,36.733
   ```

3. ✗ **Gate-count fix is still partly wrong: interpreter 215/226 is duplicates, not absent names.**

   The spec says the interpreter run list has 226 lines but only 215 names exist as live tests, and that gtest silently skips 11 absent names (`docs/changes/2026-05-12-evm-dom-chk/README.md:253-255`). The fresh interpreter run did execute 215 tests:

   Command:
   ```sh
   EVMONE_EXTERNAL_OPTIONS="$(pwd)/build/lib/libdtvmapi.so,mode=interpreter" \
     /home/abmcar/evmone/build/bin/evmone-unittests \
     --gtest_filter="$(paste -sd: tests/evmone_unittests/EVMOneInterpreterUnitTestsRunList.txt)"
   ```
   Output ended with:
   ```text
   [==========] 215 tests from 1 test suite ran. (418 ms total)
   [  PASSED  ] 215 tests.
   ```

   But the reason is not absent names. Fresh counts show 226 lines and 215 unique names:
   ```sh
   printf 'lines '; wc -l < tests/evmone_unittests/EVMOneInterpreterUnitTestsRunList.txt
   printf 'unique '; sort tests/evmone_unittests/EVMOneInterpreterUnitTestsRunList.txt | uniq | wc -l
   ```
   Output:
   ```text
   lines 226
   unique 215
   ```
   Fresh duplicate check lists exactly 11 duplicated run-list names:
   ```sh
   sort tests/evmone_unittests/EVMOneInterpreterUnitTestsRunList.txt | uniq -d | nl -ba
   ```
   Output starts with the 11 duplicate entries, including `multi_vm/evm.call_high_gas/external_vm`, `multi_vm/evm.create/external_vm`, and `multi_vm/evm.sstore_cost/external_vm`. Fresh unique-absence check found zero absent names:
   ```sh
   comm -23 <(sort -u tests/evmone_unittests/EVMOneInterpreterUnitTestsRunList.txt) \
     <(EVMONE_EXTERNAL_OPTIONS="$(pwd)/build/lib/libdtvmapi.so,mode=interpreter" \
       /home/abmcar/evmone/build/bin/evmone-unittests --gtest_list_tests |
       awk '/^[^ ]/ && $1 ~ /\.$/ {suite=$1; sub(/\.$/, "", suite); next} /^  / {test=$1; if (test != "") print suite "." test}' |
       sort -u) | wc -l
   ```
   Output:
   ```text
   0
   ```

   The statetest part of this R1 fix is otherwise supported: the spec says there is no curated statetest run list (`docs/changes/2026-05-12-evm-dom-chk/README.md:255`), and fresh `find . -type f \( -iname '*run*list*.txt' -o -iname '*runlist*.txt' \) -print | sort` found only the two evmone unit-test run lists. A worktree-relative statetest path is unavailable:
   ```sh
   EVMONE_EXTERNAL_OPTIONS="$(pwd)/build/lib/libdtvmapi.so,mode=multipass,enable_gas_metering=true" \
     /home/abmcar/evmone/build/bin/evmone-statetest \
     tests/fixtures/fixtures/state_tests --vm external_vm -k fork_Cancun
   ```
   Output:
   ```text
   path: Path does not exist: tests/fixtures/fixtures/state_tests
   Run with --help for more information.
   ```
   Using the spec's cited local fixture root `~/DTVM/tests/fixtures/` (`docs/changes/2026-05-12-evm-dom-chk/README.md:255`) produced 2723/2723:
   ```sh
   EVMONE_EXTERNAL_OPTIONS="$(pwd)/build/lib/libdtvmapi.so,mode=multipass,enable_gas_metering=true" \
     /home/abmcar/evmone/build/bin/evmone-statetest \
     /home/abmcar/DTVM/tests/fixtures/fixtures/state_tests --vm external_vm -k fork_Cancun
   ```
   Output ended with:
   ```text
   [==========] 2723 tests from 101 test suites ran. (64858 ms total)
   [  PASSED  ] 2723 tests.
   ```

4. ✓ **Format gate is now scoped to PR-changed files.**

   The spec says gate 1 is `clang-format --dry-run -style=file -Werror` on `src/evm/evm_cache.cpp`, `src/evm/evm_cache_for_testing.h`, and `src/tests/evm_cache_tests.cpp`, while repo-wide format failures are pre-existing and unrelated (`docs/changes/2026-05-12-evm-dom-chk/README.md:251`).

   Command:
   ```sh
   clang-format --dry-run -style=file -Werror src/evm/evm_cache.cpp src/evm/evm_cache_for_testing.h src/tests/evm_cache_tests.cpp
   ```
   Output: none, exit 0.

   Fresh repo-wide command `tools/format.sh check` exited 123 and reported unrelated files such as `src/singlepass/x64/assembler.h:34:3`, `src/singlepass/x64/asm/assembler.h:340:50`, and `src/platform/sgx/zen_sgx_file.h:65:31`, matching the spec's out-of-scope framing (`docs/changes/2026-05-12-evm-dom-chk/README.md:251`).

5. ✓ **Warning grep is now scoped to PR-changed files.**

   The spec says gate 2 uses `cmake --build build --target dtvmapi` and only asserts no warnings in PR-touched files, with unrelated pre-existing warnings called out (`docs/changes/2026-05-12-evm-dom-chk/README.md:252`). A clean rebuild with writable ccache completed:
   ```sh
   CCACHE_DIR=/tmp/codex-ccache CCACHE_TEMPDIR=/tmp/codex-ccache/tmp \
     cmake --build build --target dtvmapi -j$(nproc) 2>&1 |
     tee /tmp/dtvm-r2-build-clean-ccachetmp.log
   ```
   Output ended with:
   ```text
   [100%] Built target dtvmapi
   ```

   The changed-files-only grep is empty:
   ```sh
   grep -E "warning|error" /tmp/dtvm-r2-build-clean-ccachetmp.log |
     rg "evm_cache|evm_cache_tests|evm_cache_for_testing" || echo "<no changed-file warnings/errors>"
   ```
   Output:
   ```text
   <no changed-file warnings/errors>
   ```

   Repo-wide warning output remains unrelated to the changed files: fresh `grep -E "warning|error" /tmp/dtvm-r2-build-clean-ccachetmp.log | head -40` reported `src/common/traphandler.cpp:117`, `src/common/evm_traphandler.cpp:133`, `src/utils/others.cpp:86`, and `src/compiler/cgir/pass/cg_inline_spiller.cpp:1405`.

6. ✓ **Loop-collection complexity wording is now scoped to dominance queries.**

   The spec row explicitly says only the dominance-query path moves to interval containment and the surrounding loop-membership bitset code remains bitset-based (`docs/changes/2026-05-12-evm-dom-chk/README.md:193-199`). The code confirms that the dominance queries use `Dom.dominates(...)` at `src/evm/evm_cache.cpp:943` and `src/evm/evm_cache.cpp:990`, while loop membership still uses bitsets at `src/evm/evm_cache.cpp:913-915`, `src/evm/evm_cache.cpp:966-979`, and `src/evm/evm_cache.cpp:998-1004`.

7. ✓ **Step 6 and the Risks update match current behavior.**

   Step 6 says class-C detection moved from the post-fixpoint sweep into init so descendants can intersect against a settled root (`docs/changes/2026-05-12-evm-dom-chk/README.md:373-379`). The risk section says class C is handled by init seeding and the post-fixpoint sweep is only a defensive backstop for orphan reachable components (`docs/changes/2026-05-12-evm-dom-chk/README.md:322-330`). Current code seeds class C during init by scanning reachable predecessors and assigning `IDom[I] = I` when none are reachable (`src/evm/evm_cache.cpp:639-660`), then later runs the fixpoint over non-root nodes (`src/evm/evm_cache.cpp:739-773`) and only then applies the defensive `UINT32_MAX -> self` sweep (`src/evm/evm_cache.cpp:775-782`).

   Cosmetic note: the code comment at `src/evm/evm_cache.cpp:775-777` still says remaining `UINT32_MAX` may be class C, even though current code seeds class C at init (`src/evm/evm_cache.cpp:647-660`). The behavior and spec risk text are aligned; the comment is stale.

8. ✓ **`ClassCDescendant_SeedsAtInit` really exercises the init-time path.**

   The test fixture builds `Succs = {{1}, {2}, {3}, {}}` and `Reachable = {0, 1, 1, 1}` (`src/tests/evm_cache_tests.cpp:241-258`). The testing helper derives `Preds` directly from `Succs` (`src/evm/evm_cache.cpp:1427-1435`), so node 1 has only pred 0, node 2 has only pred 1, and node 3 has only pred 2. The test expects `IDom[1] = 1`, `IDom[2] = 1`, and `IDom[3] = 2` (`src/tests/evm_cache_tests.cpp:260-265`).

   Current init code is what makes that expectation possible: node 1 is reachable, has non-empty preds, and has no reachable pred, so it is seeded as self-root at `src/evm/evm_cache.cpp:651-660`. The fixpoint then skips roots (`src/evm/evm_cache.cpp:742-745`), lets node 2 use processed reachable pred 1 (`src/evm/evm_cache.cpp:748-768`), and lets node 3 use processed reachable pred 2 in the same mechanism. If node 1 were not seeded at init, node 1's only pred 0 would be skipped as unreachable (`src/evm/evm_cache.cpp:748-750`), node 2 would skip pred 1 while `IDom[1] == UINT32_MAX` (`src/evm/evm_cache.cpp:752-753`), and the post-fixpoint sweep would self-root unresolved nodes (`src/evm/evm_cache.cpp:778-780`), contradicting the test's expected `IDom[2] == 1` and `IDom[3] == 2` (`src/tests/evm_cache_tests.cpp:263-265`).

9. ✓ **Required small gates pass on the rebuilt artifact.**

   `evmCacheTests` was rebuilt and run:
   ```sh
   CCACHE_DIR=/tmp/codex-ccache CCACHE_TEMPDIR=/tmp/codex-ccache/tmp cmake --build build --target evmCacheTests -j$(nproc)
   ./build/evmCacheTests
   ```
   Output ended with:
   ```text
   [==========] 9 tests from 2 test suites ran. (0 ms total)
   [  PASSED  ] 9 tests.
   ```

   Multipass evmone unit tests were run with the local-test rule's `~/evmone` binary and `mode=multipass` (`.claude/rules/dtvm-local-test.md:26-35`):
   ```sh
   EVMONE_EXTERNAL_OPTIONS="$(pwd)/build/lib/libdtvmapi.so,mode=multipass" \
     /home/abmcar/evmone/build/bin/evmone-unittests \
     --gtest_filter="$(paste -sd: tests/evmone_unittests/EVMOneMultipassUnitTestsRunList.txt)"
   ```
   Output ended with:
   ```text
   [==========] 223 tests from 1 test suite ran. (8516 ms total)
   [  PASSED  ] 223 tests.
   ```

Verdict: REVISE — concrete blockers listed

- Fix `docs/changes/2026-05-12-evm-dom-chk/README.md:254`: the interpreter 226-to-215 discrepancy is caused by 11 duplicate run-list entries, not by 11 absent test names being silently skipped.
