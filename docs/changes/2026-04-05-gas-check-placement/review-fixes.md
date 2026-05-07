# PR #446 Review Response Plan

- **Status**: Implemented (F1, F4, F5); F2/F3 applied to PR body; F6 dropped
- **Date**: 2026-05-07
- **Parent change**: `README.md` (gas check placement w/ mixed CFG, SPP JIT output, interpreter-mode gating)
- **Branch**: `feat/gas-check-placement`

## Status update (2026-05-07)

- **F1 implemented** in commit `81efba3` — `Prev2Pc/Prev2Opcode` removed,
  whole-repo grep clean, `GasBlock` shrinks ~9 bytes.
- **F4 implemented** in commit `81efba3` (squashed with F1) — added the
  soundness-pairing comment to `buildCFGEdges`.
- **F5 implemented** in commit `691069a` — `CacheNeedsSPP` lifecycle
  invariant comment added.
- **F2 / F3 applied** to the PR body via `gh pr edit` — Copilot threads
  noted as already-resolved + content-stale (live GraphQL confirmed
  `isResolved: true` for all three before the edit), perf table
  rewritten with honest +17 to +22.8% jump-heavy regressions from the
  latest CI bot output.
- **F6 dropped** — opening an upstream issue for an `addEdge` O(deg²)
  concern that was theoretical, unmeasured, and not touched by any
  commit on this branch would have been noise. The concern remains
  documented below for future reference but no issue is filed.

This plan addresses the findings of the 2026-05-07 self-review of PR #446.
Items are grouped by whether they block merge.

## Blocking before merge

### F1 — Remove dead `Prev2Pc` / `Prev2Opcode` tracking

**Symptom**: `src/evm/evm_cache.cpp:195, 198` add two `GasBlock` fields and
`src/evm/evm_cache.cpp:323-324` write them in `buildGasBlocks`, but no
reader exists in `src/` or `tests/`. The PR description justifies them as
"future 3-instruction call-site window lookup", but Phase 5 (commit
`c26bf7c`) removed call-site enumeration entirely, so the rationale no
longer applies on this branch.

**Why this blocks**: a fresh reviewer will re-question every PR cycle until
the dead fields are gone or have a concrete forward link. Leaving them in
also adds a small per-block bookkeeping cost on every cache build.

**Fix**: remove `GasBlock::Prev2Pc`, `GasBlock::Prev2Opcode`, and the two
writes inside `buildGasBlocks`. Verify no header or test exposes them.

**Verification**:
- `grep -rn 'Prev2Pc\|Prev2Opcode'` (whole repo) returns nothing.
- `tools/format.sh check` clean.
- Local `evmone-unittests` multipass + interpreter both pass — confirm no
  hidden dependency surfaces.

**Side effect to note in commit body**: `GasBlock` shrinks by ~9 bytes
(one `uint32_t` + one `uint8_t` + alignment). Cache memory footprint
drops marginally; not expected to perturb perf but worth flagging.

**Out of scope**: re-introducing the tracking when a real consumer lands.
That belongs in the consumer's own PR.

### F2 — Annotate PR body re: stale Copilot AI threads

**Symptom**: the three Copilot AI inline comments on PR #446 target an
earlier iteration that included `ResolvedJumpTargets` and call-site
enumeration. Phase 5 (`c26bf7c`) deleted that code, making the threads
content-stale.

**Round-2 update**: a live GraphQL query
(`gh api graphql ... reviewThreads`) on 2026-05-07 confirmed that all
three Copilot threads are **already** `isResolved: true` (Copilot author
login: `copilot-pull-request-reviewer`). zoowii's design-doc thread is
also resolved. So the previously-planned `resolveReviewThread` mutation
is unnecessary.

**Why this still matters (downgraded from blocking)**: even though the
threads are visually collapsed, the resolution didn't cite the commit
that made them obsolete. A future reviewer expanding the threads can
still be confused. A short pointer in the PR body removes that
confusion.

**Fix**:
1. Edit the PR description to add a short "Resolved review threads" line
   noting that Phase 5 commit `c26bf7c` (call-site enumeration removal)
   makes the three Copilot AI inline threads content-stale; threads are
   already resolved on the GitHub side.
2. Do **not** edit, reply to, re-resolve, or unresolve any thread — they
   are already in the correct state, and zoowii's thread must be left
   alone per the "no-auto-reply-to-zoowii" rule.

**Verification**:
- `gh api graphql -f query='query{repository(owner:"DTVMStack",name:"DTVM"){pullRequest(number:446){reviewThreads(first:50){nodes{id isResolved comments(first:1){nodes{author{login}}}}}}}}'`
  still reports `isResolved: true` for all 4 threads (3 Copilot + 1
  zoowii) after the PR body edit.
- `gh pr view 446` shows the PR body now mentions `c26bf7c` as the
  commit that obsoleted the call-site / `ResolvedJumpTargets`
  discussion.

### F3 — Make `weierstrudel` / `jump_around` regression visible in PR body

**Symptom**: the multipass perf table shows `weierstrudel/15 +17.5%`,
`weierstrudel/1 +19.5%`, `micro/jump_around/empty +22.8%` — within the
25% gate but clustered near the ceiling. The current PR description
groups them with "small regressions remain (≤ +6%)" which is wrong, and
buries them in the per-bench list.

**Why this blocks**: hides a known design-tradeoff cost from upstream
reviewers; if a future contract trips +25%, reviewers will treat it as a
new regression rather than the predicted cost of mixed-CFG over-approx.

**Fix**: rewrite the "Risks" / "Evaluation" section of the PR body to:
1. Correct the "≤ +6%" claim; explicitly list the ~+17 to +23% jump-heavy
   regressions with the actual numbers.
2. State that these are the predicted cost of CFG over-approximation on
   jump-heavy contracts (consistent with the design-doc rationale) — not
   noise.
3. Note the 25% threshold buffer is intentional but tight; if a future
   contract trips, the right move is to investigate that contract, not
   to widen the threshold.

**Verification**:
- Read the rewritten PR body once before pushing, confirm each cited
  number matches the CI bot's latest table (per the
  "PR perf table integrity" rule, regenerate from the bot, do not paste
  from memory).

## Non-blocking follow-ups (file as TODO comments + GitHub issue)

### F4 — Document `buildCFGEdges` over-approx invariant

`buildCFGEdges` is at `src/evm/evm_cache.cpp:389-429`. Its function-level
comment (lines 386-388) and inline branch comment (lines 419-422) already
explain *why* over-approximation is intentional, but neither links forward
to the soundness mechanism that absorbs the cost (`lemma614Update` at line
920, which uses the `effectivePredCount > 1` guard at line 911 to refuse
shifting along over-approx edges).

Append one sentence to the function-level comment block at lines 386-388:

> "After this pass, JUMPDEST blocks may have many predecessors; this is
> the intentional partner to `lemma614Update`'s `effectivePredCount > 1`
> guard, which refuses to shift gas across edges with multiple
> predecessors and so absorbs the over-approximation soundly."

Documentation only — no behavior change. ~3-line edit at the function
header.

### F5 — `CacheNeedsSPP` lifecycle invariant comment

The `CacheNeedsSPP` field is at `src/runtime/evm_module.h:82` (already
has a short comment about JIT consumption). The lifecycle constraint is
visible at `src/runtime/evm_module.cpp:117` (set before
`performEVMJITCompile`), `:125` (`getBytecodeCache` triggers build), and
`:135` (`initBytecodeCache` reads `CacheNeedsSPP`).

Append to the field's existing comment:

> "Must be set before any `getBytecodeCache()` call — once the cache is
> built, the `EnableSPP` decision is fixed for the lifetime of the
> module. Future lazy / on-demand JIT paths must flip this flag before
> triggering the lazy cache build."

Documentation only.

### F6 — `addEdge` O(deg²) compile-time guardrail [DROPPED 2026-05-07]

**Status**: dropped. Opening an upstream issue about a code path none
of the F1/F4/F5 commits touch, with no measured evidence of compile-
time pain on the existing CI matrix, would have been noise.

**Original concern (kept for future reference)**: `addEdge`
(`src/evm/evm_cache.cpp:204` area) uses `std::find` for dedup, giving
O(current_deg) per insertion. Combined with over-approximated
dynamic-jump edges (`|JUMPDEST| × |dynamic jumps|`), pathological
contracts could inflate compile time. Phase 4 gating limits exposure
to JIT-consumer modules.

**If a future contract trips this**: capture the offending bytecode
+ JIT compile-time profile first, then either (a) switch `Succs` /
`Preds` to a `vector<uint32_t>` + `unordered_set<uint32_t>` hybrid for
O(1) dedup, or (b) add a `LOG_INFO` warning when
`JumpDestBlocks.size() * dynamic_jump_count` exceeds a threshold so
the next tuning cycle has telemetry. Don't act preemptively.

## Sequencing

| Step | Action | Where |
|------|--------|-------|
| 1 | F1: remove `Prev2Pc/Prev2Opcode` (1 commit) | `src/evm/evm_cache.cpp` |
| 2 | F4 + F5: documentation tweaks (1 commit, squashable) | `src/evm/evm_cache.cpp`, `src/runtime/evm_module.h` |
| 3 | Build + format + local test gate (see below) | `tools/format.sh` + `evmone-unittests` + `evmone-statetest` + `ctest` |
| 4 | Push to `feat/gas-check-placement`; await CI green (~35 min for the multipass perf job) | — |
| 5 | F2: edit PR body to point at `c26bf7c` (no thread mutation — Round-2 live query confirmed all 4 threads already resolved) | GitHub web/CLI |
| 6 | F3: rewrite Evaluation section in PR body using numbers from the latest CI bot table (per "PR perf table integrity" rule, never paste from memory) | GitHub web/CLI |
| 7 | (F6 dropped) | — |

## Out-of-scope

- Re-introducing call-site resolution / `ResolvedJumpTargets`: belongs in
  a future PR with a real consumer (e.g. MIR direct-branch optimization).
- Tuning the 25% perf threshold or adjusting individual bench tolerances:
  that is a CI-config concern, not a code change.
- Switching `addEdge` data structure: see F6 — follow-up only.

## Quality gates

Before pushing the F1+F4+F5 commit, the build must use the CI-faithful
flag set (`.claude/rules/dtvm-build-config.md` /
`.claude/rules/match_ci_cmake_flags`): in particular
`-DZEN_ENABLE_JIT_PRECOMPILE_FALLBACK=ON` and `-DZEN_ENABLE_LIBEVM=ON`,
otherwise interpreter / fallback paths run a different code shape than
CI.

1. `tools/format.sh check` clean.
2. `cmake --build build --target dtvmapi -j$(nproc)` succeeds, no new
   warnings.
3. `evmone-unittests` multipass: 223/223 pass.
4. `evmone-unittests` interpreter: 215/215 pass.
5. `evmone-statetest --fork Cancun` multipass: 2723/2723 pass (current
   baseline; the count must match — any drop is a regression).
6. `evmone-statetest --fork Cancun` interpreter: must match the pass
   count reported by the most recent CI green run on
   `feat/gas-check-placement` (binary equality — record it once before
   making the F1+F4+F5 commit so the local re-run can be compared
   exactly, not just "all green").
7. `ctest` from `build/` (the project's built-in EVM spec tests, per
   `.claude/rules/dtvm-local-test.md`).
8. CI green on the new push, including the matrix jobs:
   `Build and test DTVM multipass on x86-64`,
   `Build and test DTVM interpreter on x86-64`,
   `Test DTVM-EVM JIT fallback in release mode with ctest on x86-64`,
   `Test DTVM-EVM multipass evmtestsuite with gas register in release
   mode with ctest on x86-64`,
   `Performance Regression Check (interpreter)` and
   `Performance Regression Check (multipass)`.
   (~35 min for the multipass perf job.)

Skip F3 (PR-body edits) until F1+F4+F5 commits land and CI passes, since
the PR description should match the final state of the branch.
