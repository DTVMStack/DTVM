# PR #446 Round-2 Review Response Plan

- **Status**: Revised after round-1 review (Opus + Codex)
- **Date**: 2026-05-12
- **Parent change**: `README.md` (SPP CFG implicit-dyn-pred Phase 7)
- **Branch**: `feat/gas-check-placement`

This plan addresses the 2026-05-12 self-review of post-rebase PR #446,
revised after round-1 dual-reviewer feedback. Round-1 surfaced four
substantive corrections: R1.1 is not directly observable, R1.2 needs a
stronger oracle, R2 is a real semantic change (not a perf guard), and
R3's target should be the stale comment at evm_cache.cpp:1054-1059.

## Blocking before merge

### R1 — Targeted cache-builder unit tests for Phase 7 invariants

**Symptom**: Phase 7 introduces two new mechanisms — `ImplicitDynamicPredCount`
folded into `effectivePredCount`, and a reachability stitch that seeds every
JUMPDEST as a BFS root after `computeReachable`. No test in `src/tests/`
exercises either directly. The 223+215+2723 corpus pass empirically but
won't isolate a regression in the stitch or implicit-pred logic.

**Observability constraint** (from round-1 review): `struct GasBlock` and
`ImplicitDynamicPredCount` are file-static in `src/evm/evm_cache.cpp` (line
~197). Only `EVMBytecodeCache` arrays are exposed via `evm_cache.h`.
**`GasChunkCostSPP[i] != 0` is not a valid oracle for "block was reached"**
— `buildGasChunksSPP` writes every non-empty block's `Metering[Id]` into
`GasChunkCostSPP` regardless of whether SPP analysis reached it
(evm_cache.cpp:1207-1219). The only valid oracle is the **specific shifted
value at PC**: when SPP analysis ran on a block, the shifted value differs
from the unshifted base cost in a deterministic, hand-computable way.

**Fix**: add a new test executable `evmCacheTests` to `src/tests/CMakeLists.txt`
that includes `evm/evm_cache.h` directly and drives `buildBytecodeCache`.
Use raw-hex bytecode fixtures.

Three cases:

1. **`Stitch_Reaches_DynOnly_JumpDest_Affects_SPP`**
   Fixture: a contract where one JUMPDEST `A` has NO static predecessor
   (only reachable via a dynamic JUMP elsewhere). `A` has a successor `S`
   with `effectivePredCount(S) == 1` and a non-terminator cost that
   lemma 6.14 would shift back into `A`.

   **Oracle caveat (round-2 review)**: `computeReverseTopo`
   (evm_cache.cpp:697-735) iterates every block without filtering by
   `Reachable[]`, so the negative-control claim "without stitch, S not
   in RevTopo" would be wrong. What actually changes when the stitch
   fires is `computeDominators` input (Reachable-gated at
   evm_cache.cpp:630-633): with stitch, A's dom-set is computed against
   a live forward CFG; without stitch, A is self-dom.
   `findBackEdgesUsingDominators` and the loop-aware shift path then
   diverge.

   Oracle: build the cache twice — once with the stitch live (current
   code) and once with a test-local stitch-off path that no-ops the
   seed loop. Assert `GasChunkCostSPP[A.Start]` differs between the two.
   This is a "stitch toggles observable behavior" assertion; it does NOT
   require hand-computing the exact shifted value, but does require a
   stitch-off variant accessible to the test (a `#ifdef
   DTVM_TEST_STITCH_OFF` block, or duplicate the build path in the test
   TU with the seed loop disabled). If the toggle mechanic proves too
   invasive, skip case 1 and rely on cases 2 and 3 below.

2. **`No_Shift_Into_Implicit_MultiPred_JumpDest`**
   Fixture: a JUMPDEST `B` with exactly 1 explicit static predecessor AND
   ≥ 1 implicit dyn-jump source elsewhere in the contract.
   - lemma 6.14 INTO `B`: `effectivePredCount(B) = 1 + DynamicJumpCount ≥ 2`,
     should refuse to shift cost from B's predecessor INTO B.
   - Assertion: `GasChunkCostSPP[predOf_B.Start]` is NOT modified by a
     shift that would have moved cost into `B`. Concretely, the shifted
     value at the predecessor should not include any contribution from
     `B`'s base cost.

3. **`Shift_OUT_From_MultiPred_JumpDest_Still_Works`** (added per round-1
   reviewer note)
   Fixture: a JUMPDEST `M` that has multiple implicit dyn-pred (so
   `effectivePredCount(M) > 1`, no shift INTO M), but has at least one
   successor `T` with `effectivePredCount(T) == 1`.
   - lemma 6.14 looks at M's successors (evm_cache.cpp:960-972). The
     check is on `effectivePredCount(Blocks[Succ])`, NOT on M itself. So
     shifting cost from `T` back into `M` IS still allowed.
   - Assertion: `GasChunkCostSPP[M.Start]` reflects the shift FROM T, i.e.
     is greater than `GasChunkCost[M.Start]` (M's unshifted base cost).

**Verification**:
- New test target builds and links cleanly.
- All three cases pass; explicitly disabling the stitch (debug experiment)
  must make case 1 fail (oracle is meaningful).
- `tools/format.sh check` clean.
- Existing 223/215/2723 corpus unaffected.

**Out of scope**: bytecode fuzzing. Targeted hand-crafted fixtures only.

### R2 — Restrict stitch BFS seeding to dyn-target JUMPDESTs only

**Re-framed per round-1 review**: this is a **semantic change**, not a
perf guard. The current stitch (evm_cache.cpp:1066-1092) seeds every
JUMPDEST as a BFS root, including:

1. JUMPDESTs in no-dyn-jump contracts that are statically dead (no pred).
2. JUMPDESTs in mixed contracts (dyn + static) that have no static or
   implicit-dyn predecessor — i.e. genuinely-dead JUMPDESTs that no jump
   targets at all.

Pre-Phase-7, both classes were unreachable in `Reachable[]` and therefore
ignored by `computeDominators` / `lemma614Update`. Post-Phase-7, both
classes are now in `Reachable[]`, their dom-tree positions get computed
(evm_cache.cpp:630-657), they enter `RevTopo`, and `lemma614Update` is
called on them (evm_cache.cpp:1127-1132 has no `Reachable[]` gate). So
their loop / backedge / SPP decisions are now potentially different.

**Why this blocks**: silent semantic change on a class of contracts the
post-rebase 27-bench corpus doesn't isolate. The behavior change is
benign in most cases (dead JUMPDESTs have no out-flow, so no cost shifts
through them), but it widens the dom/loop analysis input set in ways the
review can't fully predict.

**Fix**: change the stitch seed set from "all JUMPDESTs" to "only JUMPDESTs
with `ImplicitDynamicPredCount > 0`". Implementation: inside the stitch
loop (currently evm_cache.cpp:1076-1080), gate the `if (Reachable[JdId] == 0)`
seed with `if (Blocks[JdId].ImplicitDynamicPredCount > 0)`. This restores
pre-Phase-7 behavior on truly-dead JUMPDESTs while still rescuing real
dyn-targets.

**Verification**:
- `Reachable[]` is internal to `buildGasChunksSPP`; the public header
  only exposes `GasChunkCost{,SPP}`, `JumpDestMap`, `PushValueMap`,
  `GasChunkEnd` (evm_cache.h:18-36). So the test asserts on cache state
  delta, not on `Reachable[]` directly.
- Fixture: contract with no dyn-jumps + one statically-dead JUMPDEST
  `D`. With R2's gate, `D.ImplicitDynamicPredCount == 0`, the stitch
  skips it, and `D`'s `Metering[]` value remains its unshifted base
  cost (no `lemma614Update` call considers shifting into `D` because
  no block has `D` in its Succs). Assertion:
  `GasChunkCostSPP[D.Start] == GasChunkCost[D.Start]` (no shift).
  Without the gate (regression case), `D` is in `Reachable[]`,
  `computeDominators` may treat its position differently, and a
  shift may alter `GasChunkCostSPP[D.Start]`. The before/after is the
  observable delta. Implement as a unit test in `evmCacheTests`.
- Existing tests pass.

**Out of scope**: revisiting whether the dom/loop analyses should run on
unreachable nodes at all. The conservative move here is to preserve
pre-Phase-7 behavior on the dead-island class.

### R3 — Fix the stale CFG comment block at evm_cache.cpp:1054-1059

**Symptom**: the comment block above the `buildCFGEdges` call site at
`evm_cache.cpp:1054-1059` reads:

```
// Build CFG with over-approximation for all unresolved dynamic jumps.
// Static jumps (PUSH → JUMP) get precise single-target edges; dynamic
// jumps get edges to every JUMPDEST. This is intentionally conservative —
// ...
```

The text "dynamic jumps get edges to every JUMPDEST" is **wrong** post-
Phase-7. Inside `buildCFGEdges` (evm_cache.cpp:446-447) the new behavior
is explicitly "No explicit Succs/Preds edges added" for dyn jumps. A
future contributor reading the call-site comment will be misled.

**Why this blocks**: stale documentation lures contributors into
re-introducing the D × J explicit edges (undoing Phase 7) "to match the
documented behavior".

**Fix**: replace the call-site comment block (1054-1059) with one that
matches the new implementation. Suggested text:

```
// Build CFG. Static jumps (PUSH → JUMP) get precise single-target edges.
// For unresolved dynamic jumps the CFG is kept sound by stamping each
// JUMPDEST with ImplicitDynamicPredCount instead of materialising the
// D × |JUMPDEST| explicit edges — that count is folded into
// `effectivePredCount`, so `lemma614Update`'s "shift only into
// single-effective-pred successors" check behaves identically to the
// old explicit-edge representation. The `splitCriticalEdges` pass below
// operates on explicit Succs/Preds and therefore never sees dyn-jump →
// JUMPDEST edges; that is intentional because the multi-predecessor
// guard in `lemma614Update` (with implicit count folded INTO
// effectivePredCount) blocks shifts whenever effective preds > 1.
```

**Wording rationale (round-2 review note)**: an earlier draft said "any
`ImplicitDynamicPredCount > 0` rejects shifts INTO". That is wrong when
`ImplicitDynamicPredCount == 1` and the JUMPDEST has no explicit static
pred — `effectivePredCount` would be 1 and the guard would NOT fire. In
practice that case is moot (no block has the JUMPDEST in its Succs when
all entries are dyn, so no `lemma614Update` call considers shifting
into it), but the comment must phrase the invariant in terms of
`effectivePredCount > 1` to be technically correct.

**Verification**: comment correct vs implementation. No code change.

## Non-blocking nice-to-have

### R5 — Soften the `loop_full_of_jumpdests` compile-time claim

**Symptom**: `docs/changes/2026-05-11-spp-cfg-implicit-dyn-pred/README.md`
claims "7.3s → 3.3s" without noting that this is a local single-machine
measurement, not regression-protected by CI.

**Fix**: update the README phrasing to "7.3s → 3.3s on a local
single-machine run; not currently tracked in CI". Defer adding a
compile-time bench lane to a separate PR.

### R6 — Optional paranoid assert in implicit-pred stamp loop

**Symptom**: `buildCFGEdges` stamps `ImplicitDynamicPredCount` on every
block ID in `JumpDestBlocks` without verifying each ID is actually a
JUMPDEST opcode.

**Fix (if cheap)**: add `ZEN_ASSERT(Blocks[JdId].LastOpcode == evmc::OP_JUMPDEST)`
before the stamp. Skip if `ZEN_ASSERT` is not available in this TU
without dragging in extra includes.

## Dropped

### R4 — Document duplicated `isGasChunkTerminator` check — **dropped**

Round-1 review: the comment block above `effectivePredCount` (~line
930-937) already documents the multi-pred guarantee, and the
`MinSucc = 0` rationale is already commented at evm_cache.cpp:963-967.
Adding another comment is noise per `.claude/rules/cpp-code-style.md`
("Only include essential comments").

## Execution order

1. **R3** (comment-only) — lowest risk, no code behavior change. Land
   first so any subsequent diff stays small.
2. **R2** (stitch-gate) — code change. Verify via fixture that
   statically-dead JUMPDESTs return to `Reachable[]=0`.
3. **R1** (3 unit tests). Build `evmCacheTests` and ensure all three
   cases pass against the post-R2 implementation.
4. **R5** (doc softening) — one-line phrase change.
5. **R6** (assert) — optional, decide at execution time based on header
   reach.

After each step: `tools/format.sh check`, build target, run unit tests.

## Verification gate before commit

- New `evmCacheTests` target builds and all 3 cases pass.
- `tools/format.sh check` clean.
- `cmake --build build --target dtvmapi -j$(nproc)` clean (no new warnings).
- `evmone-unittests` multipass: 223/223 pass.
- `evmone-statetest --fork Cancun` multipass: smoke run.

## Risks

- **R1 fixture authoring** is the largest unknown. Hand-computing the
  expected shifted SPP value requires careful bytecode design. If
  difficulty exceeds budget, fall back to a single "stitch toggles
  observable behavior" assertion (case 1 only).
- **R2 semantic change** may surface in the existing 2723 statetest
  corpus. If so, this becomes a 3-way decision: revert R2, narrow the
  guard further, or accept the semantic broadening. Run statetest after
  R2 lands.
- **R3, R5, R6** carry no runtime risk.

