Verdict: REVISE — the implementation tracks the §Design spec closely and the three caller rewrites use the correct (dominator, dominated) order, but (a) a class-C *descendant* corner case produces a strictly weaker dominance relation than the old bitset pass, and (b) the GTest set never exercises the post-fixpoint sweep (class C) it is designed to handle. Other findings are NITs.

## 1. Spec compliance — PASS

- CHK intersect with postorder fingers — `src/evm/evm_cache.cpp:708-726`. Walks the lower-postorder finger up the partially-built IDom tree, matches Cooper-Harvey-Kennedy 2001 Fig. 3.
- Multi-root divergence sentinel — `src/evm/evm_cache.cpp:712-715` and `:717-722` return `UINT32_MAX` iff a finger reaches its own root (`P == B1 || P == UINT32_MAX`). Caller at `:748-751` flags `Diverged=true` and falls back to self-root at `:754-755`. Matches §Design step 5 (option (a) from R2: divergence-only at this site).
- Post-fixpoint sweep — `src/evm/evm_cache.cpp:767-771`. Promotes residual `UINT32_MAX` (class C and any orphan reachable component) to self-root. Matches §Design step 7.
- Enter/Exit DFS on a single global `Time` counter — `src/evm/evm_cache.cpp:789-808`. Iterates roots in node-id order, recurses through `Children[]` (inverted IDom), increments `Time` on both enter and exit. Each root receives a disjoint `[Enter, Exit]` interval, so cross-root pairs correctly answer `dominates == false`.

## 2. Output semantics — PASS (argument orders correct)

`bitsetTest(Dom[X], Y)` reads "Y dominates X", i.e. Y is the dominator candidate. The rewrites:

| Old site | New site | Call |
|----------|----------|------|
| `evm_cache.cpp:684` (`bitsetTest(Dom[From], To)`) | `evm_cache.cpp:823` | `Dom.dominates(To, From)` — back-edge: To dominates From. ✓ |
| `evm_cache.cpp:793` | `evm_cache.cpp:932` | `Dom.dominates(To, From)` — header discovery: same orientation. ✓ |
| `evm_cache.cpp:838` | `evm_cache.cpp:979` | `Dom.dominates(Loop.Header, Node)` — loop-body sanity: header dominates body. ✓ |

`grep -n "Dom.dominates" src/evm/evm_cache.cpp` returns exactly these 3 hits — no stragglers.

## 3. DomInfo::dominates correctness — PASS

`evm_cache.cpp:623-631`. The interval-containment invariant `Enter[A] <= Enter[B] && Exit[B] <= Exit[A]` is correct iff the Enter/Exit DFS assigns each subtree a contiguous interval. The DFS at `:789-808` does exactly this:
- Pre-tick on push (`Info.Enter[Root] = Time++` at `:794`; `Info.Enter[C] = Time++` at `:801`).
- Post-tick on pop (`Info.Exit[Top.Node] = Time++` at `:804`).

For any A ancestor of B in the dom tree, A's subtree DFS strictly encloses B's, so `Enter[A] < Enter[B] && Exit[B] < Exit[A]`. For cross-root pairs, the global counter ticks monotonically across roots, so two roots get strictly disjoint intervals; non-containment holds.

## 4. BLOCKER — Class-C *descendant* drift from old bitset semantics

Location: `src/evm/evm_cache.cpp:737-762` (fixpoint inner loop) and `:767-771` (sweep).

Scenario: node N is class C (`Reachable[N]==1`, `Preds` non-empty, all preds `Reachable==0`). Node M has `Reachable[M]==1` and its only Reachable pred is N.

- **Old bitset pass** (`computeDominators`, removed): N's `HasPred=false` branch produced `Dom[N] = {N}`. For M, `Dom[M] = (All & Dom[N]) ∪ {M} = {N, M}` — **N dominates M**.
- **New CHK pass**: At `:738-740` we skip Reachable==0 preds; at `:741-743` we skip preds whose `IDom == UINT32_MAX`. For N: all preds skipped → `NewIDom = UINT32_MAX` → no update. For M (visited later in RPO): its only Reachable pred N still has `IDom = UINT32_MAX` at this point, skipped → `NewIDom = UINT32_MAX` → no update. After the fixpoint converges, both N and M are still `UINT32_MAX`; the sweep at `:767-771` makes both self-roots. **N does NOT dominate M.**

This is a strictly weaker dominance relation than the old pass. The three query sites all read "does X dominate Y"; a false answer can:
- Suppress a back-edge `findBackEdgesUsingDominators` would otherwise detect (`:823`).
- Drop a loop header (`:932`).
- Or, conversely, fail the loop-body sanity check (`:979`) — `buildLoopsUsingDominance` returns false and SPP falls back to non-linear processing.

The change doc (README §Risks bullet 2 at `docs/changes/2026-05-12-evm-dom-chk/README.md:300-304`) only addresses class C *itself*, not its descendants. The doc claims class C "is expected absent post-stitch", but that only protects the node-itself case; a class-C descendant chain (M, M', M'' all only reachable through N) is the broader corner.

Fixes (pick one):

- (a) **Preserve old semantics**: after the post-fixpoint sweep promotes class-C nodes to self, run **one more RPO pass** so descendants pick up the now-promoted class-C node as their IDom seed. (Cheap; a single pass for the rare case.)
- (b) **Treat any reachable orphan as a fresh root at init**: extend the init at `:646-650` to seed `IDom[N] = N` for any node whose Reachable-true pred set is empty (the third class A∪B∪C up front), then the fixpoint and sweep are unchanged.
- (c) **Accept the divergence and prove it cannot affect SPP**: requires a proof that no class-C *chain* survives Phase-7 stitch (the stitch only adds forward edges through Succs, but it can leave class-C descendants if a JUMPDEST chain is entered only via a stitched node whose own preds were stale). I do not see this proof in the change doc.

Recommend (b) — it is one extra line in the init loop and removes the entire foot-gun.

## 5. MED — GTests do not exercise the post-fixpoint sweep

Location: `src/tests/evm_cache_tests.cpp:154-241` (the four new dominator tests).

`LinearChain_Correct`, `DiamondCFG_Correct`, `NestedLoop_Correct` only have nodes that are either Reachable==1 with at least one Reachable pred, or Reachable==1 with empty preds (entry). `DisjointRoots_SelfIdom` exercises true multi-root divergence (preds in distinct forests) — that hits the `intersect → UINT32_MAX → Diverged=true` path at `:748-755`, **not** the post-fixpoint sweep at `:767-771`.

The sweep at `:767-771` is unexercised. The class-C corner from finding 4 is also unexercised. A targeted test would build a 3-node CFG: node 0 with `Reachable==0`, node 1 with `Reachable==1, Preds={0}`, node 2 with `Reachable==1, Preds={1}`. Expected old semantics: `IDom[1]=1, IDom[2]=1`. Current implementation: `IDom[1]=1, IDom[2]=2` (drift). The test makes the drift testable.

Fix: add `ClassC_DescendantsRouteToNodeRoot` (or equivalent name reflecting the chosen resolution from finding 4).

## 6. NIT — Defensive DFS reachability over Succs only

Location: `src/evm/evm_cache.cpp:698-702`.

The defensive DFS visits any unvisited node, but it only follows Succs (`Blocks[Top.Node].Succs` at `:674`). A reachable orphan whose entry has empty Succs (a single-node island with no outgoing edges) would be visited as a 1-node DFS — fine. But if the orphan island is entered only through Preds (reachable from elsewhere via Succs of an unreachable node), the defensive sweep at `:698-702` would visit them in node-id order; not a correctness issue, just noting that "DFS over Succs from every unvisited node" is a strict superset of "DFS over Succs from roots" and the postorder numbering for class-C and orphan nodes is well-defined.

## 7. NIT — Header comment slightly verbose vs project style

Location: `src/evm/evm_cache.cpp:606-617`.

`.claude/rules/cpp-code-style.md` says "Only include essential comments — avoid excessive documentation". The 12-line header is defensible (algorithm + 3 root classes + sentinel rule), but trims well: the §Design table is in the change doc, and the inline comment could be ~4 lines (algorithm name, root semantics, query-helper pointer). Not a blocker.

## 8. NIT — Frame reference is invalidated on push, relies on increment-before-push

Location: `src/evm/evm_cache.cpp:673-686` (DfsFrame) and `:797-806` (EtFrame).

`DfsFrame &Top = Stack.back()` at `:673` is a live reference, and `Stack.push_back(...)` at `:680` may invalidate it. The code increments `Top.SuccIdx` *before* the push and never re-reads `Top` after the push in the same iteration — so this is safe, but it is fragile to future edits. Both stacks are `reserve(N)`'d (`:663`, `:788`) and max depth is ≤ N, so reallocation should not occur even if the push did happen after re-read. Recommend a one-line comment: `// Top may be invalidated by push_back below; do not reuse.`

## 9. NIT — `for_testing::computeIDomForTesting` Preds reconstruction order

Location: `src/evm/evm_cache.cpp:1409-1422`.

Preds are reconstructed in node-id order, which is not necessarily the order Preds appear in the production pipeline (where `buildCFGEdges` may emit them in a different order). The fixpoint inner loop is order-insensitive for correctness (final `NewIDom` is the intersection), but if a future regression test depends on a specific Pred order to trigger a class-C path, the testing shim may mask it. Document the order-insensitive invariant or pin the Preds order to match production.

## 10. Commit message conformance — PASS

Planned title: `perf(core): replace iterative-bitset dominator with Cooper-Harvey-Kennedy algorithm`.

Per `.claude/rules/commit-conventions.md`:
- Type `perf` ✓ (perf change).
- Scope `core` ✓ (touches `src/evm/`, which `repo-architecture.md` groups under core runtime).
- Subject lowercase, imperative ("replace"), no trailing period ✓.
- Length 91 chars < 120 ✓.

## Suggested test additions

1. `ClassC_DescendantsRouteToNodeRoot` — see finding 4/5.
2. `CrossRootDominatesFalse` — direct `DomInfo::dominates(A, B)` check across roots (currently only indirect via IDom equality). Build a 2-disjoint-tree fixture and assert `dominates` returns false for cross-root pairs. (Optional but easy.)

Reviewed by: opus (impl R1)
