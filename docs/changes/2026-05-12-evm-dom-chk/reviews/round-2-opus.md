Verdict: REVISE — §Design step 5 already collapses UINT32_MAX → self mid-fixpoint, so step 7's "post-fixpoint sweep" can never fire on the class-C nodes it claims to handle. This is internal incoherence and needs one of the two paths removed.

## R1 follow-up

- R1-1 (BLOCKER) ✓ Resolved. Line 243: gate 4 reads "**226/226**" and references the run-list `wc -l`; confirmed `wc -l EVMOneInterpreterUnitTestsRunList.txt = 226`.
- R1-2 (HIGH) ◐ Partially resolved. Class C is named explicitly in the init table (line 84) and §Risks bullet 2 (lines 304-311); §Design step 7 adds a post-fixpoint sweep with `ZEN_ASSERT` (lines 117-119). But — see new finding #1 — step 5 also collapses during the RPO loop, making step 7 unreachable. Mark ◐ until one of them is removed.
- R1-3 (HIGH) ✓ Resolved. `dominatesIDom` body at lines 139-149 has the `Finger < IDom.size()` guard; line 152-155 explains rationale.
- R1-4 (MED) ✓ Resolved. §Test plan §4 "DisjointRoots_SelfIdom" (lines 281-285); §Impact line 215 lists "four dominator correctness GTests" including the new one; checklist references 4 tests (lines 366-367).
- R1-5 (MED) ✓ Resolved. Gate 5 (lines 245-248) now reads "zero new failures vs baseline on `feat/gas-check-placement@HEAD`" and defers exact count to Phase 5.
- R1-6 (MED) ✓ Resolved. §Design step 3 (lines 102-106): "Build RPO seeded from the set `{ N : IDom[N] == N }`" — explicit invariant given.
- R1-7 (NIT) ✓ Consistent. Lines 167-176 enumerate 3 sites, matching `grep`.
- R1-8 (NIT) ✓ Resolved. §Risks now has small-N overhead bullet (lines 312-318) and ASAN bullet (lines 319-323); §Verification gates also adds an "ASAN coverage" informational note (lines 260-262).

## New findings

### 1. HIGH — Step 5 and Step 7 are mutually exclusive; pick one
Location: `README.md` §Design steps 4-7 (lines 106-119).

Step 4 computes `new_idom` over "processed reachable preds". For a class-C node (Reachable==1, Preds non-empty, all preds Reachable==0), the processed-reachable-pred set is empty, so `new_idom` never leaves its initial UINT32_MAX. Step 5 then says: "If, after processing all reachable preds, `new_idom` is still `UINT32_MAX`, the driver collapses it to `IDom[N] = N`." This fires during pass 1. By the time step 6's fixpoint converges, every class-C node is already `IDom[N] = N` and step 7's "any node still at UINT32_MAX" branch has nothing to do.

This is two ways of saying the same thing. Worse, the wording in step 5 ("fingers walk off the top without ever meeting") suggests the intended trigger is true multi-root divergence between *processed* preds, not the empty-set case — implying class C is meant to be caught by step 7 alone, not step 5. Pick one path:

- (a) Restrict step 5 to multi-root divergence (≥2 processed preds with no common ancestor) and keep step 7 for the empty-set class-C case.
- (b) Drop step 7 and explicitly state that step 5 also handles the empty-set case.

Option (a) is cleaner for the `ZEN_ASSERT` in step 7 (it can assert `Preds with Reachable==1 == ∅`, which is the actual class-C invariant). Option (b) makes the assertion implicit.

### 2. NIT — RPO-pass convergence claim ("at most 2 passes") needs the class-C caveat
Location: `README.md` §Design lines 121-123.

"For a single-entry reducible CFG, the loop converges in at most 2 passes over RPO." True for the standard CHK case. But under interpretation (a) above, a class-C node won't get its self-IDom until step 7, which runs *after* the fixpoint. Worth noting that the 2-pass bound counts step 7 as a separate finalising sweep, not as a third RPO pass. Minor wording fix.

### 3. NIT — "diverge" in step 5 needs a concrete sentinel rule
Location: `README.md` §Design step 5 (lines 109-115).

Standard CHK's `intersect` returns the meet-point only when both fingers converge. The doc says "returns `UINT32_MAX`" on divergence but doesn't show the helper signature; readers may assume the standard CHK helper aborts. A two-line pseudocode sketch of `intersect` (especially what it does when one operand is UINT32_MAX, i.e. unprocessed pred) would close the gap.

---

Reviewed by: opus (R2)
