# Change: Fix phi-materialization crashes in the EVM SSA stack-lift path

- **Status**: Implemented
- **Date**: 2026-06-09
- **Tier**: Light

## Overview

The EVM multipass JIT has an optional SSA stack-lifting path, gated by the
build flag `ZEN_ENABLE_EVM_STACK_SSA_LIFT` (default **OFF**, introduced in
#395, fed by the range analyzer from #493). When that flag is enabled the
JIT emitted invalid MIR that the verifier rejects and that aborts the
compiler (SIGABRT) on common real-world control flow. This change fixes
three independent defects in that path. All edits are reachable only when a
block is lifted, so the default (flag-off) build is unaffected.

## Motivation

With `ZEN_ENABLE_EVM_STACK_SSA_LIFT=ON`, compiling ordinary contracts trips
the MIR verifier's phi invariants and then aborts:

1. **Phi contiguity.** `createPendingPhi` appended each phi at the block end.
   A stack merge with two or more slots emits, per slot, four phi components
   followed by four temp-store `dassign`s; a later slot's phis therefore
   landed *after* an earlier slot's `dassign`s, violating the
   "phis contiguous at block start" invariant
   (`mir/pass/verifier.h`). Multi-slot merge blocks — e.g. any loop header
   carrying more than one stack value — aborted.

2. **Dynamic-jump-target phi undersize.** Codegen's indirect-jump dispatch
   wires an edge from every block that performs a computed `JUMP`/`JUMPI` to
   every `JUMPDEST`. The analyzer's shape-class predecessor enumeration
   (`getPotentialEntryPredecessorsForBlock`), which sizes a merge block's
   phis, is a strict subset of that set. So a dynamic-jump-target merge block
   received phis with fewer incoming slots than its actual MIR predecessor
   count; a later pass indexing phi incomings by predecessor then ran out of
   bounds (silent SIGABRT in a release build).

3. **Loop back-edge phi incoming block.** A loop header's merge phi froze its
   back-edge incoming *block* before the `JUMPI` terminator wired the real CFG
   edge into the header. The forward walk that resolves the incoming block
   could not yet reach the true predecessor and recorded the source EVM
   block's *entry* MIR basic block instead of the basic block that actually
   branches back. The verifier rejected the phi
   ("phi incoming block must be a predecessor of the current block").

These are latent correctness/robustness bugs in merged code. Fixing them is
worthwhile independent of whether the feature is enabled.

## Approach

1. **Phi contiguity** — `createPendingPhi` (evm_mir_compiler.cpp): create the
   phi without appending, scan the block's leading run of phis, and insert the
   new phi immediately after it. All phis stay grouped at the block start
   regardless of how many slots or interleaved `dassign`s precede.

2. **Dynamic-jump-target exclusion** — `finalizeLiftability` (evm_analyzer.h):
   a new coverage check
   (`dynamicJumpTargetPredecessorsCoverCodegenEdges`) sets
   `CanLiftStack = false` for any dynamic-jump-target candidate whose static
   predecessor enumeration does not account for every dispatch source codegen
   will wire. Such blocks fall back to the existing memory-backed stack path —
   the correct conservative behavior: never lift a block whose phi predecessor
   set cannot be modeled exactly.

3. **Deferred incoming-block re-resolution** —
   `finalizeStackMergePhiIncomingBlocks` (evm_mir_compiler.cpp), called at the
   end of `finalizeEVMBase` once the whole CFG exists: for each stack-merge phi,
   any incoming block that is not yet a real predecessor of the owning block is
   re-resolved by a forward walk to the actual predecessor. Only the block
   pointer is corrected; the incoming **value** is preserved.

The fixes touch only phi *placement* and *predecessor bookkeeping*; no
arithmetic lowering or value semantics change.

## Impact

- **Modules**: `src/compiler/evm_frontend/` only (`evm_mir_compiler.{h,cpp}`,
  `evm_analyzer.h`).
- **Default build (flag OFF)**: unaffected. `createPendingPhi`,
  `finalizeStackMergePhiIncomingBlocks`, and the new analyzer code are
  reachable only on the lift path; with the flag off the bookkeeping vector
  stays empty and the lift-only paths are never entered.
- **Lift build (flag ON)**: the three abort/verifier failures above no longer
  occur on the validated workloads.

## Validation

- **Default-path neutrality** (build rebuilt from this change, flag OFF):
  - multipass `evmone-unittests`: **223/223**
  - multipass `evmone-statetest -k fork_Cancun` (EEST `state_tests`):
    **2723/2723**
- **Lift path** (flag ON):
  - multipass `evmone-unittests`: **223/223** (was 222/223 before fix 3;
    `memory_grow_mstore8` now passes)
  - 228-fixture mainnet-replay corpus: JIT-compiles crash-free, verifier-clean
    (was SIGABRT before fixes 1–2)
- `tools/format.sh check`: passes.

## Known limitation (disclosed)

This change does **not** make SSA stack-lifting production-ready, and the flag
stays **OFF**. With the flag ON, at least one further crash remains: the EEST
`stEIP1153_transientStorage/transStorageOK` state test still aborts under
SSA-lift (confirmed in isolation; passes with the flag off). That defect is
independent of the three fixed here and will be addressed separately. CI does
not build with `ZEN_ENABLE_EVM_STACK_SSA_LIFT=ON`, so it does not exercise this
path; the lift-path results above were produced manually.

## Checklist

- [x] Implementation complete
- [x] Default-path tests pass (unittests 223/223, statetest 2723/2723)
- [x] Build and format checks pass
- [ ] SSA-lift made fully correct (tracked separately — see Known limitation)
