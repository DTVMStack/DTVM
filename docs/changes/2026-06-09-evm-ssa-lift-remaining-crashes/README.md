# Change: Fix the remaining EVM SSA stack-lift crashes

- **Status**: Implemented
- **Date**: 2026-06-09
- **Tier**: Light

## Overview

Follow-up to the phi-materialization fixes (PR #530). Fixes the remaining
crashes in the EVM multipass JIT's SSA stack-lift path
(`ZEN_ENABLE_EVM_STACK_SSA_LIFT`, default **OFF**). With the flag ON, the JIT
aborted (SIGABRT) on several contracts in the EEST state-test suite and the
mainnet-replay corpus. After this change, SSA-lift compiles both corpora
crash-free and produces results identical to the default build. All edits are
reachable only on the lift path; the default (flag-off) build is unaffected.

## Defects and fixes

### 1. Dynamic-jump shape-class entry-depth gate

A block that is both a dynamic-jump target and a dynamic-jump source whose own
`JUMP` net-pops the stack (entry depth ≠ exit depth) crashed:
`getCompatibleDynamicJumpTargetBlocksForSourceBlock` reused the block's target
shape class as its source class, assuming it re-dispatches at the depth it
entered. Its shallow exit stack was then assigned as a deeper region's entry
state, tripping `EntryDepth == Values.size()`.

Fix (`evm_analyzer.h`): gate the fallback on the source block's
`ResolvedExitStackDepth` equalling the candidate shape class's entry depth (new
helper `getDynamicJumpShapeClassEntryDepth`). This enforces the source side of
the invariant `source-exit-depth == target-entry-depth == shape-class-entry-depth`,
which was previously checked only on the target side.

### 2. JUMPDEST double-begin

When a `JUMP`/`JUMPI` terminator falls through into a `JUMPDEST`, the
terminator handler begins the fallthrough block and the main loop's `JUMPDEST`
handler then begins the same block again. With the flag OFF this is benign;
with SSA-lift ON the second begin (a) records a self-edge
`PredBlockPC == BlockPC` absent from the predecessor order (→ `getPhiIncomingSlot`
abort), and (b) re-restores the lifted logical entry state, doubling the logical
stack (→ entry-depth mismatch abort).

Fix (`evm_bytecode_visitor.h`): detect `RunStartPC == CurrentBlockEntryPC`
(gated on `CurrentBlockLifted`), skip the redundant edge assignment, and drain
the stale logical-stack copy so the entry state is restored exactly once.

### 3. Operand identity key on a non-U256 operand

`getOperandIdentityKey` dereferenced `getU256VarComponents()` based only on a
compile-time type check, so an empty/deferred operand (not multi-component) hit
the "Not a multi-component U256" assertion.

Fix (`evm_lifted_stack_lifter.h`): add a runtime `isU256MultiComponent()` guard;
non-multi-component operands fall through to the opaque-key path.

## Impact

- **Modules**: `src/action/evm_bytecode_visitor.h`,
  `src/compiler/evm_frontend/evm_analyzer.h`,
  `src/compiler/evm_frontend/evm_lifted_stack_lifter.h`.
- **Default build (flag OFF)**: unaffected (each fix is lift-path-gated).

## Validation

- **Lift path (flag ON)**:
  - multipass `evmone-unittests`: **223/223**
  - multipass `evmone-statetest -k fork_Cancun` (EEST): **2723/2723, 0 failed,
    no SIGABRT** — matches the default-build baseline exactly
  - 227-fixture mainnet-replay corpus: no SIGABRT; failing-test set identical to
    the default build (0 regressions)
- **Default path (flag OFF, rebuilt from this change)**: multipass
  `evmone-unittests` **223/223**, `evmone-statetest -k fork_Cancun` **2723/2723**.
- `tools/format.sh check`: passes.

## Known residual (not a crash)

The EEST run still emits five benign `PredBlockPC == BlockPC` self-edge cases on
single-predecessor blocks (no merge phis, no abort, all tests pass). They point
to a residual double-begin path not covered by the `CurrentBlockLifted`-gated
guard; addressing them would require a broader audit of the terminator/JUMPDEST
begin handshake rather than a surgical change.

## Checklist

- [x] Implementation complete
- [x] Lift-path crash-free on EEST statetest + replay corpus
- [x] Default-path neutrality (unittests 223/223, statetest 2723/2723)
- [x] Build and format checks pass
