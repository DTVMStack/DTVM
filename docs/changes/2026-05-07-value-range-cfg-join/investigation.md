# Investigation: ValueRange Survival Across CFG Joins

- **Date**: 2026-05-07
- **Status**: **Investigation only — original Light-tier fix attempt rolled back here; the deeper refactor it called for landed in PR #493 (lifted-block plumbing in commit `2ebfd29`).  See `README.md` and the §Soundness regression evidence addendum below.**
- **Branch**: `perf/value-range-cfg-join` (live; PR #493)
- **Related**: `u256-batch2-null-result.md` (the prior investigation that surfaced this question)

## What we set out to fix

The prior u256 batch2 investigation found that batch1's (#458) `Operand::ValueRange` u64-narrow fast paths (handleBinaryArithmetic ADD/SUB, handleMul, handleDiv/handleMod, handleMulMod) appeared not to fire on a hand-crafted `AND PUSH8 0xFF..FF` ADDMOD hot loop — a workload that should trigger them per code reading. The hypothesis at the end of that note was: **`ValueRange` is destroyed at CFG joins** (`materializeStackMergeOperand`, `stackGet`, `createStackEntryOperand` all return Operand without Range, defaulting to `ValueRange::U256`). If true, fixing those drop sites would activate batch1's existing fast paths on real Solidity uint64 arithmetic — a high-leverage win.

## Empirical pre-fix evidence (hypothesis confirmed)

Two synthetic ADD u64 contracts on `main` (HEAD `5e5fddd`, batch1 already merged):

- **straight-line** (16 chained ADDs in one basic block, `CALLDATALOAD + AND PUSH8 0xFF..FF` operands)
- **loop** (1 ADD inside a JUMPDEST loop body, same operand source)

Captured under `ZEN_ENABLE_JIT_LOGGING=ON`:

| x86 instruction | straight-line | loop body |
|---|---|---|
| `ADC64rr` (chained limbs 2–4 of u256 ADC) | **0** | **3** |
| `ADD64rr` (single-limb fast path / chain limb 1) | 24 | 9 |

`ADC64rr=0` in straight-line confirms each ADD took the u64 fast path. `ADC64rr=3` in loop confirms the loop body emits the full 4-limb ADC chain — fast path **does not** fire across the JUMPDEST PHI.

## Fix attempted

Two-part change in `evm_mir_compiler.{cpp,h}`:

1. Added `Operand(U256Var, EVMType, ValueRange)` constructor overload (analogous to existing `Operand(U256Inst, EVMType, ValueRange)` at h:148).
2. Modified `materializeStackMergeOperand` to compute `merged_range = max(incoming_ranges)` and pass it to the new constructor; falls back to `U256` if any predecessor's value isn't yet known (back-edge of a self-loop).
3. Modified `prepareStackPhiIncoming` to forward the input Operand's Range into the wrapped output (it was dropping Range upstream of `materializeStackMergeOperand`, masking the fix).

## Empirical post-fix result (fix did NOT work)

Re-running the same JIT-log capture with the fix applied:

| x86 instruction | straight-line (after) | loop body (after) | if-else merge (after) |
|---|---|---|---|
| `ADC64rr` | 0 | **3** (unchanged) | **3** (unchanged) |
| `ADD64rr` | 24 | 9 | 9 |

The loop and even the **forward-only if-else merge** still emit the full 4-limb chain. To rule out a logic bug in our merge computation, we ran a probe that forced `MergedRange = ValueRange::U64` unconditionally (unsound, for diagnostic purposes only) — the fast path **still did not fire**.

This means the Operand returned from `materializeStackMergeOperand` is **not** the Operand that the downstream `handleBinaryArithmetic<BO_ADD>` eventually sees. There is at least one more layer between the merge result and the consumer (the visitor's `pop()`, the lifter's `EVMLiftedStackLifter::StackValue` machinery, or one of the fallback paths via `stackGet` / `stackPop`) that re-wraps the value into a fresh Operand without preserving Range.

## Drop sites identified (incomplete list)

Each of these constructs an Operand with `Operand(..., EVMType::UINT256)` (Range defaults to `ValueRange::U256`):

| Function | File:line | When invoked |
|---|---|---|
| `createStackEntryOperand` | `evm_mir_compiler.cpp:1007` | Function-entry stack slots |
| `stackPop` | `evm_mir_compiler.cpp:943` | Physical stack pop after spill |
| `stackGet` | `evm_mir_compiler.cpp:987` | Physical stack peek after spill |
| `prepareStackPhiIncoming` | `evm_mir_compiler.cpp:1027` | Lifter-level PHI incoming wrapping (calls `protectUnsafeValue` per limb) |
| `materializeStackMergeOperand` | `evm_mir_compiler.cpp:1042` (return at 1096) | JUMPDEST PHI merge; returns U256Var-backed Operand |

Fixing 4 and 5 alone does not fix the loop/if-else case (verified empirically). At least one more drop site exists between the merge result and the visitor's logical pop().

## Why a Light-tier fix isn't enough

The visitor uses `EVMLiftedStackLifter` for stack tracking. Its `StackValue` struct stores Operands by value, and PHI resolution happens through `PendingPhi` machinery with `ResolutionKind::{Pending, Folded, RequiresMaterialization}`. The interaction:

- When entering a JUMPDEST, the lifter may **materialize** a PHI (calling `materializeStackMergeOperand`) and store the result back into its own `StackValue`. This logical Operand has the merged Range from our fix.
- However, when the visitor's `pop()` is called inside the loop body, the lifter may produce a fresh Operand via a different path (re-extraction of components, fallback `stackGet` for blocks marked as "lifted with resolved entry depth"), losing Range.
- Investigating the precise hand-off path between materialize and pop requires reading ~500 lines of `evm_lifted_stack_lifter.h` and tracing through the PHI bookkeeping. Beyond Light-tier scope.

## Proper-fix scope (Full-tier estimate)

1. **Track Range in `EVMLiftedStackLifter::StackValue`** (currently just `Operand Value` + `StackValueId Id`).
2. **Track Range in `EVMAnalyzer::BlockInfo`** for stack slots at lifted block entry (so `stackGet`-fallback paths can recover the Range from analyzer metadata).
3. **Make `Operand::Range` mutable** (or expose a `setRange()`) so back-edge patches (`assignStackMergeOperand`) can retroactively widen the merged Range as more predecessors are seen.
4. **OR introduce a two-pass codegen**: pass 1 emits MIR with conservative Range, pass 2 narrows based on dataflow analysis. Substantial.
5. Add 4–5 new constructor overloads with explicit Range, and audit all `Operand(..., EVMType::UINT256)` call sites for Range propagation.

Likely 200–500 LOC across `evm_mir_compiler.{cpp,h}`, `evm_lifted_stack_lifter.h`, and `evm_analyzer.h`. Risk: medium — touches the SSA-construction core. Reward: real Solidity uint64 arithmetic in loops would activate batch1's fast paths.

## Decision

Rolled back all source changes. Branch deleted. The investigation is preserved here; the change doc README that lived on the worktree is also discarded — its contents are folded into this note.

The 27-bench paper benches that Solidity-style uint64 patterns dominate (weierstrudel, snailtracer, swap_math, etc.) all use loops, so this fix could plausibly deliver another #458-scale win on top of the existing +18.3% on weierstrudel/15. But the cost-benefit ratio depends on the actual scope being closer to the 200-LOC end vs. the 500-LOC end, and on someone having time to characterize the lifter's pop-path before committing.

## Reproducibility

Bytecode generators and the bench JSONs were under `/tmp/range-cfg-investigation/` and `~/evmone/test/evm-benchmarks/benchmarks/main_user/` (cleaned up after the investigation). Two key snippets if anyone wants to re-run the experiment:

- ADD u64 hot loop: setup loads `x = CALLDATALOAD(0x04) & 0xFF..FF` (PUSH8 mask) and similarly `y = CALLDATALOAD(0x24)`; body does `[counter, x, y]` → `DUP3 DUP3 ADD POP` then `JUMP loop_start`. 65536 inner iterations per call.
- Straight-line variant: same loads, then 16 × `[DUP2 DUP2 ADD POP]` (no JUMPDEST in the hot region).

The smoking-gun signal is the `ADC64rr` count in `ZEN_ENABLE_JIT_LOGGING=ON` output — 0 in straight-line, 3 in loop body. After the proper fix, both should be 0.

## Soundness regression evidence (2026-05-12)

After commit `2ebfd29` plumbed the analyzer's per-slot range into both
codegen paths, end-to-end execution-level evidence for the two soundness
fixes (`5d46f7e`, `a73f782`) became producible.  Two regression artifacts
landed under `regression/`:

1. **Analyzer-level regression net** (white-box).  Empirical check on
   2026-05-12 with both `5d46f7e` and `a73f782` reverted in place: 6 of
   the 7 directly-relevant tests fail (`SDivByU256IsU256`,
   `SModByU256IsU256`, `TimestampIsU256`, `NumberIsU256`,
   `GasLimitIsU256`, `ChainIdIsU256`).  One passes by coincidence
   (`SDivU256DividendIsU256` — pre-fix and post-fix rules happen to
   agree when dividend is already U256).  See `regression/README.md`.

2. **Execution-level reproducer** (black-box).
   `regression/sdiv_sign_mismatch_repro.hex` plus
   `regression/repro_sdiv_fast_path_truncate.sh`.  Bytecode crosses a
   CFG join through a lifted JUMPDEST and feeds the bothFitU64-gated
   ADD with the SDIV(U64-dividend, U256-divisor) result.  Outputs:

   | Build | Output |
   |---|---|
   | evmone reference | `0xFF...FC` (−4 in signed 256-bit, spec-correct) |
   | DTVM multipass (fix applied) | `0xFF...FC` — matches reference |
   | DTVM multipass (fix reverted) | `0x000...000FC` — upper 192 bits truncated to 0 |

   This is exactly the "limbs[2..3] silent truncation" failure mode the
   `5d46f7e` fix commit message described, surfaced as a state divergence
   visible in 32-byte RETURN data.

The host-context-opcode bug is harder to reproduce as a black-box test
because `evmc run`'s default host returns small values that don't surface
the truncation; the four `Timestamp/Number/GasLimit/ChainIdIsU256` tests
in the white-box net are the operative regression evidence for that
class.
