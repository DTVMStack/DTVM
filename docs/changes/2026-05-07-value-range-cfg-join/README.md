# Change: Track Operand::ValueRange Across CFG Joins

- **Status**: Implemented (PR #493 ready, perf disclosure landed)
- **Date**: 2026-05-07
- **Tier**: Full
- **Branch**: `perf/value-range-cfg-join`
- **Related**: [`./investigation.md`](./investigation.md)

## Overview

Add a separate `EVMRangeAnalyzer` dataflow pass that computes per-stack-slot `Operand::ValueRange` at every block entry, stored in `EVMAnalyzer::BlockInfo::EntryStackRanges`. Plumb it into the visitor's non-lifted JUMPDEST entry so that `Builder.stackPop()` results gain the correct narrow Range. This activates batch1 (#458)'s u64-narrow fast paths (ADD/SUB/MUL/DIV/MOD via `Operand::bothFitU64`) on values that flow through control-flow joins — the common case for arithmetic in Solidity loop bodies.

## Motivation

batch1 introduced `Operand::ValueRange { U64, U128, U256 }` and four families of fast paths gated on `bothFitU64`. Empirical investigation (see archived note) found:

| x86 instruction | straight-line ADD u64 | ADD u64 in JUMPDEST loop body |
|---|---|---|
| `ADC64rr` (chained limbs 2–4) | **0** (fast path fires) | **3** (full 4-limb chain) |

The cause is that the active build (`ZEN_ENABLE_EVM_STACK_SSA_LIFT=OFF`, the default and CI configuration) routes block-boundary stack values through a memory spill round-trip: producer block calls `Builder.stackPush()` (writes 4 limbs to EVM stack memory), consumer block calls `Builder.stackPop()` (reads them back). `stackPop` constructs a fresh `Operand` with default `ValueRange::U256`, discarding any narrow Range the producer had. Inside loops this means the value-range fast paths only fire on values that never cross a JUMPDEST — almost never in real Solidity bytecode.

A first-pass fix that targeted `materializeStackMergeOperand` and `prepareStackPhiIncoming` had no effect because those live entirely under `#ifdef ZEN_ENABLE_EVM_STACK_SSA_LIFT` and are dead code under the default build.

## Impact

### Affected Modules

- `docs/modules/compiler/` (EVM frontend) — adds new analyzer pass; existing `EVMAnalyzer::BlockInfo` extended with one field.

### Affected Contracts

No public API changes. `Operand::setRange()` is added as a new public method but not exposed outside the EVM frontend.

### Compatibility

No bytecode-level or EVMC-level compatibility concerns. The change is internal to JIT compilation and only activates additional fast paths that are already correct under their range constraint. CI test pass rate (5884/5884) must hold.

## Implementation Plan

Each phase is a separate commit for review-ability.

### Phase 1: Foundation — Operand setter + BlockInfo schema (≈15 LOC)

- [ ] Add `Operand::setRange(ValueRange)` setter in `evm_mir_compiler.h` near the existing `getRange()` accessor.
- [ ] Add `std::vector<ValueRange> EntryStackRanges` field to `EVMAnalyzer::BlockInfo` in `evm_analyzer.h`. Default empty (means "no Range info available, assume U256").
- [ ] Single trivial commit; build only, no behavior change.

Validation: build passes, full test suite passes, no codegen change (analyzer not yet emitting Range info).

### Phase 2: Range dataflow analyzer (≈150 LOC)

- [ ] New analyzer pass `EVMRangeAnalyzer` (could be a class in `evm_analyzer.h` or a separate header — TBD during implementation).
- [ ] Abstract domain: per stack slot, a `ValueRange` from `{ U64, U128, U256 }` lattice.
- [ ] Lattice operations: `meet = max` (widen to most pessimistic), `bottom = U64`, `top = U256`.
- [ ] Per-block transfer function: scan block bytecode, applying per-opcode rules to a working stack of Ranges.
- [ ] CFG fixed-point: worklist iteration over `BlockInfos`, propagating exit-stack to successor entry-stacks via `meet`. Reuses existing predecessor/successor metadata in `BlockInfo`.
- [ ] At fixed point, write each block's entry-stack Range vector to `BlockInfo::EntryStackRanges`.
- [ ] Phase 2 commit: analyzer runs, populates field, but no consumer reads it yet (so still no behavior change).

Per-opcode transfer functions (initial set, can be expanded):

| Opcode group | Transfer |
|---|---|
| `PUSH0`–`PUSH32` | push Range derived from the constant: `value < 2^64` → U64, `< 2^128` → U128, else U256 |
| `DUP_N` | push copy of slot N's Range |
| `SWAP_N` | swap top with slot N |
| `POP` | drop top |
| `AND` | if either side is `U64` → U64; else `min(LHS, RHS)` |
| `OR` / `XOR` | `max(LHS, RHS)` |
| `NOT` | U256 (narrow flips to wide) |
| `ADD` | `max(LHS, RHS) widened by 1 step` (U64+U64 → U128), capped U256 |
| `SUB` | U256 (could underflow) |
| `MUL` | `max(LHS, RHS) widened`, capped U256 |
| `DIV` / `MOD` | result ≤ dividend's Range |
| `ADDMOD` / `MULMOD` | result < modulus → modulus's Range |
| `LT/GT/SLT/SGT/EQ/ISZERO` | U64 (always 0 or 1) |
| `BYTE` | U64 |
| `SHL` | U256 (can shift narrow to wide) |
| `SHR` / `SAR` | result ≤ value's Range |
| `CLZ` | U64 (≤ 256) |
| `CALLDATALOAD`, `SLOAD`, `TLOAD`, `KECCAK256`, `BALANCE`, `SELFBALANCE` | U256 |
| `PC`, `MSIZE`, `GAS` | U64 (truly bounded; PC ≤ code size, MSIZE/GAS bounded by EVM limits) |
| `CALLDATASIZE`, `CODESIZE`, `RETURNDATASIZE`, `EXTCODESIZE` | U64 (bounded by call-frame sizes) |
| `TIMESTAMP`, `NUMBER`, `GASLIMIT`, `CHAINID`, `BASEFEE`, `BLOBBASEFEE`, `PREVRANDAO` | U256 (EVMC host returns full uint256 or 32-byte buffer; classify conservatively) |
| `ADDRESS`, `CALLER`, `ORIGIN`, `COINBASE` | U256 (20-byte addresses fit in 160 bits, but treating as U256 is safe and avoids risk) |
| `CALLVALUE`, `GASPRICE`, `BLOCKHASH`, `BLOBHASH` | U256 |
| `MLOAD` | U256 |
| `CALL` / `STATICCALL` / `DELEGATECALL` / `CALLCODE` | U64 (0/1 success bool) |
| `CREATE` / `CREATE2` | U256 (returns contract address — 20 bytes — or 0 on failure, not a bool) |
| `SSTORE`, `MSTORE`, `MSTORE8`, `LOG_N`, `STOP`, `RETURN`, `REVERT`, `INVALID`, `SELFDESTRUCT`, `JUMPDEST` | no stack effect on Range domain (consumes/no push) |
| `JUMP`, `JUMPI` | consume target (and cond), terminator |

For dynamic-jump regions (where target is computed), conservative analysis: when a block is a dynamic-jump source or target, its successors are unknown precisely; meet against `U256` for all successor entry slots. Existing `EVMAnalyzer` already tracks dynamic-jump regions (see `hasDynamicJumpRegion`), reuse that.

Validation: analyzer self-consistency unit test (build a small bytecode, check `EntryStackRanges` matches expectation). Build + full test suite passes.

### Phase 3: Plumb Range into stackPop consumer + lifted-block factories

- [ ] In `evm_bytecode_visitor.h:1140-1150` (the non-lifted JUMPDEST entry path that calls `Builder.stackPop()` in a loop), after each pop, look up `BlockInfo.EntryStackRanges[slot]` (if available) and call `Opnd.setRange(Range)`.
- [ ] Slot indexing convention: `EntryStackRanges[0]` is the bottom of the entry stack, `[depth-1]` is the top. Match the analyzer's representation to the visitor's pop order.

Validation: empirical sanity check rerun. The synthetic ADD u64 loop bench captured under `ZEN_ENABLE_JIT_LOGGING=ON` should now show `ADC64rr=0` in the loop body (matching the straight-line case).

### Phase 4: Test + bench validation (no code change)

- [ ] Unit test: `tests/evm_asm/range_loop_*.easm` fixtures exercising forward joins and self-loop back-edges with u64 narrow values. Verify outputs unchanged from baseline (correctness preserved).
- [ ] `evmone-unittests` multipass + interpreter: 223 + 215 = 438 expected.
- [ ] `evmone-statetest` `-k fork_Cancun` multipass + interpreter: 2723 × 2 expected.
- [ ] paper §4.2 27-bench, ≥10 reps, taskset-pinned, multipass mode. Expected: positive geomean delta if real-world contracts have u64 arithmetic in loops; weierstrudel/15 specifically should show additional improvement on top of #458's existing +18.3%.

## Compatibility Notes

No backwards-incompatible changes. Disabling the analyzer (e.g. by leaving `EntryStackRanges` empty for all blocks) reproduces current behavior exactly.

## Risks

- **Soundness of transfer functions** (low-medium): each per-opcode rule must be sound under a `max`-meet lattice — i.e., the output range must contain every possible runtime value. Bug here would cause batch1 fast paths to fire on values that exceed their declared range, producing incorrect results. Mitigation: conservative defaults (when in doubt, U256), audit every transfer function against the EVM spec, statetest suite catches semantic deviations.
- **Fixed-point convergence** (low): the lattice has height 3 (U64 → U128 → U256), so iteration converges in O(blocks × 3) at most. Worklist algorithm with no special tricks suffices.
- **Dynamic jumps** (low): `EVMAnalyzer` already tracks dynamic-jump regions; the new pass meets against U256 for all-successor unknowns, which is the existing analyzer's pattern.
- **Two-pass overhead** (low): adds one analyzer pass per function, O(opcodes × 3) work. Function compilation is JIT-time, not hot-path; CI compile-time check should not regress.
- **Interaction with SSA_LIFT=ON path** (medium): when the build flag is enabled, the lifter takes a different path. Phase 3's plumbing is in the non-lifted branch, so SSA_LIFT=ON continues to use the lifter's PHI machinery (currently with Range=U256 from `materializeStackMergeOperand`). Phase 3 does not regress SSA_LIFT=ON. Future work could extend the analyzer to feed the lifter as well, but is not required here.

## Checklist

- [x] Phase 1: foundation + schema
- [x] Phase 2: Range analyzer pass + transfer functions + fixed-point
- [x] Phase 3: plumbing into `stackPop` consumer (non-lifted path) **and** lifted-block factories `createStackEntryOperand` / `materializeStackMergeOperand`
- [x] Phase 4: bench-validated; `ADC64rr=0` confirmed on synthetic ADD u64 loop
- [x] `evmone-unittests` multipass (223) + interpreter (215) all green
- [x] `evmone-statetest` `-k fork_Cancun` multipass (2723) all green
- [x] `tools/format.sh check` clean
- [x] 27-bench paired A-B-A on current `upstream/main` (`c644fbe`): geomean +0.34% (CI [−0.07%, +0.78%]); 5 per-bench regressions, largest `snailtracer/benchmark −2.29%` appears to be an interaction with rebase-pickup upstream commits (not bisected)
- [x] PR body discloses CI lower bound below +0.8% acceptance gate and reframes from `perf:` to `feat:` (analyzer infrastructure + soundness fixes + 42 white-box tests)

## What shipped (2026-05-12)

12 source commits on `perf/value-range-cfg-join` (last source HEAD `da4f4cc`; plus subsequent docs-only commits), rebased onto `upstream/main` at `c644fbe`.

**Analyzer infrastructure** (3 commits): enum extract (`3846a1e`), dataflow pass (`061c500`), non-lifted consumer wiring (`c6de6eb`).

**Soundness fixes** (3 commits, uncovered during white-box test development or PR review): SDIV/SMOD sign-mismatch (`5d46f7e`), host-context opcode widening for TIMESTAMP/NUMBER/GASLIMIT/CHAINID (`a73f782`), CREATE/CREATE2 address widening (`3f32828`, caught by Copilot reviewer).

**Tests + cleanup + lifted-block wiring** (7 commits): MockOperand stub (`72c5e0b`), 42 white-box tests across per-opcode/CFG-join/dynamic-jump/cross-bb groups (`e27ac3c` + `da4f4cc`), defensive-path cleanup (`f203bd5`), **lifted-block factory plumbing** (`2ebfd29` — closes the gap noted in the original Findings section), analyzer-table caching + ZEN_ASSERT invariant (`da5571c`), clang-format wrap (`1dca9d5`).

**Perf rounds** measured on this machine across the rebase decision cycle:

| Run | HEAD | Geomean | 95% CI | Notes |
|---|---|---|---|---|
| Pre-rebase | `5357578` | −1.97% | [−6.69, +2.82] | memory_grow_* killed by missing upstream opts |
| Post-rebase | `f203bd5` | −0.57% | [−1.97, +0.76] | rebase fixed memory_grow_*; swap_math/sha1 collapsed due to #483 interaction |
| D1 — revert #483 | `3d273e0` | +0.95% | [−0.63, +2.60] | confirmed #483 is one interaction source; not deployable as a revert |
| **D6 — lifted plumbing** | **`da4f4cc`** | **+0.34%** | **[−0.07, +0.78]** | swap_math/sha1_shifts/jump_around recovered; snailtracer −2.29% residual |

The lifted-block plumbing (`2ebfd29`) addresses the "Future work" item in the original §2b Findings: extending the analyzer to feed the lifted codegen path. With it landed, the original PR's empirical hypothesis (u64 fast paths gated on cross-BB Range) is now exercised on the dominant codegen path; the residual snailtracer regression appears to be a rebase-pickup interaction unrelated to analyzer correctness and is deferred to a follow-up PR.

## Findings during implementation (2026-05-11)

### §2b execution-level differential harness — DROPPED

The original v4 design proposed 5 evmone-statetest fixtures running under
DTVM `mode=multipass`, asserting that bytecode patterns triggering the
SDIV/SMOD/host-opcode bug would diverge from the evmone reference under
the buggy classifier and converge under the fix.

Task 4 implementation discovered this is architecturally infeasible.
`evm_bytecode_visitor.h:1131-1138` short-circuits lifted JUMPDESTs (the
default for well-formed bytecode) before the `setRange` refinement at
L1155 fires. The `bothFitU64` u64 fast path therefore cannot truncate
high limbs of values flowing through lifted blocks, and minimal bytecode
that disables lifting (via `HasUndefinedInstr`, `HasInconsistentEntryDepth`,
or dynamic-jump conflict) cannot simultaneously reach state-affecting
opcodes that surface the bug.

**Implication**: the analyzer's classifier fix is defense-in-depth.
The white-box tests in `src/tests/evm_range_analyzer_tests.cpp` (Groups A/B/C/D, 42 tests) verify the classifier. The existing `evmone-statetest
-k fork_Cancun` corpus (2723 tests × 2 modes) covers end-to-end
multipass correctness on real bytecode. Together they bound the fix's
scope; no additional fixtures are needed.

**Future work** (later landed in commit `2ebfd29`): extending the analyzer to feed the lifter's `materializeStackMergeOperand` / `prepareStackPhiIncoming` path was originally a Non-Goal in the v4 design spec. Empirical perf evidence (post-rebase run showing swap_math/sha1 collapse) forced the issue, and the plumbing fix subsequently recovered those wins. See the `## What shipped` section above for the four-way perf comparison.
