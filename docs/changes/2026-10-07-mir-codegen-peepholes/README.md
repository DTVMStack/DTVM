# Change: MIR/codegen peephole pack (ctz/clz, select-icmp, algebra, const-br)

- **Status**: Accepted
- **Date**: 2026-10-07
- **Tier**: Full

## Overview

Add a deterministic MIR mid-end peephole pass, inspired by Wasmtime
[#13332](https://github.com/bytecodealliance/wasmtime/pull/13332)/[#13343](https://github.com/bytecodealliance/wasmtime/pull/13343)
(A), [#12135](https://github.com/bytecodealliance/wasmtime/pull/12135) (B),
the [#11637](https://github.com/bytecodealliance/wasmtime/pull/11637) family (C),
and [#13267](https://github.com/bytecodealliance/wasmtime/pull/13267)/[#13391](https://github.com/bytecodealliance/wasmtime/pull/13391) (D).

The pass runs after `MVerifier` and before `DeadMBasicBlockElim` in
`compileMIRToCgIR`. It rewrites local expression trees and constant
terminators; dead-block elim then clears unreachable blocks.

Out of scope: E (a64 BFM), J (bulk memory), L (csdb).

## Motivation

DTVM multipass has only a narrow x86 Cg peep (`setcc→jcc`) and no MIR
algebraic/terminator folds. Patterns that Wasmtime already reduces to a
bit test or an unconditional jump still emit BSR/BSF, `select+cmp`, or
a live untaken `br_if` arm. A small, proven rewrite pack is a better
fit than an egraph: the IR is a tree, the VM is deterministic, and
trap/gas semantics must stay exact.

## Impact

### Affected Modules

- [compiler](../../modules/compiler/spec.md): new `MIRPeephole` pass;
  `DeadMBasicBlockElim` also strips dead predecessors / phi incomings
- tests: litmus, WAST, concurrent compile/execute stress, microbench

### Affected Contracts

No public API change. Compile pipeline gains one MIR pass. Semantics of
wasm traps, gas, and integer wraparound are unchanged.

### Compatibility

Backward compatible. Output code may differ (fewer instructions / fewer
blocks) but must match interpreter/singlepass results.

## Implementation Plan

### Phase 1: Mid-end pass + CFG cleanup

- [x] `MIRPeephole` walk of statement / expression trees
- [x] A — `ctz(x)==0` → `(x & 1) != 0`; `clz(x)==0` → signed `< 0`
- [x] B — `icmp eq/ne (select c, k1, k2), k` → condition on `c` (or const)
- [x] C — local identities: `+0`, `-0`, `x-x`, `*0/*1`, `&/|/^` with
      `0/-1/x`, `not(not x)`, shift-by-0, absorption, const-const int fold
- [x] D — constant `br_if` → `br` (or delete); then dead-block elim
- [x] Wire into `compileMIRToCgIR`; re-verify after transforms

### Phase 2: Tests and measurement

- [x] Positive / negative litmus (including `ctz==4` must not fold)
- [x] Concurrent compile + execute stress
- [x] Before/after microbenchmarks on this agent VM

Measured on this agent (Intel Xeon, 4×2400 MHz, Linux 6.12, Release,
multipass, `--disable-multipass-multithread`). Same `peephole_mod.wasm`
on parent `410c579` vs this branch; process wall time, 1 warmup + 7
runs, 1+4 executions per process. Outputs matched.

| Kernel | n | baseline min | PR min | Δ |
| --- | ---: | ---: | ---: | ---: |
| A `bench_ctz_eqz` | 20e6 | 201.1 ms | 153.7 ms | −23.6% |
| B `bench_select` | 20e6 | 194.4 ms | 152.7 ms | −21.4% |
| C `bench_algebra` | 20e6 | 105.0 ms | 54.6 ms | −47.9% |
| D `bench_const_br` | 20e6 | 115.6 ms | 75.6 ms | −34.6% |
| mixed A–D | 8e6 | 290.1 ms | 200.7 ms | −30.8% |
| `bitmix` LCG kernel | 8e6 | 227.3 ms | 195.5 ms | −14.0% |

In-tree paper `.wasm` artifacts are Git LFS stubs (~128 B, not valid
modules), so they were not used. Compile-time (20 extra compilations of
this module) was 30.1 → 28.5 ms min — noise, not a regression.

Concurrent: `ParallelCompileAndExecute` 8×40 eager; `ParallelLazyCompileAndExecute`
8×20 lazy (one runtime per thread); `LazyJitWarmupThenReplay` 200 calls;
`--gtest_repeat=20 --gtest_break_on_failure` all passed. `lazyJitStubTests`
`--gtest_repeat=50` passed.

## Compatibility Notes

None. No migration.

## Risks

- **Over-folding shifts**: wasm/x86 mask the shift count; do not combine
  consecutive shifts when `n+m >= width`. Only fold shift-by-0 and
  const-const with the masked count.
- **Trap / gas**: never fold `div`/`rem` (zero divisor). Constant
  `br_if` to a trap block is rewritten only when the condition is a
  real integer constant.
- **Phi / CFG**: folding a terminator updates successors **and** strips
  matching phi incomings on a still-live drop target (shared EVM
  JUMPDEST). `removeIncoming` compact uses a fixed old-N operand-slot
  base so decrementing `_operand_num` cannot remap remaining values.
  Dead-block elim also dedupes dead predecessors before
  `removePredecessor`. Pred/succ lists use swap-pop (not `vector::erase`)
  so Release+ASan does not memmove into the LLVM bump red zone.
  `MInstruction::freeMem` uses `_operand_cap` after a live-count shrink.
  DCE reachability uses a host `std::queue`. Pred/succ lists are
  `SmallVector<*,4>` (not bump `CompileVector`) so Release+ASan does not
  poison neighboring IR. `MVerifier` still holds.
- **Parallel compile**: the pass is function-local and uses the
  per-function `CompileMemPool`; no shared mutable state.
