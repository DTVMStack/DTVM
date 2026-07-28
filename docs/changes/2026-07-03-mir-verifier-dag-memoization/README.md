# Change: Memoize the MIR verifier operand walk

- **Status**: Implemented
- **Date**: 2026-07-03
- **Tier**: Light

## Overview

`MVisitor::visitInstruction` recurses into every non-Phi operand of every
statement. A value produced once can be an operand of many later instructions,
so a node reachable by K distinct paths is dispatched K times per traversal.
`MVerifier` now records each instruction as absent, active, or completed. A
completed instruction is not dispatched again, while reaching an active
instruction reports a cycle in the recursively traversed operand graph. The
state map is cleared at the start of every public `visit()` call, including the
call made by `verify()`. The general `MVisitor` traversal keeps its original
per-use semantics for visitors whose behavior depends on the path or use being
traversed.

## Motivation

Unsigned 256-bit DIV/MOD lower to a cluster of instructions with shared,
reconvergent sub-expressions: the divide-by-zero guard, the guarded-divisor
select, and the upper-limb test all feed several consumers, and each op both
consumes and feeds the loop-carried accumulator that connects to the next op.
Path count therefore grows combinatorially with the length of a data-dependent
DIV/MOD chain, and `MVerifier::verify()` — the first sub-phase of
`compileMIRToCgIR` — dominates compile time long before any other pass.

Measured on a synthetic dependent-chain loop corpus (cold compile plus first
execution, median of 3 fresh-VM runs, x86-64 Linux, 2026-07-03):

| chain depth | DIV before | DIV after | MOD before | MOD after | SDIV (control) |
|---|---|---|---|---|---|
| 8  | 3.3 ms | 3.2 ms | — | — | — |
| 12 | 17.7 ms | 4.3 ms | — | — | — |
| 16 | 791.6 ms | 5.4 ms | 795.0 ms | 5.6 ms | 8.9 ms |
| 20 | not practical (multi-second) | 6.5 ms | — | — | — |
| 32 | not practical | 10.0 ms | — | — | — |

![MIR-verifier compile time vs dependent-chain depth: before super-linear, after linear](figures/compile-scaling.svg)

*Figure: MIR-verifier compile time vs dependent-chain depth (lower is better,
log-y). Before the fix, DIV compile time grows super-linearly (3.3 → 17.7 →
791.6 ms, then multi-second at depth 20 and impractical at depth 32 — no finite
value recorded, shown as an off-scale break). Memoizing the walk makes it linear
(3.2 → 10.0 ms across depths 8–32), tracking the already-linear SDIV control.
Because a straight line on a log-y axis would mean exponential growth, the
after-curve's linearity is shown in the linear-axes inset. Median of 3 fresh-VM
runs; gas byte-identical, steady-state throughput unchanged.*

Signed SDIV/SMOD lower to a straight-line runtime call with no reconvergent
DAG, which is why they stay linear on the unfixed baseline; after the fix,
DIV/MOD track the SDIV curve. This synthetic chain demonstrates the
pathological traversal complexity and the effect of memoization. This
synthetic-chain measurement predates the active/completed implementation. The
current implementation was measured separately on tree-shaped MIR, shared
DAGs, and one full-contract compile; those results are reported below.

## Impact

- Production changes: `src/compiler/compiler.cpp`,
  `src/compiler/mir/pass/verifier.cpp`, and
  `src/compiler/mir/pass/verifier.h`.
- Memoization is local to `MVerifier`; other `MVisitor` subclasses retain
  per-use traversal.
- `MVerifier::visit()` clears and reserves the state map for every traversal.
  This also makes repeated direct calls through the inherited public API
  independent, rather than carrying completed nodes over from an earlier
  traversal.
- `compileMIRToCgIR` limits `MVerifier` to a local scope, releasing the state
  map before dead basic-block elimination (MBBDCE), lowering, and register
  allocation.
- Reaching an active instruction reports a non-Phi operand cycle instead of
  silently accepting it. Phi inputs are not recursively traversed by
  `MVisitor`, so control-flow cycles represented through Phi nodes are outside
  this check.
- Every verifier instruction check is a function of the node itself (operand
  type kinds, predicate ranges, callee signatures, and block-target indices)
  plus per-function state (`CurFunc`). No instruction check depends on the path
  by which a node is reached, so visiting each instruction once preserves
  those checks. Block-level checks still run in `visitBasicBlock` and are
  unaffected.
- The `DenseMap` looks up every visited instruction and stores an
  active/completed state for each distinct instruction. A verifier-only
  microbenchmark used a GCC 12 Release/O3 build pinned to CPU 14, constructed a
  fresh `MVerifier` for each sample, and ran 12 interleaved repeats. The
  baseline is the verifier without memoization; the PR `DenseSet` is the
  original patch:

  | tree N | fixed `DenseMap` vs baseline | fixed vs PR `DenseSet` |
  |---:|---:|---:|
  | 100 | +127.1% | ~29% faster |
  | 1,000 | +123.0% | ~47% faster |
  | 10,000 | +185.3% | ~62% faster |

  The fixed implementation adds approximately 3.6–5.2 ns per unique
  instruction on these tree-shaped inputs. The percentage is high because the
  baseline walk is very small, while the fixed implementation is consistently
  faster than the PR's original `DenseSet` implementation.
- On shared DAG inputs in the same verifier-only benchmark, the fixed
  implementation is 262x faster than the baseline at depth 12 and 3,778x
  faster at depth 16.
- Relative to the baseline, a tree containing 400,001 instructions increased
  peak RSS by 14,756 KiB, approximately 37.8 bytes per instruction. The local
  verifier scope prevents this allocation from overlapping later compiler
  passes; it does not remove the verifier's own peak.
- Relative to the baseline, a SimpleERC20 full-compile sanity check measured
  +1.73% wall time and +1.87% user time. Both differences are comparable to the
  run IQR, so this result is not a mainnet-workload A/B measurement.
- Code generation is untouched. The previously measured synthetic corpus kept
  gas byte-identical and showed no steady-state throughput change within
  run-to-run noise.
- Scope: `compileMIRToCgIR` verifies MIR for both the EVM and the WASM
  multipass pipelines, so this change affects WASM compile time as well. The
  soundness argument above is frontend-agnostic (every check is node-local
  over the same `MInstruction` kinds); the empirical validation below is
  EVM-side, and CI's WASM jobs cover the shared path.
- The measurements show the expected per-instruction verifier cost on
  tree-shaped MIR but no evidence of a large end-to-end regression. The
  full-compile evidence is limited to SimpleERC20; mainnet replay A/B
  measurements have not been run.

## Tests

- `evmRangeAnalyzerTests` passed 49/49.
- `tools/dtvm_local_test.sh --auto` completed its selected suites:
  `evmone-unittests` passed 223/223, state tests passed 2723/2723, CTest passed
  12/12, and `tests/evm_asm` passed 209/209.
- Formatting and diff checks pass for every changed file, and the changed code
  builds without warnings. The full-repository `tools/format.sh check` remains
  blocked only by pre-existing violations in unchanged files.

## Checklist

- [x] Implementation complete
- [x] Existing test suites pass
- [ ] Module specs in `docs/modules/` updated (if affected) — not affected
- [x] Build and tests pass
