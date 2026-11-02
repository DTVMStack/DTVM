# Change: cmp→jcc lowering and non-entry FP const hoist

- **Status**: Implemented
- **Date**: 2026-10-31
- **Tier**: Light

## Overview

Two trap-safe multipass codegen cleanups from the jacobi-2d / fib dumps:

1. Hoist non-zero FP constants used outside the entry block into an entry
   `dassign` so jacobi-style stencil coefficients (e.g. `f64.const 0.2`)
   are materialized once. This is **entry-wide**, not loop/preheader or
   use-frequency analysis: every distinct eligible constant is initialized
   on every invocation, including single uses on cold paths.
2. Lower `br_if` of a compare whose result has not already been
   materialized as `cmp`/`ucomi` + `jcc` with the predicate's condition
   code, matching select's flag-preserving path. `FCMP_OEQ`/`FCMP_UNE`
   stay on `setcc` (two flags). The existing `setcc`+`test`+`jcc` peep
   also inverts `COND_E` for short diamonds. Its one-use guard counts
   consumer instructions, not operands, so `TEST rr` of the same vreg
   still matches.

Out of scope: folding `add(dyn,imm)` into load/store displacement
(rejected in zoowii/DTVM#14 / `address_add_imm_wrap.wast`).

## Motivation

Hot jacobi compute is wasm `main` / `function_2` (nested stencil, mild
spills). MIR currently embeds a fresh `ConstantInstruction` at each
`f64.const`, so lowering materializes `MOV64ri`+bitcast in the loop.
`br_if` of an icmp always did `setcc`+`test`+`jcc` even when the compare
was not already materialized; fib/jacobi loop edges show that sequence.
Select already consumes flags directly.

## Impact

- [compiler](../../modules/compiler/spec.md): `MIRPeephole` entry-wide
  FP hoist; `X86CgLowering::lowerBrIfStmt`; `X86CgPeephole::optimizeCmp`
  `COND_E`
- tests: MIR litmus, CgIR shape (exact CC/dest, i32/i64, FP NaN/inf/-0,
  diamond, OEQ/UNE fallback, peep live-consumer), `peephole.wast` /
  `peephole_mod.wat`

No public API change. Wasm trap, gas, and wraparound semantics are
unchanged. `+0.0` is not hoisted (x86 `FLD0`). Entry blocks with
predecessors are not rewritten (backedge would re-execute the init).

Profitability is an **unmeasured tradeoff**. Saved jacobi assembly grew
the stack allocation from `0x28` to `0x58`; the coefficient is stored to
an entry spill slot and reloaded into the stencil, so this does not prove
permanent XMM residency. N=3 / N=5 jacobi Execution numbers swing in
both directions with overlapping ranges. This change does **not** claim a
stable jacobi wall-clock win.

## Checklist

- [x] Implementation complete
- [x] Tests added/updated
- [x] Module specs in `docs/modules/` updated (if affected)
- [x] Build and tests pass
